#!/usr/bin/env python3
"""maclab installed-mode collector (maclab.installed-observed/1). Read only, run as root.

  collect.py --phase before|booted|after|freeze --device NAME --krel RELEASE [--job ID]
             [--entry-path LIMINE_PATH] [--pkgs a,b,c] [--payload]

Prints one JSON object: what is installed and what is running. maclab compares
it with the frozen expectation; this script judges nothing.
"""
import argparse, glob, gzip, hashlib, json, os, re, struct, subprocess, time, zlib

ESP = "/boot/efi"


def sha(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
    except OSError:
        return None
    return h.hexdigest()


def blake2b(path):
    """BLAKE2b-512, the hash a Limine path's #pin names."""
    h = hashlib.blake2b()
    try:
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
    except OSError:
        return None
    return h.hexdigest()


def rd(p):
    try:
        return open(p, "rb").read().replace(b"\0", b"").decode(errors="replace").strip()
    except OSError:
        return None


def run(*a):
    try:
        return subprocess.run(a, capture_output=True, text=True, timeout=120).stdout.strip()
    except Exception:
        return ""


def packages(names):
    out = {}
    for name in names:
        v = run("pacman", "-Q", name)
        ver = v.split()[-1] if v else None
        mtree = None
        if ver:
            p = f"/var/lib/pacman/local/{name}-{ver}/mtree"
            try:
                mtree = hashlib.sha256(gzip.decompress(open(p, "rb").read())).hexdigest()
            except (OSError, EOFError, gzip.BadGzipFile):
                mtree = None
        out[name] = {"version": ver, "mtree_sha256": mtree}
    return out


def payload(krel):
    root = f"/usr/lib/modules/{krel}"
    files = {}
    for dirpath, _, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            files[os.path.relpath(p, root)] = sha(p)
    return {"krel": krel, "root": root, "count": len(files), "files": files}


def uki_sections(path):
    try:
        b = open(path, "rb").read()
    except OSError:
        return {}
    if b[:2] != b"MZ":
        return {}
    pe = struct.unpack("<I", b[0x3c:0x40])[0]
    if b[pe:pe + 4] != b"PE\0\0":
        return {}
    nsec = struct.unpack("<H", b[pe + 6:pe + 8])[0]
    optsz = struct.unpack("<H", b[pe + 20:pe + 22])[0]
    off = pe + 24 + optsz
    out = {}
    for i in range(nsec):
        sh = b[off + 40 * i: off + 40 * (i + 1)]
        name = sh[:8].rstrip(b"\0").decode(errors="replace")
        vsize, _, rsize, roff = struct.unpack("<IIII", sh[8:24])
        data = b[roff:roff + (min(vsize, rsize) if vsize else rsize)]
        if name in (".linux", ".initrd", ".cmdline", ".osrel", ".uname", ".dtb", ".ucode"):
            s = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            if name in (".cmdline", ".uname"):
                s["text"] = data.rstrip(b"\0").decode(errors="replace").strip()
            out[name] = s
    return out


def esp_file(p):
    p = p.split("#", 1)[0]
    p = re.sub(r"^[a-z]+\([^)]*\):", "", p)
    return ESP + "/" + p.lstrip("/")


def limine_entries():
    """Every entry with its own lines, as written in limine.conf."""
    conf = f"{ESP}/limine.conf"
    try:
        text = open(conf).read()
    except OSError:
        return None, []
    entries, cur, stack = [], None, []
    for raw in text.splitlines():
        s = raw.strip()
        m = re.match(r"^(/+)([-+]?)(.*)$", s)
        if m and not s.startswith("//#"):
            depth = len(m.group(1))
            stack = stack[:depth - 1] + [m.group(3).strip()]
            cur = {"name": " / ".join(stack), "depth": depth, "lines": [raw.rstrip()]}
            entries.append(cur)
            continue
        if cur is None:
            continue
        if s == "":
            cur["closed"] = True
            continue
        if cur.get("closed") or s.startswith("#"):
            continue
        cur["lines"].append(raw.rstrip())
        kv = re.match(r"^([a-z_]+)\s*:\s*(.*)$", s)
        if kv:
            cur.setdefault("kv", []).append((kv.group(1), kv.group(2).strip()))
    return sha(conf), entries


def installer_entry(krel, entry_path):
    conf_sha, entries = limine_entries()
    best = None
    for e in entries:
        kv = dict(e.get("kv", []))
        path = kv.get("path") or kv.get("kernel_path")
        if not path or e["name"].startswith("maclab") or "Snapshots" in e["name"]:
            continue
        f = esp_file(path)
        secs = uki_sections(f) if f.lower().endswith(".efi") else {}
        cand = {"found": True, "name": e["name"], "protocol": kv.get("protocol"), "path": path,
                "cmdline": kv.get("cmdline", ""), "cmdline_tokens": kv.get("cmdline", "").split(),
                "entry_lines": e["lines"],
                "entry_sha256": hashlib.sha256(("\n".join(e["lines"]) + "\n").encode()).hexdigest(),
                "uki_file": f, "uki_sha256": sha(f), "uki_blake2b": blake2b(f), "uki_sections": secs,
                "limine_conf_sha256": conf_sha}
        if entry_path:
            if path == entry_path:
                return cand
        elif secs.get(".uname", {}).get("text") == krel:
            best = best or cand
    return best or {"found": False, "limine_conf_sha256": conf_sha}


FDT = b"\xd0\x0d\xfe\xed"


def root_compat(blob):
    _, _, off_struct, off_strings, _, _, _, _, _, size_struct = struct.unpack(">10I", blob[:40])
    p, depth = off_struct, 0
    while p < off_struct + size_struct:
        tok = struct.unpack(">I", blob[p:p + 4])[0]
        p += 4
        if tok == 1:
            p = (blob.index(b"\0", p) + 1 + 3) & ~3
            depth += 1
            if depth > 1:
                break
        elif tok == 3:
            ln, nameoff = struct.unpack(">II", blob[p:p + 8])
            p += 8
            val = blob[p:p + ln]
            p = (p + ln + 3) & ~3
            s = off_strings + nameoff
            if depth == 1 and blob[s:blob.index(b"\0", s)] == b"compatible":
                return [c.decode() for c in val.split(b"\0") if c]
        elif tok == 2:
            depth -= 1
        elif tok == 9:
            break
    return []


def bootbin(board):
    path = f"{ESP}/m1n1/boot.bin"
    out = {"path": path, "sha256": sha(path), "parts": None}
    try:
        buf = open(path, "rb").read()
    except OSError:
        return out
    gzs = {m.start() for m in re.finditer(b"\x1f\x8b\x08", buf)}
    for m in re.finditer(re.escape(FDT), buf):
        start = o = m.start()
        chain = []
        while buf[o:o + 4] == FDT and o + 40 <= len(buf):
            n = struct.unpack(">I", buf[o + 4:o + 8])[0]
            if n < 40:
                break
            chain.append((o, n))
            o += n
            if o in gzs:
                d = zlib.decompressobj(31)
                try:
                    d.decompress(buf[o:])
                    d.flush()
                except zlib.error:
                    break
                if not d.eof:
                    break
                end = len(buf) - len(d.unused_data)
                m1n1 = buf[:start]
                dtbs = [buf[a:a + k] for a, k in chain]
                board_idx = [i for i, b in enumerate(dtbs) if board in root_compat(b)]
                out["parts"] = {
                    "m1n1_sha256": hashlib.sha256(m1n1).hexdigest(), "m1n1_bytes": len(m1n1),
                    "m1n1_versions": sorted({v.decode() for v in re.findall(rb"v1\.\d+\.\d+[0-9A-Za-z.+_-]*", m1n1)}),
                    "dtb_count": len(dtbs), "dtb_shas": [hashlib.sha256(b).hexdigest() for b in dtbs],
                    "board_dtb_index": board_idx[-1] if board_idx else None,
                    "board_dtb_count": len(board_idx),
                    "board_dtb_sha256": hashlib.sha256(dtbs[board_idx[-1]]).hexdigest() if board_idx else None,
                    "uboot_gz_sha256": hashlib.sha256(buf[o:end]).hexdigest(),
                    "trailer": buf[end:].decode(errors="replace")}
                return out
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", required=True)
    ap.add_argument("--device", required=True)
    ap.add_argument("--krel", required=True)
    ap.add_argument("--job", default="")
    ap.add_argument("--entry-path", default="")
    ap.add_argument("--pkgs", default="")
    ap.add_argument("--payload", action="store_true")
    a = ap.parse_args()
    try:
        board = open("/proc/device-tree/compatible", "rb").read().split(b"\0")[0].decode()
        compat = [c.decode() for c in open("/proc/device-tree/compatible", "rb").read().split(b"\0") if c]
    except OSError:
        board, compat = "", []
    comp = None
    for name in ("chonkstep-wayla", "Hyprland"):
        for pid in run("pgrep", "-x", name).split():
            exe = os.readlink(f"/proc/{pid}/exe")
            comp = {"exe": exe, "sha256": sha(exe)}
            break
        if comp:
            break
    obs = {
        "schema": "maclab.installed-observed/1", "phase": a.phase, "device": a.device, "job": a.job,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "running": {"boot_id": rd("/proc/sys/kernel/random/boot_id"), "uname_r": os.uname().release,
                    "proc_cmdline": rd("/proc/cmdline")},
        "packages": packages([p for p in a.pkgs.split(",") if p]),
        "payload": payload(a.krel) if a.payload else None,
        "installer_entry": installer_entry(a.krel, a.entry_path),
        "boot_bin": bootbin(board),
        "dt": {"board": board, "compatible": compat, "live_model": rd("/proc/device-tree/model"),
               "live_stage2_version": rd("/proc/device-tree/chosen/asahi,m1n1-stage2-version"),
               "live_fdt_sha256": sha("/sys/firmware/fdt")},
        "compositor": comp,
    }
    print(json.dumps(obs, indent=1))


if __name__ == "__main__":
    main()
