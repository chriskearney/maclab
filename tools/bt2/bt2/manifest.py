#!/usr/bin/env python3
"""Generate a labd installed manifest (maclab.installed-manifest/2) from package archives.

Same algorithm as aurora-recipes/release-deps/installed-12.0/build-manifest.py, generalised:
- kernel package = the archive containing exactly one usr/lib/modules/<krel>/vmlinuz;
- payload = every regular file under usr/lib/modules/<krel>/ of the KERNEL package only;
- dtbs = kernel package usr/lib/modules/<krel>/dtbs/*.dtb sorted bytewise by full path;
- m1n1.bin from the m1n1 package (usr/lib/asahi-boot/m1n1.bin); m1n1.version from the live DT
  (/proc/device-tree/chosen/asahi,m1n1-stage2-version) because the binary regex is unreliable;
- per-Mac boot.bin = m1n1.bin + DTB bytes + that Mac's current U-Boot gz + trailer (from its current boot.bin).
"""
import gzip
import hashlib
import json
import re
import struct
import tarfile
import time
import zlib

REGENERATED = ["modules.alias", "modules.alias.bin", "modules.builtin.alias.bin", "modules.builtin.bin",
               "modules.dep", "modules.dep.bin", "modules.devname", "modules.softdep",
               "modules.symbols", "modules.symbols.bin", "modules.weakdep"]
FDT = b"\xd0\x0d\xfe\xed"


class ManifestError(RuntimeError):
    pass


def H(b):
    return hashlib.sha256(b).hexdigest()


def read_members(path, want):
    """Return {name: bytes} for the requested member names (normalised, no leading ./)."""
    out = {}
    with tarfile.open(path, mode='r:*') as t:
        for m in t:
            n = m.name[2:] if m.name.startswith('./') else m.name
            if (n in want or (callable(want) and want(n))) and m.isfile():
                out[n] = t.extractfile(m).read()
    return out


def parse_bootbin(buf):
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
                return buf[:start], [buf[a:a + k] for a, k in chain], buf[o:end], buf[end:]
    raise ManifestError("unparseable boot.bin")


def artifact_row(insp):
    mt = read_members(insp['path'], {'.MTREE'})['.MTREE']
    return {"name": insp['pkginfo']['pkgname'], "file": insp['file'], "sha256": insp['sha256'],
            "version": insp['pkginfo']['pkgver'], "mtree_sha256": H(gzip.decompress(mt))}


def generate(release, inspections, macs, m1n1_version, created=None, approved_by=()):
    """inspections: artifacts.inspect() results for every package in the manifest (candidates + unchanged
    boot-chain packages such as m1n1-aurora/uboot-asahi). macs: {device: {'board', 'board_dtb', 'bootbin': bytes}}."""
    rows = [artifact_row(i) for i in sorted(inspections, key=lambda x: x['file'])]
    kernels = [i for i in inspections if len(i['kernel_releases']) == 1]
    if len(kernels) != 1:
        raise ManifestError('need exactly one kernel package, found %d' % len(kernels))
    k = kernels[0]
    krel = k['kernel_releases'][0]
    prefix = 'usr/lib/modules/%s/' % krel
    payload = {}
    for n, r in k['members'].items():
        if n.startswith(prefix) and r['type'] == 'f':
            payload[n[len(prefix):]] = r['sha256']
    plines = "".join("%s  %s\n" % (payload[r], r) for r in sorted(payload))
    dtb_names = sorted([n for n in k['members'] if n.startswith(prefix + 'dtbs/') and n.endswith('.dtb')
                        and k['members'][n]['type'] == 'f'], key=lambda s: s.encode())
    dtb_bytes_map = read_members(k['path'], set(dtb_names))
    dtbs = [{"name": n.rsplit('/', 1)[1], "sha256": H(dtb_bytes_map[n])} for n in dtb_names]
    dtb_bytes = b"".join(dtb_bytes_map[n] for n in dtb_names)
    digest = H("".join("%s %s\n" % (d['name'], d['sha256']) for d in dtbs).encode())
    m1n1_pkgs = [i for i in inspections if 'usr/lib/asahi-boot/m1n1.bin' in i['members']]
    if len(m1n1_pkgs) != 1:
        raise ManifestError('need exactly one package providing usr/lib/asahi-boot/m1n1.bin')
    m1n1 = read_members(m1n1_pkgs[0]['path'], {'usr/lib/asahi-boot/m1n1.bin'})['usr/lib/asahi-boot/m1n1.bin']
    out_macs = {}
    expected = {}
    for name, m in macs.items():
        if m['board_dtb'] not in [d['name'] for d in dtbs]:
            raise ManifestError('board dtb %s not in kernel dtbs' % m['board_dtb'])
        _, _, gz, trailer = parse_bootbin(m['bootbin'])
        img = m1n1 + dtb_bytes + gz + trailer
        expected[name] = img
        out_macs[name] = {"board": m['board'], "board_dtb": m['board_dtb'], "uboot_gz_sha256": H(gz),
                          "trailer": trailer.decode(errors="replace"), "boot_bin_sha256": H(img),
                          "basis": "m1n1 + %d DTBs (byte order) + U-Boot gz and trailer from current boot.bin (%s)"
                                   % (len(dtbs), H(m['bootbin'])[:16])}
    man = {"schema": "maclab.installed-manifest/2", "release": release,
           "created": created or time.strftime("%Y-%m-%dT%H:%M:%S%z"), "approved_by": list(approved_by),
           "artifacts": rows,
           "kernel": {"release": krel, "vmlinuz_sha256": payload["vmlinuz"],
                      "payload_manifest": "payload/linux-aurora.files.sha256",
                      "payload_manifest_sha256": H(plines.encode()), "payload_count": len(payload),
                      "regenerated_on_mac": REGENERATED},
           "m1n1": {"bin_sha256": H(m1n1), "version": m1n1_version},
           "dtbs": dtbs, "dtbs_sha256": digest, "macs": out_macs}
    raw = (json.dumps(man, indent=2) + "\n").encode()
    return man, raw, plines.encode(), expected


def semantic_diff(a, b, ignore=('release', 'created', 'approved_by')):
    """List differing top-level/nested keys between two manifests (ignoring informational fields)."""
    diffs = []

    def walk(x, y, p):
        if isinstance(x, dict) and isinstance(y, dict):
            for key in sorted(set(x) | set(y)):
                if p == '' and key in ignore:
                    continue
                if key == 'basis':
                    continue
                if key not in x or key not in y:
                    diffs.append(p + '/' + key)
                else:
                    walk(x[key], y[key], p + '/' + key)
        elif isinstance(x, list) and isinstance(y, list):
            if p.endswith('artifacts'):
                xs = sorted(json.dumps(v, sort_keys=True) for v in x)
                ys = sorted(json.dumps(v, sort_keys=True) for v in y)
                if xs != ys:
                    diffs.append(p)
            elif len(x) != len(y):
                diffs.append(p + ' (len)')
            else:
                for i, (u, v) in enumerate(zip(x, y)):
                    walk(u, v, '%s/%d' % (p, i))
        elif x != y:
            diffs.append(p)
    walk(a, b, '')
    return diffs
