"""Tiny, deterministic pacman-like archives and boot.bin for the controller tests (no real payloads)."""
import gzip
import hashlib
import io
import json
import shutil
import struct
import tarfile
from pathlib import Path

KREL7 = '7.2.11-7-1-ARCH'
KREL6 = '7.2.11-6-1-ARCH'
M1N1 = b'M1N1-stage1-fake-' * 32
# for the boot.bin-changing path: stage 2 binaries carrying m1n1's version marker (src/main.c version_tag)
M1N1_V20 = b'M1N1-aurora20-fake-' * 30 + b'##m1n1_ver##f5a82fdb-dirty\0' + b'tail' * 8
M1N1_V22 = b'M1N1-aurora22-fake-' * 34 + b'##m1n1_ver##5d17a034-dirty\0' + b'tail' * 8
UBOOT_GZ = gzip.compress(b'U-BOOT-NODTB-fake' * 16, mtime=0)


def H(b):
    return hashlib.sha256(b).hexdigest()


def fdt(tag, size=64):
    return b'\xd0\x0d\xfe\xed' + struct.pack('>I', size) + tag.encode().ljust(size - 8, b'\0')


DTBS = {'t6030-j516s.dtb': fdt('j516s'), 't8103-j293.dtb': fdt('j293'), 't8103-j313.dtb': fdt('j313')}


def bootbin(trailer=b'', m1n1=M1N1):
    return m1n1 + b''.join(DTBS[n] for n in sorted(DTBS)) + UBOOT_GZ + trailer


def make_pkg(outdir, name, version, files, links=None):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pkginfo = ('pkgname = %s\npkgbase = %s\npkgver = %s\narch = aarch64\nsize = %d\n'
               % (name, name, version, sum(len(b) for b in files.values()))).encode()
    mtree = gzip.compress(('#mtree\n' + ''.join('./%s type=file size=%d sha256digest=%s\n' % (p, len(b), H(b))
                                                 for p, b in sorted(files.items()))).encode(), mtime=0)
    path = outdir / ('%s-%s-aarch64.pkg.tar.zst' % (name, version))
    with tarfile.open(path, 'w:zst') as t:
        def add(n, data, mode=0o644):
            ti = tarfile.TarInfo(n)
            ti.size, ti.mode, ti.mtime = len(data), mode, 0
            t.addfile(ti, io.BytesIO(data))
        add('.PKGINFO', pkginfo)
        add('.MTREE', mtree)
        for n, b in sorted(files.items()):
            add(n, b, 0o755 if '.so' in n else 0o644)
        for n, target in sorted((links or {}).items()):
            ti = tarfile.TarInfo(n)
            ti.type, ti.linkname, ti.mtime, ti.mode = tarfile.SYMTYPE, target, 0, 0o777
            t.addfile(ti)
    return path


def mtree_sha(path):
    with tarfile.open(path, 'r:*') as t:
        return H(gzip.decompress(t.extractfile('.MTREE').read()))


def kernel_files(krel, image):
    pre = 'usr/lib/modules/%s/' % krel
    f = {pre + 'vmlinuz': image, pre + 'modules.alias': b'alias ' + image, pre + 'kernel/x.ko.zst': b'ko' + image}
    for n, b in DTBS.items():
        f[pre + 'dtbs/' + n] = b
    return f


def mesa_files(tag):
    t = tag.encode()
    return {'usr/lib/libgallium-26.3.0-devel.so': b'gallium-' + t, 'usr/lib/libEGL_mesa.so.0.0.0': b'egl-' + t,
            'usr/lib/dri/libdril_dri.so': b'dril-' + t, 'usr/lib/libGLX_mesa.so.0.0.0': b'glx-' + t,
            'usr/lib/libgbm.so.1.0.0': b'gbm-' + t}


MESA_LINKS = {'usr/lib/libEGL_mesa.so.0': 'libEGL_mesa.so.0.0.0', 'usr/lib/dri/asahi_dri.so': 'libdril_dri.so'}


def to_store(store, path):
    sha = H(Path(path).read_bytes())
    d = Path(store) / sha
    d.mkdir(parents=True, exist_ok=True)
    dest = d / Path(path).name
    shutil.move(str(path), dest)
    return dest


def build_cohort(root, kept_in_store=True, m1n1_candidate=False):
    """Candidates (aurora7 cohort), originals (aurora6 cohort) and kept boot-chain archives."""
    root = Path(root)
    cand = root / 'cand'
    tmp = root / 'tmp'
    store = root / 'store'
    extra = root / 'extra'
    cands = [make_pkg(cand, 'linux-aurora', '7.2.11.aurora7-1', kernel_files(KREL7, b'IMAGE7')),
             make_pkg(cand, 'mesa-aurora', '1:26.3.0_devel.7c-1', mesa_files('7c'), MESA_LINKS),
             make_pkg(cand, 'vulkan-aurora', '1:26.3.0_devel.7c-1', {'usr/lib/libvulkan_asahi.so': b'vk-7c'}),
             make_pkg(cand, 'omarchy-mac-boot', '20261026-1', {'usr/share/libalpm/hooks/95-x.hook': b'hook-26'})]
    originals = {'linux-aurora': '7.2.11.aurora6-1', 'mesa-aurora': '1:26.3.0_devel.147a-1',
                 'vulkan-aurora': '1:26.3.0_devel.147a-1', 'omarchy-mac-boot': '20261010-1'}
    ofiles = {'linux-aurora': kernel_files(KREL6, b'IMAGE6'), 'mesa-aurora': mesa_files('147a'),
              'vulkan-aurora': {'usr/lib/libvulkan_asahi.so': b'vk-147a'},
              'omarchy-mac-boot': {'usr/share/libalpm/hooks/95-x.hook': b'hook-10'}}
    orig_paths = {}
    for n, v in originals.items():
        orig_paths[n] = to_store(store, make_pkg(tmp, n, v, ofiles[n]))
    if m1n1_candidate:
        cands.append(make_pkg(cand, 'm1n1-aurora', '1.6.1.aurora22-1', {'usr/lib/asahi-boot/m1n1.bin': M1N1_V22}))
    kept = {'m1n1-aurora': ('1.6.1.aurora20-4', {'usr/lib/asahi-boot/m1n1.bin': M1N1_V20 if m1n1_candidate else M1N1}),
            'uboot-asahi': ('2026.07.asahi2-4', {'usr/lib/asahi-boot/u-boot-nodtb.bin': b'UBOOT'})}
    kept_paths = {}
    for n, (v, files) in kept.items():
        p = make_pkg(tmp, n, v, files)
        if kept_in_store:
            kept_paths[n] = to_store(store, p)
        else:
            extra.mkdir(parents=True, exist_ok=True)
            kept_paths[n] = Path(shutil.move(str(p), extra / p.name))
    packages = dict(originals)
    packages.update({n: v for n, (v, _) in kept.items()})
    # the probe reports the installed mtree of every probed package (originals too: the fresh baseline checks them)
    mtree = {n: mtree_sha(p) for n, p in [*kept_paths.items(), *orig_paths.items()]}
    return {'candidates': [str(p) for p in cands], 'store': store, 'extra': [str(p) for p in kept_paths.values()],
            'packages': packages, 'mtree': mtree}


def make_frozen_release(frozen, release, device, manifest_raw, payload):
    """A minimal frozen release that installed.source_cohort() accepts (expected + preinstall)."""
    root = Path(frozen) / release
    (root / 'expected/payload').mkdir(parents=True)
    (root / 'expected/manifest.json').write_bytes(manifest_raw)
    (root / 'expected/payload/linux-aurora.files.sha256').write_bytes(payload)
    (root / 'PINS.expected').write_text('# PINS.expected test\n%s  expected/manifest.json\n%s  '
                                        'expected/payload/linux-aurora.files.sha256\n' % (H(manifest_raw), H(payload)))
    pre = root / 'preinstall' / device
    pre.mkdir(parents=True)
    files = {'omt-report.json': json.dumps({'tool': {'version': 't'}}).encode(),
             'omt-status.json': b'{"a":"pass"}\n', 'dmesg-errors.txt': b'', 'baseline-job.json': b'{"id":"j1"}\n'}
    lines = ['# PINS.preinstall test']
    for n, b in files.items():
        (pre / n).write_bytes(b)
        lines.append('%s  preinstall/%s/%s' % (H(b), device, n))
    (root / 'PINS.preinstall').write_text('\n'.join(lines) + '\n')
    return root
