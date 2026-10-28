"""Fake-root builder for bt2 target tests (state capture / esp / etc / audit).

A Fixture is a temp dir under /dev/shm/maclab-bt2-tests holding:
  root/   a tree mirroring / (ESP at root/boot/efi, pacman local DB, /etc, /usr/lib/modules, /proc bits, ...)
  shim_etc_restore.py   runner used only while __main__.py has no 'etc-restore' entry yet
Fake tools live in fx_state/bin (pacman reads root's local DB; systemctl reads root/fake/systemd.json).
Profiles: 'm1' (package-owned running kernel, auto default entry), 'air' (menu derived from the real Air
reference.conf with fixture hashes substituted), 'm3' (custom unowned running kernel + custom default,
boot package absent, unowned files at boot-package paths).
"""
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

FX = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(FX, 'bin')
TARGET = os.environ.get('BT2_TARGET') or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'target')   # the target tree under test
SCRATCH = '/dev/shm/maclab-bt2-tests'
AIR_DIR = os.path.join(FX, 'menus')
RUN_ID = 'bt2-test-0001'
RUN_SYS = '/var/lib/maclab/bt2/' + RUN_ID
LAB_BEGIN = '# maclab: begin. Managed by lab-agent: staged test kernels, booted once via LoaderEntryOneShot.'
LAB_END = '# maclab: end'
GUID = '4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
MiB = 1 << 20
AIR_UKI_SHA = '15ca6b6aba0fbf163065adb421c1ab6c22fa8a45297b97426055604bc8da352a'
AIR_UKI_B2 = ('d9e9c6dc7dccece6eb6415171b10b611315dfccc380551911996ec5586cd3a4df0f5597a4ad0844c5049e8fc0b0605389e2'
              'a4fb948a4074b072b3f3dda214db3')
AIR_SF_B2 = ('4e6dae72a02d8ce130cd2c4941fc2249fdf68385a9fbe44c411fc8004e0b465b3ff7fe5a992d8fc0231768dc6fdadca3101e0e3'
             '2f9fec9c5ca4f696e122a5ef4')
SHIM = '''import sys
sys.path.insert(0, %r)
import common, espops
common.main({'etc-restore': espops.etc_restore})
''' % TARGET


def rd(path):
    with open(path, 'rb') as f:
        return f.read()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def b2(b):
    return hashlib.blake2b(b, digest_size=64).hexdigest()


def blob(tag, n):
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(b'%s:%d' % (tag.encode(), i)).digest()
        i += 1
    return bytes(out[:n])


class Pkg:
    def __init__(self, name, version, files, links=None, backup=()):
        self.name, self.version = name, version
        self.files = dict(files)          # rel -> bytes
        self.links = dict(links or {})    # rel -> target
        self.backup = list(backup)

    def entries(self):
        dirs = set()
        for rel in list(self.files) + list(self.links):
            parts = rel.split('/')[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add('/'.join(parts[:i]))
        out = [(d, 'd', None) for d in dirs]
        out += [(r, 'f', b) for r, b in self.files.items()]
        out += [(r, 'l', t) for r, t in self.links.items()]
        return sorted(out)

    def mtree(self):
        lines = ['#mtree'] + ['./%s type=%s' % (r, {'d': 'dir', 'f': 'file', 'l': 'link'}[k]) +
                              (' sha256digest=%s' % sha(v) if k == 'f' else '') for r, k, v in self.entries()]
        return gzip.compress(('\n'.join(lines) + '\n').encode(), mtime=0)

    def pkginfo(self):
        s = 'pkgname = %s\npkgbase = %s\npkgver = %s\narch = aarch64\n' % (self.name, self.name, self.version)
        return (s + ''.join('backup = %s\n' % b for b in self.backup)).encode()

    def filename(self):
        return '%s-%s-aarch64.pkg.tar.zst' % (self.name, self.version)

    def write_archive(self, path):
        with tarfile.open(path, 'w:zst') as t:
            def add(name, data, mode=0o644, kind=tarfile.REGTYPE, link=''):
                ti = tarfile.TarInfo(name)
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = 'root'
                ti.mtime, ti.mode, ti.type, ti.linkname = 1700000000, mode, kind, link
                if kind == tarfile.REGTYPE:
                    ti.size = len(data)
                    t.addfile(ti, io.BytesIO(data))
                else:
                    t.addfile(ti)
            add('.PKGINFO', self.pkginfo())
            add('.MTREE', self.mtree())
            for rel, kind, val in self.entries():
                if kind == 'd':
                    add(rel, None, 0o755, tarfile.DIRTYPE)
                elif kind == 'l':
                    add(rel, None, 0o777, tarfile.SYMTYPE, val)
                else:
                    add(rel, val)
        data = rd(path)
        return {'name': self.name, 'version': self.version, 'file': os.path.basename(path), 'sha256': sha(data),
                'bytes': len(data)}

    def install(self, root):
        for rel, kind, val in self.entries():
            p = os.path.join(root, rel)
            if kind == 'd':
                os.makedirs(p, exist_ok=True)
            elif kind == 'l':
                os.makedirs(os.path.dirname(p), exist_ok=True)
                os.symlink(val, p)
            else:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, 'wb') as f:
                    f.write(val)
        d = os.path.join(root, 'var/lib/pacman/local/%s-%s' % (self.name, self.version))
        os.makedirs(d)
        with open(d + '/desc', 'w') as f:
            f.write('%%NAME%%\n%s\n\n%%VERSION%%\n%s\n\n%%BASE%%\n%s\n\n' % (self.name, self.version, self.name))
        with open(d + '/files', 'w') as f:
            f.write('%FILES%\n' + ''.join(r + ('/' if k == 'd' else '') + '\n' for r, k, _ in self.entries()) + '\n')
            if self.backup:
                f.write('%BACKUP%\n' + ''.join('%s\t%s\n' % (b, hashlib.md5(self.files[b]).hexdigest())
                                               for b in self.backup) + '\n')
        with open(d + '/mtree', 'wb') as f:
            f.write(self.mtree())


def kernel_pkg(krel, version, tag):
    base = 'usr/lib/modules/%s/' % krel
    return Pkg('linux-aurora', version, {
        base + 'vmlinuz': blob(tag + 'vmlinuz', 40000),
        base + 'modules.order': b'kernel/drivers/gpu/asahi.ko\n',
        base + 'modules.builtin': b'kernel/fs/btrfs.ko\n',
        base + 'modules.dep': b'kernel/drivers/gpu/asahi.ko:\n',
        base + 'kernel/drivers/gpu/asahi.ko': blob(tag + 'asahi', 30000),
        base + 'pkgbase': b'linux-aurora\n',
    }, links={base + 'build': '../../../src/linux-aurora'})


def boot_pkg(version, tag, extra=None):
    files = {'etc/default/update-m1n1': b'# update-m1n1 defaults %s\nDTBS=auto\n' % tag.encode(),
             'usr/lib/systemd/system/omarchy-mac-efi-vars.service': b'[Unit]\nDescription=efi vars %s\n' % tag.encode(),
             'usr/share/libalpm/hooks/95-omarchy-mac-dtb-overlays.hook': b'[Trigger]\n# %s\n' % tag.encode(),
             'usr/bin/update-m1n1': b'#!/bin/sh\n# %s\n' % tag.encode()}
    files.update(extra or {})
    return Pkg('omarchy-mac-boot', version, files, backup=['etc/default/update-m1n1'])


class Fixture:
    def __init__(self, profile='m1', **config_over):
        os.makedirs(SCRATCH, exist_ok=True)
        self.base = tempfile.mkdtemp(prefix='bt2fx-%s-' % profile, dir=SCRATCH)
        self.root = os.path.join(self.base, 'root')
        self.profile = profile
        self.shim = os.path.join(self.base, 'shim_etc_restore.py')
        with open(self.shim, 'w') as f:
            f.write(SHIM)
        self.calls = []
        os.makedirs(self.root)
        getattr(self, '_build_' + ('m3' if profile == 'm3' else 'm1'))()
        self._write_config(config_over)

    # ---- helpers
    def P(self, p):
        return self.root + p

    def write(self, p, data, mode=0o644, mtime_ns=None):
        full = self.P(p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as f:
            f.write(data)
        os.chmod(full, mode)
        if mtime_ns is not None:
            os.utime(full, ns=(mtime_ns, mtime_ns))

    def read(self, p):
        return rd(self.P(p))

    def link(self, p, target):
        full = self.P(p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        os.symlink(target, full)

    def flip_byte(self, p, offset=0):
        """Change one byte, keeping size and mtime (only a content hash can see it)."""
        full = self.P(p)
        st = os.lstat(full)
        data = bytearray(self.read(p))
        data[offset] ^= 0x01
        with open(full, 'r+b') as f:
            f.write(bytes(data))
        os.utime(full, ns=(st.st_atime_ns, st.st_mtime_ns))

    @property
    def run_dir(self):
        return self.P(RUN_SYS)

    def config(self):
        return json.loads(rd(self.run_dir + '/config.json'))

    def set_config(self, **kv):
        cfg = self.config()
        cfg.update(kv)
        with open(self.run_dir + '/config.json', 'w') as f:
            json.dump(cfg, f, indent=1, sort_keys=True)

    def state(self):
        return json.loads(rd(self.run_dir + '/capture/state.json'))

    def units(self, **changes):
        p = self.P('/fake/systemd.json')
        d = json.loads(rd(p))
        for u, props in changes.items():
            d['units'].setdefault(u, {}).update(props)
        with open(p, 'w') as f:
            json.dump(d, f, indent=1, sort_keys=True)

    def run(self, cmd, *extra, timeout=120):
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'BT2_TEST_ROOT': self.root, 'BT2_TEST_BIN': BIN,
               'BT2_TEST_UNAME_R': self.uname}
        wired = ("'%s'" % cmd).encode() in rd(os.path.join(TARGET, '__main__.py'))
        entry = TARGET if wired else self.shim
        r = subprocess.run([sys.executable, '-I', '-B', entry, cmd, '--run-dir', RUN_SYS, *extra], env=env,
                           capture_output=True, timeout=timeout)
        lines = r.stdout.decode(errors='replace').strip().splitlines()
        try:
            out = json.loads(lines[-1]) if lines else {}
        except ValueError:
            out = {'unparsed_stdout': r.stdout.decode(errors='replace')[-2000:]}
        out['_stderr'] = r.stderr.decode(errors='replace')[-3000:]
        self.calls.append((cmd, r.returncode))
        return r.returncode, out

    def snapshot_tree(self, exclude=(RUN_SYS,)):
        """sha of the whole fake root (paths, types, modes, sizes, mtimes, bytes, link targets)."""
        h = hashlib.sha256()
        ex = [self.P(e) for e in exclude]
        for dp, dns, fns in os.walk(self.root):
            dns[:] = sorted(d for d in dns if os.path.join(dp, d) not in ex)
            for n in sorted(dns + fns):
                p = os.path.join(dp, n)
                if p in ex:
                    continue
                st = os.lstat(p)
                h.update(('%s|%o|%d|%d\n' % (os.path.relpath(p, self.root), st.st_mode, st.st_size,
                                             st.st_mtime_ns)).encode())
                if os.path.islink(p):
                    h.update(os.readlink(p).encode())
                elif os.path.isfile(p):
                    h.update(rd(p))
        return h.hexdigest()

    def close(self):
        shutil.rmtree(self.base, ignore_errors=True)

    # ---- common pieces
    def _common(self, board, uuid, mid, krel):
        self.uname = krel
        self.board = board
        self.write('/proc/sys/kernel/random/boot_id', b'0b0b0b0b-1111-2222-3333-444444444444\n')
        self.write('/proc/device-tree/compatible', board.encode() + b'\0apple,arm-platform\0')
        self.write('/proc/cmdline', ('root=UUID=%s rw rootflags=subvol=@ quiet\n' % uuid).encode())
        self.write('/etc/machine-id', (mid + '\n').encode())
        self.write('/etc/pacman.conf', b'[options]\nHoldPkg = pacman glibc\nArchitecture = auto\n\n[core]\n'
                                       b'Include = /etc/pacman.d/mirrorlist\n')
        self.write('/etc/default/limine', b'TARGET_OS_NAME="Omarchy"\nENABLE_UKI=yes\n')
        self.write('/etc/limine-entry-tool.conf', b'# limine-entry-tool\n')
        self.write('/etc/mkinitcpio.conf', b'HOOKS=(base udev autodetect)\n')
        self.write('/etc/mkinitcpio.conf.d/90-omarchy-mac.conf', b'MODULES+=(apple-dcp)\n')
        self.write('/etc/mkinitcpio.d/linux-aurora.preset', b"PRESETS=('default')\n")
        lib = '/usr/lib/systemd/system/'
        self.link('/etc/systemd/system/limine-snapper-watcher.service', lib + 'limine-snapper-sync.service')
        self.link('/etc/systemd/system/multi-user.target.wants/limine-snapper-sync.service',
                  lib + 'limine-snapper-sync.service')
        self.link('/etc/systemd/system/timers.target.wants/snapper-cleanup.timer', lib + 'snapper-cleanup.timer')
        self.write('/etc/systemd/system/linux-modules-cleanup.service.d/zz-keep-local-kernels.conf',
                   b'[Service]\n# skip trees holding .keep-local-kernel\n')
        self.write('/var/lib/pacman/local/ALPM_DB_VERSION', b'9\n')
        self.write('/var/lib/maclab/known-good.json', b'{"kernel": "%s"}\n' % krel.encode())
        self.write('/var/lib/maclab/known-good.json.prev', b'{"kernel": "older"}\n')
        os.makedirs(self.P('/sys/firmware/efi/efivars'))
        self.write('/sys/firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c', b'\x07\0\0\0x')
        os.makedirs(self.P('/run/lock'))
        os.makedirs(self.P('/usr/lib/modules/.old'))
        Pkg('bash', '5.3.3-1', {'usr/bin/bash': b'\x7fELF bash'}).install(self.root)
        Pkg('limine-snapper-sync', '1.6.2-1', {
            'usr/lib/systemd/system/limine-snapper-sync.service': b'[Service]\nExecStart=/usr/bin/limine-snapper-watcher\n',
            'usr/bin/limine-snapper-watcher': b'#!/bin/sh\n'}).install(self.root)
        Pkg('snapper', '0.12-1', {'usr/lib/systemd/system/snapper-cleanup.timer': b'[Timer]\n',
                                  'usr/lib/systemd/system/snapper-timeline.timer': b'[Timer]\n'}).install(self.root)
        os.makedirs(self.run_dir + '/pkgs')
        os.makedirs(self.run_dir + '/originals')
        os.chmod(self.run_dir, 0o700)
        self.units_base = {
            'limine-snapper-sync.service': {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled',
                                            'FragmentPath': lib + 'limine-snapper-sync.service'},
            'limine-snapper-watcher.service': {'LoadState': 'loaded', 'ActiveState': 'active',
                                               'UnitFileState': 'enabled',
                                               'FragmentPath': lib + 'limine-snapper-sync.service'},
            'snapper-timeline.timer': {'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'disabled',
                                       'FragmentPath': lib + 'snapper-timeline.timer'},
            'snapper-cleanup.timer': {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled',
                                      'FragmentPath': lib + 'snapper-cleanup.timer'},
            'linux-modules-cleanup.service': {
                'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'enabled',
                'FragmentPath': lib + 'linux-modules-cleanup.service',
                'DropInPaths': '/etc/systemd/system/linux-modules-cleanup.service.d/zz-keep-local-kernels.conf'},
        }

    def _esp_common(self):
        self.write('/boot/efi/EFI/BOOT/BOOTAA64.EFI', blob('limine-efi', 20000))
        self.write('/boot/efi/m1n1/boot.bin', blob('bootbin', 50000))
        self.write('/boot/efi/m1n1/boot.bin.old', blob('bootbin-old', 48000))
        self.write('/boot/efi/limine.conf.old', b'timeout: 5\n')
        self.write('/boot/efi/ubootefi.var', blob('ubootvar', 8192))
        self.write('/boot/efi/maclab/README', b'lab-agent job dirs live here\n')

    def _finish_units(self, extra=None):
        u = dict(self.units_base)
        u.update(extra or {})
        self.write('/fake/systemd.json', json.dumps({'units': u}, indent=1, sort_keys=True).encode())

    # ---- profiles
    def _build_m1(self):
        air = self.profile == 'air'
        uuid = '4f4d5801-524f-4f54-8000-000000000001'
        mid = '1acdf795000000000000000000000001'
        krel = '7.2.11-6-1-ARCH'
        self._common('apple,j313' if air else 'apple,j293', uuid, mid, krel)
        k6 = kernel_pkg(krel, '7.2.11.aurora6-1', 'k6')
        b_old = boot_pkg('20261010-1', 'boot-old')
        k6.install(self.root)
        b_old.install(self.root)
        mods = self.P('/usr/lib/modules/' + krel)
        self.write('/usr/lib/modules/%s/modules.dep' % krel, b'kernel/drivers/gpu/asahi.ko: (depmod regenerated)\n')
        self.write('/usr/lib/modules/%s/modules.alias' % krel, b'alias of:Napple dcp\n')
        assert os.path.isdir(mods)
        # ESP
        self._esp_common()
        uki = blob('uki-6-1', 300 * 1024)
        sf = blob('sf-uki', 200 * 1024)
        self.uki, self.sf = uki, sf
        self.write('/boot/efi/EFI/Linux/omarchy_linux-aurora.efi', uki)
        self.write('/boot/efi/EFI/Linux/siliconforest-normal-205f5e8b20fc.efi', sf)
        self.write('/boot/efi/boot.bin.pre-omacom-50fb', blob('pre-omacom', 100 * 1024))
        self.write('/boot/efi/%s/limine_history/omarchy_linux-aurora.efi_sha256_%s' % (mid, sha(uki)), uki)
        if air:
            self.write('/boot/efi/siliconforest/branding/limine-wallpaper.png', blob('wallpaper', 4000))
            menu = self.air_menu('reference.conf')
        else:
            menu = m1_menu(mid, uuid, b2(uki), b2(sf))
        self.write('/boot/efi/limine.conf', menu)
        os.makedirs(self.P('/.snapshots'))
        for i in (range(496, 516) if air else (1, 2)):
            os.makedirs(self.P('/.snapshots/%d/snapshot' % i))
        # artifacts
        k7 = kernel_pkg('7.2.11-7-1-ARCH', '7.2.11.aurora7-1', 'k7')
        b_new = boot_pkg('20261026-1', 'boot-new')
        self.cands = [k7.write_archive(self.run_dir + '/pkgs/' + k7.filename()),
                      b_new.write_archive(self.run_dir + '/pkgs/' + b_new.filename())]
        self.origs = [k6.write_archive(self.run_dir + '/originals/' + k6.filename()),
                      b_old.write_archive(self.run_dir + '/originals/' + b_old.filename())]
        self.pkgs = {'k6': k6, 'k7': k7, 'b_old': b_old, 'b_new': b_new}
        self.parkable = ['EFI/Linux/siliconforest-normal-205f5e8b20fc.efi', 'boot.bin.pre-omacom-50fb']
        lib = '/usr/lib/systemd/system/'
        self._finish_units({'omarchy-mac-efi-vars.service': {
            'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'enabled',
            'FragmentPath': lib + 'omarchy-mac-efi-vars.service'}})

    def _build_m3(self):
        uuid = '4f4d5801-524f-4f54-8000-000000000001'
        mid = 'cbb1e723000000000000000000000003'
        krel = '7.2.11-lab7876c8e8-cc71'
        self._common('apple,j516s', uuid, mid, krel)
        k6 = kernel_pkg('7.2.11-6-1-ARCH', '7.2.11.aurora6-1', 'k6')
        k6.install(self.root)
        base = '/usr/lib/modules/%s/' % krel
        self.write(base + 'vmlinuz', blob('custom-vmlinuz', 30000))
        self.write(base + 'modules.order', b'kernel/drivers/gpu/asahi.ko\n')
        self.write(base + 'kernel/drivers/gpu/asahi.ko', blob('custom-asahi', 20000))
        self.write(base + '.keep-local-kernel', b'')
        self.link(base + 'build', '/home/chrisk/src/linux')
        self.write('/etc/m1n1.conf', b'chosen.asahi,t6030-gpu=1\n')
        self.write('/etc/default/update-m1n1', b'# local unowned update-m1n1\n')
        self.write('/etc/initcpio/install/omarchy-vendorfw', b'#!/bin/bash\n# legacy unowned\n')
        self._esp_common()
        custom = blob('uki-custom-m3', 280 * 1024)
        stock = blob('uki-stock-m3', 260 * 1024)
        grub = blob('grub', 30000)
        self.uki = custom
        self.write('/boot/efi/EFI/Linux/omacom-aurora6-m3.efi', custom)
        self.write('/boot/efi/EFI/Linux/omarchy_linux-aurora.efi', stock)
        self.write('/boot/efi/EFI/grub/grubaa64.efi', grub)
        self.write('/boot/efi/EFI/Linux/siliconforest-mixtape-77648eb77168.efi', blob('mixtape', 150 * 1024))
        self.write('/boot/efi/limine.conf', m3_menu(mid, uuid, b2(stock), b2(custom),
                                                    b2(blob('mixtape', 150 * 1024))))
        os.makedirs(self.P('/.snapshots/7/snapshot'))
        k7 = kernel_pkg('7.2.11-7-1-ARCH', '7.2.11.aurora7-1', 'k7')
        self.link('/usr/lib/systemd/system/omarchy-vendorfw.service',
                  '/etc/systemd/system/omarchy-vendor-firmware.service')      # unowned symlink at a package path
        b_new = boot_pkg('20261026-1', 'boot-new',
                         extra={'etc/initcpio/install/omarchy-vendorfw': b'#!/bin/bash\n# packaged\n',
                                'usr/lib/systemd/system/omarchy-vendorfw.service': b'[Unit]\n'})
        self.cands = [k7.write_archive(self.run_dir + '/pkgs/' + k7.filename()),
                      b_new.write_archive(self.run_dir + '/pkgs/' + b_new.filename())]
        self.origs = [k6.write_archive(self.run_dir + '/originals/' + k6.filename()),
                      {'name': 'omarchy-mac-boot', 'version': None}]
        self.pkgs = {'k6': k6, 'k7': k7, 'b_new': b_new}
        self.parkable = ['EFI/Linux/siliconforest-mixtape-77648eb77168.efi']
        self._finish_units()

    def air_menu(self, name):
        raw = rd(os.path.join(AIR_DIR, name))
        return (raw.replace(AIR_UKI_SHA.encode(), sha(self.uki).encode())
                   .replace(AIR_UKI_B2.encode(), b2(self.uki).encode())
                   .replace(AIR_SF_B2.encode(), b2(self.sf).encode()))

    def _write_config(self, over):
        cfg = {
            'schema': 'bt2.target-config/1', 'run_id': RUN_ID, 'device': self.profile, 'board': self.board,
            'known_good_kernel': self.uname, 'gui_user': 'chrisk', 'gui_uid': 1000, 'esp': '/boot/efi',
            'esp_reserve_bytes': 125829120, 'root_reserve_bytes': 2147483648,
            'candidates': self.cands, 'originals': self.origs,
            'artifact_shas': {p['file']: p['sha256'] for p in self.cands + self.origs if p.get('file')},
            'writer_units': ['limine-snapper-sync.service', 'limine-snapper-watcher.service',
                             'snapper-timeline.timer', 'snapper-cleanup.timer'],
            'etc_capture': ['/etc/pacman.conf', '/etc/default/limine', '/etc/limine-entry-tool.conf',
                            '/etc/limine-entry-tool.d', '/etc/default/update-m1n1', '/etc/m1n1.conf',
                            '/etc/mkinitcpio.conf', '/etc/mkinitcpio.conf.d', '/etc/mkinitcpio.d',
                            '/etc/systemd/system'],
            'allow_bootbin_change': False, 'expected_bootbin_sha256': sha(self.read('/boot/efi/m1n1/boot.bin')),
            'parkable': self.parkable, 'peak_bytes': 67108864,
            'test_esp_free': 400 * MiB, 'test_root_free': 10 << 30,
        }
        cfg.update(over)
        with open(self.run_dir + '/config.json', 'w') as f:
            json.dump(cfg, f, indent=1, sort_keys=True)


def m1_menu(mid, uuid, uki_b2, sf_b2):
    return ('''timeout: 3
default_entry: Omarchy/linux-aurora
interface_branding: Omarchy Bootloader
hash_mismatch_panic: no

/+Omarchy
### This OS entry is auto-generated by limine-entry-tool
comment: Omarchy
comment: machine-id=%(mid)s order-priority=50
  //linux-aurora
  ### This kernel entry is auto-generated by limine-entry-tool
  comment: Kernel version: 7.2.11-6-1-ARCH
  comment: kernel-id=linux-aurora
  protocol: efi
  path: boot():/EFI/Linux/omarchy_linux-aurora.efi#%(uki)s
  cmdline: root=UUID=%(uuid)s rw rootflags=subvol=@ loglevel=3 quiet splash

/SiliconForest - kernel 177+182
    comment: Local 177+182 M1 kernel; previous boot entries retained
    protocol: efi
    path: boot():/EFI/Linux/siliconforest-normal-205f5e8b20fc.efi#%(sf)s

/Omacom Edge - aurora6
    comment: Omacom Edge aurora6; previous kernel retained
    protocol: efi
    path: boot():/EFI/Linux/omarchy_linux-aurora.efi#%(uki)s

%(lab)s
%(end)s
''' % {'mid': mid, 'uuid': uuid, 'uki': uki_b2, 'sf': sf_b2, 'lab': LAB_BEGIN, 'end': LAB_END}).encode()


def m3_menu(mid, uuid, stock_b2, custom_b2, mix_b2):
    return ('''timeout: 3
default_entry: Omacom Edge - aurora6 M3 GPU
interface_branding: SiliconForest Linux
hash_mismatch_panic: no

/+SiliconForest Linux
### This OS entry is auto-generated by limine-entry-tool
comment: SiliconForest Linux
comment: machine-id=%(mid)s order-priority=50
  //linux-aurora
  ### This kernel entry is auto-generated by limine-entry-tool
  comment: Kernel version: 7.2.11-6-1-ARCH
  comment: kernel-id=linux-aurora
  protocol: efi
  path: boot():/EFI/Linux/omarchy_linux-aurora.efi#%(stock)s
  cmdline: root=UUID=%(uuid)s rw rootflags=subvol=@ quiet

/Omacom Edge - aurora6 M3 GPU
    comment: custom lab kernel 7876
    protocol: efi
    path: boot():/EFI/Linux/omacom-aurora6-m3.efi#%(custom)s
    cmdline: root=UUID=%(uuid)s rw rootflags=subvol=@ video=HDMI-A-1:1920x1080@60

/SiliconForest - kernel 177+182+187
    protocol: efi
    path: boot():/EFI/Linux/siliconforest-mixtape-77648eb77168.efi#%(mix)s

/GRUB (M3 bring-up kernels)
    protocol: efi
    path: boot():/EFI/grub/grubaa64.efi

%(lab)s
%(end)s
''' % {'mid': mid, 'uuid': uuid, 'stock': stock_b2, 'custom': custom_b2, 'mix': mix_b2, 'lab': LAB_BEGIN,
       'end': LAB_END}).encode()
