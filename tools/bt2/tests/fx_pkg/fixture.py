"""Fake-root builder for bt2 I2 tests (pkg.py install/rollback, writers.py hold/release).

Everything lives under /dev/shm/maclab-bt2-tests/i2-*/root (a tree that mirrors /). Packages are real
.pkg.tar.zst archives installed by the fake pacman into a real-format local DB. capture/state.json is built here
per CONTRACT.md (capture.py is written by another agent), hashing module trees with the target's own functions.
"""
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, 'bin')
# the target tree under test: BT2_TARGET, else this checkout's own target/ (never a historical copy)
TARGET = os.environ.get('BT2_TARGET') or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'target')
SCRATCH = '/dev/shm/maclab-bt2-tests'
sys.path.insert(0, HERE)
if TARGET not in sys.path:
    sys.path.insert(0, TARGET)
import fakebin  # noqa: E402
import limine  # noqa: E402  (target copy)
import pkg as tpkg  # noqa: E402  (target copy: same tree hashing as install/rollback)

K6 = '7.2.11-6-1-ARCH'
K7 = '7.2.11-7-1-ARCH'
KM3 = '7.2.11-lab7876c8e8-cc71'
KERYK = '7.1.12-labf08d2b6f-049a'
MESA_OLD = '1:26.3.0_devel.20261025.147a62f6190-1'
MESA_NEW = '1:26.3.0_devel.20261025.231095.7c86130d26c-1'
WRITERS = ['limine-snapper-sync.service', 'limine-snapper-watcher.service', 'snapper-timeline.timer',
           'snapper-cleanup.timer']
CMDLINE = fakebin.UKI_CMDLINE
MTIME = 1700000000

PACMAN_CONF = b"""#
# /etc/pacman.conf
#
# See the pacman.conf(5) manpage for option and repository directives

#
# GENERAL OPTIONS
#
[options]
HoldPkg     = pacman glibc
Architecture = auto
CheckSpace
ParallelDownloads = 5
# By default, pacman accepts packages signed by keys that its local keyring
SigLevel    = Required DatabaseOptional
LocalFileSigLevel = Optional

#
# REPOSITORIES
#
[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[asahi-alarm]
Server = https://example.invalid/$arch/$repo
"""


def sha(b):
    return hashlib.sha256(b).hexdigest()


def rd(p):
    with open(p, 'rb') as f:
        return f.read()


def wr(p, data, mode=0o644, mtime=None):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'wb') as f:
        f.write(data)
    os.chmod(p, mode)
    if mtime is not None:
        os.utime(p, (mtime, mtime))


def make_pkg(out_dir, name, version, files, depends=(), backup=()):
    """files: {rel: bytes | ('f', mode, bytes) | ('l', 0o777, target) | ('d', mode, None)} -> (file, sha, size)."""
    entries = {}
    for rel, spec in files.items():
        parts = rel.split('/')
        for i in range(1, len(parts)):
            entries.setdefault('/'.join(parts[:i]), ('d', 0o755, None))
        entries[rel] = ('f', 0o644, spec) if isinstance(spec, bytes) else spec
    info = ['pkgname = %s' % name, 'pkgbase = %s' % name, 'pkgver = %s' % version, 'arch = aarch64']
    info += ['depend = %s' % d for d in depends] + ['backup = %s' % b for b in backup]
    mt = ['#mtree']
    for rel in sorted(entries):
        t, mode, data = entries[rel]
        kind = {'f': 'file', 'l': 'link', 'd': 'dir'}[t]
        extra = ' sha256digest=%s' % sha(data) if t == 'f' else (' link=%s' % data if t == 'l' else '')
        mt.append('./%s time=%d.0 mode=%o type=%s%s' % (rel, MTIME, mode, kind, extra))
    mtree = gzip.compress(('\n'.join(mt) + '\n').encode(), mtime=0)
    fn = '%s-%s-aarch64.pkg.tar.zst' % (name, version)
    path = os.path.join(out_dir, fn)
    os.makedirs(out_dir, exist_ok=True)
    with tarfile.open(path, 'w:zst') as tf:
        def add(n, data=None, kind='f', mode=0o644, link=None):
            ti = tarfile.TarInfo(n)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = 'root'
            ti.mtime = MTIME
            ti.mode = mode
            if kind == 'd':
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif kind == 'l':
                ti.type = tarfile.SYMTYPE
                ti.linkname = link
                tf.addfile(ti)
            else:
                ti.size = len(data)
                import io
                tf.addfile(ti, io.BytesIO(data))
        add('.PKGINFO', ('\n'.join(info) + '\n').encode())
        add('.MTREE', mtree)
        for rel in sorted(entries):
            t, mode, data = entries[rel]
            if t == 'd':
                add(rel, kind='d', mode=mode)
            elif t == 'l':
                add(rel, kind='l', mode=0o777, link=data)
            else:
                add(rel, data, mode=mode)
    b = rd(path)
    return {'name': name, 'version': version, 'file': fn, 'sha256': sha(b), 'bytes': len(b)}


def kernel_files(krel, tag, dtb=b'DTB-j293-v1'):
    m = 'usr/lib/modules/%s/' % krel
    return {m + 'vmlinuz': b'vmlinuz-' + tag.encode() * 64, m + 'pkgbase': b'linux-aurora\n',
            m + 'kernel/drivers/gpu/asahi.ko': b'asahi.ko ' + tag.encode(),
            m + 'kernel/drivers/net/brcmfmac.ko': b'brcmfmac.ko ' + tag.encode(),
            m + 'modules.builtin': b'kernel/drivers/base.ko\n', m + 'dtbs/apple/t8103-j293.dtb': dtb,
            m + 'source': ('l', 0o777, 'build')}


def header_files(krel, tag):
    m = 'usr/lib/modules/%s/build/' % krel
    return {m + 'Makefile': b'# kernel Makefile ' + tag.encode(), m + '.config': b'CONFIG_X=y # ' + tag.encode(),
            m + 'include/linux/version.h': b'#define VER "' + tag.encode() + b'"'}


def base_packages(cache):
    return [
        make_pkg(cache, 'limine-snapper-sync', '1.9.0-1', {
            'usr/lib/systemd/system/limine-snapper-sync.service': b'[Service]\nExecStart=/usr/bin/limine-snapper-watcher\n[Install]\nAlias=limine-snapper-watcher.service\n',
            'usr/bin/limine-snapper-watcher': ('f', 0o755, b'#!/bin/sh\n')}),
        make_pkg(cache, 'snapper', '0.11.2-1', {
            'usr/lib/systemd/system/snapper-timeline.timer': b'[Timer]\nOnCalendar=hourly\n',
            'usr/lib/systemd/system/snapper-timeline.service': b'[Service]\nType=oneshot\n',
            'usr/lib/systemd/system/snapper-cleanup.timer': b'[Timer]\nOnUnitActiveSec=1d\n',
            'usr/lib/systemd/system/snapper-cleanup.service': b'[Service]\nType=oneshot\n'}),
        make_pkg(cache, 'kernel-modules-hook', '0.1.7-1', {
            'usr/lib/systemd/system/linux-modules-cleanup.service': b'[Service]\nType=oneshot\n',
            'usr/share/libalpm/hooks/10-linux-modules-pre.hook': b'[Trigger]\n',
            'usr/share/libalpm/hooks/10-linux-modules-post.hook': b'[Trigger]\n'}),
    ]


class Lab:
    def __init__(self, name, krel, device, board):
        os.makedirs(SCRATCH, exist_ok=True)
        self.base = tempfile.mkdtemp(prefix='i2-%s-' % name, dir=SCRATCH)
        self.root = self.base + '/root'
        self.run_id = 'i2t-%s-%s' % (name, os.path.basename(self.base)[-6:].lower().replace('_', '0'))
        self.run_id = ''.join(ch if ch.isalnum() or ch == '-' else '0' for ch in self.run_id.lower())
        self.run_sys = '/var/lib/maclab/bt2/' + self.run_id
        self.run = self.root + self.run_sys
        self.krel = krel
        self.device = device
        self.board = board
        self.boot_id = '11111111-2222-3333-4444-555555555555'
        for d in ('/etc/systemd/system', '/etc/default', '/usr/lib/systemd/system', '/usr/lib/modules',
                  '/var/lib/pacman/local', '/var/lib/pacman/sync', '/var/cache/fixture', '/run/lock',
                  '/boot/efi/EFI/Linux', '/boot/efi/EFI/BOOT', '/boot/efi/m1n1', '/boot/efi/maclab',
                  '/proc/sys/kernel/random', '/proc/device-tree', '/.fake', self.run_sys + '/pkgs',
                  self.run_sys + '/originals', self.run_sys + '/capture'):
            os.makedirs(self.root + d, exist_ok=True)
        wr(self.R('/proc/sys/kernel/random/boot_id'), (self.boot_id + '\n').encode())
        wr(self.R('/proc/cmdline'), ('root=UUID=4f4d5801 rw quiet splash\n').encode())
        wr(self.R('/proc/device-tree/compatible'), board.encode() + b'\0apple,arm-platform\0')
        wr(self.R('/etc/pacman.conf'), PACMAN_CONF)
        wr(self.R('/var/lib/pacman/local/ALPM_DB_VERSION'), b'9\n')

    # -- plumbing --------------------------------------------------------------------------------
    def R(self, p):
        return self.root + p

    def env(self, **kw):
        e = {'PATH': BIN + ':/usr/bin:/bin', 'BT2_TEST_ROOT': self.root, 'BT2_TEST_BIN': BIN,
             'BT2_TEST_UNAME_R': self.krel, 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
        e.update({k: str(v) for k, v in kw.items()})
        return e

    def target(self, cmd, **kw):
        r = subprocess.run([sys.executable, '-I', '-B', TARGET, cmd, '--run-dir', self.run_sys],
                           capture_output=True, env=self.env(**kw), timeout=900)
        lines = r.stdout.decode(errors='replace').strip().splitlines()
        try:
            res = json.loads(lines[-1]) if lines else None
        except ValueError:
            res = None
        return r.returncode, res, r

    def fake(self, prog, *args, **kw):
        return subprocess.run([os.path.join(BIN, prog), *args], capture_output=True, env=self.env(**kw), timeout=120)

    def pacman_install(self, pkgs):
        paths = ['/var/cache/fixture/' + p['file'] for p in pkgs]
        r = self.fake('pacman', '-U', '--noconfirm', '--', *paths, BT2_FAKE_NO_HOOKS=1)
        assert r.returncode == 0, r.stderr.decode()

    def versions(self):
        r = self.fake('pacman', '-Q')
        return dict(line.split() for line in r.stdout.decode().splitlines())

    def sd(self):
        with open(self.R('/.fake/systemd.json')) as f:
            return json.load(f)

    def sd_set(self, unit, **kv):
        sd = self.sd()
        sd['units'].setdefault(unit, {}).update(kv)
        fakebin.atomic_write(self.R('/.fake/systemd.json'), json.dumps(sd, indent=1, sort_keys=True).encode())

    def systemctl_log(self):
        p = self.R('/.fake/systemctl.log')
        if not os.path.exists(p):
            return []
        return [json.loads(x)['argv'] for x in rd(p).decode().splitlines()]

    def show(self, unit):
        r = self.fake('systemctl', 'show', unit)
        return dict(line.split('=', 1) for line in r.stdout.decode().splitlines() if '=' in line)

    def cleanup(self):
        if not os.environ.get('BT2_KEEP'):
            shutil.rmtree(self.base, ignore_errors=True)

    # -- building blocks -------------------------------------------------------------------------
    def systemd(self, active):
        """active: {unit: (ActiveState, UnitFileState)} for the writer + cleanup units."""
        units = {}
        for u, (a, ufs) in active.items():
            units[u] = {'ActiveState': a, 'SubState': {'active': 'running', 'inactive': 'dead'}.get(a, a),
                        'UnitFileState': ufs, 'FragmentPath': '/usr/lib/systemd/system/' + u, 'DropInPaths': ''}
        units['linux-modules-cleanup.service']['DropInPaths'] = \
            '/etc/systemd/system/linux-modules-cleanup.service.d/zz-keep-local-kernels.conf'
        sd = {'units': units, 'aliases': {'limine-snapper-watcher.service': 'limine-snapper-sync.service'},
              'views': {}}
        fakebin.atomic_write(self.R('/.fake/systemd.json'), json.dumps(sd, indent=1, sort_keys=True).encode())
        etc = self.R('/etc/systemd/system')
        os.symlink('/usr/lib/systemd/system/limine-snapper-sync.service', etc + '/limine-snapper-watcher.service')
        os.makedirs(etc + '/multi-user.target.wants')
        os.symlink('/usr/lib/systemd/system/limine-snapper-sync.service',
                   etc + '/multi-user.target.wants/limine-snapper-sync.service')
        wr(etc + '/linux-modules-cleanup.service.d/zz-keep-local-kernels.conf',
           b'[Service]\nExecStart=\nExecStart=/bin/sh -c "... skip trees with .keep-local-kernel ..."\n')
        assert self.fake('systemctl', 'daemon-reload').returncode == 0

    def esp(self, menu_text, files):
        for rel, data in files.items():
            wr(self.R('/boot/efi/' + rel), data, mtime=MTIME)
        wr(self.R('/boot/efi/limine.conf'), menu_text.encode(), mtime=MTIME)

    def config(self, candidates, originals, **kw):
        cfg = {'schema': 'bt2.target-config/1', 'run_id': self.run_id, 'device': self.device, 'board': self.board,
               'known_good_kernel': self.krel, 'gui_user': 'chrisk', 'gui_uid': 1000, 'esp': '/boot/efi',
               'esp_reserve_bytes': 125829120, 'root_reserve_bytes': 2147483648, 'candidates': candidates,
               'originals': originals,
               'artifact_shas': {p['file']: p['sha256'] for p in candidates + originals if p.get('file')},
               'writer_units': list(WRITERS), 'etc_capture': ['/etc/pacman.conf', '/etc/default/update-m1n1'],
               'allow_bootbin_change': False,
               'expected_bootbin_sha256': sha(rd(self.R('/boot/efi/m1n1/boot.bin')))}
        cfg.update(kw)
        for p in candidates:
            shutil.copy2(self.R('/var/cache/fixture/' + p['file']), self.run + '/pkgs/' + p['file'])
        for p in originals:
            if p.get('file'):
                shutil.copy2(self.R('/var/cache/fixture/' + p['file']), self.run + '/originals/' + p['file'])
        self.cfg = cfg
        wr(self.run + '/config.json', (json.dumps(cfg, indent=1, sort_keys=True) + '\n').encode(), 0o600)
        return cfg

    # -- capture (CONTRACT bt2.capture/1 subset that pkg/writers read) ---------------------------
    def capture(self):
        cfg = self.cfg
        st = {'schema': 'bt2.capture/1', 'run_id': self.run_id, 'device': self.device, 'boot_id': self.boot_id,
              'kernel': self.krel, 'board': self.board, 'captured_at': time.time()}
        allp = self.versions()
        st['packages_all'] = allp
        cand_names = {p['name'] for p in cfg['candidates']}
        named = sorted(cand_names | {p['name'] for p in cfg['originals']})
        pk = {}
        for n in named:
            v = allp.get(n)
            files = self.fake('pacman', '-Qlq', n).stdout.decode().split() if v else []
            mt = self.R('/var/lib/pacman/local/%s-%s/mtree' % (n, v)) if v else None
            pk[n] = {'version': v, 'mtree_sha256': sha(gzip.decompress(rd(mt))) if v else None, 'files': files}
        st['packages'] = pk
        st['backup_files'] = []
        archives = [fakebin.Archive(self.run + '/pkgs/' + p['file']) for p in cfg['candidates']] + \
            [fakebin.Archive(self.run + '/originals/' + p['file']) for p in cfg['originals'] if p.get('file')]
        krels = {self.krel} | {k for a in archives for k in a.kernels()}
        mods = {}
        for k in sorted(krels):
            d = self.R('/usr/lib/modules/' + k)
            if not os.path.isdir(d):
                continue
            rows = tpkg._TREE(d)
            r = self.fake('pacman', '-Qqo', '/usr/lib/modules/' + k)
            mods[k] = {'owned_by': r.stdout.decode().split() if r.returncode == 0 else [],
                       'keep_marker': os.path.lexists(d + '/.keep-local-kernel'),
                       'tree_sha256': tpkg._TSHA(rows), 'entries': len(rows)}
        st['modules'] = mods
        owned = mods[self.krel]['owned_by']
        copy = None
        if set(owned) & cand_names:
            os.makedirs(self.run + '/capture/modules', exist_ok=True)
            copy = 'capture/modules/%s.tar' % self.krel
            with tarfile.open(self.run + '/' + copy, 'w') as tf:
                tf.add(self.R('/usr/lib/modules/' + self.krel), arcname=self.krel)
        st['running_kernel'] = {'krel': self.krel, 'owned_by': owned, 'copy': copy}
        esp = self.R('/boot/efi')
        files, dirs = {}, []
        for base, ds, fs in os.walk(esp):
            rb = os.path.relpath(base, esp)
            rb = '' if rb == '.' else rb + '/'
            ds[:] = sorted(d for d in ds if rb + d != 'maclab')
            dirs += [rb + d for d in ds]
            for fn in fs:
                rel = rb + fn
                if fn.startswith('ubootefi.var') and not rb:
                    continue
                s = os.lstat(os.path.join(base, fn))
                files[rel] = {'size': s.st_size, 'sha256': sha(rd(os.path.join(base, fn))), 'mtime_ns': s.st_mtime_ns}
                dst = self.run + '/capture/esp/' + rel
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(os.path.join(base, fn), dst)
        sv = os.statvfs(esp)
        st['esp'] = {'root': '/boot/efi', 'free': sv.f_bavail * sv.f_frsize, 'excluded': ['ubootefi.var*', 'maclab/'],
                     'files': files, 'dirs': dirs, 'info': {'ubootefi.var': None}}
        raw = rd(esp + '/limine.conf')
        m = limine.Menu(raw)
        d = m.default()
        rel, pin = limine.split_path(d.path())
        st['menu'] = {'sha256': sha(raw), 'bytes': len(raw), 'default': {
            'name': d.fullname, 'path': rel, 'uki_sha256': sha(rd(esp + '/' + rel)),
            'uki_b2': hashlib.blake2b(rd(esp + '/' + rel), digest_size=64).hexdigest(),
            'cmdline': d.opts.get('cmdline', (None, None))[1], 'auto_entry': d.parent is not None}}
        st['bootbin_sha256'] = sha(rd(esp + '/m1n1/boot.bin'))
        st['etc'] = {}
        units = list(cfg['writer_units']) + ['snapper-cleanup.service', 'snapper-timeline.service',
                                             'linux-modules-cleanup.service']
        for a in archives:
            for n, t, _, _, _ in a.entries:
                if t == 'f' and n.startswith('usr/lib/systemd/system/') and n.count('/') == 4:
                    units.append(n.rsplit('/', 1)[1])
        st['units'] = {}
        for u in sorted(set(units)):
            s = self.show(u)
            st['units'][u] = {k: s.get(k, '') for k in ('LoadState', 'ActiveState', 'UnitFileState',
                                                         'FragmentPath', 'DropInPaths')}
        st['systemd_etc'] = {}
        st['efivars'] = {'LoaderEntryOneShot': False, 'LoaderEntryDefault': False}
        st['snapshots'], st['limine_history'] = [], {}
        conflicts = []
        for p in cfg['candidates']:
            a = fakebin.Archive(self.run + '/pkgs/' + p['file'])
            for n, t, _, _, _ in a.entries:
                live = self.R('/' + n)
                if t != 'f' or not os.path.lexists(live):
                    continue
                if self.fake('pacman', '-Qqo', '/' + n).returncode == 0:
                    continue
                s = os.lstat(live)
                conflicts.append({'path': '/' + n, 'package': p['name'], 'sha256': sha(rd(live)),
                                  'mode': s.st_mode & 0o7777, 'uid': s.st_uid, 'gid': s.st_gid,
                                  'mtime_ns': s.st_mtime_ns})
        st['conflicts'] = conflicts
        st['known_good_refs'], st['originals_verified'] = {}, {}
        st['copies'] = {'esp': 'capture/esp', 'etc': 'capture/etc'}
        self.state = st
        wr(self.run + '/capture/state.json', (json.dumps(st, indent=1, sort_keys=True) + '\n').encode(), 0o600)
        return st

    def run8(self):
        return self.cfg.get('run8') or sha(self.run_id.encode())[:8]

    def esp_prep_fallback(self):
        """What esp-prep (another agent) does for an auto-entry default: copy + stanza + default repoint."""
        run8 = self.run8()
        esp = self.R('/boot/efi')
        raw = rd(esp + '/limine.conf')
        m = limine.Menu(raw)
        d = m.default()
        rel, _ = limine.split_path(d.path())
        data = rd(esp + '/' + rel)
        copy = 'EFI/Linux/bt2-%s-original.efi' % run8
        wr(esp + '/' + copy, data)
        name = 'bt2 original %s' % run8
        before = m.globals['default_entry'][1]
        m.insert_entry_before_lab(name, [('protocol', 'efi'), ('path', limine.join_path(copy, data)),
                                         ('cmdline', d.opts['cmdline'][1])])
        m.set_global('default_entry', name)
        wr(esp + '/limine.conf', m.raw())
        # receipt shape written by target/espops.py prep()
        prep = {'status': 'done', 'run_id': self.run_id, 'run8': run8, 'auto_entry': True, 'parked': [],
                'fallback': {'path': copy, 'entry': name, 'sha256': sha(data), 'b2': fakebin.b2(data),
                             'bytes': len(data), 'source': rel},
                'default_before': {'name': d.fullname, 'path': rel, 'uki_sha256': sha(data), 'was': before},
                'default_after': {'name': name, 'path': copy}, 'menu_after_sha256': sha(m.raw())}
        wr(self.run + '/espops-prep.json', json.dumps(prep).encode(), 0o600)
        return prep

    def esp_prep_custom(self, status='done'):
        """espops.py receipt for a custom (non-auto) default: no copy, default kept."""
        st = self.state['menu']['default']
        prep = {'status': status, 'run_id': self.run_id, 'run8': self.run8(), 'auto_entry': False, 'parked': [],
                'fallback': None, 'default_before': {'name': st['name'], 'path': st['path']},
                'default_after': {'name': st['name'], 'path': st['path']}}
        wr(self.run + '/espops-prep.json', json.dumps(prep).encode(), 0o600)
        return prep

    def snapshot(self, subs=('/usr', '/etc', '/var/lib/pacman/local'), skip=()):
        out = {}
        for s in subs:
            top = self.R(s)
            for base, ds, fs in os.walk(top):
                ds.sort()
                for n in ds + sorted(fs):
                    p = os.path.join(base, n)
                    rel = p[len(self.root):]
                    if any(rel == k or rel.startswith(k + '/') for k in skip):
                        continue
                    st = os.lstat(p)
                    if os.path.islink(p):
                        out[rel] = ('l', os.readlink(p))
                    elif os.path.isdir(p):
                        out[rel] = ('d', st.st_mode & 0o7777)
                    else:
                        out[rel] = ('f', st.st_mode & 0o7777, sha(rd(p)))
        return out


def menu(os_name, machine, kernels, extra_stanzas, default):
    """kernels: [(pkg, krel, uki_rel, uki_bytes)]"""
    lines = ['timeout: 3', 'default_entry: ' + default, 'hash_mismatch_panic: no', '', '/+' + os_name,
             '### This OS entry is auto-generated by limine-entry-tool', 'comment: ' + os_name,
             'comment: machine-id=%s order-priority=50 ' % machine]
    for p, k, rel, data in kernels:
        lines += ['  //' + p, '  ### This kernel entry is auto-generated by limine-entry-tool',
                  '  comment: Kernel version: ' + k, '  comment: kernel-id=%s ' % p, '  protocol: efi',
                  '  path: boot():/%s#%s' % (rel, fakebin.b2(data)), '  cmdline: ' + CMDLINE]
    for name, rel, data, cmd in extra_stanzas:
        lines += ['', '/' + name, '    comment: hand-written entry', '    protocol: efi',
                  '    path: boot():/%s#%s' % (rel, fakebin.b2(data))]
        if cmd:
            lines.append('    cmdline: ' + cmd)
    lines += ['', '# maclab: begin. Managed by lab-agent: staged test kernels, booted once via LoaderEntryOneShot.',
              '# maclab: end', '']
    return '\n'.join(lines)


# -- scenarios ------------------------------------------------------------------------------------
def m1_lab(name):
    """M1-like: package-owned running kernel 6-1, boot package installed, auto-entry default (fallback copy)."""
    lab = Lab(name, K6, 'm1', 'apple,j293')
    cache = lab.R('/var/cache/fixture')
    base = base_packages(cache)
    orig = [
        make_pkg(cache, 'linux-aurora', '7.2.11.aurora6-1', kernel_files(K6, 'six')),
        make_pkg(cache, 'linux-aurora-headers', '7.2.11.aurora6-1', header_files(K6, 'six')),
        make_pkg(cache, 'mesa-aurora', MESA_OLD, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 147a',
                                                  'usr/lib/libEGL_mesa.so.0.0.0': b'egl 147a'}),
        make_pkg(cache, 'vulkan-aurora', MESA_OLD, {'usr/lib/libvulkan_asahi.so': b'vk 147a'}),
        make_pkg(cache, 'omarchy-mac-boot', '20261010-1', {
            'usr/bin/update-m1n1': ('f', 0o755, b'#!/bin/sh\n# update-m1n1 old\n'),
            'etc/default/update-m1n1': b'M1N1_UPDATE=1\n',
            'usr/lib/systemd/system/omarchy-mac-efi-vars.service': b'[Service]\nType=oneshot\n',
            'usr/share/libalpm/hooks/95-m1n1-install.hook': b'[Trigger]\nTarget = usr/lib/modules/*/dtbs/*\n'},
            backup=['etc/default/update-m1n1']),
    ]
    cand = [
        make_pkg(cache, 'linux-aurora', '7.2.11.aurora7-1', kernel_files(K7, 'seven')),
        make_pkg(cache, 'linux-aurora-headers', '7.2.11.aurora7-1', header_files(K7, 'seven')),
        make_pkg(cache, 'mesa-aurora', MESA_NEW, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 7c86',
                                                  'usr/lib/libEGL_mesa.so.0.0.0': b'egl 7c86',
                                                  'usr/lib/libdril_dri.so': b'dril 7c86'}),
        make_pkg(cache, 'vulkan-aurora', MESA_NEW, {'usr/lib/libvulkan_asahi.so': b'vk 7c86'}),
        make_pkg(cache, 'omarchy-mac-boot', '20261026-1', {
            'usr/bin/update-m1n1': ('f', 0o755, b'#!/bin/sh\n# update-m1n1 new\n'),
            'etc/default/update-m1n1': b'M1N1_UPDATE=1\n',
            'usr/lib/systemd/system/omarchy-mac-efi-vars.service': b'[Service]\nType=oneshot\n',
            'usr/share/libalpm/hooks/95-m1n1-install.hook': b'[Trigger]\nTarget = usr/lib/modules/*/dtbs/*\n',
            'usr/share/omarchy-mac-boot/dtb-overlays/README': b'overlays\n'},
            backup=['etc/default/update-m1n1']),
    ]
    lab.pacman_install(base + orig)
    fakebin_root(lab, lambda: fakebin.depmod(K6))
    vml = rd(lab.R('/usr/lib/modules/%s/vmlinuz' % K6))
    uki = fakebin.build_uki(K6, vml)
    lab.esp(menu('Omarchy', '1acdf795aaaa', [('linux-aurora', K6, 'EFI/Linux/omarchy_linux-aurora.efi', uki)],
                 [('Omacom Edge - aurora6', 'EFI/Linux/omarchy_linux-aurora.efi', uki, None)], 'Omarchy/linux-aurora'),
            {'EFI/Linux/omarchy_linux-aurora.efi': uki, 'EFI/BOOT/BOOTAA64.EFI': b'limine efi',
             'm1n1/boot.bin': b'm1n1 stage2 + dtbs + u-boot (54fa)', 'm1n1/boot.bin.old': b'm1n1 older (fc1d)',
             'ubootefi.var': b'uboot vars', 'maclab/agent.marker': b'lab agent'})
    lab.systemd({'limine-snapper-sync.service': ('active', 'enabled'), 'snapper-timeline.timer': ('inactive', 'disabled'),
                 'snapper-cleanup.timer': ('active', 'enabled'), 'snapper-cleanup.service': ('inactive', 'static'),
                 'snapper-timeline.service': ('inactive', 'static'),
                 'linux-modules-cleanup.service': ('active', 'enabled')})
    lab.config(cand, orig)
    return lab


def m3_lab(name):
    """M3-like: custom unowned running kernel with a pre-existing marker, boot package ABSENT, 2 unowned files at
    boot-package paths, linux-m3-eryk installed (boot-package install rebuilds an extra Eryk UKI), custom default."""
    lab = Lab(name, KM3, 'm3pro', 'apple,j516s')
    cache = lab.R('/var/cache/fixture')
    base = base_packages(cache) + [make_pkg(cache, 'linux-m3-eryk', '20261001-1', {
        'usr/lib/modules/%s/vmlinuz' % KERYK: b'vmlinuz-eryk' * 32,
        'usr/lib/modules/%s/kernel/drivers/eryk.ko' % KERYK: b'eryk.ko'})]
    orig = [
        make_pkg(cache, 'linux-aurora', '7.2.11.aurora6-1', kernel_files(K6, 'six', b'DTB-j516s-v1')),
        make_pkg(cache, 'mesa-aurora', MESA_OLD, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 147a'}),
    ]
    boot = make_pkg(cache, 'omarchy-mac-boot', '20261026-1', {
        'usr/bin/update-m1n1': ('f', 0o755, b'#!/bin/sh\n# update-m1n1 new\n'),
        'etc/default/update-m1n1': b'M1N1_UPDATE=1 # package default\n',
        'etc/systemd/system/omarchy-vendor-firmware.service': b'[Unit]\nDescription=vendor fw (package)\n',
        'usr/lib/systemd/system/omarchy-mac-efi-vars.service': b'[Service]\nType=oneshot\n'},
        backup=['etc/default/update-m1n1'])
    cand = [
        make_pkg(cache, 'linux-aurora', '7.2.11.aurora7-1', kernel_files(K7, 'seven', b'DTB-j516s-v1')),
        make_pkg(cache, 'mesa-aurora', MESA_NEW, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 7c86'}),
        boot,
    ]
    lab.pacman_install(base + orig)
    fakebin_root(lab, lambda: (fakebin.depmod(K6), fakebin.depmod(KERYK)))
    # custom unowned running tree with a pre-existing (not ours) marker
    m = lab.R('/usr/lib/modules/' + KM3)
    wr(m + '/vmlinuz', b'vmlinuz-custom-7876' * 16)
    wr(m + '/kernel/drivers/gpu/asahi.ko', b'asahi custom')
    wr(m + '/modules.dep', b'kernel/drivers/gpu/asahi.ko:\n')
    wr(m + '/.keep-local-kernel', b'')
    # unowned legacy files at boot-package paths (M3 has 5; two here)
    wr(lab.R('/etc/default/update-m1n1'), b'M1N1 local M3 config (unowned)\n', 0o644, MTIME - 5000)
    wr(lab.R('/etc/systemd/system/omarchy-vendor-firmware.service'), b'[Unit]\nDescription=local vendor fw\n',
       0o640, MTIME - 7000)
    stock = fakebin.build_uki(K6, rd(lab.R('/usr/lib/modules/%s/vmlinuz' % K6)))
    custom = b'CUSTOM-UKI-7876' * 64
    lab.esp(menu('SiliconForest Linux', 'cbb1e723aaaa', [('linux-aurora', K6, 'EFI/Linux/omarchy_linux-aurora.efi', stock)],
                 [('Omacom Edge - aurora6 M3 GPU', 'EFI/Linux/omacom-aurora6-m3.efi', custom,
                   'root=UUID=4f4d5801 rw video=HDMI-A-1:1920x1080@60')], 'Omacom Edge - aurora6 M3 GPU'),
            {'EFI/Linux/omarchy_linux-aurora.efi': stock, 'EFI/Linux/omacom-aurora6-m3.efi': custom,
             'EFI/BOOT/BOOTAA64.EFI': b'limine efi', 'm1n1/boot.bin': b'm1n1 + m1n1.conf trailer (e29f)',
             'ubootefi.var': b'uboot vars m3'})
    lab.systemd({'limine-snapper-sync.service': ('active', 'enabled'), 'snapper-timeline.timer': ('inactive', 'disabled'),
                 'snapper-cleanup.timer': ('active', 'enabled'), 'snapper-cleanup.service': ('inactive', 'static'),
                 'snapper-timeline.service': ('inactive', 'static'),
                 'linux-modules-cleanup.service': ('active', 'enabled')})
    lab.config(cand, orig + [{'name': 'omarchy-mac-boot', 'version': None}])
    return lab


def fakebin_root(lab, fn):
    """Run a fakebin helper in-process against this lab's root."""
    old = os.environ.get('BT2_TEST_ROOT')
    os.environ['BT2_TEST_ROOT'] = lab.root
    try:
        fn()
    finally:
        if old is None:
            os.environ.pop('BT2_TEST_ROOT', None)
        else:
            os.environ['BT2_TEST_ROOT'] = old
