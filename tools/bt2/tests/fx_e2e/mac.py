"""One fake lab Mac per scenario for the bt2 end-to-end test (tests/test_e2e.py).

The fake root lives under /dev/shm/maclab-bt2-tests/e2e-*/root. It is driven by fx_pkg's fake pacman (real-format
local DB, real .pkg.tar.zst extraction, install hooks: kernel-modules-hook, depmod, UKI + limine auto entry rewrite,
boot-package rebuild_all, efi-vars post_install) and fake systemctl (/.fake/systemd.json, masks/aliases from real
symlinks). On top of that this module simulates what happens BETWEEN target commands on a real Mac:
  - reboots: new boot_id, running kernel, tmpfs /run/lock wiped, units back to their boot state (masks honoured),
    linux-modules-cleanup.service moving unowned trees without .keep-local-kernel to /usr/lib/modules/.old;
  - the lab agent during a job: LoaderEntryOneShot set then consumed, ubootefi.var rewritten, maclab/ job files;
  - the controller's own steps (push config + target, upload/fetch archives, locks-after-job).
Config is built like bt2/controller.py make_config() from the real devices/<dev>.json (etc_capture, parkable,
writer_units), plus the test-only overrides test_esp_free / test_root_free.
"""
import fnmatch
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
BT2 = os.path.dirname(TESTS)
sys.path.insert(0, os.path.join(TESTS, 'fx_pkg'))
import fixture as fxp  # noqa: E402  (package builder; also imports the target's limine/pkg)
import fakebin  # noqa: E402

TARGET = os.path.join(BT2, 'target')
SCRATCH = '/dev/shm/maclab-bt2-tests'
BIN = fxp.BIN
K6, K7, KM3, KERYK = fxp.K6, fxp.K7, fxp.KM3, fxp.KERYK
MTIME = fxp.MTIME
MiB = 1 << 20
LAB_BEGIN = '# maclab: begin. Managed by lab-agent: staged test kernels, booted once via LoaderEntryOneShot.'
LAB_END = '# maclab: end'
EFIVAR = '/sys/firmware/efi/efivars/LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
DROPIN = '/etc/systemd/system/linux-modules-cleanup.service.d/zz-keep-local-kernels.conf'
LIB = '/usr/lib/systemd/system/'
# Whole-root comparison exclusions (SPEC 'audit' allowed differences + fake-machine internals):
#   /proc, /run (tmpfs), the run dir, /usr/lib/modules/.old (linux-modules-cleanup), ESP ubootefi.var* and maclab/
#   (lab-agent owned), /.fake (fake systemd/pacman state; unit states are compared through systemctl show instead).
EXCLUDE = ('/proc', '/run', '/.fake', '/usr/lib/modules/.old', '/boot/efi/maclab')
ESP = '/boot/efi'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def b2(b):
    return hashlib.blake2b(b, digest_size=64).hexdigest()


def rd(p):
    with open(p, 'rb') as f:
        return f.read()


def blob(tag, n):
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(b'%s:%d' % (tag.encode(), i)).digest()
        i += 1
    return bytes(out[:n])


def device_profile(dev):
    with open(os.path.join(BT2, 'tests', 'devices', dev + '.json')) as f:
        return json.load(f)


class Mac:
    def __init__(self, name, device, board, krel, machine_id):
        os.makedirs(SCRATCH, exist_ok=True)
        self.base = tempfile.mkdtemp(prefix='e2e-%s-' % name, dir=SCRATCH)
        self.root = self.base + '/root'
        tail = ''.join(ch for ch in os.path.basename(self.base)[-6:].lower() if ch.isalnum()) or 'x'
        self.run_id = 'bt2-e2e-%s-%s' % (name, tail)
        self.run_sys = '/var/lib/maclab/bt2/' + self.run_id
        self.run = self.root + self.run_sys
        self.device, self.board, self.krel, self.uname = device, board, krel, krel
        self.machine_id = machine_id
        self.prof = device_profile(device)
        self.calls = []            # (cmd, extra, exit code, result)
        self.events = []           # simulated boot-time / agent events
        self.boot_states = {}
        self.boot_id = None
        for d in ('/etc/systemd/system', '/etc/default', '/usr/lib/systemd/system', '/usr/lib/modules',
                  '/var/lib/pacman/local', '/var/lib/pacman/sync', '/var/cache/fixture', '/run/lock',
                  ESP + '/EFI/Linux', ESP + '/EFI/BOOT', ESP + '/m1n1', ESP + '/maclab', '/proc/sys/kernel/random',
                  '/proc/device-tree', '/sys/firmware/efi/efivars', '/.fake', '/.snapshots', '/var/lib/maclab/bt2'):
            os.makedirs(self.R(d), exist_ok=True)
        self.new_boot_id()
        self.wr('/proc/cmdline', b'root=UUID=4f4d5801-524f-4f54-8000-000000000001 rw rootflags=subvol=@ quiet\n')
        self.wr('/proc/device-tree/compatible', board.encode() + b'\0apple,arm-platform\0')
        self.wr('/etc/machine-id', (machine_id + '\n').encode())
        self.wr('/etc/pacman.conf', fxp.PACMAN_CONF, mtime=MTIME - 900)
        self.wr('/etc/pacman.d/mirrorlist', b'Server = https://example.invalid/$arch/$repo\n')
        self.wr('/etc/pacman.d/hooks/90-local.hook', b'[Trigger]\nOperation = Upgrade\n', mtime=MTIME - 800)
        self.wr('/etc/default/limine', b'TARGET_OS_NAME="Omarchy"\nENABLE_UKI=yes\n', mtime=MTIME - 700)
        self.wr('/etc/limine-entry-tool.conf', b'# limine-entry-tool\n', mtime=MTIME - 600)
        self.wr('/etc/mkinitcpio.conf', b'HOOKS=(base udev autodetect)\n', mtime=MTIME - 500)
        self.wr('/etc/mkinitcpio.conf.d/90-omarchy-mac.conf', b'MODULES+=(apple-dcp)\n', mtime=MTIME - 400)
        self.wr('/etc/mkinitcpio.d/linux-aurora.preset', b"PRESETS=('default')\n", mtime=MTIME - 300)
        self.wr('/var/lib/pacman/local/ALPM_DB_VERSION', b'9\n')
        self.wr('/var/lib/maclab/known-good.json', b'{"kernel": "%s"}\n' % krel.encode())
        self.wr('/var/lib/maclab/known-good.json.prev', b'{"kernel": "older"}\n')
        self.wr('/sys/firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c', b'\x07\0\0\0boot')
        for i in (1, 2):
            os.makedirs(self.R('/.snapshots/%d/snapshot' % i))

    # ------------------------------------------------------------------------------------ plumbing
    def R(self, p):
        return self.root + p

    def wr(self, p, data, mode=0o644, mtime=None):
        full = self.R(p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as f:
            f.write(data)
        os.chmod(full, mode)
        if mtime is not None:
            os.utime(full, (mtime, mtime))

    def env(self, **kw):
        e = {'PATH': BIN + ':/usr/bin:/bin', 'BT2_TEST_ROOT': self.root, 'BT2_TEST_BIN': BIN,
             'BT2_TEST_UNAME_R': self.uname, 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
        e.update({k: str(v) for k, v in kw.items()})
        return e

    def fake(self, prog, *args, **kw):
        return subprocess.run([os.path.join(BIN, prog), *args], capture_output=True, env=self.env(**kw), timeout=120)

    def target(self, cmd, *extra, **env):
        """Exactly as the controller: python3 -I -B <t> <cmd> --run-dir <run> --config-sha256 <sha> [extra]."""
        argv = [sys.executable, '-I', '-B', TARGET, cmd, '--run-dir', self.run_sys,
                '--config-sha256', self.cfg_sha, *extra]
        r = subprocess.run(argv, capture_output=True, env=self.env(**env), timeout=900)
        lines = r.stdout.decode(errors='replace').strip().splitlines()
        try:
            res = json.loads(lines[-1]) if lines else None
        except ValueError:
            res = None
        self.calls.append((cmd, list(extra), r.returncode, res))
        return r.returncode, res, r

    def versions(self):
        r = self.fake('pacman', '-Q')
        return dict(line.split() for line in r.stdout.decode().splitlines())

    def show(self, unit):
        r = self.fake('systemctl', 'show', unit)
        return dict(line.split('=', 1) for line in r.stdout.decode().splitlines() if '=' in line)

    def sd(self):
        with open(self.R('/.fake/systemd.json')) as f:
            return json.load(f)

    def sd_save(self, sd):
        fakebin.atomic_write(self.R('/.fake/systemd.json'), json.dumps(sd, indent=1, sort_keys=True).encode())

    def state(self):
        with open(self.run + '/capture/state.json') as f:
            return json.load(f)

    def cleanup(self):
        if not os.environ.get('BT2_KEEP'):
            shutil.rmtree(self.base, ignore_errors=True)

    # ------------------------------------------------------------------------------------ building
    def install_baseline(self, pkgs):
        paths = ['/var/cache/fixture/' + p['file'] for p in pkgs]
        r = self.fake('pacman', '-U', '--noconfirm', '--', *paths, BT2_FAKE_NO_HOOKS=1)
        assert r.returncode == 0, r.stderr.decode()

    def depmod(self, *krels):
        old = os.environ.get('BT2_TEST_ROOT')
        os.environ['BT2_TEST_ROOT'] = self.root
        try:
            for k in krels:
                fakebin.depmod(k)
        finally:
            if old is None:
                os.environ.pop('BT2_TEST_ROOT', None)
            else:
                os.environ['BT2_TEST_ROOT'] = old

    def systemd(self, units, boot_states):
        """units: {unit: (ActiveState, UnitFileState)}; boot_states: what runs after a boot, {unit: SubState}."""
        sd = {'units': {}, 'aliases': {'limine-snapper-watcher.service': 'limine-snapper-sync.service'}, 'views': {}}
        for u, (a, ufs) in units.items():
            sd['units'][u] = {'ActiveState': a, 'SubState': {'active': 'waiting' if u.endswith('.timer') else
                                                             'running', 'inactive': 'dead'}.get(a, a),
                              'UnitFileState': ufs, 'FragmentPath': LIB + u, 'DropInPaths': ''}
        sd['units']['linux-modules-cleanup.service']['DropInPaths'] = DROPIN
        self.sd_save(sd)
        self.boot_states = dict(boot_states)
        etc = self.R('/etc/systemd/system')
        os.symlink(LIB + 'limine-snapper-sync.service', etc + '/limine-snapper-watcher.service')
        os.makedirs(etc + '/multi-user.target.wants')
        os.symlink(LIB + 'limine-snapper-sync.service', etc + '/multi-user.target.wants/limine-snapper-sync.service')
        os.symlink(LIB + 'linux-modules-cleanup.service',
                   etc + '/multi-user.target.wants/linux-modules-cleanup.service')
        os.makedirs(etc + '/timers.target.wants')
        os.symlink(LIB + 'snapper-cleanup.timer', etc + '/timers.target.wants/snapper-cleanup.timer')
        self.wr(DROPIN, b'[Service]\nExecStart=\nExecStart=/usr/lib/kernel-modules-hook/cleanup '
                        b'--skip-marker .keep-local-kernel\n', mtime=MTIME - 200)
        for d in (etc + '/multi-user.target.wants', etc + '/timers.target.wants',
                  etc + '/linux-modules-cleanup.service.d', etc):
            os.utime(d, (MTIME - 100, MTIME - 100))
        assert self.fake('systemctl', 'daemon-reload').returncode == 0

    def esp(self, menu_text, files):
        for rel, data in files.items():
            self.wr(ESP + '/' + rel, data, mtime=MTIME)
        self.wr(ESP + '/limine.conf', menu_text.encode(), mtime=MTIME)

    def configure(self, candidates, originals, **kw):
        """controller make_config() + push (config.json, run dir 0700) + upload/fetch (archives into pkgs/originals)."""
        p = self.prof
        cands = sorted(candidates, key=lambda x: x['name'])
        cfg = {'schema': 'bt2.target-config/1', 'run_id': self.run_id, 'device': self.device, 'board': p['board'],
               'known_good_kernel': p['known_good_kernel'], 'gui_user': p['gui_user'], 'gui_uid': p['gui_uid'],
               'esp': p['esp'], 'esp_reserve_bytes': 125829120, 'root_reserve_bytes': 2147483648,
               'candidates': cands, 'originals': originals,
               'artifact_shas': {x['file']: x['sha256'] for x in cands + originals if x.get('file')},
               'writer_units': p['writer_units'], 'etc_capture': p['etc_capture'], 'parkable': p['parkable'],
               'boot_package': 'omarchy-mac-boot', 'allow_bootbin_change': False,
               'expected_bootbin_sha256': sha(rd(self.R(ESP + '/m1n1/boot.bin'))),
               'expected_kernel': K7, 'release': 'bt2-%s-%s' % (self.device, self.run_id[-8:]),
               'recovery_mode': 'network-only', 'test_root_free': 10 << 30}
        assert cfg['known_good_kernel'] == self.krel, 'device profile known-good kernel'
        assert cfg['board'] == self.board
        cfg.update(kw)
        os.makedirs(self.run, mode=0o700)
        for sub in ('t', 'native', 'pkgs', 'originals'):
            os.makedirs(self.run + '/' + sub, mode=0o700)
        for x in cands:
            shutil.copy2(self.R('/var/cache/fixture/' + x['file']), self.run + '/pkgs/' + x['file'])
        for x in originals:
            if x.get('file'):
                shutil.copy2(self.R('/var/cache/fixture/' + x['file']), self.run + '/originals/' + x['file'])
        raw = (json.dumps(cfg, sort_keys=True, indent=1) + '\n').encode()
        with open(self.run + '/config.json', 'wb') as f:
            f.write(raw)
        os.chmod(self.run + '/config.json', 0o600)
        os.chmod(self.run, 0o700)
        self.cfg, self.cfg_sha = cfg, sha(raw)
        return cfg

    # ------------------------------------------------------------------------------------ simulation
    def new_boot_id(self):
        self.boot_id = str(uuid.uuid4())
        self.wr('/proc/sys/kernel/random/boot_id', (self.boot_id + '\n').encode())

    def controller_locks(self):
        """controller 'locks' snippet: create /run/lock/boot-partition.lock (0644) only if missing."""
        p = self.R('/run/lock/boot-partition.lock')
        if not os.path.lexists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            os.fchmod(fd, 0o644)
            os.close(fd)

    def reboot(self, uname, cmdline=None):
        """Power cycle: new boot_id, kernel, /run/lock (tmpfs) emptied, units to boot state, cleanup service."""
        self.new_boot_id()
        self.uname = uname
        self.wr('/proc/cmdline', (cmdline or 'root=UUID=4f4d5801-524f-4f54-8000-000000000001 rw '
                                  'rootflags=subvol=@ quiet').encode() + b'\n')
        lock = self.R('/run/lock')
        for e in os.listdir(lock):
            p = os.path.join(lock, e)
            shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
        # the firmware/limine consumed a one-shot entry, if the agent set one
        if os.path.lexists(self.R(EFIVAR)):
            os.unlink(self.R(EFIVAR))
            self.events.append(('efivar-consumed', 'LoaderEntryOneShot'))
        # systemd-boot-random-seed.service rewrites the ESP seed on every boot (seen on the real M1)
        if os.path.lexists(self.R(ESP + '/loader/random-seed')):
            os.unlink(self.R(ESP + '/loader/random-seed'))
            self.wr(ESP + '/loader/random-seed', os.urandom(32))
            self.events.append(('random-seed-refreshed', self.boot_id))
        sd = self.sd()
        etc = self.R('/etc/systemd/system/')
        for u, rec in sd['units'].items():
            masked = os.path.islink(etc + u) and os.readlink(etc + u) == '/dev/null'
            sub = None if masked else self.boot_states.get(u)
            rec['ActiveState'], rec['SubState'] = ('active', sub) if sub else ('inactive', 'dead')
        self.sd_save(sd)
        assert self.fake('systemctl', 'daemon-reload').returncode == 0
        self.modules_cleanup()

    def modules_cleanup(self):
        """linux-modules-cleanup.service + the keep-local-kernel drop-in: every /usr/lib/modules/[0-9]* dir that is
        not the running kernel, not owned by a package and has no .keep-local-kernel goes to /usr/lib/modules/.old
        (hidden dirs such as .bt2-hold-* escape the glob, as on the device)."""
        base = self.R('/usr/lib/modules')
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            if not name[:1].isdigit() or name == self.uname or os.path.islink(p) or not os.path.isdir(p):
                continue
            if self.fake('pacman', '-Qqo', '/usr/lib/modules/' + name).returncode == 0:
                continue
            if os.path.lexists(p + '/.keep-local-kernel'):
                continue
            os.makedirs(base + '/.old', exist_ok=True)
            dst, i = base + '/.old/' + name, 1
            while os.path.lexists(dst):
                dst, i = '%s/.old/%s.%d' % (base, name, i), i + 1
            os.rename(p, dst)
            self.events.append(('modules-cleanup', name, os.path.basename(dst)))

    def agent_block(self, stanza_lines):
        """lab-agent (limine.go:271-292): strip the '# maclab:' block, normalise the whitespace before it and
        regenerate it at the end with the given stanza lines (under the boot-partition lock on the device)."""
        p = self.R(ESP + '/limine.conf')
        text = rd(p).decode()
        b, e = text.index(LAB_BEGIN), text.index(LAB_END) + len(LAB_END)
        head, tail = text[:b].rstrip(), text[e:].strip()
        new = head + '\n\n' + '\n'.join([LAB_BEGIN] + stanza_lines + [LAB_END]) + '\n' + (tail + '\n' if tail else '')
        fakebin.atomic_write(p, new.encode(), os.stat(p).st_mode & 0o777)

    def job(self, candidate_krel, job_id='4711', installer_path=None):
        """The labd installed-mode job. Agent stageInstalled: maclab/<job>/{entry.limine,krel,installed}, a
        /maclab-<job> stanza with the installer's path inside the maclab block, LoaderEntryOneShot, ubootefi.var
        persisted. The Mac boots the candidate, the tests run, labd's restore reboots to the default entry
        (known-good), and the agent cleans up its block (the job dir and ubootefi.var stay: agent-owned)."""
        path = installer_path or 'boot():/EFI/Linux/omarchy_linux-aurora.efi'
        cmd = 'root=UUID=4f4d5801-524f-4f54-8000-000000000001 rw rootflags=subvol=@ quiet maclab.job=%s panic=10' \
            % job_id
        jd = ESP + '/maclab/' + job_id
        self.wr(jd + '/entry.limine', ('/maclab-%s\n    protocol: efi\n    path: %s\n    cmdline: %s\n'
                                       % (job_id, path, cmd)).encode())
        self.wr(jd + '/krel', candidate_krel.encode() + b'\n')
        self.wr(jd + '/installed', b'1\n')
        self.agent_block(['/maclab-%s' % job_id, '    protocol: efi', '    path: ' + path, '    cmdline: ' + cmd])
        self.wr(EFIVAR, b'\x07\0\0\0' + ('maclab-' + job_id).encode('utf-16-le'))
        uv = self.R(ESP + '/ubootefi.var')
        if os.path.lexists(uv):
            data = bytearray(rd(uv))
            data[:4] = b'J%03d' % (int(job_id) % 1000)
            with open(uv, 'wb') as f:
                f.write(bytes(data))
        self.reboot(candidate_krel, cmdline=cmd)
        self.events.append(('booted', candidate_krel))
        self.wr(jd + '/result.json', b'{"outcome": "pass"}\n')
        self.reboot(self.krel)
        self.events.append(('booted', self.krel))
        self.agent_block([])

    # ------------------------------------------------------------------------------------ comparison
    def _excluded(self, rel):
        if rel in EXCLUDE or rel == self.run_sys:
            return True
        return os.path.dirname(rel) == ESP and fnmatch.fnmatchcase(os.path.basename(rel).lower(), 'ubootefi.var*')

    def snapshot(self):
        """{abs path: {type, mode, uid, gid, mtime_ns, size+sha256 (files), target (links)}} of the whole root."""
        out = {}
        for dp, dns, fns in os.walk(self.root):
            rdp = dp[len(self.root):] or '/'
            dns[:] = sorted(d for d in dns if not self._excluded(rdp.rstrip('/') + '/' + d))
            for n in sorted(dns + fns):
                rel = rdp.rstrip('/') + '/' + n
                if self._excluded(rel):
                    continue
                st = os.lstat(dp + '/' + n)
                m = st.st_mode
                rec = {'type': 'f' if stat.S_ISREG(m) else 'd' if stat.S_ISDIR(m) else 'l' if stat.S_ISLNK(m)
                       else 'o', 'mode': stat.S_IMODE(m), 'uid': st.st_uid, 'gid': st.st_gid,
                       'mtime_ns': st.st_mtime_ns}
                if rec['type'] == 'f':
                    rec.update(size=st.st_size, sha256=sha(rd(dp + '/' + n)))
                elif rec['type'] == 'l':
                    rec['target'] = os.readlink(dp + '/' + n)
                out[rel] = rec
        return out

    def promised_mtimes(self, state, before):
        """Paths whose mtime the SPEC promises to restore: every ESP file in the capture manifest, the /etc
        capture set (files, links and dirs, incl. /etc/systemd/system), and the unowned conflict files."""
        out = {ESP + '/' + rel for rel in state['esp']['files']}
        out |= {p for p, e in state['etc'].items() if e['type'] != 'absent'}
        out |= {cf['path'] for cf in state.get('conflicts', [])}
        return out & set(before)

    @staticmethod
    def compare(before, after, mtime_paths):
        """The ESP is FAT on the Mac: mode/uid/gid are mount options (fmask/dmask/uid=), not per-file state, so the
        capture manifest has no mode and nothing restores one. On the tmpfs fake the hooks' chmod would show up as
        a difference that cannot exist on the device; ESP entries are compared on type/bytes/size/mtime only."""
        diffs = []
        for p in sorted(set(before) | set(after)):
            a, b = before.get(p), after.get(p)
            if a is None or b is None:
                diffs.append({'path': p, 'issue': 'added' if a is None else 'removed', 'entry': a or b})
                continue
            fat = p == ESP or p.startswith(ESP + '/')
            keys = ['type', 'size', 'sha256', 'target'] + ([] if fat else ['mode', 'uid', 'gid']) + \
                (['mtime_ns'] if p in mtime_paths else [])
            bad = [k for k in keys if a.get(k) != b.get(k)]
            if bad:
                diffs.append({'path': p, 'fields': bad, 'before': {k: a.get(k) for k in bad},
                              'after': {k: b.get(k) for k in bad}})
        return diffs


# ---------------------------------------------------------------------------------------------- menus
def auto_block(os_name, mid, kernels):
    """limine-entry-tool OS block; kernels: [(pkg, krel, uki_rel, uki_bytes)]."""
    lines = ['/+' + os_name, '### This OS entry is auto-generated by limine-entry-tool', 'comment: ' + os_name,
             'comment: machine-id=%s order-priority=50' % mid]
    for p, k, rel, data in kernels:
        lines += ['  //' + p, '  ### This kernel entry is auto-generated by limine-entry-tool',
                  '  comment: Kernel version: ' + k, '  comment: kernel-id=%s' % p, '  protocol: efi',
                  '  path: boot():/%s#%s' % (rel, b2(data)), '  cmdline: ' + fakebin.UKI_CMDLINE]
    return lines


def menu(default, branding, block, stanzas):
    """stanzas: [(name, rel, data, cmdline|None, comment|None)]"""
    lines = ['timeout: 3', 'default_entry: ' + default, 'interface_branding: ' + branding,
             'hash_mismatch_panic: no', ''] + block
    for name, rel, data, cmd, comment in stanzas:
        lines += ['', '/' + name] + (['    comment: ' + comment] if comment else []) + \
                 ['    protocol: efi', '    path: boot():/%s%s' % (rel, ('#' + b2(data)) if data else '')]
        if cmd:
            lines.append('    cmdline: ' + cmd)
    lines += ['', LAB_BEGIN, LAB_END, '']
    return '\n'.join(lines)


# ---------------------------------------------------------------------------------------------- scenarios
def boot_files(update_m1n1, tag, extra=None):
    f = {'usr/bin/update-m1n1': ('f', 0o755, b'#!/bin/sh\n# update-m1n1 %s\n' % tag.encode()),
         'etc/default/update-m1n1': update_m1n1,
         'usr/lib/systemd/system/omarchy-mac-efi-vars.service': b'[Service]\nType=oneshot\n# %s\n' % tag.encode(),
         'usr/share/libalpm/hooks/95-m1n1-install.hook': b'[Trigger]\nTarget = usr/lib/modules/*/dtbs/*\n'}
    f.update(extra or {})
    return f


WRITER_UNITS = {'limine-snapper-sync.service': ('active', 'enabled'),
                'snapper-timeline.timer': ('inactive', 'disabled'),
                'snapper-cleanup.timer': ('active', 'enabled'),
                'snapper-cleanup.service': ('inactive', 'static'),
                'snapper-timeline.service': ('inactive', 'static'),
                'linux-modules-cleanup.service': ('inactive', 'enabled')}
BOOT_STATES = {'limine-snapper-sync.service': 'running', 'snapper-cleanup.timer': 'waiting'}


def m1_mac(name='m1'):
    """M1-like: package-owned running kernel 7.2.11-6-1-ARCH, default = limine-entry-tool auto entry
    Omarchy/linux-aurora -> EFI/Linux/omarchy_linux-aurora.efi, boot package installed (newer candidate), locally
    edited backup= file (.pacnew round trip), SF parkable UKI + stanza, ESP free tight so parking is needed."""
    mid = '1acdf795c0ffee000000000000000001'
    mac = Mac(name, 'm1', 'apple,j293', K6, mid)
    cache = mac.R('/var/cache/fixture')
    base = fxp.base_packages(cache)
    orig = [
        fxp.make_pkg(cache, 'linux-aurora', '7.2.11.aurora6-1', fxp.kernel_files(K6, 'six')),
        fxp.make_pkg(cache, 'linux-aurora-headers', '7.2.11.aurora6-1', fxp.header_files(K6, 'six')),
        fxp.make_pkg(cache, 'mesa-aurora', fxp.MESA_OLD, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 147a',
                                                          'usr/lib/libEGL_mesa.so.0.0.0': b'egl 147a'}),
        fxp.make_pkg(cache, 'vulkan-aurora', fxp.MESA_OLD, {'usr/lib/libvulkan_asahi.so': b'vk 147a'}),
        fxp.make_pkg(cache, 'omarchy-mac-boot', '20261010-1', boot_files(b'M1N1_UPDATE=1\n', 'old', {
            'etc/systemd/system/omarchy-vendor-firmware.service': b'[Unit]\nDescription=vendor fw (old)\n'}),
            backup=['etc/default/update-m1n1']),
    ]
    cand = [
        fxp.make_pkg(cache, 'linux-aurora', '7.2.11.aurora7-1', fxp.kernel_files(K7, 'seven')),
        fxp.make_pkg(cache, 'linux-aurora-headers', '7.2.11.aurora7-1', fxp.header_files(K7, 'seven')),
        fxp.make_pkg(cache, 'mesa-aurora', fxp.MESA_NEW, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 7c86',
                                                          'usr/lib/libEGL_mesa.so.0.0.0': b'egl 7c86',
                                                          'usr/lib/libdril_dri.so': b'dril 7c86'}),
        fxp.make_pkg(cache, 'vulkan-aurora', fxp.MESA_NEW, {'usr/lib/libvulkan_asahi.so': b'vk 7c86'}),
        fxp.make_pkg(cache, 'omarchy-mac-boot', '20261026-1',
                     boot_files(b'M1N1_UPDATE=1\nDTB_OVERLAYS=auto\n', 'new',
                                {'usr/share/omarchy-mac-boot/dtb-overlays/README': b'overlays\n',
                                 'etc/systemd/system/omarchy-vendor-firmware.service':
                                     b'[Unit]\nDescription=vendor fw (package)\n'}),
                     backup=['etc/default/update-m1n1']),
    ]
    mac.install_baseline(base + orig)
    mac.depmod(K6)
    # locally edited backup= file: a candidate with a different default yields .pacnew (moved aside by etc-restore)
    mac.wr('/etc/default/update-m1n1', b'M1N1_UPDATE=1\nM1N1_LOCAL_DTB=1 # local edit\n', mtime=MTIME - 1234)
    uki = fakebin.build_uki(K6, rd(mac.R('/usr/lib/modules/%s/vmlinuz' % K6)))
    sf = blob('sf-uki-177-182', 200 * 1024)
    mac.uki, mac.sf = uki, sf
    mac.esp(menu('Omarchy/linux-aurora', 'Omarchy Bootloader',
                 auto_block('Omarchy', mid, [('linux-aurora', K6, 'EFI/Linux/omarchy_linux-aurora.efi', uki)]),
                 [('SiliconForest - kernel 177+182', 'EFI/Linux/siliconforest-normal-205f5e8b20fc.efi', sf, None,
                   'Local 177+182 M1 kernel; previous boot entries retained')]),
            {'EFI/Linux/omarchy_linux-aurora.efi': uki, 'EFI/Linux/siliconforest-normal-205f5e8b20fc.efi': sf,
             'EFI/BOOT/BOOTAA64.EFI': blob('limine-efi', 20000),
             'm1n1/boot.bin': b'm1n1 stage2 + dtbs + u-boot (54fa)', 'm1n1/boot.bin.old': b'm1n1 older (fc1d)',
             'm1n1/boot.bin.pre-omacom-50fb': blob('pre-omacom', 90 * 1024),
             '%s/limine_history/omarchy_linux-aurora.efi_sha256_%s' % (mid, sha(uki)): uki,
             'ubootefi.var': blob('ubootvar', 8192), 'maclab/agent.marker': b'lab agent\n',
             'loader/random-seed': blob('seed', 32)})
    mac.systemd(WRITER_UNITS, BOOT_STATES)
    # ESP free just short of reserve + peak + fallback copy + 1 MiB: parking the first parkable (SF UKI) is needed
    peak = -(-len(uki) // 4096) * 4096 + 4 * MiB   # esp-prep's measured peak: the replaced UKI + 4 MiB
    need = 125829120 + peak + -(-len(uki) // 4096) * 4096 + MiB
    mac.configure(cand, orig, test_esp_free=need - 64 * 1024)
    mac.cand_pkgs, mac.orig_pkgs = cand, orig
    return mac


def m3_mac(name='m3'):
    """M3-like: custom unowned running kernel with a pre-existing .keep-local-kernel, custom default entry, boot
    package ABSENT (install adds it, rollback -R's it), two unowned files at boot-package paths (held, reinstated),
    linux-m3-eryk installed (boot-package rebuild_all adds an extra Eryk UKI + menu entry)."""
    mid = 'cbb1e723c0ffee000000000000000003'
    mac = Mac(name, 'm3pro', 'apple,j516s', KM3, mid)
    cache = mac.R('/var/cache/fixture')
    base = fxp.base_packages(cache) + [fxp.make_pkg(cache, 'linux-m3-eryk', '20261001-1', {
        'usr/lib/modules/%s/vmlinuz' % KERYK: b'vmlinuz-eryk' * 32,
        'usr/lib/modules/%s/kernel/drivers/eryk.ko' % KERYK: b'eryk.ko'})]
    orig = [
        fxp.make_pkg(cache, 'linux-aurora', '7.2.11.aurora6-1', fxp.kernel_files(K6, 'six', b'DTB-j516s-v1')),
        fxp.make_pkg(cache, 'mesa-aurora', fxp.MESA_OLD, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 147a'}),
    ]
    cand = [
        fxp.make_pkg(cache, 'linux-aurora', '7.2.11.aurora7-1', fxp.kernel_files(K7, 'seven', b'DTB-j516s-v1')),
        fxp.make_pkg(cache, 'mesa-aurora', fxp.MESA_NEW, {'usr/lib/libgallium-26.3.0-devel.so': b'gallium 7c86'}),
        fxp.make_pkg(cache, 'omarchy-mac-boot', '20261026-1', boot_files(
            b'M1N1_UPDATE=1 # package default\n', 'new',
            {'etc/systemd/system/omarchy-vendor-firmware.service': b'[Unit]\nDescription=vendor fw (package)\n',
             'etc/initcpio/install/omarchy-vendorfw': ('f', 0o755, b'#!/bin/bash\n# packaged\n'),
             'usr/bin/omarchy-vendorfw.sh': ('f', 0o755, b'#!/bin/sh\n# vendor firmware loader\n'),
             'usr/lib/systemd/system/omarchy-vendorfw.service': b'[Service]\nExecStart=/usr/bin/omarchy-vendorfw.sh\n'}),
            backup=['etc/default/update-m1n1']),
    ]
    mac.install_baseline(base + orig)
    mac.depmod(K6, KERYK)
    m = '/usr/lib/modules/' + KM3
    mac.wr(m + '/vmlinuz', b'vmlinuz-custom-7876' * 16)
    mac.wr(m + '/kernel/drivers/gpu/asahi.ko', b'asahi custom')
    mac.wr(m + '/modules.dep', b'kernel/drivers/gpu/asahi.ko:\n')
    mac.wr(m + '/.keep-local-kernel', b'')
    os.symlink('/home/chrisk/src/linux', mac.R(m + '/build'))
    mac.wr('/etc/m1n1.conf', b'chosen.asahi,t6030-gpu=1\n', mtime=MTIME - 3000)
    mac.wr('/etc/initcpio/install/omarchy-vendorfw', b'#!/bin/bash\n# legacy unowned\n', mtime=MTIME - 3500)
    # unowned files at boot-package paths (the real M3 has 5)
    mac.wr('/etc/default/update-m1n1', b'M1N1 local M3 config (unowned)\n', 0o644, MTIME - 5000)
    mac.wr('/etc/systemd/system/omarchy-vendor-firmware.service', b'[Unit]\nDescription=local vendor fw\n',
           0o640, MTIME - 7000)
    stock = fakebin.build_uki(K6, rd(mac.R('/usr/lib/modules/%s/vmlinuz' % K6)))
    custom = b'CUSTOM-UKI-7876' * 64
    mix = blob('mixtape', 150 * 1024)
    mac.uki = custom
    mac.esp(menu('Omacom Edge - aurora6 M3 GPU', 'SiliconForest Linux',
                 auto_block('SiliconForest Linux', mid,
                            [('linux-aurora', K6, 'EFI/Linux/omarchy_linux-aurora.efi', stock)]),
                 [('Omacom Edge - aurora6 M3 GPU', 'EFI/Linux/omacom-aurora6-m3.efi', custom,
                   'root=UUID=4f4d5801 rw rootflags=subvol=@ video=HDMI-A-1:1920x1080@60', 'custom lab kernel 7876'),
                  ('SiliconForest - kernel 177+182+187', 'EFI/Linux/siliconforest-mixtape-77648eb77168.efi', mix,
                   None, None),
                  ('GRUB (M3 bring-up kernels)', 'EFI/grub/grubaa64.efi', None, None, None)]),
            {'EFI/Linux/omarchy_linux-aurora.efi': stock, 'EFI/Linux/omacom-aurora6-m3.efi': custom,
             'EFI/Linux/siliconforest-mixtape-77648eb77168.efi': mix, 'EFI/grub/grubaa64.efi': blob('grub', 30000),
             'EFI/BOOT/BOOTAA64.EFI': blob('limine-efi', 20000), 'm1n1/boot.bin': b'm1n1 + m1n1.conf trailer (e29f)',
             'ubootefi.var': blob('ubootvar-m3', 8192), 'maclab/agent.marker': b'lab agent\n'})
    mac.systemd(WRITER_UNITS, BOOT_STATES)
    mac.configure(cand, orig + [{'name': 'omarchy-mac-boot', 'version': None}], test_esp_free=400 * MiB)
    mac.cand_pkgs, mac.orig_pkgs = cand, orig
    return mac
