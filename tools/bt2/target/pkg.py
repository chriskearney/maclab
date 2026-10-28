"""install / rollback of candidate packages (SPEC 'install' + 'rollback'; research M1, M2, M7-M10, M12, M17).

install:  phases = [every candidate except omarchy-mac-boot] then [omarchy-mac-boot]; each phase is one bounded
          `pacman --config <local-only> -U --noconfirm` after an exact `--print` plan; unowned conflict files of
          the phase's packages are moved to hold/conflicts/ first. Post checks: versions, running-kernel module
          tree exact (restore from capture copy if not), owned .keep-local-kernel marker, boot.bin, default entry,
          report (candidate krel + installer entry, new ESP files/menu entries, units started).
rollback: on the known-good untagged boot with writers masked: stop units the transaction started, remove our
          marker, hold the unowned running tree by same-parent rename, boot package first (-R or -U original),
          then the rest (-U originals, then -R new packages), reinstate held conflicts, verify versions + mtree +
          running tree, delete the hold tree only when exact.
Every mutation sets ctx.changed first and journals an intent file in <run>/install/ or <run>/rollback/ before
acting; pacman outcomes are recorded durably before any follow-up. Rollback is resumable: packages already at
their original version are skipped unless an install phase containing them did not complete.
"""
import errno
import fnmatch
import gzip
import json
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

import common as c
import limine
import writers

BOOT_PKG = 'omarchy-mac-boot'
PEAK = 67108864                      # fallback only; the real limit is esp-prep's measured 'peak' (peak(ctx))
PACMAN_TIMEOUT = 900
PACMAN_GRACE = 30
KILL_DRAIN = 10
PRINT_TIMEOUT = 120
PRINT_GRACE = 10
PRINT_FSIZE = 1 << 20
FMT = 'BT2\t%n\t%v\t%l'
MARKER = '.keep-local-kernel'
MODULES = '/usr/lib/modules'
DB_LOCK = '/var/lib/pacman/db.lck'
LOCAL_DB = '/var/lib/pacman/local'
PROGRESS = {'loading packages...', 'resolving dependencies...', 'looking for conflicting packages...',
            'checking dependencies...', 'looking for inter-conflicts...'}
GATE = 'IFS= read -r token || exit 125; [ "$token" = BT2_RUN ] || exit 125; exec "$@"'
ERR_RE = re.compile(r'(^|[\s:(])error:|command failed to execute correctly|^\s*==> ERROR|^ERROR:', re.I)
WARN_RE = re.compile(r'(^|[\s:])warning:|^\s*==> WARNING', re.I)
FILE_RE = re.compile(r'^[A-Za-z0-9@_.+:-]{1,200}$')
UNIT_FILE_RE = re.compile(r'^usr/lib/systemd/system/([A-Za-z0-9@_.:\\-]+\.(service|socket|timer|path|mount))$')
VMLINUZ_RE = re.compile(r'^usr/lib/modules/([^/]+)/vmlinuz$')


def _tval(name, default):
    """Test-only timing override (ignored on a real Mac, where BT2_TEST_ROOT is unset)."""
    v = os.environ.get(name) if c.TEST_ROOT else None
    return float(v) if v else default


def _lstat(p):
    try:
        return os.lstat(p)
    except FileNotFoundError:
        return None


def run8(ctx):
    """Shared bt2 rule: config['run8'] if present, else sha256(run_id)[:8]."""
    r = ctx.config.get('run8') or c.H(ctx.config['run_id'].encode())[:8]
    c.need(isinstance(r, str) and re.fullmatch(r'[a-z0-9]{1,16}', r), 'bad run8 %r' % (r,), after_change=ctx.changed)
    return r


def sys_run(ctx):
    return '/var/lib/maclab/bt2/' + ctx.config['run_id']


# -- journal ---------------------------------------------------------------------------------------
class Journal:
    def __init__(self, ctx, name):
        self.ctx = ctx
        self.name = name
        self.dir = ctx.run_dir / name
        if not os.path.lexists(self.dir):
            os.mkdir(self.dir, 0o700)

    def p(self, name):
        return self.dir / name

    def has(self, name):
        return os.path.lexists(self.dir / name)

    def read(self, name):
        return json.loads(c.read_small(self.dir / name, 16 << 20))

    def write(self, name, obj):
        return c.write_new(self.dir / name, c.dump({**obj, 'boot_id': c.boot_id(), 'at': time.time()}))

    def once(self, name, obj):
        if not self.has(name):
            self.write(name, obj)

    def next_attempt(self, tag):
        n = 0
        while self.has('%s.%d.intent.json' % (tag, n)) or self.has('%s.%d.print.log' % (tag, n)):
            n += 1
        return n

    def attempts(self, tag):
        out = []
        n = 0
        while self.has('%s.%d.print.log' % (tag, n)) or self.has('%s.%d.intent.json' % (tag, n)):
            out.append(n)
            n += 1
        return out


def _install_journal_existing(ctx):
    return Journal(ctx, 'install') if os.path.lexists(ctx.run_dir / 'install') else None


# -- module trees (M1) -----------------------------------------------------------------------------
def tree_rows(root):
    """{rel: row} for every entry under root (incl. '.'); no symlink following."""
    root = os.fspath(root)
    st = os.lstat(root)
    c.need(stat.S_ISDIR(st.st_mode), 'not a directory: %s' % root)

    def row(p, s):
        r = {'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid}
        if stat.S_ISLNK(s.st_mode):
            r.update(type='l', target=os.readlink(p))
        elif stat.S_ISDIR(s.st_mode):
            r['type'] = 'd'
        elif stat.S_ISREG(s.st_mode):
            h, n = c.sha_file(p)
            r.update(type='f', size=n, sha256=h)
        else:
            raise c.Failed('unexpected object type in module tree: %s' % p)
        return r

    rows = {'.': row(root, st)}
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in dirs + sorted(files):
            p = os.path.join(base, name)
            rows[os.path.relpath(p, root)] = row(p, os.lstat(p))
        c.need(len(rows) <= 200000, 'module tree too large: %s' % root)
    return rows


def tree_sha(rows):
    return c.H(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode())


# Cross-module contract with capture.py/audit.py (keep stable): rows {rel: {mode, uid, gid, type, size+sha256 for
# files, target for symlinks}} incl. '.', hashed as compact sort_keys JSON. capture.py does the same lookup: a shared
# common.tree_rows/tree_sha wins when present, otherwise these byte-compatible local definitions.
_TREE = getattr(c, 'tree_rows', None) or tree_rows
_TSHA = getattr(c, 'tree_sha', None) or tree_sha


def tsha_of(path, drop_marker=False):
    if not os.path.isdir(path) or os.path.islink(path):
        return None
    rows = _TREE(path)
    if drop_marker:
        rows.pop(MARKER, None)
    return _TSHA(rows)


def _norm(name):
    while name.startswith('./'):
        name = name[2:]
    return name.rstrip('/')


def extract_tree(tar_path, dest, krel):
    """Safe extraction of a captured module tree (capture/modules/<krel>.tar) into the empty dir dest."""
    fd = os.open(tar_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f, tarfile.open(fileobj=f, mode='r:*') as tf:
        members = tf.getmembers()
        names = [_norm(m.name) for m in members]
        strip = bool(names) and all(n == krel or n.startswith(krel + '/') for n in names)
        sel, links, root = [], set(), None
        for m, n in zip(members, names):
            rel = (n[len(krel):].lstrip('/') if strip else n) or '.'
            parts = rel.split('/')
            c.need(not rel.startswith('/') and '..' not in parts and '' not in parts,
                   'unsafe member in tree copy: %r' % m.name, after_change=True)
            c.need(m.isreg() or m.isdir() or m.issym(), 'unsupported member type in tree copy: %r' % m.name,
                   after_change=True)
            if rel == '.':
                root = m
                continue
            for i in range(1, len(parts)):
                c.need('/'.join(parts[:i]) not in links, 'member below a symlink: %r' % m.name, after_change=True)
            if m.issym():
                links.add(rel)
            m.name = rel
            sel.append(m)
        tf.extractall(dest, members=sel, numeric_owner=True, filter='fully_trusted')
    if root is not None:
        if os.geteuid() == 0:
            os.chown(dest, root.uid, root.gid)
        os.chmod(dest, root.mode & 0o7777)
    else:
        os.chmod(dest, 0o755)
    os.sync()


# -- archives --------------------------------------------------------------------------------------
class Archive:
    """Index of one package archive: .PKGINFO + member names (no extraction)."""

    def __init__(self, path):
        self.path = path
        self.info = {}
        self.members = {}
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as f, tarfile.open(fileobj=f, mode='r:*') as tf:
            for m in tf:
                n = _norm(m.name)
                if n == '.PKGINFO':
                    for line in tf.extractfile(m).read(1 << 20).decode('utf-8', 'replace').splitlines():
                        if ' = ' in line and not line.startswith('#'):
                            k, v = line.split(' = ', 1)
                            self.info.setdefault(k.strip(), []).append(v.strip())
                elif n and not n.startswith('.'):
                    self.members[n] = 'd' if m.isdir() else 'l' if m.issym() else 'f' if m.isreg() else '?'

    def name(self):
        return (self.info.get('pkgname') or [None])[0]

    def version(self):
        return (self.info.get('pkgver') or [None])[0]

    def kernels(self):
        return sorted({VMLINUZ_RE.match(n).group(1) for n in self.members if VMLINUZ_RE.match(n)})

    def units(self):
        return sorted({UNIT_FILE_RE.match(n).group(1) for n in self.members
                       if self.members[n] != 'd' and UNIT_FILE_RE.match(n)})

    def owns_tree(self, krel):
        pre = 'usr/lib/modules/%s/' % krel
        return any(n == pre[:-1] or n.startswith(pre) for n in self.members)


class Plan:
    """config candidates/originals, archive identities and the phase split."""

    def __init__(self, ctx, need_originals=True):
        cfg = ctx.config
        self.ctx = ctx
        self.cand = {p['name']: p for p in cfg['candidates']}
        self.orig = {p['name']: p for p in cfg['originals']}
        c.need(self.cand, 'no candidates in config')
        for n in self.cand:
            c.need(n in self.orig, 'candidate %s has no originals entry (rollback impossible)' % n,
                   after_change=ctx.changed)
        self.arch = {}
        for kind, rows, sub in (('cand', self.cand.values(), 'pkgs'), ('orig', self.orig.values(), 'originals')):
            for p in rows:
                if kind == 'orig' and (p.get('version') is None or not need_originals):
                    continue
                f = p.get('file')
                c.need(isinstance(f, str) and FILE_RE.match(f) and '/' not in f and f not in ('.', '..'),
                       'bad archive file name for %s' % p['name'], after_change=ctx.changed)
                path = ctx.run_dir / sub / f
                c.need(os.path.isfile(path) and not os.path.islink(path), 'archive missing: %s/%s' % (sub, f),
                       after_change=ctx.changed)
                h, n = c.sha_file(path)
                c.need(h == p['sha256'] and n == p['bytes'], 'archive sha/size mismatch: %s/%s' % (sub, f),
                       after_change=ctx.changed)
                a = Archive(path)
                c.need(a.name() == p['name'] and a.version() == p['version'],
                       'archive %s/.PKGINFO says %s %s, config says %s %s'
                       % (f, a.name(), a.version(), p['name'], p['version']), after_change=ctx.changed)
                a.sys_path = '%s/%s/%s' % (sys_run(ctx), sub, f)
                self.arch[(kind, p['name'])] = a
        main = [n for n in self.cand if n != BOOT_PKG]
        self.phases = [(tag, names) for tag, names in (('main', main), ('boot', [BOOT_PKG] if BOOT_PKG in self.cand
                                                                          else [])) if names]

    def cand_archive(self, n):
        return self.arch[('cand', n)]

    def orig_archive(self, n):
        return self.arch.get(('orig', n))

    def candidate_kernels(self):
        return [(n, k) for n in self.cand for k in self.cand_archive(n).kernels()]

    def shipped_units(self):
        out = set()
        for a in self.arch.values():
            out.update(a.units())
        return out


# -- capture / small readers -----------------------------------------------------------------------
def load_state(ctx):
    p = ctx.run_dir / 'capture' / 'state.json'
    c.need(os.path.lexists(p), 'capture/state.json missing (run capture first)', after_change=ctx.changed)
    st = json.loads(c.read_small(p, 256 << 20))
    c.need(st.get('schema') == 'bt2.capture/1' and st.get('run_id') == ctx.config['run_id'],
           'capture/state.json schema/run_id mismatch', after_change=ctx.changed)
    return st


def mtree_sha(name, version):
    p = c.P('%s/%s-%s/mtree' % (LOCAL_DB, name, version))
    if not os.path.lexists(p):
        return None
    return c.H(gzip.decompress(c.read_small(p, 64 << 20)))


def esp_free(ctx):
    """statvfs on the Mac. Under BT2_TEST_ROOT with config test_esp_free, the same simulated ESP that capture,
    esp-prep and audit measure (capture.esp_free), so the phase gate checks what esp-prep actually reserved."""
    if c.TEST_ROOT and 'test_esp_free' in ctx.config:
        import capture
        return capture.esp_free(ctx, load_state(ctx))
    s = os.statvfs(ctx.esp)
    return s.f_bavail * s.f_frsize


def owned_by(sys_path):
    r = c.run([c.BIN('pacman'), '-Qqo', sys_path], check=False, timeout=60)
    return r.stdout.decode().split() if r.returncode == 0 else []


def meta(path):
    s = os.lstat(path)
    out = {'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid, 'mtime_ns': s.st_mtime_ns,
           'size': s.st_size, 'ino': s.st_ino, 'dev': s.st_dev, 'regular': stat.S_ISREG(s.st_mode)}
    if stat.S_ISREG(s.st_mode):
        out['sha256'] = c.sha_file(path)[0]
    return out


def _same_meta(m, cf):
    return m.get('regular') and all(m.get(k) == cf.get(k) for k in ('sha256', 'mode', 'uid', 'gid', 'mtime_ns'))


# -- pacman: local-only config, print plan, bounded run (M7, M8) -----------------------------------
def options_only(raw):
    """Byte-exact preamble + leading [options] block of pacman.conf; no repositories, no Include."""
    c.need(0 < len(raw) <= 65536 and b'\0' not in raw, 'pacman.conf: bounded text required')
    headers, end, off = [], None, 0
    for line in raw.splitlines(keepends=True):
        active = line.split(b'#', 1)[0].strip()
        if active.startswith(b'['):
            m = re.fullmatch(rb'\[([A-Za-z0-9_.-]+)\]', active)
            c.need(m is not None, 'pacman.conf: invalid section header')
            name = m.group(1)
            if not headers:
                c.need(name == b'options', 'pacman.conf: first section must be [options]')
            elif name == b'options':
                raise c.Refused('pacman.conf: more than one [options] section')
            elif end is None:
                end = off
            headers.append(name)
        elif active:
            c.need(bool(headers), 'pacman.conf: directive before [options]')
            if end is None:
                c.need(not re.match(rb'(?i)include\s*=', active), 'pacman.conf: Include inside [options] refused')
        off += len(line)
    c.need(headers and headers[0] == b'options', 'pacman.conf: no [options] section')
    sel = raw if end is None else raw[:end]
    c.need(sum(1 for x in sel.splitlines() if x.split(b'#', 1)[0].strip().startswith(b'[')) == 1,
           'local-only config would contain a repository')
    return sel


def local_conf(ctx, j):
    """Write (once) <run>/pkgs/pacman-local-only.conf; returns its system path."""
    src = c.read_small(c.P('/etc/pacman.conf'), 65536)
    data = options_only(src)
    d = ctx.run_dir / 'pkgs'
    c.need(os.path.isdir(d) and not os.path.islink(d), 'pkgs/ missing', after_change=ctx.changed)
    p = d / 'pacman-local-only.conf'
    if os.path.lexists(p):
        c.need(c.read_small(p, 65536) == data, 'existing local-only config differs from /etc/pacman.conf options',
               after_change=ctx.changed)
    else:
        c.write_new(p, data, 0o644)
    j.once('local-conf.json', {'path': sys_run(ctx) + '/pkgs/pacman-local-only.conf', 'sha256': c.H(data),
                               'bytes': len(data), 'source_sha256': c.H(src)})
    return sys_run(ctx) + '/pkgs/pacman-local-only.conf'


def pacman_env():
    e = {'PATH': ((c.TEST_BIN + ':') if c.TEST_BIN else '') + '/usr/local/sbin:/usr/local/bin:/usr/bin',
         'HOME': '/root', 'LC_ALL': 'C', 'LANG': 'C'}
    if c.TEST_ROOT:
        e.update({k: v for k, v in os.environ.items() if k.startswith('BT2_')})
    return e


class Cancellation:
    """Record SIGTERM/HUP/INT during a pacman run instead of dying with children alive."""

    def __init__(self):
        self.signals = []
        self.prev = {}

    def _rec(self, num, _frame):
        self.signals.append(num)

    def __enter__(self):
        for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            self.prev[s] = signal.signal(s, self._rec)
        return self

    def __exit__(self, *exc):
        for s, h in self.prev.items():
            signal.signal(s, h)
        return False


def live_group(gid):
    live = []
    for e in os.listdir('/proc'):
        if not e.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % e, 'rb') as f:
                data = f.read(4096).decode()
            fields = data[data.rfind(')') + 2:].split()
            if (int(fields[2]) == gid or int(fields[3]) == gid) and fields[0] != 'Z':
                live.append(int(e))
        except (OSError, ValueError, IndexError):
            continue
    return live


def drain(gid, seconds):
    deadline = time.monotonic() + seconds
    while live_group(gid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def bounded(argv, log_path, ident_path, timeout, grace, fsize):
    """Run argv in its own session/pgid with RLIMIT_FSIZE; identity is durable before launch is released."""
    lfd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))

    res = {'argv': argv, 'exit_code': None, 'timed_out': False, 'launch_error': None, 'launch_released': False,
           'lingering_children': False, 'group_drained': True, 'per_regular_file_limit_bytes': fsize,
           'pgid': None, 'cancel_signals': []}
    p = None
    with Cancellation() as cancel:
        try:
            try:
                p = subprocess.Popen(['/bin/sh', '-c', GATE, 'bt2-pacman', *argv], stdin=subprocess.PIPE,
                                     stdout=lfd, stderr=subprocess.STDOUT, start_new_session=True,
                                     preexec_fn=limits, env=pacman_env(), cwd='/', close_fds=True)
                res['pgid'] = p.pid
                with open('/proc/%d/stat' % p.pid, 'rb') as f:
                    raw = f.read(4096).decode()
                fields = raw[raw.rfind(')') + 2:].split()
                if not (int(fields[2]) == p.pid and int(fields[3]) == p.pid):
                    raise RuntimeError('child is not its own session/group leader')
                c.write_new(ident_path, c.dump({'pid': p.pid, 'pgid': p.pid, 'sid': p.pid,
                                                'starttime_ticks': int(fields[19]), 'argv': argv,
                                                'per_regular_file_limit_bytes': fsize, 'boot_id': c.boot_id()}))
                if not cancel.signals:
                    p.stdin.write(b'BT2_RUN\n')
                    p.stdin.flush()
                    res['launch_released'] = True
                p.stdin.close()
                try:
                    res['exit_code'] = p.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    res['timed_out'] = True
            except BaseException as e:  # noqa: BLE001 - recorded; the group is drained below
                res['launch_error'] = '%s: %s' % (type(e).__name__, str(e)[:300])
            finally:
                if p is not None and p.stdin and not p.stdin.closed:
                    try:
                        p.stdin.close()
                    except OSError:
                        pass
            if p is not None:
                res['lingering_children'] = res['exit_code'] is not None and bool(live_group(p.pid))
                if res['timed_out'] or res['launch_error'] or res['lingering_children']:
                    try:
                        os.killpg(p.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    if not drain(p.pid, grace):
                        try:
                            os.killpg(p.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        if not drain(p.pid, KILL_DRAIN):
                            res['group_drained'] = False
                if res['group_drained']:
                    try:
                        code = p.wait(timeout=10)
                        if res['exit_code'] is None:
                            res['exit_code'] = code
                    except subprocess.TimeoutExpired:
                        res['group_drained'] = False
                if res['group_drained'] and live_group(p.pid):
                    res['group_drained'] = False
        finally:
            try:
                os.fsync(lfd)
            finally:
                os.close(lfd)
        res['cancel_signals'] = list(cancel.signals)
    return res


def classify(r):
    if not r['group_drained']:
        return 'UNKNOWN'
    if r['pgid'] is None:
        return 'NOT_LAUNCHED'              # Popen itself failed: nothing ran
    if not r['launch_released'] and not r['timed_out']:
        return 'NOT_LAUNCHED'              # gate never received the token: the shell exits 125, pacman never ran
    if r['timed_out'] or r['lingering_children'] or r['launch_error'] or r['exit_code'] is None \
            or r['exit_code'] < 0:
        return 'UNKNOWN'
    return 'COMPLETED' if r['exit_code'] == 0 else 'FAILED'


def scan_log(raw):
    errors, warnings = [], []
    for line in raw.decode('utf-8', 'replace').splitlines():
        if ERR_RE.search(line):
            errors.append(line[:300])
        elif WARN_RE.search(line):
            warnings.append(line[:300])
    return errors, warnings


def parse_print(raw, expect, allowed):
    """expect {name: (version, location)} -> (ok, rows, unexpected_lines)."""
    if len(raw) > PRINT_FSIZE or b'\0' in raw or b'\x1b' in raw:
        return False, {}, ['unbounded/binary/colored print output']
    rows, bad = {}, []
    for line in raw.decode('utf-8', 'replace').splitlines():
        if line.startswith('BT2\t'):
            f = line.split('\t')
            loc = expect[f[1]][1] if len(f) == 4 and f[1] in expect else ''
            # loc None (removals): installed local package; any non-URL location (pacman prints name-version)
            loc_ok = len(f) == 4 and ('://' not in f[3] if loc is None else f[3] in (loc, 'file://' + loc))
            if len(f) == 4 and f[1] in expect and f[1] not in rows and f[2] == expect[f[1]][0] and loc_ok:
                rows[f[1]] = {'version': f[2], 'location': f[3]}
            else:
                bad.append(line[:300])
        elif line.strip() and line.strip() not in PROGRESS and line.strip() not in allowed:
            bad.append(line[:300])
    if set(rows) != set(expect):
        bad.append('missing targets: %s' % sorted(set(expect) - set(rows)))
    return not bad, rows, bad


def gates(ctx, purpose='install'):
    """Before every pacman transaction. Install phases keep the lab-agent's staging reserve on top of the peak
    (the labd job stages its UKI after the install). Rollback phases only need room for the largest file pacman may
    write (RLIMIT_FSIZE == peak) + 1 MiB: no job follows, and an install that added a UKI (the M3 boot package's
    rebuild_all made a 66 MB linux-m3-eryk UKI) can leave less than reserve+peak, which must not block the way back."""
    c.need(not os.path.lexists(c.P(DB_LOCK)), 'pacman db.lck present', after_change=ctx.changed)
    writers.verify_masked(ctx, after_change=ctx.changed)
    pk = peak(ctx)
    if purpose == 'rollback':
        need, what = pk + (1 << 20), 'peak+1MiB'
    else:
        need, what = ctx.config.get('esp_reserve_bytes', 125829120) + pk, 'reserve+peak'
    free = esp_free(ctx)
    c.need(free >= need, 'ESP free %d < %s %d' % (free, what, need), after_change=ctx.changed)
    return {'esp_free': free, 'need': need, 'rule': what}


def run_phase(ctx, j, tag, op, names, plan_targets, expect, allowed, before_mutation=None, purpose='install'):
    """One bounded pacman transaction (op 'U' with archive paths, or 'R' with names), print-checked first."""
    conf = local_conf(ctx, j)
    attempt = j.next_attempt(tag)
    pre = 'pkg.%s.%d' % (tag, attempt)
    g = gates(ctx, purpose)
    flag = '-' + op
    tail = ['--', *plan_targets]
    pargv = [c.BIN('pacman'), '--config', conf, flag, '--print', '--print-format', FMT, *tail]
    pres = bounded(pargv, j.p('%s.%d.print.log' % (tag, attempt)), j.p('%s.%d.print.group.json' % (tag, attempt)),
                   _tval('BT2_TEST_PRINT_TIMEOUT', PRINT_TIMEOUT), PRINT_GRACE, PRINT_FSIZE)
    pres['outcome'] = classify(pres)
    praw = c.read_small(j.p('%s.%d.print.log' % (tag, attempt)), 64 << 20)
    ok, rows, bad = parse_print(praw, expect, allowed)
    j.write('%s.%d.print.outcome.json' % (tag, attempt), {**pres, 'plan_ok': ok, 'rows': rows, 'unexpected': bad,
                                                          'packages': names, 'op': op})
    c.need(pres['outcome'] == 'COMPLETED' and pres['exit_code'] == 0 and not pres['cancel_signals'],
           '%s: pacman --print failed (%s, exit %s): %s' % (tag, pres['outcome'], pres['exit_code'],
                                                           praw.decode('utf-8', 'replace')[-400:]),
           after_change=ctx.changed)
    c.need(ok, '%s: print plan is not exactly the phase targets: %s' % (tag, bad[:6]), after_change=ctx.changed)
    c.need(not os.path.lexists(c.P(DB_LOCK)), 'print left db.lck', after_change=ctx.changed)
    if before_mutation:
        before_mutation()
    argv = [c.BIN('pacman'), '--config', conf, flag, '--noconfirm', *tail]
    j.write('%s.%d.intent.json' % (tag, attempt), {'op': op, 'packages': names, 'argv': argv, 'expect': expect,
                                                   'versions_before': c.pacman_versions(names), 'gates': g,
                                                   'local_conf': conf})
    ctx.changed = True
    log = j.p('%s.%d.log' % (tag, attempt))
    res = bounded(argv, log, j.p('%s.%d.group.json' % (tag, attempt)), _tval('BT2_TEST_PACMAN_TIMEOUT', PACMAN_TIMEOUT),
                  _tval('BT2_TEST_PACMAN_GRACE', PACMAN_GRACE), peak(ctx))
    outcome = classify(res)
    try:
        errors, warns = scan_log(c.read_small(log, 64 << 20))
    except Exception as e:  # noqa: BLE001 - never lose the outcome record
        errors, warns = ['log unreadable: %s' % e], []
    rec = {**res, 'outcome': outcome, 'hook_errors': errors, 'warnings': warns, 'packages': names, 'op': op}
    j.write('%s.%d.outcome.json' % (tag, attempt), rec)          # durable BEFORE any follow-up
    if outcome == 'UNKNOWN':
        raise c.Failed('UNKNOWN: %s pacman outcome unknown (timed_out=%s drained=%s exit=%s); no restore until '
                       'the group is proven drained; see %s/%s/%s.%d.outcome.json'
                       % (tag, res['timed_out'], res['group_drained'], res['exit_code'], sys_run(ctx), j.name,
                          tag, attempt))
    c.need(outcome == 'COMPLETED', '%s: pacman %s (exit %s): %s' % (tag, outcome, res['exit_code'],
                                                                     (errors or ['-'])[:4]), after_change=True)
    c.need(not res['cancel_signals'], '%s: cancelled by signal %s during pacman' % (tag, res['cancel_signals']),
           after_change=True)
    c.need(not errors, '%s: error/hook-failure lines in pacman output: %s' % (tag, errors[:4]), after_change=True)
    rec['attempt'] = attempt
    rec['tag'] = tag
    return rec


def _phase_status(j, tag):
    """(last_attempt, outcome_record or None) of a journalled phase."""
    att = [n for n in j.attempts(tag) if j.has('%s.%d.intent.json' % (tag, n))]
    if not att:
        return None, None
    n = att[-1]
    name = '%s.%d.outcome.json' % (tag, n)
    return n, (j.read(name) if j.has(name) else None)


def _check_groups_drained(ctx, *journals):
    """Every pacman group we ever launched in this boot must be gone before we touch module trees."""
    me = c.boot_id()
    for j in journals:
        if j is None:
            continue
        for f in sorted(os.listdir(j.dir)):
            if f.endswith('.group.json'):
                g = j.read(f)
                if g.get('boot_id') == me:
                    c.need(not live_group(g['pgid']), 'pacman group %d from %s still live' % (g['pgid'], f),
                           after_change=ctx.changed)


# -- unowned conflict files ------------------------------------------------------------------------
def _cid(cf):
    return c.H(cf['path'].encode())[:16]


def _chold(ctx, cf):
    return ctx.run_dir / 'hold' / 'conflicts' / cf['sha256'] / os.path.basename(cf['path'])


def _move(src, dst):
    """rename (same inode: bytes/mode/owner/mtime preserved); copy+verify+unlink across filesystems."""
    try:
        os.rename(src, dst)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise
        s = os.lstat(src)
        data = c.read_small(src, 1 << 30)
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, data)
            if os.geteuid() == 0:
                os.fchown(fd, s.st_uid, s.st_gid)
            os.fchmod(fd, stat.S_IMODE(s.st_mode))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.utime(dst, ns=(s.st_atime_ns, s.st_mtime_ns), follow_symlinks=False)
        c.need(c.sha_file(dst)[0] == c.H(data), 'cross-device copy mismatch: %s' % dst, after_change=True)
        os.unlink(src)
    c.fsync_dir(Path(dst).parent)
    c.fsync_dir(Path(src).parent)


def _ancestors(sys_path):
    out = []
    p = Path(sys_path).parent
    while str(p) != '/':
        s = os.lstat(c.P(str(p)))
        out.append({'path': str(p), 'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid})
        p = p.parent
    return out


def hold_conflicts(ctx, ij, conflicts):
    held = []
    plan = []
    for cf in conflicts:   # verify everything before the first move
        dst = _chold(ctx, cf)
        if ij.has('conflict.%s.held.json' % _cid(cf)):
            continue
        live = c.P(cf['path'])
        if _lstat(live) is None and _lstat(dst) is not None and ij.has('conflict.%s.intent.json' % _cid(cf)):
            plan.append((cf, 'reconcile'))
            continue
        c.need(_lstat(live) is not None, 'unowned conflict file vanished since capture: %s' % cf['path'],
               after_change=ctx.changed)
        m = meta(live)
        c.need(_same_meta(m, cf), 'unowned conflict file changed since capture: %s' % cf['path'],
               after_change=ctx.changed)
        c.need(not owned_by(cf['path']), 'conflict file is owned now: %s' % cf['path'], after_change=ctx.changed)
        c.need(_lstat(dst) is None, 'hold slot already used: %s' % dst, after_change=ctx.changed)
        plan.append((cf, 'move'))
    for cf, how in plan:
        dst = _chold(ctx, cf)
        rec = {**cf, 'held': '%s/hold/conflicts/%s/%s' % (sys_run(ctx), cf['sha256'], os.path.basename(cf['path'])),
               'ancestors': _ancestors(cf['path'])}
        if how == 'move':
            ij.once('conflict.%s.intent.json' % _cid(cf), rec)
            ctx.changed = True
            os.makedirs(dst.parent, mode=0o700, exist_ok=True)
            _move(c.P(cf['path']), dst)
        m = meta(dst)
        c.need(_same_meta(m, cf), 'held conflict file differs from capture: %s' % dst, after_change=True)
        ij.write('conflict.%s.held.json' % _cid(cf), {**rec, 'held_ino': m['ino']})
        held.append(cf['path'])
    return held


def reinstate_conflicts(ctx, ij, rj, conflicts):
    out = []
    for cf in conflicts:
        cid = _cid(cf)
        if not ij.has('conflict.%s.held.json' % cid) and not ij.has('conflict.%s.intent.json' % cid):
            continue  # never held (install did not reach that phase)
        live = c.P(cf['path'])
        dst = _chold(ctx, cf)
        ls, hs = _lstat(live), _lstat(dst)
        if hs is None:
            c.need(ls is not None and _same_meta(meta(live), cf), 'held conflict missing and live differs: %s'
                   % cf['path'], after_change=ctx.changed)
            if not rj.has('conflict.%s.reinstated.json' % cid):
                rj.write('conflict.%s.reinstated.json' % cid, {**cf, 'already': True})
            out.append(cf['path'])
            continue
        c.need(_same_meta(meta(dst), cf), 'held conflict copy changed: %s' % dst, after_change=ctx.changed)
        if ls is not None:
            # A leftover the transaction created (owner now removed): move it aside, never delete.
            c.need(not owned_by(cf['path']), 'conflict path still owned by a package: %s' % cf['path'],
                   after_change=ctx.changed)
            aside = ctx.run_dir / 'hold' / 'displaced' / cid / os.path.basename(cf['path'])
            rj.once('conflict.%s.displace.json' % cid, {'path': cf['path'], 'meta': meta(live), 'hold': '%s/hold/'
                                                        'displaced/%s/%s' % (sys_run(ctx), cid,
                                                                             os.path.basename(cf['path']))})
            ctx.changed = True
            os.makedirs(aside.parent, mode=0o700, exist_ok=True)
            c.need(_lstat(aside) is None, 'displace slot used: %s' % aside, after_change=True)
            _move(live, aside)
        rec = ij.read('conflict.%s.held.json' % cid) if ij.has('conflict.%s.held.json' % cid) else \
            ij.read('conflict.%s.intent.json' % cid)
        rj.once('conflict.%s.reinstate-intent.json' % cid, rec)
        ctx.changed = True
        for a in reversed(rec.get('ancestors', [])):
            ap = c.P(a['path'])
            if _lstat(ap) is None:
                os.mkdir(ap, a['mode'])
                if os.geteuid() == 0:
                    os.chown(ap, a['uid'], a['gid'])
                os.chmod(ap, a['mode'])
        _move(dst, live)
        c.need(_same_meta(meta(live), cf), 'reinstated conflict differs from capture: %s' % cf['path'],
               after_change=True)
        rj.write('conflict.%s.reinstated.json' % cid, {**cf, 'ino': os.lstat(live).st_ino})
        out.append(cf['path'])
    return out


# -- running kernel tree + marker (M1, M2) ---------------------------------------------------------
def marker_content(ctx, krel):
    return ('bt2 owned marker: run=%s krel=%s\n' % (ctx.config['run_id'], krel)).encode()


def ensure_running_tree(ctx, ij, st):
    rk = st['running_kernel']
    krel = rk['krel']
    mod = st['modules'].get(krel)
    c.need(mod is not None, 'capture has no module map for running kernel %s' % krel, after_change=True)
    live = c.P(MODULES) / krel
    ours = ij.has('marker.json') or ij.has('marker.intent.json')
    if tsha_of(live, drop_marker=ours) == mod['tree_sha256']:
        return {'krel': krel, 'status': 'exact'}
    c.need(rk.get('copy'), 'running kernel tree %s differs from capture and no capture copy exists' % krel,
           after_change=True)
    tar = ctx.run_dir / rk['copy']
    c.need(os.path.isfile(tar) and not os.path.islink(tar), 'capture tree copy missing: %s' % rk['copy'],
           after_change=True)
    n = 0
    while ij.has('tree-restore.%d.intent.json' % n):
        n += 1
    ij.write('tree-restore.%d.intent.json' % n, {'krel': krel, 'copy': rk['copy'],
                                                'expected_tree_sha256': mod['tree_sha256'],
                                                'live_tree_sha256': tsha_of(live)})
    ctx.changed = True
    staging = Path(tempfile.mkdtemp(prefix='.bt2-restore-%s-' % run8(ctx), dir=live.parent))
    extract_tree(tar, staging, krel)
    got = tsha_of(staging)
    c.need(got == mod['tree_sha256'], 'restore staging %s != capture tree (kept at %s)' % (got, staging),
           after_change=True)
    leftover = None
    if os.path.lexists(live):
        # Residue the transaction left at the running tree path (e.g. depmod output of the replaced package) is moved
        # aside into the run dir's hold/ (never deleted here). A sibling under /usr/lib/modules would survive every
        # later step and fail the final audit (module_dir_added); hold/ is removed by cleanup only after an ok final
        # audit, which finds it through this result's 'leftover'. hold/ shares /etc's filesystem (writers.hold
        # gate); if /usr/lib/modules is elsewhere (EXDEV) the hidden sibling is kept and the audit reports it.
        lroot = ctx.sub('hold') / 'modules-leftover'
        os.makedirs(lroot, mode=0o700, exist_ok=True)
        leftover = Path(tempfile.mkdtemp(prefix='%s.' % krel, dir=lroot))
        try:
            os.rename(live, leftover)
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
            os.rmdir(leftover)
            leftover = Path(tempfile.mkdtemp(prefix='.bt2-leftover-%s-' % run8(ctx), dir=live.parent))
            os.rename(live, leftover)
        c.fsync_dir(leftover.parent)
    os.rename(staging, live)
    c.fsync_dir(live.parent)
    c.need(tsha_of(live) == mod['tree_sha256'], 'running kernel tree restore verification failed', after_change=True)
    rec = {'krel': krel, 'status': 'restored', 'leftover': str(leftover) if leftover else None}
    ij.write('tree-restore.%d.done.json' % n, rec)
    return rec


def ensure_marker(ctx, ij, st):
    """Owned .keep-local-kernel in the running tree, only if absent at capture and the tree is now unowned."""
    krel = st['running_kernel']['krel']
    mod = st['modules'][krel]
    path = c.P(MODULES) / krel / MARKER
    sysp = '%s/%s/%s' % (MODULES, krel, MARKER)
    content = marker_content(ctx, krel)
    if ij.has('marker.json'):
        rec = ij.read('marker.json')
        s = _lstat(path)
        c.need(s is not None and s.st_ino == rec['ino'] and c.sha_file(path)[0] == rec['sha256'],
               'owned marker drifted', after_change=True)
        return {**rec, 'created': False, 'verified': True}
    if mod.get('keep_marker'):
        c.need(os.path.lexists(path), 'pre-existing marker vanished: %s' % sysp, after_change=True)
        return {'path': sysp, 'preexisting': True}
    owners = owned_by('%s/%s' % (MODULES, krel))
    if owners:
        return {'path': sysp, 'needed': False, 'owned_by': owners}
    if os.path.lexists(path):
        c.need(ij.has('marker.intent.json') and c.read_small(path, 4096) == content,
               'marker exists but is not ours: do not adopt (%s)' % sysp, after_change=True)
    else:
        ij.once('marker.intent.json', {'path': sysp, 'krel': krel, 'sha256': c.H(content),
                                       'base_tree_sha256': mod['tree_sha256']})
        ctx.changed = True
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        try:
            os.fchmod(fd, 0o644)
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        c.fsync_dir(path.parent)
    s = os.lstat(path)
    rec = {'path': sysp, 'krel': krel, 'dev': s.st_dev, 'ino': s.st_ino, 'sha256': c.H(content),
           'size': len(content), 'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid,
           'content': content.decode(), 'base_tree_sha256': mod['tree_sha256']}
    ij.write('marker.json', rec)
    c.need(tsha_of(path.parent, drop_marker=True) == mod['tree_sha256'], 'base tree changed around marker',
           after_change=True)
    return {**rec, 'created': True}


# -- ESP checks (M10, M4, M18) ---------------------------------------------------------------------
def check_bootbin(ctx, ij, st):
    cfg = ctx.config
    bb = ctx.esp / 'm1n1' / 'boot.bin'
    live = c.sha_file(bb)[0] if os.path.lexists(bb) else None
    expected = cfg.get('expected_bootbin_sha256') or st['bootbin_sha256']
    old = ctx.esp / 'm1n1' / 'boot.bin.old'
    old_sha = c.sha_file(old)[0] if os.path.lexists(old) else None
    budget = None
    if live == expected and cfg.get('allow_bootbin_change'):
        # only the exact manifest-computed candidate, and update-m1n1 must have kept the original as boot.bin.old:
        # the copy a person at macOS Recovery puts back if the candidate stage 2 never reaches Linux.
        # The install grew boot.bin.old and boot.bin. The ESP must still pass the install gate (reserve + peak):
        # the way back rewrites a package UKI (charged at peak) above the unchanged reserve. Else stop here,
        # before anything boots the candidate.
        free = esp_free(ctx)
        need = int(cfg.get('esp_reserve_bytes', 125829120)) + peak(ctx)
        budget = {'esp_free': free, 'need': need, 'rule': 'reserve+peak after install', 'ok': free >= need}
        if live != st['bootbin_sha256'] and old_sha == st['bootbin_sha256'] and budget['ok']:
            return {'bootbin_unchanged': False, 'bootbin_is_expected': True, 'bootbin_sha256': live,
                    'recovery_copy': {'path': 'm1n1/boot.bin.old', 'sha256': old_sha}, 'esp_budget': budget}, None
    elif live == expected:
        return {'bootbin_unchanged': True, 'bootbin_sha256': live}, None
    restored = []
    with writers.BootLock():
        for rel, want in (('m1n1/boot.bin', st['bootbin_sha256']),
                          ('m1n1/boot.bin.old', (st['esp']['files'].get('m1n1/boot.bin.old') or {}).get('sha256'))):
            if want is None:
                continue
            dst = ctx.esp / rel
            if os.path.lexists(dst) and c.sha_file(dst)[0] == want:
                continue
            src = ctx.run_dir / 'capture' / 'esp' / rel
            if not os.path.lexists(src) and rel == 'm1n1/boot.bin':
                src = ctx.run_dir / 'capture' / 'boot.bin'
            data = c.read_small(src, 64 << 20)
            c.need(c.H(data) == want, 'captured %s copy mismatch' % rel, after_change=True)
            ij.write('bootbin-restore.%s.intent.json' % rel.replace('/', '_'),
                     {'rel': rel, 'live_sha256': c.sha_file(dst)[0] if os.path.lexists(dst) else None,
                      'restore_sha256': want})
            ctx.changed = True
            c.replace_file(dst, data)
            restored.append(rel)
    return ({'bootbin_unchanged': False, 'bootbin_sha256': live, 'bootbin_old_sha256': old_sha, 'restored': restored,
             'esp_budget': budget},
            'boot.bin changed by the transaction (live %s, boot.bin.old %s; expected %s, original %s; ESP budget %s); '
            'captured bytes restored (%s)' % (live, old_sha, expected, st['bootbin_sha256'], budget,
                                              ', '.join(restored) or 'nothing to restore'))


def _capture_menu(ctx, st):
    for rel in ('capture/esp/limine.conf', 'capture/menu.conf'):
        p = ctx.run_dir / rel
        if os.path.lexists(p):
            raw = c.read_small(p, 1 << 20)
            if c.H(raw) == st['menu']['sha256']:
                return raw
    return None


def entry_comments(m, e):
    out = []
    for line in m.lines[e.idx + 1:]:
        s = line.strip()
        if s.startswith('/') or s.startswith(limine.LAB_BEGIN):
            break
        mm = re.match(r'^comment:\s?(.*)$', s)
        if mm:
            out.append(mm.group(1).strip())
    return out


def load_prep(ctx):
    """espops-prep.json (written by esp-prep) or {} when esp-prep was not run (custom default kept)."""
    p = ctx.run_dir / 'espops-prep.json'
    if not os.path.lexists(p):
        return {}
    prep = json.loads(c.read_small(p, 4 << 20))
    c.need(prep.get('status', 'done') == 'done', 'esp-prep did not complete (status %s): run esp-restore first'
           % prep.get('status'), after_change=ctx.changed)
    return prep


def peak(ctx):
    """Per-file limit for pacman (RLIMIT_FSIZE) and the ESP gate: the value esp-prep measured and reserved."""
    p = load_prep(ctx).get('peak')
    return int(p) if p else int(ctx.config.get('peak_bytes') or PEAK)


def fallback_expect(prep):
    """Accepts espops.py's receipt (fallback {path, entry, sha256, ...}) and the older brief form
    (fallback {stanza_name, copy_path, default_after}); None when the default stays custom."""
    fb = prep.get('fallback')
    if not fb:
        return None
    name = (fb.get('entry') or fb.get('stanza_name') or '').lstrip('/')
    path = fb.get('path') or fb.get('copy_path')
    c.need(bool(name) and bool(path), 'espops-prep.json fallback lacks entry/path', after_change=True)
    value = fb['default_after'] if isinstance(fb.get('default_after'), str) else name
    return {'name': name, 'path': path, 'value': value.strip(), 'sha256': fb.get('sha256')}


def prep_ignore(prep):
    fb = fallback_expect(prep)
    out = [fb['path']] if fb else []
    out += [p['path'] for p in prep.get('parked') or [] if isinstance(p, dict) and p.get('path')]
    return out


def reassert_default(ctx, ij, st, prep):
    fb = fallback_expect(prep)
    cap = st['menu']['default']
    menu_p = ctx.esp / 'limine.conf'
    with writers.BootLock():
        raw = c.read_small(menu_p, 1 << 20)
        m = limine.Menu(raw)
        if fb:
            want_value, want_name, want_path = fb['value'], fb['name'], fb['path']
        else:
            capraw = _capture_menu(ctx, st)
            cm = limine.Menu(capraw) if capraw is not None else None
            want_value = cm.globals['default_entry'][1].strip() if cm and 'default_entry' in cm.globals else None
            want_name, want_path = cap['name'], cap['path']
        cur = m.globals.get('default_entry', (None, None))[1]
        rewrote = None
        if want_value is not None and (cur or '').strip() != want_value:
            m.set_global('default_entry', want_value)
            new = m.raw()
            n = 0
            while ij.has('default-reassert.%d.intent.json' % n):
                n += 1
            ij.write('default-reassert.%d.intent.json' % n, {'before': cur, 'after': want_value,
                                                             'before_sha256': c.H(raw), 'after_sha256': c.H(new)})
            ctx.changed = True
            c.need(c.H(c.read_small(menu_p, 1 << 20)) == c.H(raw), 'menu changed under the lock (CAS)',
                   after_change=True)
            c.replace_file(menu_p, new)
            c.need(c.read_small(menu_p, 1 << 20) == new, 'menu readback mismatch', after_change=True)
            raw, m, rewrote = new, limine.Menu(new), {'before': cur, 'after': want_value}
        d = m.default()
        c.need(d is not None and d.path(), 'default entry unresolvable after install', after_change=True)
        rel, pin = limine.split_path(d.path())
        uki = ctx.esp / rel
        sha = c.sha_file(uki)[0] if os.path.lexists(uki) else None
        b2 = c.b2_file(uki) if sha else None
        problems = []
        if d.fullname != want_name:
            problems.append('default resolves to %r, want %r' % (d.fullname, want_name))
        if rel != want_path:
            problems.append('default UKI path %s, want %s' % (rel, want_path))
        want_sha = (fb or {}).get('sha256') or cap['uki_sha256']
        if sha != want_sha or sha != cap['uki_sha256']:
            problems.append('default UKI bytes changed (%s != capture %s)' % (sha, cap['uki_sha256']))
        if pin is not None and pin != b2:
            problems.append('default path blake2b pin does not match UKI bytes')
        c.need(not problems, 'default entry check failed: ' + '; '.join(problems), after_change=True)
        return {'name': d.fullname, 'path': rel, 'uki_sha256': sha, 'mode': 'fallback' if fb else 'custom',
                'rewritten': rewrote, 'menu_sha256': c.H(raw)}, m


def installer_entries(ctx, m, plan):
    out = []
    for pkg, krel in plan.candidate_kernels():
        hits = []
        for e in m.walk():
            if not e.path() or '/Snapshots' in '/' + e.fullname:
                continue
            com = entry_comments(m, e)
            if 'Kernel version: %s' % krel not in com:
                continue
            rel, pin = limine.split_path(e.path())
            if 'limine_history/' in rel:
                continue
            uki = ctx.esp / rel
            sha = c.sha_file(uki)[0] if os.path.lexists(uki) else None
            hits.append({'pkg': pkg, 'krel': krel, 'entry_name': e.fullname, 'uki_path': rel, 'uki_sha256': sha,
                         'pin_ok': bool(sha) and (pin is None or pin == c.b2_file(uki)),
                         'kernel_id_match': ('kernel-id=%s' % pkg) in com})
        best = [h for h in hits if h['kernel_id_match']] or hits
        out.append(best[0] if len(best) == 1 else {'pkg': pkg, 'krel': krel, 'ambiguous_or_missing': hits})
    return out


def _excluded(rel, pats):
    for p in pats:
        if p.endswith('/'):
            if rel == p[:-1] or rel.startswith(p):
                return True
        elif fnmatch.fnmatchcase(rel, p):
            return True
    return False


def esp_diff(ctx, st, ignore=()):
    files = st['esp']['files']
    pats = st['esp'].get('excluded', ['ubootefi.var*', 'maclab/'])
    now = {}
    root = os.fspath(ctx.esp)
    for base, dirs, fns in os.walk(root, followlinks=False):
        rb = os.path.relpath(base, root)
        rb = '' if rb == '.' else rb + '/'
        dirs[:] = sorted(d for d in dirs if not _excluded(rb + d + '/', pats) and not _excluded(rb + d, pats))
        for fn in fns:
            rel = rb + fn
            if not _excluded(rel, pats):
                now[rel] = os.lstat(os.path.join(base, fn))
    new, changed = [], []
    for rel in sorted(set(now) - set(files) - set(ignore)):
        new.append({'path': rel, 'size': now[rel].st_size, 'sha256': c.sha_file(os.path.join(root, rel))[0]})
    for rel in sorted(set(now) & set(files)):
        f = files[rel]
        if now[rel].st_size != f['size'] or now[rel].st_mtime_ns != f['mtime_ns']:
            h = c.sha_file(os.path.join(root, rel))[0]
            if h != f['sha256']:
                changed.append({'path': rel, 'size': now[rel].st_size, 'sha256': h})
    return {'new': new, 'changed': changed, 'missing': sorted(set(files) - set(now) - set(ignore))}


def units_diff(ctx, st, plan):
    wu = set(ctx.config.get('writer_units', []))
    names = (set(st.get('units', {})) | plan.shipped_units()) - wu
    started, enabled = [], []
    for u in sorted(names):
        if u.startswith('snapper-'):
            continue
        s = writers.show(u)
        cap = st.get('units', {}).get(u, {})
        if s.get('ActiveState') in writers.RUNNING and cap.get('ActiveState') not in writers.RUNNING:
            started.append(u)
        if (s.get('UnitFileState') or '') != (cap.get('UnitFileState') or '') and s.get('LoadState') == 'loaded':
            enabled.append({'unit': u, 'now': s.get('UnitFileState'), 'capture': cap.get('UnitFileState')})
    return started, enabled


# -- install ---------------------------------------------------------------------------------------
def install(ctx):
    cfg = ctx.config
    st = load_state(ctx)
    krel_now = c.kernel_release()
    c.need(krel_now == cfg['known_good_kernel'] and krel_now == st['kernel'],
           'install must run on the known-good kernel captured (%s)' % st['kernel'])
    c.need('maclab.job=' not in c.cmdline(), 'install refused on a lab job boot')
    prep = load_prep(ctx)
    ij = Journal(ctx, 'install')
    plan = Plan(ctx)
    capver = {n: st['packages'].get(n, {}).get('version') for n in plan.cand}
    rk = st['running_kernel']
    if set(rk.get('owned_by') or []) & set(plan.cand):
        c.need(rk.get('copy') and os.path.isfile(ctx.run_dir / rk['copy']),
               'running kernel tree is owned by a candidate package but has no capture copy', after_change=ctx.changed)
    _check_groups_drained(ctx, ij)
    conflicts = st.get('conflicts', [])
    for cf in conflicts:
        c.need(cf.get('package') in plan.cand, 'conflict %s belongs to a non-candidate' % cf.get('path'))
    phases = []
    for tag, names in plan.phases:
        cur = c.pacman_versions(names)
        n, out = _phase_status(ij, tag)
        done = all(cur[x] == plan.cand[x]['version'] for x in names)
        if n is not None:
            c.need(out is not None and out.get('outcome') == 'COMPLETED' and not out.get('hook_errors') and done,
                   'install phase %s attempt %d did not complete (outcome %s): no automatic retry; run rollback'
                   % (tag, n, out.get('outcome') if out else 'missing'), after_change=ctx.changed)
            phases.append({'tag': tag, 'packages': names, 'outcome': 'COMPLETED', 'attempt': n, 'resumed': True})
            continue
        for x in names:
            c.need(cur[x] == capver[x], '%s is %s, capture %s: refusing' % (x, cur[x], capver[x]),
                   after_change=ctx.changed)
        expect = {x: (plan.cand[x]['version'], plan.cand_archive(x).sys_path) for x in names}
        allowed = set()
        for x in names:
            if cur[x] is not None:
                allowed.add('warning: downgrading package %s (%s => %s)' % (x, cur[x], plan.cand[x]['version']))
                allowed.add('warning: %s-%s is up to date -- reinstalling' % (x, cur[x]))
        mine = [cf for cf in conflicts if cf['package'] in names]
        rec = run_phase(ctx, ij, tag, 'U', names, [plan.cand_archive(x).sys_path for x in names], expect, allowed,
                        before_mutation=(lambda mine=mine: hold_conflicts(ctx, ij, mine)) if mine else None)
        after = c.pacman_versions(names)
        c.need(all(after[x] == plan.cand[x]['version'] for x in names),
               'phase %s versions after pacman: %s' % (tag, after), after_change=True)
        phases.append({'tag': tag, 'packages': names, 'outcome': rec['outcome'], 'attempt': rec['attempt'],
                       'warnings': rec['warnings']})
    vers = c.pacman_versions(list(plan.cand))
    c.need(all(vers[x] == plan.cand[x]['version'] for x in plan.cand), 'versions != candidates: %s' % vers,
           after_change=ctx.changed)
    _check_groups_drained(ctx, ij)
    tree = ensure_running_tree(ctx, ij, st)
    marker = ensure_marker(ctx, ij, st)
    bootbin, bootbin_err = check_bootbin(ctx, ij, st)
    default, menu = reassert_default(ctx, ij, st, prep)
    if bootbin_err:
        raise c.Failed(bootbin_err)
    entries = installer_entries(ctx, menu, plan)
    bad = [e for e in entries if 'ambiguous_or_missing' in e]
    c.need(not bad, 'installer entry for candidate kernel not found exactly once: %s' % bad, after_change=True)
    diff = esp_diff(ctx, st, prep_ignore(prep))
    capraw = _capture_menu(ctx, st)
    cap_entries = {e.fullname for e in limine.Menu(capraw).walk()} if capraw else set()
    fb_name = (fallback_expect(prep) or {}).get('name')
    new_entries = sorted(e.fullname for e in menu.walk() if e.fullname not in cap_entries and e.fullname != fb_name) \
        if capraw else None
    started, enabled = units_diff(ctx, st, plan)
    report = {'phases': phases, 'versions': vers, 'candidate': entries[0] if entries else None,
              'candidates_kernels': entries, 'running_tree': tree, 'marker': marker, **bootbin,
              'default_entry': default, 'esp_new_files': diff['new'], 'esp_changed_files': diff['changed'],
              'esp_missing_files': diff['missing'], 'menu_entries_new': new_entries, 'units_started': started,
              'units_enabled': enabled, 'conflicts_held': [cf['path'] for cf in conflicts
                                                           if ij.has('conflict.%s.held.json' % _cid(cf))],
              'esp_free': esp_free(ctx)}
    if not ij.has('result.json'):
        ij.write('result.json', report)
    return report


# -- rollback --------------------------------------------------------------------------------------
def _completed_packages(j):
    done = set()
    if j is None:
        return done
    for f in os.listdir(j.dir):
        if f.endswith('.outcome.json') and '.print.' not in f:
            r = j.read(f)
            if r.get('outcome') == 'COMPLETED' and not r.get('hook_errors'):
                done.update(r.get('packages', []))
    return done


def _suspects(ij):
    """Packages in an install phase that started but did not complete (files may be partial)."""
    out = set()
    if ij is None:
        return out
    for f in os.listdir(ij.dir):
        mm = re.fullmatch(r'(.+)\.(\d+)\.intent\.json', f)
        if not mm or mm.group(1).startswith(('conflict', 'marker', 'tree-restore', 'default-reassert',
                                              'bootbin-restore')):
            continue
        oname = '%s.%s.outcome.json' % (mm.group(1), mm.group(2))
        o = ij.read(oname) if ij.has(oname) else None
        if o is None or o.get('outcome') != 'COMPLETED' or o.get('hook_errors'):
            out.update(ij.read(f).get('packages', []))
    return out


def remove_marker(ctx, ij, rj):
    if ij is None or not (ij.has('marker.json') or ij.has('marker.intent.json')):
        return {'owned_marker': False}
    rec = ij.read('marker.json') if ij.has('marker.json') else ij.read('marker.intent.json')
    path = c.P(rec['path'])
    s = _lstat(path)
    if s is None:
        return {'owned_marker': True, 'removed': True, 'already_absent': True}
    want = rec['sha256']
    c.need(stat.S_ISREG(s.st_mode) and c.sha_file(path)[0] == want, 'marker content is not ours; not removing',
           after_change=ctx.changed)
    if 'ino' in rec:
        c.need(s.st_ino == rec['ino'], 'marker inode drift; not removing', after_change=ctx.changed)
        if rec.get('boot_id') == c.boot_id():
            c.need(s.st_dev == rec['dev'], 'marker device drift; not removing', after_change=ctx.changed)
    rj.once('marker.remove-intent.json', {'receipt': rec, 'live_ino': s.st_ino, 'live_dev': s.st_dev})
    ctx.changed = True
    os.unlink(path)
    c.fsync_dir(path.parent)
    rj.once('marker.removed.json', {'path': rec['path']})
    return {'owned_marker': True, 'removed': True}


def stop_units(ctx, rj, st, plan):
    stopped = []
    started, _ = units_diff(ctx, st, plan)
    for u in started:
        rj.once('unit-stop.%s.json' % u, {'unit': u, 'state': writers.show(u)})
        ctx.changed = True
        writers.systemctl('stop', u)
        s = writers.wait_state(u, writers.STOPPED)
        c.need(s.get('ActiveState') in writers.STOPPED, 'could not stop %s' % u, after_change=True)
        stopped.append(u)
    return stopped


def rollback(ctx):
    cfg = ctx.config
    st = load_state(ctx)
    c.need(c.kernel_release() == cfg['known_good_kernel'], 'rollback must run on the known-good kernel %s (now %s)'
           % (cfg['known_good_kernel'], c.kernel_release()))
    c.need('maclab.job=' not in c.cmdline(), 'rollback refused on a lab job boot')
    c.need(not os.path.lexists(c.P(DB_LOCK)), 'pacman db.lck present')
    writers.verify_masked(ctx)
    ij = _install_journal_existing(ctx)
    rj = Journal(ctx, 'rollback')
    _check_groups_drained(ctx, ij, rj)
    plan = Plan(ctx)
    cand = {n: p['version'] for n, p in plan.cand.items()}
    orig = {n: plan.orig[n].get('version') for n in plan.cand}
    for n in plan.cand:
        c.need(st['packages'].get(n, {}).get('version') == orig[n], 'config original %s %s != capture %s'
               % (n, orig[n], st['packages'].get(n, {}).get('version')))
    cur = c.pacman_versions(list(plan.cand))
    for n in plan.cand:
        c.need(cur[n] in (cand[n], orig[n]), '%s is %s: neither candidate %s nor original %s'
               % (n, cur[n], cand[n], orig[n]), after_change=ctx.changed)
    suspects = (_suspects(ij) | _suspects(rj)) - _completed_packages(rj)
    conflicts = st.get('conflicts', [])
    krel = st['running_kernel']['krel']
    live = c.P(MODULES) / krel
    hold = c.P(MODULES) / ('.bt2-hold-%s-%s' % (run8(ctx), krel))
    res = {'units_stopped': stop_units(ctx, rj, st, plan)}
    res['marker'] = remove_marker(ctx, ij, rj)

    def needs(n):
        return cur[n] != orig[n] or (n in suspects and orig[n] is not None)

    # Phase plan (reversed install order): boot package first, then -U originals, then -R new packages.
    todo = []
    if BOOT_PKG in plan.cand and needs(BOOT_PKG) and (orig[BOOT_PKG] is not None or cur[BOOT_PKG] is not None):
        todo.append(('boot', 'R' if orig[BOOT_PKG] is None else 'U', [BOOT_PKG]))
    rest_u = [n for n in plan.cand if n != BOOT_PKG and orig[n] is not None and needs(n)]
    rest_r = [n for n in plan.cand if n != BOOT_PKG and orig[n] is None and cur[n] is not None]
    if rest_u:
        todo.append(('rest-u', 'U', rest_u))
    if rest_r:
        todo.append(('rest-r', 'R', rest_r))
    res['unrecoverable_partial'] = sorted(n for n in suspects if orig[n] is None and cur[n] is None)

    # Hold the unowned running tree when an original archive will own it again (M9).
    reinstalling = [plan.orig_archive(n) for _, op, names in todo if op == 'U' for n in names]
    tree = {'krel': krel, 'held': False}
    if os.path.lexists(hold):
        tree.update(held=True, resumed=True)
    elif os.path.isdir(live) and not os.path.islink(live) and any(a.owns_tree(krel) for a in reinstalling if a):
        if not owned_by('%s/%s' % (MODULES, krel)):
            rows_sha = tsha_of(live)
            rj.once('tree.hold-intent.json', {'live': '%s/%s' % (MODULES, krel), 'hold': '%s/%s' % (MODULES, hold.name),
                                              'tree_sha256': rows_sha,
                                              'capture_tree_sha256': st['modules'][krel]['tree_sha256']})
            ctx.changed = True
            os.rename(live, hold)
            c.fsync_dir(live.parent)
            c.need(tsha_of(hold) == rows_sha and not os.path.lexists(live), 'tree hold readback mismatch',
                   after_change=True)
            rj.once('tree.held.json', {'hold': '%s/%s' % (MODULES, hold.name), 'tree_sha256': rows_sha})
            tree['held'] = True

    phases = []
    for tag, op, names in todo:
        now = c.pacman_versions(names)
        if op == 'U':
            expect = {n: (orig[n], plan.orig_archive(n).sys_path) for n in names}
            targets = [plan.orig_archive(n).sys_path for n in names]
            allowed = set()
            for n in names:
                if now[n] is not None:
                    allowed.add('warning: downgrading package %s (%s => %s)' % (n, now[n], orig[n]))
                    allowed.add('warning: %s-%s is up to date -- reinstalling' % (n, now[n]))
        else:
            expect = {n: (now[n], None) for n in names}
            targets, allowed = list(names), set()
        rec = run_phase(ctx, rj, tag, op, names, targets, expect, allowed, purpose='rollback')
        after = c.pacman_versions(names)
        c.need(all(after[n] == orig[n] for n in names), 'rollback phase %s versions: %s' % (tag, after),
               after_change=True)
        phases.append({'tag': tag, 'op': op, 'packages': names, 'attempt': rec['attempt'], 'warnings': rec['warnings']})
        cur.update(after)
        mine = [cf for cf in conflicts if cf['package'] in names]
        if mine:
            reinstate_conflicts(ctx, ij, rj, mine) if ij else None
    res['phases'] = phases
    # Sweep: every held conflict whose package is back at its original state.
    res['conflicts_reinstated'] = reinstate_conflicts(ctx, ij, rj, [cf for cf in conflicts
                                                                     if cur.get(cf['package']) == orig.get(cf['package'])]) \
        if ij else []
    # Every leftover ever displaced into hold/displaced/ (also by an earlier, failed attempt): named in this result,
    # i.e. in receipts/rollback.N.json, so cleanup (which only trusts receipts and run-dir JSON) can remove hold/.
    res['conflicts_displaced'] = sorted(
        rj.read(f).get('hold') or '%s/hold/displaced/%s/%s' % (sys_run(ctx), f.split('.')[1],
                                                              os.path.basename(rj.read(f)['path']))
        for f in os.listdir(rj.dir) if re.fullmatch(r'conflict\.[0-9a-f]+\.displace\.json', f))

    # Verify packages + DB identity.
    names_all = sorted(st['packages'])
    vers = c.pacman_versions(names_all)
    diffs = ['%s %s != capture %s' % (n, vers[n], st['packages'][n]['version']) for n in names_all
             if vers[n] != st['packages'][n]['version']]
    for n in names_all:
        v = st['packages'][n]['version']
        want = st['packages'][n].get('mtree_sha256')
        if v is not None and want is not None and mtree_sha(n, v) != want:
            diffs.append('%s mtree sha differs from capture' % n)
    c.need(not diffs, 'post-rollback package state != capture: ' + '; '.join(diffs), after_change=ctx.changed)

    # Running tree must equal capture; the hold is deleted only when it is exact too.
    _check_groups_drained(ctx, ij, rj)
    expected = st['modules'][krel]['tree_sha256']
    live_sha = tsha_of(live)
    if tree['held'] or os.path.lexists(hold):
        hold_sha = tsha_of(hold)
        subset = False
        if live_sha == expected and hold_sha != expected and os.path.isdir(hold):
            # A partial tree (e.g. left by a failed install) is deletable only if every entry it holds exists
            # byte/meta-identical in the exact live tree: nothing is lost (M1 reference 'leftover subset' rule).
            lrows, hrows = _TREE(live), _TREE(hold)
            subset = all(lrows.get(k) == v for k, v in hrows.items())
        c.need(live_sha == expected and (hold_sha == expected or subset),
               'running tree after rollback: live %s, held %s, capture %s; both kept (%s)'
               % (live_sha, hold_sha, expected, hold.name), after_change=True)
        rj.once('tree.hold-delete-intent.json', {'hold': '%s/%s' % (MODULES, hold.name), 'tree_sha256': hold_sha,
                                                 'exact': hold_sha == expected, 'subset_of_live': subset})
        ctx.changed = True
        shutil.rmtree(hold)
        c.fsync_dir(hold.parent)
        rj.once('tree.hold-deleted.json', {'hold': '%s/%s' % (MODULES, hold.name)})
        tree.update(held=True, hold_deleted=True, hold_was_partial=subset)
    else:
        c.need(live_sha == expected, 'running tree %s after rollback differs from capture (%s != %s)'
               % (krel, live_sha, expected), after_change=ctx.changed)
    tree['exact'] = True
    res['tree'] = tree
    res['packages'] = vers
    # Unowned residue of candidate trees (e.g. depmod output) is reported; linux-modules-cleanup removes it on the
    # next ordinary boot and audit accounts for it. We never delete what the package manager left.
    res['leftover_candidate_module_dirs'] = sorted(
        k for _, k in plan.candidate_kernels()
        if k != krel and os.path.lexists(c.P(MODULES) / k) and not (st['modules'].get(k) or {}).get('tree_sha256'))
    res['units_still_started'] = units_diff(ctx, st, plan)[0]
    c.need(not res['units_still_started'], 'units started by the transaction still active: %s'
           % res['units_still_started'], after_change=ctx.changed)
    # A package absent at capture whose install phase died mid-transaction has no local DB entry, so no -R removes
    # what it extracted, and the audit (packages, trees, ESP, /etc set) cannot see unowned payload elsewhere. Every
    # existing, unowned payload path of such a package that is not a captured conflict (reinstated above) and not in
    # the /etc capture set (etc-restore moves those aside) was written by that transaction: stop, record, report
    # instead of declaring the rollback exact. Nothing is deleted.
    res['partial_residue'] = partial_residue(st, plan, res['unrecoverable_partial'])
    c.need(not res['partial_residue'], 'rollback incomplete: the interrupted install of %s left unowned payload '
           '(review and move aside, then re-run rollback): %s' % (res['unrecoverable_partial'],
                                                                  res['partial_residue'][:20]), after_change=True)
    return res


def partial_residue(st, plan, partial):
    if not partial:
        return []
    import capture   # shared batched `pacman -Qqo` (same semantics as the capture conflict scan)
    known = {x['path'] for x in st.get('conflicts', []) + st.get('conflicts_other', [])} | set(st.get('etc', {}))
    live = sorted({'/' + m for n in partial for m, kind in plan.cand_archive(n).members.items()
                   if kind != 'd' and '/' + m not in known and _lstat(c.P('/' + m)) is not None})
    unowned = capture.owners_unowned(live) if live else set()
    return [p for p in live if p in unowned]
