"""hold-writers / release-writers (SPEC 'hold-writers / release-writers'; research M5 + M13).

Persistent writer hold that survives reboots:
- refuse while snapper-cleanup.service / snapper-timeline.service run (never cancel cleanup/snapshot);
- under /run/lock/boot-partition.lock: stop timers first, then services (each Id once);
- an alias symlink in /etc/systemd/system is hard-linked to <run>/hold/alias.<unit> (same inode) and unlinked;
- a mask symlink <unit> -> /dev/null is created by os.symlink (exact path/target are ours), then daemon-reload;
- verify masked + inactive. writers.json records exactly what we did; release undoes only that.
Every mutation journals an intent file in <run>/writers/ first and updates writers.json right after, so a
crashed hold/release can be re-run and continues from the recorded state.
"""
import fcntl
import json
import os
import re
import stat
import time

import common as c

ETC = '/etc/systemd/system'
LOCK = '/run/lock/boot-partition.lock'
BUSY = ('snapper-cleanup.service', 'snapper-timeline.service')
RUNNING = ('active', 'activating', 'deactivating', 'reloading', 'refreshing')
STOPPED = ('inactive', 'failed')
PROPS = ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'FragmentPath', 'DropInPaths')
CAPTURE_PROPS = ('LoadState', 'ActiveState', 'UnitFileState', 'FragmentPath', 'DropInPaths')
UNIT_RE = re.compile(r'^[A-Za-z0-9@_.:\\-]{1,200}\.(service|timer|socket|path)$')
SCHEMA = 'bt2.writers/1'


# -- boot partition lock (M13) ---------------------------------------------------------------------
class BootLock:
    """flock on /run/lock/boot-partition.lock; the tmpfs file is created only if missing (root 0644,
    O_EXCL|O_NOFOLLOW). Creating the lock file is not a system-state change (it vanishes at reboot)."""

    def __init__(self, timeout=60):
        self.timeout = timeout
        self.fd = None
        self.created = False

    def __enter__(self):
        p = c.P(LOCK)
        try:
            fd = os.open(p, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            try:
                fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
                os.fchmod(fd, 0o644)
                self.created = True
            except FileExistsError:
                fd = os.open(p, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise c.Refused('boot-partition.lock is not a regular file')
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise c.Refused('boot-partition.lock still held after %ds' % self.timeout)
                time.sleep(0.05)
        ls = os.lstat(p)
        if (ls.st_dev, ls.st_ino) != (st.st_dev, st.st_ino):
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            raise c.Refused('boot-partition.lock path replaced while locking')
        self.fd = fd
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None
        return False


# -- systemctl -------------------------------------------------------------------------------------
def show(unit):
    r = c.run([c.BIN('systemctl'), 'show', unit, '--no-pager', '--property=' + ','.join(PROPS)], timeout=30)
    props = {}
    for line in r.stdout.decode(errors='replace').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            props[k] = v
    return props


def systemctl(*args, timeout=120):
    return c.run([c.BIN('systemctl'), *args], timeout=timeout)


def wait_state(unit, want, seconds=20):
    """Poll show() until ActiveState is in `want` (handles activating/deactivating transitions)."""
    deadline = time.monotonic() + seconds
    while True:
        s = show(unit)
        if s.get('ActiveState') in want or time.monotonic() >= deadline:
            return s
        time.sleep(0.2)


# -- helpers ---------------------------------------------------------------------------------------
def _lstat(p):
    try:
        return os.lstat(p)
    except FileNotFoundError:
        return None


def _wpath(ctx):
    return ctx.run_dir / 'writers.json'


def _load(ctx):
    return json.loads(c.read_small(_wpath(ctx), 4 << 20))


def _save(ctx, w):
    c.replace_file(_wpath(ctx), c.dump(w), 0o600)


def _sys_hold(ctx, unit):
    return '/var/lib/maclab/bt2/%s/hold/alias.%s' % (ctx.config['run_id'], unit)


def _journal(ctx, name, obj):
    """Write an intent file once (O_EXCL); a re-run after a crash keeps the first intent."""
    p = ctx.sub('writers') / name
    if not os.path.lexists(p):
        c.write_new(p, c.dump({**obj, 'boot_id': c.boot_id(), 'at': time.time()}))
    return p


def _has(ctx, name):
    return os.path.lexists(ctx.run_dir / 'writers' / name)


def _read_j(ctx, name):
    return json.loads(c.read_small(ctx.run_dir / 'writers' / name, 1 << 20))


def _load_capture(ctx, required):
    p = ctx.run_dir / 'capture' / 'state.json'
    if not os.path.lexists(p):
        c.need(not required, 'capture/state.json missing', after_change=ctx.changed)
        return None
    st = json.loads(c.read_small(p, 256 << 20))
    c.need(st.get('schema') == 'bt2.capture/1' and st.get('run_id') == ctx.config['run_id'],
           'capture/state.json schema/run mismatch', after_change=ctx.changed)
    return st


def _units(ctx):
    units = list(ctx.config.get('writer_units', []))
    for u in units:
        c.need(UNIT_RE.match(u) and '/' not in u, 'bad writer unit name: %r' % u)
    return units


def verify_masked(ctx, w=None, after_change=False):
    """Proof that the hold recorded in writers.json is in force (used by hold, install and rollback)."""
    if w is None:
        p = _wpath(ctx)
        c.need(os.path.lexists(p), 'writers are not held (writers.json missing)', after_change)
        w = _load(ctx)
    c.need(w.get('schema') == SCHEMA and w.get('complete') and not w.get('released'),
           'writer hold incomplete or already released', after_change)
    proof = {'masks': [], 'aliases': [], 'units': {}}
    for m in w['masks']:
        p = c.P(m['path'])
        ls = _lstat(p)
        c.need(ls is not None and stat.S_ISLNK(ls.st_mode) and os.readlink(p) == '/dev/null'
               and ls.st_ino == m['ino'], 'owned mask drifted: %s' % m['path'], after_change)
        proof['masks'].append({'unit': m['unit'], 'ino': ls.st_ino})
    for a in w['aliases']:
        h = c.P(a['held'])
        hs = _lstat(h)
        c.need(hs is not None and stat.S_ISLNK(hs.st_mode) and hs.st_ino == a['ino']
               and os.readlink(h) == a['target'], 'held alias drifted: %s' % a['held'], after_change)
        proof['aliases'].append({'unit': a['unit'], 'ino': hs.st_ino})
    for u in w['present']:
        s = show(u)
        c.need(s.get('LoadState') == 'masked' and s.get('ActiveState') in STOPPED,
               'writer %s not masked+inactive (%s/%s)' % (u, s.get('LoadState'), s.get('ActiveState')), after_change)
        proof['units'][u] = {'LoadState': s.get('LoadState'), 'ActiveState': s.get('ActiveState')}
    for b in BUSY:
        s = show(b)
        c.need(s.get('ActiveState') not in RUNNING, '%s is %s' % (b, s.get('ActiveState')), after_change)
    return proof


# -- hold ------------------------------------------------------------------------------------------
def hold(ctx):
    units = _units(ctx)
    etc = c.P(ETC)
    wp = _wpath(ctx)
    w = None
    if os.path.lexists(wp):
        w = _load(ctx)
        c.need(w.get('schema') == SCHEMA and w.get('units') == units, 'writers.json does not match config')
        c.need(not w.get('released'), 'writers already released in this run; refusing to re-hold')
        if w.get('complete'):
            return {'already_held': True, 'writers': w, 'proof': verify_masked(ctx, w)}
    _load_capture(ctx, required=False)  # schema check only; hold does not depend on capture contents
    hold_dir = ctx.sub('hold')
    c.need(os.lstat(hold_dir).st_dev == os.lstat(etc).st_dev,
           'run dir hold/ and %s are on different filesystems: alias hard link impossible' % ETC,
           after_change=ctx.changed)

    # Gates (before any change): no running cleanup/snapshot, no transitional writer, no custom unit file.
    for b in BUSY:
        s = show(b)
        c.need(s.get('ActiveState') not in RUNNING,
               '%s is %s: never cancel a running cleanup/snapshot' % (b, s.get('ActiveState')),
               after_change=ctx.changed)
    states = {u: show(u) for u in units}
    present = [u for u in units if states[u].get('LoadState') in ('loaded', 'masked')
               or os.path.lexists(etc / u)]
    for u in present:
        ls = _lstat(etc / u)
        c.need(ls is None or stat.S_ISLNK(ls.st_mode),
               'custom unit file/dir at %s/%s: not a symlink, refusing' % (ETC, u), after_change=ctx.changed)
        a = states[u].get('ActiveState')
        c.need(a in RUNNING[:1] + STOPPED, 'writer %s is in transitional state %s' % (u, a), after_change=ctx.changed)
    if w is None:
        w = {'schema': SCHEMA, 'run_id': ctx.config['run_id'], 'units': units, 'present': present,
             'not_present': [u for u in units if u not in present],
             'before': {u: {k: states[u].get(k) for k in PROPS} for u in units},
             'masks': [], 'aliases': [], 'stopped': [], 'was_active': [], 'preexisting_masks': [],
             'complete': False, 'released': False, 'hold_boot_id': c.boot_id(),
             # recorded BEFORE the first change; release restores it (audit compares the dir's metadata)
             'etc_systemd_dir_mtime_ns': os.lstat(etc).st_mtime_ns}
    else:
        present = w['present']

    with BootLock() as lk:
        # 1. stop: timers first (no new cleanup trigger), then services; each unit Id once.
        order = [u for u in present if u.endswith('.timer')] + [u for u in present if not u.endswith('.timer')]
        seen = set()
        for u in order:
            s = show(u)
            uid = s.get('Id') or u
            if uid in seen:
                continue
            seen.add(uid)
            if s.get('ActiveState') in RUNNING:
                if uid not in w['was_active']:
                    w['was_active'].append(uid)
                _journal(ctx, 'stop.%s.json' % uid, {'unit': uid, 'via': u, 'before': s})
                ctx.changed = True
                _save(ctx, w)
                systemctl('stop', uid)
                s2 = wait_state(uid, STOPPED)
                c.need(s2.get('ActiveState') in STOPPED, 'stop of %s did not take (%s)' % (uid, s2.get('ActiveState')),
                       after_change=True)
                if uid not in w['stopped']:
                    w['stopped'].append(uid)
                _save(ctx, w)
            for b in BUSY:
                sb = show(b)
                c.need(sb.get('ActiveState') not in RUNNING, '%s started while stopping writers' % b,
                       after_change=ctx.changed)

        # 2. persistent masks (+ alias hold by hard link).
        for u in present:
            p = etc / u
            sysp = ETC + '/' + u
            mine = [m for m in w['masks'] if m['unit'] == u]
            if mine:
                ls = _lstat(p)
                c.need(ls is not None and stat.S_ISLNK(ls.st_mode) and os.readlink(p) == '/dev/null'
                       and ls.st_ino == mine[0]['ino'], 'owned mask drifted: %s' % sysp, after_change=ctx.changed)
                continue
            ls = _lstat(p)
            if ls is not None and stat.S_ISLNK(ls.st_mode) and os.readlink(p) == '/dev/null':
                if _has(ctx, 'mask.%s.json' % u):      # we created it before a crash: adopt with proof
                    w['masks'].append({'unit': u, 'path': sysp, 'ino': ls.st_ino, 'target': '/dev/null'})
                    _save(ctx, w)
                elif u not in w['preexisting_masks']:  # someone else's mask: leave it alone
                    w['preexisting_masks'].append(u)
                continue
            if ls is not None:  # an alias / custom symlink: hold its inode by hard link, then unlink
                c.need(stat.S_ISLNK(ls.st_mode), 'not a symlink: %s' % sysp, after_change=ctx.changed)
                target = os.readlink(p)
                held = hold_dir / ('alias.' + u)
                rec = {'unit': u, 'path': sysp, 'held': _sys_hold(ctx, u), 'ino': ls.st_ino, 'dev': ls.st_dev,
                       'target': target}
                _journal(ctx, 'alias.%s.json' % u, rec)
                ctx.changed = True
                hs = _lstat(held)
                if hs is None:
                    os.link(p, held, follow_symlinks=False)
                    c.fsync_dir(hold_dir)
                    hs = os.lstat(held)
                c.need(stat.S_ISLNK(hs.st_mode) and hs.st_ino == ls.st_ino and os.readlink(held) == target,
                       'held alias is not the same inode: %s' % held, after_change=True)
                os.unlink(p)
                c.fsync_dir(etc)
                w['aliases'].append({k: rec[k] for k in ('unit', 'path', 'held', 'ino', 'target')})
                _save(ctx, w)
            elif _has(ctx, 'alias.%s.json' % u) and not any(a['unit'] == u for a in w['aliases']):
                rec = _read_j(ctx, 'alias.%s.json' % u)   # crashed after unlink: reconcile from intent
                hs = _lstat(c.P(rec['held']))
                c.need(hs is not None and hs.st_ino == rec['ino'], 'alias intent without held inode: %s' % u,
                       after_change=True)
                w['aliases'].append({k: rec[k] for k in ('unit', 'path', 'held', 'ino', 'target')})
                _save(ctx, w)
            _journal(ctx, 'mask.%s.json' % u, {'unit': u, 'path': sysp, 'target': '/dev/null'})
            ctx.changed = True
            os.symlink('/dev/null', p)
            ms = os.lstat(p)
            c.fsync_dir(etc)
            w['masks'].append({'unit': u, 'path': sysp, 'ino': ms.st_ino, 'target': '/dev/null'})
            _save(ctx, w)
        if ctx.changed or not w['complete']:
            systemctl('daemon-reload')
        w['complete'] = True
        try:
            proof = verify_masked(ctx, w, after_change=ctx.changed)
        except (c.Refused, c.Failed):
            w['complete'] = False
            _save(ctx, w)
            raise
        w['lock_created'] = lk.created
        _save(ctx, w)
    return {'already_held': False, 'writers': w, 'proof': proof}


# -- release ---------------------------------------------------------------------------------------
def _alias_ino(w, unit):
    for a in w['aliases']:
        if a['unit'] == unit:
            return a['ino']
    return None


def _verify_released(ctx, w, st, after_change):
    for m in w['masks']:
        ls = _lstat(c.P(m['path']))
        ai = _alias_ino(w, m['unit'])
        c.need(ls is None or (ai is not None and ls.st_ino == ai), 'mask still present: %s' % m['path'],
               after_change)
    for a in w['aliases']:
        ls = _lstat(c.P(a['path']))
        c.need(ls is not None and stat.S_ISLNK(ls.st_mode) and ls.st_ino == a['ino']
               and os.readlink(c.P(a['path'])) == a['target'], 'alias not re-linked with original inode: %s'
               % a['path'], after_change)
        c.need(not os.path.lexists(c.P(a['held'])), 'held alias link still present: %s' % a['held'], after_change)
    want = w.get('etc_systemd_dir_mtime_ns')
    if want is not None:
        got = os.lstat(c.P(ETC)).st_mtime_ns
        c.need(got == want, '%s mtime %d != recorded %d' % (ETC, got, want), after_change)
    caps = (st or {}).get('units', {})
    units = {}
    diffs = []
    for u in w['units']:
        if u not in caps:
            continue
        want = caps[u]
        s = show(u)
        if s.get('ActiveState') != want.get('ActiveState') and s.get('ActiveState') in RUNNING[1:]:
            s = wait_state(u, (want.get('ActiveState'),), 15)
        units[u] = {k: s.get(k) for k in CAPTURE_PROPS}
        for k in CAPTURE_PROPS:
            if k in want and (s.get(k) or '') != (want.get(k) or ''):
                diffs.append('%s %s=%r (capture %r)' % (u, k, s.get(k), want.get(k)))
    c.need(not diffs, 'writer states differ from capture: ' + '; '.join(diffs), after_change)
    return {'units': units, 'equal_to_capture': True}


def release(ctx):
    c.need(os.path.lexists(_wpath(ctx)), 'no writer hold recorded (writers.json missing)')
    w = _load(ctx)
    c.need(w.get('schema') == SCHEMA, 'writers.json schema')
    st = _load_capture(ctx, required=True)
    if w.get('released'):
        return {'already_released': True, 'writers': w, 'proof': _verify_released(ctx, w, st, False)}
    etc = c.P(ETC)
    with BootLock():
        for m in reversed(w['masks']):
            p = c.P(m['path'])
            ls = _lstat(p)
            if ls is None:
                continue  # removed by an earlier (crashed) release
            ai = _alias_ino(w, m['unit'])
            if ai is not None and ls.st_ino == ai:
                continue  # already replaced by the re-linked original alias (crashed release)
            c.need(stat.S_ISLNK(ls.st_mode) and os.readlink(p) == '/dev/null' and ls.st_ino == m['ino'],
                   'mask at %s is not the one we created; refusing' % m['path'], after_change=ctx.changed)
            _journal(ctx, 'unmask.%s.json' % m['unit'], m)
            ctx.changed = True
            os.unlink(p)
            c.fsync_dir(etc)
        for a in w['aliases']:
            p, h = c.P(a['path']), c.P(a['held'])
            ls = _lstat(p)
            if ls is not None:
                c.need(stat.S_ISLNK(ls.st_mode) and ls.st_ino == a['ino'],
                       'alias path %s occupied by another inode' % a['path'], after_change=ctx.changed)
                hs = _lstat(h)
                if hs is not None:  # re-linked before a crash; drop our extra link
                    c.need(hs.st_ino == a['ino'], 'held alias inode drift', after_change=ctx.changed)
                    ctx.changed = True
                    os.unlink(h)
                    c.fsync_dir(h.parent)
                continue
            hs = _lstat(h)
            c.need(hs is not None and stat.S_ISLNK(hs.st_mode) and hs.st_ino == a['ino']
                   and os.readlink(h) == a['target'], 'held alias missing or changed: %s' % a['held'],
                   after_change=ctx.changed)
            _journal(ctx, 'relink.%s.json' % a['unit'], a)
            ctx.changed = True
            os.link(h, p, follow_symlinks=False)
            c.fsync_dir(etc)
            ps = os.lstat(p)
            c.need(ps.st_ino == a['ino'] and os.readlink(p) == a['target'], 're-linked alias inode mismatch',
                   after_change=True)
            os.unlink(h)
            c.fsync_dir(h.parent)
        systemctl('daemon-reload')
        want = w.get('etc_systemd_dir_mtime_ns')
        if want is not None and os.lstat(etc).st_mtime_ns != want:
            _journal(ctx, 'etc-dir-mtime.json', {'path': ETC, 'mtime_ns': want,
                                                 'live_mtime_ns': os.lstat(etc).st_mtime_ns})
            ctx.changed = True
            os.utime(etc, ns=(os.lstat(etc).st_atime_ns, want), follow_symlinks=False)
            c.fsync_dir(etc)
            c.need(os.lstat(etc).st_mtime_ns == want, '%s mtime restore failed' % ETC, after_change=True)
    # Start (outside the lock: a started writer takes the lock itself) only what was active at capture.
    caps = st.get('units', {})
    start = []
    for u in w['present']:
        s = show(u)
        uid = s.get('Id') or u
        cap = caps.get(u, {}).get('ActiveState')
        should = (cap == 'active') if cap is not None else (uid in w['was_active'])
        if should and s.get('ActiveState') not in RUNNING and uid not in start:
            start.append(uid)
    start.sort(key=lambda x: x.endswith('.timer'))  # services first, timers last (reverse of stop order)
    for uid in start:
        _journal(ctx, 'start.%s.json' % uid, {'unit': uid})
        ctx.changed = True
        systemctl('start', uid)
    proof = _verify_released(ctx, w, st, after_change=ctx.changed)
    w['released'] = True
    w['started'] = start
    w['release_boot_id'] = c.boot_id()
    _save(ctx, w)
    return {'already_released': False, 'started': start, 'writers': w, 'proof': proof}
