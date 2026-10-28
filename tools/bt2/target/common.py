"""bt2 target-side shared helpers (stdlib only; runs as root on the Mac).

Conventions (see CONTRACT.md):
- exit 0 ok; 3 refused before any change; 4 failed after a change; 5 internal error.
- exactly one JSON object on the last stdout line; the same object is written to receipts/<cmd>.<seq>.json.
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

ESP_DEFAULT = '/boot/efi'
SCHEMA_RESULT = 'bt2.target-result/1'

# Test seams. On a real Mac both are unset: P() is identity and BIN() is /usr/bin.
# Tests set BT2_TEST_ROOT (a temp dir that mirrors / ) and BT2_TEST_BIN (fake pacman/systemctl/...).
TEST_ROOT = os.environ.get('BT2_TEST_ROOT')
TEST_BIN = os.environ.get('BT2_TEST_BIN')


def P(path):
    """Map an absolute system path into the test root (identity in production)."""
    path = str(path)
    if TEST_ROOT and path.startswith('/'):
        return Path(TEST_ROOT + path)
    return Path(path)


def BIN(name):
    return (TEST_BIN.rstrip('/') + '/' + name) if TEST_BIN else '/usr/bin/' + name


class Refused(Exception):
    """Gate failed before any change was made (exit 3)."""


class Failed(Exception):
    """Failure after a change was made; restore required (exit 4)."""


def need(cond, msg, after_change=False):
    if not cond:
        raise (Failed if after_change else Refused)(msg)


def H(b):
    return hashlib.sha256(b).hexdigest()


def sha_file(path, limit=None):
    h = hashlib.sha256()
    n = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            h.update(b)
            n += len(b)
            if limit is not None and n > limit:
                raise Refused('file exceeds limit: %s' % path)
    finally:
        os.close(fd)
    return h.hexdigest(), n


def b2_file(path):
    h = hashlib.blake2b(digest_size=64)
    with open(path, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def read_small(path, limit=4 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_size <= limit, 'not a bounded regular file: %s' % path)
        parts = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            parts.append(b)
        return b''.join(parts)
    finally:
        os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data, mode=0o600):
    """O_EXCL write + fsync + dir fsync + readback."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view[:1 << 20])
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(path.parent)
    if read_small(path, len(data) + 1) != data:
        raise Failed('readback mismatch: %s' % path)
    return {'path': str(path), 'sha256': H(data), 'bytes': len(data)}


def replace_file(path, data, mode=None):
    """Atomic replace via temp file in the same dir (fsync), keeping the existing mode unless given."""
    path = Path(path)
    if mode is None:
        mode = stat.S_IMODE(os.lstat(path).st_mode) if os.path.lexists(path) else 0o644
    tmp = path.with_name('.' + path.name + '.bt2tmp')
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view[:1 << 20])
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    fsync_dir(path.parent)
    got, n = sha_file(path)
    if got != H(data) or n != len(data):
        raise Failed('replace readback mismatch: %s' % path)


def dump(obj):
    return (json.dumps(obj, sort_keys=True, indent=1) + '\n').encode()


def run(argv, timeout=600, check=True, env=None, input=None):
    e = {'PATH': ((TEST_BIN + ':') if TEST_BIN else '') + '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
    if TEST_ROOT:
        e['BT2_TEST_ROOT'] = TEST_ROOT
    if env:
        e.update(env)
    r = subprocess.run(argv, capture_output=True, timeout=timeout, env=e, input=input)
    if check and r.returncode != 0:
        raise Refused('%s failed (%d): %s' % (argv[0], r.returncode, r.stderr.decode(errors='replace')[-600:]))
    return r


def boot_id():
    return P('/proc/sys/kernel/random/boot_id').read_text().strip()


def board():
    return P('/proc/device-tree/compatible').read_bytes().split(b'\0')[0].decode()


def cmdline():
    return P('/proc/cmdline').read_text().strip()


def kernel_release():
    t = os.environ.get('BT2_TEST_UNAME_R') if TEST_ROOT else None
    return t or os.uname().release


def pacman_versions(names):
    """{name: version or None} using the local DB directly (no sync DB, no network)."""
    out = {}
    for n in names:
        r = run([BIN('pacman'), '-Q', n], check=False, timeout=60)
        if r.returncode == 0:
            parts = r.stdout.decode().split()
            out[n] = parts[1] if len(parts) == 2 and parts[0] == n else None
        else:
            out[n] = None
    return out


def pacman_all():
    r = run([BIN('pacman'), '-Q'], timeout=120)
    rows = {}
    for line in r.stdout.decode().splitlines():
        n, v = line.split()
        rows[n] = v
    return rows


class Ctx:
    """Per-invocation context: run dir, config, receipts."""

    RUN_RE = re.compile(r'^/var/lib/maclab/bt2/[a-z0-9][a-z0-9-]{3,80}$')

    def __init__(self, cmd, run_dir):
        self.cmd = cmd
        need(self.RUN_RE.match(str(run_dir)), 'run dir must be /var/lib/maclab/bt2/<run-id>')
        self.run_dir = P(run_dir)
        if not TEST_ROOT:
            need(os.geteuid() == 0, 'target must run as root')
            for p in [self.run_dir, *self.run_dir.parents]:
                if str(p) in ('/', '/var', '/var/lib'):
                    continue
                s = os.lstat(p)
                need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                     'unsafe run dir ancestry: %s' % p)
        self.config_raw = read_small(self.run_dir / 'config.json', 1 << 20)
        self.config = json.loads(self.config_raw)
        need(self.config.get('schema') == 'bt2.target-config/1', 'config schema')
        need(self.config['run_id'] == self.run_dir.name, 'config run_id/run dir mismatch')
        self.esp = P(self.config.get('esp', ESP_DEFAULT))
        (self.run_dir / 'receipts').mkdir(mode=0o700, exist_ok=True)
        self.changed = False
        self.t0 = time.time()

    def sub(self, name):
        p = self.run_dir / name
        p.mkdir(mode=0o700, exist_ok=True)
        return p

    def base(self):
        return {'schema': SCHEMA_RESULT, 'cmd': self.cmd, 'run_id': self.config['run_id'],
                'device': self.config['device'], 'boot_id': boot_id(), 'kernel': kernel_release(),
                'config_sha256': H(self.config_raw)}

    def receipt(self, result):
        rd = self.run_dir / 'receipts'
        seq = 0
        while os.path.lexists(rd / ('%s.%d.json' % (self.cmd, seq))):
            seq += 1
        write_new(rd / ('%s.%d.json' % (self.cmd, seq)), dump(result))


def main(commands):
    """commands: {name: fn(ctx) -> dict}. Implements the exit-code/receipt contract."""
    if len(sys.argv) < 4 or sys.argv[2] != '--run-dir':
        print(json.dumps({'schema': SCHEMA_RESULT, 'ok': False, 'error': 'usage: t <cmd> --run-dir DIR'}))
        sys.exit(5)
    cmd, run_dir = sys.argv[1], sys.argv[3]
    extra = sys.argv[4:]
    ctx = None
    try:
        if cmd not in commands:
            raise Refused('unknown command ' + cmd)
        ctx = Ctx(cmd, run_dir)
        ctx.argv = extra
        if '--config-sha256' in extra:
            i = extra.index('--config-sha256')
            need(i + 1 < len(extra) and extra[i + 1] == H(ctx.config_raw),
                 'config.json sha256 differs from the controller-supplied pin')
        res = commands[cmd](ctx) or {}
        out = {**ctx.base(), 'ok': True, 'changed': ctx.changed, 'seconds': round(time.time() - ctx.t0, 3), **res}
        code = 0
    except Refused as e:
        out = {'schema': SCHEMA_RESULT, 'cmd': cmd, 'ok': False, 'changed': bool(ctx and ctx.changed),
               'refused_reason': str(e)}
        code = 4 if (ctx and ctx.changed) else 3
    except Failed as e:
        out = {'schema': SCHEMA_RESULT, 'cmd': cmd, 'ok': False, 'changed': True, 'error': str(e)}
        code = 4
    except Exception as e:  # noqa: BLE001 - contract: report, never mask
        out = {'schema': SCHEMA_RESULT, 'cmd': cmd, 'ok': False, 'changed': bool(ctx and ctx.changed),
               'error': '%s: %s' % (type(e).__name__, str(e)[:2000])}
        code = 5
    if ctx is not None:
        try:
            ctx.receipt(out)
        except Exception as e:  # noqa: BLE001
            out['receipt_error'] = str(e)[:300]
            code = code or 5
    print(json.dumps(out, sort_keys=True, separators=(',', ':')))
    sys.exit(code)
