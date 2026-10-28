#!/usr/bin/env python3
"""bt2 controller: one generic, journaled boot-test run per lab Mac (SPEC.md "Controller sequence").

  python3 -m bt2.controller run --device m1 --artifact a.pkg.tar.zst [--artifact ...] [--mode network-only]
                                [--baseline fresh|stale]
  python3 -m bt2.controller restore --run <run-id> [--retry <step>]
  python3 -m bt2.controller status --run <run-id>

Every step writes a journal intent BEFORE it runs and done/failed after (journal.py). Mutating steps record
their inverse target command. Every labd call (redacted, bounded) is appended to <run>/labd-calls.jsonl and
every target result is stored under <run>/target/. Nothing is retried automatically.
Exit codes: 0 job passed + restored + lease released; 1 job did not pass, Mac restored + lease released;
3 refused before any Mac mutation; 4 stopped after a mutation (run `restore`); 2 usage error.
"""
import argparse
import datetime
import hashlib
import json
import base64
import os
import re
import shlex
import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bt2 import artifacts, installed, labd, m5, native, transport  # noqa: E402
from bt2 import manifest as manifest_gen  # noqa: E402
from bt2.journal import Journal  # noqa: E402

SCHEMA_RUN = 'bt2.run/1'
DEFAULT_HOLDER = 'bt2-claude'
DEFAULT_STATE_ROOT = Path.home() / '.local/share/maclab/bt2/runs'
DEFAULT_STORE = Path.home() / '.local/share/maclab/boot-test/artifacts'
DEVICES_DIR = ROOT / 'devices'
TARGET_DIR = ROOT / 'target'
REMOTE_BASE = '/var/lib/maclab/bt2'
RUN_RE = re.compile(r'^[a-z0-9][a-z0-9-]{3,80}$')
TXN_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$')
JOB_RE = re.compile(r'^j[0-9]{4}-[0-9]{6}-[a-f0-9]{4}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
MODES = ('network-only', 'serial-assisted')
LEASE_TTL = 7320            # >= 7200 s for the run (+120 like runtime.select)
LEASE_MIN = 7200
LEASE_RENEW_BELOW = 3600    # renew at step boundaries / while waiting when less is left
ESP_RESERVE = 125829120     # 120 MiB (SPEC esp-prep)
ROOT_RESERVE = 2147483648   # 2 GiB (SPEC capture)
BOOT_PACKAGE = 'omarchy-mac-boot'
REBOOT_WAIT = 360           # 6 min for a new boot id
POLL = 10
JOB_BUDGET = 4 * 3600
WAIT_CHUNK = 2400           # GET /api/jobs/<id>/wait?timeout=<= 2400
TIMEOUTS = {'preflight': 300, 'fetch': 1800, 'capture': 1800, 'hold-writers': 300, 'esp-prep': 900,
            'install': 3000, 'rollback': 3000, 'esp-restore': 900, 'etc-restore': 600, 'audit': 900,
            'release-writers': 300, 'cleanup': 600}
RESTORE_ORDER = ('bootbin-guard-remove', 'rollback', 'esp-restore', 'etc-restore', 'release-writers')
FIX_STEPS = ('bootbin-guard-remove', 'rollback', 'esp-restore', 'etc-restore')   # change what the next boot runs
M1N1_BIN = 'usr/lib/asahi-boot/m1n1.bin'
M1N1_VER_MARK = b'##m1n1_ver##'   # src/main.c version_tag; /chosen/asahi,m1n1-stage2-version = the text after it
REBOOT_STEPS = ('reboot', 'restore-reboot', 'restore-return')
EXTRA_TEST = 'eryk-bench'
EXTRA_TIMEOUT = 2400
CTS_TEST = 'eryk-cts'       # candidate job only, after EXTRA_TEST, with its own result (never folded into the benchmark)
CTS_TIMEOUT = 1500          # pinned per-list deqp deadlines + extract/verify + the fault checks around each list
CTS_SLACK = 300             # CTS_TIMEOUT minus the sum of list deadlines must leave at least this
JOB_STEPS = ('submit', 'base-submit')    # a submitted labd job may leave the Mac on a tagged boot
# Fresh baseline (default): an installed-mode job of the Mac's ORIGINAL cohort runs after capture + hold-writers;
# its omarchy-m-test report, kernel error lines and job record become this run's frozen preinstall. Installed jobs
# never promote (server/installed.go:15-16), so labd's known-good references stay untouched. 'stale' byte-copies
# the device profile's baseline_release preinstall (the pre-2026-10-27 behaviour).
# 'auto' (default): fresh when the Mac's known-good kernel ships in one of its original packages (the base job then
# boots that same kernel), else stale (e.g. a custom unowned known-good kernel: an installed-mode base job would
# boot a different, packaged kernel, which is not like-for-like).
BASELINE_MODES = ('auto', 'fresh', 'stale')
GPU_PROVIDER_PACKAGES = ('mesa-aurora', 'vulkan-aurora')   # whose files the native GL/VK test pins
BASE_SUFFIX = '-base'
BASE_OK_OUTCOMES = ('pass', 'tests_failed')   # tests_failed: e.g. its omt regressed vs the stale pins (irrelevant)
OMT_REPORT_FILE = 'test-omarchy-m-test/omt-report.json'
DMESG_FILE = 'installed/dmesg-errors.txt'     # = boot0/dmesg-errors.txt (server/installed.go:455,464)
SEALED_JOB_FILE = 'installed/job.json'        # labd's sealed record (server/installed.go:517)


class Refused(RuntimeError):
    """A gate failed; this step changed nothing."""


class StepFailure(RuntimeError):
    def __init__(self, msg, code=None, refused=False, ambiguous=False, changed=None):
        super().__init__(msg)
        self.code = code
        self.refused = refused
        self.ambiguous = ambiguous
        self.changed = changed


class UsageError(RuntimeError):
    pass


def need(cond, msg):
    if not cond:
        raise Refused(msg)


def check(cond, msg):
    if not cond:
        raise StepFailure(msg)


def H(b):
    return hashlib.sha256(b).hexdigest()


def canon(o):
    return (json.dumps(o, sort_keys=True, indent=1) + '\n').encode()


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def expiry(lease):
    t = datetime.datetime.fromisoformat(str(lease['expires']).replace('Z', '+00:00'))
    if t.tzinfo is None:
        raise StepFailure('lease expiry without timezone')
    return t


def write_once(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view[:1 << 20]):]
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    if path.read_bytes() != data:
        raise StepFailure('local write readback mismatch: %s' % path)
    return {'path': str(path), 'sha256': H(data), 'bytes': len(data)}


def _small(o, limit=3000):
    try:
        s = json.dumps(o, sort_keys=True, default=str)
    except (TypeError, ValueError):
        s = repr(o)
    if len(s) <= limit:
        return json.loads(s)
    return {'truncated': True, 'sha256': H(s.encode()), 'head': s[:limit // 2]}


def release_name(run_id):
    base = run_id if run_id.startswith('bt2-') else 'bt2-' + run_id
    base = re.sub(r'[^0-9A-Za-z._-]', '-', base)[:96]
    if not installed.REL_RE.match(base):
        raise UsageError('cannot derive a labd release name from run id %r' % run_id)
    return base


def default_run_id(device, now):
    return 'bt2-%s-%s' % (device, now.strftime('%Y%m%d%H%M%S'))


# ------------------------------------------------------------------------------------- journal analysis
def step_states(records):
    st = {}
    for r in records:
        s, ev = r.get('step'), r.get('event')
        if s is None or ev not in ('intent', 'done', 'failed'):
            continue
        if ev == 'intent':
            prev = st.get(s, {})
            st[s] = {'state': 'ambiguous', 'intent_seq': r['seq'], 'inverse': r.get('inverse'),
                     'followups': r.get('inverse_followups') or [], 'mutating': r.get('mutating', False),
                     'ever_done': prev.get('ever_done', False), 'done_seq': prev.get('done_seq'),
                     'attempts': prev.get('attempts', 0) + 1}
            if prev.get('inverse') and not r.get('inverse'):
                st[s]['inverse'], st[s]['followups'] = prev['inverse'], prev['followups']
        elif s in st:
            if ev == 'done':
                st[s].update(state='done', ever_done=True, done_seq=r['seq'])
            else:
                st[s].update(state='refused' if r.get('refused') else 'failed', exit_code=r.get('exit_code'),
                             error=r.get('error'))
    return st


def restore_plan(records):
    """Pure: which inverses `restore` still has to run (in order) and which need an explicit --retry."""
    st = step_states(records)
    needed = []
    for name in sorted(st, key=lambda n: st[n]['intent_seq']):
        s = st[name]
        if s.get('inverse') and s['state'] != 'refused':      # started and possibly changed something
            for c in [s['inverse'], *s.get('followups', [])]:
                if c not in needed:
                    needed.append(c)
    todo = [c for c in RESTORE_ORDER if c in needed and not st.get(c, {}).get('ever_done')]
    todo += [c for c in needed if c not in RESTORE_ORDER and not st.get(c, {}).get('ever_done')]
    blocked = [c for c in todo if st.get(c, {}).get('state') in ('failed', 'ambiguous')]
    fixes = [st[c]['done_seq'] for c in FIX_STEPS if st.get(c, {}).get('ever_done')]
    boots = [st[c]['done_seq'] for c in REBOOT_STEPS if st.get(c, {}).get('ever_done')]
    reboot_pending = bool(fixes) and (not boots or max(boots) < max(fixes))
    boot_risk = any(s in st and st[s]['state'] != 'refused' for s in JOB_STEPS)
    mutated = bool(needed) or boot_risk
    return {'mutated': mutated, 'needed': needed, 'todo': todo, 'blocked': blocked,
            'reboot_pending': reboot_pending, 'boot_risk': boot_risk,
            'capture_done': bool(st.get('capture', {}).get('ever_done')),
            'cleanup_done': bool(st.get('cleanup', {}).get('ever_done')),
            'm5_root': bool(st.get('m5-capture', {}).get('ever_done'))}


def stage2_version(data):
    """The stage 2 version m1n1 publishes in /chosen: the text after its one '##m1n1_ver##' marker, to the NUL."""
    vals, i = set(), data.find(M1N1_VER_MARK)
    while i >= 0:
        a = i + len(M1N1_VER_MARK)
        j = data.find(b'\0', a, a + 80)
        need(j > a, 'unterminated m1n1 version marker')
        vals.add(data[a:j])
        i = data.find(M1N1_VER_MARK, a)
    need(len(vals) == 1, 'm1n1.bin must carry exactly one version marker value (found %d)' % len(vals))
    v = vals.pop().decode('ascii', errors='replace')
    need(re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z._+-]{0,63}', v) is not None, 'odd m1n1 version %r' % v)
    return v


def last_end(records):
    ends = [r for r in records if r.get('event') == 'note' and r.get('step') == 'end']
    return ends[-1] if ends else None


def run_is_open(records):
    e = last_end(records)
    if e is not None:
        return bool(e.get('mutated')) and not e.get('lease_released')
    return any(r.get('event') == 'intent' and r.get('step') == 'lease' for r in records)


# ------------------------------------------------------------------------------------- labd recorder
def _summ(o, depth=0):
    if isinstance(o, (bytes, bytearray)):
        return {'bytes': len(o), 'sha256': H(bytes(o))}
    if isinstance(o, str):
        return o if len(o) <= 4096 else {'text_head': o[:1024], 'len': len(o), 'sha256': H(o.encode())}
    if isinstance(o, dict) and depth < 12:
        return {str(k): _summ(v, depth + 1) for k, v in o.items()}
    if isinstance(o, (list, tuple)) and depth < 12:
        return [_summ(v, depth + 1) for v in o]
    return o if isinstance(o, (int, float, bool, type(None))) else repr(o)[:500]


class Recorder:
    """Proxy for a labd client: each call + redacted, bounded response appended (fsync) to a JSONL file."""

    def __init__(self, inner, path):
        self._inner = inner
        self._path = Path(path)
        self._seq = 0

    def _append(self, rec):
        line = (json.dumps(rec, sort_keys=True, default=str) + '\n').encode()
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    def __getattr__(self, name):
        fn = getattr(self._inner, name)
        if name.startswith('_') or not callable(fn):
            return fn

        def call(*a, **k):
            self._seq += 1
            rec = {'seq': self._seq, 'at': time.time(), 'call': name,
                   'args': _summ(labd.redact(list(a))), 'kwargs': _summ(labd.redact(k))}
            try:
                res = fn(*a, **k)
            except Exception as e:
                rec['error'] = {'type': type(e).__name__, 'code': getattr(e, 'code', None),
                                'body': str(getattr(e, 'body', e))[:2000]}
                self._append(rec)
                raise
            rec['response'] = _summ(labd.redact(res) if isinstance(res, (dict, list)) else res)
            self._append(rec)
            return res
        return call


# ------------------------------------------------------------------------------------- Mac operations
SNIPPETS = {
    'probe': r'''
import gzip,hashlib,json,os,pwd,subprocess,sys
a=json.loads(sys.argv[1])
def rd(p,n=65536):
    try:
        with open(p,'rb') as f:return f.read(n)
    except OSError:return None
def sha(p):
    try:
        h=hashlib.sha256()
        with open(p,'rb') as f:
            for b in iter(lambda:f.read(1<<20),b''):h.update(b)
        return h.hexdigest()
    except OSError:return None
env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}
o={'schema':'bt2.probe/1','kernel':os.uname().release,'machine':os.uname().machine}
o['boot_id']=(rd('/proc/sys/kernel/random/boot_id') or b'').decode().strip()
o['cmdline']=(rd('/proc/cmdline') or b'').decode().strip()
o['board']=(rd('/proc/device-tree/compatible') or b'').split(b'\0')[0].decode()
v=rd('/proc/device-tree/chosen/asahi,m1n1-stage2-version')
o['m1n1_stage2_version']=None if v is None else v.replace(b'\0',b'').decode(errors='replace').strip()
pk={};mt={}
for n in a.get('packages',[]):
    r=subprocess.run(['/usr/bin/pacman','-Q','--',n],capture_output=True,text=True,timeout=60,env=env)
    parts=r.stdout.split();ver=parts[1] if r.returncode==0 and len(parts)==2 and parts[0]==n else None
    pk[n]=ver;m=None
    if ver:
        try:m=hashlib.sha256(gzip.decompress(open('/var/lib/pacman/local/%s-%s/mtree'%(n,ver),'rb').read())).hexdigest()
        except (OSError,EOFError,gzip.BadGzipFile):m=None
    mt[n]=m
o['packages']=pk;o['mtree']=mt
w=[]
for i in sorted(os.listdir('/sys/class/net')):
    b='/sys/class/net/'+i;ue=rd(b+'/uevent') or b''
    w.append({'interface':i,'mac':(rd(b+'/address') or b'').decode().strip(),'operstate':(rd(b+'/operstate') or b'').decode().strip(),'wireless':os.path.isdir(b+'/wireless') or b'DEVTYPE=wlan' in ue})
o['wifi']=w
g=a.get('gui_user')
try:
    u=pwd.getpwnam(g) if g else None;o['gui']={'user':g,'uid':u.pw_uid} if u else None
except KeyError:o['gui']=None
o['tools']={p:sha(p) for p in a.get('tools',[])}
o['bootbin_sha256']=sha(a.get('esp','/boot/efi')+'/m1n1/boot.bin')
o['db_lock']=os.path.lexists('/var/lib/pacman/db.lck')
o['run_dir_exists']=os.path.lexists(a['run_dir']) if a.get('run_dir') else None
print(json.dumps(o,sort_keys=True))
''',
    'mkrun': r'''
import json,os,stat,sys
a=json.loads(sys.argv[1]);run=a['run_dir'];base=os.path.dirname(run)
assert base=='/var/lib/maclab/bt2' and os.path.basename(run)==a['run_id'],'bad run dir'
s=os.lstat('/var/lib/maclab');assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'unsafe /var/lib/maclab'
try:os.mkdir(base,0o700)
except FileExistsError:pass
s=os.lstat(base);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'unsafe '+base
assert not os.path.lexists(run),'run dir already exists'
os.mkdir(run,0o700)
for sub in a.get('subdirs',[]):os.mkdir(run+'/'+sub,0o700)
for p in (base,run):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'created':True,'run_dir':run,'subdirs':a.get('subdirs',[])}))
''',
    'tdir-new': r'''
import json,os,stat,sys
a=json.loads(sys.argv[1]);run=a['run_dir'];k=int(a['k'])
assert os.path.dirname(run)=='/var/lib/maclab/bt2','bad run dir'
s=os.lstat(run);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o077,'unsafe run dir'
assert os.path.isdir(run+'/t'),'run has no target package'
new=run+'/t.r%d'%k;assert not os.path.lexists(new),'refresh dir exists'
assert not os.path.lexists(run+'/t.prev-%d'%k),'previous-package dir exists'
os.mkdir(new,0o700);fd=os.open(run,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'created':new}))
''',
    'tdir-swap': r'''
import hashlib,json,os,sys
a=json.loads(sys.argv[1]);run=a['run_dir'];k=int(a['k']);want=a['files']
new,cur,prev=run+'/t.r%d'%k,run+'/t',run+'/t.prev-%d'%k
def tree(d):return {n:hashlib.sha256(open(d+'/'+n,'rb').read()).hexdigest() for n in sorted(os.listdir(d)) if n.endswith('.py')}
got=tree(new);assert got==want,'refreshed package differs from the controller copy'
old=tree(cur)
os.rename(cur,prev);os.rename(new,cur)
fd=os.open(run,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
assert tree(cur)==want
print(json.dumps({'previous':prev,'previous_files':old,'files':got}))
''',
    'locks': r'''
import json,os,stat
o={}
for p in ('/run/lock/boot-partition.lock','/tmp/limine-global.lock'):
    created=False
    if not os.path.lexists(p):
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
        try:os.fchmod(fd,0o644)
        finally:os.close(fd)
        created=True
    s=os.lstat(p);o[p]={'created':created,'regular':stat.S_ISREG(s.st_mode),'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}
ok=all(v['regular'] and v['uid']==0 for v in o.values())
print(json.dumps({'locks':o,'ok':ok}))
raise SystemExit(0 if ok else 1)
''',
    'settle': r'''
import hashlib,json,os,sys,time
a=json.loads(sys.argv[1]);menu=a.get('esp','/boot/efi')+'/limine.conf'
quiet=float(a.get('quiet',15));limit=time.monotonic()+float(a.get('max',180))
def busy():
    out=[]
    for p in os.listdir('/proc'):
        if not p.isdigit():continue
        try:cmd=open('/proc/%s/cmdline'%p,'rb').read().replace(b'\0',b' ').decode(errors='replace')
        except OSError:continue
        if ('limine-snapper-sync' in cmd and 'limine-snapper-watcher' not in cmd) or cmd.startswith('/usr/bin/snapper ') or cmd.startswith('snapper '):out.append(cmd[:120])
    return out
def menu_id():
    try:
        b=open(menu,'rb').read();return hashlib.sha256(b).hexdigest()
    except OSError:return None
last=menu_id();since=time.monotonic();samples=0;seen=[]
while True:
    time.sleep(3);samples+=1;b=busy();m=menu_id()
    if b:seen=b
    if b or m!=last:last=m;since=time.monotonic()
    if time.monotonic()-since>=quiet:
        print(json.dumps({'settled':True,'menu_sha256':last,'samples':samples,'seen_busy':seen[:5]}));raise SystemExit(0)
    if time.monotonic()>limit:
        print(json.dumps({'settled':False,'menu_sha256':last,'samples':samples,'busy':b[:5]}));raise SystemExit(1)
''',
    'tar': r'''
import hashlib,json,os,subprocess,sys
a=json.loads(sys.argv[1]);run=a['run_dir'];out=run+'/'+a['name']
assert os.path.isdir(run+'/capture'),'no capture dir'
assert not os.path.lexists(out),'tarball exists'
r=subprocess.run(['/usr/bin/tar','--sort=name','--numeric-owner','--format=gnu','-C',run,'-cf',out,'capture','receipts'],capture_output=True,timeout=1500,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
assert r.returncode==0,'tar failed: '+r.stderr.decode(errors='replace')[-400:]
os.chmod(out,0o600);h=hashlib.sha256();n=0
with open(out,'rb') as f:
    for b in iter(lambda:f.read(1<<20),b''):h.update(b);n+=len(b)
    os.fsync(f.fileno())
rec={}
for x in sorted(os.listdir(run+'/receipts')):
    with open(run+'/receipts/'+x,'rb') as f:rec[x]=hashlib.sha256(f.read()).hexdigest()
print(json.dumps({'path':out,'sha256':h.hexdigest(),'bytes':n,'receipts':rec}))
''',
}


class Ops:
    """Everything the controller does ON the Mac goes through here (all via labd exec)."""

    def __init__(self, api, device):
        self.api = api
        self.device = device

    def push(self, path, data, mode=0o600):
        return transport.push(self.api, self.device, path, data, mode)

    def pull(self, path, limit=1 << 31):
        return transport.pull(self.api, self.device, path, limit)

    def target(self, run_dir, cmd, timeout, extra=()):
        return transport.run_target(self.api, self.device, run_dir, cmd, timeout, extra)

    def snippet(self, name, arg, timeout=120):
        cmd = '/usr/bin/python3 -I -B -c %s %s' % (shlex.quote(SNIPPETS[name]),
                                                     shlex.quote(json.dumps(arg, sort_keys=True)))
        r = self.api.exec(self.device, cmd, timeout)
        obj = None
        lines = [x for x in (r.get('stdout') or '').splitlines() if x.strip()]
        if lines:
            try:
                obj = json.loads(lines[-1])
            except ValueError:
                obj = None
        return r.get('exit_code'), obj, r

    def reboot(self):
        return self.api.exec(self.device, 'systemctl --no-block reboot', 30)


# ------------------------------------------------------------------------------------- controller
class Controller:
    def __init__(self, api, *, state_root=DEFAULT_STATE_ROOT, ops_factory=Ops, m5_runner=None,
                 devices_dir=DEVICES_DIR, target_dir=TARGET_DIR, native_src=native.DEFAULT_SRC,
                 stores=(DEFAULT_STORE,), frozen_root=None, sleep=time.sleep, clock=time.monotonic,
                 wall=utcnow, checker_pins=None, out=None, err=None):
        self.raw_api = api
        self.state_root = Path(state_root)
        self.ops_factory = ops_factory
        self.m5_runner = m5_runner or m5._run
        self.devices_dir = Path(devices_dir)
        self.target_dir = Path(target_dir)
        self.native_src = Path(native_src)
        self.stores = [Path(s) for s in stores]
        if frozen_root is not None:
            installed.FROZEN = Path(frozen_root)
        self.sleep = sleep
        self.clock = clock
        self.wall = wall
        self.checker_pins_override = checker_pins       # unused since checker r3 (cohort comes from the archives)
        self.out = out or sys.stdout
        self.err = err or sys.stderr
        self._insp_cache = {}
        self._tseq = 0

    # -- plumbing --------------------------------------------------------------------------------------
    def log(self, msg):
        print('bt2: ' + msg, file=self.err, flush=True)

    def emit(self, obj):
        print(json.dumps(obj, indent=1, sort_keys=True), file=self.out, flush=True)

    def load_profile(self, device):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', device or ''):
            raise UsageError('bad device name')
        p = self.devices_dir / (device + '.json')
        if not p.is_file():
            raise UsageError('no device profile %s' % p)
        raw = p.read_bytes()
        prof = json.loads(raw)
        for k in ('name', 'board', 'board_dtb', 'dt_model', 'known_good_kernel', 'gui_user', 'gui_uid',
                  'recovery_modes', 'writer_units', 'parkable', 'baseline_release', 'manifest_source_release',
                  'etc_capture'):
            if k not in prof:
                raise UsageError('device profile %s lacks %s' % (p, k))
        if prof['name'] != device:
            raise UsageError('device profile name mismatch')
        return prof, raw

    def _bind(self, run_id, rd, j, prof, holder, mode, remote):
        self.run_id, self.rd, self.j, self.prof = run_id, Path(rd), j, prof
        self.device, self.holder, self.mode, self.rrun = prof['name'], holder, mode, remote
        self.release = release_name(run_id)
        self.api = Recorder(self.raw_api, self.rd / 'labd-calls.jsonl')
        self.ops = self.ops_factory(self.api, self.device)
        self._tseq = len(list((self.rd / 'target').glob('*.json')))

    def step(self, name, fn, *, inverse=None, followups=(), mutating=False, **meta):
        self.j.intent(name, inverse=inverse, inverse_followups=list(followups), mutating=mutating, **meta)
        self.log('-> ' + name)
        try:
            out = fn()
        except Refused as e:
            self.j.failed(name, e, refused=True, changed=False)
            raise
        except StepFailure as e:
            self.j.failed(name, e, exit_code=e.code, refused=e.refused, ambiguous=e.ambiguous, changed=e.changed)
            raise
        except BaseException as e:
            self.j.failed(name, '%s: %s' % (type(e).__name__, e), refused=False, ambiguous=mutating,
                          changed=None if mutating else False)
            raise
        self.j.done(name, summary=_small(out if isinstance(out, (dict, list)) else {}))
        return out

    def save_local(self, rel, data):
        return write_once(self.rd / rel, data)

    # -- target commands ----------------------------------------------------------------------------------
    def target(self, cmd, extra=()):
        args = ['--config-sha256', self.cfg_sha, *extra]
        self._tseq += 1
        try:
            code, res, raw = self.ops.target(self.rrun, cmd, TIMEOUTS.get(cmd, 900), args)
        except Exception as e:
            self._save_target(cmd, None, None, {'error': '%s: %s' % (type(e).__name__, e)})
            raise StepFailure('target %s: transport error, outcome unknown: %s' % (cmd, e), ambiguous=True)
        self._save_target(cmd, code, res, raw)
        if not isinstance(res, dict) or res.get('schema') != 'bt2.target-result/1' or res.get('cmd') != cmd:
            raise StepFailure('target %s: no valid result JSON (exit %r): %s' % (
                cmd, code, str((raw or {}).get('stderr') or '')[-300:]), code=code, ambiguous=True)
        if code == 0 and res.get('ok') is True:
            if res.get('run_id') != self.run_id or res.get('device') != self.device:
                raise StepFailure('target %s answered for another run/device' % cmd, code=0, ambiguous=True)
            if res.get('config_sha256') not in (None, self.cfg_sha):
                raise StepFailure('target %s used another config (%s)' % (cmd, res.get('config_sha256')), code=0,
                                  ambiguous=True)
            return res
        reason = res.get('refused_reason') or res.get('error') or 'not ok'
        if code == 3 and res.get('changed') is False:
            raise StepFailure('target %s refused (nothing changed): %s' % (cmd, reason), code=3, refused=True,
                              changed=False)
        raise StepFailure('target %s failed (exit %r, changed=%r): %s' % (cmd, code, res.get('changed'), reason),
                          code=code, changed=res.get('changed', True), ambiguous=code not in (4, 5))

    def _save_target(self, cmd, code, res, raw):
        raw = raw if isinstance(raw, dict) else {}
        doc = {'cmd': cmd, 'exit_code': code, 'result': res, 'stderr_tail': str(raw.get('stderr') or '')[-4000:],
               'error': raw.get('error'), 'at': time.time()}
        self.save_local('target/%03d-%s.json' % (self._tseq, cmd), canon(doc))

    def tstep(self, name, cmd=None, *, extra=(), inverse=None, followups=(), mutating=False, verify=None, **meta):
        cmd = cmd or name

        def fn():
            res = self.target(cmd, extra)
            if verify:
                verify(res)
            return {'cmd': cmd, 'exit_code': 0, 'changed': res.get('changed'),
                    'boot_id': res.get('boot_id'), 'kernel': res.get('kernel')}
        return self.step(name, fn, inverse=inverse, followups=followups, mutating=mutating, cmd=cmd, **meta)

    # -- labd helpers ---------------------------------------------------------------------------------------
    def remaining(self, lease):
        return (expiry(lease) - self.wall()).total_seconds()

    def device_gate(self, d):
        p = self.prof
        need(d.get('name') == self.device, 'labd device name differs')
        f = d.get('facts') or {}
        need(f.get('machine') == 'aarch64', 'actual architecture mismatch')
        if 'compatible' in f:
            need(isinstance(f['compatible'], list) and f['compatible'] and f['compatible'][0] == p['board'],
                 'actual board %r != %s' % (f.get('compatible'), p['board']))
        if 'dt_model' in f:
            need(f['dt_model'] == p['dt_model'], 'actual model %r != %r' % (f['dt_model'], p['dt_model']))
        need('compatible' in f or f.get('dt_model') == p['dt_model'], 'no board/model evidence from labd')
        need(d.get('alive') is True, 'Mac is not alive (last_seen %s)' % d.get('last_seen'))
        need(d.get('state') == 'ready', 'Mac state is %r, not ready' % d.get('state'))
        need(not d.get('active_job') and not d.get('queued'), 'Mac is not idle (job %r, queued %r)' % (
            d.get('active_job'), d.get('queued')))
        need('maclab.job=' not in (d.get('cmdline') or ''), 'Mac is on a tagged lab-job boot')
        need(d.get('kernel') == p['known_good_kernel'], 'running kernel %s != known-good %s' % (
            d.get('kernel'), p['known_good_kernel']))
        lease = d.get('lease')
        need(not lease or lease.get('holder') == self.holder, 'foreign lease held by %r' % (lease or {}).get('holder'))
        return d

    def gate_device(self):
        try:
            d = self.api.device(self.device)
        except labd.APIError as e:
            raise Refused('labd device %s unavailable (%s)' % (self.device, e.code))
        self.device_gate(d)
        need(d.get('known_good'), 'labd has no known-good baseline for %s (installed jobs need one)' % self.device)
        return {'boot_id': d.get('boot_id'), 'kernel': d.get('kernel'), 'labd_known_good': d.get('known_good'),
                'lease': d.get('lease')}

    def gate_capabilities(self):
        cap = self.api.capabilities()
        need(isinstance(cap, dict) and type(cap.get('schema')) is int and cap['schema'] == 1
             and cap.get('per_job_oob_isolation') is True and cap.get('transaction_isolation') is True
             and self.mode in (cap.get('modes') or []), 'controller isolation / mode %s unavailable: %r' % (
                 self.mode, cap))
        return cap

    def gate_oob(self):
        o = self.api.oob(self.device)
        need(isinstance(o, dict) and str(o.get('controller', '')).startswith('oobd ')
             and o.get('serial_connected') is True and o.get('status') and not o.get('error'),
             'serial-assisted needs a connected OOB serial route; oob reports %r' % (o,))
        return o

    def gate_oob_config(self):
        """Before the lease: labd has an OOB route for this Mac. The live serial check (gate_oob) runs after
        serial-assisted is selected, because labd hides OOB status while the sticky mode is network-only."""
        o = self.api.device(self.device).get('oob') or {}
        need(o.get('driver') == 'oobd' and str(o.get('url', '')).startswith('http'),
             'serial-assisted needs an OOB route configured in labd for %s' % self.device)
        return {'driver': o['driver'], 'url': o['url']}

    def _lease_request(self, d):
        try:
            got = self.api.lease(self.device, self.holder, LEASE_TTL)
        except Exception as e:
            seen = None
            try:
                seen = self.api.device(self.device).get('lease')
            except Exception:  # noqa: BLE001
                pass
            self.j.note('lease', ambiguous=True, error=str(e)[:500], lease_readback=seen)
            raise StepFailure('lease request outcome unknown: %s' % e, ambiguous=True)
        rem = self.remaining(got)
        check(got.get('holder') == self.holder and LEASE_MIN <= rem <= LEASE_TTL + 30,
              'lease holder/TTL differs: %r' % (got,))
        fresh = self.api.device(self.device)
        check(fresh.get('lease') == got and fresh.get('boot_id') == d.get('boot_id'), 'lease/boot readback differs')
        return got

    def acquire_lease(self):
        d = self.api.device(self.device)
        lease = d.get('lease')
        need(not lease or lease.get('holder') == self.holder, 'foreign lease held by %r' % (lease or {}).get('holder'))
        if lease and self.remaining(lease) >= LEASE_MIN:
            return {'acquired': False, 'renewed': False, 'expires': lease['expires']}
        got = self._lease_request(d)
        return {'acquired': not lease, 'renewed': bool(lease), 'expires': got['expires']}

    def ensure_lease(self, minimum=LEASE_RENEW_BELOW):
        d = self.api.device(self.device)
        lease = d.get('lease')
        if lease and lease.get('holder') != self.holder:
            raise StepFailure('foreign lease %r appeared during the run' % lease.get('holder'))
        if not lease or self.remaining(lease) < minimum:
            got = self._lease_request(d)
            self.j.note('lease-renew', expires=got['expires'], reacquired=not lease)
            return got
        return lease

    def lease_acquired(self):
        for r in self.j.records:
            if r.get('step') == 'lease' and r.get('event') == 'done':
                return bool((r.get('summary') or {}).get('acquired'))
        return False

    def release_lease(self):
        try:
            resp = self.api.release(self.device, self.holder)
        except Exception as e:
            seen = None
            try:
                seen = self.api.device(self.device).get('lease')
            except Exception:  # noqa: BLE001
                pass
            raise StepFailure('lease release outcome unknown: %s (readback %r)' % (e, seen), ambiguous=True)
        fresh = self.api.device(self.device)
        check(not fresh.get('lease') or fresh['lease'].get('holder') != self.holder, 'owned lease remains')
        return {'response': resp if isinstance(resp, (str, dict)) else None}

    def select_mode(self):
        d = self.api.device(self.device)
        self.device_gate(d)
        lease = d.get('lease')
        need(lease and lease.get('holder') == self.holder and self.remaining(lease) >= LEASE_MIN,
             'owned lease with the run budget required before mode selection')
        q = {'mode': self.mode, 'holder': self.holder, 'transaction': self.run_id}
        r = self.api.recovery_mode(self.device, self.mode, self.holder, self.run_id)
        need(r == {'schema': 1, 'device': self.device, **q, 'quiescent': True},
             'quiescent transaction response differs: %r' % (r,))
        fresh = self.api.device(self.device)
        need(fresh.get('boot_id') == d.get('boot_id') and fresh.get('effective_recovery_mode') == self.mode
             and fresh.get('recovery_transaction') == self.run_id and fresh.get('recovery_holder') == self.holder,
             'selected transaction readback differs')
        if self.mode == 'serial-assisted':
            self.gate_oob()
        return {'selection': r}

    # -- Mac reads ------------------------------------------------------------------------------------------
    def snippet(self, name, arg, timeout=120):
        code, obj, raw = self.ops.snippet(name, arg, timeout)
        if code != 0 or not isinstance(obj, dict):
            raise StepFailure('%s on the Mac failed (exit %r): %s' % (
                name, code, str((raw or {}).get('stderr') or '')[-400:]), code=code, ambiguous=code is None)
        return obj

    def identity(self):
        return self.snippet('probe', {'packages': [], 'tools': [], 'gui_user': None, 'esp': self.prof['esp']})

    def probe(self):
        names = sorted({i['pkginfo']['pkgname'] for i in self.cands} | set(self.prof.get('boot_chain_packages', []))
                       | set(GPU_PROVIDER_PACKAGES))
        tools = sorted(t['path'] for t in self.tools.values())
        f = self.snippet('probe', {'packages': names, 'tools': tools, 'gui_user': self.prof['gui_user'],
                                   'esp': self.prof['esp'], 'run_dir': self.rrun})
        need(f.get('schema') == 'bt2.probe/1', 'probe schema')
        self.save_local('probe.json', canon(f))
        need(f.get('machine') == 'aarch64' and f.get('board') == self.prof['board'], 'probe board %r' % f.get('board'))
        need(f.get('kernel') == self.prof['known_good_kernel'], 'probe kernel %s != known-good' % f.get('kernel'))
        need('maclab.job=' not in (f.get('cmdline') or ''), 'probe: tagged boot')
        d = self.api.device(self.device)
        need(f.get('boot_id') == d.get('boot_id'), 'probe boot id differs from labd')
        need(not f.get('db_lock'), 'pacman db lock present')
        need(f.get('run_dir_exists') is False, 'remote run dir %s already exists' % self.rrun)
        need(HEX64.match(str(f.get('bootbin_sha256') or '')), 'no boot.bin on the ESP')
        need(f.get('m1n1_stage2_version'), 'no m1n1 stage2 version in the live DT')
        self.facts = f
        return {'packages': f['packages'], 'm1n1_stage2_version': f['m1n1_stage2_version'],
                'bootbin_sha256': f['bootbin_sha256']}

    # -- package resolution -----------------------------------------------------------------------------------
    def inspect(self, path):
        p = str(Path(path).resolve())
        if p not in self._insp_cache:
            self._insp_cache[p] = artifacts.inspect(p)
        return self._insp_cache[p]

    def inspect_candidates(self):
        self.cands = []
        for p in self.artifact_paths:
            try:
                i = self.inspect(p)
            except (OSError, artifacts.ArtifactError, Exception) as e:  # noqa: BLE001
                raise Refused('cannot inspect candidate %s: %s' % (p, e))
            self.cands.append(i)
        names = [i['pkginfo']['pkgname'] for i in self.cands]
        need(len(set(names)) == len(names), 'duplicate candidate package names %r' % names)
        kernels = [i for i in self.cands if len(i['kernel_releases']) == 1]
        need(len(kernels) == 1, 'need exactly one candidate kernel package (found %d)' % len(kernels))
        self.krel = kernels[0]['kernel_releases'][0]
        need(self.krel != self.prof['known_good_kernel'], 'candidate kernel equals the known-good kernel')
        return {'candidates': [{'name': i['pkginfo']['pkgname'], 'version': i['pkginfo']['pkgver'],
                                'file': i['file'], 'sha256': i['sha256'], 'bytes': i['bytes']} for i in self.cands],
                'krel': self.krel}

    def find_package(self, name, version):
        want = {'%s-%s-%s.pkg.tar.zst' % (name, version, a) for a in ('aarch64', 'any')}
        hits = []
        for root in self.stores:
            if not root.is_dir():
                continue
            for d in sorted(root.iterdir()):
                if not (HEX64.match(d.name) and d.is_dir()):
                    continue
                for f in sorted(d.iterdir()):
                    if f.name in want:
                        i = self.inspect(f)
                        need(i['sha256'] == d.name, 'durable store entry %s does not hash to its directory' % f)
                        hits.append(i)
        for p in self.extra_packages:
            i = self.inspect(p)
            if i['pkginfo']['pkgname'] == name and i['pkginfo']['pkgver'] == version:
                hits.append(i)
        hits = [i for i in hits if i['pkginfo']['pkgname'] == name and i['pkginfo']['pkgver'] == version]
        shas = {i['sha256'] for i in hits}
        need(len(shas) <= 1, 'several different archives for %s %s: %s' % (name, version, sorted(shas)))
        return hits[0] if hits else None

    def decide_baseline(self, requested):
        kg = self.prof['known_good_kernel']
        owners = sorted(i['pkginfo']['pkgname'] for i in self.orig_insps if kg in (i.get('kernel_releases') or []))
        if requested == 'auto':
            self.baseline = 'fresh' if owners else 'stale'
        else:
            self.baseline = requested
        why = ('known-good kernel %s ships in original %s' % (kg, owners) if owners else
               'known-good kernel %s is not in any original package: an installed-mode base job would boot a '
               'different kernel' % kg)
        return {'requested': requested, 'baseline': self.baseline, 'reason': why}

    def resolve_packages(self):
        f = self.facts
        self.originals, self.orig_insps, self.kept_insps = [], [], []
        cand_names = {i['pkginfo']['pkgname'] for i in self.cands}
        for i in sorted(self.cands, key=lambda x: x['pkginfo']['pkgname']):
            n, cv = i['pkginfo']['pkgname'], i['pkginfo']['pkgver']
            need(n in f['packages'], 'probe did not report %s' % n)
            v = f['packages'][n]
            if v is None:
                self.originals.append({'name': n, 'version': None})
                continue
            need(v != cv, '%s %s is already installed; not a candidate change' % (n, v))
            o = self.find_package(n, v)
            need(o is not None, 'no original archive for %s %s in %s (or --extra-package): rollback impossible'
                 % (n, v, ', '.join(map(str, self.stores))))
            self.orig_insps.append(o)
            self.originals.append({'name': n, 'version': v, 'file': o['file'], 'sha256': o['sha256'],
                                   'bytes': o['bytes'], 'path': o['path']})
        for n in self.prof.get('boot_chain_packages', []):
            if n in cand_names:
                continue
            v = f['packages'].get(n)
            need(v, 'boot-chain package %s is not installed on the Mac' % n)
            k = self.find_package(n, v)
            need(k is not None, 'kept boot-chain archive %s %s not found in %s or --extra-package (manifest '
                 'generation needs it)' % (n, v, ', '.join(map(str, self.stores))))
            row = manifest_gen.artifact_row(k)
            need(row['mtree_sha256'] == f['mtree'].get(n), 'installed %s %s mtree differs from archive %s' % (
                n, v, k['file']))
            self.kept_insps.append(k)
        # GPU providers that stay installed (e.g. a kernel-only run keeps the Mac's Mesa): the native test pins
        # their files, so their exact installed archives must be in the store (mtree-checked like kept packages)
        self.stay_insps = []
        for n in GPU_PROVIDER_PACKAGES:
            if n in cand_names or not f['packages'].get(n):
                continue
            v = f['packages'][n]
            k = self.find_package(n, v)
            need(k is not None, 'installed %s %s (kept: not a candidate) not found in %s or --extra-package; the '
                 'native GL/VK test needs its archive to pin the provider files' % (n, v, ', '.join(map(str, self.stores))))
            need(manifest_gen.artifact_row(k)['mtree_sha256'] == f['mtree'].get(n),
                 'installed %s %s mtree differs from archive %s' % (n, v, k['file']))
            self.stay_insps.append(k)
        return {'originals': [{k: o.get(k) for k in ('name', 'version', 'file', 'sha256')} for o in self.originals],
                'kept': [{'name': k['pkginfo']['pkgname'], 'version': k['pkginfo']['pkgver'], 'file': k['file'],
                          'sha256': k['sha256']} for k in self.kept_insps],
                'staying_providers': [{'name': k['pkginfo']['pkgname'], 'version': k['pkginfo']['pkgver'],
                                       'file': k['file'], 'sha256': k['sha256']} for k in self.stay_insps]}

    def pull_bootbin(self):
        data = self.ops.pull(self.prof['esp'] + '/m1n1/boot.bin', limit=64 << 20)
        need(H(data) == self.facts['bootbin_sha256'], 'pulled boot.bin differs from the probe hash')
        self.bootbin = data
        self.save_local('bootbin.current', data)
        return {'sha256': H(data), 'bytes': len(data)}

    def make_manifest(self):
        dev = self.device
        if self.manifest_mode == 'reuse':
            cohort = installed.source_cohort(self.prof['manifest_source_release'], dev)
            man, raw = installed.new_manifest(cohort, self.release, dev)
            payload = cohort['payload_raw']
            rows = {a['name']: a for a in man['artifacts']}
            for i in self.cands:
                a = rows.get(i['pkginfo']['pkgname'])
                need(a and a['version'] == i['pkginfo']['pkgver'] and a['sha256'] == i['sha256'],
                     'candidate %s %s is not in reused manifest %s' % (
                         i['pkginfo']['pkgname'], i['pkginfo']['pkgver'], self.prof['manifest_source_release']))
            cand_names = {i['pkginfo']['pkgname'] for i in self.cands}
            for n, a in rows.items():
                if n not in cand_names:
                    need(self.facts['packages'].get(n) == a['version'] and self.facts['mtree'].get(n) == a['mtree_sha256'],
                         'reused manifest artifact %s %s is neither a candidate nor installed' % (n, a['version']))
            need(man['kernel']['release'] == self.krel, 'reused manifest kernel differs from candidate kernel')
        else:
            macs = {dev: {'board': self.prof['board'], 'board_dtb': self.prof['board_dtb'], 'bootbin': self.bootbin}}
            try:
                man, raw, payload, _expected = manifest_gen.generate(
                    self.release, self.cands + self.kept_insps, macs, self.m1n1_version(),
                    approved_by=self.approved_by)
            except manifest_gen.ManifestError as e:
                raise Refused('manifest generation: %s' % e)
        need(man['kernel']['release'] == self.krel, 'manifest kernel differs from candidate kernel')
        mac = man['macs'][dev]
        need(mac['board'] == self.prof['board'], 'manifest board differs')
        if mac['boot_bin_sha256'] == H(self.bootbin):
            need(not self.allow_bootbin, '--allow-bootbin-change given, but the candidate set leaves boot.bin '
                 'unchanged')
        else:
            need(self.allow_bootbin, 'candidate set would change boot.bin (%s -> %s); allow_bootbin_change is false' % (
                H(self.bootbin)[:16], mac['boot_bin_sha256'][:16]))
            need(self.manifest_mode == 'generate', '--allow-bootbin-change needs --manifest generate')
        self.man, self.man_raw, self.payload = man, raw, payload
        self.save_local('manifest.json', raw)
        self.save_local('payload.sha256', payload)
        info = {}
        try:
            src = installed.source_cohort(self.prof['manifest_source_release'], dev)
            info['diff_vs_source'] = manifest_gen.semantic_diff(src['manifest'], man)
        except Exception as e:  # noqa: BLE001 - informational only
            info['diff_vs_source_error'] = str(e)[:300]
        return {'mode': self.manifest_mode, 'manifest_sha256': H(raw), 'payload_sha256': H(payload),
                'krel': self.krel, 'boot_bin_sha256': mac['boot_bin_sha256'], **info}

    def m1n1_version(self):
        """Stage 2 version the candidate job must see in /chosen. A candidate m1n1.bin is allowed only with
        --allow-bootbin-change, and its marker rule must first reproduce the live version from the installed one."""
        live = self.facts['m1n1_stage2_version']
        self.cand_stage2_version = live
        cands = [i for i in self.cands if M1N1_BIN in i['members']]
        if not cands:
            return live
        need(self.allow_bootbin, 'candidate %s ships a stage 2 (%s); that needs --allow-bootbin-change' % (
            cands[0]['file'], M1N1_BIN))
        need(len(cands) == 1, 'more than one candidate ships %s' % M1N1_BIN)
        origs = [i for i in [*self.orig_insps, *self.kept_insps] if M1N1_BIN in i['members']]
        need(len(origs) == 1, 'need the installed m1n1 package archive to check the version rule')
        ov = stage2_version(manifest_gen.read_members(origs[0]['path'], {M1N1_BIN})[M1N1_BIN])
        need(ov == live, 'installed m1n1.bin marker %r is not the live stage 2 version %r' % (ov, live))
        v = stage2_version(manifest_gen.read_members(cands[0]['path'], {M1N1_BIN})[M1N1_BIN])
        need(v != live, 'candidate stage 2 version %s equals the installed one' % v)
        self.cand_stage2_version = v
        return v

    def make_base_manifest(self):
        """Fresh baseline, pre-mutation: the installed manifest of what the Mac runs NOW (the originals the
        candidates replace + the kept boot-chain packages). labd's identity check of the base job compares exactly
        these artifacts (version + installed mtree), the kernel payload, the installer entry and the whole boot.bin
        (internal/installed/installed.go:396-497), so every one of them is proven here before anything changes.
        A candidate with no installed original (m3pro: omarchy-mac-boot is absent) is simply not in it: labd checks
        only the manifest's artifacts, so an absent package needs no row."""
        dev = self.device
        insps, seen = [], set()
        for i in [*self.orig_insps, *self.kept_insps]:
            if i['sha256'] not in seen:
                seen.add(i['sha256'])
                insps.append(i)
        absent = sorted(o['name'] for o in self.originals if o['version'] is None)
        for i in self.orig_insps:
            n = i['pkginfo']['pkgname']
            row = manifest_gen.artifact_row(i)
            need(row['mtree_sha256'] == self.facts['mtree'].get(n),
                 'fresh baseline: installed %s %s mtree differs from its archive %s (the base job identity would '
                 'MISMATCH; use --baseline stale)' % (n, i['pkginfo']['pkgver'], i['file']))
        macs = {dev: {'board': self.prof['board'], 'board_dtb': self.prof['board_dtb'], 'bootbin': self.bootbin}}
        try:
            man, raw, payload, _ = manifest_gen.generate(self.base_release, insps, macs,
                                                         self.facts['m1n1_stage2_version'],
                                                         approved_by=self.approved_by)
        except manifest_gen.ManifestError as e:
            raise Refused('fresh baseline manifest of the installed originals: %s (use --baseline stale)' % e)
        mac = man['macs'][dev]
        need(mac['boot_bin_sha256'] == H(self.bootbin),
             'fresh baseline: the installed originals do not reproduce the current boot.bin (%s -> %s); the base '
             'job identity would MISMATCH (use --baseline stale)' % (H(self.bootbin)[:16], mac['boot_bin_sha256'][:16]))
        base_krel = man['kernel']['release']
        need(base_krel != self.krel, 'fresh baseline kernel %s equals the candidate kernel' % base_krel)
        self.base_man, self.base_raw, self.base_payload = man, raw, payload
        self.save_local('base/manifest.json', raw)
        self.save_local('base/payload.sha256', payload)
        return {'release': self.base_release, 'manifest_sha256': H(raw), 'krel': base_krel,
                'artifacts': sorted('%s %s' % (a['name'], a['version']) for a in man['artifacts']),
                'absent_originals': absent, 'boot_bin_sha256': mac['boot_bin_sha256'],
                # m3pro: the base job boots the PACKAGED original kernel through its installer entry, not the
                # custom default kernel the Mac normally runs (recorded so the comparison is read correctly)
                'kernel_is_known_good': base_krel == self.prof['known_good_kernel'],
                'known_good_kernel': self.prof['known_good_kernel']}

    def gate_native(self):
        tools = self.tools
        try:
            providers = native.providers_from(self.cands, [*self.kept_insps, *self.stay_insps])
            native.pick_wifi(self.facts)
        except native.NativeError as e:
            raise Refused('native test inputs: %s' % e)
        problems = native.cohort_problems(self.krel, providers, tools, self.nsrc['checker'])
        need(not problems, 'checker %s cannot test this cohort: %s' % (native.CHECKER_SHA[:8], '; '.join(problems)))
        # the cohort compiled into the job Script (stage_native) and bound by the checker on the Mac
        self.native_cohort = native.cohort_pins(self.krel, providers, self.nsrc['checker'])
        for t in tools.values():
            need(self.facts['tools'].get(t['path']) == t['sha256'], 'probe tool %s missing or different on the Mac'
                 % t['path'])
        gui = self.facts.get('gui') or {}
        need(gui.get('uid') == self.prof['gui_uid'], 'GUI user %s uid %r != profile %r' % (
            self.prof['gui_user'], gui.get('uid'), self.prof['gui_uid']))
        return {'providers': {k: v['sha256'] for k, v in providers.items()}, 'wifi': native.pick_wifi(self.facts),
                'cohort_kernel': self.native_cohort['expected_kernel'],
                'cohort_sha256': H(native.encode(self.native_cohort))}

    def gate_frozen(self):
        need(not (installed.FROZEN / self.release).exists(), 'frozen release %s already exists' % self.release)
        if self.baseline == 'fresh':
            need(installed.REL_RE.match(self.base_release), 'bad base release name %r' % self.base_release)
            need(not (installed.FROZEN / self.base_release).exists(),
                 'frozen release %s already exists' % self.base_release)
        try:
            # stale: the candidate's preinstall; fresh: only the base job's own (ignored) comparison
            self.cohort = installed.source_cohort(self.prof['baseline_release'], self.device)
        except (OSError, installed.InstalledError, KeyError, ValueError) as e:
            raise Refused('baseline release %s unusable: %s' % (self.prof['baseline_release'], e))
        return {'baseline': self.baseline, 'baseline_release': self.prof['baseline_release'],
                'base_release': self.base_release if self.baseline == 'fresh' else None,
                'preinstall': sorted(self.cohort['preinstall'])}

    def gate_open_runs(self):
        others = []
        for jp in sorted(self.state_root.glob('*/journal.jsonl')):
            if jp.parent.name == self.run_id:
                continue
            try:
                recs = Journal(jp.parent).records
            except Exception:  # noqa: BLE001
                continue
            if recs and recs[0].get('device') == self.device and run_is_open(recs):
                others.append(jp.parent.name)
        need(not others, 'bt2 run(s) %s on %s still need `restore`' % (others, self.device))
        return {'open_runs': others}

    def make_config(self):
        p = self.prof
        cands = [{'name': i['pkginfo']['pkgname'], 'version': i['pkginfo']['pkgver'], 'file': i['file'],
                  'sha256': i['sha256'], 'bytes': i['bytes']}
                 for i in sorted(self.cands, key=lambda x: x['pkginfo']['pkgname'])]
        origs = [{k: o[k] for k in ('name', 'version', 'file', 'sha256', 'bytes')} if o['version'] else
                 {'name': o['name'], 'version': None} for o in self.originals]
        shas = {c['file']: c['sha256'] for c in cands}
        for o in origs:
            if o['version']:
                need(o['file'] not in shas, 'original and candidate share file name %s' % o['file'])
                shas[o['file']] = o['sha256']
        self.local_files = {i['file']: i['path'] for i in self.cands}
        self.local_files.update({o['file']: o['path'] for o in self.originals if o['version']})
        cfg = {'schema': 'bt2.target-config/1', 'run_id': self.run_id, 'device': self.device, 'board': p['board'],
               'known_good_kernel': p['known_good_kernel'], 'gui_user': p['gui_user'], 'gui_uid': p['gui_uid'],
               'esp': p['esp'], 'esp_reserve_bytes': ESP_RESERVE, 'root_reserve_bytes': ROOT_RESERVE,
               'candidates': cands, 'originals': origs, 'artifact_shas': shas, 'writer_units': p['writer_units'],
               'etc_capture': p['etc_capture'], 'parkable': p['parkable'], 'boot_package': BOOT_PACKAGE,
               'allow_bootbin_change': self.allow_bootbin,
               # pacman's per-file size limit (and the ESP peak) can never be below the largest packaged file
               'largest_member_bytes': max([int(r.get('size') or 0) for i in [*self.cands, *self.originals]
                                            for r in (i.get('members') or {}).values() if r.get('type') == 'f']
                                           or [0]),
               'expected_bootbin_sha256': self.man['macs'][self.device]['boot_bin_sha256'],
               'expected_kernel': self.krel, 'release': self.release, 'recovery_mode': self.mode}
        if self.allow_bootbin:
            r8 = H(self.run_id.encode())[:8]   # = target capture.run8()
            cfg['bootbin_guard'] = {
                'unit': 'bt2-%s-bootbin-guard.service' % r8, 'recovery_copy': 'm1n1/boot.bin.old',
                'candidate_sha256': cfg['expected_bootbin_sha256'], 'original_sha256': H(self.bootbin),
                'candidate_krel': self.krel, 'candidate_stage2_version': self.cand_stage2_version,
                'original_stage2_version': self.facts['m1n1_stage2_version']}
        self.cfg = cfg
        self.cfg_raw = (json.dumps(cfg, sort_keys=True, indent=1) + '\n').encode()
        self.cfg_sha = H(self.cfg_raw)
        self.save_local('config.json', self.cfg_raw)
        return {'config_sha256': self.cfg_sha, 'expected_bootbin_sha256': cfg['expected_bootbin_sha256'],
                'bootbin_guard': cfg.get('bootbin_guard')}

    # -- mutating sequence ---------------------------------------------------------------------------------------
    def push_package(self):
        self.snippet('mkrun', {'run_dir': self.rrun, 'run_id': self.run_id,
                               'subdirs': ['t', 'native'] + (['cts'] if self.cts else [])}, 60)
        files = {}
        srcs = sorted(self.target_dir.glob('*.py'))
        check(any(f.name == '__main__.py' for f in srcs), 'target package has no __main__.py')
        for f in srcs:
            data = f.read_bytes()
            r = self.ops.push(self.rrun + '/t/' + f.name, data, 0o600)
            check(r['sha256'] == H(data), 'push readback %s' % f.name)
            files[f.name] = H(data)
        r = self.ops.push(self.rrun + '/config.json', self.cfg_raw, 0o600)
        check(r['sha256'] == self.cfg_sha, 'config push readback')
        return {'target_files': files, 'config_sha256': self.cfg_sha}

    def upload_artifacts(self):
        done = {}
        for f, sha in sorted(self.cfg['artifact_shas'].items()):
            data = Path(self.local_files[f]).read_bytes()
            check(H(data) == sha, 'local artifact %s changed since inspection' % f)
            up = self.api.put_artifact(data)
            check(isinstance(up, dict) and up.get('sha256') == sha and up.get('size') in (None, len(data)),
                  'labd artifact upload mismatch for %s: %r' % (f, up))
            done[f] = sha
        return {'uploaded': done}

    def verify_preflight(self, res):
        f = res.get('facts') or {}
        for n in [c['name'] for c in self.cfg['candidates']]:
            check((f.get('packages') or {}).get(n) == self.facts['packages'].get(n),
                  'preflight %s version %r differs from probe %r' % (n, (f.get('packages') or {}).get(n),
                                                                   self.facts['packages'].get(n)))
        check(f.get('kernel') == self.prof['known_good_kernel'], 'preflight kernel')
        check(f.get('bootbin_sha256') in (None, H(self.bootbin)), 'preflight boot.bin differs')
        self.save_local('preflight-facts.json', canon(f))

    def verify_capture(self, res):
        check(HEX64.match(str(res.get('capture_sha256') or '')), 'capture result lacks capture_sha256')
        self.capture_result = res

    def pull_capture(self):
        cap = self.capture_result
        state = self.ops.pull(self.rrun + '/capture/state.json', limit=256 << 20)
        check(H(state) == cap['capture_sha256'], 'pulled state.json differs from capture_sha256')
        self.save_local('capture/state.json', state)
        st = json.loads(state)
        check(st.get('run_id') == self.run_id and st.get('device') == self.device, 'capture identity')
        check(st.get('kernel') in (None, self.prof['known_good_kernel']), 'capture kernel')
        for o in self.cfg['originals']:
            got = ((st.get('packages') or {}).get(o['name']) or {}).get('version', o['version'])
            check(got == o['version'], 'capture %s version %r != original %r' % (o['name'], got, o['version']))
        t = self.snippet('tar', {'run_dir': self.rrun, 'name': 'bt2-capture.tar'}, 1800)
        tar = self.ops.pull(t['path'])
        check(H(tar) == t['sha256'] and len(tar) == t['bytes'], 'capture tarball pull mismatch')
        # The tarball is ESP-sized. The controller disk is nearly full and gives EIO on big writes, so the
        # tarball stays in memory for the M5 copy; the Mac keeps capture/ and only the hash is written here.
        self.save_local('capture/bt2-capture.tar.json', canon({'sha256': t['sha256'], 'bytes': t['bytes'],
                                                                'mac_path': t['path']}))
        for name, sha in sorted((t.get('receipts') or {}).items()):
            check(re.fullmatch(r'[A-Za-z0-9._-]{1,120}', name) is not None, 'odd receipt name')
            data = self.ops.pull(self.rrun + '/receipts/' + name, limit=1 << 20)
            check(H(data) == sha, 'receipt %s pull mismatch' % name)
            self.save_local('receipts/' + name, data)
        self.capture_blobs = {'capture-state.json': state, 'capture.tar': tar,
                              'capture-result.json': canon(cap)}
        return {'state_sha256': H(state), 'tar_sha256': t['sha256'], 'tar_bytes': t['bytes'],
                'receipts': sorted(t.get('receipts') or {})}

    def m5_capture(self):
        r = m5.Retainer(self.run_id, runner=self.m5_runner)
        storage = r.init(sum(len(b) for b in self.capture_blobs.values()))
        recs = [r.put(n, b) for n, b in sorted(self.capture_blobs.items())]
        self.save_local('m5-capture.json', canon({'storage': storage, 'files': recs}))
        return {'root': r.root, 'files': [x['name'] for x in recs]}

    def write_preinstall(self):
        pins = installed.write_preinstall(self.release, self.device, self.cohort,
                                          'byte copy of %s preinstall for bt2 run %s' % (
                                              self.prof['baseline_release'], self.run_id))
        return {'release': self.release, 'pins': pins}

    def freeze_manifest(self):
        resp = installed.freeze_manifest(self.api, self.release, self.man_raw, self.payload, self.approved_by)
        check(isinstance(resp, dict) and resp.get('release') == self.release
              and resp.get('manifest_sha256') in (None, H(self.man_raw)), 'freeze-manifest response %r' % (resp,))
        self.save_local('freeze-manifest.json', canon(resp))
        return {'manifest_sha256': H(self.man_raw), 'pins_sha256': resp.get('pins_sha256')}

    def verify_install(self, res):
        cand = res.get('candidate') or {}
        check(cand.get('krel') == self.krel, 'install reports candidate krel %r, manifest %s' % (
            cand.get('krel'), self.krel))
        if self.allow_bootbin:
            check(res.get('bootbin_is_expected') is True
                  and res.get('bootbin_sha256') == self.cfg['expected_bootbin_sha256'],
                  'install did not leave exactly the expected candidate boot.bin: %r' % (res.get('bootbin_sha256'),))
        elif 'bootbin_unchanged' in res:
            check(res['bootbin_unchanged'] is True, 'install changed boot.bin')
        self.install_result = res

    def _freeze_entry(self, release, krel, save_as):
        resp = installed.freeze_entry(self.api, release, self.device)
        check(isinstance(resp, dict) and resp.get('device') == self.device and resp.get('release') == release,
              'freeze-entry response %r' % (_small(resp),))
        entry = None
        f = installed.FROZEN / release / 'installer-entry' / (self.device + '.json')
        if f.is_file():
            raw = f.read_bytes()
            pins = installed.FROZEN / release / ('PINS.installer-entry.' + self.device)
            if pins.is_file():
                listed = {ln.split('  ', 1)[1]: ln.split('  ', 1)[0] for ln in pins.read_text().splitlines()
                          if ln and not ln.startswith('#') and '  ' in ln}
                rel = 'installer-entry/%s.json' % self.device
                check(listed.get(rel) in (None, H(raw)), 'frozen entry differs from its pin')
            entry = json.loads(raw)
        if entry is None:
            entry = resp.get('entry')
        check(isinstance(entry, dict) and entry.get('found') is True, 'freeze-entry found no installer entry')
        check(((entry.get('uki_sections') or {}).get('.uname') or {}).get('text', krel) == krel,
              'frozen entry is not kernel %s' % krel)
        self.save_local(save_as, canon(entry))
        return entry, resp

    def freeze_entry(self):
        entry, resp = self._freeze_entry(self.release, self.krel, 'installer-entry.json')
        self.entry = entry
        self.entry_api = resp
        return {'entry_name': entry.get('name'), 'path': entry.get('path'), 'uki_sha256': entry.get('uki_sha256'),
                'entry_sha256': resp.get('entry_sha256')}

    # -- fresh baseline (installed-mode job of the ORIGINAL cohort, before any install) --------------------------
    def base_preinstall(self):
        # labd needs SOME frozen preinstall to run an installed job; the base job's own verdict against it is
        # recorded and ignored. Only the base job's outputs (fresh-preinstall) judge the candidate.
        pins = installed.write_preinstall(self.base_release, self.device, self.cohort,
                                          'byte copy of %s preinstall for the base job of bt2 run %s (its verdict '
                                          'is not used)' % (self.prof['baseline_release'], self.run_id))
        return {'release': self.base_release, 'pins': pins}

    def base_freeze_manifest(self):
        resp = installed.freeze_manifest(self.api, self.base_release, self.base_raw, self.base_payload,
                                         self.approved_by)
        check(isinstance(resp, dict) and resp.get('release') == self.base_release
              and resp.get('manifest_sha256') in (None, H(self.base_raw)), 'base freeze-manifest response %r' % (resp,))
        self.save_local('base/freeze-manifest.json', canon(resp))
        return {'manifest_sha256': H(self.base_raw), 'pins_sha256': resp.get('pins_sha256')}

    def base_freeze_entry(self):
        entry, resp = self._freeze_entry(self.base_release, self.base_man['kernel']['release'],
                                         'base/installer-entry.json')
        self.base_entry = entry
        return {'entry_name': entry.get('name'), 'path': entry.get('path'), 'uki_sha256': entry.get('uki_sha256'),
                'entry_sha256': resp.get('entry_sha256')}

    def extra_tests(self, arm):
        if not self.extra_sha:
            return []
        # Not a gui test: lab-agent runs a gui test as the desktop user (runuser, internal/agent/tests.go), but the
        # runner must start as root (0600 root input, kernel journal, provider audit) and drops each workload to the
        # desktop user itself.
        tests = [{'name': EXTRA_TEST, 'script': self.extra_sha, 'timeout_sec': EXTRA_TIMEOUT}]
        if arm == 'candidate' and self.cts_sha:
            # its own TestSpec, after the benchmark, candidate job only; also not gui (the CTS script starts as root)
            tests.append({'name': CTS_TEST, 'script': self.cts_sha, 'timeout_sec': CTS_TIMEOUT})
        return tests

    def stage_cts(self):
        """The pinned CTS archive and case lists into bt2's own run dir (<run>/cts, removed by the target's cleanup,
        on restore too), the candidate input (kernel + candidate provider pins + the pins of everything staged), then
        the CTS script. Nothing is installed: the script extracts into /run at test time (gone at the return reboot)."""
        cand = self.native_cohort
        d = self.rrun + '/cts'
        check(any(k in self.extra['assets'] for k in ('vk_work', 'vkquake')),
              'the CTS gate needs the benchmark workload executables (--extra-assets vk_work/vkquake)')
        staged = {}
        for name, data in [('cts.pkg.tar.zst', self.cts['archive'])] + \
                [('%s.txt' % l['name'], l['data']) for l in self.cts['lists']]:
            r = self.ops.push(d + '/' + name, data, 0o600)
            check(r['sha256'] == H(data), 'cts push readback: %s' % name)
            staged[name] = {'path': d + '/' + name, 'sha256': H(data), 'bytes': len(data)}
        raw = native.encode({'schema': 'eryk-cts-input/1', 'arm': 'candidate', 'run_id': self.run_id,
                             'device': self.device, 'board': self.prof['board'],
                             'expected_kernel': cand['expected_kernel'], 'providers': cand['providers'],
                             'archive': staged['cts.pkg.tar.zst'], 'deqp_vk_sha256': self.cts['deqp_vk_sha256'],
                             # the CTS gate requires this job's benchmark settle receipt for exactly this input, and
                             # proves none of these executables still runs (a SIGKILLed eryk-bench leaves its runuser
                             # session-scope workloads behind until the return reboot)
                             'bench': {'input_sha256': self.extra_inputs['candidate']['sha256'],
                                       'executables': sorted({a['path'] for k, a in self.extra['assets'].items()
                                                              if k in ('vk_work', 'vkquake') and isinstance(a, dict)})},
                             'data_manifest_sha256': self.cts['data_manifest_sha256'],
                             'lists': [{'name': l['name'], 'path': staged['%s.txt' % l['name']]['path'],
                                        'sha256': l['sha256'], 'cases': l['cases'], 'deadline_s': l['deadline_s']}
                                       for l in self.cts['lists']]})
        r = self.ops.push(d + '/cts-input-%s.json' % cand['expected_kernel'], raw, 0o600)
        check(r['sha256'] == H(raw), 'cts input push readback')
        self.save_local('cts/input-candidate.json', raw)
        self.cts_input = {'kernel': cand['expected_kernel'], 'sha256': H(raw)}
        script = cts_script(self.extra['runner'], self.cts['runner'], d, {cand['expected_kernel']: H(raw)})
        up = self.api.put_artifact(script)
        check(isinstance(up, dict) and up.get('sha256') == H(script), 'cts script artifact upload mismatch')
        self.save_local('cts/script.sh', script)
        self.cts_sha = H(script)
        return {'script_sha256': self.cts_sha, 'runner_sha256': H(self.cts['runner']), 'input': self.cts_input,
                'staged': {k: v['sha256'] for k, v in staged.items()}}

    def cts_results(self):
        """The CTS test's own result: labd's verdict on eryk-cts plus its summary/gate (never fatal, never folded into
        the benchmark outcome). Functional Fail/NotSupported are data in the summary, not a lost run."""
        tests = [t for t in ((self.job or {}).get('result') or {}).get('tests') or [] if t.get('name') == CTS_TEST]
        got = {'test_passed': len(tests) == 1 and tests[0].get('passed') is True}
        for name in ('summary.json', 'gate.json'):
            try:
                data = self.api.job_file(self.job_id, 'test-%s/eryk-cts/%s' % (CTS_TEST, name), limit=16 << 20)
            except Exception as e:  # noqa: BLE001
                got[name] = 'unavailable: %s' % str(e)[:200]
                continue
            self.save_local('cts/candidate-%s' % name, bytes(data))
            got[name] = H(bytes(data))
            try:
                doc = json.loads(bytes(data))
            except ValueError:
                doc = {}
            if name == 'gate.json':
                got['binding_ok'] = (doc.get('job') == self.job_id and doc.get('input_sha256') == self.cts_input['sha256']
                                     and doc.get('release') == self.cts_input['kernel'] and doc.get('arm') == 'candidate')
            else:
                got['status'] = doc.get('status')
                got['failures'] = doc.get('failures')
                got['counts'] = doc.get('counts')
        self.cts_outcome = got
        return got

    def stage_extra(self):
        """Per-arm input (kernel release + the six GPU provider pins + frozen assets) into bt2's own run dir, then the
        one script both jobs run. Baseline pins come from the original archives, candidate pins are gate-native's."""
        base_krel = self.base_man['kernel']['release']
        try:
            base = native.cohort_pins(base_krel, native.providers_from(
                self.orig_insps, [*self.kept_insps, *self.stay_insps]), self.nsrc['checker'])
        except native.NativeError as e:
            raise StepFailure('extra test baseline providers: %s' % e, changed=False)
        cand = self.native_cohort
        check(base['expected_kernel'] != cand['expected_kernel'], 'baseline and candidate boot the same kernel release')
        inputs = {}
        for arm, cohort in (('baseline', base), ('candidate', cand)):
            raw = native.encode({'schema': 'eryk-bench-input/1', 'arm': arm, 'run_id': self.run_id,
                                 'device': self.device, 'board': self.prof['board'],
                                 'expected_kernel': cohort['expected_kernel'], 'providers': cohort['providers'],
                                 'assets': self.extra['assets'], 'warmups': 2, 'repetitions': 5,
                                 'start_temperature_c': 60,
                                 # the runner's settle receipt, only where eryk-cts follows (candidate job, --cts-test)
                                 **({'settle_receipt': True} if self.cts and arm == 'candidate' else {})})
            r = self.ops.push(self.rrun + '/extra-input-%s.json' % cohort['expected_kernel'], raw, 0o600)
            check(r['sha256'] == H(raw), 'extra input push readback')
            self.save_local('extra/input-%s.json' % arm, raw)
            inputs[arm] = {'kernel': cohort['expected_kernel'], 'sha256': H(raw)}
        self.extra_inputs = inputs
        script = extra_script(self.extra['runner'], self.rrun, {v['kernel']: v['sha256'] for v in inputs.values()})
        up = self.api.put_artifact(script)
        check(isinstance(up, dict) and up.get('sha256') == H(script), 'extra script artifact upload mismatch')
        self.save_local('extra/script.sh', script)
        self.extra_sha = H(script)
        return {'script_sha256': self.extra_sha, 'runner_sha256': H(self.extra['runner']), 'inputs': inputs}

    def extra_results(self, job_id, arm):
        """Copy the extra test's summary and gate into the run dir (never fatal; labd keeps the full job files), and
        record labd's own verdict on the extra test in that job (a complete summary never outweighs a failed test)."""
        job = self.base_job if arm == 'baseline' else self.job
        tests = [t for t in ((job or {}).get('result') or {}).get('tests') or [] if t.get('name') == EXTRA_TEST]
        got = {'test_passed': len(tests) == 1 and tests[0].get('passed') is True}
        for name in ('summary.json', 'gate.json'):
            try:
                data = self.api.job_file(job_id, 'test-%s/eryk-bench/%s' % (EXTRA_TEST, name), limit=16 << 20)
            except Exception as e:  # noqa: BLE001
                got[name] = 'unavailable: %s' % str(e)[:200]
                continue
            self.save_local('extra/%s-%s' % (arm, name), bytes(data))
            got[name] = H(bytes(data))
            try:
                doc = json.loads(bytes(data))
            except ValueError:
                doc = {}
            if name == 'gate.json':
                want = self.extra_inputs[arm]
                got['binding_ok'] = (doc.get('job') == job_id and doc.get('input_sha256') == want['sha256']
                                     and doc.get('release') == want['kernel'] and doc.get('arm') == arm)
            else:
                got['status'] = doc.get('status')
        self.extra_outcome[arm] = got
        return got

    def base_submit(self):
        spec = installed.job_spec(self.device, self.holder, H(self.base_raw), self.mode, self.run_id,
                                  extra_tests=self.extra_tests('baseline'))
        self.base_job_id, self.base_pre_boot = self._submit_spec(spec, 'base/job-spec.json')
        return {'job_id': self.base_job_id, 'pre_submit_boot_id': self.base_pre_boot}

    def base_job_wait(self):
        job = self._wait_job(self.base_job_id, 'base-job-wait')
        self.base_job = job
        self.save_local('base/job.json', canon(job))
        return {'job_id': self.base_job_id, 'outcome': job.get('outcome'), 'summary': str(job.get('summary'))[:500]}

    def base_verify_return(self):
        return self._verify_return(self.base_job, self.base_pre_boot)

    def _job_file(self, job_id, name, limit=16 << 20):
        try:
            data = self.api.job_file(job_id, name, limit=limit)
        except labd.APIError as e:
            raise StepFailure('base job %s has no %s (%s)' % (job_id, name, e.code), changed=False)
        except Exception as e:  # noqa: BLE001
            raise StepFailure('reading base job file %s: %s' % (name, e), changed=False)
        check(isinstance(data, (bytes, bytearray)), 'base job file %s is not bytes' % name)
        return bytes(data)

    def fresh_preinstall(self):
        """The base job's outputs -> this run's frozen preinstall (same files + PINS format as the stale copy)."""
        job, jid = self.base_job, self.base_job_id
        base_krel = self.base_man['kernel']['release']
        res = job.get('result') or {}
        inst = res.get('installed') or {}
        verdicts = inst.get('verdicts') or {}
        check(job.get('state') == 'done' and job.get('outcome') in BASE_OK_OUTCOMES,
              'base job %s ended %r (%s): no usable fresh baseline' % (jid, job.get('outcome'),
                                                                       str(job.get('summary'))[:300]))
        check(res.get('booted') is True and res.get('boot_kernel') == base_krel,
              'base job %s did not boot the installed original %s (booted %r, kernel %r)' % (
                  jid, base_krel, res.get('booted'), res.get('boot_kernel')))
        check(all(verdicts.get(p) == 'MATCH' for p in ('before', 'booted', 'after')),
              'base job %s identity is not MATCH/MATCH/MATCH: %r' % (jid, verdicts))
        failed = sorted(t.get('name') for t in res.get('tests') or [] if not t.get('passed'))
        report = self._job_file(jid, OMT_REPORT_FILE)
        try:
            status, tool, kernel = installed.report_status(report)
        except (ValueError, installed.InstalledError) as e:
            raise StepFailure('base job omarchy-m-test report: %s' % e, changed=False)
        check(status and '' not in status, 'base job omarchy-m-test report has no usable checks')
        check(kernel == base_krel, 'base job omarchy-m-test ran on %r, not %s' % (kernel, base_krel))
        dmesg = self._job_file(jid, DMESG_FILE)
        try:
            sealed = self._job_file(jid, SEALED_JOB_FILE)
            check(json.loads(sealed).get('id') == jid, 'sealed base job record names another job')
            job_raw, job_src = sealed, SEALED_JOB_FILE
        except (StepFailure, ValueError, AttributeError):
            job_raw, job_src = (json.dumps(job, indent=2) + '\n').encode(), 'api'
        files = {'omt-report.json': report, 'omt-status.json': installed.status_json(status),
                 'dmesg-errors.txt': dmesg, 'baseline-job.json': job_raw}
        prov = {'schema': 'bt2.preinstall-fresh/1', 'run_id': self.run_id, 'base_release': self.base_release,
                'base_job': jid, 'base_outcome': job.get('outcome'), 'base_summary': str(job.get('summary'))[:500],
                'base_kernel': base_krel, 'base_failed_tests': failed, 'base_omt_vs_stale': inst.get('omt'),
                'base_dmesg_vs_stale': inst.get('dmesg'), 'baseline_job_source': job_src,
                'stale_source_release': self.prof['baseline_release'], 'promoted': False,
                'scope': 'this run only: labd never promotes an installed job (server/installed.go:15-16)'}
        pins = installed.write_preinstall_files(
            self.release, self.device, files, 'fresh baseline from base job %s (%s) of bt2 run %s' % (
                jid, self.base_release, self.run_id), 'PREINSTALL-FRESH.json', prov)
        for n, b in files.items():
            self.save_local('base/preinstall/' + n, b)
        counts = {k: sum(1 for v in status.values() if v == k) for k in ('pass', 'fail', 'skip')}
        return {'release': self.release, 'pins': pins, 'base_job': jid, 'base_outcome': job.get('outcome'),
                'base_failed_tests': failed, 'base_omt_vs_stale': inst.get('omt'), 'omt_tool': tool,
                'omt_counts': counts, 'checks': len(status), 'baseline_job_source': job_src}

    def stage_native(self):
        script = native.build_script(self.rrun, self.nsrc, self.native_cohort)
        sha = H(script)
        try:
            inp = native.compute_input(run_id=self.run_id, run_dir=self.rrun, profile=self.prof, facts=self.facts,
                                       inspections=self.cands, manifest=self.man, entry=self.entry,
                                       script_sha256=sha, mode=self.mode, tools=self.tools,
                                       cohort=self.native_cohort, fallback_inspections=[*self.kept_insps, *self.stay_insps])
        except native.NativeError as e:
            raise StepFailure('native input: %s' % e, changed=False)
        inp_raw = native.encode(inp)
        self.save_local('native/script.sh', script)
        self.save_local('native/native-input.json', inp_raw)
        r = self.ops.push(self.rrun + '/native/checker.py', self.nsrc['checker'], 0o600)
        check(r['sha256'] == native.CHECKER_SHA, 'checker push readback')
        r = self.ops.push(self.rrun + '/native-input.json', inp_raw, 0o600)
        check(r['sha256'] == H(inp_raw), 'native-input push readback')
        up = self.api.put_artifact(script)
        check(isinstance(up, dict) and up.get('sha256') == sha, 'script artifact upload mismatch')
        self.script_sha = sha
        return {'script_sha256': sha, 'native_input_sha256': H(inp_raw)}

    def _submit_spec(self, spec, spec_name):
        self.ensure_lease()
        d = self.api.device(self.device)
        self.device_gate(d)
        pre = d['boot_id']
        self.save_local(spec_name, canon(spec))
        try:
            resp = self.api.submit(spec)
        except labd.APIError as e:
            raise StepFailure('labd refused the job (%s): %s' % (e.code, e.body[:500]), code=e.code, changed=False)
        except Exception as e:
            raise StepFailure('job submit outcome unknown: %s' % e, ambiguous=True)
        jid = (resp or {}).get('id')
        check(isinstance(jid, str) and JOB_RE.match(jid), 'submit response without a job id: %r' % (resp,))
        return jid, pre

    def submit(self):
        spec = installed.job_spec(self.device, self.holder, H(self.man_raw), self.mode, self.run_id,
                                  native_script_sha=self.script_sha, extra_tests=self.extra_tests('candidate'))
        self.job_id, self.pre_submit_boot = self._submit_spec(spec, 'job-spec.json')
        return {'job_id': self.job_id, 'pre_submit_boot_id': self.pre_submit_boot}

    def _wait_job(self, job_id, note_step):
        deadline = self.clock() + JOB_BUDGET
        q = urllib.parse.quote(job_id, safe='')
        while True:
            self.ensure_lease()
            left = deadline - self.clock()
            if left <= 0:
                raise StepFailure('job %s not done within %d s' % (job_id, JOB_BUDGET), ambiguous=True)
            chunk = int(max(60, min(WAIT_CHUNK, left)))
            try:
                job = self.api.get('/api/jobs/%s/wait?timeout=%d' % (q, chunk), timeout=chunk + 60)
            except Exception as e:  # noqa: BLE001 - timeouts are expected; fall back to polling
                self.j.note(note_step, wait_error=str(e)[:300])
                try:
                    job = self.api.job(job_id)
                except Exception as e2:  # noqa: BLE001
                    self.j.note(note_step, poll_error=str(e2)[:300])
                    self.sleep(30)
                    continue
            if isinstance(job, dict) and job.get('state') == 'done':
                return job
            self.sleep(POLL)

    def job_wait(self):
        job = self._wait_job(self.job_id, 'job-wait')
        self.job = job
        self.save_local('job.json', canon(job))
        return {'job_id': self.job_id, 'outcome': job.get('outcome'), 'summary': str(job.get('summary'))[:500]}

    def on_known_good(self, d):
        return (d.get('kernel') == self.prof['known_good_kernel'] and 'maclab.job=' not in (d.get('cmdline') or '')
                and d.get('state') == 'ready' and d.get('alive') is True and not d.get('active_job'))

    def verify_return(self):
        return self._verify_return(self.job, self.pre_submit_boot)

    def _verify_return(self, job, pre_boot):
        outcome = job.get('outcome')
        deadline = self.clock() + REBOOT_WAIT
        while True:
            d = self.api.device(self.device)
            if self.on_known_good(d) and (d.get('boot_id') != pre_boot or outcome != 'pass'):
                break
            if self.clock() >= deadline:
                raise StepFailure('Mac is not back on the known-good untagged boot (state %r kernel %r boot %r)' % (
                    d.get('state'), d.get('kernel'), d.get('boot_id')), ambiguous=True)
            self.sleep(POLL)
        ident = self.identity()
        check(ident['boot_id'] == d['boot_id'] and ident['kernel'] == self.prof['known_good_kernel']
              and 'maclab.job=' not in ident['cmdline'], 'Mac identity after the job differs from labd')
        return {'boot_id': d['boot_id'], 'boot_changed': d['boot_id'] != pre_boot, 'outcome': outcome}

    def verify_guard_install(self, res):
        g = self.cfg['bootbin_guard']
        check(res.get('recovery_copy_sha256') == g['original_sha256'], 'guard install: Recovery copy not the original')
        st = res.get('state') or {}
        check(st.get('LoadState') == 'loaded' and st.get('ActiveState') == 'inactive' and st.get('UnitFileState') == 'enabled',
              'guard unit state %r' % (st,))
        ident = res.get('esp_identity') or {}
        check(ident.get('partition_uuid'), 'guard install: no ESP partition UUID for the Recovery card')
        self.save_local('RECOVERY.txt', recovery_card(self.device, self.run_id, ident, g, len(self.bootbin)).encode())

    def guard_check(self):
        """Back on known-good after the candidate job: the guard must have put the original boot.bin back."""
        g = self.cfg['bootbin_guard']
        res = self.target('bootbin-guard-status')
        self.save_local('bootbin-guard-status.json', canon(res))
        recs = res.get('receipts') or []
        restored = [r for r in recs if r.get('action') == 'restored']
        bad = [r for r in recs if r.get('ok') is not True or r.get('action') == 'unexpected-left-alone']
        check(res.get('is_original') is True, 'boot.bin %s after the job is not the original %s' % (
            res.get('bootbin_sha256'), g['original_sha256']))
        check(len(restored) == 1 and not bad, 'guard receipts not one clean restore: %s' % _small(recs))
        r = restored[0]
        keep = [k for k in recs if k.get('action') == 'keep-candidate-boot']
        check(len(keep) == 1 and keep[0].get('running_kernel') == self.krel and keep[0].get('boot_id'),
              'no single guard start receipt from the candidate kernel boot: %s' % _small(recs))
        v = ((self.job.get('result') or {}).get('installed') or {}).get('verdicts') or {}
        check(v.get('booted') == 'MATCH' and v.get('after') == 'MATCH', 'candidate job identity verdicts %r: boot.bin %s '
              'and stage 2 %s not proven on the candidate boot' % (v, g['candidate_sha256'][:16], g['candidate_stage2_version']))
        check(r.get('phase') != 'stop' or r.get('boot_id') == keep[0]['boot_id'],
              'stop-hook restore ran on boot %s, not the candidate boot %s' % (r.get('boot_id'), keep[0]['boot_id']))
        by = ('stop hook of the candidate boot' if r.get('phase') == 'stop' and r.get('running_kernel') == self.krel
              else 'start hook of a later boot (the candidate stage 2 ran again first)' if r.get('phase') == 'start'
              else 'other: %s' % r.get('phase'))
        want = g['original_stage2_version'] if r.get('phase') == 'stop' else g['candidate_stage2_version']
        check(res.get('stage2_version') == want, 'return boot stage 2 %r, expected %r for a restore by the %s' % (
            res.get('stage2_version'), want, by))
        check(res.get('recovery_copy_sha256') == g['original_sha256'], 'Recovery copy on the ESP changed')
        self.guard_result = {'candidate_stage2_boots': 1 if r.get('phase') == 'stop' else 2, 'restored_by': by}
        return {'candidate_boot_id': keep[0]['boot_id'], 'restored_by': by, 'restore_receipt': r.get('receipt'), 'return_boot_stage2': res.get('stage2_version'),
                'candidate_stage2_boots': 1 if r.get('phase') == 'stop' else 2}

    def stage2_final(self):
        g = self.cfg['bootbin_guard']
        f = self.identity()
        check(f.get('bootbin_sha256') == g['original_sha256'], 'final boot.bin %s is not the original' % (
            f.get('bootbin_sha256'),))
        check(f.get('m1n1_stage2_version') == g['original_stage2_version'], 'final boot ran stage 2 %r, not the '
              'original %r' % (f.get('m1n1_stage2_version'), g['original_stage2_version']))
        return {'stage2_version': f.get('m1n1_stage2_version'), 'bootbin_sha256': f.get('bootbin_sha256')}

    def locks(self):
        o = self.snippet('locks', {}, 60)
        check(o.get('ok') is True, 'boot locks not usable: %r' % o)
        return o

    def reboot_and_wait(self):
        d0 = self.api.device(self.device)
        old = d0.get('boot_id')
        try:
            r = self.ops.reboot()
            if isinstance(r, dict) and r.get('exit_code') not in (0, None):
                raise StepFailure('reboot command failed (exit %r): %s' % (r.get('exit_code'), r.get('stderr')),
                                  code=r.get('exit_code'), changed=False)
            self.j.note('reboot', exec_result=_small(r))
        except StepFailure:
            raise
        except Exception as e:  # noqa: BLE001 - the agent may die before answering
            self.j.note('reboot', exec_ambiguous=str(e)[:300])
        deadline = self.clock() + REBOOT_WAIT
        while True:
            self.sleep(POLL)
            try:
                d = self.api.device(self.device)
            except Exception:  # noqa: BLE001
                d = {}
            if d.get('boot_id') and d['boot_id'] != old and d.get('state') == 'ready' and d.get('alive') is True \
                    and not d.get('active_job'):
                break
            if self.clock() >= deadline:
                raise StepFailure('no new boot id within %d s after reboot' % REBOOT_WAIT, ambiguous=True)
        ident = self.identity()
        check(ident['boot_id'] == d['boot_id'], 'post-reboot identity differs from labd')
        check(ident['kernel'] == self.prof['known_good_kernel'], 'rebooted into %s, not known-good %s' % (
            ident['kernel'], self.prof['known_good_kernel']))
        check('maclab.job=' not in ident['cmdline'], 'rebooted into a tagged lab boot')
        return {'old_boot_id': old, 'boot_id': d['boot_id'], 'kernel': ident['kernel']}

    def verify_audit(self, res):
        check(res.get('differences') in ([], None) and res.get('ok') is True,
              'audit differences: %s' % _small(res.get('differences')))

    def m5_result(self, tag):
        r = m5.Retainer(self.run_id, runner=self.m5_runner)
        seq = len(self.j.records)
        res = r.put('%s-result-%d.json' % (tag, seq), canon(self.summary(tag)))
        jr = r.put('%s-journal-%d.jsonl' % (tag, seq), (self.rd / 'journal.jsonl').read_bytes())
        return {'files': [res['name'], jr['name']]}

    def summary(self, tag):
        job = getattr(self, 'job', None) or {}
        base = getattr(self, 'base_job', None) or {}
        return {'schema': 'bt2.run-result/1', 'tag': tag, 'run_id': self.run_id, 'device': self.device,
                'release': self.release, 'mode': self.mode, 'holder': self.holder,
                'baseline': getattr(self, 'baseline', None),
                'job': {'id': getattr(self, 'job_id', None) or job.get('id'), 'outcome': job.get('outcome'),
                        'summary': job.get('summary')},
                'base_job': {'id': getattr(self, 'base_job_id', None) or base.get('id'), 'outcome': base.get('outcome'),
                             'summary': base.get('summary')},
                'steps': {k: v['state'] for k, v in step_states(self.j.records).items()}, 'at': time.time()}

    # -- commands --------------------------------------------------------------------------------------------------
    def run(self, device, artifact_paths, mode='network-only', holder=DEFAULT_HOLDER, run_id=None,
            extra_packages=(), approved_by=(), manifest_mode='generate', baseline='auto', extra_test=None,
            extra_assets=None, cts_test=None, cts_assets=None, allow_bootbin_change=False):
        prof, prof_raw = self.load_profile(device)
        self.allow_bootbin = bool(allow_bootbin_change)
        if mode not in MODES:
            raise UsageError('mode must be one of %s' % (MODES,))
        if baseline not in BASELINE_MODES:
            raise UsageError('baseline must be one of %s' % (BASELINE_MODES,))
        if not artifact_paths:
            raise UsageError('at least one --artifact is required')
        run_id = run_id or default_run_id(device, self.wall())
        if not (RUN_RE.match(run_id) and TXN_RE.match(run_id)):
            raise UsageError('run id must match %s' % RUN_RE.pattern)
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        rd = self.state_root / run_id
        if rd.exists():
            raise UsageError('run dir %s already exists' % rd)
        self.artifact_paths = [str(Path(p).resolve()) for p in artifact_paths]
        self.extra_packages = [str(Path(p).resolve()) for p in extra_packages]
        self.approved_by = list(approved_by) or [holder]
        self.manifest_mode = manifest_mode
        self.extra, self.extra_sha, self.extra_inputs, self.extra_outcome = None, None, {}, {}
        if extra_test:
            if baseline == 'stale':
                raise UsageError('--extra-test runs in both jobs, so it needs a fresh baseline job')
            try:
                runner = Path(extra_test).read_bytes()
                assets = json.loads(Path(extra_assets).read_bytes()) if extra_assets else {}
            except (OSError, ValueError) as e:
                raise UsageError('--extra-test/--extra-assets: %s' % e)
            if not isinstance(assets, dict):
                raise UsageError('--extra-assets must be a JSON object')
            self.extra = {'runner': runner, 'assets': assets}
        self.cts, self.cts_sha, self.cts_input, self.cts_outcome = None, None, None, {}
        if cts_test:
            if not self.extra:
                raise UsageError('--cts-test runs after the --extra-test benchmark in the candidate job; give both')
            try:
                cts_runner = Path(cts_test).read_bytes()
                cts_doc = json.loads(Path(cts_assets).read_bytes()) if cts_assets else None
            except (OSError, ValueError) as e:
                raise UsageError('--cts-test/--cts-assets: %s' % e)
            self.cts = load_cts(cts_runner, cts_doc)
        remote = REMOTE_BASE + '/' + run_id
        header = {'schema': SCHEMA_RUN, 'run_id': run_id, 'device': device, 'mode': mode, 'holder': holder,
                  'release': release_name(run_id), 'remote_run_dir': remote, 'artifacts': self.artifact_paths,
                  'extra_packages': self.extra_packages, 'manifest_mode': manifest_mode, 'baseline': baseline,
                  'base_release': release_name(run_id) + BASE_SUFFIX if baseline != 'stale' else None,
                  'profile_sha256': H(prof_raw), 'controller_sha256': H(Path(__file__).read_bytes()),
                  'extra_test_sha256': H(self.extra['runner']) if self.extra else None,
                  'extra_assets_sha256': H(native.encode(self.extra['assets'])) if self.extra else None,
                  'cts_test_sha256': H(self.cts['runner']) if self.cts else None,
                  'cts_assets_sha256': self.cts['assets_sha256'] if self.cts else None,
                  'allow_bootbin_change': self.allow_bootbin,
                  'started': self.wall().isoformat()}
        j = Journal.create(rd, header)
        self._bind(run_id, rd, j, prof, holder, mode, remote)
        self.baseline = baseline
        self.base_release = self.release + BASE_SUFFIX
        self.save_local('device.json', prof_raw)
        s = self.step
        try:
            # ---- pre-mutation gates (nothing on the Mac changes) ----
            s('gate-profile', lambda: need(mode in prof['recovery_modes'], 'mode %s not in %s recovery_modes %s' % (
                mode, device, prof['recovery_modes'])) or {'recovery_modes': prof['recovery_modes']})
            s('gate-device', self.gate_device)
            s('gate-capabilities', self.gate_capabilities)
            if mode == 'serial-assisted':
                s('gate-oob', self.gate_oob_config)
            s('gate-open-runs', self.gate_open_runs)
            s('inspect-candidates', self.inspect_candidates)
            s('native-sources', self.load_native)
            s('gate-frozen', self.gate_frozen)
            s('lease', self.acquire_lease)
            s('recovery-mode', self.select_mode)
            s('probe', self.probe)
            s('resolve-packages', self.resolve_packages)
            s('baseline-mode', lambda: self.decide_baseline(baseline))
            if self.extra:
                s('gate-extra', lambda: need(self.baseline == 'fresh', '--extra-test needs the fresh baseline job, '
                                             'and this run resolved to %s' % self.baseline) or {'baseline': self.baseline})
            s('pull-bootbin', self.pull_bootbin)
            s('manifest', self.make_manifest)
            if self.baseline == 'fresh':
                s('base-manifest', self.make_base_manifest)
            s('gate-native', self.gate_native)
            s('config', self.make_config)
            # ---- run dir + capture (only bt2's own run dir changes) ----
            s('push', self.push_package, mutating=True)
            s('upload', self.upload_artifacts)
            self.tstep('fetch')
            self.tstep('preflight', verify=self.verify_preflight)
            self.tstep('capture', verify=self.verify_capture)
            # ---- system mutations (each with its inverse) ----
            # writers are held straight after the capture: the snapshot tools rewrite limine.conf on their own
            # schedule (seen on the M1 2 minutes after a capture), and esp-prep needs the ESP exactly as captured
            self.ensure_lease()
            self.tstep('hold-writers', inverse='release-writers', mutating=True)
            s('pull-capture', self.pull_capture)
            s('m5-capture', self.m5_capture)
            if self.extra:
                s('extra-stage', self.stage_extra, mutating=True)
            if self.cts:
                s('cts-stage', self.stage_cts, mutating=True)
            if self.baseline == 'fresh':
                # same conditions as the candidate job (writers held, nothing installed yet); only reboots happen
                s('base-preinstall', self.base_preinstall)
                s('base-freeze-manifest', self.base_freeze_manifest)
                s('base-freeze-entry', self.base_freeze_entry)
                s('base-submit', self.base_submit, mutating=True)
                s('base-job-wait', self.base_job_wait)
                if self.extra:
                    s('base-extra-results', lambda: self.extra_results(self.base_job_id, 'baseline'))
                s('base-verify-return', self.base_verify_return)
                s('base-locks', self.locks, mutating=True)
                self.ensure_lease()
                s('fresh-preinstall', self.fresh_preinstall)
            else:
                s('preinstall', self.write_preinstall)
            s('freeze-manifest', self.freeze_manifest)
            self.ensure_lease()
            self.tstep('esp-prep', inverse='esp-restore', mutating=True)
            self.tstep('install', inverse='rollback', followups=('esp-restore', 'etc-restore'), mutating=True,
                       verify=self.verify_install)
            if self.allow_bootbin:
                # boot.bin is the candidate from here: the guard goes in before anything reboots
                self.tstep('bootbin-guard-install', inverse='bootbin-guard-remove', mutating=True,
                           verify=self.verify_guard_install)
            s('freeze-entry', self.freeze_entry)
            s('native', self.stage_native, mutating=True)
            s('submit', self.submit, mutating=True)
            s('job-wait', self.job_wait)
            if self.extra:
                s('extra-results', lambda: self.extra_results(self.job_id, 'candidate'))
            if self.cts:
                s('cts-results', self.cts_results)
            s('verify-return', self.verify_return)
            if self.allow_bootbin:
                s('bootbin-guard-check', self.guard_check)
            s('locks-after-job', self.locks, mutating=True)
            self.ensure_lease()
            if self.allow_bootbin:
                self.tstep('bootbin-guard-remove', mutating=True, inverts='bootbin-guard-install')
            self.tstep('rollback', mutating=True, inverts='install')
            self.tstep('esp-restore', mutating=True, inverts='esp-prep')
            self.tstep('etc-restore', mutating=True, inverts='install')
            s('reboot', self.reboot_and_wait, mutating=True)
            if self.allow_bootbin:
                s('stage2-final', self.stage2_final)
            s('locks-after-reboot', self.locks, mutating=True)
            self.tstep('audit-held', 'audit', extra=('--held',), verify=self.verify_audit)
            self.tstep('release-writers', mutating=True, inverts='hold-writers')
            s('settle', lambda: self.snippet('settle', {'esp': self.prof['esp'], 'quiet': 15, 'max': 180}, 240))
            self.tstep('audit', verify=self.verify_audit)
            self.tstep('cleanup', mutating=True)
            s('m5-result', lambda: self.m5_result('run'))
            s('release-lease', self.release_lease)
        except BaseException as e:  # noqa: BLE001 - classify, journal, report; never retry
            return self._failed(e)
        passed = self.job.get('outcome') == 'pass'
        if self.allow_bootbin and passed and (getattr(self, 'guard_result', None) or {}).get('candidate_stage2_boots') != 1:
            self.j.note('guard', late_restore=getattr(self, 'guard_result', None))
            passed = False
        if self.extra and not passed:
            # bt2's own tests decide pass/fail; the benchmark (and the CTS test) are judged separately just below
            failed = [t.get('name') for t in (self.job.get('result') or {}).get('tests') or [] if not t.get('passed')]
            campaign = [EXTRA_TEST] + ([CTS_TEST] if self.cts else [])
            passed = (self.job.get('outcome') == 'tests_failed' and bool(failed) and len(set(failed)) == len(failed)
                      and set(failed) <= set(campaign))
        status = 'PASSED_RESTORED_LEASE_RELEASED' if passed else 'TESTS_FAILED_RESTORED_LEASE_RELEASED'
        if self.allow_bootbin and (getattr(self, 'guard_result', None) or {}).get('candidate_stage2_boots') != 1:
            status = 'GUARD_LATE_RESTORE_RESTORED_LEASE_RELEASED'   # the candidate stage 2 ran on a second boot
        if self.extra and passed and not all(
                (self.extra_outcome.get(arm) or {}).get('test_passed') is True
                and (self.extra_outcome.get(arm) or {}).get('status') == 'complete'
                and (self.extra_outcome.get(arm) or {}).get('binding_ok') is True for arm in ('baseline', 'candidate')):
            status, passed = 'PASSED_EXTRA_INCOMPLETE_RESTORED_LEASE_RELEASED', False   # never a silent pass
        cts_status = cts_verdict(self.cts_outcome) if self.cts else None
        if passed and cts_status not in (None, 'CTS_NO_FAILURES'):
            # eryk-cts is outside bt2's own tests, but its own bound result still decides: a CTS Fail/Crash/Timeout/
            # DeviceLost, a stopped run or an unbound result is never an overall pass
            status, passed = '%s_RESTORED_LEASE_RELEASED' % cts_status, False
        self.j.note('end', status=status, mutated=True, lease_released=True, outcome=self.job.get('outcome'))
        summary = {**self.summary('run'), 'status': status}
        if self.extra:
            summary['extra'] = {'test': EXTRA_TEST, 'script_sha256': self.extra_sha, 'inputs': self.extra_inputs,
                                'outcome': self.extra_outcome}
        if self.cts:
            summary['cts'] = {'test': CTS_TEST, 'script_sha256': self.cts_sha, 'input': self.cts_input,
                              'outcome': self.cts_outcome, 'status': cts_status}
        self.save_local('RESULT.json', canon(summary))
        self.emit(summary)
        return 0 if passed else 1

    def load_native(self):
        try:
            self.nsrc = native.load_sources(self.native_src)
        except (OSError, native.NativeError) as e:
            raise Refused('native test sources: %s' % e)
        self.tools = native.template_tools(self.nsrc['template'])
        return {'checker_sha256': H(self.nsrc['checker']), 'supervisor_sha256': H(self.nsrc['supervisor']),
                'template_sha256': H(self.nsrc['template'])}

    def _failed(self, e):
        plan = restore_plan(self.j.records)
        reason = '%s: %s' % (type(e).__name__, e)
        if not plan['mutated']:
            released = False
            if self.lease_acquired():
                try:
                    self.step('release-lease', self.release_lease)
                    released = True
                except Exception as e2:  # noqa: BLE001
                    self.log('lease release failed: %s' % e2)
            self.j.note('end', status='refused', mutated=False, lease_released=released, error=reason[:2000])
            out = {'status': 'REFUSED_NO_CHANGE', 'run_id': self.run_id, 'device': self.device, 'reason': reason,
                   'lease_released': released, 'run_dir': str(self.rd)}
            self.emit(out)
            return 3
        self.j.note('end', status='stopped', mutated=True, lease_released=False, error=reason[:2000])
        out = {'status': 'STOPPED_RESTORE_REQUIRED', 'run_id': self.run_id, 'device': self.device, 'reason': reason,
               'lease_retained_for_restore': True, 'restore_plan': plan, 'run_dir': str(self.rd),
               'next': 'python3 -m bt2.controller restore --run %s' % self.run_id}
        self.emit(out)
        self.log('STOPPED. Run: python3 -m bt2.controller restore --run %s' % self.run_id)
        return 4

    def _load(self, run_id):
        if not RUN_RE.match(run_id or ''):
            raise UsageError('bad run id')
        rd = self.state_root / run_id
        if not (rd / 'journal.jsonl').is_file():
            raise UsageError('no journal for run %s under %s' % (run_id, self.state_root))
        j = Journal(rd)
        h = j.header()
        if not h or h.get('schema') != SCHEMA_RUN:
            raise UsageError('journal header is not a bt2 run')
        prof = json.loads((rd / 'device.json').read_bytes())
        self._bind(run_id, rd, j, prof, h['holder'], h['mode'], h['remote_run_dir'])
        cfg = rd / 'config.json'
        self.cfg_raw = cfg.read_bytes() if cfg.is_file() else None
        self.cfg_sha = H(self.cfg_raw) if self.cfg_raw else None
        self.cfg = json.loads(self.cfg_raw) if self.cfg_raw else None
        self.allow_bootbin = bool(h.get('allow_bootbin_change')) or bool((self.cfg or {}).get('allow_bootbin_change'))
        jf = rd / 'job.json'
        self.job = json.loads(jf.read_bytes()) if jf.is_file() else {}
        self.baseline = h.get('baseline', 'stale')          # runs before 2026-10-27 had no fresh baseline
        if self.baseline == 'auto':                          # decided during the run (baseline-mode step)
            dec = [r for r in j.records if r.get('step') == 'baseline-mode' and r.get('event') == 'done']
            self.baseline = (dec[-1].get('summary') or {}).get('baseline', 'stale') if dec else 'stale'
        self.base_release = h.get('base_release')
        bf = rd / 'base' / 'job.json'
        self.base_job = json.loads(bf.read_bytes()) if bf.is_file() else {}
        return h

    def restore(self, run_id, retry=(), refresh_target=False):
        self._load(run_id)
        if not run_is_open(self.j.records):
            self.emit({'status': 'NOTHING_TO_RESTORE', 'run_id': run_id, 'end': last_end(self.j.records)})
            return 0
        plan = restore_plan(self.j.records)
        self.j.note('restore-start', plan=plan, retry=list(retry), refresh_target=bool(refresh_target))
        s = self.step
        try:
            blocked = [c for c in plan['blocked'] if c not in retry]
            if blocked:
                raise StepFailure('inverse step(s) %s previously failed after a change or have no recorded '
                                  'outcome; inspect %s/target and the Mac, then rerun restore with --retry %s'
                                  % (blocked, self.rd, ' --retry '.join(blocked)), changed=False)
            if plan['todo'] or plan['capture_done']:
                check(self.cfg_raw is not None, 'run has no config.json; cannot drive target inverses')
            s('restore-gate', self.restore_gate)
            s('restore-lease', lambda: {'expires': self.ensure_lease(LEASE_MIN)['expires']})
            if refresh_target:
                s('restore-refresh-target', self.refresh_target)
            if plan['mutated']:
                d = self.api.device(self.device)
                if not self.on_known_good(d):
                    s('restore-return', self.reboot_and_wait, mutating=True)
                s('restore-locks', self.locks, mutating=True)
                ran = False
                for c in plan['todo']:
                    if c == 'release-writers':
                        continue
                    self.tstep(c, mutating=True, restore=True)
                    ran = True
                if ran or plan['reboot_pending']:
                    s('restore-reboot', self.reboot_and_wait, mutating=True)
                    s('restore-locks-after-reboot', self.locks, mutating=True)
                held = 'release-writers' in plan['todo']
                if (self.cfg or {}).get('bootbin_guard'):
                    s('restore-stage2-final', self.stage2_final)
                if held and plan['capture_done']:
                    self.tstep('audit-held', 'audit', extra=('--held',), verify=self.verify_audit, restore=True)
                if held:
                    self.tstep('release-writers', mutating=True, restore=True)
                    s('restore-settle', lambda: self.snippet('settle', {'esp': self.prof['esp'], 'quiet': 15,
                                                                        'max': 180}, 240))
                if plan['capture_done']:
                    self.tstep('audit', verify=self.verify_audit, restore=True)
                    if not plan['cleanup_done']:
                        self.tstep('cleanup', mutating=True, restore=True)
            if plan['m5_root']:
                s('m5-result', lambda: self.m5_result('restore'))
            s('release-lease', self.release_lease)
        except BaseException as e:  # noqa: BLE001
            reason = '%s: %s' % (type(e).__name__, e)
            self.j.note('end', status='restore-stopped', mutated=True, lease_released=False, error=reason[:2000])
            self.emit({'status': 'RESTORE_STOPPED', 'run_id': run_id, 'reason': reason,
                       'plan': restore_plan(self.j.records), 'lease_retained_for_restore': True})
            return 4
        self.j.note('end', status='restored', mutated=True, lease_released=True)
        out = {**self.summary('restore'), 'status': 'RESTORED_LEASE_RELEASED'}
        self.save_local('RESULT.restore-%d.json' % len(self.j.records), canon(out))
        self.emit(out)
        return 0

    def refresh_target(self):
        k = 1 + sum(1 for r in self.j.records if r.get('step') == 'restore-refresh-target' and r.get('event') == 'done')
        srcs = sorted(self.target_dir.glob('*.py'))
        check(any(f.name == '__main__.py' for f in srcs), 'target package has no __main__.py')
        self.snippet('tdir-new', {'run_dir': self.rrun, 'k': k}, 60)
        files = {}
        for f in srcs:
            data = f.read_bytes()
            r = self.ops.push('%s/t.r%d/%s' % (self.rrun, k, f.name), data, 0o600)
            check(r['sha256'] == H(data), 'push readback %s' % f.name)
            files[f.name] = H(data)
        out = self.snippet('tdir-swap', {'run_dir': self.rrun, 'k': k, 'files': files}, 60)
        changed = sorted(n for n in set(files) | set(out['previous_files'])
                         if files.get(n) != out['previous_files'].get(n))
        return {'k': k, 'previous_dir': out['previous'], 'changed_files': changed, 'files': files,
                'previous_files': out['previous_files']}

    def restore_gate(self):
        d = self.api.device(self.device)
        check(d.get('alive') is True, 'Mac is not alive (state %r); it needs hands or time' % d.get('state'))
        check(not d.get('active_job'), 'labd job %s is still active on the Mac; wait for it' % d.get('active_job'))
        check(d.get('state') == 'ready', 'Mac state is %r, not ready; wait or recover it first' % d.get('state'))
        lease = d.get('lease')
        check(not lease or lease.get('holder') == self.holder, 'foreign lease %r' % (lease or {}).get('holder'))
        return {'boot_id': d.get('boot_id'), 'kernel': d.get('kernel'), 'state': d.get('state')}

    def status(self, run_id):
        h = self._load(run_id)
        st = step_states(self.j.records)
        steps = [{'step': k, 'state': v['state'], 'attempts': v['attempts'], 'inverse': v.get('inverse'),
                  'exit_code': v.get('exit_code'), 'error': (v.get('error') or '')[:300] or None}
                 for k, v in sorted(st.items(), key=lambda kv: kv[1]['intent_seq'])]
        plan = restore_plan(self.j.records)
        would = []
        if run_is_open(self.j.records):
            if plan['mutated']:
                would.append('reboot to the known-good default first if the Mac is not on the known-good untagged '
                             'boot; recreate boot locks')
                would += [c for c in plan['todo'] if c != 'release-writers']
                if any(c != 'release-writers' for c in plan['todo']) or plan['reboot_pending']:
                    would.append('ordinary reboot + wait (<= 6 min, known-good, untagged) + locks')
                if 'release-writers' in plan['todo'] and plan['capture_done']:
                    would.append('audit --held')
                if 'release-writers' in plan['todo']:
                    would.append('release-writers')
                if plan['capture_done']:
                    would.append('audit')
                    if not plan['cleanup_done']:
                        would.append('cleanup')
            would.append('release lease %s' % self.holder)
        out = {'run_id': run_id, 'device': h['device'], 'mode': h['mode'], 'holder': h['holder'],
               'release': h['release'], 'open': run_is_open(self.j.records), 'end': last_end(self.j.records),
               'steps': steps, 'restore_plan': plan, 'restore_would': would,
               'blocked_needs_retry': plan['blocked'], 'job': self.job.get('id'), 'outcome': self.job.get('outcome'),
               'baseline': self.baseline, 'base_job': self.base_job.get('id'),
               'base_outcome': self.base_job.get('outcome')}
        self.emit(out)
        return 0


# ------------------------------------------------------------------------------------- CLI
def recovery_card(device, run_id, ident, g, nbytes):
    esp_uuid = '%s (FAT serial %s, %s bytes, Linux %s)' % (ident.get('partition_uuid'), ident.get('fat_serial'),
                                                         ident.get('esp_bytes'), ident.get('linux_device'))
    return ('bt2 run %s on %s: candidate m1n1 stage 2 %s in m1n1/boot.bin until the guard or rollback restores it.\n'
            'If the Mac stops before Linux (logo or black screen, no network) on every power-on:\n'
            '  1. Hold the power button until "Loading startup options", choose Options -> macOS Recovery.\n'
            '  2. Utilities -> Terminal.  diskutil list   -> the 500 MB "EFI" partition of the Linux install;\n'
            '     confirm with diskutil info <diskXsY>: Disk / Partition UUID %s.\n'
            '  3. diskutil mount <that diskXsY>;  cd /Volumes/<its name>/m1n1\n'
            '  4. shasum -a 256 %s   must print %s (%d bytes)\n'
            '  5. cp %s boot.bin && sync && shasum -a 256 boot.bin   (must print the same hash)\n'
            '  6. Restart. Linux boots the original stage 2 %s; then: bt2 restore --run %s\n'
            % (run_id, device, g['candidate_stage2_version'], esp_uuid, g['recovery_copy'].split('/')[-1],
               g['original_sha256'], nbytes, g['recovery_copy'].split('/')[-1], g['original_stage2_version'], run_id))


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--state-root', default=str(DEFAULT_STATE_ROOT))
    common.add_argument('--frozen-root', default=None, help='labd frozen store (default ~/.local/share/maclab/frozen)')
    common.add_argument('--artifact-store', action='append', default=None,
                        help='durable package store root(s) <sha>/<file> (default ~/.local/share/maclab/boot-test/artifacts)')
    common.add_argument('--devices-dir', default=str(DEVICES_DIR))
    common.add_argument('--target-dir', default=str(TARGET_DIR))
    common.add_argument('--native-src', default=str(native.DEFAULT_SRC))
    p = argparse.ArgumentParser(prog='bt2', description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run', parents=[common])
    r.add_argument('--device', required=True)
    r.add_argument('--artifact', action='append', required=True, help='candidate package archive (repeatable)')
    r.add_argument('--mode', default='network-only', choices=MODES)
    r.add_argument('--holder', default=DEFAULT_HOLDER)
    r.add_argument('--run-id', default=None)
    r.add_argument('--extra-package', action='append', default=[],
                   help='extra local archive usable as original/kept package (not installed as a candidate)')
    r.add_argument('--approved-by', action='append', default=[])
    r.add_argument('--extra-test', default=None, help='campaign-local python runner added as the last script test of '
                   'both jobs (needs a fresh baseline)')
    r.add_argument('--extra-assets', default=None, help='JSON object of frozen asset paths/hashes for --extra-test')
    r.add_argument('--cts-test', default=None, help='campaign-local CTS script run after --extra-test in the candidate '
                   'job only, as its own test')
    r.add_argument('--cts-assets', default=None, help='JSON object: pinned CTS archive, case lists and deadlines')
    r.add_argument('--allow-bootbin-change', action='store_true',
                   help='allow the candidates (a stage 2 m1n1.bin and/or DTBs) to change m1n1/boot.bin, only to the '
                   'exact manifest-computed bytes; adds a Recovery copy on the ESP and the boot.bin guard unit')
    r.add_argument('--manifest', dest='manifest_mode', default='generate', choices=('generate', 'reuse'))
    r.add_argument('--baseline', default='auto', choices=BASELINE_MODES,
                   help='auto (default): fresh when the known-good kernel is packaged, else stale; '
                   'fresh: an installed-mode job of the Mac\'s original packages, run right before the '
                   'install, is the omarchy-m-test/kernel-error baseline; stale: byte copy of the device profile\'s '
                   'baseline_release preinstall (debugging only)')
    x = sub.add_parser('restore', parents=[common])
    x.add_argument('--run', required=True)
    x.add_argument('--retry', action='append', default=[], help='explicitly re-run an inverse whose earlier attempt '
                   'failed after a change or has no outcome')
    x.add_argument('--refresh-target', action='store_true', help='re-push the current target package into '
                   'the run (old one kept as t.prev-N, both hash sets journaled) before the inverses run')
    t = sub.add_parser('status', parents=[common])
    t.add_argument('--run', required=True)
    return p


def extra_script(runner, run_dir, expect):
    """labd script: write the runner into the test's output dir, check its sha256, run it on bt2's run dir with the
    exact input hash expected for each kernel release (the runner refuses any other input)."""
    digest = H(runner)
    b64 = base64.b64encode(runner).decode()
    return ('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n: "${MACLAB_OUT:?}"\n'
            'f="$MACLAB_OUT/eryk_bench.py"\n'
            "printf '%s' " + shlex.quote(b64) + ' | /usr/bin/base64 -d > "$f"\n'
            'test "$(/usr/bin/sha256sum "$f" | cut -d" " -f1)" = ' + digest + '\n'
            'export ERYK_BENCH_EXPECT=' + shlex.quote(json.dumps(expect, sort_keys=True)) + '\n'
            'exec /usr/bin/python3 -I "$f" ' + shlex.quote(run_dir) + '\n').encode()


CTS_ASSET_KEYS = {'archive', 'deqp_vk_sha256', 'data_manifest_sha256', 'lists'}


def cts_verdict(o):
    """The CTS test's own verdict from labd's result for eryk-cts and its bound summary:
    CTS_NO_FAILURES  every pinned case has a result, none of the failure class (Fail/Crash/Timeout/DeviceLost/
                     InternalError/ResourceError), and labd saw the test pass. NotSupported cases are SKIP, never
                     qualified; the summary carries them explicitly.
    CTS_FAILED       at least one failure-class result (also when the run then stopped)
    CTS_STOPPED      stopped (kernel fault/OOM line, interrupt, gate) with no failure-class result
    CTS_INCOMPLETE   missing, unbound or inconsistent result"""
    o = o or {}
    if o.get('binding_ok') is not True or not isinstance(o.get('failures'), int) or o.get('status') not in (
            'complete', 'stopped'):
        return 'CTS_INCOMPLETE'
    if o['failures'] > 0:
        return 'CTS_FAILED' if o.get('test_passed') is False else 'CTS_INCOMPLETE'
    if o['status'] == 'stopped':
        return 'CTS_STOPPED' if o.get('test_passed') is False else 'CTS_INCOMPLETE'
    return 'CTS_NO_FAILURES' if o.get('test_passed') is True else 'CTS_INCOMPLETE'


def load_cts(runner, doc):
    """Frozen CTS inputs for --cts-test: the archive and each case list are read now and must match their pins."""
    if not isinstance(doc, dict) or set(doc) != CTS_ASSET_KEYS or not isinstance(doc.get('lists'), list):
        raise UsageError('--cts-assets must be a JSON object with exactly %s' % sorted(CTS_ASSET_KEYS))

    def load(item, what):
        try:
            data = Path(item['path']).read_bytes()
        except (OSError, KeyError, TypeError) as e:
            raise UsageError('--cts-assets %s: %s' % (what, e))
        if H(data) != item.get('sha256'):
            raise UsageError('--cts-assets %s: sha256 differs from its pin' % what)
        return data

    for key in ('deqp_vk_sha256', 'data_manifest_sha256'):
        if not (isinstance(doc[key], str) and re.fullmatch(r'[0-9a-f]{64}', doc[key])):
            raise UsageError('--cts-assets %s must be a sha256' % key)
    archive = load(doc['archive'], 'archive')
    lists = []
    for item in doc['lists']:
        name = item.get('name') if isinstance(item, dict) else None
        dl = item.get('deadline_s') if isinstance(item, dict) else None
        if not (isinstance(name, str) and re.fullmatch(r'[a-z0-9-]{1,64}', name) and type(dl) is int and 0 < dl <= 900):
            raise UsageError('--cts-assets list entries need a name [a-z0-9-] and an int deadline_s in 1..900')
        data = load(item, 'list ' + name)
        cases = data.decode('ascii', 'replace').splitlines()
        if (cases != [c for c in cases if re.fullmatch(r'dEQP-VK(\.[A-Za-z0-9_]+)+', c)] or len(set(cases)) != len(cases)
                or len(cases) != item.get('cases')):
            raise UsageError('--cts-assets list %s: case names/count differ from its pin' % name)
        lists.append({'name': name, 'data': data, 'sha256': H(data), 'cases': len(cases), 'deadline_s': dl})
    if (not lists or len({l['name'] for l in lists}) != len(lists)
            or sum(l['deadline_s'] for l in lists) + CTS_SLACK > CTS_TIMEOUT):
        raise UsageError('--cts-assets lists: none, duplicate names, or deadlines that leave under %d s of the %d s '
                         'test budget' % (CTS_SLACK, CTS_TIMEOUT))
    return {'runner': runner, 'archive': archive, 'lists': lists, 'deqp_vk_sha256': doc['deqp_vk_sha256'],
            'data_manifest_sha256': doc['data_manifest_sha256'], 'assets_sha256': H(native.encode(doc))}


def cts_script(bench_lib, runner, cts_dir, expect):
    """labd script for the CTS test: write the reviewed benchmark runner (used only as a helper library) and the CTS
    script into the test's output dir, check both sha256, run the CTS script on bt2's <run>/cts with the exact input
    hash expected for the candidate kernel release."""
    out = '#!/usr/bin/env bash\nset -euo pipefail\numask 077\n: "${MACLAB_OUT:?}"\n'
    for fname, data in (('eryk_bench.py', bench_lib), ('eryk_cts.py', runner)):
        out += ("printf '%s' " + shlex.quote(base64.b64encode(data).decode()) + ' | /usr/bin/base64 -d > "$MACLAB_OUT/'
                + fname + '"\n' + 'test "$(/usr/bin/sha256sum "$MACLAB_OUT/' + fname + '" | cut -d" " -f1)" = '
                + H(data) + '\n')
    out += ('export ERYK_CTS_EXPECT=' + shlex.quote(json.dumps(expect, sort_keys=True)) + '\n'
            'export ERYK_CTS_LIB_SHA256=' + H(bench_lib) + '\n'
            'exec /usr/bin/python3 -I "$MACLAB_OUT/eryk_cts.py" ' + shlex.quote(cts_dir) + '\n')
    return out.encode()


def main(argv=None, api=None, **kw):
    a = build_parser().parse_args(argv)
    try:
        if api is None and a.cmd != 'status':
            api = labd.Labd()
        ctl = Controller(api, state_root=a.state_root, frozen_root=a.frozen_root, devices_dir=a.devices_dir,
                         target_dir=a.target_dir, native_src=a.native_src,
                         stores=a.artifact_store or (DEFAULT_STORE,), **kw)
        if a.cmd == 'run':
            return ctl.run(a.device, a.artifact, a.mode, a.holder, a.run_id, a.extra_package, a.approved_by,
                           a.manifest_mode, a.baseline, a.extra_test, a.extra_assets, a.cts_test, a.cts_assets,
                           a.allow_bootbin_change)
        if a.cmd == 'restore':
            return ctl.restore(a.run, a.retry, a.refresh_target)
        return ctl.status(a.run)
    except UsageError as e:
        print('bt2: usage: %s' % e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
