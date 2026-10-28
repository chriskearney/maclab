#!/usr/bin/env python3
"""Generic native GL/VK in-job test for bt2 (controller side).

build_script(run_dir, sources) -> bytes of the labd Script test 'native-gl-vk'. The bytes depend only on the
remote run dir path and the sha-pinned reference components (supervisor/guardian, smoke-manifest template).
At job time the worker reads <run>/native-input.json (written by the controller before submit), builds the
checker manifest and runs the pinned checker r3 staged at <run>/native/checker.py with the reference guardian
semantics (subreaper, parent-abort, bounded drain). Exit 0 only on pass.

Cohort (r3): the candidate kernel release and the six Mesa provider pins (path, sha256, bytes) are computed by the
controller from the inspected candidate archives (cohort_pins) and EMBEDDED in the Script bytes, whose sha256 labd
pins in the job spec and the worker re-checks on disk. The worker requires native-input.json to carry exactly that
cohort, builds the checker manifest from it, and requires the checker to bind exactly it (bind_cohort). Before r3
these values were literals inside the checker, which locked bt2 to one kernel/Mesa build.

compute_input(...) -> native-input.json object from probe/preflight facts + candidate artifact inspections.
cohort_problems() lets the controller refuse BEFORE any mutation when the candidate archives cannot give a cohort
the checker accepts (a missing/odd provider, bad pin) or the lab tools differ from the checker's tool pins.
"""
import ast
import base64
import hashlib
import json
import os
import re
import types
from pathlib import Path

CHECKER_SHA = '134641c8db108429eed56441434d63e5ca1197fffd55e8343ede55cb67fc8950'
SUPERVISOR_SHA = 'c8b64cd52dd7e469af075e1c02f43aacdd97d8ec5661ce395948a92819d625a4'
TEMPLATE_SHA = 'dc2f091a4546b5562d7deea5ab3615543cde7e319ab25206b69daba09613504e'
# r3 (2026-10-26): r2 7fdae7d0 (b33eb239 + exit/exec /proc race fix) + cohort pins from the manifest (bind_cohort);
# supervisor and template unchanged from components/native. BT2_NATIVE_SRC overrides (tests).
DEFAULT_SRC = Path(os.environ.get('BT2_NATIVE_SRC') or Path(__file__).resolve().parent.parent / 'native-src')
SOURCE_FILES = {'checker': ('checker-r3.py', CHECKER_SHA),
                'supervisor': ('supervisor.py', SUPERVISOR_SHA),
                'template': ('smoke-manifest.template.json', TEMPLATE_SHA)}
RUN_DIR_RE = re.compile(r'^/var/lib/maclab/bt2/[a-z0-9][a-z0-9-]{3,80}$')
TEST_NAME = 'native-gl-vk'
TIMEOUT_SEC = 180
EGL_NOTE = 'unchanged wrapper; insufficient alone'
# role -> archive member (regex for gallium: its soname carries the Mesa version)
PROVIDER_MEMBERS = {
    'gallium': re.compile(r'usr/lib/libgallium-[^/]+\.so'),
    'egl': re.compile(re.escape('usr/lib/libEGL_mesa.so.0.0.0')),
    'vulkan': re.compile(re.escape('usr/lib/libvulkan_asahi.so')),
    'dril': re.compile(re.escape('usr/lib/dri/libdril_dri.so')),
    'glx': re.compile(re.escape('usr/lib/libGLX_mesa.so.0.0.0')),
    'gbm': re.compile(re.escape('usr/lib/libgbm.so.1.0.0')),
}
MAC_RE = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')


class NativeError(RuntimeError):
    pass


def H(b):
    return hashlib.sha256(b).hexdigest()


def encode(obj):
    return (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode()


def load_sources(src_dir=DEFAULT_SRC):
    """Read the sha-pinned reference components (read-only)."""
    out = {}
    for key, (name, sha) in SOURCE_FILES.items():
        raw = (Path(src_dir) / name).read_bytes()
        if H(raw) != sha:
            raise NativeError('native source %s sha %s != pinned %s' % (name, H(raw), sha))
        out[key] = raw
    return out


def template_tools(template_raw):
    return json.loads(template_raw)['tools']


# --------------------------------------------------------------------------------------------- worker
# Runs as root inside the labd job (python3 -E -c, child of the guardian). Generic: every device/cohort fact
# comes from <run>/native-input.json; the checker is executed unchanged and validates the manifest against
# its own pins.
WORKER = r'''"""bt2 generic native GL/VK job worker: unchanged checker, inputs from <run>/native-input.json."""
import contextlib,hashlib,io,json,os,re,secrets,signal,stat,sys,types,uuid
from pathlib import Path
PACKET='REQUIRED_PACKET'
CHECKER='134641c8db108429eed56441434d63e5ca1197fffd55e8343ede55cb67fc8950'
COHORT='REQUIRED_COHORT'
TEST='native-gl-vk'
UKI_LIMIT=67108864
RUN_RE=r'/var/lib/maclab/bt2/[a-z0-9][a-z0-9-]{3,80}'
HEX64=re.compile(r'[0-9a-f]{64}')
PROVIDER_KEYS=('gallium','egl','vulkan','dril','glx','gbm')
EGL_NOTE='unchanged wrapper; insufficient alone'
def need(v,msg):
    if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def unique(raw):
    def pairs(items):
        d={}
        for k,v in items:need(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs)
def identity(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
def regular(path,limit=1048576,virtual=False):
    path=Path(path);meta=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(meta);need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and st.st_size<=limit,'unsafe bounded root file '+str(path))
        fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            raw=os.pread(fd,(limit if virtual else st.st_size)+1,0)
            need(len(raw)<=limit and (virtual or len(raw)==st.st_size) and identity(os.fstat(fd))==identity(st)==identity(path.lstat()),'file identity drift '+str(path))
        finally:os.close(fd)
        return raw
    finally:os.close(meta)
def private_dir(path,exclusive=False):
    path=Path(path)
    if exclusive:path.mkdir(mode=0o700)
    st=path.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'root-owned nonwritable directory '+str(path));return path
def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        v=memoryview(raw)
        while v:
            n=os.write(fd,v);need(n>0,'short artifact write');v=v[n:]
        os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);need(regular(path,max(len(raw),1))==raw,'artifact readback')
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def module(raw,name):
    m=types.ModuleType(name);m.__file__=str(Path(PACKET)/'native'/name);exec(compile(raw,m.__file__,'exec'),m.__dict__);return m
def validate_input(inp):
    need(isinstance(inp,dict) and inp.get('schema')=='bt2.native-input/1','native input schema')
    need(inp.get('run_dir')==PACKET and inp.get('run_id')==Path(PACKET).name,'native input is bound to another run dir')
    need(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}',str(inp.get('device',''))) and re.fullmatch(r'apple,[a-z0-9]+',str(inp.get('board',''))),'explicit device/board')
    need(isinstance(inp.get('expected_kernel'),str) and re.fullmatch(r'[A-Za-z0-9._+-]{1,64}',inp['expected_kernel']),'explicit candidate kernel')
    gui=inp.get('gui') or {};need(isinstance(gui.get('uid'),int) and gui['uid']>0 and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',str(gui.get('user',''))),'explicit GUI user')
    wifi=inp.get('wifi') or {};need(re.fullmatch(r'[A-Za-z0-9._-]+',str(wifi.get('interface',''))) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',str(wifi.get('mac',''))),'explicit Wi-Fi')
    tools=inp.get('tools') or {};need(set(tools)=={'gl_pixels','vk_pixels'} and all(HEX64.fullmatch(str(t.get('sha256',''))) and str(t.get('path','')).startswith('/') for t in tools.values()),'explicit tools')
    prov=inp.get('providers') or {};need(set(prov)==set(PROVIDER_KEYS),'explicit provider roles')
    for p in prov.values():need(str(p.get('path','')).startswith('/usr/lib/') and '..' not in Path(p['path']).parts and HEX64.fullmatch(str(p.get('sha256',''))) and type(p.get('bytes')) is int and p['bytes']>0,'explicit provider pin')
    need(prov['egl'].get('note')==EGL_NOTE,'EGL note')
    toks=inp.get('entry_cmdline_tokens');need(isinstance(toks,list) and toks and all(isinstance(t,str) and t and ' ' not in t for t in toks),'frozen installer cmdline tokens')
    uki=inp.get('candidate_uki') or {};need(str(uki.get('path','')).startswith('/boot/efi/') and '..' not in Path(uki['path']).parts and HEX64.fullmatch(str(uki.get('sha256',''))),'frozen candidate UKI')
    need(HEX64.fullmatch(str(inp.get('script_sha256',''))),'script pin')
    need(inp.get('checker_sha256')==CHECKER,'checker pin')
    need(inp['expected_kernel']==COHORT['expected_kernel'] and {r:{k:p.get(k) for k in ('path','sha256','bytes')} for r,p in prov.items()}==COHORT['providers'] and inp.get('cohort_sha256')==H(encoded(COHORT)),'native input cohort differs from the cohort compiled into this Script')
    need(inp.get('recovery_mode') in ('network-only','serial-assisted'),'explicit recovery mode')
    return inp
def job_identity(env,cmdline,boot,kernel,machine,board,inp):
    job=env.get('MACLAB_JOB','');need(re.fullmatch(r'j[0-9]{4}-[0-9]{6}-[a-f0-9]{4}',job),'actual MACLAB_JOB required')
    tags=[t.split('=',1)[1] for t in cmdline.split() if t.startswith('maclab.job=')];need(tags==[job] and env.get('MACLAB_TEST')==TEST,'exact single current job tag/test')
    need(kernel==inp['expected_kernel'] and machine=='aarch64' and board==inp['board'] and str(uuid.UUID(boot))==boot,'actual candidate boot identity');return job
def installed_cmdline(actual,base,job):
    # labd's installed.Additions, followed by agent.withLabBootParams (0.8).
    # Keep the frozen prefix exact; accept only the agent's missing parameters,
    # appended once in its order. Legacy agents append neither parameter.
    normal=base+['maclab.job='+job,'panic=10']
    serial=normal+['console=ttySAC0,115200','console=tty0','loglevel=7']
    for want,is_serial in ((normal,False),(serial,True)):
        if actual==want:
            return is_serial
        if actual[:len(want)]!=want:
            continue
        names={t.split('=',1)[0] for t in want}
        extra=actual[len(want):]
        if 'watchdog.open_timeout' not in names:
            if not extra or re.fullmatch(r'watchdog\.open_timeout=[0-9]+',extra[0]) is None:
                continue
            extra=extra[1:]
        if 'maclab.lab_boot' not in names:
            if not extra or extra[0]!='maclab.lab_boot=1':
                continue
            extra=extra[1:]
        if not extra:
            return is_serial
    need(False,'actual job cmdline differs from frozen installer plus exact lab additions')
def checker_manifest(template_raw,inp,board,boot,token):
    m=unique(template_raw)
    m.update(approved=True,source_review='accepted-by-root',device=inp['device'],board=board,expected_kernel=inp['expected_kernel'],expected_boot_id=boot,token=token,gui_user=inp['gui']['user'],gui_uid=inp['gui']['uid'],wifi_interface=inp['wifi']['interface'],wifi_mac=inp['wifi']['mac'],output_dir='/var/tmp/sf-rc-normal-session-'+token[:16],tools=json.loads(json.dumps(inp['tools'])),providers=json.loads(json.dumps(inp['providers'])))
    return m
def run_checker(w,mp,m,evidence,job,boot,run_id,live_check):
    stdout=io.StringIO();failure=None;retained={}
    try:
        with contextlib.redirect_stdout(stdout):w.run(mp)
    except BaseException as e:failure=type(e).__name__+': '+str(e)
    try:
        write(evidence/'checker-stdout.txt',stdout.getvalue().encode());source=Path(m['output_dir'])
        for name in ('before.json','after.json','GL.json','VK.json','complete.json','stopped.json'):
            path=source/name
            if os.path.lexists(path):raw=regular(path,1048576);write(evidence/name,raw);retained[name]={'sha256':H(raw),'bytes':len(raw)}
        if failure is None:
            need(set(retained)=={'before.json','after.json','GL.json','VK.json','complete.json'},'missing or stopped checker artifacts')
            complete=unique(regular(evidence/'complete.json'));need(complete['status']=='pass','checker did not pass')
            for api in ('GL','VK'):
                rec=unique(regular(evidence/(api+'.json')));need(rec['status']=='pass' and rec['metrics']['wrong_pixels']==0 and rec['owned_processes_remaining']==[] and not w.group(rec['owned_pgid']),'native oracle or owned-process drain');w.parse_pixels(rec['output'])
            live_check()
    except BaseException as e:
        if failure is None:failure=type(e).__name__+': '+str(e)
    result={'schema':'bt2.native-result/1','status':'pass' if failure is None else 'failed','job':job,'boot_id':boot,'run_id':run_id,'checker_sha256':CHECKER,'artifacts':retained,'failure':failure,'job_graphics_compatibility_only':True,'ordinary_login_qualification':False}
    write(evidence/'result.json',encoded(result));print(json.dumps({'schema':'bt2.native-status/1','status':result['status'],'failure':failure,'evidence':'native-evidence/result.json'}))
    if failure is not None:raise RuntimeError(failure)
    return result
def main():
    need(os.geteuid()==0,'root Script test required');P=Path(PACKET);need(P.is_absolute() and re.fullmatch(RUN_RE,PACKET),'compiled bt2 run dir')
    for parent in (P,*P.parents):private_dir(parent)
    inpraw=regular(P/'native-input.json');inp=validate_input(unique(inpraw))
    boot=regular('/proc/sys/kernel/random/boot_id',128,True).decode().strip();cmdline=regular('/proc/cmdline',32768,True).decode().strip();board=regular('/proc/device-tree/compatible',4096,True).split(b'\0')[0].decode()
    job=job_identity(os.environ,cmdline,boot,os.uname().release,os.uname().machine,board,inp)
    out=Path(os.environ.get('MACLAB_OUT',''));need(out.is_absolute() and str(out)==os.environ.get('MACLAB_OUT') and '..' not in out.parts and out.parent.name=='out' and 1<=len(out.name)<=128,'actual agent command-output tree');private_dir(out);private_dir(out.parent);evidence=private_dir(out/'native-evidence',True)
    script=Path(os.environ.get('MACLAB_NATIVE_SCRIPT',''));need(script.is_absolute() and script.name=='test-native-gl-vk.sh' and script.parent.name==job and script.parent.parent.name=='jobs' and script.parent.parent.parent==out.parent.parent and H(regular(script,4194304))==inp['script_sha256'],'actual static Script artifact')
    checker_raw=regular(P/'native'/'checker.py',1048576);need(H(checker_raw)==CHECKER and H(_TEMPLATE_SOURCE)==_TEMPLATE_SHA256,'fixed source closure');w=module(checker_raw,'normal_checker')
    serial_tokens=installed_cmdline(cmdline.split(),list(inp['entry_cmdline_tokens']),job)
    uki=regular(inp['candidate_uki']['path'],UKI_LIMIT);need(H(uki)==inp['candidate_uki']['sha256'],'actual candidate UKI differs from frozen entry')
    token=secrets.token_hex(32);m=checker_manifest(_TEMPLATE_SOURCE,inp,board,boot,token);w.frozen_manifest(m)
    need(w.KERNEL==COHORT['expected_kernel'] and w.PROVIDERS==COHORT['providers'],'checker bound a cohort other than the compiled one')
    for pin in w.TOOLS.values():need(H(regular(pin['path'],67108864))==pin['sha256'],'frozen readback tool')
    for pin in w.PROVIDERS.values():raw=regular(pin['path'],pin['bytes']);need(len(raw)==pin['bytes'] and H(raw)==pin['sha256'],'installed native provider')
    mp=evidence/'manifest.json';write(mp,encoded(m));write(evidence/'native-input.json',inpraw)
    write(evidence/'preflight.json',encoded({'job':job,'boot_id':boot,'kernel':os.uname().release,'board':board,'run_id':inp['run_id'],'device':inp['device'],'uki_sha256':H(uki),'checker_sha256':CHECKER,'cohort_sha256':H(encoded(COHORT)),'recovery_mode':inp['recovery_mode'],'serial_cmdline_additions_observed':serial_tokens,'job_graphics_compatibility_only':True,'ordinary_login_qualification':False,'physical_recovery_readiness_confirmed':False}))
    def same_job():need(regular('/proc/sys/kernel/random/boot_id',128,True).decode().strip()==boot and job_identity(os.environ,regular('/proc/cmdline',32768,True).decode(),boot,os.uname().release,os.uname().machine,board,inp)==job,'job boot changed during work')
    run_checker(w,mp,m,evidence,job,boot,inp['run_id'],same_job)
if __name__=='__main__':
    def interrupted(*args):raise RuntimeError('termination requested')
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    main()
'''


def worker_source(run_dir, sources, cohort):
    """The worker Python source for one run dir and cohort (template + cohort embedded; deterministic)."""
    if not RUN_DIR_RE.match(run_dir):
        raise NativeError('run dir must be /var/lib/maclab/bt2/<run-id>')
    assert WORKER.count("PACKET='REQUIRED_PACKET'") == 1 and WORKER.count("COHORT='REQUIRED_COHORT'") == 1
    canon = canonical_cohort(cohort, sources['checker'])
    template = sources['template']
    src = ('import base64\n_TEMPLATE_SOURCE=base64.b64decode(' + repr(base64.b64encode(template).decode()) + ')\n'
           '_TEMPLATE_SHA256=' + repr(H(template)) + '\n' +
           WORKER.replace("PACKET='REQUIRED_PACKET'", 'PACKET=' + repr(run_dir))
                 .replace("COHORT='REQUIRED_COHORT'", 'COHORT=json.loads(' + repr(json.dumps(canon, sort_keys=True)) + ')'))
    ast.parse(src)
    return src


def build_script(run_dir, sources, cohort):
    """bash -> guardian (unchanged supervisor.py) -> worker; same shape as the reference compile.py."""
    worker = worker_source(run_dir, sources, cohort)
    guardian = sources['supervisor'].decode()
    guard = ('import base64\n' + guardian + '\n_WORKER_SOURCE=base64.b64decode(' +
             repr(base64.b64encode(worker.encode()).decode()) + ').decode()\n'
             'sys.exit(run(_WORKER_SOURCE,int(sys.argv[1]),Path(os.environ["MACLAB_OUT"])))\n')
    ast.parse(guard)
    if '\nMACLAB_NATIVE_PYTHON\n' in '\n' + guard + '\n':
        raise NativeError('heredoc delimiter collision')
    return ("#!/usr/bin/env bash\nset -euo pipefail\nexport MACLAB_NATIVE_SCRIPT=\"$0\"\n"
            "/usr/bin/python3 -E - \"$$\" <<'MACLAB_NATIVE_PYTHON'\n" + guard +
            "\nMACLAB_NATIVE_PYTHON\nstatus=$?\nexit \"$status\"\n").encode()


def test_spec(script_sha):
    return {'name': TEST_NAME, 'script': script_sha, 'timeout_sec': TIMEOUT_SEC}


# --------------------------------------------------------------------------------------------- inputs
def providers_from(inspections, fallback=()):
    """Provider pins from the candidate archives (fallback: archives of the packages that stay installed)."""
    out = {}
    for role, pat in PROVIDER_MEMBERS.items():
        hits = []
        for group in (inspections, fallback):
            hits = [(i, n, r) for i in group for n, r in sorted(i['members'].items())
                    if r['type'] == 'f' and pat.fullmatch(n)]
            if hits:
                break
        if len(hits) != 1:
            raise NativeError('provider %s: expected exactly one regular file in the packages, found %d'
                              % (role, len(hits)))
        i, n, r = hits[0]
        out[role] = {'path': '/' + n, 'sha256': r['sha256'], 'bytes': r['size'], 'package': i['pkginfo']['pkgname'],
                     'package_version': i['pkginfo']['pkgver']}
    out['egl']['note'] = EGL_NOTE
    return out


def pick_wifi(facts):
    rows = [w for w in facts.get('wifi') or [] if w.get('wireless')]
    if len(rows) != 1:
        raise NativeError('need exactly one wireless interface on the Mac, found %r' % [w.get('interface') for w in rows])
    w = rows[0]
    if not re.fullmatch(r'[A-Za-z0-9._-]+', str(w.get('interface', ''))) or not MAC_RE.match(str(w.get('mac', ''))):
        raise NativeError('wireless interface identity is not explicit: %r' % w)
    return {'interface': w['interface'], 'mac': w['mac']}


def compute_input(*, run_id, run_dir, profile, facts, inspections, manifest, entry, script_sha256, mode, tools,
                  cohort, fallback_inspections=()):
    """native-input.json (schema bt2.native-input/1). facts = controller probe / preflight facts. cohort = the one
    compiled into the Script (cohort_pins); the providers/kernel recomputed here must be exactly it."""
    if not RUN_DIR_RE.match(run_dir) or run_dir.rsplit('/', 1)[1] != run_id:
        raise NativeError('run dir / run id mismatch')
    krel = manifest['kernel']['release']
    providers = providers_from(inspections, fallback_inspections)
    if krel != cohort['expected_kernel'] or {r: {k: p[k] for k in ('path', 'sha256', 'bytes')}
                                             for r, p in providers.items()} != cohort['providers']:
        raise NativeError('candidate kernel/providers differ from the cohort compiled into the Script')
    sections = entry.get('uki_sections') or {}
    if entry.get('found') is not True or (sections.get('.uname', {}).get('text') not in (None, krel)):
        raise NativeError('frozen installer entry is not the candidate kernel entry')
    toks = entry.get('cmdline_tokens')
    if not isinstance(toks, list) or not toks:
        raise NativeError('frozen installer entry has no cmdline tokens')
    uki_file = entry.get('uki_file')
    if not isinstance(uki_file, str) or not uki_file.startswith('/boot/efi/'):
        raise NativeError('frozen installer entry UKI path is not under /boot/efi')
    gui = facts.get('gui') or {}
    if gui.get('uid') != profile['gui_uid'] or gui.get('user') != profile['gui_user']:
        raise NativeError('GUI user on the Mac %r differs from the device profile' % gui)
    return {
        'schema': 'bt2.native-input/1', 'run_id': run_id, 'run_dir': run_dir, 'device': profile['name'],
        'board': profile['board'], 'recovery_mode': mode, 'release': manifest['release'],
        'expected_kernel': krel, 'vmlinuz_sha256': manifest['kernel']['vmlinuz_sha256'],
        'gui': {'user': profile['gui_user'], 'uid': profile['gui_uid']},
        'wifi': pick_wifi(facts),
        'tools': json.loads(json.dumps(tools)),
        'providers': providers, 'cohort_sha256': H(encode(cohort)),
        'entry_cmdline_tokens': list(toks), 'entry_path': entry.get('path'), 'entry_sha256': entry.get('entry_sha256'),
        'candidate_uki': {'path': uki_file, 'sha256': entry.get('uki_sha256')},
        'script_sha256': script_sha256, 'checker_sha256': CHECKER_SHA,
    }


# --------------------------------------------------------------------------------------------- cohort gate
_MODULES = {}


def checker_module(checker_raw):
    """The checker's own definitions (exec'd once per sha, never run): its validate_cohort and TOOLS are the rules."""
    sha = H(checker_raw)
    if sha not in _MODULES:
        m = types.ModuleType('bt2_native_checker_' + sha[:12])
        m.__file__ = 'native-checker-' + sha[:12]
        exec(compile(checker_raw, m.__file__, 'exec'), m.__dict__)
        if not callable(getattr(m, 'validate_cohort', None)) or not isinstance(getattr(m, 'TOOLS', None), dict):
            raise NativeError('checker %s has no validate_cohort/TOOLS (cohort-locked checker?)' % sha[:12])
        _MODULES[sha] = m
    return _MODULES[sha]


def cohort_pins(expected_kernel, providers, checker_raw):
    """Canonical cohort {expected_kernel, providers{role: path, sha256, bytes}} validated by the checker itself."""
    try:
        kernel, pins = checker_module(checker_raw).validate_cohort(expected_kernel, providers)
    except ValueError as e:
        raise NativeError('cohort refused by checker %s: %s' % (H(checker_raw)[:8], e))
    return {'expected_kernel': kernel, 'providers': pins}


def canonical_cohort(cohort, checker_raw):
    if not isinstance(cohort, dict) or set(cohort) != {'expected_kernel', 'providers'}:
        raise NativeError('cohort must be {expected_kernel, providers}')
    canon = cohort_pins(cohort['expected_kernel'], cohort['providers'], checker_raw)
    if canon != cohort:
        raise NativeError('cohort is not canonical (extra provider keys?)')
    return canon


def checker_pins(checker_raw):
    """The checker's module-level literal pins: since r3 only the REFERENCE cohort (template/tests) + tool pins."""
    tree = ast.parse(checker_raw)
    env = {}

    def ev(n):
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            return env[n.id]
        if isinstance(n, ast.Dict):
            if any(k is None for k in n.keys):
                raise ValueError('dict unpack')
            return {ev(k): ev(v) for k, v in zip(n.keys, n.values)}
        if isinstance(n, (ast.List, ast.Tuple)):
            return [ev(x) for x in n.elts]
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Pow, ast.Mult)):
            a, b = ev(n.left), ev(n.right)
            return a ** b if isinstance(n.op, ast.Pow) else a * b
        raise ValueError('not a literal')

    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                env[node.targets[0].id] = ev(node.value)
            except (ValueError, KeyError, TypeError):
                pass
    return {'kernel': env['KERNEL'], 'providers': env['PROVIDERS'], 'tools': env['TOOLS']}


def cohort_problems(expected_kernel, providers, tools, checker_raw):
    """Why the checker would reject this cohort (empty list = it can pass). Checked BEFORE any mutation."""
    out = []
    try:
        cohort_pins(expected_kernel, providers, checker_raw)
    except NativeError as e:
        out.append(str(e))
    if tools != checker_module(checker_raw).TOOLS:
        out.append('tool pins differ from the checker')
    return out
