"""Exact reviewed official adapter + staged source closure + sealed private export.

No workload/schema/oracle is replaced. Public capability remains disabled until
root qualification. Only authenticated job-owned inputs can reach this module.
"""
from pathlib import Path
import hashlib, json, os, pwd, re, stat, subprocess, time, types
ADAPTER_SHA='ecadaa3a772c7ea2c5fce91e4563914fe33187e660e5b059cea60f761217f2cb'
SUPERVISOR_SHA='10e5805c5f8c6eaf3149f0d846813191a536c02b69d3cd6a609065f38339db0a'
GUARD_SHA='f65d169c599f08213632849090c75a8e6f4499ed85691baff2e21890821c0efe'
ARCHIVE_SHA='f209493b34e13e2985b1752c147a33a9a45e3e2eac99eb9606ae5a664c252f99'
COMMIT='e81d80938876c906b64c4e3f31f76c6c33ba95b1'
MAX_FILE=4*1024**2
MAX_EXPORT=32*1024**2
class Refuse(RuntimeError):pass
def need(v,why):
    if not v:raise Refuse(why)
def digest(data):return hashlib.sha256(data).hexdigest()
def metadata(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
def owned_parents(path):
    for p in [Path(path),*Path(path).parents]:
        st=p.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid in (0,os.geteuid()) and (not stat.S_IMODE(st.st_mode)&0o022 or st.st_uid==0 and st.st_mode&stat.S_ISVTX),'unsafe root artifact ancestry')
def read_owned(path,limit=MAX_FILE):
    path=Path(path);owned_parents(path.parent);held=fd=None
    try:
        held=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC);st=os.fstat(held)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and not stat.S_IMODE(st.st_mode)&0o022 and 0<=st.st_size<=limit,'artifact ownership/type/size')
        fd=os.open('/proc/self/fd/'+str(held),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC);need(metadata(os.fstat(fd))==metadata(st),'artifact reopen drift');parts=[];n=0;deadline=time.monotonic()+5
        while n<=st.st_size:
            need(time.monotonic()<=deadline,'artifact read deadline')
            b=os.read(fd,min(1<<20,st.st_size+1-n))
            if not b:break
            n+=len(b);parts.append(b)
        need(n==st.st_size and metadata(os.fstat(fd))==metadata(st)==metadata(path.lstat()),'artifact read/path drift');return b''.join(parts)
    finally:
        if fd is not None:os.close(fd)
        if held is not None:os.close(held)
def write_owned(path,data):
    path=Path(path);owned_parents(path.parent);need(len(data)<=MAX_FILE,'export file size')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        view=memoryview(data)
        while view:
            n=os.write(fd,view);need(n>0,'export short write');view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)
    need(read_owned(path)==data,'export readback');directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
def encoded(value):
    def special(x):
        if isinstance(x,bytes):return {'bytes_hex':x.hex()}
        if x.__class__.__name__=='RetiredEvent' and set(vars(x))=={'pid','birth','phase'}:return {'record_type':'RetiredEvent',**vars(x)}
        raise TypeError('unknown official evidence type')
    return (json.dumps(value,sort_keys=True,indent=2,default=special)+'\n').encode()
def module_bytes(name,raw):
    m=types.ModuleType(name);m.__file__='<verified:'+name+'>';exec(compile(raw,m.__file__,'exec'),m.__dict__);return m

def source_closure(plan,manifest):
    sources=plan.get('official_sources');need(isinstance(sources,dict) and set(sources)=={'adapter','integration','supervisor','guard','archive'},'official source closure missing')
    prefix=Path(manifest['prefix']);expected={'adapter':(prefix/'mesa_official.py',ADAPTER_SHA),'integration':(prefix/'mesa_official_integration.py',digest(read_owned(__file__))), 'supervisor':(prefix/'official/full-supervisor.py',SUPERVISOR_SHA),'guard':(prefix/'official/admission-supervisor.py',GUARD_SHA),'archive':(prefix/'official/archive.tar.gz',ARCHIVE_SHA)};raw={}
    need(manifest.get('official_archive')==sources['archive'],'manifest archive binding')
    for role,(path,want) in expected.items():
        pin=sources[role];need(pin=={'path':str(path),'sha256':want},'official source role/path/pin mismatch: '+role);body=read_owned(path)
        need(digest(body)==want,'official source bytes drift: '+role);raw[role]=body
    need(len(raw['archive'])==372821,'official archive size');return raw

def require_current(plan,adapter,prefix):
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['boot_id'],'official current boot mismatch')
    need(Path('/proc/sys/kernel/osrelease').read_text().strip()==plan['kernel'],'official current kernel mismatch')
    cmdline=Path('/proc/cmdline').read_bytes();need(digest(cmdline)==plan['cmdline_sha256'],'official current cmdline mismatch')
    need(('maclab.job='+plan['job']) in cmdline.decode().split(),'official current job mismatch')
    account=pwd.getpwnam(plan['gui_user']);need((account.pw_uid,account.pw_gid,account.pw_dir)==(plan['gui_uid'],plan['gui_gid'],plan['gui_home']),'official current GUI mismatch')
    raw=Path('/proc/device-tree/compatible').read_bytes();need(raw.endswith(b'\0') and raw[:-1].decode('ascii').split('\0')==plan['official_identity']['device']['compatible'],'official current board/SoC mismatch')
    adapter.recheck_official_identity(plan,prefix)

def configure(adapter,raw,plan,manifest,context):
    """Use pinned primitives with ACTIVE gates bound to this typed job.

    The old standalone validate/execute/report entrypoints are intentionally
    inaccessible: they encode a private M1/kernel6 allocation. Active schema,
    65 oracles/order, signature, cgroup, fault and health primitives stay intact.
    """
    def load(prefix=None):
        need(Path(prefix)==Path(manifest['prefix']),'official dependency prefix')
        source_closure(plan,manifest)
        full=module_bytes('job_full_supervisor',raw['supervisor']);guard=module_bytes('job_guard',raw['guard']);full.s=guard
        need(full.COMMIT==COMMIT and full.GUARD_SHA==GUARD_SHA and full.WALL==1800,'supervisor protocol pin')
        need(guard.ARCHIVE_SHA==ARCHIVE_SHA and guard.HELPER_SHA==adapter.HELPER_SHA and guard.SOURCE_SHA==adapter.SOURCE_SHA and {'gpu','dart'}<=set(guard.FAULTS),'guard protocol pin')
        guard.KERNEL=plan['kernel']  # Explicit admission parameter, not an oracle/workload change.
        health=guard.health_snapshot
        def typed_health(payload):require_current(plan,adapter,manifest['prefix']);return health(payload)
        guard.health_snapshot=typed_health
        def standalone_forbidden(*a,**kw):raise Refuse('private M1 standalone admission entrypoint is not a Mesa job')
        for name in ('validate','execute','validate_report'):setattr(full,name,standalone_forbidden)
        for name in ('validate_plan','execute','protected_state','smoke_result'):setattr(guard,name,standalone_forbidden)
        check=full.owner_check
        def owner(p,value,invocation=None):
            actual=check(p,value,invocation)
            if context.get('invocation') is not None:need(actual==context['invocation'],'official invocation drift')
            context['invocation']=actual
            if full.terminal_success(value):context['terminal']=dict(value)
            return actual
        full.owner_check=owner;context['supervisor']=full;return full
    adapter.load_pinned=load
    retain=adapter.retain_sample
    def observe_item(seen,item):retain(seen,item);context['seen']=seen
    adapter.retain_sample=observe_item
    observe=adapter.observe_until_exit
    def observed(*a,**kw):
        items,events,clean=observe(*a,**kw);context.update(items=items,completions=events,clean_exit=clean);return items,events,clean
    adapter.observe_until_exit=observed
    execute=adapter.execute
    def executing(bound):context['bound']=bound;return execute(bound)
    adapter.execute=executing

ROOT_LOGS=('unit-start.json','unit-before-stop.json','journal-final.jsonl','observer-final.json','child.stdout','child.stderr')
def validate_and_export(adapter,plan,manifest,out,result,context):
    need(isinstance(result,dict) and result.get('status')=='PASS' and result.get('native_invocations')==65 and result.get('signature_verified') is True and result.get('source_commit')==COMMIT and result.get('archive_sha256')==ARCHIVE_SHA,'unsealed official result')
    cleanup=result.get('cleanup',{});need(cleanup.get('stopped') is True and cleanup.get('control_group_empty') is True and not cleanup.get('not_created'),'official cleanup incomplete')
    bound=context['bound'];deadline=bound.get('cleanup_deadline');need(isinstance(deadline,(int,float)) and 0<deadline-time.monotonic()<=60,'official shared cleanup deadline missing/exhausted');paths=adapter.layout_paths(bound);logs=paths['logs'];need(Path(result['report_path'])==logs/'gpu-block1.json' and result.get('artifacts',{}).get('report')==str(logs/'gpu-block1.json') and result['artifacts'].get('journal_final')==str(logs/'journal-final.jsonl') and result['artifacts'].get('observer')==str(logs/'observer-final.json'),'official artifact paths mismatch')
    need(context.get('clean_exit') is True and len(context.get('items',[]))==65 and context.get('terminal'),'official observations/terminal missing')
    supervisor=context['supervisor'];p=adapter.unit_plan(bound);terminal=context['terminal'];supervisor.owner_check(p,terminal,context['invocation']);need(supervisor.terminal_success(terminal),'official terminal failure')
    before=json.loads(read_owned(logs/'unit-before-stop.json'));supervisor.owner_check(p,before,context['invocation']);need(supervisor.terminal_success(before),'official before-stop not successful')
    blob=read_owned(logs/'gpu-block1.json');need(digest(blob)==result['report_sha256'],'official report bytes mismatch');doc=json.loads(blob)
    archive=read_owned(Path(manifest['prefix'])/'official/archive.tar.gz');supervisor.s.verify_staged(archive,paths['payload_root']/'omarchy-m-test');gpu,schema,bundled=adapter.load_report_modules(paths['payload_root']/'omarchy-m-test')
    need(not schema.errors(json.loads(bundled.gpu_document_schema()),doc),'export report schema')
    loaderpins=[x for path,x in bound['graphics_before'].items() if Path(path).name.startswith('libvulkan.so')];loaders={x['sha256'] for x in loaderpins};runs=adapter.oracle_body(doc,plan,bound['staged_identity']['vulkan']['sha256'],loaders,gpu);adapter.require_order(supervisor,gpu,runs);adapter.require_order(supervisor,gpu,adapter.official_order_from_seen(context['items']))
    node=plan['official_identity']['device']['render_node'];adapter.check_completions(context['items'],context.get('completions',[]),True,{(node['major'],node['minor'])},bound['staged_identity']['vulkan'],loaderpins,node)
    observer=json.loads(read_owned(logs/'observer-final.json'));need(observer.get('cleanup')==cleanup and observer.get('journal_error') is None and observer.get('error') is None and observer.get('fault_categories')==[],'official observer failure');adapter.screen_journal(supervisor.s,plan['boot_id'],read_owned(logs/'journal-final.jsonl'))
    require_current(plan,adapter,manifest['prefix']);source_closure(plan,manifest)
    out=Path(out);owned_parents(out);dest=out/'official';dest.mkdir(mode=0o700);files={}
    def put(name,data):
        need(time.monotonic()<deadline,'official export deadline')
        need(sum(x['bytes'] for x in files.values())+len(data)<=MAX_EXPORT,'export total budget');write_owned(dest/name,data);files[name]={'sha256':digest(data),'bytes':len(data)}
    # Verify the original signature over precisely the report bytes being
    # copied. These public-only operations never read or generate a key.
    public=adapter.recheck_official_identity(plan,manifest['prefix'])['public_identity']
    need(deadline-time.monotonic()>=10,'official signature export budget')
    signature=supervisor.verify_signature(doc,public,dest);need(signature.get('cryptographic_verification') is True,'export signature')
    for name in ('signature.sshsig','allowed-signers'):
        data=read_owned(dest/name,16384);files[name]={'sha256':digest(data),'bytes':len(data)}
    put('report.json',blob)
    for name in ROOT_LOGS:put(name,read_owned(logs/name))
    put('unit-terminal.json',encoded(terminal));put('observations.json',encoded({'items':context['items'],'completions':context.get('completions',[]),'clean_exit':True}));put('identity.json',encoded(plan['official_identity']));put('source-closure.json',encoded(plan['official_sources']));put('cleanup.json',encoded(cleanup))
    # Pinned signature helper fsyncs files, but give BOTH detached files the
    # same independent typed reopen/fsync treatment as the rest of the export.
    for name in ('signature.sshsig','allowed-signers'):
        fd=os.open(dest/name,os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        need(digest(read_owned(dest/name,16384))==files[name]['sha256'],'signature artifact readback')
    receipt={'schema':1,'status':'PASS','job':plan['job'],'boot_id':plan['boot_id'],'kernel':plan['kernel'],'manifest_sha256':plan['manifest_sha256'],'source_commit':COMMIT,'archive_sha256':ARCHIVE_SHA,'native_invocations':65,'signature_verified':True,'report_sha256':digest(blob),'files':files}
    need(time.monotonic()<deadline,'official export deadline');sealed=encoded(receipt);write_owned(dest/'seal.json',sealed)
    return {'status':'PASS','native_invocations':65,'signature_verified':True,'report_sha256':digest(blob),'seal_sha256':digest(sealed),'source_commit':COMMIT,'archive_sha256':ARCHIVE_SHA,'report_path':'official/report.json','seal_path':'official/seal.json','cleanup':cleanup}

def failure_diagnostics(out,context,error):
    """Bounded root diagnostics only, never export an unverified report as PASS."""
    try:
        deadline=context.get('bound',{}).get('cleanup_deadline',time.monotonic()+5)
        need(time.monotonic()<deadline,'diagnostic deadline')
        directory=Path(out)/'official-failed';directory.mkdir(mode=0o700);write_owned(directory/'failure.json',encoded({'status':'FAILED_UNSEALED','error':type(error).__name__+': '+str(error)[:1000]}))
        bound=context.get('bound')
        if not bound:return
        logs=Path(bound['manifest']['prefix'])/'official/root'
        for name in ROOT_LOGS:
            need(time.monotonic()<deadline,'diagnostic deadline')
            if (logs/name).exists():write_owned(directory/name,read_owned(logs/name))
        if context.get('seen'):write_owned(directory/'partial-observations.json',encoded(list(context['seen'].values())))
    except BaseException:pass  # Original failure is authoritative; Go retains its own log.

def run_official(plan,manifest,output_dir,command_env,system_graphics_pins):
    context={}
    try:
        raw=source_closure(plan,manifest);adapter=module_bytes('staged_reviewed_mesa_official',raw['adapter']);configure(adapter,raw,plan,manifest,context);require_current(plan,adapter,manifest['prefix'])
        result=adapter.run_official(plan,manifest,output_dir,command_env,system_graphics_pins)
        return validate_and_export(adapter,plan,manifest,output_dir,result,context)
    except BaseException as error:failure_diagnostics(output_dir,context,error);raise
