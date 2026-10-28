#!/usr/bin/env python3
"""Private exact seven-workload qualification; no operation without explicit flag.

The immutable tiny guard provides proved protected-state, journal, health and
archive primitives. One transient systemd control group owns ALL CLI descendants.
"""
import argparse,copy,hashlib,importlib.util,io,json,os,random,re,selectors,shutil,signal,stat,subprocess,sys,tarfile,time
from pathlib import Path
sys.dont_write_bytecode=True
GUARD_SHA='f65d169c599f08213632849090c75a8e6f4499ed85691baff2e21890821c0efe'
COMMIT='e81d80938876c906b64c4e3f31f76c6c33ba95b1'
WALL=1800
NAMESPACE='omarchy-m-test-gpu-benchmark'
s=None

def load_guard(path):
 global s
 if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=GUARD_SHA:raise SystemExit('guard-source-pin')
 spec=importlib.util.spec_from_file_location('reviewed_guard',path);s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)

def validate(p):
 s.need(isinstance(p,dict),'full-plan-object')
 s.need(p.get('allocation')=={'device':'m1','holder':'official-gpu-mbp-63a085f4','scope':'full-seven-workloads-only','maintenance_fence':'closed'},'full-allocation')
 s.need(re.fullmatch('/var/tmp/sf-official-gpu-full-[0-9a-f]{16}',p.get('prefix','')),'full-prefix')
 # Apply unchanged structural/protection validator; only authorize the two explicit scope differences above.
 shape=copy.deepcopy(p);shape['allocation']['scope']='tiny-smoke-only';shape['prefix']=p['prefix'].replace('gpu-full-','gpu-smoke-');s.validate_plan(shape)
 s.need(p['gui_uid']==p['gui_gid']==1000 and p['normal_state_paths']==['/home/chrisk/.local/state/omarchy-m-test'],'actual-signing-state')
 return p

def unit_name(p):return 'sf-official-gpu-full-'+p['prefix'].rsplit('-',1)[1]+'.service'

def signing_identity(p):
 directory=Path(p['normal_state_paths'][0]);key=directory/'machine-key';pub=directory/'machine-key.pub'
 for path,mode,directory_kind in ((directory,0o700,True),(key,0o600,False)):
  st=path.lstat();s.need(not path.is_symlink() and st.st_uid==p['gui_uid'] and st.st_gid==p['gui_gid'] and stat.S_IMODE(st.st_mode)==mode,'existing-signing-modes')
  s.need(stat.S_ISDIR(st.st_mode) if directory_kind else stat.S_ISREG(st.st_mode),'existing-signing-type')
 st=pub.lstat();s.need(stat.S_ISREG(st.st_mode) and not pub.is_symlink() and st.st_uid==p['gui_uid'] and st.st_size<=16384,'existing-public-key')
 value=' '.join(pub.read_text().split()[:2]);s.need(re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{40,100}={0,2}',value),'existing-public-key-format')
 return value

def stage(p,archive):
 data=s.inspect_archive(archive);prefix=Path(p['prefix']);s.need(not prefix.exists() and not prefix.is_symlink(),'full-prefix-preexists')
 prefix.mkdir(mode=0o755);os.chmod(prefix,0o755);os.chown(prefix,0,0)
 logs=prefix/'root';logs.mkdir(mode=0o700);os.chmod(logs,0o700);s.private_write(logs/'owner.json',{'prefix':str(prefix),'scope':'full-seven-workloads-only','source_commit':COMMIT})
 payload=prefix/'payload';payload.mkdir(mode=0o755);os.chmod(payload,0o755)
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
  for m in t.getmembers():
   path=payload/m.name
   if m.isdir():path.mkdir(parents=True,exist_ok=True)
   else:
    path.parent.mkdir(parents=True,exist_ok=True)
    with t.extractfile(m) as src,path.open('xb') as dst:shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())
    os.chmod(path,m.mode)
 for f in [payload,*payload.rglob('*')]:
  os.chown(f,0,0)
  if f.is_dir():os.chmod(f,0o755)
 run=prefix/'run';run.mkdir(mode=0o700);os.chown(run,p['gui_uid'],p['gui_gid']);os.chmod(run,0o700)
 for name in ('home','tmp','state','cache','config','data','reports'):
  path=run/name;path.mkdir(mode=0o700);os.chown(path,p['gui_uid'],p['gui_gid']);os.chmod(path,0o700)
 s.verify_staged(data,payload/'omarchy-m-test')
 return prefix,payload/'omarchy-m-test',data

def command(p,payload):
 run=Path(p['prefix'])/'run'
 env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1','HOME':str(run/'home'),'TMPDIR':str(run/'tmp'),
      'XDG_STATE_HOME':'/home/chrisk/.local/state','XDG_CACHE_HOME':str(run/'cache'),'XDG_CONFIG_HOME':str(run/'config'),'XDG_DATA_HOME':str(run/'data')}
 cli=['/usr/bin/python3','-B',str(payload/'bin/omarchy-m-test'),'--gpu-benchmark','--accept-gpu-risk','--benchmark-seed','42','--benchmark-block','1','--benchmark-repetitions','7','--output',str(run/'reports/gpu-block1.json')]
 unit=unit_name(p)
 return ['systemd-run','--quiet','--unit='+unit,'--property=Type=exec','--property=Description='+owner_description(p),'--property=RemainAfterExit=yes','--property=User='+str(p['gui_uid']),
         '--property=Group='+str(p['gui_gid']),'--property=KillMode=control-group','--property=SendSIGKILL=yes','--property=TimeoutStopSec=5s',
         '--property=RuntimeMaxSec=1800s','--property=LimitFSIZE=4194304','--property=UMask=0077','--property=StandardOutput=append:'+str(run.parent/'root/child.stdout'),
         '--property=StandardError=append:'+str(run.parent/'root/child.stderr'),'/usr/bin/env','-i',*[k+'='+v for k,v in env.items()],*cli]

def owner_description(p):return 'official-gpu:'+COMMIT+':'+p['prefix'].rsplit('-',1)[1]

PROPERTIES=('Description','LimitFSIZE','LoadState','ActiveState','SubState','Transient','User','Group','Type','RemainAfterExit','KillMode','SendSIGKILL','TimeoutStopUSec','RuntimeMaxUSec','UMask','MainPID','ControlGroup','InvocationID','Result','ExecMainCode','ExecMainStatus')
def unit_state(unit):
 raw=s.capture(['systemctl','show',unit,*['--property='+x for x in PROPERTIES]],timeout=5)
 lines=raw.decode().splitlines();s.need(len(lines)<=64,'unit-property-budget');v=dict(line.split('=',1) for line in lines)
 s.need(set(v)==set(PROPERTIES),'unit-properties');return v

def owner_check(p,v,invocation=None):
 required={'Description':owner_description(p),'LimitFSIZE':'4194304','LoadState':'loaded','Transient':'yes','User':str(p['gui_uid']),'Group':str(p['gui_gid']),'Type':'exec','RemainAfterExit':'yes','KillMode':'control-group','SendSIGKILL':'yes','TimeoutStopUSec':'5s','RuntimeMaxUSec':'30min','UMask':'0077'}
 s.need(all(v.get(k)==value for k,value in required.items()),'transient-unit-contract')
 expected='/system.slice/'+unit_name(p)
 terminal=v.get('ControlGroup')=='' and invocation is not None and v.get('ActiveState')=='active' and v.get('SubState')=='exited' and v.get('MainPID')=='0' and v.get('ExecMainCode')=='1' and v.get('ExecMainStatus')=='0' and v.get('Result')=='success'
 s.need(v.get('ControlGroup')==expected or terminal,'unit-cgroup-owner')
 s.need(re.fullmatch('[0-9a-f]{32}',v.get('InvocationID','')),'unit-invocation')
 if invocation:s.need(v['InvocationID']==invocation,'unit-invocation-drift')
 return v['InvocationID']

def members(cgroup):
 s.need(re.fullmatch('/system.slice/sf-official-gpu-full-[0-9a-f]{16}\\.service',cgroup),'cgroup-path')
 root=Path('/sys/fs/cgroup'+cgroup);s.need(root.is_dir() and not root.is_symlink(),'cgroup-missing')
 files=[root/'cgroup.procs',*root.glob('*/cgroup.procs')];s.need(len(files)<=16,'cgroup-child-budget');ids=[]
 for f in files:
  text=f.read_text();s.need(len(text)<=32768,'cgroup-members-budget');ids.extend(text.split())
 s.need(len(ids)<=256 and all(x.isdecimal() for x in ids),'cgroup-members-types');result=[]
 for x in set(ids):
  try:
   f=(Path('/proc')/x/'stat').read_text().rsplit(')',1)[1].split()
   if f[0]!='Z':result.append((int(x),f[19]))
  except FileNotFoundError:continue
 return result

def terminal_success(v):
 return v.get('ActiveState')=='active' and v.get('SubState')=='exited' and v.get('MainPID')=='0' and v.get('ExecMainCode')=='1' and v.get('ExecMainStatus')=='0' and v.get('Result')=='success'

def owned_members(p,v,invocation):
 """Refresh a raced membership observation; missing alone NEVER means success.

 v is refreshed in-place only after independently confirmed terminal success.
 The outer observer then records this actual unit state before owned cleanup.
 """
 owner_check(p,v,invocation);expected='/system.slice/'+unit_name(p);path=Path('/sys/fs/cgroup'+expected)
 if v['ControlGroup']:
  try:return members(expected)
  except (s.Stop,FileNotFoundError) as error:
   if isinstance(error,s.Stop) and str(error)!='cgroup-missing':raise
   s.need(not path.exists(),'cgroup-read-failed-with-existing-path')
   fresh=unit_state(unit_name(p));owner_check(p,fresh,invocation)
   s.need(terminal_success(fresh),'missing-cgroup-without-terminal-success')
   v.clear();v.update(fresh)
 # systemd can drop a successful empty group before retaining RemainAfterExit.
 s.need(terminal_success(v),'empty-cgroup-without-terminal-success')
 if path.exists():s.need(not members(expected),'terminal-cgroup-still-populated')
 return []

def observe(p,payload,items,seen):
 expected=(payload/'omarchy_m_test/gpu_native/bin/gpu-benchmark-vulkan').resolve();providers={'implementation':Path('/usr/lib/libvulkan_asahi.so').resolve(),'loader':Path('/usr/lib/libvulkan.so.1').resolve()}
 for pid,birth in items:
  proc=Path('/proc')/str(pid)
  try:
   if (proc/'exe').resolve()!=expected:continue
   args=[x.decode() for x in (proc/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')]
   s.need(len(args) in (3,4) and args[:2]==[str(expected),'--workload'] and args[2] in ('raster','texture','compute','copy','submit-single','submit-batched','bo-lifetime') and (len(args)==3 or args==[str(expected),'--workload','compute','--negative-control']),'full-helper-arguments')
   s.need(proc.stat().st_uid==p['gui_uid'] and s.sha(proc/'exe')==s.HELPER_SHA,'full-helper-identity');key=(pid,birth)
   entry=seen.setdefault(key,{'workload':args[2],'negative':len(args)==4,'roles':set(),'render_node_observed':False})
   for fd in list((proc/'fd').iterdir())[:256]:
    try:
     st=fd.stat()
     if stat.S_ISCHR(st.st_mode) and (os.major(st.st_rdev),os.minor(st.st_rdev))==(p['render_node_pin']['major'],p['render_node_pin']['minor']):entry['render_node_observed']=True
    except FileNotFoundError:continue
   for line in (proc/'maps').read_text().splitlines():
    fields=line.split(None,5)
    if len(fields)!=6 or not fields[5].startswith('/'):continue
    path=Path(fields[5]).resolve()
    for role,frozen in providers.items():
     if path==frozen:s.need(s.sha(path)==p[role+'_sha256'],'mapped-provider-drift');entry['roles'].add(role)
  except FileNotFoundError:continue
 s.need(len(seen)<=65,'extra-native-invocation')

def expected_schedule(workloads):
 result=[('compute',False),('compute',True)];rng=random.Random(42)
 for phase,count in (('warmup',2),('measured',7)):
  for index in range(count):
   order=list(workloads);rng.shuffle(order);result.extend((name,False) for name in order)
 return result

def stop_unit(p,invocation):
 unit=unit_name(p);v=unit_state(unit)
 if v['LoadState']=='not-found':
  s.need(invocation is None,'owned-unit-vanished');return {'unit':unit,'not_created':True}
 s.need(v['Description']==owner_description(p) and v['Transient']=='yes' and re.fullmatch('[0-9a-f]{32}',v['InvocationID']),'cleanup-unit-owner')
 if invocation:s.need(v['InvocationID']==invocation,'cleanup-invocation-drift')
 # systemd's manager owns the entire cgroup, including setsid() descendants.
 try:s.capture(['systemctl','stop',unit],timeout=12)
 except s.Stop:
  s.capture(['systemctl','kill','--kill-whom=all','--signal=KILL',unit],timeout=5);s.capture(['systemctl','stop',unit],timeout=12)
 v=unit_state(unit);s.need(v['ActiveState'] in ('inactive','failed') and v['MainPID']=='0','owned-unit-not-stopped')
 path=Path('/sys/fs/cgroup/system.slice/'+unit)
 if path.exists():s.need(not members('/system.slice/'+unit),'owned-cgroup-not-empty')
 if v['ActiveState']=='failed':s.capture(['systemctl','reset-failed',unit],timeout=5)
 return {'unit':unit,'invocation_id':invocation,'stopped':True,'control_group_empty':True}

def record_and_stop(p,logs,invocation):
 # Forensic serialization must never prevent the already-owned service stop.
 try:s.private_write(logs/'unit-before-stop.json',unit_state(unit_name(p)))
 finally:cleanup=stop_unit(p,invocation)
 return cleanup

def supervise(p,payload,logs,c):
 unit=unit_name(p);before=unit_state(unit);s.need(before['LoadState']=='not-found','unit-preexists')
 watch=None;selector=selectors.DefaultSelector();streams={};sizes={};seen={};samples=[];started=time.monotonic();invocation=None;cleanup=None;launch_attempted=False;new=s.Journal(p['boot_id']);final_error=None
 try:
  for name in ('child.stdout','child.stderr'):s.private_write(logs/name,b'')
  watch=subprocess.Popen(['timeout','--signal=TERM','--kill-after=5s','1805s','journalctl','-k','-b','--after-cursor='+c,'-f','-o','json','--no-pager','--all'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  for name,stream in (('journal.jsonl',watch.stdout),('journal.stderr',watch.stderr)):
   f=(logs/name).open('xb');os.chmod(logs/name,0o600);streams[name]=f;sizes[name]=0;os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
  launch_attempted=True;s.capture(command(p,payload),timeout=10);v=unit_state(unit);invocation=owner_check(p,v);s.private_write(logs/'unit-start.json',v)
  next_state=next_health=0
  while True:
   now=time.monotonic();s.need(now-started<WALL,'full-outer-timeout');s.need(watch.poll() is None,'journal-monitor-exited')
   s.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot_id'],'unexpected-reboot')
   if now>=next_state:
    v=unit_state(unit);owner_check(p,v,invocation);next_state=now+0.5
   for name in ('child.stdout','child.stderr'):
    f=logs/name;s.need(f.is_file() and not f.is_symlink() and f.stat().st_size<=s.LOG_CAP,'child-log-budget')
   if v['SubState']=='exited':
    s.need(v['Result']=='success' and v['ExecMainCode']=='1' and v['ExecMainStatus']=='0','full-cli-failed');s.need(not owned_members(p,v,invocation),'cli-left-descendants');break
   s.need(v['ActiveState']=='active' and v['SubState']=='running','full-cli-not-running')
   observe(p,payload,owned_members(p,v,invocation),seen)
   if now>=next_health:samples.append(s.health_snapshot(payload));s.need(len(samples)<=1805,'health-count');next_health=now+1
   for name in ('child.stdout','child.stderr'):
    f=logs/name;s.need(f.is_file() and not f.is_symlink() and f.stat().st_size<=s.LOG_CAP,'child-log-budget')
   report=Path(p['prefix'])/'run/reports/gpu-block1.json'
   if report.exists():s.need(not report.is_symlink() and report.stat().st_size<=s.REPORT_CAP,'full-report-budget')
   for key,_ in selector.select(0.02):
    data=os.read(key.fd,16384)
    if not data:selector.unregister(key.fileobj);continue
    name=key.data;sizes[name]+=len(data);s.need(sizes[name]<=s.LOG_CAP,'journal-budget');streams[name].write(data)
    if name=='journal.jsonl':new.consume(data)
    else:raise s.Stop('journal-monitor-stderr')
  s.private_write(logs/'unit-terminal.json',v)
  sys.path.insert(0,str(payload));from omarchy_m_test import gpu_benchmark as gpu
  ordered=list(seen.values());s.need([(x['workload'],x['negative']) for x in ordered]==expected_schedule(gpu.WORKLOADS),'full-native-count-or-order')
  s.need(all(x['roles']=={'implementation','loader'} and x['render_node_observed'] for x in ordered),'full-provider-observation-incomplete')
  return {'elapsed_ms':int((time.monotonic()-started)*1000),'native_invocations':len(ordered),'helpers':[{**x,'roles':sorted(x['roles'])} for x in ordered],'health_samples':samples,'unit':unit,'invocation_id':invocation}
 finally:
  # Cleanup and authentic cursor rescan happen even if parser/monitor/CLI fails.
  try:
   if launch_attempted:
    cleanup=record_and_stop(p,logs,invocation)
  finally:
   try:
    if watch:s.kill_group(watch)
   finally:
    selector.close()
    for f in streams.values():f.flush();os.fsync(f.fileno());f.close()
    raw=s.capture(['journalctl','-k','-b','--after-cursor='+c,'-o','json','--no-pager','--all'],limit=s.LOG_CAP,timeout=10);s.private_write(logs/'journal-final.jsonl',raw)
    final=s.Journal(p['boot_id'])
    try:final.consume(raw);s.need(not final.pending,'journal-final-truncated')
    except s.Stop as error:final_error=str(error)
    s.private_write(logs/'observer-final.json',{'helpers':[{**x,'roles':sorted(x['roles'])} for x in seen.values()],'cleanup':cleanup,'journal_records':final.records,'fault_categories':sorted(final.categories),'journal_error':final_error})
    s.need(final_error is None,'final-journal-fault')

def verify_signature(doc,public,logs):
 sig=doc.get('signature',{});s.need(isinstance(sig,dict) and sig.get('public_key')==public and isinstance(sig.get('signature'),str),'actual-machine-signature-identity')
 s.need(len(sig['signature'])<=16384,'signature-budget')
 s.private_write(logs/'signature.sshsig',sig['signature'].encode()+b'\n');s.private_write(logs/'allowed-signers',('machine '+public+'\n').encode())
 canonical=json.dumps({k:v for k,v in doc.items() if k!='signature'},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 r=subprocess.run(['ssh-keygen','-Y','verify','-f',str(logs/'allowed-signers'),'-I','machine','-n',NAMESPACE,'-s',str(logs/'signature.sshsig')],input=canonical,capture_output=True,timeout=10,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
 s.need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=16384,'actual-machine-signature-invalid')
 return {'namespace':NAMESPACE,'existing_public_key_matches':True,'cryptographic_verification':True}

def validate_report(path,p,payload,public,logs):
 s.need(path.is_file() and not path.is_symlink() and path.stat().st_size<=s.REPORT_CAP,'full-report-file');doc=json.loads(path.read_text())
 sys.path.insert(0,str(payload));from omarchy_m_test import gpu_benchmark as gpu,gpu_schema,bundled
 s.need(not gpu_schema.errors(json.loads(bundled.gpu_document_schema()),doc),'full-schema')
 s.need(doc.get('status')=='pass' and doc['machine']['kernel']==s.KERNEL and doc['machine']['board']=='j293' and doc['machine']['soc']=='t8103' and doc['machine']['arch']=='aarch64','full-status')
 protocol=doc['protocol'];s.need(all(protocol.get(k)==v for k,v in {'warmups':2,'repetitions':7,'order_seed':42,'declared_boot_block':1,'api_scope':'native-vulkan-1.2-offscreen','upload':'never'}.items()),'full-protocol')
 controls=doc['controls'];s.need(len(controls)==2 and [x['negative'] for x in controls]==[False,True],'full-controls')
 expected=expected_schedule(gpu.WORKLOADS);schedule=[];rng=random.Random(42)
 for phase,count in (('warmup',2),('measured',7)):
  for index in range(count):
   order=list(gpu.WORKLOADS);rng.shuffle(order)
   schedule.extend({'workload':work,'phase':phase,'index':index} for work in order)
 s.need(doc['schedule']==schedule and len(doc['cases'])==7,'full-schedule')
 runs=[('compute',x['negative'],x) for x in controls]
 for case,work in zip(doc['cases'],gpu.WORKLOADS):
  s.need(case['workload']==gpu.workload_definition(work) and case['status']=='pass' and len(case['runs'])==9,'full-case-definition')
  s.need(case['metrics']==gpu.metrics_for(case['runs']),'full-statistics-recalculation')
  expected_runs=[{**x,'sequence':i} for i,x in enumerate(schedule) if x['workload']==work]
  for r,expected_run in zip(case['runs'],expected_runs):
   s.need(all(r[k]==expected_run[k] for k in ('phase','index','sequence')),'full-case-order');runs.append((work,False,r))
 for work,negative,r in runs:
  identity=r.get('identity',{});m=r.get('measurements',{});s.need(r.get('status')=='pass' and r.get('reason')==('negative-control-detected' if negative else 'completed'),'full-run-status')
  s.need(r.get('helper_sha256')==s.HELPER_SHA and identity.get('source_sha256')==s.SOURCE_SHA,'full-run-source')
  s.need(identity.get('vendor_id')==0x10005 and identity.get('driver_id')==26 and identity.get('device_type')==1 and identity.get('api_version',0)>=4202496 and identity.get('device_name')=='Apple M1 (G13G B1)','full-run-native')
  s.need(m.get('mismatches')==(1 if negative else 0) and m.get('operations')==(gpu.OPERATIONS[work]//gpu.QUERIES[work] if negative else gpu.OPERATIONS[work]) and 0<m.get('owned_bytes_peak',0)<=64*1024**2,'full-run-oracle')
  s.need((m.get('width'),m.get('height'))==((1920,1080) if work in ('raster','texture') else (0,0)),'full-run-extent')
  s.need({x['role']:x['sha256'] for x in r['driver_libraries']}=={'implementation':p['implementation_sha256'],'loader':p['loader_sha256']} and len(r['driver_libraries'])==2,'full-run-provider')
  if m.get('gpu_timestamp_status')=='supported':s.need(36<=identity['timestamp_bits']<=64 and m.get('gpu_timestamp_queries')==(1 if negative else gpu.QUERIES[work]) and gpu.integer(m.get('gpu_timestamp_ns')),'full-run-timestamps')
  else:s.need(m.get('gpu_timestamp_status')=='unsupported' and identity['timestamp_bits']==0 and m.get('gpu_timestamp_queries')==0 and 'gpu_timestamp_ns' not in m,'full-run-timestamps-unsupported')
 return {'source_commit':COMMIT,'status':'pass','native_invocations':len(runs),'report_sha256':s.sha(path),'signature':verify_signature(doc,public,logs),'scope':'one private boot block; no cross-machine or RC qualification'}

def execute(p,archive):
 s.need(os.geteuid()==0,'root-required');validate(p);before=s.protected_state(p);public=signing_identity(p);secret=os.urandom(32);normal=s.private_state(p['normal_state_paths'],secret)
 prefix,payload,data=stage(p,archive);logs=prefix/'root';receipt={'scope':'private full seven workloads only','status':'fail','source_commit':COMMIT,'before':before}
 try:
  s.start_gate(payload);c=s.cursor();s.private_write(logs/'journal-cursor.json',{'cursor':c,'boot_id':p['boot_id']})
  receipt['supervision']=supervise(p,payload,logs,c);s.health_snapshot(payload);result=validate_report(prefix/'run/reports/gpu-block1.json',p,payload,public,logs)
  s.verify_staged(data,payload);receipt['after']=s.protected_state(p);s.need(s.private_state(p['normal_state_paths'],secret)==normal,'normal-signing-state-drift');s.need(signing_identity(p)==public,'public-key-drift')
  s.private_write(logs/'reviewed-full.json',result);receipt.update(status='pass',normal_user_state_unchanged=True,protected_state_unchanged=True)
 except BaseException as error:
  receipt['reason']=str(error) if isinstance(error,s.Stop) else 'supervisor-exception'
  try:receipt['after']=s.protected_state(p)
  except BaseException:receipt['post_protected_check_failed']=True
  receipt['normal_user_state_unchanged']=s.private_state(p['normal_state_paths'],secret)==normal;raise
 finally:s.private_write(logs/'receipt.json',receipt)
 return receipt

def cancellation(signum,frame):
 # Normal TERM/HUP cancellation must run owned unit/journal cleanup.
 for sig in (signal.SIGTERM,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
 raise s.Stop('supervisor-cancelled')

def install_cancellation():
 for sig in (signal.SIGTERM,signal.SIGHUP):signal.signal(sig,cancellation)

def main():
 a=argparse.ArgumentParser();a.add_argument('--guard-source',required=True);a.add_argument('--plan',required=True);a.add_argument('--plan-sha256',required=True);a.add_argument('--archive',required=True);a.add_argument('--execute-full-suite',action='store_true');args=a.parse_args();load_guard(args.guard_source);install_cancellation()
 s.need(Path(args.plan).stat().st_size<=1024**2 and s.sha(args.plan)==args.plan_sha256 and s.HASH.fullmatch(args.plan_sha256),'full-plan-hash');p=validate(json.loads(Path(args.plan).read_text()));s.inspect_archive(args.archive)
 if not args.execute_full_suite:print('Full source/plan/archive pins valid; no target metadata or GPU action.');return
 print('Private full suite '+execute(p,args.archive)['status'])
if __name__=='__main__':main()
