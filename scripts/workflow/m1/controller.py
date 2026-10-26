#!/usr/bin/env python3
"""Reviewed fixed-protocol M1 workflow transport over existing Maclab admin API.
No new daemon, SSH credentials, arbitrary command template, or package installer.
"""
import argparse,base64,datetime,hashlib,json,os,shlex,stat,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path

LIMIT=4*1024**2
ALLOWED={'inventory-cache','stage-cache','invoke-packet','stage-backup-inputs','capture-original','collect-backup','stage-supplement-inputs','capture-supplement','collect-supplement','collect-closure'}
def need(v,msg):
 if not v:raise RuntimeError(msg)
def read_pin(pin):
 p=Path(pin['path']);fd=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(stat.S_ISREG(a.st_mode) and a.st_size==pin['bytes']<=LIMIT,'not bounded source')
  f=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   b=os.read(f,a.st_size+1);need(len(b)==a.st_size and key(os.fstat(f))==key(a)==key(p.lstat()),'source inode drift')
  finally:os.close(f)
  need(hashlib.sha256(b).hexdigest()==pin['sha256'],'source hash drift');return b
 finally:os.close(fd)
def config():
 path=Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/'maclab/client.json';c=json.loads(path.read_bytes());c['url']=os.environ.get('MACLAB_URL',c['url']).rstrip('/');c['token']=os.environ.get('MACLAB_TOKEN',c['token']);u=urllib.parse.urlsplit(c['url']);need(u.scheme in ('http','https') and u.hostname and not u.username and not u.password,'unsafe configured endpoint');return c
class API:
 def __init__(self,c):self.c=c
 def request(self,path,body=None,timeout=60):
  req=urllib.request.Request(self.c['url']+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers={'Authorization':'Bearer '+self.c['token'],'Content-Type':'application/json'})
  with urllib.request.urlopen(req,timeout=timeout) as response:raw=response.read(LIMIT+1)
  need(len(raw)<=LIMIT,'API response exceeds bound');return json.loads(raw)
def state_gate(d,p,binding,mutates,minimum_seconds=0):
 need(d['name']==p['device'] and d['state']=='ready' and d['alive'] and not d.get('active_job') and not d.get('queued'),'Mac is not genuinely ready/idle')
 need(d['kernel']==binding['expected_kernel'] and d['boot_id']==binding['expected_boot_id'],'fresh live controller identity drift')
 if mutates:
  lease=d.get('lease',{});need(lease.get('holder')==p['holder'],'exclusive coordinator lease required')
  expires=datetime.datetime.fromisoformat(lease['expires'].replace('Z','+00:00'));need(expires.tzinfo is not None and (expires-datetime.datetime.now(datetime.timezone.utc)).total_seconds()>=minimum_seconds,'lease would expire inside phase/cleanup; renew existing lease, no new user permission')
 return d

def write_capture(path,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();need(len(raw)<=LIMIT,'private capture ceiling')
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:n=os.write(fd,view);need(n>0,'short capture write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 need(path.read_bytes()==raw,'private capture readback mismatch');d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(d)
 finally:os.close(d)
 return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'independent_retention_claim':False}

def run_closure(binding,api=None):
 p=binding['profile'];pin=p['closure_collector'];source=read_pin(pin);need(source==Path(__file__).with_name('closure-collector.py').read_bytes(),'reviewed collector closure mismatch')
 c=api or API(config());d=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe=''));bound=dict(binding)
 if bound.get('expected_boot_id') is None:bound['expected_boot_id']=d['boot_id']
 state_gate(d,p,bound,False)
 # Source is fixed/pinned. All three pacman-conf calls are literal read-only
 # queries; no hook command or captured text is ever executed.
 remote="import base64,contextlib,io,json,subprocess\nsource=base64.b64decode("+repr(base64.b64encode(source).decode())+",validate=True);buf=io.StringIO();ns={'__name__':'reviewed_closure'}\nwith contextlib.redirect_stdout(buf):\n exec(compile(source,'<reviewed-readonly-collector>','exec'),ns);ns['main']()\nconf={}\nfor key in ['HookDir','NoExtract','NoUpgrade']:\n p=subprocess.run(['/usr/bin/pacman-conf',key],capture_output=True,text=True,timeout=10);conf[key]={'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}\nprint(json.dumps({'collector_stdout':buf.getvalue(),'pacman_conf':conf},separators=(',',':')))"
 command=shlex.join(['/usr/bin/python3','-E','-B','-c',remote]);need(len(command.encode())<=120000,'fixed closure transport ceiling')
 result=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe='')+'/exec',{'command':command,'timeout_sec':180},270)
 capture=write_capture(Path(__file__).parent/'closure-api-capture.json',{'schema':'maclab.m1-closure-api-capture/1','collector_source_sha256':pin['sha256'],'actual_exec':result,'controller_boot_id':d['boot_id']})
 if result['exit_code']!=0 or result.get('via')!='agent':return {'status':'M1_CLOSURE_CAPTURE_FAILED','capture':capture,'device':p['device'],'boot_id':d['boot_id']}
 envelope=json.loads(result['stdout']);actual=json.loads(envelope['collector_stdout']);need(actual['boot_id']==d['boot_id'] and actual['kernel']==bound['expected_kernel'] and actual['board']==p['board'],'closure collector actual identity mismatch')
 return {'status':'M1_CLOSURE_OBSERVED','capture':capture,'collector_source_sha256':pin['sha256'],'device':p['device'],'boot_id':actual['boot_id'],'kernel':actual['kernel'],'board':actual['board'],'collector_status':actual['status'],'STOP':actual['STOP'],'old_module_tree_sha256':actual['old_module_tree_sha256'],'hook_source_count':len(actual['all_vendor_and_local_hook_sources']),'closure_file_count':len(actual['closure_files']),'fallback_config_directories':actual['fallback_config_directories'],'pacman_conf':envelope['pacman_conf'],'readiness_claim':False,'independent_retention_claim':False}

def run(binding,api=None):
 p=binding['profile'];action=binding['action'];need(action in ALLOWED,'unknown typed M1 operation')
 if action=='collect-closure':return run_closure(binding,api)
 # Structural target validation also runs before the RPC, from the exact source
 # closure; do not dynamically import arbitrary plan modules.
 pin=p['target_adapter'];need(Path(pin['path']).name=='target.py','fixed target adapter basename required');source=read_pin(pin)
 need(source==Path(__file__).with_name('target.py').read_bytes(),'controller/target closure mismatch')
 c=api or API(config());mutates=action not in ('inventory-cache','collect-backup','collect-supplement');d=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe=''));binding=dict(binding)
 if not mutates and binding.get('expected_boot_id') is None:binding['expected_boot_id']=d['boot_id']
 state_gate(d,p,binding,mutates,int(binding['deadline_seconds'])+90)
 payload={k:binding[k] for k in ('action','profile','expected_boot_id','expected_kernel','deadline_seconds')}
 for extra in ['entry','prepared_inputs','receipt_sha256']:
  if extra in binding:payload[extra]=binding[extra]
 if mutates:
  authority=read_pin(p['authority_source']);a=json.loads(authority)
  need(a['authorization_is_persistent'] is True and a['manual_saved_work_confirmed'] is False and a['manual_nearby_recovery_confirmed'] is False and a['does_not_lift_existing_holds'] is True,'standing authority facts mismatch')
  scope=binding['root_scope'];need(scope['packet']==p['packet'] and scope['device']==p['device'] and scope['expected_boot_id']==binding['expected_boot_id'] and action in scope['operations'] and scope['authority_sha256']==p['authority_source']['sha256'],'root scope is not bound to this fresh packet/boot/operation')
  need(scope['reviewed_by'] and scope['manual_saved_work_confirmed'] is False and scope['manual_nearby_recovery_confirmed'] is False,'do not invent confirmations')
  payload['standing_authority_b64']=base64.b64encode(authority).decode();payload['root_scope']=scope
 # Exactly one logged existing exec call. Source and JSON are individually
 # quoted arguments; no profile data is evaluated as source or shell syntax.
 argv=['/usr/bin/python3','-E','-B','-c',source.decode(),'--request-json',json.dumps(payload,separators=(',',':'))]
 command=shlex.join(argv);need(len(command.encode())<=120000,'fixed transport ceiling exceeded')
 timeout=int(binding['deadline_seconds']);need(1<=timeout<=1900,'bounded phase timeout required')
 if action=='invoke-packet':need(timeout==1900,'owner/PacketC requires complete1900-second outer cleanup envelope')
 elif action=='capture-original':need(timeout==1200,'full900s capture and cleanup requires1200s envelope')
 else:need(timeout<=900,'metadata/cache deadline ceiling')
 result=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe='')+'/exec',{'command':command,'timeout_sec':timeout+60},timeout+90)
 if result['exit_code']!=0 or result.get('via')!='agent':return {'status':'M1_TARGET_FAILED','device':p['device'],'boot_id':d['boot_id'],'actual_exec':result,'source_sha256':pin['sha256']}
 # Preserve the authentic full API receipt in caller stdout for the workflow
 # journal; a success status is never synthesized from missing target evidence.
 out={'status':'OWNER_EXIT_ONLY_REQUIRES_INDEPENDENT_RECEIPT_VALIDATION','exit_code':result['exit_code'],'completion_claim':False} if action=='invoke-packet' else json.loads(result['stdout']);need(isinstance(out,dict),'target result is not an object')
 return {'status':'M1_'+action.upper().replace('-','_')+'_OBSERVED','device':p['device'],'boot_id':d['boot_id'],'kernel':d['kernel'],'actual_exec':result,'target':out,'source_sha256':pin['sha256'],'controller_state':{k:d.get(k) for k in ['name','state','alive','boot_id','kernel','lease','active_job','queued']},'no_new_user_confirmation':True}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())),separators=(',',':')))
