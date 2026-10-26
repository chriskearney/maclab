#!/usr/bin/env python3
"""Finite same-cohort expectation/code staging; no package/boot owner logic.
Immutable large ledgers stay target-local. Changed reviewed inputs use one fixed
file per call, never shell/argv templates or a large archive chunk loop.
"""
import argparse,base64,hashlib,json,shlex
from pathlib import Path
# Reuse accepted authenticated transport/type checks, not a new client service.
SDK_SHA='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
IMMUTABLE={'candidate-files.jsonl','old-package-files.jsonl','old-owner-expectations.json','linux-aurora.files.sha256','owner-expectations.json','owner-sidecars.json','owner-preinstall-guards.json','OUTPUT-CEILING-PROOF.json','CLOSURE-ADDITIONS.json','verify-package-files.py'}
INPUTS={'transact-m1.py','packet-c-old5.py','rollback-hold-old6.py','transaction-spec.json','execution-clearance.json','packet-c-clearance.json','BOOT-RECOVERY-PLAN.json','manifest.json'}
PRODUCED={'transaction-spec.json','execution-clearance.json','packet-c-clearance.json','BOOT-RECOVERY-PLAN.json','ESP-PREPARATION-EXPECTATIONS.json','ESP-ARRANGEMENT.json','ESP-PREPARATION-RECEIPT.json','ESP-RETIREMENT-RETENTION-RECEIPT.json','limine.conf.ARRANGED','FALLBACK-CONFIG-CLOSURE.json','MIRROR-RECEIPT.json','OWNER-BACKUP-DECISIONS.json'}
INPUTS|=PRODUCED
DATA={'old-owner-expectations.json':'1c024b585c91add3089cb9e98c3dc55e2227040fc2fc84899db8d161855ca120'}
CODE={'transact-m1.py':'23b7227bdf76c22047784dc37776458a4fea7c8a5936a72eb857d3eeafbc3e3b','packet-c-old5.py':'02f4c7e0210e1f28f1d945323d1b2a8503aa6c33bb1c95950fe1097fc422fa14','rollback-hold-old6.py':'0a746b40d63a0d1d8b19b3b50613af764c8d2486f73035da9089b18ecd816fcb'}
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def sdk():
 import sys
 p=Path(__file__).with_name('frozen-controller-ea3.py');raw=p.read_bytes();need(H(raw)==SDK_SHA,'accepted source transport drift');m=type(sys)('accepted_asset_transport');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__);return m
REMOTE=r'''import base64,fcntl,hashlib,json,os,re,stat,sys,time
from pathlib import Path
q=json.loads(sys.argv[1]);P=Path(q['packet']);S=Path(q['source_packet']);H=lambda b:hashlib.sha256(b).hexdigest();deadline=time.monotonic()+180
IMMUTABLE={'candidate-files.jsonl','old-package-files.jsonl','old-owner-expectations.json','linux-aurora.files.sha256','owner-expectations.json','owner-sidecars.json','owner-preinstall-guards.json','OUTPUT-CEILING-PROOF.json','CLOSURE-ADDITIONS.json','verify-package-files.py'}
INPUTS={'transact-m1.py','packet-c-old5.py','rollback-hold-old6.py','transaction-spec.json','execution-clearance.json','packet-c-clearance.json','BOOT-RECOVERY-PLAN.json','manifest.json'}
PRODUCED={'transaction-spec.json','execution-clearance.json','packet-c-clearance.json','BOOT-RECOVERY-PLAN.json','ESP-PREPARATION-EXPECTATIONS.json','ESP-ARRANGEMENT.json','ESP-PREPARATION-RECEIPT.json','ESP-RETIREMENT-RETENTION-RECEIPT.json','limine.conf.ARRANGED','FALLBACK-CONFIG-CLOSURE.json','MIRROR-RECEIPT.json','OWNER-BACKUP-DECISIONS.json'}
INPUTS|=PRODUCED
DATA={'old-owner-expectations.json':'1c024b585c91add3089cb9e98c3dc55e2227040fc2fc84899db8d161855ca120'}
CODE={'transact-m1.py':'23b7227bdf76c22047784dc37776458a4fea7c8a5936a72eb857d3eeafbc3e3b','packet-c-old5.py':'02f4c7e0210e1f28f1d945323d1b2a8503aa6c33bb1c95950fe1097fc422fa14','rollback-hold-old6.py':'0a746b40d63a0d1d8b19b3b50613af764c8d2486f73035da9089b18ecd816fcb'}
def need(v,msg):
 if not v:raise RuntimeError(msg)
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def parent_dirs(p):
 for a in [p,*p.parents]:
  st=a.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'unsafe packet ancestry')
def open_regular(p,limit):
 m=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(m);need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and not a.st_mode&0o022 and 0<a.st_size<=limit,'unsafe regular asset')
  fd=os.open('/proc/self/fd/'+str(m),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC);need(identity(os.fstat(fd))==identity(a),'held asset identity drift');return fd,a
 finally:os.close(m)
def hash_fd(fd,size):
 h=hashlib.sha256();off=0
 while off<size:
  need(time.monotonic()<deadline,'asset deadline');b=os.pread(fd,min(1048576,size-off),off);need(b,'short asset');h.update(b);off+=len(b)
 need(not os.pread(fd,1,size),'asset grew');return h.hexdigest()
def verify(p,pin):
 f,a=open_regular(p,pin['bytes'])
 try:need(a.st_size==pin['bytes'] and hash_fd(f,a.st_size)==pin['sha256'] and identity(os.fstat(f))==identity(a)==identity(p.lstat()),'asset hash/path drift');return {'sha256':pin['sha256'],'bytes':pin['bytes'],'identity':identity(a)}
 finally:os.close(f)
def read(p,limit):
 f,a=open_regular(p,limit)
 try:b=os.pread(f,a.st_size+1,0);need(len(b)==a.st_size and identity(os.fstat(f))==identity(a)==identity(p.lstat()),'input read drift');return b
 finally:os.close(f)
def syncdir(p):
 f=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(f)
 finally:os.close(f)
need(os.geteuid()==0 and os.uname().machine=='aarch64','root AArch64 stage only')
need(os.uname().release==q['expected_kernel'],'current kernel mismatch')
if q['expected_kernel']!='7.2.11-6-1-ARCH':need(q['expected_kernel']=='7.2.11-7-1-ARCH' and q['operation']=='stage-input' and [r['name'] for r in q['assets']]==['packet-c-clearance.json'],'only fresh PacketC clearance may stage on normal7')
need(re.fullmatch('/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}',str(P)) and re.fullmatch('/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}',str(S)) and P!=S,'distinct supported packets');parent_dirs(P);parent_dirs(S)
need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==q['boot_id'] and b'maclab.job=' not in Path('/proc/cmdline').read_bytes() and Path('/proc/device-tree/compatible').read_bytes().split(b'\0')[0]==b'apple,j293','fresh normal M1 identity')
need(not os.path.lexists('/var/lib/pacman/db.lck'),'ALPM active')
parent=Path(os.readlink('/proc/'+str(os.getppid())+'/exe'));need(str(parent)==q['agent_parent']['path'],'direct agent parent path');verify(parent,q['agent_parent'])
marker=json.loads(read(P/'CACHE-PROFILE.json',65536));need(marker=={'profile_sha256':q['profile_sha256'],'source_packet':str(S)},'owned fresh profile marker')
need(H(read(P/'STANDING-BOOT-AUTHORITY.json',65536))=='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365','actual standing authority')
result={}
rows=q['assets']
need(1<=len(rows)<=12 and len({x['name'] for x in rows})==len(rows),'bounded unique explicit assets')
for row in rows:
 name=row['name'];need(name in (IMMUTABLE if q['operation']=='reuse-assets' else INPUTS),'unsupported artifact leaf')
 need(type(row['bytes']) is int and 0<row['bytes']<=16777216 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded exact artifact pin')
 if name in CODE:need(row['sha256']==CODE[name],'unreviewed code source')
 if name in DATA:need(row['sha256']==DATA[name],'unreviewed immutable expectation data')
 if name in PRODUCED and q['operation']=='stage-input':
  ps=q['producer_scope'];need(ps['schema']=='maclab.m1-producer-stage-scope/1' and ps['packet']==str(P) and ps['expected_boot_id']==q['boot_id'] and ps['root_plan_sha256']==q['root_plan_sha256'] and re.fullmatch('[0-9a-f]{64}',ps['root_plan_sha256']) and re.fullmatch('[0-9a-f]{64}',ps['source_sha256']) and ps['file_name']==name and ps['file_sha256']==row['sha256'] and ps['file_bytes']==row['bytes'],'fresh selected producer proof binding')
 dest=P/name
 if os.path.lexists(dest):result[name]={**verify(dest,row),'reused':True};continue
 if q['operation']=='reuse-assets':
  source=S/name;f,a=open_regular(source,row['bytes']);temp=P/('.'+name+'.owned-stage.part');need(not os.path.lexists(temp),'partial asset retained; reconcile before retry')
  need(a.st_size==row['bytes'] and hash_fd(f,a.st_size)==row['sha256'],'source asset pin mismatch')
  out=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
  try:
   try:fcntl.ioctl(out,0x40049409,f);method='target-local-reflink'
   except OSError:
    need(os.fstat(out).st_size==0,'partial reflink failed');off=0;method='target-local-copy'
    while off<a.st_size:
     need(time.monotonic()<deadline,'asset copy deadline');b=os.pread(f,min(1048576,a.st_size-off),off);need(b and os.pwrite(out,b,off)==len(b),'short asset write');off+=len(b)
   os.fsync(out)
  finally:os.close(out)
  try:need(identity(os.fstat(f))==identity(a)==identity(source.lstat()),'retained source changed')
  finally:os.close(f)
  verify(temp,row);need(not os.path.lexists(dest),'destination appeared');os.link(temp,dest,follow_symlinks=False);syncdir(P);verify(dest,row);temp.unlink();syncdir(P);result[name]={**verify(dest,row),'method':method,'archive_network_bytes':0}
 else:
  raw=base64.b64decode(row['base64'],validate=True);need(len(raw)==row['bytes']<=65536 and H(raw)==row['sha256'],'changed input payload drift')
  out=os.open(dest,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
  try:
   view=memoryview(raw)
   while view:need(time.monotonic()<deadline,'input write deadline');n=os.write(out,view);need(n>0,'short input write');view=view[n:]
   os.fsync(out)
  finally:os.close(out)
  syncdir(P);result[name]={**verify(dest,row),'reused':False}
print(json.dumps({'status':'EXACT_ASSETS_STAGED_ONLY','operation':q['operation'],'packet':str(P),'boot_id':q['boot_id'],'assets':result,'no_package_or_boot_changes':True,**({'root_plan_sha256':q['root_plan_sha256']} if 'root_plan_sha256' in q else {})}))
'''
def run(binding,api=None):
 c=sdk();p=binding['profile'];op=binding['operation'];need(op in ('reuse-assets','stage-input'),'finite asset action');need(binding['source_reviewed_by'],'root-reviewed source needed')
 client=api or c.API(c.config());d=client.request('/api/devices/m1');expected_kernel=binding.get('expected_kernel','7.2.11-6-1-ARCH')
 if expected_kernel!='7.2.11-6-1-ARCH':need(expected_kernel=='7.2.11-7-1-ARCH' and op=='stage-input' and [r['name'] for r in binding['assets']]==['packet-c-clearance.json'],'only PacketC clearance stage on normal7')
 c.state_gate(d,p,{'expected_boot_id':binding['expected_boot_id'],'expected_kernel':expected_kernel},True,450)
 rows=[]
 for row in binding['assets']:
  need(row['name'] in (IMMUTABLE if op=='reuse-assets' else INPUTS),'unsupported named artifact');q={k:row[k] for k in ('name','sha256','bytes')}
  if row['name'] in CODE:need(q['sha256']==CODE[row['name']],'unreviewed source code')
  if row['name'] in DATA:need(q['sha256']==DATA[row['name']],'unreviewed immutable expectation data')
  if op=='stage-input':
   raw=base64.b64decode(row['base64'],validate=True) if 'base64' in row else c.read_pin(row['source']);need(len(raw)==q['bytes'] and H(raw)==q['sha256'],'root input data/source drift');q['base64']=base64.b64encode(raw).decode()
   if row['name'] in PRODUCED:
    ps=binding['producer_scope'];need(ps['schema']=='maclab.m1-producer-stage-scope/1' and ps['packet']==p['packet'] and ps['expected_boot_id']==binding['expected_boot_id'] and ps['root_plan_sha256']==binding['root_plan_sha256'] and len(ps['root_plan_sha256'])==64 and all(x in '0123456789abcdef' for x in ps['root_plan_sha256']) and ps['file_name']==row['name'] and ps['file_sha256']==q['sha256'] and ps['file_bytes']==q['bytes'],'fresh selected producer proof binding');need(H(c.read_pin(binding['producer_source']))==ps['source_sha256'],'actual reviewed producer source pin')
  rows.append(q)
 need(op!='stage-input' or len(rows)==1,'changed files use individually bounded calls')
 payload={'operation':op,'packet':p['packet'],'source_packet':p['source_packet'],'boot_id':binding['expected_boot_id'],'profile_sha256':binding['packet_profile_sha256'],'expected_kernel':expected_kernel,'agent_parent':binding['agent_parent'],'assets':rows}
 if op=='stage-input' and any(r['name'] in PRODUCED for r in rows):payload.update(root_plan_sha256=binding['root_plan_sha256'],producer_scope=binding['producer_scope'])
 command=shlex.join(['/usr/bin/python3','-E','-B','-c',REMOTE,json.dumps(payload,separators=(',',':'))]);need(len(command.encode())<=120000,'fixed transport ceiling; never broaden argument limit')
 r=client.request('/api/devices/m1/exec',{'command':command,'timeout_sec':240},330)
 if r['exit_code']!=0 or r.get('via')!='agent' or r.get('stderr'):return {'status':'M1_ASSET_STAGE_FAILED','actual_exec':r,'completion_claim':False}
 try:
  out=json.loads(r['stdout']);need(type(out) is dict and out.get('status')=='EXACT_ASSETS_STAGED_ONLY' and out.get('operation')==op and out.get('packet')==p['packet'] and out.get('boot_id')==binding['expected_boot_id'] and out.get('no_package_or_boot_changes') is True,'actual asset response identity/status mismatch')
  actual=out['assets'];need(type(actual) is dict and set(actual)=={row['name'] for row in rows},'actual asset response keyset mismatch')
  for row in rows:need(type(actual[row['name']]) is dict and actual[row['name']].get('sha256')==row['sha256'] and type(actual[row['name']].get('bytes')) is int and actual[row['name']]['bytes']==row['bytes'],'actual staged artifact pin mismatch')
  if 'root_plan_sha256' in payload:need(out.get('root_plan_sha256')==payload['root_plan_sha256'],'actual produced proof Plan mismatch')
 except Exception as e:return {'status':'M1_ASSET_STAGE_FAILED','actual_exec':r,'completion_claim':False,'response_error':str(e)}
 return {'status':'M1_ASSETS_STAGED_ONLY','target':out,'actual_exec':r,'completion_claim':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())),separators=(',',':')))
