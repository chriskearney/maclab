#!/usr/bin/env python3
"""Finite current-transaction artifact reader and genuine stdout descriptor.
No package/boot/service writes. A descriptor is observed data, not acceptance.
"""
import argparse,base64,hashlib,json,os,re,shlex,stat,sys,types,zlib
from pathlib import Path
ESP='ae0e01c7f6a2c2c84ec9944cee255f814b5788c6045b48ec1f4f1a76907d06df'
SDK='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
FIXED={'fallback-extras-spec.json','fallback-extras/APPLY-RECEIPT.json','writer-quiesce/BEFORE.json','writer-quiesce/PREPARED.json','writer-quiesce/RESTORED.json','writer-persistent-hold/APPLIED.json','writer-persistent-hold/REMOVED.json','packet-c-clearance.json','execution-clearance.json','transaction-spec.json','NORMAL7-ACTUAL-PROOF.json','NORMAL6-ROLLBACK-VERIFIED.json','ACTUAL-POSTINSTALL.json','TEMP6-DEFAULT-INTENT.json','TEMP6-DEFAULT-COMPLETE.json','candidate-uki-retention/LOCAL-RECEIPT.json'}
for prefix,names in {'transaction-receipts':('PACMAN-OUTCOME.json','PACMAN-OWNED-GROUP.json','TRANSACTION-RESULT.json','OLD-MODULE-MARKER-OWNED.json'),'packet-c-receipts':('PACMAN-OUTCOME.json','PACMAN-OWNED-GROUP.json','OWNER-RESTORE-RESULT.json','PACKAGE-PHASE-COMPLETE.json')}.items():FIXED|={prefix+'/'+n for n in names}
for action in ('plan','apply','restore'):
 for subject in ('pre','sf'):FIXED|={'esp-'+subject+'.plan.json','esp-'+subject+'.retention.json','ESP-'+action+'-'+subject+'.json','ESP-OWNER-'+action+'-'+subject+'.json'}
for action in ('fallback-apply','fallback-restore','restore-arranged-default','collect','ensure-lock'):FIXED|={'ESP-'+action+'-none.json','ESP-OWNER-'+action+'-none.json'}
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def module(raw,name,path):
 m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def load():
 # The engine copies/readback-verifies both closure files before invocation.
 # Metadata-first local reads are delegated to the exact ESP guard thereafter.
 p=Path(__file__).with_name('esp.py');meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(meta);key=lambda z:(z.st_dev,z.st_ino,z.st_mode,z.st_uid,z.st_gid,z.st_size,z.st_mtime_ns,z.st_ctime_ns);need(stat.S_ISREG(s.st_mode) and s.st_uid in (0,os.geteuid()) and not s.st_mode&0o022 and s.st_size<=65536,'bounded regular ESP closure');fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:raw=os.pread(fd,s.st_size+1,0);need(len(raw)==s.st_size and key(os.fstat(fd))==key(s)==key(p.lstat()) and H(raw)==ESP,'reviewed ESP closure drift')
  finally:os.close(fd)
 finally:os.close(meta)
 return module(raw,'proof_guard',p),raw

def describe_initial(b):
 x=b['actual_observation'];a=x['actual_exec'];need(x['status']=='M1_INITIAL_ESP_OBSERVED' and a['via']=='agent' and a['exit_code']==0 and not a['stderr'],'actual successful initial observer required');raw=a['stdout'].encode();need(0<len(raw)<=1048576,'bounded actual target stdout');o=json.loads(raw);need(o==x['target'] and o['schema']=='maclab.m1-initial-esp-observation/1' and o['status']=='ACTUAL_ORIGINAL_ESP_READONLY_OBSERVED' and o['packet']==b['packet'] and o['boot_id']==b['expected_boot_id'] and o['kernel']=='7.2.11-6-1-ARCH' and o['root_plan_sha256']==b['root_plan_sha256'] and o['target_mutations'] is False,'actual initial target stdout identity mismatch')
 return {'status':'GENUINE_INITIAL_ESP_TARGET_STDOUT_DESCRIBED_LOCAL_ONLY','packet':b['packet'],'root_plan_sha256':b['root_plan_sha256'],'boot_id':b['expected_boot_id'],'descriptor':{'raw_base64':base64.b64encode(raw).decode(),'sha256':H(raw),'bytes':len(raw)},'target_actions':False,'completion_claim':False}

def read_files(e,P,requests):
 need(type(requests) is dict and 1<=len(requests)<=32 and set(requests)<=FIXED,'finite current-P receipt leaves only');out={};total=0
 for name,expected in requests.items():
  path=P/name;e.private(path.parent);raw,s=e.regular(path,262144);total+=len(raw);need(total<=131072,'proof batch exceeds128KiB; split finite requests');sha=H(raw)
  if expected is not None:need(expected['sha256']==sha and expected['bytes']==len(raw),'actual proof differs from existing phase pin')
  out[name]={'base64':base64.b64encode(raw).decode(),'sha256':sha,'bytes':len(raw),'identity':e.key(s)}
 # Reopen and compare after the entire batch, not merely after each file.
 for name,pin in out.items():raw,s=e.regular(P/name,262144);need(H(raw)==pin['sha256'] and len(raw)==pin['bytes'] and e.key(s)==pin['identity'],'terminal proof drift')
 return out

def drained_groups(e,P):
 ownerraw,_=e.pin(P/'transact-m1.py','23b7227bdf76c22047784dc37776458a4fea7c8a5936a72eb857d3eeafbc3e3b',65536);owner=module(ownerraw,'reviewed_group_observer',P/'transact-m1.py');out={}
 for name,folder in [('transaction-receipts/PACMAN-OWNED-GROUP.json','packages'),('packet-c-receipts/PACMAN-OWNED-GROUP.json','rollback-packages')]:
  path=P/name
  if not os.path.lexists(path):need(folder=='rollback-packages','original installer group receipt missing');out[name]={'absent':True};continue
  e.private(path.parent);raw,_=e.regular(path,262144);r=json.loads(raw);gid=r['pgid'];need(type(gid) is int and 1<gid==r['pid']==r['sid'] and r['per_regular_file_limit_bytes']==64413696,'exact owned package group identity');argv=r['argv'];need(type(argv) is list and len(argv)==9 and argv[:4]==['/usr/bin/pacman','-U','--noconfirm','--'] and all(Path(x).parent==P/folder and Path(x).name not in ('.','..') for x in argv[4:]),'current-P finite package group argv');need(not owner.live_group(gid),'owned package group remains live; rollback not admitted');again,_=e.regular(path,262144);need(again==raw,'group identity receipt changed during /proc observation');out[name]={'pgid':gid,'identity_sha256':H(raw),'live':False}
 return out

def validate(b):
 p=b['profile'];need(b['operation'] in ('read-current-files','prove-owned-groups') and p['device']=='m1' and p['board']=='apple,j293' and p['holder'],'finite M1 proof operation');pattern='/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}';need(re.fullmatch(pattern,p['packet']) and re.fullmatch(pattern,p['source_packet']) and p['packet']!=p['source_packet'],'distinct owned M1 packets');need(re.fullmatch('[0-9a-f]{64}',b['root_plan_sha256']) and re.fullmatch('[0-9a-f]{64}',b['packet_profile_sha256']) and b['expected_kernel'] in ('7.2.11-6-1-ARCH','7.2.11-7-1-ARCH'),'actual Plan/profile/cohort');need(b['operation']=='prove-owned-groups' or (type(b['files']) is dict and 1<=len(b['files'])<=32 and set(b['files'])<=FIXED),'finite proof leaves')
 for value in b.get('files',{}).values():need(value is None or (type(value) is dict and set(value)=={'sha256','bytes'} and re.fullmatch('[0-9a-f]{64}',value['sha256']) and type(value['bytes']) is int and 0<value['bytes']<=262144),'bounded previously observed proof pin')
 return p

def target(b):
 validate(b);need(H(_ESP_SOURCE)==ESP,'reviewed guard source');e=module(_ESP_SOURCE,'remote_proof_guard','esp.py');p=b['profile'];P=Path(p['packet']);need(os.geteuid()==0 and os.uname().machine=='aarch64','root native proof reader');e.direct_agent_parent(p['agent_parent']);e.private(P)
 def live():need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==b['expected_boot_id'] and os.uname().release==b['expected_kernel'] and Path('/proc/device-tree/compatible').read_bytes().split(b'\0')[0]==b'apple,j293' and b'maclab.job=' not in Path('/proc/cmdline').read_bytes(),'actual normal M1 proof-read identity')
 live();raw,_=e.regular(P/'CACHE-PROFILE.json',65536);marker=json.loads(raw);need(marker=={'profile_sha256':b['packet_profile_sha256'],'source_packet':p['source_packet']},'owned current packet marker mismatch')
 if b['operation']=='prove-owned-groups':
  out=drained_groups(e,P);live();return {'schema':'maclab.m1-owned-group-drain/1','status':'OWNED_PACKAGE_GROUPS_DRAINED','packet':str(P),'boot_id':b['expected_boot_id'],'kernel':b['expected_kernel'],'root_plan_sha256':b['root_plan_sha256'],'groups':out,'target_mutations':False}
 out=read_files(e,P,b['files']);live();return {'schema':'maclab.m1-proof-read/1','status':'ACTUAL_CURRENT_PACKET_PROOFS_READ_ONLY','packet':str(P),'boot_id':b['expected_boot_id'],'kernel':b['expected_kernel'],'root_plan_sha256':b['root_plan_sha256'],'files':out,'target_mutations':False}

def run(b,api=None):
 if b['operation']=='describe-initial-esp':return describe_initial(b)
 p=validate(b)
 e,eraw=load();here=Path(__file__).parent;sraw,_=e.pin(here/'frozen-controller-ea3.py',SDK,65536,False);s=module(sraw,'proof_sdk',here/'frozen-controller-ea3.py');c=api or s.API(s.config());d=c.request('/api/devices/m1');s.state_gate(d,p,b,True,210)
 source,_=e.regular(__file__,65536,False);command=shlex.join(['/usr/bin/python3','-E','-B','-c','import base64,zlib\n_ESP_SOURCE=zlib.decompress(base64.b64decode('+repr(base64.b64encode(zlib.compress(eraw)).decode())+'))\n'+source.decode(),'--request-json',json.dumps(b,separators=(',',':'))]);need(len(command.encode())<=120000,'fixed proof command ceiling');r=c.request('/api/devices/m1/exec',{'command':command,'timeout_sec':120},180)
 try:
  need(r.get('via')=='agent' and r.get('exit_code')==0 and not r.get('stderr'),'proof RPC transport/exit/stderr');o=json.loads(r['stdout']);groups=b['operation']=='prove-owned-groups';need(o['schema']==('maclab.m1-owned-group-drain/1' if groups else 'maclab.m1-proof-read/1') and o['status']==('OWNED_PACKAGE_GROUPS_DRAINED' if groups else 'ACTUAL_CURRENT_PACKET_PROOFS_READ_ONLY') and o['packet']==p['packet'] and o['boot_id']==b['expected_boot_id'] and o['kernel']==b['expected_kernel'] and o['root_plan_sha256']==b['root_plan_sha256'] and o['target_mutations'] is False and (groups or set(o['files'])==set(b['files'])),'actual proof response binding')
  if groups:
   need(set(o['groups'])=={'transaction-receipts/PACMAN-OWNED-GROUP.json','packet-c-receipts/PACMAN-OWNED-GROUP.json'},'exact possible owned groups')
   for name,row in o['groups'].items():need((name.startswith('packet-c-') and row=={'absent':True}) or (set(row)=={'pgid','identity_sha256','live'} and type(row['pgid']) is int and row['pgid']>1 and re.fullmatch('[0-9a-f]{64}',row['identity_sha256']) and row['live'] is False),'genuine no-live-group observation')
  total=0
  for name,pin in o.get('files',{}).items():raw=base64.b64decode(pin['base64'],validate=True);total+=len(raw);need(H(raw)==pin['sha256'] and len(raw)==pin['bytes']<=262144,'actual raw proof integrity');expected=b['files'][name];need(expected is None or all(pin[k]==expected[k] for k in ('sha256','bytes')),'actual expected proof pin drift')
  need(total<=131072,'proof batch exceeds128KiB; split finite requests')
 except Exception as exc:return {'status':'M1_PROOF_READ_FAILED','actual_exec':r,'completion_claim':False,'response_error':type(exc).__name__+': '+str(exc)}
 return {'status':'M1_OWNED_PACKAGE_GROUPS_OBSERVED' if b['operation']=='prove-owned-groups' else 'M1_CURRENT_PACKET_PROOFS_OBSERVED','packet':p['packet'],'boot_id':b['expected_boot_id'],'root_plan_sha256':b['root_plan_sha256'],'actual_exec':r,'target':o,'source_sha256':H(source),'completion_claim':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();g=a.add_mutually_exclusive_group(required=True);g.add_argument('--binding',type=Path);g.add_argument('--request-json');x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())) if x.binding else target(json.loads(x.request_json)),separators=(',',':')))
