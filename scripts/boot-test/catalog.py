"""Pure typed device/catalog admission. No target/API operations or source import."""
import hashlib,json,os,re,stat
from pathlib import Path
LIMIT=4*1024**2
class Refused(RuntimeError):pass
def need(x,msg):
 if not x:raise Refused(msg)
def unique(b):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs)
def pin_shape(p,limit=LIMIT):
 need(type(p) is dict and set(p)=={'path','sha256','bytes'} and type(p['path']) is str and Path(p['path']).is_absolute() and str(Path(p['path']))==p['path'] and '..' not in Path(p['path']).parts and re.fullmatch('[0-9a-f]{64}',p['sha256']) and type(p['bytes']) is int and 0<p['bytes']<=limit,'exact bounded local descriptor required');return p

def read_pin(p,limit=LIMIT):
 pin_shape(p,limit);path=Path(p['path']);meta=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(meta);identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(stat.S_ISREG(a.st_mode) and a.st_uid in (0,os.geteuid()) and not a.st_mode&0o022 and a.st_size==p['bytes'],'owned regular descriptor only');fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:b=os.read(fd,a.st_size+1);need(len(b)==a.st_size and identity(os.fstat(fd))==identity(a)==identity(path.lstat()),'descriptor inode drift')
  finally:os.close(fd)
  need(hashlib.sha256(b).hexdigest()==p['sha256'],'descriptor hash drift');return b
 finally:os.close(meta)
def profile_shape(p):
 need(p['schema']=='maclab.device-test-profile/1' and re.fullmatch('[A-Za-z0-9_-]{1,80}',p['id']) and re.fullmatch('[a-z0-9-]{1,24}',p['device']) and re.fullmatch('apple,j[a-z0-9]+',p['board']) and type(p['dt_model']) is str and p['dt_model'],'finite exact profile identity');need(p['recovery_modes']==['network-only','serial-assisted'] and type(p['execution_ready']) is bool,'explicit recovery mode/profile readiness');o=p['original'];need(o['kind'] in ('installed','custom-current-state') and type(o['kernel']) is str and 1<=len(o['kernel'])<=128,'actual original kernel strategy');need(type(o['package_versions']) is dict and type(o['absent_packages']) is list and not set(o['package_versions'])&set(o['absent_packages']),'original package presence policy contradiction');slots=p['candidate']['artifact_slots'];need(type(slots) is dict and 1<=len(slots)<=16,'finite artifact slots')
 for n,a in slots.items():
  need(re.fullmatch('[A-Za-z0-9_.+-]{1,80}',n) and a['kind'] in ('arch-package','kernel-image','kernel-config','provider-ledger','stage2-bundle','opaque-reviewed') and re.fullmatch('[0-9a-f]{64}',a['sha256']) and type(a['bytes']) is int and 0<a['bytes']<=512*1024**2,'typed reviewed artifact slot')
  if a['kind']=='arch-package':need(a['metadata']['pkgname']==n and a['metadata']['arch'] in ('aarch64','any') and a['metadata']['pkgver']==a['version'],'exact package metadata slot')
 roles=p['sources'];need(set(roles)=={'capture','owner','rollback','final_restore'},'four explicit device source roles required')
 for role,value in roles.items():
  pin_shape(value['source']);need(type(value['closure']) is list and len(value['closure'])<=64,'finite device source-role closure')
  for pin in value['closure']:pin_shape(pin,64*1024**2)
 need(len(o['package_versions'])<=64 and len(o['absent_packages'])<=64 and len(set(o['absent_packages']))==len(o['absent_packages']) and all(type(n) is str and re.fullmatch('[A-Za-z0-9@_.+-]{1,128}',n) and type(v) is str and 0<len(v)<=200 for n,v in o['package_versions'].items()) and all(type(n) is str and re.fullmatch('[A-Za-z0-9@_.+-]{1,128}',n) for n in o['absent_packages']),'bounded explicit package presence policy')
 c=p['compiler'];pin_shape(c['source']);need(c['call'] in ('compile_oneshot','compile_device') and type(c['closure']) is list and len(c['closure'])<=512,'finite reviewed compiler')
 for pin in c['closure']:pin_shape(pin,64*1024**2)
 r=p['restore'];need(type(r['phase_order']) is list and r['phase_order'] and len(r['phase_order'])<=256 and len(set(r['phase_order']))==len(r['phase_order']) and r['final_kernel']==o['kernel'] and type(r['required_status']) is str and r['required_status'] and type(r['boot_package_must_be_absent']) is bool,'explicit final restoration contract');need(not r['boot_package_must_be_absent'] or 'omarchy-mac-boot' in o['absent_packages'],'boot package absent restore policy mismatch')
 return p

def load(catalog_pin,profile_id,device,execution=False):
 c=unique(read_pin(catalog_pin));need(c['schema']=='maclab.device-test-catalog/1' and c['status']=='ROOT_SOURCE_REVIEWED' and c['reviewed_by'] and type(c['profiles']) is dict and 1<=len(c['profiles'])<=16,'source-reviewed finite catalog required');need(profile_id in c['profiles'],'UNSUPPORTED_PROFILE: no reviewed adapter in selected catalog');pp=pin_shape(c['profiles'][profile_id]);p=profile_shape(unique(read_pin(pp)));need(p['id']==profile_id and p['device']==device,'UNSUPPORTED_DEVICE_PROFILE: no alias/substitution to another Mac')
 if execution:need(p['execution_ready'] is True,'UNSUPPORTED_PROFILE_PENDING_ADAPTER: catalog presence is not execution qualification');runtime_contract(p)
 return p,pp

def baseline(d,p,mode):
 need(mode in p['recovery_modes'] and d['name']==p['device'] and d['kernel']==p['original']['kernel'],'exact requested device/current kernel mismatch');f=d['facts'];need(f['machine']=='aarch64','actual architecture mismatch')
 if 'compatible' in f:need(type(f['compatible']) is list and f['compatible'] and f['compatible'][0]==p['board'],'actual physical board mismatch')
 if 'dt_model' in f:need(f['dt_model']==p['dt_model'],'contradictory actual model')
 need('compatible' in f or f.get('dt_model')==p['dt_model'],'actual API model evidence absent');need(d['alive'] is True and d['state']=='ready' and not d.get('active_job') and not d.get('queued') and 'maclab.job=' not in d['cmdline'],'actual ordinary idle baseline required')
 policy=p.get('baseline_capabilities',{})
 for n,v in policy.get('facts',{}).items():need(f.get(n)==v and type(f.get(n)) is type(v),'actual reviewed capability mismatch: '+n)
 if 'known_good' in policy:need(d.get('known_good')==policy['known_good'],'known-good policy mismatch')
 return {'device':p['device'],'board':p['board'],'model_basis':'api-compatible' if 'compatible' in f else 'api-dt_model','exact_target_board_proof_required':True,'current_kernel':d['kernel'],'package_presence_requires_target_owner_proof':True,'restore_strategy':p['restore']['strategy']}

def request_slots(request,p):
 slots=p['candidate']['artifact_slots'];given=request['artifacts'];need(type(given) is dict and set(given)==set(slots),'exact profile artifact slots required');return {n:{'path':given[n],**{k:slots[n][k] for k in ('sha256','bytes')}} for n in slots}

def normalize_request(request,p):
 need(request['device']==p['device'] and request['recovery_mode'] in p['recovery_modes'],'explicit device/mode differs from selected profile')
 if 'artifacts' in request:return request
 roles=p['candidate'].get('input_roles');need(type(roles) is dict,'profile has no legacy CLI role mapping; use exact artifacts map');given={}
 for role in ('kernel','kernel_headers','bootloader'):
  if role in request:need(role in roles and roles[role] in p['candidate']['artifact_slots'],'unsupported named artifact role');given[roles[role]]=request[role]
 for name,path in request.get('mesa_packages',{}).items():need(name in roles.get('mesa_packages',[]),'unsupported Mesa split role');given[name]=path
 if 'kernel_headers' in roles and roles['kernel_headers'] not in given:
  header=p['candidate']['artifact_slots'][roles['kernel_headers']];need('file' in header and 'kernel' in request,'explicit matching headers required');given[roles['kernel_headers']]=str(Path(request['kernel']).parent/header['file'])
 return {'schema':'maclab.boot-test-request/2','device':request['device'],'recovery_mode':request['recovery_mode'],'artifacts':given}

def validate_plan(plan,p,packet,mode,source_files):
 need(p['execution_ready'] is True and plan['schema']=='maclab.workflow/1' and plan['device']==p['device'] and plan['id']==Path(packet).name and plan['inputs']['recovery_mode']==mode and plan['inputs']['recovery_transaction']==Path(packet).name,'compiled device/transaction/mode differs');ids=[x['id'] for x in plan['phases']];order=p['restore']['phase_order'];need(all(n in ids for n in order) and [ids.index(n) for n in order]==sorted(ids.index(n) for n in order),'required actual restoration phase order missing')
 for h in plan['helpers'].values():
  for pin in [h['python'],h['source'],*h.get('closure',[])]:need(source_files.get(pin['path'])==pin,'unreviewed adapter source/closure')
 need(plan['inputs']['restoration_contract']==p['restore'],'compiled original-state restoration contract drift');return True

def runtime_contract(p):
 r=p['restore'];e=r.get('runtime_evidence');need(type(e) is dict and set(e)=={'audit_phase','audit_pointer','verdict_phase','final_assertion_phase','checks','bindings','absent_package_checks'},'UNSUPPORTED_PROFILE_RUNTIME_CONTRACT_INCOMPLETE')
 for key in ('audit_phase','verdict_phase','final_assertion_phase'):need(e[key] in r['phase_order'],'runtime evidence phase absent from reviewed order')
 need(e['audit_pointer']=='' or e['audit_pointer'].startswith('/'),'literal audit JSON pointer');need(type(e['checks']) is dict and len(e['checks'])<=64 and all(k.startswith('/') for k in e['checks']),'finite literal restoration checks');need(set(e['bindings'])=={'packet','plan_sha256','boot_id'} and all(type(v) is str and v.startswith('/') for v in e['bindings'].values()),'actual audit identity pointers');need(set(e['absent_package_checks'])==set(p['original']['absent_packages']),'every originally absent package needs an actual proof selector')
 for row in e['absent_package_checks'].values():need(set(row)=={'pointer','equals'} and row['pointer'].startswith('/'),'finite absent-package check')
 if any(a['kind']=='stage2-bundle' for a in p['candidate']['artifact_slots'].values()):
  keys={'manifest_sha256','candidate_loader_sha256','original_boot_sha256','candidate_boot_sha256','original_runtime_tag_sha256','candidate_runtime_tag_sha256','stage1_runtime_tag_sha256','source_commit'};native=p['candidate'].get('native_stage2');need(type(native) is dict and set(native)==keys and all(re.fullmatch('[0-9a-f]{40}' if k=='source_commit' else '[0-9a-f]{64}',v) for k,v in native.items()) and p['compiler'].get('stage2_job_runtime_proof') is True and r.get('stage2_original_runtime_proof_required') is True,'genuine Stage2 runtime/restore proof integration unsupported')
 return e
