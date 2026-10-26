#!/usr/bin/env python3
"""Fixed M1 same-cohort adapter; data only, no package-owner reimplementation.
Executed directly by the existing lab agent through its authenticated exec API.
No shell/argv templates. Cache work never changes packages, ESP, refs or services.
"""
import argparse, base64, contextlib, fcntl, hashlib, json, os, re, stat, subprocess, sys, time, types
from pathlib import Path

MAX_JSON=4*1024**2
HEX=re.compile(r'^[0-9a-f]{64}$')
PACKET=re.compile(r'^/var/lib/maclab/rc7-m1-[A-Za-z0-9_-]{1,96}$')
FICLONE=0x40049409

def need(v,why):
 if not v:raise RuntimeError(why)
def digest(b):return hashlib.sha256(b).hexdigest()
def key(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def private_dir(p,uid=0):
 p=Path(p)
 for q in (p,*p.parents):
  s=q.lstat();need(stat.S_ISDIR(s.st_mode) and not q.is_symlink() and s.st_uid in (0,uid) and (not s.st_mode&0o022 or (q!=p and s.st_uid==0 and s.st_mode&stat.S_ISVTX)),'unsafe root-owned ancestry')
 return p
@contextlib.contextmanager
def held_regular(path,max_bytes=256*1024**2,uid=0):
 path=Path(path);meta=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(meta);need(stat.S_ISREG(a.st_mode) and a.st_uid==uid and not a.st_mode&0o022 and a.st_size<=max_bytes,'unsafe/nonregular bounded source')
  fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   need(key(os.fstat(fd))==key(a),'reopened source drift');yield fd,a
   need(key(os.fstat(fd))==key(a)==key(path.lstat()),'source path/inode drift')
  finally:os.close(fd)
 finally:os.close(meta)
def hash_fd(fd,size,deadline):
 h=hashlib.sha256();off=0
 while off<size:
  need(time.monotonic()<deadline,'archive hash deadline');b=os.pread(fd,min(1024**2,size-off),off);need(b,'short source read');h.update(b);off+=len(b)
 need(not os.pread(fd,1,size),'file exceeded expected bound');return h.hexdigest()
def verify(path,pin,deadline,uid=0):
 need(HEX.fullmatch(pin['sha256']) and 0<pin['bytes']<=256*1024**2,'invalid archive pin')
 with held_regular(path,pin['bytes'],uid) as (fd,s):
  need(s.st_size==pin['bytes'] and hash_fd(fd,s.st_size,deadline)==pin['sha256'],'archive hash/size mismatch');return {'sha256':pin['sha256'],'bytes':s.st_size,'identity':key(s)}
def read_json(path,uid=0):
 with held_regular(path,MAX_JSON,uid) as (fd,s):b=os.pread(fd,s.st_size+1,0);need(len(b)==s.st_size,'JSON size drift');return json.loads(b)
def write_once(path,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  need(os.write(fd,raw)==len(raw),'short receipt write');os.fsync(fd)
 finally:os.close(fd)
 syncdir(Path(path).parent)
 with held_regular(path,len(raw),os.geteuid()) as (fd,s):need(os.pread(fd,s.st_size,0)==raw,'receipt readback mismatch')
 return digest(raw)
def cache_lock(path,uid=0):
 if not os.path.lexists(path):
  fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600);os.fsync(fd);os.close(fd);syncdir(Path(path).parent)
 meta=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(meta);need(stat.S_ISREG(before.st_mode) and before.st_uid==uid and stat.S_IMODE(before.st_mode)==0o600,'unsafe cache lock object')
  fd=os.open('/proc/self/fd/'+str(meta),os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
  need(key(os.fstat(fd))==key(before)==key(Path(path).lstat()),'cache lock inode drift');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd
 except BaseException:
  if 'fd' in locals():os.close(fd)
  raise
 finally:os.close(meta)

def current_observation(p,boot,deadline):
 versions={}
 for row in p['current_packages']:
  got=subprocess.check_output(['/usr/bin/pacman','-Q',row['name']],text=True,timeout=15).strip();need(got==row['name']+' '+row['version'],'current package cohort changed');versions[row['name']]=row['version']
 observed={};mismatch=[]
 for name,pin in p['original_file_pins'].items():
  q=Path(name)
  if pin.get('absent'):
   observed[name]={'absent':not os.path.lexists(q)}
   if os.path.lexists(q):mismatch.append(name)
  else:
   with held_regular(q,64*1024**2) as (fd,st):h=hash_fd(fd,st.st_size,deadline);observed[name]={'sha256':h,'bytes':st.st_size,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}
   if h!=pin['sha256']:mismatch.append(name)
 source=Path(p['source_packet'])/'transact-m1.py';verify(source,p['observation_owner'],deadline)
 with held_regular(source,MAX_JSON) as (fd,st):raw=os.pread(fd,st.st_size,0)
 owner=types.ModuleType('reviewed_observation_owner');owner.__file__=str(source);exec(compile(raw,str(source),'exec'),owner.__dict__)
 module_root=Path('/usr/lib/modules')/p['old_kernel'];rows=owner.tree(module_root);module_sha=owner.tree_sha(rows);need(module_sha==p['old_module_tree_sha256'],'original modules changed')
 markers={}
 for version in [p['old_kernel'],p['candidate_kernel']]:
  for marker in ['.maclab-job','.maclab-owned','.keep-local-kernel']:
   name=str(Path('/usr/lib/modules')/version/marker);markers[name]=os.path.lexists(name);need(not markers[name],'unowned module marker prevents safe test preparation')
 parent=Path(os.readlink('/proc/'+str(os.getppid())+'/exe'))
 need('lab-agent' in parent.name,'current metadata must come directly from lab-agent')
 with held_regular(parent,64*1024**2) as (fd,st):parent_image={'path':str(parent),'sha256':hash_fd(fd,st.st_size,deadline),'bytes':st.st_size}
 return {'schema':'maclab.m1-fresh-observation/1','agent_parent':parent_image,'boot_id':boot,'kernel':os.uname().release,'packages':versions,'files':observed,'original_guard_mismatches':mismatch,'old_module_tree_sha256':module_sha,'module_markers':markers,'esp_free_bytes':os.statvfs('/boot/efi').f_bavail*os.statvfs('/boot/efi').f_frsize,'no_package_changes':True,'no_boot_changes':True,'historical_receipts_reused':False}

def exact_profile(p):
 need(p['schema']=='maclab.m1-cohort-profile/1' and p['device']=='m1' and p['board']=='apple,j293','wrong supported profile')
 need(PACKET.fullmatch(p['packet']) and PACKET.fullmatch(p['source_packet']) and p['packet']!=p['source_packet'],'new distinct M1 packet required')
 need(p['old_kernel']=='7.2.11-6-1-ARCH' and p['candidate_kernel']=='7.2.11-7-1-ARCH','this adapter only covers reviewed 6→7 cohort')
 rows=p['archives'];need(len(rows)==10 and len({x['relative'] for x in rows})==10,'exact five candidate and rollback archives required')
 counts={'packages':0,'rollback-packages':0}
 for row in rows:
  parts=Path(row['relative']).parts;need(len(parts)==2 and parts[0] in counts and parts[1] not in ('.','..') and HEX.fullmatch(row['sha256']) and 0<row['bytes']<=64*1024**2,'invalid bounded archive path/pin');counts[parts[0]]+=1
 need(counts=={'packages':5,'rollback-packages':5},'incoherent split cohort')
 return digest(json.dumps(p,sort_keys=True,separators=(',',':')).encode())
def gate(p,request):
 need(os.geteuid()==0 and os.uname().machine=='aarch64','real root AArch64 required')
 need(Path('/proc/device-tree/compatible').read_bytes().split(b'\0')[0]==p['board'].encode(),'wrong M1 board')
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();need(boot==request['expected_boot_id'],'fresh boot mismatch')
 need(os.uname().release==request['expected_kernel'] and os.uname().release in (p['old_kernel'],p['candidate_kernel']),'kernel mismatch')
 need(b'maclab.job=' not in Path('/proc/cmdline').read_bytes(),'genuine normal boot required for cohort preparation')
 need(not os.path.lexists('/var/lib/pacman/db.lck'),'package manager active')
 return boot

def inventory_cache(p,deadline,uid=0):
 src=private_dir(p['source_packet'],uid);results={}
 for row in p['archives']:results[row['relative']]=verify(src/row['relative'],row,deadline,uid)
 return results

def stage_cache(p,request,deadline,uid=0):
 """One target-local copy per hash; zero archive network transfer/chunk RPCs.
 No hardlinks: each new transaction keeps a separately verified inode. Interrupted
 copies resume only with an exact owned-inode receipt and verified source prefix.
 """
 profile_sha=exact_profile(p);src=private_dir(p['source_packet'],uid);dst=Path(p['packet']);private_dir(dst.parent,uid)
 if not os.path.lexists(dst):dst.mkdir(mode=0o700);syncdir(dst.parent)
 private_dir(dst,uid)
 lockfd=cache_lock(dst/'.cache.lock',uid)
 try:
  fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  marker=dst/'CACHE-PROFILE.json'
  if os.path.lexists(marker):need(read_json(marker,uid)=={'profile_sha256':profile_sha,'source_packet':str(src)},'foreign cache packet')
  else:
   need(set(x.name for x in dst.iterdir())=={'.cache.lock'},'refuse adoption of nonempty packet');write_once(marker,{'profile_sha256':profile_sha,'source_packet':str(src)})
  results={}
  for row in p['archives']:
   need(time.monotonic()<deadline,'cache stage deadline');relative=row['relative'];folder=dst/Path(relative).parent
   if not os.path.lexists(folder):folder.mkdir(mode=0o700);syncdir(dst)
   private_dir(folder,uid);final=dst/relative
   if os.path.lexists(final):results[relative]={**verify(final,row,deadline,uid),'reused':True};continue
   reserve=sum(x['bytes'] for x in p['archives'])+128*1024**2
   fs=os.statvfs(dst);need(fs.f_bavail*fs.f_frsize>=reserve,'rootfs cache-stage reserve insufficient')
   partial=folder/('.'+final.name+'.part');receipt=folder/('.'+final.name+'.owned.json')
   with held_regular(src/relative,row['bytes'],uid) as (sf,ss):
    need(ss.st_size==row['bytes'] and hash_fd(sf,ss.st_size,deadline)==row['sha256'],'retained source archive drift')
    if os.path.lexists(receipt):
     owned=read_json(receipt,uid);need(owned['profile_sha256']==profile_sha and owned['relative']==relative and owned['sha256']==row['sha256'],'wrong partial owner')
     meta=os.open(partial,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
     try:
      ps=os.fstat(meta);need(stat.S_ISREG(ps.st_mode) and ps.st_uid==uid and stat.S_IMODE(ps.st_mode)==0o600 and [ps.st_dev,ps.st_ino]==owned['inode'] and ps.st_size<=row['bytes'],'partial inode owner drift')
      pf=os.open('/proc/self/fd/'+str(meta),os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
     finally:os.close(meta)
     # Verify every previously copied byte; size alone is not a checkpoint.
     off=0
     while off<ps.st_size:
      need(time.monotonic()<deadline,'partial verification deadline');n=min(1024**2,ps.st_size-off);need(os.pread(pf,n,off)==os.pread(sf,n,off),'partial prefix mismatch');off+=n
     method='resumed-copy'
    else:
     need(not os.path.lexists(partial),'unrecorded partial; reconcile before touching')
     pf=os.open(partial,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600);ps=os.fstat(pf)
     try:write_once(receipt,{'profile_sha256':profile_sha,'relative':relative,'sha256':row['sha256'],'inode':[ps.st_dev,ps.st_ino]})
     except BaseException:os.close(pf);raise
     off=0;method='local-copy'
     try:fcntl.ioctl(pf,FICLONE,sf);off=row['bytes'];method='local-reflink'
     except OSError:need(os.fstat(pf).st_size==0,'partial reflink failure; reconcile')
    try:
     while off<row['bytes']:
      need(time.monotonic()<deadline,'copy deadline');b=os.pread(sf,min(1024**2,row['bytes']-off),off);need(b,'short retained archive');need(os.pwrite(pf,b,off)==len(b),'short cache write');off+=len(b)
     os.fsync(pf);now=os.fstat(pf);need([now.st_dev,now.st_ino]==[ps.st_dev,ps.st_ino] and now.st_size==row['bytes'],'partial identity/size drift')
    finally:os.close(pf)
    verified=verify(partial,row,deadline,uid)
    need(not os.path.lexists(final) and [partial.lstat().st_dev,partial.lstat().st_ino]==[ps.st_dev,ps.st_ino],'cache destination drift')
    # link+unlink commits without replacing any existing destination.
    os.link(partial,final,follow_symlinks=False);syncdir(folder)
    verified=verify(final,row,deadline,uid);need(final.lstat().st_ino==ps.st_ino,'commit inode mismatch');partial.unlink();syncdir(folder)
    results[relative]={**verified,'reused':False,'method':method,'archive_network_bytes':0}
  report={'schema':'maclab.m1-target-cache/1','profile_sha256':profile_sha,'packet':str(dst),'source_packet':str(src),'files':results,'archive_network_bytes':0,'package_changes':False,'boot_changes':False,'independent_retention_claim':False}
  write_once(dst/('CACHE-VERIFIED-'+str(time.time_ns())+'.json'),report);return report
 finally:os.close(lockfd)

def verify_owned_packet(p,uid=0):
 packet=private_dir(p['packet'],uid);owner=read_json(packet/'CACHE-PROFILE.json',uid)
 need(owner=={'profile_sha256':exact_profile(p),'source_packet':p['source_packet']},'fresh packet ownership mismatch');return packet

def prepared_files(p,request,kind):
 prepared=request['prepared_inputs'];need(prepared['packet']==p['packet'] and prepared['boot_id']==request['expected_boot_id'],'prepared input packet/boot drift')
 names={'backup-m1.py','backup-spec.json','backup-clearance.json','STANDING-BOOT-AUTHORITY.json','BACKUP-SOURCE-FREEZE.json'} if kind=='backup' else {'backup-supplement.py','supplement-binding.json'}
 need(set(prepared['files'])==names,'exact prepared input closure required')
 for name,row in prepared['files'].items():
  raw=base64.b64decode(row['base64'],validate=True);need(len(raw)==row['bytes']<=65536 and digest(raw)==row['sha256'],'prepared input hash/size drift')
  if name=='backup-m1.py':need(row['sha256']==p['backup_source']['sha256'] and row['bytes']==p['backup_source']['bytes'],'backup source changed')
  if name=='backup-supplement.py':need(row['sha256']==p['supplement_source']['sha256'] and row['bytes']==p['supplement_source']['bytes'],'supplement source changed')
  if name=='STANDING-BOOT-AUTHORITY.json':need(row['sha256']==p['authority_source']['sha256'],'standing authority changed')
 return prepared['files']

def stage_prepared(p,request,deadline,kind,uid=0):
 packet=verify_owned_packet(p,uid);files=prepared_files(p,request,kind);lock=cache_lock(packet/'.inputs.lock',uid)
 try:
  results={}
  for name,pin in files.items():
   q=packet/name;raw=base64.b64decode(pin['base64'],validate=True)
   if os.path.lexists(q):results[name]={**verify(q,pin,deadline,uid),'reused_exact_input':True};continue
   # A source/spec is immutable once written. On interrupted partial input,
   # refuse and retain it for reconciliation rather than overwrite/adopt.
   fd=os.open(q,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
   try:
    view=memoryview(raw)
    while view:need(time.monotonic()<deadline,'input staging deadline');n=os.write(fd,view);need(n>0,'short input write');view=view[n:]
    os.fsync(fd)
   finally:os.close(fd)
   syncdir(packet);results[name]={**verify(q,pin,deadline,uid),'reused_exact_input':False}
  return {'schema':'maclab.m1-prepared-inputs/1','status':'EXACT_INPUTS_STAGED_ONLY','kind':kind,'packet':str(packet),'files':results,'package_changes':False,'boot_changes':False}
 finally:os.close(lock)

def capture_original(p,request,deadline):
 packet=verify_owned_packet(p);files=prepared_files(p,request,'backup')
 for name,pin in files.items():verify(packet/name,pin,deadline)
 need(not os.path.lexists(packet/'original-backup'),'original capture exists; reconcile instead of replay')
 os.execv('/usr/bin/python3',['/usr/bin/python3','-E','-B',str(packet/'backup-m1.py'),'--packet',str(packet),'--spec',str(packet/'backup-spec.json'),'--clearance',str(packet/'backup-clearance.json')])

def capture_supplement(p,request,deadline):
 packet=verify_owned_packet(p);files=prepared_files(p,request,'supplement')
 for name,pin in files.items():verify(packet/name,pin,deadline)
 need(not os.path.lexists(packet/'original-boot-supplement-r2'),'supplement exists; reconcile instead of replay')
 os.execv('/usr/bin/python3',['/usr/bin/python3','-E','-B',str(packet/'backup-supplement.py'),'--authorize-backup-supplement','--packet',str(packet),'--binding',str(packet/'supplement-binding.json')])

def collect_capture(p,request,deadline,kind):
 packet=verify_owned_packet(p);relative='original-backup/BACKUP-RECEIPT.json' if kind=='backup' else 'original-boot-supplement-r2/SUPPLEMENT-RECEIPT.json';q=packet/relative
 with held_regular(q,MAX_JSON) as (fd,s):raw=os.pread(fd,s.st_size+1,0);need(len(raw)==s.st_size,'capture receipt size drift')
 need(digest(raw)==request['receipt_sha256'],'actual capture receipt drift');r=json.loads(raw)
 need(r['device']==p['device'] and r['packet']==p['packet'] and r['boot_id']==request['expected_boot_id'],'fresh capture identity mismatch')
 need(r['status']==('LOCAL_BACKUP_VERIFIED_ONLY' if kind=='backup' else 'LOCAL_SUPPLEMENT_VERIFIED_ONLY'),'capture did not complete')
 if kind=='backup':need(r['old_module_tree_sha256']==p['old_module_tree_sha256'] and r['script_sha256']==p['backup_source']['sha256'],'capture module/source drift')
 else:need(r['supplement_script_sha256']==p['supplement_source']['sha256'],'supplement source drift')
 objects={}
 for name,pin in r['objects'].items():need(Path(name).name==name,'invalid capture object leaf');objects[name]=verify(q.parent/name,pin,deadline)
 freeze=packet/'BACKUP-SOURCE-FREEZE.json'
 with held_regular(freeze,MAX_JSON) as (fd,s):freeze_raw=os.pread(fd,s.st_size,0)
 return {'schema':'maclab.m1-capture-collection/1','kind':kind,'packet':p['packet'],'boot_id':request['expected_boot_id'],'receipt':r,'receipt_base64':base64.b64encode(raw).decode(),'receipt_sha256':digest(raw),'source_freeze_sha256':digest(freeze_raw),'objects':objects,'package_changes':False,'boot_changes':False,'independent_retention_claim':False}

def dispatch_packet(p,request,deadline):
 """Preserve direct lab-agent parent: replace adapter, never subprocess owner.
 Reviewable fixed flag map only; source itself owns all package/recovery checks.
 """
 packet=private_dir(p['packet']);entry=request['entry'];table={'install':('transact-m1.py',[]),'restore-modules':('transact-m1.py',['--restore-old-only']),'verify-modules':('transact-m1.py',['--verify-retained-old']),'rollback-packages':('packet-c-old5.py',[])}
 need(entry in table,'unsupported fixed owner operation');name,flags=table[entry];pin=p['owner_sources'][name];verify(packet/name,pin,deadline)
 # This file is a root-reviewed fresh scope, not a copied historical clearance.
 auth=request['root_scope'];need(auth['packet']==str(packet) and auth['expected_boot_id']==request['expected_boot_id'] and auth['entries']==[entry] and HEX.fullmatch(auth['root_plan_sha256']),'entry/plan/current-boot scope mismatch')
 need(auth['manual_saved_work_confirmed'] is False and auth['manual_nearby_recovery_confirmed'] is False,'confirmation facts changed')
 verify(packet/'STANDING-BOOT-AUTHORITY.json',p['authority_source'],deadline)
 # A process replacement preserves the parent's direct-agent requirement.
 argv=['/usr/bin/python3','-E','-B',str(packet/name)]
 argv+=['--packet',str(packet),*flags]
 os.execv(argv[0],argv)

def main(request):
 p=request['profile'];profile_sha=exact_profile(p);boot=gate(p,request)
 if request['action'] not in ('inventory-cache','collect-backup','collect-supplement'):
  authority=base64.b64decode(request['standing_authority_b64'],validate=True);need(digest(authority)==p['authority_source']['sha256'],'authority source drift');a=json.loads(authority);scope=request['root_scope']
  need(a['authorization_is_persistent'] is True and a['manual_saved_work_confirmed'] is False and a['manual_nearby_recovery_confirmed'] is False and a['does_not_lift_existing_holds'] is True,'standing authority facts mismatch')
  need(scope['packet']==p['packet'] and scope['device']==p['device'] and scope['expected_boot_id']==boot and scope['authority_sha256']==digest(authority) and request['action'] in scope['operations'] and scope['reviewed_by'],'root scope mismatch')
  need(scope['manual_saved_work_confirmed'] is False and scope['manual_nearby_recovery_confirmed'] is False,'manual confirmations must remain factual')
 budget=int(request['deadline_seconds']);need(1<=budget<=1900,'phase deadline ceiling');action=request['action']
 if action=='invoke-packet':need(budget==1900,'full package-owner outer cleanup envelope required')
 elif action=='capture-original':need(budget==1200,'900s capture plus complete cleanup envelope required')
 else:need(budget<=900,'cache/metadata budget ceiling')
 deadline=time.monotonic()+budget
 if action=='inventory-cache':return {'status':'FRESH_METADATA_AND_CACHE_ONLY','profile_sha256':profile_sha,'boot_id':boot,'kernel':os.uname().release,'current':current_observation(p,boot,deadline),'files':inventory_cache(p,deadline),'package_changes':False,'boot_changes':False}
 if action=='stage-cache':return stage_cache(p,request,deadline)
 if action=='stage-backup-inputs':return stage_prepared(p,request,deadline,'backup')
 if action=='capture-original':capture_original(p,request,deadline)
 if action=='collect-backup':return collect_capture(p,request,deadline,'backup')
 if action=='stage-supplement-inputs':return stage_prepared(p,request,deadline,'supplement')
 if action=='capture-supplement':capture_supplement(p,request,deadline)
 if action=='collect-supplement':return collect_capture(p,request,deadline,'supplement')
 if action=='invoke-packet':dispatch_packet(p,request,deadline)
 raise RuntimeError('unsupported typed M1 action')
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path);a.add_argument('--request-json');x=a.parse_args();request=json.loads(x.binding.read_bytes()) if x.binding else json.loads(x.request_json);print(json.dumps(main(request),separators=(',',':')))
