#!/usr/bin/env python3
"""Fixed supplement continuation for an actual newly captured main backup.
No recapture of main, profile rewrite, package/ESP/service/default/boot action.
"""
import argparse,base64,hashlib,importlib.util,json,os,shlex,sys
from pathlib import Path
SDK_SHA='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
SUPPLEMENT_SHA='c29ae63f9de7169146318ed48c7cf0c14c3463af395aba0ffab0124f9ffa2bf6'
AUTHORITY_SHA='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def sdk():
 p=Path(__file__).with_name('frozen-controller-ea3.py');b=p.read_bytes();need(H(b)==SDK_SHA,'accepted transport closure drift');m=type(sys)('accepted_m1_transport');m.__file__=str(p);exec(compile(b,str(p),'exec'),m.__dict__);return m
REMOTE=r'''import base64,hashlib,json,os,re,stat,sys,time
from pathlib import Path
q=json.loads(sys.argv[1]);P=Path(q['packet']);H=lambda b:hashlib.sha256(b).hexdigest()
def need(v,msg):
 if not v:raise RuntimeError(msg)
def key(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,limit=1048576):
 meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(meta);need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and not a.st_mode&0o022 and a.st_size<=limit,'unsafe bounded regular input')
  fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   need(key(os.fstat(fd))==key(a),'held inode drift');data=bytearray();h=hashlib.sha256();total=0
   while total<a.st_size:
    chunk=os.read(fd,min(1048576,a.st_size-total));need(chunk,'short input');data.extend(chunk);h.update(chunk);total+=len(chunk)
   need(not os.read(fd,1) and key(os.fstat(fd))==key(a)==key(p.lstat()),'source path/size drift');return bytes(data),h.hexdigest(),a
  finally:os.close(fd)
 finally:os.close(meta)
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def write_once(name,b):
 p=P/name
 if os.path.lexists(p):need(read(p)[0]==b,'different existing supplement input; no overwrite');return
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(b)
  while view:n=os.write(fd,view);need(n>0,'short input write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 syncdir(P);need(read(p)[0]==b,'supplement input readback')
need(os.geteuid()==0 and os.uname().machine=='aarch64' and os.uname().release=='7.2.11-6-1-ARCH','root M1 original6 required')
need(re.fullmatch('/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}',str(P)),'fresh M1 packet path')
for a in [P,*P.parents]:
 st=a.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'unsafe packet ancestry')
need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==q['boot_id'],'actual current boot changed')
need(Path('/proc/device-tree/compatible').read_bytes().split(b'\0')[0]==b'apple,j293','M1 J293 only')
need(b'maclab.job=' not in Path('/proc/cmdline').read_bytes() and not os.path.lexists('/var/lib/pacman/db.lck'),'normal idle original6 required')
marker=json.loads(read(P/'CACHE-PROFILE.json')[0]);need(marker['profile_sha256']==q['profile_sha256'] and marker['source_packet']==q['source_packet'],'original packet ownership mismatch')
main_raw,main_sha,_=read(P/'original-backup/BACKUP-RECEIPT.json');main=json.loads(main_raw)
need(main_sha==q['main_receipt_sha256'] and main['packet']==str(P) and main['boot_id']==q['boot_id'] and main['status']=='LOCAL_BACKUP_VERIFIED_ONLY' and main['script_sha256']=='67a36275efc2c188599a03ab850b02ad6f0b8b7d8b61fb0cba22b5c0339258a4','genuine fresh main receipt required')
need(read(P/'BACKUP-SOURCE-FREEZE.json')[1]==q['source_freeze_sha256'],'actual source-freeze drift')
authority_raw,authority_sha,_=read(P/'STANDING-BOOT-AUTHORITY.json',65536);authority=json.loads(authority_raw)
need(authority_sha==q['authority_sha256']=='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365' and authority['authorization_is_persistent'] is True and authority['manual_saved_work_confirmed'] is False and authority['manual_nearby_recovery_confirmed'] is False and authority['does_not_lift_existing_holds'] is True,'standing authority scope/facts drift')
if q['operation']=='stage':
 raw=base64.b64decode(q['source_base64'],validate=True);need(H(raw)==q['source_sha256']=='c29ae63f9de7169146318ed48c7cf0c14c3463af395aba0ffab0124f9ffa2bf6','reviewed supplementary source drift')
 scope=q['scope'];need(scope['packet']==str(P) and scope['boot_id']==q['boot_id'] and scope['main_receipt_sha256']==main_sha and scope['backup_source_freeze_sha256']==q['source_freeze_sha256'] and scope['manual_saved_work_confirmed'] is False and scope['manual_nearby_recovery_confirmed'] is False,'supplement data scope mismatch')
 need(scope['standing_authority_sha256']==authority_sha and scope['source_reviewed_by'],'root-reviewed source scope missing')
 write_once('backup-supplement.py',raw);write_once('supplement-binding.json',(json.dumps(scope,indent=2)+'\n').encode())
 print(json.dumps({'status':'SUPPLEMENT_INPUTS_STAGED_ONLY','packet':str(P),'boot_id':q['boot_id'],'main_receipt_sha256':main_sha,'supplement_source_sha256':H(raw),'package_or_boot_changes':False}))
elif q['operation']=='capture':
 need(read(P/'backup-supplement.py')[1]==q['source_sha256']=='c29ae63f9de7169146318ed48c7cf0c14c3463af395aba0ffab0124f9ffa2bf6','reviewed source drift')
 need(not os.path.lexists(P/'original-boot-supplement-r2'),'supplement exists; reconcile genuine outcome instead of replay')
 os.execv('/usr/bin/python3',['/usr/bin/python3','-E','-B',str(P/'backup-supplement.py'),'--authorize-backup-supplement','--packet',str(P),'--binding',str(P/'supplement-binding.json')])
elif q['operation']=='collect':
 raw,sha,_=read(P/'original-boot-supplement-r2/SUPPLEMENT-RECEIPT.json');need(sha==q['receipt_sha256'],'actual supplemental receipt drift');r=json.loads(raw)
 need(r['packet']==str(P) and r['boot_id']==q['boot_id'] and r['v1_target_receipt_sha256']==main_sha and r['status']=='LOCAL_SUPPLEMENT_VERIFIED_ONLY' and r['supplement_script_sha256']==q['source_sha256'],'actual supplemental identity/source mismatch')
 objects={}
 for name,pin in r['objects'].items():
  need(Path(name).name==name,'invalid object leaf');_,h,s=read(P/'original-boot-supplement-r2'/name,67108864);need(h==pin['sha256'] and s.st_size==pin['bytes'],'actual supplemental object drift');objects[name]={'sha256':h,'bytes':s.st_size,'identity':key(s)}
 print(json.dumps({'status':'ACTUAL_SUPPLEMENT_COLLECTED_ONLY','packet':str(P),'boot_id':q['boot_id'],'receipt':r,'receipt_sha256':sha,'receipt_base64':base64.b64encode(raw).decode(),'objects':objects,'independent_retention_claim':False,'package_or_boot_changes':False}))
else:raise RuntimeError('unsupported fixed operation')
'''
def run(binding,api=None):
 c=sdk();p=binding['profile'];op=binding['operation'];need(op in ('stage','capture','collect'),'fixed supplement operation required');need(binding['source_root_plan_sha256'] and binding['source_reviewed_by'],'actual source-plan/root source review required')
 main=binding['main_collection'];raw=base64.b64decode(main['receipt_base64'],validate=True);r=json.loads(raw);need(H(raw)==main['receipt_sha256'] and r==main['receipt'] and r['packet']==p['packet'] and r['boot_id']==binding['expected_boot_id'],'actual main capture binding drift')
 source=c.read_pin(binding['supplement_source']);need(H(source)==SUPPLEMENT_SHA,'reviewed supplement source changed')
 client=api or c.API(c.config());d=client.request('/api/devices/m1');bounded={'expected_boot_id':binding['expected_boot_id'],'expected_kernel':'7.2.11-6-1-ARCH'};c.state_gate(d,p,bounded,op!='collect',450)
 scope={'schema':'maclab.m1-fresh-supplement-binding/1','packet':p['packet'],'boot_id':binding['expected_boot_id'],'main_receipt_sha256':main['receipt_sha256'],'backup_source_freeze_sha256':main['source_freeze_sha256'],'old_boot_bin':binding['old_boot_bin'],'source_reviewed_by':binding['source_reviewed_by'],'standing_authority_sha256':AUTHORITY_SHA,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False}
 payload={'operation':op,'packet':p['packet'],'boot_id':binding['expected_boot_id'],'source_packet':p['source_packet'],'profile_sha256':H(json.dumps(p,sort_keys=True,separators=(',',':')).encode()),'main_receipt_sha256':main['receipt_sha256'],'source_freeze_sha256':main['source_freeze_sha256'],'authority_sha256':AUTHORITY_SHA,'source_sha256':SUPPLEMENT_SHA}
 if op=='stage':payload.update(source_base64=base64.b64encode(source).decode(),scope=scope)
 if op=='collect':payload['receipt_sha256']=binding['receipt_sha256']
 command=shlex.join(['/usr/bin/python3','-E','-B','-c',REMOTE,json.dumps(payload,separators=(',',':'))]);need(len(command.encode())<=120000,'fixed supplement transport ceiling')
 result=client.request('/api/devices/m1/exec',{'command':command,'timeout_sec':360 if op=='capture' else 120},450 if op=='capture' else 210)
 if result['exit_code']!=0 or result.get('via')!='agent':return {'status':'M1_SUPPLEMENT_FAILED','actual_exec':result,'operation':op}
 out=json.loads(result['stdout']);return {'status':'M1_SUPPLEMENT_'+op.upper()+'_OBSERVED','actual_exec':result,'target':out,'packet':p['packet'],'boot_id':binding['expected_boot_id'],'source_root_plan_sha256':binding['source_root_plan_sha256']}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())),separators=(',',':')))
