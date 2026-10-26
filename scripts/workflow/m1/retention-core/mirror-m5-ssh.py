#!/usr/bin/env python3
"""M1 private backup -> existing M5 SSH/APFS, RAM-only controller transport. No CAS claim."""
if not __debug__:raise RuntimeError('optimized Python is forbidden')
import sys
sys.dont_write_bytecode=True
import argparse,base64,datetime,hashlib,importlib.util,json,os,re,selectors,shlex,signal,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;V1=HERE/'v1-executed-source';P='/var/lib/maclab/rc7-m1-cohort-reprobe-20261026-r1'
MAIN_SHA='aa14d80d5778bba85356f19251c6bdf633c2f6f72c04f0dd4c8f57ac845095bf';FREEZE='3c802e7a4ffd0f086531b1ebc696925c96851223bc79e2ac9434eaeb92bf57a9'
ROOT='/Users/chriskearney/.local/share/maclab/recovery-retained/rc7-m1-cohort-reprobe-20261026-r1'
SSH=['/usr/bin/ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=m5','-o','ConnectTimeout=10','chriskearney@m5.local']
NAMES={'boot.bin.original','kernel6.uki.original','limine.conf.original','kernel6-tree.tar.zst','boot-inputs.original.tar','state.original.json','kernel6-tree.original.jsonl'}
END=0
REMOTE=r'''if not __debug__:raise RuntimeError('optimized Python forbidden')
import hashlib,json,os,signal,socket,stat,sys
from pathlib import Path
BASE=Path('/Users/chriskearney/.local/share/maclab/recovery-retained')
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def verify(path,size,sha):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==size
  os.fsync(fd);h=hashlib.sha256();n=0
  while n<=size:
   x=os.read(fd,min(1048576,size+1-n))
   if not x:break
   h.update(x);n+=len(x)
  assert n==size and h.hexdigest()==sha and identity(os.fstat(fd))==identity(before)
 finally:os.close(fd)
 assert identity(os.lstat(path))==identity(before)
 return {'identity':identity(before),'sha256':sha,'bytes':size,'fsync_reopen_match':True}
def store(path,size,sha,source):
 assert 0<size<=2147483648
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  h=hashlib.sha256();n=0;before=os.fstat(fd)
  with os.fdopen(fd,'wb',closefd=False) as out:
   while n<size:
    data=source.read(min(1048576,size-n));assert data,'truncated stream'
    assert len(data)<=size-n;out.write(data);h.update(data);n+=len(data)
   assert not source.read(1),'extra stream data';out.flush();os.fsync(fd)
   after=os.fstat(fd);assert (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino) and after.st_size==size and h.hexdigest()==sha
 finally:os.close(fd)
 result=verify(path,size,sha);syncdir(path.parent);return result
def safe(p):
 for q in [p,*p.parents]:
  if not os.path.lexists(q):continue
  s=q.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid in [0,os.getuid()] and not s.st_mode&0o022,'unsafe retention ancestry'
def main():
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(RuntimeError('1800s remote deadline')));signal.alarm(1800);os.umask(0o077)
 action,root=sys.argv[1],Path(sys.argv[2]);assert str(root).startswith(str(BASE)+'/') and root.parent==BASE and root.name=='rc7-m1-cohort-reprobe-20261026-r1'
 assert sys.platform=='darwin' and Path.home()==Path('/Users/chriskearney')
 if action=='init':
  safe(BASE);assert not os.path.lexists(root);BASE.mkdir(parents=True,mode=0o700,exist_ok=True);safe(BASE)
  fs=os.statvfs(BASE);assert fs.f_bavail*fs.f_frsize>=int(sys.argv[3])+128*1024**2
  root.mkdir(mode=0o700)
  for g in ['main','supplement']:(root/g).mkdir(mode=0o700)
  syncdir(root);syncdir(BASE)
  print(json.dumps({'root':str(root),'storage_dev':root.stat().st_dev,'uid':os.getuid(),'mode':stat.S_IMODE(root.stat().st_mode),'free_bytes':fs.f_bavail*fs.f_frsize,'hostname':socket.gethostname(),'os':sys.platform,'controller_different_identity':True}));return
 safe(root);rel=sys.argv[3];parts=Path(rel).parts;assert len(parts) in [1,2] and all(x not in ['.','..'] and x and '/' not in x for x in parts)
 if len(parts)==2:assert parts[0] in ['main','supplement']
 else:assert rel=='MIRROR-RECEIPT.json'
 path=root/rel;safe(path.parent);size,sha=int(sys.argv[4]),sys.argv[5];assert len(sha)==64 and set(sha)<=set('0123456789abcdef')
 if action=='write':result=store(path,size,sha,sys.stdin.buffer)
 elif action=='verify':result=verify(path,size,sha)
 else:raise RuntimeError('unknown action')
 print(json.dumps(result))
if __name__=='__main__':main()
'''
def cancel(n,_f):raise RuntimeError('mirror cancelled '+str(n))
def stop(p):
 if p.poll() is None:
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
 p.wait()
def start_ssh(action,args):
 assert time.monotonic()<END
 command=shlex.join(['/usr/bin/python3','-E','-B','-c',REMOTE,action,ROOT,*args]);assert len(command.encode())<120000
 return subprocess.Popen([*SSH,command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
def finish(p):
 p.stdin.close();p.stdin=None
 out,err=p.communicate(timeout=max(1,min(300,END-time.monotonic())));assert len(out)<=262144 and len(err)<=16384 and p.returncode==0,'M5 SSH writer/verify refused; preserve prefix/no retry'
 return json.loads(out)
def send(p,data):
 os.set_blocking(p.stdin.fileno(),False);view=memoryview(data);deadline=min(END,time.monotonic()+60);sel=selectors.DefaultSelector();sel.register(p.stdin,selectors.EVENT_WRITE)
 try:
  while view:
   assert time.monotonic()<deadline and p.poll() is None,'SSH stdin blocked/exited'
   if not sel.select(.2):continue
   try:n=os.write(p.stdin.fileno(),view);view=view[n:]
   except BlockingIOError:pass
 finally:sel.close()
def control(action,args):
 p=start_ssh(action,args)
 try:return finish(p)
 finally:stop(p)
def main():
 global END
 ap=argparse.ArgumentParser();ap.add_argument('--source-holder',required=True);ap.add_argument('--supplement-receipt-sha256');a=ap.parse_args();END=time.monotonic()+1800
 for sig in [signal.SIGTERM,signal.SIGHUP,signal.SIGINT]:signal.signal(sig,cancel)
 for n,h in {'backup-m1.py':'67a36275efc2c188599a03ab850b02ad6f0b8b7d8b61fb0cba22b5c0339258a4','stage-controller.py':'7dff1c9da9c8d097ebfe88d2f0aea4c22c5eef137ed02d384c8cea466ee3d3ad','retain-controller.py':'66ee32ba1561e7637eb27fe460330645c50d211280adf55167de24a2d29af71d'}.items():assert hashlib.sha256((V1/n).read_bytes()).hexdigest()==h
 sp=importlib.util.spec_from_file_location('v1_reader',V1/'retain-controller.py');v=importlib.util.module_from_spec(sp);sp.loader.exec_module(v)
 sp=importlib.util.spec_from_file_location('v1_gate',V1/'stage-controller.py');gate=importlib.util.module_from_spec(sp);sp.loader.exec_module(gate)
 c=json.loads((Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/'maclab/client.json').read_bytes());c={'url':os.environ.get('MACLAB_URL',c['url']),'token':os.environ.get('MACLAB_TOKEN',c['token']),'lease_holder':a.source_holder}
 start=gate.state_gate(c,a.source_holder,2100)
 def read(path,off,n,final=False):
  assert time.monotonic()<END;return v.exec_read(c,path,off,n,final)
 def receipt(path,want):
  assert re.fullmatch('[0-9a-f]{64}',want);r=read(path,0,262144);blob=base64.b64decode(r['data'],validate=True);ident=r['identity'];assert r['offset']==0 and r['length']==ident[5]==len(blob) and len(blob)<=262144 and hashlib.sha256(blob).hexdigest()==want
  last=read(path,len(blob),0,True);assert last['identity']==ident and last['sha256']==want
  return json.loads(blob),blob
 main_receipt,blob=receipt(P+'/original-backup/BACKUP-RECEIPT.json',MAIN_SHA);assert main_receipt['schema']=='maclab.rc-m1-original-backup/1' and main_receipt['status']=='LOCAL_BACKUP_VERIFIED_ONLY' and main_receipt['packet']==P and set(main_receipt['objects'])==NAMES
 groups={'main':{'source_root':P+'/original-backup/','receipt_sha256':MAIN_SHA,'objects':{**main_receipt['objects'],'BACKUP-RECEIPT.json':{'sha256':MAIN_SHA,'bytes':len(blob)}}}}
 if a.supplement_receipt_sha256:
  sr,sb=receipt(P+'/original-boot-supplement-r1/SUPPLEMENT-RECEIPT.json',a.supplement_receipt_sha256)
  assert sr['schema']=='maclab.rc-m1-backup-supplement/1' and sr['status']=='LOCAL_SUPPLEMENT_VERIFIED_ONLY' and sr['packet']==P and sr['v1_target_receipt_sha256']==MAIN_SHA and set(sr['objects'])=={'boot.bin.old.original','boot-metadata.original.json'}
  assert sr['objects']['boot.bin.old.original']=={'sha256':'fc1da19d9a13b47304866ed42c52683901fd31dc7521e15e235b956b8e379e4d','bytes':9707724}
  groups['supplement']={'source_root':P+'/original-boot-supplement-r1/','receipt_sha256':a.supplement_receipt_sha256,'objects':{**sr['objects'],'SUPPLEMENT-RECEIPT.json':{'sha256':a.supplement_receipt_sha256,'bytes':len(sb)}}}
 total=sum(pin['bytes'] for g in groups.values() for pin in g['objects'].values());assert total<=3*1024**3 and all(0<pin['bytes']<=2*1024**3 and re.fullmatch('[0-9a-f]{64}',pin['sha256']) for g in groups.values() for pin in g['objects'].values())
 storage=control('init',[str(total)]);assert storage['root']==ROOT and storage['os']=='darwin' and storage['mode']==0o700;proofs={}
 for group,g in groups.items():
  proofs[group]={}
  for name,pin in g['objects'].items():
   path=g['source_root']+name;rel=group+'/'+name;p=start_ssh('write',[rel,str(pin['bytes']),pin['sha256']]);off=0;identity=None;h=hashlib.sha256();chunks=0
   try:
    while off<pin['bytes']:
     r=read(path,off,min(262144,pin['bytes']-off));data=base64.b64decode(r['data'],validate=True)
     if identity is None:identity=r['identity'];assert identity[5]==pin['bytes']
     assert r['identity']==identity and r['offset']==off and r['length']==len(data)==min(262144,pin['bytes']-off)
     send(p,data);h.update(data);off+=len(data);chunks+=1
    assert h.hexdigest()==pin['sha256'];remote=finish(p)
    assert remote['sha256']==pin['sha256'] and remote['bytes']==pin['bytes'] and remote['fsync_reopen_match']
    final=read(path,off,0,True);assert final['identity']==identity and final['sha256']==pin['sha256']
    proofs[group][name]={**pin,'source_path':path,'source_identity':identity,'source_full_hash_match':True,'remote_path':ROOT+'/'+rel,'remote_identity':remote['identity'],'remote_fsync_reopen_match':True,'source_chunks':chunks}
   finally:stop(p)
 # Terminal complete-source and remote reopen verification, then receipt retained on M5.
 for group,items in proofs.items():
  for name,pin in items.items():
   final=read(pin['source_path'],pin['bytes'],0,True);remote=control('verify',[group+'/'+name,str(pin['bytes']),pin['sha256']]);assert final['identity']==pin['source_identity'] and final['sha256']==remote['sha256']==pin['sha256'] and remote['identity']==pin['remote_identity'] and remote['fsync_reopen_match']
 end=gate.state_gate(c,a.source_holder,60)
 result={'schema':'maclab.rc-m1-independent-remote-retention/1','status':'INDEPENDENT_REMOTE_RETENTION_VERIFIED','backend':'remote-ssh-m5','device':'m1','packet':P,'v1_target_receipt_sha256':MAIN_SHA,'v1_source_freeze_sha256':FREEZE,'mirror_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'source_start':start,'source_end':end,'destination':{'device':'m5','ssh_route':SSH,'storage':storage,'identity_basis':'root-verified distinct Darwin M5 known-host SSH route; no Linux machine-id claim'},'groups':proofs,'supplement_target_receipt_sha256':a.supplement_receipt_sha256,'original_file_pins':main_receipt['original_file_pins'],'old_module_tree_sha256':main_receipt['old_module_tree_sha256'],'rollback_copy_pins':{**main_receipt['rollback_copy_pins'],'original-backup/BACKUP-RECEIPT.json':MAIN_SHA},'controller_ram_transport_only':True,'controller_durable_copy_claimed':False,'cas_claimed':False,'package_mutation':False,'reboot':False}
 data=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode();assert len(data)<=262144;sha=hashlib.sha256(data).hexdigest();p=start_ssh('write',['MIRROR-RECEIPT.json',str(len(data)),sha])
 try:send(p,data);done=finish(p);assert done['sha256']==sha and done['fsync_reopen_match']
 finally:stop(p)
 print(json.dumps({'status':result['status'],'backend':result['backend'],'receipt_path':ROOT+'/MIRROR-RECEIPT.json','receipt_sha256':sha,'receipt_bytes':len(data),'groups':{g:len(x) for g,x in proofs.items()},'total_bytes':total,'controller_ram_transport_only':True,'controller_durable_copy_claimed':False,'cas_claimed':False,'package_mutation':False,'reboot':False}))
if __name__=='__main__':main()
