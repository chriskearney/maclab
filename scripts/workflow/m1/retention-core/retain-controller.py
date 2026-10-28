#!/usr/bin/env python3
"""Controller private durable retention + existing lab upload/CAS readback.
No credentials on Mac. No public endpoint, service, job, target install or boot.
"""
if not __debug__:raise RuntimeError("optimized Python is forbidden")
import argparse,hashlib,importlib.util,json,os,re,shlex,stat,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('backup',HERE/'backup-m1.py');b=importlib.util.module_from_spec(sp);sp.loader.exec_module(b)
NAMES={'boot.bin.original','kernel6.uki.original','limine.conf.original','kernel6-tree.tar.zst','boot-inputs.original.tar','state.original.json','kernel6-tree.original.jsonl'}
CHUNK=256*1024
REMOTE_READ=r"""if not __debug__:raise RuntimeError("optimized Python is forbidden")
import os,stat,sys,json,base64,hashlib
p,off,n,final=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),sys.argv[4]=='1'
assert 0<=off<=2147483648 and 0<=n<=262144
m=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 s=os.fstat(m);assert stat.S_ISREG(s.st_mode) and s.st_size<=2147483648
 key=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 before=key(s);assert off<=s.st_size
 fd=os.open('/proc/self/fd/'+str(m),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  assert key(os.fstat(f.fileno()))==before
  if final:
   assert off==s.st_size and n==0;h=hashlib.sha256();total=0
   while total<=s.st_size:
    z=f.read(min(1048576,s.st_size+1-total))
    if not z:break
    total+=len(z);h.update(z)
   assert total==s.st_size;data=b'';digest=h.hexdigest()
  else:
   f.seek(off);data=f.read(min(n,s.st_size-off));assert len(data)==min(n,s.st_size-off);digest=None
  assert key(os.fstat(f.fileno()))==before
 assert key(os.lstat(p))==before
 print(json.dumps({'offset':off,'length':len(data),'identity':before,'data':base64.b64encode(data).decode(),'sha256':digest}))
finally:os.close(m)
"""
def exec_read(config,remote,offset,length,final):
 import urllib.request
 guard=importlib.util.spec_from_file_location('stage_guard',HERE/'stage-controller.py');g=importlib.util.module_from_spec(guard);guard.loader.exec_module(g);g.state_gate(config,config['lease_holder'],60)
 command=shlex.join(['/usr/bin/python3','-E','-c',REMOTE_READ,remote,str(offset),str(length),'1' if final else '0'])
 req=urllib.request.Request(config['url'].rstrip('/')+'/api/devices/m1/exec',data=json.dumps({'command':command,'timeout_sec':300 if final else 30}).encode(),headers={'Authorization':'Bearer '+config['token'],'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=340 if final else 70) as f:
  raw=f.read(1048577);assert len(raw)<=1048576,'exec response cap'
 r=json.loads(raw);assert r['exit_code']==0 and r['via']=='agent' and not r['stderr'],'bounded agent read failed; no serial fallback'
 assert len(r['stdout'])<=1048576
 return json.loads(r['stdout'])
def receive(config,remote,dest,pin=None,reader=exec_read):
 import base64
 identity=None;offset=0;h=hashlib.sha256();first=True;count=0
 with open(dest,'xb') as f:
  os.chmod(dest,0o600)
  while first or offset<identity[5]:
   first=False;r=reader(config,remote,offset,CHUNK,False);count+=1
   if identity is None:
    identity=r['identity'];assert len(identity)==8 and 0<=identity[5]<=2147483648 and stat.S_ISREG(identity[2])
    if pin:assert identity[5]==pin['bytes']
    else:assert identity[5]<=1024*1024,'receipt size cap'
   assert r['identity']==identity and r['offset']==offset,'source inode/offset drift'
   data=base64.b64decode(r['data'],validate=True);want=min(CHUNK,identity[5]-offset)
   assert len(data)==r['length']==want and r['sha256'] is None,'short/oversize chunk'
   f.write(data);h.update(data);offset+=len(data)
   assert count<=8193,'chunk count cap'
  f.flush();os.fsync(f.fileno())
 r=reader(config,remote,offset,0,True)
 assert r['identity']==identity and r['offset']==offset and r['length']==0 and r['data']=='' and r['sha256']==h.hexdigest(),'terminal target hash/identity drift'
 if pin:assert h.hexdigest()==pin['sha256']
 assert b.fsync_file(dest)=={'sha256':h.hexdigest(),'bytes':offset}
 return {'transport':'existing-authenticated-lab-exec','chunk_bytes':CHUNK,'chunks':count,'target_identity':identity,'target_terminal_sha256':r['sha256']}
def copy(src,dst):
 b.regular(src,2*1024**3);subprocess.run(['/usr/bin/cp','--reflink=never','--',str(src),str(dst)],check=True,timeout=900);os.chmod(dst,0o600);b.fsync_file(dst)
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--source-dir');g.add_argument('--lab-device',choices=['m1']);ap.add_argument('--lease-holder');ap.add_argument('--packet',required=True);ap.add_argument('--expected-receipt-sha256',required=True);ap.add_argument('--retain-dir',required=True);ap.add_argument('--cas-dir',default=str(Path.home()/'.local/share/maclab/artifacts'));a=ap.parse_args()
 assert re.fullmatch('[0-9a-f]{64}',a.expected_receipt_sha256)
 assert re.fullmatch('/var/lib/maclab/rc7-m1-[a-z0-9-]{8,64}',a.packet)
 dest=Path(a.retain_dir);assert dest.is_absolute() and not dest.is_relative_to('/dev/shm') and not dest.is_relative_to('/tmp'),'durable private retention only'
 b.parents_no_symlink(dest);assert not os.path.lexists(dest);dest.mkdir(mode=0o700);b.syncdir(dest.parent)
 source=Path(a.source_dir) if a.source_dir else None
 config=None
 if not source:
  config=json.loads((Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/'maclab/client.json').read_bytes())
  assert a.lease_holder,'existing owned lease holder required for lab pull'
  config={'url':os.environ.get('MACLAB_URL',config['url']),'token':os.environ.get('MACLAB_TOKEN',config['token']),'lease_holder':a.lease_holder}
  assert config['url'].startswith(('http://','https://')) and config['token']
 def get(name,pin=None):
  if source:copy(source/name,dest/name);return {'transport':'pre-existing-authenticated-private-copy'}
  return receive(config,a.packet+'/original-backup/'+name,dest/name,pin)
 trans=get('BACKUP-RECEIPT.json');assert b.regular(dest/'BACKUP-RECEIPT.json')[0]==a.expected_receipt_sha256,'target receipt identity mismatch'
 r=json.loads((dest/'BACKUP-RECEIPT.json').read_bytes());assert r['schema']=='maclab.rc-m1-original-backup/1' and r['status']=='LOCAL_BACKUP_VERIFIED_ONLY' and r['device']=='m1' and r['packet']==a.packet
 assert set(r['objects'])==NAMES and r['controller_retention_required'] is True
 assert sum(x['bytes'] for x in r['objects'].values())<=3*1024**3,'total backup bound'
 objects=dict(r['objects']);objects['BACKUP-RECEIPT.json']={'sha256':a.expected_receipt_sha256,'bytes':(dest/'BACKUP-RECEIPT.json').stat().st_size}
 # Space for controller retained copy + CAS file + 512MiB reserve; fail before bulk transfer.
 fs=os.statvfs(dest);assert fs.f_bavail*fs.f_frsize>=2*sum(x['bytes'] for x in objects.values())+512*1024**2
 proofs={}
 for name,pin in objects.items():
  assert pin['bytes']<=2*1024**3 and re.fullmatch('[0-9a-f]{64}',pin['sha256'])
  if name!='BACKUP-RECEIPT.json':transport=get(name,pin)
  else:transport=trans
  assert b.fsync_file(dest/name)==pin,'controller retained content mismatch'
  # Existing admin client loads its own local config; token never enters argv or target.
  out=subprocess.run([str(Path.home()/'.local/bin/lab'),'upload',str(dest/name)],capture_output=True,text=True,timeout=900,check=True).stdout.strip()
  assert out==pin['sha256'],'CAS upload returned wrong identity'
  cp=Path(a.cas_dir)/out;assert b.fsync_file(cp)==pin,'independent CAS reopen/readback mismatch'
  # Keep a non-GC private copy; CAS alone can later be unreferenced/collected.
  proofs[name]={'sha256':out,'bytes':pin['bytes'],'retained_path':str(dest/name),'cas_path':str(cp),'retained_fsync_reopen_match':True,'cas_fsync_reopen_match':True,'transport':transport}
 b.syncdir(dest);b.syncdir(Path(a.cas_dir))
 result={'schema':'maclab.rc-m1-controller-retention/1','status':'CONTROLLER_RETENTION_VERIFIED','device':'m1','packet':a.packet,'target_receipt_sha256':a.expected_receipt_sha256,'transport':trans,'objects':proofs,'original_file_pins':r['original_file_pins'],'old_module_tree_sha256':r['old_module_tree_sha256'],'rollback_copy_pins':{**r['rollback_copy_pins'],'original-backup/BACKUP-RECEIPT.json':a.expected_receipt_sha256},'controller_source_sha256':b.regular(Path(__file__))[0],'target_script_sha256':r['script_sha256'],'automatic_install':False}
 b.dump(dest/'CONTROLLER-RETENTION-RECEIPT.json',result);b.syncdir(dest);b.syncdir(dest.parent)
 print(json.dumps({'status':result['status'],'receipt_sha256':b.regular(dest/'CONTROLLER-RETENTION-RECEIPT.json')[0],'receipt':str(dest/'CONTROLLER-RETENTION-RECEIPT.json')}))
if __name__=='__main__':main()
