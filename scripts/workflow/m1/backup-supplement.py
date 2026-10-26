#!/usr/bin/env python3
"""Write-once off-ESP boot.bin.old + current boot metadata supplement. No boot/package action."""
if not __debug__:raise RuntimeError('optimized Python is forbidden')
import argparse,hashlib,json,os,signal,stat,time,types
from pathlib import Path
P=None
V1_SOURCE='67a36275efc2c188599a03ab850b02ad6f0b8b7d8b61fb0cba22b5c0339258a4'
V1_FREEZE=V1_RECEIPT=BOOT=OLD_SHA=OLD_BYTES=None

def guarded(p,limit):
 meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(meta);assert stat.S_ISREG(s.st_mode) and s.st_size<=limit
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  with os.fdopen(fd,'rb') as f:
   assert key(os.fstat(f.fileno()))==key(s);data=f.read(limit+1);assert len(data)==s.st_size and key(os.fstat(f.fileno()))==key(s)
  assert key(os.lstat(p))==key(s);return hashlib.sha256(data).hexdigest(),data
 finally:os.close(meta)
def main():
 global P,V1_FREEZE,V1_RECEIPT,BOOT,OLD_SHA,OLD_BYTES
 ap=argparse.ArgumentParser();ap.add_argument('--authorize-backup-supplement',action='store_true');ap.add_argument('--packet',required=True);ap.add_argument('--binding',required=True);a=ap.parse_args();assert a.authorize_backup_supplement
 P=Path(a.packet);assert P.is_absolute() and str(P).startswith('/var/lib/maclab/rc7-m1-') and len(P.parts)==5
 binding=Path(a.binding);assert binding.parent==P and binding.name=='supplement-binding.json'
 raw=guarded(binding,65536)[1];scope=json.loads(raw)
 assert scope['schema']=='maclab.m1-fresh-supplement-binding/1' and scope['packet']==str(P)
 assert scope['manual_saved_work_confirmed'] is False and scope['manual_nearby_recovery_confirmed'] is False
 assert scope['source_reviewed_by'] and scope['standing_authority_sha256'] and scope['old_boot_bin']['bytes']>0
 V1_FREEZE=scope['backup_source_freeze_sha256'];V1_RECEIPT=scope['main_receipt_sha256'];BOOT=scope['boot_id'];OLD_SHA=scope['old_boot_bin']['sha256'];OLD_BYTES=scope['old_boot_bin']['bytes']
 for pin in [V1_FREEZE,V1_RECEIPT,OLD_SHA]:assert isinstance(pin,str) and len(pin)==64 and set(pin)<=set('0123456789abcdef')
 assert os.geteuid()==0 and os.uname().release=='7.2.11-6-1-ARCH'
 for parent in [P,*P.parents]:
  st=parent.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
 assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT
 os.umask(0o077);sh,source=guarded(P/'backup-m1.py',32768);assert sh==V1_SOURCE
 rh,data=guarded(P/'original-backup/BACKUP-RECEIPT.json',1048576);assert rh==V1_RECEIPT
 r=json.loads(data);assert r['status']=='LOCAL_BACKUP_VERIFIED_ONLY' and r['packet']==str(P) and r['boot_id']==BOOT and r['script_sha256']==V1_SOURCE
 b=types.ModuleType('verified_v1_backup');exec(compile(source,str(P/'backup-m1.py'),'exec'),b.__dict__)
 b.DEADLINE=time.monotonic()+180
 for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,b.cancelled)
 original=Path('/boot/efi/m1n1/boot.bin.old');before=b.row(original);assert before['type']=='f' and before['sha256']==OLD_SHA and before['bytes']==OLD_BYTES
 dest=P/'original-boot-supplement-r2';assert not os.path.lexists(dest)
 assert os.stat(P).st_dev!=os.stat('/boot/efi').st_dev
 fs=os.statvfs(P);assert fs.f_bavail*fs.f_frsize>=2*OLD_BYTES+128*1024**2
 dest.mkdir(mode=0o700);b.syncdir(P)
 copy=dest/'boot.bin.old.original';b.command(['/usr/bin/cp','--preserve=all','--reflink=never','--',str(original),str(copy)])
 assert b.row(original)==before and b.fsync_file(copy)=={'sha256':OLD_SHA,'bytes':OLD_BYTES}
 mappings={'boot.bin.original':'/boot/efi/m1n1/boot.bin','kernel6.uki.original':'/boot/efi/EFI/Linux/omarchy_linux-aurora.efi','limine.conf.original':'/boot/efi/limine.conf'};rows={}
 for name,path in mappings.items():
  current=b.row(Path(path));saved=b.row(P/'original-backup'/name)
  assert current['sha256']==saved['sha256']==r['objects'][name]['sha256']==r['original_file_pins'][path]['sha256']
  for key in ['type','mode','uid','gid','xattrs','bytes']:assert current[key]==saved[key],(path,key)
  rows[path]={'current_original':current,'retained_backup_copy':saved,'content_type_mode_owner_xattrs_match':True,'mtime_equal':current['mtime_ns']==saved['mtime_ns'],'mtime_scope':'both timestamps observed; historical difference allowed without causal inference'}
 saved=b.row(copy)
 for key in ['type','mode','uid','gid','mtime_ns','xattrs','bytes','sha256']:assert before[key]==saved[key],key
 rows[str(original)]={'current_original':before,'retained_backup_copy':saved,'content_and_preserved_metadata_match':True}
 for path,entry in rows.items():assert b.row(Path(path))==entry['current_original'],'metadata drift during capture'
 assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT and guarded(P/'original-backup/BACKUP-RECEIPT.json',1048576)[0]==V1_RECEIPT
 metadata={'schema':'maclab.rc-m1-boot-metadata-supplement/1','boot_id':BOOT,'v1_target_receipt_sha256':V1_RECEIPT,'observation_scope':'post-v1-backup only; original inode/ctime before v1 not retrospectively asserted','files':rows}
 b.dump(dest/'boot-metadata.original.json',metadata)
 objects={name:b.fsync_file(dest/name) for name in ['boot.bin.old.original','boot-metadata.original.json']}
 script_sha=b.regular(Path(__file__))[0]
 receipt={'schema':'maclab.rc-m1-backup-supplement/1','status':'LOCAL_SUPPLEMENT_VERIFIED_ONLY','device':'m1','packet':str(P),'boot_id':BOOT,'v1_source_freeze_sha256':V1_FREEZE,'v1_target_receipt_sha256':V1_RECEIPT,'v1_target_source_sha256':V1_SOURCE,'supplement_script_sha256':script_sha,'supplement_directory':str(dest),'historical_mtime_difference_recorded':True,'original_file_pins':{str(original):{'sha256':OLD_SHA,'bytes':OLD_BYTES}},'objects':objects,'controller_retention_required':True,'package_mutation':False,'reboot':False}
 b.dump(dest/'SUPPLEMENT-RECEIPT.json',receipt);b.syncdir(dest);b.syncdir(P)
 print(json.dumps({'status':receipt['status'],'receipt':str(dest/'SUPPLEMENT-RECEIPT.json'),'receipt_sha256':b.regular(dest/'SUPPLEMENT-RECEIPT.json')[0],'v1_target_receipt_sha256':V1_RECEIPT,'supplement_script_sha256':script_sha,'package_mutation':False,'reboot':False}))
if __name__=='__main__':main()
