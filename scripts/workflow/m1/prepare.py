#!/usr/bin/env python3
"""Pure local fresh-backup binder. It never executes or contacts a Mac.
Prior completion/boot receipts are never promoted into a fresh transaction.
"""
import argparse,base64,datetime,hashlib,json,os,stat
from pathlib import Path

def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def bytes_json(x):return (json.dumps(x,indent=2)+'\n').encode()
def read_pin(pin):
 p=Path(pin['path']);meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(meta);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(stat.S_ISREG(a.st_mode) and a.st_size==pin['bytes']<=4*1024**2,'bounded pinned template required')
  fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:b=os.read(fd,a.st_size+1);need(len(b)==a.st_size and key(os.fstat(fd))==key(a)==key(p.lstat()),'template source inode drift')
  finally:os.close(fd)
  need(H(b)==pin['sha256'],'template/source drift');return b
 finally:os.close(meta)

def make(binding):
 p=binding['profile'];observed=binding['preflight'];need(observed['status']=='M1_INVENTORY_CACHE_OBSERVED' and observed['device']==p['device'],'actual fresh profile preflight required')
 need(observed['source_sha256']==p['target_adapter']['sha256'],'actual preflight source version drift')
 actual=observed['actual_exec'];need(actual['exit_code']==0 and actual['via']=='agent','actual agent transport required')
 target=json.loads(actual['stdout']);need(target==observed['target'],'raw exec/decoded evidence mismatch');need(target['profile_sha256']==H(json.dumps(p,sort_keys=True,separators=(',',':')).encode()),'actual preflight profile drift');current=target['current'];boot=observed['boot_id']
 need(target['boot_id']==current['boot_id']==boot and observed['kernel']==current['kernel']==p['old_kernel'],'fresh normal old6 identity required')
 need(current['original_guard_mismatches']==[] and current['old_module_tree_sha256']==p['old_module_tree_sha256'],'fresh complete original-state guards required')
 need(current['module_markers'] and not any(current['module_markers'].values()),'old/new module ownership conflict')
 need(set(target['files'])=={row['relative'] for row in p['archives']},'complete target cache inventory required')
 for row in p['archives']:
  found=target['files'][row['relative']];need(found['sha256']==row['sha256'] and found['bytes']==row['bytes'],'cached cohort mismatch')
 authority=read_pin(p['authority_source']);proof=json.loads(authority);need(proof['authorization_is_persistent'] is True and proof['manual_saved_work_confirmed'] is False and proof['manual_nearby_recovery_confirmed'] is False,'persistent authority facts changed')
 templates=binding['templates'];spec=json.loads(read_pin(templates['backup_spec']));clear=json.loads(read_pin(templates['backup_clearance']));backup=read_pin(templates['backup_source'])
 need(spec['schema']=='maclab.rc-m1-original-backup-spec/1' and spec['device']=='m1' and spec['board']==p['board'] and spec['old_release']==p['old_kernel'],'wrong backup template family')
 need(clear['schema']=='maclab.rc-m1-backup-clearance/1' and clear['boot_authorized'] is False,'backup cannot authorize a boot')
 guards={name:({'absent':True} if row.get('absent') else {'sha256':row['sha256']}) for name,row in current['files'].items()}
 need(set(guards)==set(p['original_file_pins']),'complete observed original guard closure required')
 spec['expected_boot_id']=boot;spec['original_file_pins']=guards
 # The capture's authorizations come from the already scoped workflow and
 # persistent actual user authority, not fictional saved-work/nearby answers.
 reviewer=binding.get('root_profile_reviewer');need(isinstance(reviewer,str) and reviewer and not reviewer.startswith('PENDING'),'reviewed supported profile source gate remains closed')
 coordinator=binding['coordinator_state'];need(coordinator['state']=='ready' and coordinator['alive'] and coordinator['boot_id']==boot and coordinator['kernel']==p['old_kernel'] and not coordinator.get('active_job') and not coordinator.get('queued'),'fresh leased coordinator state required')
 lease=coordinator['lease'];need(lease['holder']==p['holder'],'wrong coordinator lease');expires=datetime.datetime.fromisoformat(lease['expires'].replace('Z','+00:00'));need((expires-datetime.datetime.now(datetime.timezone.utc)).total_seconds()>=1900,'lease insufficient for fresh backup and cleanup')
 spec_raw=bytes_json(spec)
 clear.update(packet=p['packet'],expected_boot_id=boot,spec_sha256=H(spec_raw),script_sha256=H(backup),backup_authorized=True,backup_scope_reviewed=True,lease_and_idle_reviewed=True,boot_authorized=False)
 rawfiles={'backup-spec.json':spec_raw,'backup-clearance.json':bytes_json(clear),'backup-m1.py':backup,'STANDING-BOOT-AUTHORITY.json':authority}
 freeze={'schema':'maclab.m1-fresh-backup-source-freeze/1','packet':p['packet'],'boot_id':boot,'sources':{name:{'sha256':H(raw),'bytes':len(raw)} for name,raw in rawfiles.items()},'package_changes':False,'boot_authorized':False,'source_reviewed_by':reviewer};rawfiles['BACKUP-SOURCE-FREEZE.json']=bytes_json(freeze)
 files={name:{'sha256':H(raw),'bytes':len(raw),'base64':base64.b64encode(raw).decode()} for name,raw in rawfiles.items()}
 return {'schema':'maclab.m1-fresh-backup-binding/1','status':'FRESH_BACKUP_INPUTS_BOUND_NO_TARGET_ACTION','packet':p['packet'],'boot_id':boot,'profile_source_reviewer':reviewer,'files':files,'preflight_raw_exec_sha256':H(bytes_json(actual)),'authority_sha256':p['authority_source']['sha256'],'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False,'historical_backup_or_boot_receipts_copied':False,'package_or_boot_authorization':False,'next':'stage exact files using reviewed write-once input adapter; invoke unchanged backup67a with --packet/--spec/--clearance; retain actual new main8 and supplemental3 independently before any destructive work'}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(make(json.loads(x.binding.read_bytes())),separators=(',',':')))
