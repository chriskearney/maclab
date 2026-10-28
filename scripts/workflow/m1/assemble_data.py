#!/usr/bin/env python3
"""Finite local workflow projections. No network, target writes, or authorization.
Every execution/acceptance remains in the separately pinned evidence consumer.
"""
import argparse,copy,hashlib,json,re
from pathlib import Path
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
NEW='7.2.11-7-1-ARCH';OLD='7.2.11-6-1-ARCH'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def run(x):
 op=x['operation'];p=x['profile'];packet=p['packet'];plan=x['root_plan_sha256'];need(p['device']=='m1' and p['board']=='apple,j293' and re.fullmatch('[0-9a-f]{64}',plan),'fixed packet/Plan projection')
 if op=='marker-context':
  y=x['observed'];b=x['invocation'];need(b['entry']=='verify-modules' and b['profile']['packet']==packet and b['root_scope']['root_plan_sha256']==plan and y['boot_id']==b['expected_boot_id'],'actual marker invocation context');return {'status':'ACTUAL_MARKER_INVOCATION_CONTEXT_PROJECTED','packet':packet,'boot_id':b['expected_boot_id'],'kernel':b['expected_kernel'],'root_plan_sha256':plan,'source_sha256':y['source_sha256'],'owned_marker_receipt_sha256':x['owned_marker_receipt_sha256'],'actual_exec':y['actual_exec']}
 if op=='session-binding':
  audit=copy.deepcopy(x['audit_binding']);need(audit['packet']==packet and audit['root_plan_sha256']==plan and audit['operation']=='inventory' and audit['metadata_observation'] is None,'actual audit context');m=x['manifest'];need(m['device']=='m1' and m['board']=='apple,j293' and m['expected_kernel']==NEW and re.fullmatch('[0-9a-f]{64}',m['token']) and m['approved'] is True and m['source_review']=='accepted-by-root','actual admitted normal7 manifest');manifestsha=hashlib.sha256((json.dumps(m,sort_keys=True,indent=2)+'\n').encode()).hexdigest();need(manifestsha==x['manifest_sha256'],'actual canonical manifest pin');normal={'boot_id':m['expected_boot_id'],'manifest_path':packet+'/normal-smoke-'+m['token'][:16]+'.json','manifest_sha256':manifestsha}
  if x.get('capture') is not None:
   c=x['capture'];need(c['packet']==packet and c['root_plan_sha256']==plan and c['boot_id']==normal['boot_id'] and c['kernel']==NEW and c['status']=='ACTUAL_CURRENT_NORMAL7_PROOF_CAPTURED' and c['no_new_workload'] is True,'actual same-workflow native capture');normal['proof_sha256']=c['sha256']
  operation=x['session_operation'];need(operation in ('capture-normal7-proof','verify-original-session'),'finite session operation');need(audit['expected_kernel']==(NEW if operation=='capture-normal7-proof' else OLD),'actual session boot kernel');q={'operation':operation,'packet':packet,'expected_boot_id':audit['expected_boot_id'],'root_plan_sha256':plan,'profile':p,'deadline_seconds':180,'audit_binding':audit,'root_scope':{'packet':packet,'expected_boot_id':audit['expected_boot_id'],'entries':[operation],'root_plan_sha256':plan,'authority_sha256':AUTH,'reviewed_by':x['reviewed_by'],'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False},'normal7':normal,'original_session':{'wifi_interface':m['wifi_interface'],'wifi_mac':m['wifi_mac']}}
  if operation=='verify-original-session':
   a=x['actual_old_audit'];need(a['packet']==packet and a['root_plan_sha256']==plan and a['boot_id']==audit['expected_boot_id'] and a['kernel']==OLD and a['status']=='ORIGINAL_ROLLBACK_INVENTORY_ONLY' and a['state_diffs']==[],'actual empty original-state inventory');tag=a.get('response_binding');need(tag=={'schema':'maclab.m1-normal-response-binding/1','packet':packet,'boot_id':audit['expected_boot_id'],'kernel':OLD,'root_plan_sha256':plan,'action':'original-inventory','entry':'inventory'},'exact actual original-inventory transport tag');payload={k:v for k,v in a.items() if k!='response_binding'};q['old_payload_observation_sha256']=hashlib.sha256((json.dumps(payload,sort_keys=True,indent=2)+'\n').encode()).hexdigest()
  return {'status':'SESSION_BINDING_PROJECTED_LOCAL_ONLY','binding':q}
 if op=='final-return-evidence':
  y=x['session'];t=y['target'];need(y['status']=='ORIGINAL_SESSION_TARGET_OBSERVED' and t['status']=='ACTUAL_ORIGINAL6_SESSION_AND_ROLLBACK_VERIFIED' and t['packet']==packet and t['root_plan_sha256']==plan and t['kernel']==OLD and t['normal6_rollback_verified_by_root'] is True and t['no_gpu_workload_after_original_restore'] is True,'actual original-session evidence');r=y['actual_exec'];need(r['via']=='agent' and r['exit_code']==0 and not r['stderr'] and json.loads(r['stdout'])==t,'actual original-session raw bytes');return {'status':'ACTUAL_ORIGINAL_RETURN_EVIDENCE_PROJECTED','boot_id':t['boot_id'],'normal_proof_sha256':hashlib.sha256((json.dumps(json.loads(r['stdout']),indent=2)+'\n').encode()).hexdigest(),'normal_proof_root_plan_sha256':plan,'candidate_extra_path':'/boot/efi/EFI/Linux/rc-old6-linux-aurora-7.2.11-6-1.efi','candidate_extra_removed':True,'absence_basis':'exact reviewed original-session target requires this leaf absent before emitting this status','completion_claim':False}
 raise RuntimeError('unsupported finite local projection')
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);b=a.parse_args();print(json.dumps(run(json.loads(b.binding.read_bytes())),separators=(',',':')))
