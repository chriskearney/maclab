#!/usr/bin/env python3
"""Compile a data-bound M1 same-cohort workflow from a reusable reviewed recipe.
Local files only. No network, target access, helper execution, or approval creation.
"""
import argparse,hashlib,json,os,sys
from pathlib import Path
HERE=Path(__file__).parent

def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def pin(path):
 path=Path(path).resolve(strict=True);b=path.read_bytes();return {'path':str(path),'sha256':H(b),'bytes':len(b)}
def load_pin(p):
 b=Path(p['path']).read_bytes();need(H(b)==p['sha256'] and len(b)==p['bytes'],'recipe input drift');return json.loads(b)
def write(path,value):
 b=(json.dumps(value,indent=2)+'\n').encode()
 with path.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 need(path.read_bytes()==b,'local compiler output mismatch');return H(b)
def compile_profile(recipe,new_packet,out):
 r=load_pin(recipe['transaction_spec']);a=load_pin(recipe['original_clearance']);authority=load_pin(recipe['authority_source']);need(r['device']=='m1' and r['board']=='apple,j293' and r['old_release']=='7.2.11-6-1-ARCH' and r['candidate_release']=='7.2.11-7-1-ARCH','recipe is not reviewed M1 6→7 family')
 need(authority['authorization_is_persistent'] is True and authority['manual_saved_work_confirmed'] is False and authority['manual_nearby_recovery_confirmed'] is False,'standing authority facts drift')
 need(new_packet!=recipe['source_packet'] and new_packet.startswith('/var/lib/maclab/rc7-m1-') and Path(new_packet).name==new_packet[len('/var/lib/maclab/'):],'fresh packet required')
 owners=recipe['owner_sources'];need(set(owners)=={'transact-m1.py','packet-c-old5.py','rollback-hold-old6.py'},'exact reviewed owner closure required')
 for name,p in owners.items():need(pin(p['path'])==p,'owner source pin changed')
 rows=[]
 for section,folder in [('candidate_packages','packages'),('rollback_packages','rollback-packages')]:
  for x in r[section]:rows.append({'relative':folder+'/'+x['file'],'sha256':x['sha256'],'bytes':x['bytes'],'package':x['name'],'version':x['version']})
 p={'schema':'maclab.m1-cohort-profile/1','device':'m1','board':'apple,j293','packet':new_packet,'source_packet':recipe['source_packet'],'holder':recipe['holder'],'old_kernel':r['old_release'],'candidate_kernel':r['candidate_release'],'archives':rows,'current_packages':[{'name':x['name'],'version':x['version']} for x in r['rollback_packages']]+[{'name':n,'version':v['version']} for n,v in r['unchanged_packages'].items()],'original_file_pins':a['original_file_pins'],'old_module_tree_sha256':a['old_module_tree_sha256'],'observation_owner':recipe['observation_owner'],'owner_sources':owners,'authority_source':recipe['authority_source'],'target_adapter':pin(HERE/'target.py'),'claims':{'installed_pass':False,'boot_test_pass':False,'original_backup_reused_without_fresh_capture':False,'independent_retention_verified':False}}
 # Existing completed backup/boot receipts are intentionally not copied. They
 # are neither the identity nor the acceptance of this new transaction.
 scope={'packet':new_packet,'device':'m1','expected_boot_id':None,'authority_sha256':recipe['authority_source']['sha256'],'operations':['stage-cache'],'reviewed_by':None,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False}
 request={'profile':p,'action':'inventory-cache','expected_boot_id':None,'expected_kernel':r['old_release'],'deadline_seconds':300}
 stage={'profile':p,'action':'stage-cache','expected_boot_id':None,'expected_kernel':r['old_release'],'deadline_seconds':900,'root_scope':scope}
 py=pin(Path(sys.executable));helper={'python':py,'source':pin(HERE/'controller.py'),'closure':[pin(HERE/'target.py')]}
 plan={'schema':'maclab.workflow/1','id':Path(new_packet).name,'device':'m1','inputs':{'root_profile_reviewer':None},'helpers':{'m1':helper},'phases':[
  {'id':'preflight-binding','kind':'bind','timeout_sec':2,'mutates':False,'template':request},
  {'id':'preflight','kind':'helper','timeout_sec':390,'mutates':False,'helper':'m1','input_phase':'preflight-binding','checks':[{'pointer':'/status','equals':'M1_INVENTORY_CACHE_OBSERVED'},{'pointer':'/target/current/old_module_tree_sha256','equals':a['old_module_tree_sha256']}]},
  {'id':'cache-binding','kind':'bind','timeout_sec':2,'mutates':False,'template':stage,'bind':{'/expected_boot_id':{'from':'preflight','pointer':'/boot_id'},'/root_scope/expected_boot_id':{'from':'preflight','pointer':'/boot_id'},'/root_scope/reviewed_by':{'from':'inputs','pointer':'/root_profile_reviewer'}}},
  {'id':'target-cache','kind':'helper','timeout_sec':1020,'mutates':True,'scope':'target-cache','helper':'m1','input_phase':'cache-binding','checks':[{'pointer':'/status','equals':'M1_STAGE_CACHE_OBSERVED'},{'pointer':'/target/archive_network_bytes','equals':0},{'pointer':'/target/package_changes','equals':False},{'pointer':'/target/boot_changes','equals':False}]}
 ]}
 out=Path(out);out.mkdir(mode=0o700,parents=False,exist_ok=False);pins={};pins['PROFILE.json']=write(out/'PROFILE.json',p);pins['WORKFLOW.CLOSED.json']=write(out/'WORKFLOW.CLOSED.json',plan)
 blocked={'status':'SOURCE_REVIEW_PENDING','no_execution_permission_created':True,'existing_user_authorization_is_persistent':True,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False,'remaining_pipeline_phases':['fresh original capture and M5 content-reuse retention','writer hold and safe ESP arrangement / archive-retire receipts','fresh bound owner clearance and exact resolved transaction','candidate identity/UKI observation and supported installed job','genuine normal-session GL/VK and full rollback/return proof'],'closed_mutating_profile_reviewer':True,'files':pins}
 pins['READINESS.json']=write(out/'READINESS.json',blocked);return {'status':'LOCAL_DATA_PROFILE_COMPILED_MUTATION_CLOSED','output':str(out),'files':pins,'no_target_actions':True}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--recipe',type=Path,required=True);ap.add_argument('--packet',required=True);ap.add_argument('--out',required=True);args=ap.parse_args();print(json.dumps(compile_profile(json.loads(args.recipe.read_bytes()),args.packet,args.out)))
