"""Pure compiler fragments for existing installed APIs and exact three-test jobs.
Namespace setup precedes the first target mutation. The postinstall entry is
frozen only after the separate reviewed physical candidate/retention checks.
"""
import importlib.util,os
from pathlib import Path
HERE=Path(__file__).parent
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def load(name):
 s=importlib.util.spec_from_file_location('fixed_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def namespace(plan,p,recipe,python,out):
 compiler=load('compile');adapter=load('installed');out=Path(out);out.mkdir(mode=0o700,exist_ok=False);cwd=os.getcwd();os.chdir(out)
 try:expectation=adapter.prepare_expectation({'profile':p,'source_reviewed_by':'data-only compiler; runtime root review remains pending','source_manifest':recipe['source_manifest'],'payload':recipe['payload']})
 finally:os.chdir(cwd)
 plan['inputs']['installed_expectation']=expectation;plan['helpers']['installed']={'python':python,'source':compiler.pin(HERE/'installed.py'),'closure':[compiler.pin(HERE/'frozen-controller-ea3.py')]}
 def ref(src,ptr=''):return {'from':src,'pointer':ptr}
 def scope(op):return {'packet':p['packet'],'operation':op,'root_plan_sha256':None,'authority_sha256':AUTH,'reviewed_by':None}
 base={'profile':p,'root_plan_sha256':None,'source_reviewed_by':None}
 binds={'/root_plan_sha256':ref('workflow','/plan_sha256'),'/source_reviewed_by':ref('inputs','/root_profile_reviewer'),'/root_scope/root_plan_sha256':ref('workflow','/plan_sha256'),'/root_scope/reviewed_by':ref('inputs','/root_profile_reviewer')}
 phases=[{'id':'namespace-preinstall-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':{**base,'action':'freeze-preinstall','root_scope':scope('freeze-preinstall'),**{k:recipe[k] for k in ('frozen_root','source_release','source_baseline_job','source_pins','preinstall_pins')}},'bind':binds},{'id':'namespace-preinstall','kind':'helper','timeout_sec':60,'mutates':True,'scope':'installed-namespace','helper':'installed','input_phase':'namespace-preinstall-binding','checks':[{'pointer':'/status','equals':'GENUINE_PREINSTALL_BYTES_FROZEN'},{'pointer':'/new_baseline_claim','equals':False}]}]
 for kind in ('manifest','payload'):
  phases += [{'id':'expected-'+kind+'-cache','kind':'cache','timeout_sec':30,'mutates':False,'file':expectation[kind]},{'id':'expected-'+kind+'-upload','kind':'upload','timeout_sec':120,'mutates':False,'input_phase':'expected-'+kind+'-cache'}]
 phases += [{'id':'namespace-manifest-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':{**base,'action':'freeze-manifest','root_scope':scope('freeze-manifest'),'expectation':expectation,'expected_boot_id':None,'manifest_artifact':None,'payload_artifact':None},'bind':{**binds,'/expected_boot_id':ref('preflight','/boot_id'),'/manifest_artifact':ref('expected-manifest-upload','/sha256'),'/payload_artifact':ref('expected-payload-upload','/sha256')}},{'id':'namespace-manifest','kind':'helper','timeout_sec':450,'mutates':True,'scope':'installed-namespace','helper':'installed','input_phase':'namespace-manifest-binding','checks':[{'pointer':'/status','equals':'SUPPORTED_INSTALLED_FREEZE_MANIFEST_OBSERVED'}]}]
 # The first two phases are genuine read-only preflight. No Mac writer hold,
 # package/ESP/cache mutation precedes successful durable namespace setup.
 need([x['id'] for x in plan['phases'][:2]]==['preflight-binding','preflight'],'fixed preflight prefix required');plan['phases'][2:2]=phases
 return expectation

def job(plan,p,expectation,postinstall_from,postinstall_pointer=''):
 def ref(src,ptr=''):return {'from':src,'pointer':ptr}
 manifest=expectation['manifest']['sha256'];base={'profile':p,'source_reviewed_by':None,'root_plan_sha256':None,'root_scope':{'packet':p['packet'],'operation':'freeze-entry','root_plan_sha256':None,'authority_sha256':AUTH,'reviewed_by':None}}
 plan['phases'] += [{'id':'installer-entry-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':{**base,'action':'freeze-entry','postinstall':None,'expected_boot_id':None,'installed_manifest_sha256':manifest},'bind':{'/postinstall':ref(postinstall_from,postinstall_pointer),'/expected_boot_id':ref('preflight','/boot_id'),'/source_reviewed_by':ref('inputs','/root_profile_reviewer'),'/root_plan_sha256':ref('workflow','/plan_sha256'),'/root_scope/root_plan_sha256':ref('workflow','/plan_sha256'),'/root_scope/reviewed_by':ref('inputs','/root_profile_reviewer')}},{'id':'installer-entry','kind':'helper','timeout_sec':450,'mutates':True,'scope':'installed-entry','helper':'installed','input_phase':'installer-entry-binding','checks':[{'pointer':'/status','equals':'SUPPORTED_INSTALLED_FREEZE_ENTRY_OBSERVED'}]},
 {'id':'installed-job-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':{'device':'m1','holder':p['holder'],'installed_manifest':manifest,'tests':[{'name':'boot-health','builtin':'boot-health'},{'name':'gui-smoke','builtin':'gui-smoke','gui':True},{'name':'omarchy-m-test','builtin':'omarchy-m-test','timeout_sec':900,'gui':True}]}},
 {'id':'installed-job','kind':'submit','timeout_sec':60,'mutates':True,'scope':'installed-boot-test','input_phase':'installed-job-binding','m1_submission_admission':{'boot_id':ref('preflight','/boot_id'),'agent_sha256':ref('preflight','/target/current/agent_parent/sha256'),'minimum_lease_sec':2700}},
 {'id':'installed-job-complete','kind':'wait','timeout_sec':2400,'mutates':False,'input_phase':'installed-job'},
 {'id':'job-return-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':{'action':'observe-job-return','profile':p,'source_reviewed_by':None,'job_result':None,'installed_manifest_sha256':manifest,'installer_entry_sha256':None,'prejob_boot_id':None},'bind':{'/source_reviewed_by':ref('inputs','/root_profile_reviewer'),'/job_result':ref('installed-job-complete'),'/installer_entry_sha256':ref('installer-entry','/actual_api_response/entry_sha256'),'/prejob_boot_id':ref('preflight','/boot_id')}},
 {'id':'job-return','kind':'helper','timeout_sec':90,'mutates':False,'helper':'installed','input_phase':'job-return-binding','checks':[{'pointer':'/status','equals':'ACTUAL_INSTALLED_JOB_AND_NORMAL6_RETURN_OBSERVED'}]}]
 return {'job':'installed-job','completed':'installed-job-complete','job_return':'job-return'}
