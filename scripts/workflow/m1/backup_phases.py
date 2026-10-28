"""Data-only independent-backup continuation for the fixed same-cohort graph.
Every receipt source is a current upstream phase. Only old byte-candidate pins
are static recipe inputs; an old completion never supplies a fresh phase.
"""
import base64,hashlib,json
from pathlib import Path
HERE=Path(__file__).parent
COMPARE='6d04ae60d3f27be535e61c6f41e147fda539620a655da3c3e862b69e5103a707'
READER='1216671b431768ef7dded344666beba0babc3b762fa1e03ea7dc51d3624b71a7'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def pin(p):
 p=Path(p).resolve(strict=True);raw=p.read_bytes();return {'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
def append(plan,profile,recipe,python):
 from_prepare=__import__('importlib.util').util.spec_from_file_location('backup_graph_prepare',HERE/'prepare.py');m=__import__('importlib.util').util.module_from_spec(from_prepare);from_prepare.loader.exec_module(m)
 for key,expected in [('closure_comparator',COMPARE),('m5_receipt_reader',READER)]:need(recipe[key]['sha256']==expected and pin(recipe[key]['path'])==recipe[key],'reviewed graph source drift: '+key)
 need(profile['supplement_source']==pin(HERE/'backup-supplement.py'),'current reviewed supplementary source required; old203 profile is capture-only')
 candidates=[]
 for p in recipe['retention_candidate_receipts']:
  raw=m.read_pin(p);candidates.append({'sha256':p['sha256'],'raw_base64':base64.b64encode(raw).decode()})
 need(1<=len(candidates)<=4,'explicit bounded retained byte candidates')
 plan['inputs'].update(profile=profile,retention_candidate_receipts=candidates)
 def helper(name,path,closure=()):plan['helpers'][name]={'python':python,'source':pin(path),'closure':[pin(p) for p in closure]}
 helper('retention-bind',HERE/'retention_bind.py');helper('retention',HERE/'retention.py',[(HERE/'retention-core'/n) for n in ('mirror_reuse.py','reuse_remote.py','mirror-m5-ssh.py','retain-controller.py')]);helper('m5-reader',recipe['m5_receipt_reader']['path']);helper('supplement',HERE/'supplement.py',[HERE/'frozen-controller-ea3.py']);helper('closure-compare',recipe['closure_comparator']['path'])
 def ref(src,ptr=''):return {'from':src,'pointer':ptr}
 def step(name,h,t,bind,status,timeout=30,mutates=False,scope=''):
  plan['phases'] += [{'id':name+'-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':t,'bind':bind},{'id':name,'kind':'helper','timeout_sec':timeout,'mutates':mutates,'scope':scope,'helper':h,'input_phase':name+'-binding','checks':[{'pointer':'/status','equals':status}]}];return name
 # This complete namespace observation must occur before any writer hold.
 profile['closure_collector']=pin(HERE/'closure-collector.py');plan['helpers']['m1']['closure'].append(profile['closure_collector'])
 # Changing the profile after CACHE-PROFILE publication would invalidate its
 # ownership hash. The compiler calls append before profile publication, and
 # existing templates below must use this same final immutable profile object.
 step('source-closure','m1',{'profile':profile,'action':'collect-closure','expected_boot_id':None,'expected_kernel':profile['old_kernel'],'deadline_seconds':180},{'/expected_boot_id':ref('preflight','/boot_id')},'M1_CLOSURE_OBSERVED',300)
 step('source-closure-compared','closure-compare',{'schema':'maclab.m1-code-closure-comparison/1','expected_boot_id':None,'root_plan_sha256':None,'baseline_pin':recipe['closure_baseline'],'current_capture_pin':{'path':None,'sha256':None,'bytes':None}},{'/expected_boot_id':ref('preflight','/boot_id'),'/root_plan_sha256':ref('workflow','/plan_sha256'),**{'/current_capture_pin/'+k:ref('source-closure','/capture/'+k) for k in ('path','sha256','bytes')}},'M1_CODE_CLOSURE_AND_EFFECTIVE_PACMAN_MATCHED',30)
 def retain(kind,capture,main_parent=None):
  name=kind+'-retention-binding';template={'operation':kind,'profile':None,'root_plan_sha256':None,'boot_id':None,'main_capture':{k:None for k in ('receipt','receipt_base64','receipt_sha256','source_freeze_sha256')},'retained_candidate_receipts':None};bind={'/profile':ref('inputs','/profile'),'/root_plan_sha256':ref('workflow','/plan_sha256'),'/boot_id':ref('preflight','/boot_id'),**{'/main_capture/'+k:ref('backup-collected','/target/'+k) for k in ('receipt','receipt_base64','receipt_sha256','source_freeze_sha256')},'/retained_candidate_receipts':ref('inputs','/retention_candidate_receipts')}
  if kind=='supplement':template.update(supplement_capture=None,actual_main_retention=None);bind.update({'/supplement_capture':ref(capture,'/target'),'/actual_main_retention':ref(main_parent)})
  # The binder returns the exact fixed12406 wrapper interface, not a nested
  # envelope requiring per-run extraction code.
  plan['phases'] += [{'id':name+'-input','kind':'bind','timeout_sec':3,'mutates':False,'template':template,'bind':bind},{'id':name,'kind':'helper','timeout_sec':30,'mutates':False,'helper':'retention-bind','input_phase':name+'-input','checks':[{'pointer':'/mode','equals':kind}]}]
  retained=kind+'-retained';plan['phases'].append({'id':retained,'kind':'helper','timeout_sec':2100,'mutates':True,'scope':'independent-'+kind+'-retention','helper':'retention','input_phase':name,'checks':[{'pointer':'/status','equals':'INDEPENDENT_REMOTE_RETENTION_VERIFIED'},{'pointer':'/historical_completion_reused','equals':False}]})
  fetch=kind+'-fetch-binding';plan['phases'] += [{'id':fetch+'-input','kind':'bind','timeout_sec':3,'mutates':False,'template':{'operation':'fetch','mode':kind,'profile':None,'root_plan_sha256':None,'retention_result':None,'storage_dev':None},'bind':{'/profile':ref('inputs','/profile'),'/root_plan_sha256':ref('workflow','/plan_sha256'),'/retention_result':ref(retained),'/storage_dev':ref(name,'/reviewed_m5_storage_dev')}},{'id':fetch,'kind':'helper','timeout_sec':30,'mutates':False,'helper':'retention-bind','input_phase':fetch+'-input'}]
  output='main-actual-receipt' if kind=='main' else 'combined-actual-receipt';plan['phases'].append({'id':output,'kind':'helper','timeout_sec':180,'mutates':False,'helper':'m5-reader','input_phase':fetch,'checks':[{'pointer':'/status','equals':'ACTUAL_M5_RECEIPT_FETCHED'}]});return output
 main=retain('main','backup-collected')
 for op,budget in [('stage',210),('capture',450),('collect',210)]:
  template={'operation':op,'profile':None,'main_collection':{k:None for k in ('receipt','receipt_base64','receipt_sha256','source_freeze_sha256')},'expected_boot_id':None,'agent_parent':None,'source_root_plan_sha256':None,'source_reviewed_by':None,'supplement_source':profile['supplement_source'],'old_boot_bin':None}
  binds={'/profile':ref('inputs','/profile'),**{'/main_collection/'+k:ref('backup-collected','/target/'+k) for k in ('receipt','receipt_base64','receipt_sha256','source_freeze_sha256')},'/expected_boot_id':ref('preflight','/boot_id'),'/agent_parent':ref('preflight','/target/current/agent_parent'),'/source_root_plan_sha256':ref('workflow','/plan_sha256'),'/source_reviewed_by':ref('inputs','/root_profile_reviewer'),'/old_boot_bin':ref('preflight','/target/current/files/~1boot~1efi~1m1n1~1boot.bin.old')}
  if op=='collect':template['receipt_sha256']=None;binds['/receipt_sha256']=ref('supplement-capture','/target/receipt_sha256')
  step('supplement-'+op,'supplement',template,binds,'M1_SUPPLEMENT_'+op.upper()+'_OBSERVED',budget,op!='collect','backup-supplement' if op!='collect' else '')
 retain('supplement','supplement-collect',main)
 return {'main_retention':'main-actual-receipt','combined_retention':'combined-actual-receipt','source_comparison':'source-closure-compared'}
