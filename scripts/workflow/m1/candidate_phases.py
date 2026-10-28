"""Finite source-only phase compiler for reviewed postinstall/UKI retention.
The source observes real package output, never invents an expected UKI hash.
"""
import hashlib,json
from pathlib import Path
SOURCE='8a2bb9b1cc7357f74f5d7375b3d849e4c12ec1f00cfa00caaf6a7f8297523ab4'
CLOSURE={'frozen-controller-ea3.py':'d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a','installed-collect.py':'08c40a85ca2aa90cbe9f25e8a10ecf8e05a90c08a276fa6be2f4ffd6043ca661','mirror-m5-ssh.py':'2da24f72f7e240d9a0d0c8892df0a0095bd942995c107216960a3b834efcf9ab','retain-controller.py':'66ee32ba1561e7637eb27fe460330645c50d211280adf55167de24a2d29af71d'}
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def pin(p):
 p=Path(p).resolve(strict=True);b=p.read_bytes();return {'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)}
def append(plan,profile,python,contract_pin,producer_from,fallback_from,producer_pointer='',fallback_pointer='/fallback_spec_sha256'):
 cp=Path(contract_pin['path']);need(pin(cp)==contract_pin,'postinstall source contract drift');contract=json.loads(cp.read_bytes());source=contract['source'];need(source['sha256']==SOURCE and pin(source['path'])==source,'reviewed postinstall source changed');closure=contract['closure'];need({Path(x['path']).name:x['sha256'] for x in closure}==CLOSURE and all(pin(x['path'])==x for x in closure),'reviewed postinstall closure changed');plan['helpers']['postinstall']={'python':python,'source':source,'closure':closure}
 def ref(src,ptr=''):return {'from':src,'pointer':ptr}
 def step(name,action,status,extra=None,bind_extra=None,timeout=450):
  template={'schema':'maclab.m1-postinstall-binding/1','action':action,'profile':{k:profile[k] for k in ('device','board','packet','source_packet','holder')},'expected_boot_id':None,'root_plan_sha256':None,'root_scope':{'packet':profile['packet'],'device':'m1','expected_boot_id':None,'root_plan_sha256':None,'operations':[action],'authority_sha256':AUTH,'reviewed_by':None,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False},'inputs':{'clearance_sha256':None,'spec_sha256':None}}
  bind={'/expected_boot_id':ref('preflight','/boot_id'),'/root_plan_sha256':ref('workflow','/plan_sha256'),'/root_scope/expected_boot_id':ref('preflight','/boot_id'),'/root_scope/root_plan_sha256':ref('workflow','/plan_sha256'),'/root_scope/reviewed_by':ref('inputs','/root_profile_reviewer'),'/inputs/clearance_sha256':ref(producer_from,producer_pointer+'/files/execution-clearance.json/sha256'),'/inputs/spec_sha256':ref(producer_from,producer_pointer+'/files/transaction-spec.json/sha256')}
  if extra:template['inputs'].update(extra)
  if bind_extra:bind.update(bind_extra)
  plan['phases'] += [{'id':name+'-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':template,'bind':bind},{'id':name,'kind':'helper','timeout_sec':timeout,'mutates':True,'scope':'candidate-observation-retention','helper':'postinstall','input_phase':name+'-binding','checks':[{'pointer':'/status','equals':status}]}]
 step('postinstall-observed','observe-install','NATIVE_CANDIDATE_PAYLOAD_AND_UKI_OBSERVED_NO_BOOT',{'fallback_spec_sha256':None},{'/inputs/fallback_spec_sha256':ref(fallback_from,fallback_pointer)})
 step('candidate-safe-default6','prepare-temp6','SAFE_OLD6_DEFAULT_PREPARED_NO_REBOOT',{'postinstall':None},{'/inputs/postinstall':ref('postinstall-observed','/target')})
 step('candidate-double-retained','retain-candidate','ACTUAL_CANDIDATE_UKI_DOUBLE_RETENTION_VERIFIED',{'postinstall':None,'original_m5_receipt':{'raw_base64':None,'sha256':None,'bytes':None}},{'/inputs/postinstall':ref('postinstall-observed','/target'),**{'/inputs/original_m5_receipt/'+key:ref('combined-actual-receipt','/observed/'+key) for key in ('raw_base64','sha256','bytes')}},1500)
 return {'postinstall':'postinstall-observed','postinstall_pointer':'/target','safe_default':'candidate-safe-default6','candidate_retained':'candidate-double-retained'}
