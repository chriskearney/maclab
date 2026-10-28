"""Pure-data finite writer/ESP workflow fragments; no API or target actions."""
import copy,hashlib,re,stat
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
WRITER_ROOT=ROOT/'components/writer'
ESP_ROOT=ROOT/'components/esp'
DATA_ROOT=Path(__file__).resolve().parent
WRITER='a17f0f44816a1094b76ba87f79a1814ab909a490aa8fb3fb082760e11b96834e'
ESP='ae0e01c7f6a2c2c84ec9944cee255f814b5788c6045b48ec1f4f1a76907d06df'
OBSERVER='22e77f79f5d9967d1c8ea37d48fa563be0c0a66d41110fd6ae84c9d0275b744c'
RETAIN='b59182c435b046d519dfd94a2109798e2d3d79195525a6bf97d143a662e13b7a'
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
COMPARE='6d04ae60d3f27be535e61c6f41e147fda539620a655da3c3e862b69e5103a707'
OLD='7.2.11-6-1-ARCH'
RETENTION_KEYS=('v1_target_receipt_sha256','v1_source_freeze_sha256','mirror_source_sha256','supplement_target_receipt_sha256','supplement_source_sha256','main_mirror_source_sha256','parent_main_remote_receipt_sha256','destination')
def need(v,msg):
 if not v:raise ValueError(msg)
def ref(src,ptr=''):
 need(isinstance(src,str) and src and isinstance(ptr,str) and (ptr=='' or ptr.startswith('/')),'explicit phase/pointer');return {'from':src,'pointer':ptr}
def child(r,ptr):return ref(r['from'],r['pointer']+ptr)
def escaped(value):return value.replace('~','~0').replace('/','~1')
def pin(path,want):
 path=Path(path);s=path.lstat();need(stat.S_ISREG(s.st_mode) and s.st_size<=65536,'bounded regular reviewed source');raw=path.read_bytes();need(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==want,'reviewed source bytes drift');return {'path':str(path),'sha256':want,'bytes':len(raw)}
def helpers(python_pin,prefix):
 w=WRITER_ROOT;e=ESP_ROOT
 return {prefix+'-writer':{'python':python_pin,'source':pin(w/'writer.py',WRITER),'closure':[pin(w/'esp.py',ESP),pin(w/'observe.py',OBSERVER)]},prefix+'-esp':{'python':python_pin,'source':pin(e/'esp.py',ESP),'closure':[]},prefix+'-retain':{'python':python_pin,'source':pin(e/'retain.py',RETAIN),'closure':[pin(e/'esp.py',ESP)]}}
class Builder:
 def __init__(self,base,prefix,reviewer_pointer='/root_profile_reviewer'):
  need(set(base)=={'device','board','packet','source_packet','holder','authority_source'} and base['device']=='m1' and base['board']=='apple,j293','minimal fixed profile only');need(re.fullmatch('[a-z][a-z0-9-]{1,27}',prefix),'bounded phase prefix');self.base=copy.deepcopy(base);self.prefix=prefix;self.phases=[];self.reviewer_pointer=reviewer_pointer
 def binding(self,name,template,bind):
  key=self.prefix+'-'+name;self.phases.append({'id':key,'kind':'bind','timeout_sec':2,'mutates':False,'template':template,'bind':bind});return ref(key)
 def step(self,name,template,bind,helper,status,timeout,mutates=True,extra_checks=()):
  br=self.binding(name+'-binding',template,bind);key=self.prefix+'-'+name;checks=[{'pointer':'/status','equals':status},*extra_checks];self.phases.append({'id':key,'kind':'helper','timeout_sec':timeout+90,'mutates':mutates,'scope':('m1-writer' if helper=='writer' else 'm1-esp') if mutates else '', 'helper':self.prefix+'-'+helper,'input_phase':br['from'],'checks':checks});return ref(key)
 def scope(self,action,boot):return {'packet':self.base['packet'],'device':'m1','expected_boot_id':None,'root_plan_sha256':None,'authority_sha256':AUTH,'operations':[action],'reviewed_by':None,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False}
 def common(self,action,profile,boot,kernel,menu=None,subject='sf',timeout=120,writer=False):
  operation='writer-'+action if writer else action;t={'schema':'maclab.m1-writer-binding/1' if writer else 'maclab.m1-esp-binding/1','profile':None,'action':action,'expected_boot_id':None,'expected_kernel':OLD,'root_plan_sha256':None,'deadline_seconds':timeout,'root_scope':self.scope(operation,boot),'inputs':{}}
  binds={'/profile':profile,'/expected_boot_id':boot,'/root_plan_sha256':ref('workflow','/plan_sha256'),'/root_scope/expected_boot_id':boot,'/root_scope/root_plan_sha256':ref('workflow','/plan_sha256'),'/root_scope/reviewed_by':ref('inputs',self.reviewer_pointer)}
  if isinstance(kernel,dict):binds['/expected_kernel']=kernel
  else:need(kernel==OLD or kernel=='7.2.11-7-1-ARCH','finite live kernel');t['expected_kernel']=kernel
  if not writer:
   t.update(subject=subject,expected_menu_sha256=None,plan_origin_boot_id=None,plan_origin_kernel=OLD,writer_hold_receipt_sha256=None);binds.update({'/expected_menu_sha256':menu,'/plan_origin_boot_id':child(profile,'/plan_origin/boot_id')})
  return t,binds
 def writer(self,name,action,profile,boot,extra=None,extra_bind=None,timeout=120):
  t,b=self.common(action,profile,boot,OLD,timeout=timeout,writer=True);t['inputs']=extra or {};b.update({'/inputs/'+k:v for k,v in (extra_bind or {}).items()});local=action=='bind';checks=[] if local else [{'pointer':'/target/status','equals':'M1_WRITER_PHASE_OBSERVED'},{'pointer':'/actual_exec/via','equals':'agent'},{'pointer':'/actual_exec/exit_code','equals':0},{'pointer':'/actual_exec/stderr','equals':''}]
  return self.step(name,t,b,'writer','FRESH_WRITER_DATA_BOUND_LOCAL_ONLY' if local else 'ACTUAL_WRITER_PHASE_OBSERVED',timeout,not local,checks)
 def esp(self,name,action,profile,boot,kernel,menu,held,subject='sf',extra=None,extra_bind=None,timeout=120):
  t,b=self.common(action,profile,boot,kernel,menu,subject,timeout);t['inputs']=extra or {};b.update({'/inputs/'+k:v for k,v in (extra_bind or {}).items()});b['/writer_hold_receipt_sha256']=held
  local=action=='bind-fallback';retain=action=='archive-retain';status='FALLBACK_DATA_DERIVED_NO_TARGET_ACTION' if local else ('INDEPENDENT_ESP_RETENTION_VERIFIED' if retain else 'ACTUAL_ESP_PHASE_RESPONSE');checks=[] if local or retain else [{'pointer':'/target/status','equals':'M1_ESP_PHASE_OBSERVED'},{'pointer':'/actual_exec/via','equals':'agent'},{'pointer':'/actual_exec/exit_code','equals':0},{'pointer':'/actual_exec/stderr','equals':''}]
  return self.step(name,t,b,'retain' if retain else 'esp',status,timeout,not local,checks)

def preparation_fragment(base,python_pin,aliases,transport_pins,prefix='esp-writer',reviewer_pointer='/root_profile_reviewer'):
 """aliases: preflight current object; preflight_receipt scalarSHA; initial
 observer3 TARGET; capture typed descriptor; comparison6d04 result; retention
 actual fetched JSON; retention_descriptor actualreader observed object.
 All are explicit {from,pointer}; no actual result or permission synthesized.
 """
 need(set(aliases)=={'preflight','preflight_receipt','initial','capture','comparison','retention','retention_descriptor'},'complete explicit preparation producer refs');need(set(transport_pins)=={'m5_transport_source','typed_reader_source'},'reviewed finite controller transport pins')
 B=Builder(base,prefix,reviewer_pointer);a=aliases;boot=child(a['preflight'],'/boot_id')
 ctx={**copy.deepcopy(base),**copy.deepcopy(transport_pins),'esp_source_sha256':ESP,'writer_source_sha256':WRITER,'agent_parent':None,'esp_original_pins':None,'reference_pins':None,'history_pins':None,'plan_origin':{'boot_id':None,'kernel':OLD,'preflight_receipt_sha256':None}}
 p=B.binding('context',ctx,{'/agent_parent':child(a['preflight'],'/agent_parent'),'/esp_original_pins':child(a['initial'],'/esp_original_pins'),'/reference_pins':child(a['initial'],'/reference_pins'),'/history_pins':child(a['initial'],'/history_pins'),'/plan_origin/boot_id':boot,'/plan_origin/preflight_receipt_sha256':a['preflight_receipt']})
 inp={'closure_capture_pin':{k:None for k in ['path','sha256','bytes']},'closure_comparison':None,'comparison_source_sha256':COMPARE,'closure_root_plan_sha256':None};bindings={'closure_capture_pin/'+k:child(a['capture'],'/'+k) for k in ['path','sha256','bytes']};bindings.update(closure_comparison=a['comparison'],closure_root_plan_sha256=child(a['comparison'],'/root_plan_sha256'))
 data=B.writer('bind-writer','bind',p,boot,inp,bindings,10)
 retention_inputs={'retention_descriptor':{k:None for k in ['raw_base64','sha256','bytes']},'retention_root_plan_sha256':None,'retention_pins':{k:None for k in RETENTION_KEYS}}
 retention_refs={'retention_descriptor/'+k:child(a['retention_descriptor'],'/'+k) for k in ['raw_base64','sha256','bytes']};retention_refs['retention_root_plan_sha256']=child(a['retention'],'/root_plan_sha256');retention_refs.update({'retention_pins/'+k:child(a['retention'],'/'+k) for k in RETENTION_KEYS})
 stage=B.writer('stage-writer','stage',p,boot,{**copy.deepcopy(retention_inputs),'bound_writer':None},{**retention_refs,'bound_writer':data})
 app=child(stage,'/target/files/writer-prep-clearance.json/sha256');template=child(stage,'/target/files/writer-hold-clearance.TEMPLATE.json/sha256')
 stopped=B.writer('stop-writer','prepare',p,boot,{**copy.deepcopy(retention_inputs),'prep_clearance_sha256':None},{**retention_refs,'prep_clearance_sha256':app})
 prepared=child(stopped,'/target/files/'+escaped('writer-quiesce/PREPARED.json')+'/sha256')
 held=B.writer('hold-writer','apply',p,boot,{'prep_clearance_sha256':None,'prepared_receipt_sha256':None,'hold_template_sha256':None},{'prep_clearance_sha256':app,'prepared_receipt_sha256':prepared,'hold_template_sha256':template})
 holdpin=child(held,'/target/files/'+escaped('writer-persistent-hold/APPLIED.json')+'/sha256')
 B.writer('held-proof','collect',p,boot,{'prep_clearance_sha256':None,'expected_phase':'held'},{'prep_clearance_sha256':app})
 originalmenu=child(a['initial'],'/menu_sha256')
 sf=B.esp('sf-plan','plan',p,boot,OLD,originalmenu,holdpin,'sf')
 sfsha=child(sf,'/target/result/plan_sha256');sfraw=child(sf,'/target/result/plan_raw_base64')
 fb=B.esp('fallback-data','bind-fallback',p,boot,OLD,originalmenu,holdpin,'sf',{'sf_plan_sha256':None,'sf_plan_raw_base64':None},{'sf_plan_sha256':sfsha,'sf_plan_raw_base64':sfraw},10)
 def retain_apply(subject,plan,menu):
  planhash=child(plan,'/target/result/plan_sha256');raw=child(plan,'/target/result/plan_raw_base64');r=B.esp(subject+'-retain','archive-retain',p,boot,OLD,menu,holdpin,subject,{'plan_sha256':None,'plan_raw_base64':None},{'plan_sha256':planhash,'plan_raw_base64':raw},300)
  return B.esp(subject+'-apply','apply',p,boot,OLD,menu,holdpin,subject,{'plan_sha256':None,'retention_sha256':None,'retention_raw_base64':None},{'plan_sha256':planhash,'retention_sha256':child(r,'/retention_sha256'),'retention_raw_base64':child(r,'/retention_raw_base64')})
 sfapply=retain_apply('sf',sf,originalmenu);sfafter=child(sfapply,'/target/menu_sha256')
 pre=B.esp('pre-plan','plan',p,boot,OLD,sfafter,holdpin,'pre');preapply=retain_apply('pre',pre,sfafter)
 fallback=B.esp('fallback-apply','fallback-apply',p,boot,OLD,child(preapply,'/target/menu_sha256'),holdpin,'sf',{'sf_plan_sha256':None,'fallback_spec_sha256':None},{'sf_plan_sha256':sfsha,'fallback_spec_sha256':child(fb,'/fallback_spec_sha256')})
 collected=B.esp('prepared-proof','collect',p,boot,OLD,child(fallback,'/target/menu_sha256'),holdpin,None)
 return {'schema':'maclab.m1-writer-esp-fragment/1','source_only':True,'helpers':helpers(python_pin,prefix),'phases':B.phases,'context':{'profile':p,'origin_boot':boot,'initial':a['initial'],'initial_plan':child(a['initial'],'/root_plan_sha256'),'prep_clearance_sha256':app,'held_receipt_sha256':holdpin,'sf_plan':sf,'pre_plan':pre,'fallback_data':fb,'prepared':collected,'retired_sf_menu':sfafter},'outputs':{'prepared':collected,'prepared_menu_sha256':child(collected,'/target/result/prepared_menu_sha256'),'old6_fallback':child(collected,'/target/result/old6_fallback'),'fallback_spec_sha256':child(fb,'/fallback_spec_sha256'),'fallback_spec_raw_base64':child(fb,'/fallback_spec_raw_base64')},'runtime_qualified':False}

def inverse_fragment(base,python_pin,context,current,prefix='esp-inverse',reviewer_pointer='/root_profile_reviewer'):
 """current explicit refs: boot_id,kernel,menu_sha256,packet_c_receipt_sha256.
 Call after genuine clean PacketC, before the ordinary original6 return.
 Both live7 and live6 are admitted by accepted ESP4 inverse phases only.
 """
 need(set(current)=={'boot_id','kernel','menu_sha256','packet_c_receipt_sha256'},'actual postPacketC current identity/menu/files refs required');B=Builder(base,prefix,reviewer_pointer);c=context;p=c['profile'];sfsha=child(c['sf_plan'],'/target/result/plan_sha256');spec=child(c['fallback_data'],'/fallback_spec_sha256');held=c['held_receipt_sha256']
 defaults=B.esp('restore-arranged-default','restore-arranged-default',p,current['boot_id'],current['kernel'],current['menu_sha256'],held,'sf',{'sf_plan_sha256':None,'fallback_spec_sha256':None,'packet_c_receipt_sha256':None},{'sf_plan_sha256':sfsha,'fallback_spec_sha256':spec,'packet_c_receipt_sha256':current['packet_c_receipt_sha256']})
 inverse=B.esp('fallback-inverse','fallback-restore',p,current['boot_id'],current['kernel'],child(defaults,'/target/menu_sha256'),held,'sf',{'sf_plan_sha256':None,'fallback_spec_sha256':None},{'sf_plan_sha256':sfsha,'fallback_spec_sha256':spec})
 return {'schema':'maclab.m1-writer-esp-inverse-fragment/1','source_only':True,'helpers':{prefix+'-esp':helpers(python_pin,prefix)[prefix+'-esp']},'phases':B.phases,'outputs':{'fallback_inverse':inverse,'expected_original_return_menu_sha256':child(inverse,'/target/menu_sha256')},'next_required':'genuine ordinary changedUUID original6 return and actual original147 session proof; no extra reboot invented here','runtime_qualified':False}

def final_restore_fragment(base,python_pin,context,returned,prefix='esp-final',reviewer_pointer='/root_profile_reviewer'):
 """Only after genuine final original6 proof. returned explicit refs:
 boot_id,normal_proof_sha256,normal_proof_root_plan_sha256,menu_sha256,
 initial_actual_exec,candidate_extra_path,candidate_extra_removed.
 No static true is substituted for candidate removal or bounded consistency.
 """
 need(set(returned)=={'boot_id','normal_proof_sha256','normal_proof_root_plan_sha256','menu_sha256','initial_actual_exec','candidate_extra_path','candidate_extra_removed'},'all genuine return/candidate/initial refs required');B=Builder(base,prefix,reviewer_pointer);c=context;p=c['profile'];r=returned;boot=r['boot_id'];held=c['held_receipt_sha256'];app=c['prep_clearance_sha256']
 here=DATA_ROOT;data_source=here/'data.py';data_pin=pin(data_source,hashlib.sha256(data_source.read_bytes()).hexdigest());H={k:v for k,v in helpers(python_pin,prefix).items() if not k.endswith('-retain')};H[prefix+'-data']={'python':python_pin,'source':data_pin,'closure':[pin(here/'observe.py',OBSERVER)]}
 template={'operation':'initial-observer-descriptor','packet':base['packet'],'initial_boot_id':None,'initial_root_plan_sha256':None,'initial':None,'actual_exec':None};bind={'/initial_boot_id':c['origin_boot'],'/initial_root_plan_sha256':c['initial_plan'],'/initial':c['initial'],'/actual_exec':r['initial_actual_exec']};descriptor=B.step('initial-descriptor',template,bind,'data','ACTUAL_INITIAL_OBSERVER_DESCRIPTOR_BOUND_LOCAL_ONLY',10,False)
 lock=B.esp('ensure-lock','ensure-lock',p,boot,OLD,r['menu_sha256'],held,None)
 normal={'prep_clearance_sha256':None,'normal_return_receipt_sha256':None,'normal_return_root_plan_sha256':None};normal_refs={'prep_clearance_sha256':app,'normal_return_receipt_sha256':r['normal_proof_sha256'],'normal_return_root_plan_sha256':r['normal_proof_root_plan_sha256']}
 removed=B.writer('unhold','remove',p,boot,copy.deepcopy(normal),normal_refs)
 removepin=child(removed,'/target/files/'+escaped('writer-persistent-hold/REMOVED.json')+'/sha256')
 resumed=B.writer('resume','resume',p,boot,{**normal,'removed_receipt_sha256':None,'expected_menu_sha256':None},{**normal_refs,'removed_receipt_sha256':removepin,'expected_menu_sha256':child(lock,'/target/menu_sha256')})
 restoredpin=child(resumed,'/target/files/'+escaped('writer-quiesce/RESTORED.json')+'/sha256')
 catch=B.writer('catchup','verify-catchup',p,boot,{**normal,'removed_receipt_sha256':None,'restored_receipt_sha256':None,'initial_observation':None,'initial_observation_root_plan_sha256':None,'sf_plan_sha256':None,'sf_plan_root_plan_sha256':None},{**normal_refs,'removed_receipt_sha256':removepin,'restored_receipt_sha256':restoredpin,'initial_observation':child(descriptor,'/descriptor'),'initial_observation_root_plan_sha256':c['initial_plan'],'sf_plan_sha256':child(c['sf_plan'],'/target/result/plan_sha256'),'sf_plan_root_plan_sha256':child(c['sf_plan'],'/target/root_plan_sha256')},180)
 # Pin narrow actual observation status and false unbounded queue claim too.
 B.phases[-1]['checks'] += [{'pointer':'/target/result/status','equals':'BOUNDED_WRITER_RESUME_CONSISTENCY_OBSERVED'},{'pointer':'/target/result/bounded_consistency_verified','equals':True},{'pointer':'/target/result/unbounded_queue_completion_claimed','equals':False}]
 # catchup confirms actual SF.after menu; no source data transform needed.
 expected_menu=c['retired_sf_menu'];restores={}
 for subject in ['pre','sf']:
  target_plan=c[subject+'_plan'];extra={'plan_sha256':None,'candidate_extra_removed':None,'writers_resumed_catchup_verified':None,'candidate_extra_path':None,'restore_receipt_sha256':{'writer-persistent-hold/REMOVED.json':None,'writer-quiesce/RESTORED.json':None}}
  extra_refs={'plan_sha256':child(target_plan,'/target/result/plan_sha256'),'candidate_extra_removed':r['candidate_extra_removed'],'writers_resumed_catchup_verified':child(catch,'/target/result/bounded_consistency_verified'),'candidate_extra_path':r['candidate_extra_path'],'restore_receipt_sha256/'+escaped('writer-persistent-hold/REMOVED.json'):removepin,'restore_receipt_sha256/'+escaped('writer-quiesce/RESTORED.json'):restoredpin}
  actual=B.esp('restore-'+subject,'restore',p,boot,OLD,expected_menu,held,subject,extra,extra_refs);restores[subject]=actual;expected_menu=child(actual,'/target/menu_sha256')
 return {'schema':'maclab.m1-writer-esp-final-fragment/1','source_only':True,'helpers':H,'phases':B.phases,'outputs':{'writer_catchup':catch,'writer_catchup_receipt':child(catch,'/target/phase_receipt'),'esp_pre_restored':restores['pre'],'esp_sf_restored':restores['sf'],'final_menu_sha256':expected_menu},'next_required':'fresh complete original payload/config/module/reference/history/ESP audit and actual original writer-state/GUI/basicdevices final proof; source fragment is not final success','runtime_qualified':False}
