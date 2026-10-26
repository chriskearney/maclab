#!/usr/bin/env python3
"""Compile the closed M1 same-cohort transaction from reviewed finite fragments.
Local data/source only. No helper execution, endpoint access or permission grant.
"""
import argparse,base64,copy,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
OLD='7.2.11-6-1-ARCH';NEW='7.2.11-7-1-ARCH'
ESP=Path('/dev/shm/m1-esp-fragment-source-r4');WRITER=Path('/dev/shm/m1-writer-fragment-source-r3');EP=Path('/dev/shm/m1-writer-esp-phases-r2');NORMAL=Path('/dev/shm/sf-m1-normal-workflow-integration-r4');SESSION=Path('/dev/shm/sf-m1-original-session-proof-r2');ROLLBACK=Path('/dev/shm/sf-m1-rollback-binding-r2');PRODUCER=Path('/dev/shm/sf-m1-package-clearance-producer-r2');OBSERVER=Path('/dev/shm/sf-m1-initial-esp-observer-r3')
ACCEPTED={EP/'phases.py':'b4ed530f9eae62770391547f9ab5a2ad8085708fe0dc9e34ab5670e6f10d7503',PRODUCER/'produce.py':'14513fdd7f23f73b4a25299bde921863514c27ac5339849d4414293b5e7ab2e8',PRODUCER/'policy.json':'16e6a2e94cb65bf60573363638a74f402c315d0b71733cdc3df861876bb0e143',ROLLBACK/'rollback.py':'ce1b10f57383eb953f44f1fc64c058f3228a16a259afb7568db76b62a718f8b3',OBSERVER/'observe.py':'22e77f79f5d9967d1c8ea37d48fa563be0c0a66d41110fd6ae84c9d0275b744c',NORMAL/'normal_adapter.py':'3c988f3c4b99784fc83aa406462e67b014d035370b142ead310ba96e73b1f6f2',SESSION/'controller.py':'2d641aa306c57163227573b400ee13d3cd6d49ac3c0cf1e2d2ef4f5ce582f9eb'}
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
 path=Path(path).resolve(strict=True);b=path.read_bytes();need(path not in ACCEPTED or H(b)==ACCEPTED[path],'accepted component drift: '+str(path));return {'path':str(path),'sha256':H(b),'bytes':len(b)}
def load(path):
 pin(path);s=importlib.util.spec_from_file_location('assemble_'+H(str(path).encode())[:12],path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def ref(name,pointer=''):return {'from':name,'pointer':pointer}
def esc(s):return str(s).replace('~','~0').replace('/','~1')
def at(r,p):return ref(r['from'],r['pointer']+p)
def descriptor(p):return {k:p[k] for k in ('path','sha256','bytes')}
class Graph:
 def __init__(self,plan,py):self.plan=plan;self.py=py
 def helper(self,name,source,closure=()):self.plan['helpers'][name]={'python':self.py,'source':pin(source),'closure':[pin(p) for p in closure]}
 def binding(self,name,value):
  binds={}
  def walk(x,p=''):
   if isinstance(x,dict) and set(x)=={'from','pointer'}:binds[p]=x;return None
   if isinstance(x,dict):return {k:walk(v,p+'/'+esc(k)) for k,v in x.items()}
   if isinstance(x,list):return [walk(v,p+'/'+str(i)) for i,v in enumerate(x)]
   return x
  self.plan['phases'].append({'id':name,'kind':'bind','timeout_sec':3,'mutates':False,'template':walk(value),'bind':binds});return ref(name)
 def step(self,name,helper,value,status,timeout=30,scope=None,checks=()):
  b=self.binding(name+'-binding',value);self.plan['phases'].append({'id':name,'kind':'helper','timeout_sec':timeout,'mutates':scope is not None,'scope':scope or '', 'helper':helper,'input_phase':b['from'],'checks':([{'pointer':'/status','equals':status}] if status else [])+list(checks)});return ref(name)
 def fragment(self,fragment,name=None):
  if 'helpers' in fragment:self.plan['helpers'].update(fragment['helpers'])
  elif 'helper' in fragment:need(name,'explicit helper name');self.plan['helpers'][name]=fragment['helper']
  self.plan['phases']+=fragment['phases'];return fragment

def assemble(recipe,packet,out):
 out=Path(out).absolute();C=load(HERE/'compile.py');C.compile_profile(recipe,packet,out);plan=json.loads((out/'WORKFLOW.CLOSED.json').read_bytes());p=json.loads((out/'PROFILE.json').read_bytes());py=pin(Path(sys.executable).resolve());G=Graph(plan,py);fullpath=str(out/'WORKFLOW.FULL.CLOSED.json');plan['inputs'].update(root_emit_package_clearance=False,root_emit_packet_c_clearance=False);review=ref('inputs','/root_profile_reviewer');boot=ref('preflight','/boot_id');meta=ref('workflow','/plan_sha256');base={k:p[k] for k in ('device','board','packet','source_packet','holder','authority_source')};preagent=ref('preflight','/target/current/agent_parent');profile={**base,'agent_parent':preagent};scopebase={'packet':packet,'expected_boot_id':boot,'root_plan_sha256':meta,'authority_sha256':AUTH,'reviewed_by':review,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False}
 # Historical expectation namespace setup fails locally before Mac mutation.
 I=load(HERE/'installed_phases.py');expect=I.namespace(plan,p,recipe['installed'],py,out/'installed-expectation')
 G.helper('technical',HERE/'technical.py',[HERE/'frozen-controller-ea3.py']);G.helper('observer',OBSERVER/'observe.py',[OBSERVER/'esp.py',OBSERVER/'frozen-controller-ea3.py']);G.helper('proofs',HERE/'proofs.py',[ESP/'esp.py',HERE/'frozen-controller-ea3.py']);G.helper('assets',HERE/'assets.py',[HERE/'frozen-controller-ea3.py']);G.helper('resolver',HERE/'resolver.py',[HERE/'proofs.py',ESP/'esp.py',HERE/'frozen-controller-ea3.py']);G.helper('owner',HERE/'owner-invoke.py',[HERE/'technical.py',HERE/'frozen-controller-ea3.py',HERE/'target.py']);G.helper('owner-readonly',HERE/'frozen-controller-ea3.py',[HERE/'target.py']);G.helper('projection',HERE/'assemble_data.py');G.helper('expected-menu','/dev/shm/m1-inverse-menu-data-r1/derive.py',['/dev/shm/m1-inverse-menu-data-r1/esp.py','/dev/shm/m1-inverse-menu-data-r1/fallback-extras.py']);G.helper('producer',PRODUCER/'produce.py',[PRODUCER/n for n in ('policy.json','owner.py','compare.py','observe.py','esp.py','writer.py')]);G.helper('rollback',ROLLBACK/'rollback.py',[ROLLBACK/n for n in ('rollback-audit.py','frozen-controller-ea3.py','original-packages.json')])
 def technical(name,currentboot=boot,kernel=OLD):return G.step(name,'technical',{'profile':profile,'root_plan_sha256':meta,'expected_boot_id':currentboot,'expected_kernel':kernel,'minimum_lease_seconds':1990},'FRESH_M1_TECHNICAL_READINESS_OBSERVED',30)
 # Insert live technical gate + complete original ESP observation after readonly
 # preflight and before namespace writes/cache/writer/ESP actions.
 before=len(plan['phases']);technical('initial-technical');initial=G.step('initial-esp','observer',{'schema':'maclab.m1-initial-esp-binding/1','profile':profile,'expected_boot_id':boot,'root_plan_sha256':meta,'root_scope':{**scopebase,'operation':'observe-original-esp'}},'M1_INITIAL_ESP_OBSERVED',180);early=plan['phases'][before:];del plan['phases'][before:];plan['phases'][2:2]=early
 aliases={'preflight':ref('preflight','/target/current'),'preflight_receipt':ref('backup-inputs','/preflight_raw_exec_sha256'),'initial':at(initial,'/target'),'capture':ref('source-closure','/capture'),'comparison':ref('source-closure-compared'),'retention':ref('combined-actual-receipt','/receipt'),'retention_descriptor':ref('combined-actual-receipt','/observed')};E=load(EP/'phases.py');prep=G.fragment(E.preparation_fragment(base,py,aliases,recipe['esp_transport']));ctx=prep['context'];ep=ctx['profile'];prepared=ctx['prepared'];profile_sha=ref('preflight','/target/profile_sha256')
 def proofs(name,files,currentboot=boot,kernel=OLD,groups=False):return G.step(name,'proofs',{'operation':'prove-owned-groups' if groups else 'read-current-files','profile':profile,'expected_boot_id':currentboot,'expected_kernel':kernel,'root_plan_sha256':meta,'packet_profile_sha256':profile_sha,**({} if groups else {'files':{n:None for n in files}})},'M1_OWNED_PACKAGE_GROUPS_OBSERVED' if groups else 'M1_CURRENT_PACKET_PROOFS_OBSERVED',210)
 def assetstage(name,rows,currentboot=boot,kernel=OLD,produced=None,leaf=None):
  q={'operation':'stage-input','profile':profile,'expected_boot_id':currentboot,'expected_kernel':kernel,'packet_profile_sha256':profile_sha,'source_reviewed_by':review,'root_plan_sha256':meta,'agent_parent':preagent,'assets':rows}
  if produced:
   q.update(assets=[{'name':leaf,**{k:at(produced,'/files/'+leaf+'/'+k) for k in ('sha256','bytes','base64')}}],producer_scope={'schema':'maclab.m1-producer-stage-scope/1','packet':p['packet'],'expected_boot_id':currentboot,'root_plan_sha256':meta,'source_sha256':at(produced,'/source_sha256'),'file_name':leaf,'file_sha256':at(produced,'/files/'+leaf+'/sha256'),'file_bytes':at(produced,'/files/'+leaf+'/bytes')},producer_source=pin(PRODUCER/'produce.py'))
  return G.step(name,'assets',q,'M1_ASSETS_STAGED_ONLY',450,'workflow-inputs')
 immutable=load(HERE/'assets.py').IMMUTABLE;rows=[]
 for n in sorted(immutable):d=recipe['immutable_assets'][n];rows.append({'name':n,**{k:d[k] for k in ('sha256','bytes')}})
 G.step('immutable-assets','assets',{'operation':'reuse-assets','profile':profile,'expected_boot_id':boot,'packet_profile_sha256':profile_sha,'source_reviewed_by':review,'agent_parent':preagent,'assets':rows},'M1_ASSETS_STAGED_ONLY',450,'workflow-inputs')
 for n,d in p['owner_sources'].items():assetstage('code-'+n.replace('.py',''),[{'name':n,'sha256':d['sha256'],'bytes':d['bytes'],'source':d}])
 assetstage('manifest-input',[{'name':'manifest.json',**{k:expect['manifest'][k] for k in ('sha256','bytes')},'source':expect['manifest']}])
 resolved=G.step('resolved-preflight','resolver',{'schema':'maclab.m1-resolver-binding/1','profile':profile,'expected_boot_id':boot,'root_plan_sha256':meta,'packet_profile_sha256':profile_sha},'M1_READONLY_RESOLVER_OBSERVED',450)
 current=G.step('prepared-observation','m1',{'profile':p,'action':'inventory-cache','expected_boot_id':boot,'expected_kernel':OLD,'deadline_seconds':300},'M1_INVENTORY_CACHE_OBSERVED',390)
 docs=['esp-sf.plan.json','esp-sf.retention.json','esp-pre.plan.json','esp-pre.retention.json','writer-persistent-hold/APPLIED.json','fallback-extras/APPLY-RECEIPT.json'];preparedproofs=proofs('prepared-proofs',docs);ready=technical('package-technical')
 documents={n:descriptor(recipe['immutable_assets'][n]) for n in ('candidate-files.jsonl','old-package-files.jsonl','linux-aurora.files.sha256','OUTPUT-CEILING-PROOF.json','owner-expectations.json','owner-sidecars.json','owner-preinstall-guards.json')};documents['manifest.json']=descriptor(expect['manifest']);documents.update({n:at(preparedproofs,'/target/files/'+esc(n)) for n in docs})
 policy=pin(PRODUCER/'policy.json')['sha256'];produced=G.step('package-produced','producer',{'operation':'produce-package','packet':packet,'expected_boot_id':boot,'root_plan_sha256':meta,'holder':p['holder'],'plan_path':fullpath,'root_scope':{**scopebase,'reviewed_source_policy_sha256':policy,'emit_package_clearance':ref('inputs','/root_emit_package_clearance'),'reviewed_evidence_sources':{'esp':pin(ESP/'esp.py')['sha256'],'writer':pin(WRITER/'writer.py')['sha256'],'fallback':pin(ESP/'esp.py')['sha256'],'resolver':pin(HERE/'resolver.py')['sha256']}},'authority':descriptor(p['authority_source']),'main_capture':ref('backup-collected'),'supplement_capture':ref('supplement-collect'),'combined_retention':ref('combined-actual-receipt','/observed'),'backup_preparation':ref('backup-inputs'),'technical':at(ready,'/technical'),'documents':documents,'source_comparison':{'result':{'value':ref('source-closure-compared')},'baseline':descriptor(recipe['independent_retention']['closure_baseline']),'current_capture':ref('source-closure','/capture')},'latest_observation':current,'cache_staged':ref('target-cache'),'initial_esp':initial,'esp_profile':ep,'esp_prepared':prepared,'esp_applied':{'sf':ref('esp-writer-sf-apply'),'pre':ref('esp-writer-pre-apply')},'esp_retained':{'sf':ref('esp-writer-sf-retain'),'pre':ref('esp-writer-pre-retain')},'writer_held':ref('esp-writer-hold-writer'),'fallback_applied':ref('esp-writer-fallback-apply'),'resolved_preflight':resolved},'PACKAGE_PHASE_CLEARANCE_DATA_PRODUCED',60)
 for name in ('transaction-spec.json','execution-clearance.json','BOOT-RECOVERY-PLAN.json','ESP-PREPARATION-EXPECTATIONS.json','MIRROR-RECEIPT.json','OWNER-BACKUP-DECISIONS.json','ESP-ARRANGEMENT.json','ESP-PREPARATION-RECEIPT.json','ESP-RETIREMENT-RETENTION-RECEIPT.json','limine.conf.ARRANGED','FALLBACK-CONFIG-CLOSURE.json'):assetstage('input-'+name.lower().replace('.json','').replace('.','-'),[],produced=produced,leaf=name)
 def invoke(name,entry,currentboot=boot,kernel=OLD,readonly=False):
  q={'profile':p,'action':'invoke-packet','entry':entry,'expected_boot_id':currentboot,'expected_kernel':kernel,'deadline_seconds':1900,'root_scope':{'packet':packet,'device':'m1','expected_boot_id':currentboot,'root_plan_sha256':meta,'entries':[entry],'operations':['invoke-packet'],'authority_sha256':AUTH,'reviewed_by':review,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False}}
  return G.step(name,'owner-readonly' if readonly else 'owner',q,'M1_INVOKE_PACKET_OBSERVED',2020,None if readonly else 'package-owner')
 invoke('install-packages','install');candidate=load(HERE/'candidate_phases.py').append(plan,p,py,pin('/dev/shm/sf-m1-postinstall-reusable-r2/CONTRACT.json'),'package-produced',ctx['fallback_data']['from']);job=I.job(plan,p,expect,candidate['postinstall'],'/target')
 normalmod=load(NORMAL/'normal_phases.py');normal=G.fragment(normalmod.fragment(base,py,candidate['postinstall'],job['job_return'],postinstall_pointer='/target'),'normal')
 # Finish wiring below only uses genuinely changed boot outputs. A completed
 # old callback/receipt is never substituted for this transaction's observation.
 return plan,p,{'graph':G,'base':base,'profile':profile,'boot':boot,'meta':meta,'review':review,'technical':technical,'proofs':proofs,'assetstage':assetstage,'invoke':invoke,'prepared':prep,'normal':normal,'produced':produced,'normalmod':normalmod,'epmodule':E,'expectation':expect,'fullpath':fullpath,'out':out,'py':py}

def finish(plan,p,c):
 G=c['graph'];py=c['py'];base=c['base'];profile=c['profile'];meta=c['meta'];review=c['review'];produced=c['produced'];prep=c['prepared'];ctx=prep['context'];proofs=c['proofs'];technical=c['technical'];invoke=c['invoke'];stage=c['assetstage'];out=c['out'];fullpath=c['fullpath'];boot7=ref('normal-wait7','/boot_id')
 # Capture the actual native result files before the inverse/PacketC. The b9c
 # context here is CAPTURE_ONLY and contains no future rollback-completion claim.
 before=len(plan['phases']);pre_c=proofs('normal7-capture-proofs',['writer-persistent-hold/APPLIED.json','esp-sf.plan.json','esp-pre.plan.json'],boot7,NEW)
 def rollback_build(name,current,operation='build'):
  return G.step(name,'rollback',{'operation':operation,'profile':base,'root_plan_sha256':meta,'plan_path':fullpath,'reviewed_by':review,'package_produced':{**{k:at(produced,'/'+k) for k in ('schema','status','packet','root_plan_sha256','expected_boot_id','source_sha256','source_policy_sha256','package_execution_authorized','boot_authorized','target_actions')},'files':{k:at(produced,'/files/'+k) for k in ('execution-clearance.json','transaction-spec.json')}},'main_capture':ref('backup-collected'),'current_proofs':current},'CURRENT_NORMAL7_CAPTURE_CONTEXT_BUILT_LOCAL_ONLY' if operation=='build-capture-context' else 'FRESH_ROLLBACK_AUDIT_BINDING_BUILT_LOCAL_ONLY',30)
 capturecontext=rollback_build('capture-context',pre_c,'build-capture-context')
 capturebinding=G.step('capture-session-binding','projection',{'operation':'session-binding','profile':base,'root_plan_sha256':meta,'reviewed_by':review,'audit_binding':at(capturecontext,'/binding'),'manifest':ref('normal-manifest','/manifest'),'manifest_sha256':ref('normal-manifest','/manifest_sha256'),'session_operation':'capture-normal7-proof'},'SESSION_BINDING_PROJECTED_LOCAL_ONLY')
 S=load(SESSION/'phases.py');capture=G.fragment(S.fragment(py,capturebinding['from'],'/binding','capture-normal7-proof','normal7-capture'),'normal7-capture')
 addition=plan['phases'][before:];del plan['phases'][before:];index=next(i for i,x in enumerate(plan['phases']) if x['id']=='normal-inverse-binding-binding');plan['phases'][index:index]=addition
 marker=proofs('retained-marker',['transaction-receipts/OLD-MODULE-MARKER-OWNED.json'],boot7,NEW);verification=invoke('verify-retained-modules','verify-modules',boot7,NEW,True)
 markercontext=G.step('retained-marker-context','projection',{'operation':'marker-context','profile':base,'root_plan_sha256':meta,'observed':verification,'invocation':ref('verify-retained-modules-binding'),'owned_marker_receipt_sha256':at(marker,'/target/files/transaction-receipts~1OLD-MODULE-MARKER-OWNED.json/sha256')},'ACTUAL_MARKER_INVOCATION_CONTEXT_PROJECTED')
 groups=proofs('package-groups-drained',[],boot7,NEW,True);technical7=technical('rollback-technical',boot7,NEW);policy=pin(PRODUCER/'policy.json')['sha256']
 initial_compact={k:at(produced,'/'+k) for k in ('schema','packet','root_plan_sha256','source_sha256','source_policy_sha256')};initial_compact['files']={k:at(produced,'/files/'+k) for k in ('execution-clearance.json','transaction-spec.json')}
 pc=G.step('packet-c-produced','producer',{'operation':'bind-packet-c','packet':p['packet'],'expected_boot_id':boot7,'root_plan_sha256':meta,'holder':p['holder'],'plan_path':fullpath,'root_scope':{'packet':p['packet'],'expected_boot_id':boot7,'root_plan_sha256':meta,'reviewed_source_policy_sha256':policy,'reviewed_by':review,'emit_packet_c_clearance':ref('inputs','/root_emit_packet_c_clearance'),'reviewed_evidence_sources':{'marker':p['target_adapter']['sha256'],'groups':pin(HERE/'proofs.py')['sha256']}},'authority':descriptor(p['authority_source']),'initial_production':initial_compact,'cache_staged':ref('target-cache'),'technical':at(technical7,'/technical'),'owned_marker':at(marker,'/target/files/transaction-receipts~1OLD-MODULE-MARKER-OWNED.json'),'marker_verification':markercontext,'group_drain':groups},'PACKET_C_CLEARANCE_DATA_PRODUCED',30)
 stage('input-packet-c',[],boot7,NEW,pc,'packet-c-clearance.json');invoke('rollback-packages','rollback-packages',boot7,NEW)
 cnames=['packet-c-clearance.json','packet-c-receipts/PACMAN-OUTCOME.json','packet-c-receipts/PACMAN-OWNED-GROUP.json','packet-c-receipts/OWNER-RESTORE-RESULT.json','packet-c-receipts/PACKAGE-PHASE-COMPLETE.json','writer-persistent-hold/APPLIED.json','esp-sf.plan.json','esp-pre.plan.json']
 post_c=proofs('actual-packet-c-proofs',cnames,boot7,NEW);rollback=rollback_build('rollback-context',post_c)
 # This helper reports a source-derived EXPECTED CAS preimage, never an observed
 # menu. The unchanged target owns the strict actual whole-menu CAS.
 menu=G.step('post-c-expected-menu','expected-menu',{'schema':'maclab.m1-inverse-menu-data-binding/1','operation':'derive-expected-post-packet-c-menu','profile':ctx['profile'],'root_plan_sha256':meta,'sf_plan_descriptor':at(post_c,'/target/files/esp-sf.plan.json'),'fallback_data':ctx['fallback_data']},'EXPECTED_POST_PACKET_C_MENU_BOUND_LOCAL_ONLY')
 packetpins=G.binding('actual-packet-c-receipt-pins',{n:at(post_c,'/target/files/'+esc(n)+'/sha256') for n in cnames[:5]})
 current={'boot_id':boot7,'kernel':NEW,'menu_sha256':at(menu,'/expected_menu_sha256'),'packet_c_receipt_sha256':packetpins}
 inverse=G.fragment(c['epmodule'].inverse_fragment(base,py,ctx,current));
 def derive(name,binding,operation,current,inventory=None):
  return G.step(name,'rollback',{'operation':'derive','binding':binding,'audit_operation':operation,'current_proofs':current,**({'inventory':inventory} if inventory else {})},'CURRENT_ROLLBACK_BINDING_DERIVED_LOCAL_ONLY')
 def audit(name,binding,operation_scope=None):return G.step(name,'rollback',{'operation':'run-audit','profile':base,'binding':binding,'execution_clearance_sha256':at(produced,'/files/execution-clearance.json/sha256')},'ROLLBACK_AUDIT_TARGET_OBSERVED',390,operation_scope)
 inv=audit('old-payload-inventory',at(rollback,'/binding'));mt=derive('mtime-binding',at(rollback,'/binding'),'restore-mtimes',post_c,inv);audit('original-mtime-inverse',at(mt,'/binding'),'original-metadata-inverse');ret=derive('original-return-binding',at(rollback,'/binding'),'prepare-original-return',post_c)
 original=G.fragment(c['normalmod'].original_return_fragment(base,py,ret['from'],'/binding'),'original-return');wait=ref(original['outputs']['original6_boot_audit']);boot6=at(wait,'/boot_id');inner=at(wait,'/normal_inspect/target');newaudit=at(wait,'/original_binding')
 finalbinding=G.step('original-session-input','projection',{'operation':'session-binding','profile':base,'root_plan_sha256':meta,'reviewed_by':review,'audit_binding':newaudit,'manifest':ref('normal-manifest','/manifest'),'manifest_sha256':ref('normal-manifest','/manifest_sha256'),'capture':ref('normal7-capture','/target'),'session_operation':'verify-original-session','actual_old_audit':inner},'SESSION_BINDING_PROJECTED_LOCAL_ONLY');finalsession=G.fragment(S.fragment(py,finalbinding['from'],'/binding','verify-original-session','original-session'),'original-session')
 finalreturn=G.step('original-return-evidence','projection',{'operation':'final-return-evidence','profile':base,'root_plan_sha256':meta,'session':ref('original-session')},'ACTUAL_ORIGINAL_RETURN_EVIDENCE_PROJECTED')
 returned={'boot_id':boot6,'normal_proof_sha256':at(finalreturn,'/normal_proof_sha256'),'normal_proof_root_plan_sha256':meta,'menu_sha256':at(inverse['outputs']['fallback_inverse'],'/target/menu_sha256'),'initial_actual_exec':ref('initial-esp','/actual_exec'),'candidate_extra_path':at(finalreturn,'/candidate_extra_path'),'candidate_extra_removed':at(finalreturn,'/candidate_extra_removed')};restored=G.fragment(c['epmodule'].final_restore_fragment(base,py,ctx,returned))
 finalproofs=proofs('final-current-proofs',['esp-sf.plan.json','esp-pre.plan.json'],boot6,OLD);finalb=derive('final-audit-binding',newaudit,'final-verify',finalproofs);audit('final-original-audit',at(finalb,'/binding'))
 plan['inputs']['assembly_claims']={'source_only':True,'runtime_qualified':False,'recovery_branch_qualified':False,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False,'all_permissions_from_retained_standing_authority':True}
 # A clean success path is not a generic recovery permission. Recovery remains
 # explicitly blocked until the failed-phase-specific evidence is reviewed.
 plan['inputs']['full_pipeline_runtime_qualified']=False
 need(len({x['id'] for x in plan['phases']})==len(plan['phases']),'duplicate assembled phase')
 return plan

def compile_full(recipe,packet,out):
 for path in ACCEPTED:pin(path)
 plan,p,context=assemble(recipe,packet,out);finish(plan,p,context);raw=(json.dumps(plan,indent=2)+'\n').encode();target=Path(context['fullpath']);
 with target.open('xb') as f:
  f.write(raw);f.flush();__import__('os').fsync(f.fileno())
 need(target.read_bytes()==raw,'compiled full plan readback failed')
 summary={'schema':'maclab.m1-full-workflow-source-assembly/1','plan':pin(target),'phase_count':len(plan['phases']),'mutating_scopes':sorted({x['scope'] for x in plan['phases'] if x.get('mutates')}),'default_closed':plan['inputs']['root_profile_reviewer'] is None and plan['inputs']['root_emit_package_clearance'] is False and plan['inputs']['root_emit_packet_c_clearance'] is False,'runtime_qualified':False,'recovery_branch_qualified':False,'target_actions':False,'no_deployment_or_execution_permission_created':True}
 Path(out,'ASSEMBLY.json').write_text(json.dumps(summary,indent=2)+'\n');return summary
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--recipe',type=Path,required=True);a.add_argument('--packet',required=True);a.add_argument('--out',required=True);args=a.parse_args();print(json.dumps(compile_full(json.loads(args.recipe.read_bytes()),args.packet,args.out)))
