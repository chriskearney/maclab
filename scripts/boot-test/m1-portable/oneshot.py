#!/usr/bin/env python3
"""Local-only finite M1 installed one-shot compiler. No service/target calls."""
import argparse,copy,hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PREFIX=HERE/'snapshot'
BUNDLE_ROOT=HERE.parent
SOURCES=None
PRODUCER=HERE/'producer'
FRAGMENT=HERE/'writer_esp'
MODE=NATIVE=STAGE=NORMAL=POSTJOB=None

def configure(recipe):
 global SOURCES,MODE,NATIVE,STAGE,NORMAL,POSTJOB
 spec=importlib.util.spec_from_file_location('installed_source_components',HERE/'components.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 SOURCES=module.Sources(BUNDLE_ROOT,recipe['device_profile']['compiler']['resources'])
 MODE,NATIVE,STAGE,NORMAL,POSTJOB=(getattr(SOURCES,k) for k in ('mode','native','stage','normal','postjob'))

OLD='7.2.11-6-1-ARCH'
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
def need(v,m):
 if not v:raise RuntimeError(m)
def H(b):return hashlib.sha256(b).hexdigest()
def load(path):
 if SOURCES is not None:SOURCES.pin(path)
 s=importlib.util.spec_from_file_location('oneshot_'+H(str(path).encode())[:12],path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def pin(p):
 p=Path(p).resolve(strict=True);raw=p.read_bytes();return {'path':str(p),'sha256':H(raw),'bytes':len(raw)}
def ref(n,p=''):return {'from':n,'pointer':p}
def at(r,p):return ref(r['from'],r['pointer']+p)
def esc(s):return s.replace('~','~0').replace('/','~1')
def compact_producer(r):
 out={k:at(r,'/'+k) for k in ('schema','status','packet','root_plan_sha256','expected_boot_id','source_sha256','source_policy_sha256','package_execution_authorized','boot_authorized','target_actions','recovery_mode')};out['files']={k:at(r,'/files/'+k) for k in ('execution-clearance.json','transaction-spec.json')};return out

def component_freeze(folder,want):
 raw=(folder/'SOURCE-FREEZE.json').read_bytes();need(H(raw)==want,'reviewed component freeze drift: '+str(folder));doc=json.loads(raw)
 for name,v in doc['files'].items():
  if not isinstance(v,dict) or 'sha256' not in v or Path(name).suffix not in ('.py','.json'):continue
  actual=(folder/name).read_bytes();need(H(actual)==v['sha256'] and len(actual)==v['bytes'],'reviewed component source drift: '+name)
 return doc

def prefix(recipe,packet,out,mode):
 need(mode in ('network-only','serial-assisted'),'explicit supported recovery_mode required')
 component_freeze(NATIVE,SOURCES.freeze('native'))
 component_freeze(MODE,SOURCES.freeze('mode'))
 component_freeze(PRODUCER,SOURCES.freeze('producer'))
 SOURCES.pin(STAGE/'native.py')
 A=load(PREFIX/'assemble.py');A.PRODUCER=PRODUCER;A.WRITER=SOURCES.writer;A.EP=FRAGMENT;A.ESP=SOURCES.esp;A.NORMAL=SOURCES.legacy_normal;A.SESSION=SOURCES.session;A.ROLLBACK=SOURCES.rollback;A.OBSERVER=SOURCES.observer;A.EXPECTED_MENU=SOURCES.expected_menu;A.POSTINSTALL=SOURCES.postinstall;A.ACCEPTED={p:r['sha256'] for p,r in SOURCES.files.items()}
 # All imported compiler code is local. Existing package/ESP/backup owners remain
 # byte-identical. New policy only changes explicit recovery admission bindings.
 recipe=copy.deepcopy(recipe);recipe['supplement_source']=pin(PREFIX/'backup-supplement.py')
 fallback=pin(HERE/'target_sources/fallback-extras.py');need(fallback['sha256']=='e8a1c9fdd1cb10a5a5400b716f47a00b2cd41491d283ce990841a35904f374bf' and fallback['bytes']==15728,'fixed fallback source drift')
 supplied=recipe['immutable_assets'].get('fallback-extras.py')
 need(supplied is None or (supplied['sha256'],supplied['bytes'])==(fallback['sha256'],fallback['bytes']),'recipe cannot override reviewed fallback helper')
 recipe['immutable_assets']['fallback-extras.py']=fallback
 plan,p,c=A.assemble(recipe,packet,out);G=c['graph'];c['A']=A
 G.helper('assets',PREFIX/'assets.py',[PREFIX/'frozen-controller-ea3.py',HERE/'target_sources/fallback-extras.py'])
 first=next(i for i,x in enumerate(plan['phases']) if x['id'].startswith('normal-'));del plan['phases'][first:]
 plan['phases']=[x for x in plan['phases'] if x['id'] not in ('job-return-binding','job-return')]
 plan['inputs'].update(recovery_mode=mode,recovery_transaction=Path(packet).name,oneshot_scope='TAGGED_INSTALLED_JOB_NATIVE_GL_VK_NOT_ORDINARY_LOGIN',transaction_selection_required_before_first_exec=True)
 review=c['review'];meta=c['meta'];boot=c['boot'];profile=c['profile'];produced=c['produced'];base=c['base'];py=c['py']
 G.helper('technical',PREFIX/'technical.py',[PREFIX/'frozen-controller-ea3.py',PREFIX/'mode_policy.py'])
 G.helper('owner',PREFIX/'owner-invoke.py',[PREFIX/'technical.py',PREFIX/'mode_policy.py',PREFIX/'frozen-controller-ea3.py',PREFIX/'target.py'])
 G.helper('producer',PRODUCER/'produce.py',[PRODUCER/n for n in ('policy.json','owner.py','compare.py','observe.py','esp.py','writer.py','mode_policy.py')])
 G.helper('oneshot-data',HERE/'data.py')
 # Static Script bytes depend on fresh P only, and precede the immutable Plan.
 script=load(NATIVE/'compile.py').build(packet);scriptpath=Path(out)/'native-gl-vk.sh'
 with scriptpath.open('xb') as f:f.write(script);f.flush();os.fsync(f.fileno())
 need(scriptpath.read_bytes()==script,'compiled static native Script readback')
 scriptpin=pin(scriptpath);plan['inputs']['native_script_sources']={n:pin(NATIVE/n) for n in ('compile.py','wrapper.py','supervisor.py','installed-collect.py','normal-session-smoke-launchfix.py','smoke-manifest.template.json')}
 oldlen=len(plan['phases']);plan['phases'] += [{'id':'native-script-cache','kind':'cache','timeout_sec':30,'mutates':False,'file':scriptpin},{'id':'native-script-upload','kind':'upload','timeout_sec':120,'mutates':False,'input_phase':'native-script-cache'}]
 G.helper('native-stage',STAGE/'native.py',[STAGE/'frozen-controller-ea3.py',STAGE/'normal-session-smoke-launchfix.py'])
 native=G.step('native-inputs','native-stage',{'operation':'prepare-and-stage-native-inputs','profile':profile,'expected_boot_id':boot,'root_plan_sha256':meta,'recovery_mode':mode,'packet_profile_sha256':ref('preflight','/target/profile_sha256'),'root_scope':{'packet':packet,'expected_boot_id':boot,'root_plan_sha256':meta,'operations':['stage-native-inputs'],'recovery_mode':mode,'authority_sha256':AUTH,'reviewed_by':review,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False},'package_produced':compact_producer(produced),'postinstall':ref('postinstall-observed','/target'),'freeze_entry':ref('installer-entry'),'script':scriptpin},'NATIVE_JOB_INPUTS_STAGED_NO_BOOT',330,'workflow-inputs')
 addition=plan['phases'][oldlen:];del plan['phases'][oldlen:];idx=next(i for i,x in enumerate(plan['phases']) if x['id']=='installed-job-binding');plan['phases'][idx:idx]=addition
 jobspec=next(x for x in plan['phases'] if x['id']=='installed-job-binding');jobspec['template'].update(recovery_mode=mode,recovery_transaction=Path(packet).name);jobspec['template']['tests'].append({'name':'native-gl-vk','script':None,'timeout_sec':180,'gui':False});jobspec.setdefault('bind',{})['/tests/3/script']=ref('native-script-upload','/sha256')
 next(x for x in plan['phases'] if x['id']=='installed-job-complete')['wait_completion']=True
 c.update(script=scriptpin,native=native,mode=mode)
 return plan,p,c

def wire_mode(plan,mode):
 # These exact independently reviewed boundaries require explicit top/root scope
 # mode, not a tier-derived fallback. All other owner algorithms stay unchanged.
 for x in plan['phases']:
  if x['kind']!='bind':continue
  t=x.get('template')
  if not isinstance(t,dict):continue
  if x['id'] in ('initial-technical-binding','package-technical-binding','rollback-technical-binding') or t.get('operation') in ('produce-package','bind-packet-c') or (t.get('action')=='invoke-packet' and t.get('entry') in ('install','rollback-packages')):
   t['recovery_mode']=mode
   if isinstance(t.get('root_scope'),dict):t['root_scope']['recovery_mode']=mode
  if t.get('operation')=='bind-packet-c':t['initial_production']['recovery_mode']=mode

# Tail is finite and consumes real completed job/current-old6 observations. It
# never references a normal7 manifest or a fabricated native login receipt.
def tail(plan,p,c,postjob_dir=None):
 if postjob_dir is None:postjob_dir=POSTJOB
 need(Path(postjob_dir).resolve()==POSTJOB.resolve(),'fixed reviewed completion source only')
 component_freeze(POSTJOB,SOURCES.freeze('postjob'))
 component_freeze(NORMAL,SOURCES.freeze('normal'))
 A=c['A'];G=c['graph'];py=c['py'];base=c['base'];profile=c['profile'];meta=c['meta'];review=c['review'];produced=c['produced'];prep=c['prepared'];ctx=prep['context'];proofs=c['proofs'];technical=c['technical'];invoke=c['invoke'];stage=c['assetstage'];fullpath=c['fullpath'];mode=c['mode']
 O=load(HERE/'observer_phases.py');O.HERE=Path(postjob_dir);O.SESSION=SOURCES.session;observed=G.fragment(O.completion_fragment(profile,py,{'completed_job':ref('installed-job-complete'),'submission':ref('installed-job'),'installed_manifest_sha256':c['expectation']['manifest']['sha256'],'server_entry_sha256':ref('installer-entry','/actual_api_response/entry_sha256'),'prejob_boot_id':c['boot'],'postinstall':ref('postinstall-observed','/target'),'native_stage':at(c['native'],'/target'),'script':c['script'],'initial_production':compact_producer(produced),'packet_profile_sha256':ref('preflight','/target/profile_sha256')},mode,fullpath),'postjob')
 returned=ref(observed['outputs']['completed_return']);boot=at(returned,'/boot_id')
 marker=proofs('retained-marker',['transaction-receipts/OLD-MODULE-MARKER-OWNED.json'],boot,OLD);verification=invoke('verify-retained-modules','verify-modules',boot,OLD,True)
 markercontext=G.step('retained-marker-context','projection',{'operation':'marker-context','profile':base,'root_plan_sha256':meta,'observed':verification,'invocation':ref('verify-retained-modules-binding'),'owned_marker_receipt_sha256':at(marker,'/target/files/transaction-receipts~1OLD-MODULE-MARKER-OWNED.json/sha256')},'ACTUAL_MARKER_INVOCATION_CONTEXT_PROJECTED')
 groups=proofs('package-groups-drained',[],boot,OLD,True);ready=technical('rollback-technical',boot,OLD);policy=pin(PRODUCER/'policy.json')['sha256']
 pc=G.step('packet-c-produced','producer',{'operation':'bind-packet-c','recovery_mode':mode,'packet':p['packet'],'expected_boot_id':boot,'root_plan_sha256':meta,'holder':p['holder'],'plan_path':fullpath,'root_scope':{'packet':p['packet'],'expected_boot_id':boot,'root_plan_sha256':meta,'recovery_mode':mode,'reviewed_source_policy_sha256':policy,'reviewed_by':review,'emit_packet_c_clearance':ref('inputs','/root_emit_packet_c_clearance'),'reviewed_evidence_sources':{'marker':p['target_adapter']['sha256'],'groups':pin(PREFIX/'proofs.py')['sha256']}},'authority':A.descriptor(p['authority_source']),'initial_production':compact_producer(produced),'cache_staged':ref('target-cache'),'technical':at(ready,'/technical'),'owned_marker':at(marker,'/target/files/transaction-receipts~1OLD-MODULE-MARKER-OWNED.json'),'marker_verification':markercontext,'group_drain':groups},'PACKET_C_CLEARANCE_DATA_PRODUCED',30)
 stage('input-packet-c',[],boot,OLD,pc,'packet-c-clearance.json');invoke('rollback-packages','rollback-packages',boot,OLD)
 cnames=['packet-c-clearance.json','packet-c-receipts/PACMAN-OUTCOME.json','packet-c-receipts/PACMAN-OWNED-GROUP.json','packet-c-receipts/OWNER-RESTORE-RESULT.json','packet-c-receipts/PACKAGE-PHASE-COMPLETE.json','writer-persistent-hold/APPLIED.json','esp-sf.plan.json','esp-pre.plan.json'];postc=proofs('actual-packet-c-proofs',cnames,boot,OLD)
 rollback=G.step('rollback-context','rollback',{'operation':'build','profile':base,'root_plan_sha256':meta,'plan_path':fullpath,'reviewed_by':review,'package_produced':compact_producer(produced),'main_capture':ref('backup-collected','/envelope'),'current_proofs':postc},'FRESH_ROLLBACK_AUDIT_BINDING_BUILT_LOCAL_ONLY',30)
 menu=G.step('post-c-expected-menu','expected-menu',{'schema':'maclab.m1-inverse-menu-data-binding/1','operation':'derive-expected-post-packet-c-menu','profile':ctx['profile'],'root_plan_sha256':meta,'sf_plan_descriptor':at(postc,'/target/files/esp-sf.plan.json'),'fallback_data':ctx['fallback_data']},'EXPECTED_POST_PACKET_C_MENU_BOUND_LOCAL_ONLY')
 packetpins=G.binding('actual-packet-c-receipt-pins',{n:at(postc,'/target/files/'+esc(n)+'/sha256') for n in cnames[:5]});inverse=G.fragment(c['epmodule'].inverse_fragment(base,py,ctx,{'boot_id':boot,'kernel':OLD,'menu_sha256':at(menu,'/expected_menu_sha256'),'packet_c_receipt_sha256':packetpins}))
 def derive(name,binding,operation,current,inventory=None):return G.step(name,'rollback',{'operation':'derive','binding':binding,'audit_operation':operation,'current_proofs':current,**({'inventory':inventory} if inventory else {})},'CURRENT_ROLLBACK_BINDING_DERIVED_LOCAL_ONLY')
 def audit(name,binding,scope=None):return G.step(name,'rollback',{'operation':'run-audit','profile':base,'binding':binding,'execution_clearance_sha256':at(produced,'/files/execution-clearance.json/sha256')},'ROLLBACK_AUDIT_TARGET_OBSERVED',390,scope)
 inv=audit('old-payload-inventory',at(rollback,'/binding'));mt=derive('mtime-binding',at(rollback,'/binding'),'restore-mtimes',postc,inv);audit('original-mtime-inverse',at(mt,'/binding'),'original-metadata-inverse');ret=derive('original-return-binding',at(rollback,'/binding'),'prepare-original-return',postc)
 N=load(NORMAL/'normal_phases.py');original=G.fragment(N.original_return_fragment(base,py,ret['from'],'/binding',plan_path=fullpath),'original-return');wait=ref(original['outputs']['original6_boot_audit']);boot6=at(wait,'/boot_id');inner=at(wait,'/normal_inspect/target');newaudit=at(wait,'/original_binding')
 final=G.fragment(O.original_session_fragment(profile,py,{'audit_binding':newaudit,'actual_old_audit':at(wait,'/normal_inspect'),'clearance_sha256':at(produced,'/files/execution-clearance.json/sha256'),'expected_boot_id':boot6},mode,fullpath),'original-session')
 finalreturn=G.step('original-return-evidence','projection',{'operation':'final-return-evidence','profile':base,'root_plan_sha256':meta,'session':ref(final['outputs']['original_session'])},'ACTUAL_ORIGINAL_RETURN_EVIDENCE_PROJECTED')
 restored=G.fragment(c['epmodule'].final_restore_fragment(base,py,ctx,{'boot_id':boot6,'normal_proof_sha256':at(finalreturn,'/normal_proof_sha256'),'normal_proof_root_plan_sha256':meta,'menu_sha256':at(inverse['outputs']['fallback_inverse'],'/target/menu_sha256'),'initial_actual_exec':ref('initial-esp','/actual_exec'),'candidate_extra_path':at(finalreturn,'/candidate_extra_path'),'candidate_extra_removed':at(finalreturn,'/candidate_extra_removed')}))
 fp=proofs('final-current-proofs',['esp-sf.plan.json','esp-pre.plan.json'],boot6,OLD);fb=derive('final-audit-binding',newaudit,'final-verify',fp);fa=audit('final-original-audit',at(fb,'/binding'))
 verdict=G.step('restored-job-verdict','oneshot-data',{'operation':'final-verdict','profile':base,'root_plan_sha256':meta,'completed_job':ref('installed-job-complete'),'submission':ref('installed-job'),'actual_return':{k:at(returned,'/'+k) for k in ('status','packet','root_plan_sha256','job_id','outcome','job_result','kernel','ready_idle','ordinary_native_pass_claimed','native_reports')},'final_audit':fa,'final_session':ref(final['outputs']['original_session'])},'ORIGINAL_JOB_VERDICT_AFTER_RESTORATION_RETAINED')
 G.binding('final-test-verdict',{'passed':at(verdict,'/passed'),'original_outcome':at(verdict,'/original_outcome'),'restoration_verified':at(verdict,'/restoration_verified')});plan['phases'][-1]['checks']=[{'pointer':'/passed','equals':True},{'pointer':'/restoration_verified','equals':True}]
 wire_mode(plan,mode);used={x['helper'] for x in plan['phases'] if x['kind']=='helper'};plan['helpers']={k:v for k,v in plan['helpers'].items() if k in used};plan['inputs']['assembly_claims']={'source_only':True,'runtime_qualified':False,'ordinary_native_login_qualified':False,'tagged_job_native_test_only':True,'persistent_normal7_fragment_included':False,'failed_nonterminal_phase_auto_recovery':False}
 return plan

def compile_oneshot(recipe,packet,out,mode,postjob_dir=None):
 configure(recipe)
 plan,p,c=prefix(recipe,packet,out,mode);tail(plan,p,c,postjob_dir)
 dependency_raw=(HERE/'target-dependencies.json').read_bytes();SOURCES.pin(HERE/'target-dependencies.json');dependencies=json.loads(dependency_raw)
 load(HERE/'target_dependencies.py').validate(plan,dependencies);plan['inputs']['fixed_target_dependencies']=dependencies
 raw=(json.dumps(plan,indent=2)+'\n').encode();target=Path(c['fullpath'])
 with target.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 need(target.read_bytes()==raw,'compiled minimal Plan readback failed');return {'schema':'maclab.m1-minimal-oneshot-source/1','plan':pin(target),'phase_count':len(plan['phases']),'mode':mode,'transaction':Path(packet).name,'source_only':True,'target_actions':False,'hardware_qualified':False,'requires_mode_selected_before_exec':True,'not_automatic_recovery_from_arbitrary_phase_failure':True}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--recipe',type=Path,required=True);a.add_argument('--packet',required=True);a.add_argument('--out',required=True);a.add_argument('--recovery-mode',choices=('network-only','serial-assisted'),required=True);x=a.parse_args();print(json.dumps(compile_oneshot(json.loads(x.recipe.read_bytes()),x.packet,x.out,x.recovery_mode)))
