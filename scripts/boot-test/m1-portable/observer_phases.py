"""Finite pure phase glue for the pinned completion observer and null-native UI.
No calls and no authorization creation. Target algorithms belong to their owners.
"""
import hashlib
from pathlib import Path
HERE=None
SESSION=None
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
def pin(p):
 p=Path(p).resolve(strict=True);raw=p.read_bytes();return {'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
def ref(n,p=''):return {'from':n,'pointer':p}
def escape(s):return str(s).replace('~','~0').replace('/','~1')
class B:
 def __init__(self,profile,py):self.profile=profile;self.py=py;self.helpers={};self.phases=[]
 def helper(self,n,source,closure):self.helpers[n]={'python':self.py,'source':pin(source),'closure':[pin(p) for p in closure]}
 def step(self,n,helper,value,status,timeout=390,scope=None,checks=()):
  binds={}
  def walk(v,p=''):
   if isinstance(v,dict) and set(v)=={'from','pointer'}:binds[p]=v;return None
   if isinstance(v,dict):return {k:walk(x,p+'/'+escape(k)) for k,x in v.items()}
   if isinstance(v,list):return [walk(x,p+'/'+str(i)) for i,x in enumerate(v)]
   return v
  self.phases.extend([{'id':n+'-binding','kind':'bind','timeout_sec':3,'mutates':False,'template':walk(value),'bind':binds},{'id':n,'kind':'helper','timeout_sec':timeout,'mutates':scope is not None,'scope':scope or '', 'helper':helper,'input_phase':n+'-binding','checks':[{'pointer':'/status','equals':status},*checks]}]);return ref(n)
 def finish(self,outputs):return {'helpers':self.helpers,'phases':self.phases,'outputs':outputs}
def completion_helper(b):
 b.helper('completion',HERE/'completion.py',[HERE/n for n in ('observer.py','mode_policy.py','frozen-controller-ea3.py','normal7-m1.py','normal_target.py','target.py','normal-session-smoke-launchfix.py')])
def root_scope(profile,mode,entry):return {'packet':profile['packet'],'root_plan_sha256':ref('workflow','/plan_sha256'),'entry':entry,'recovery_mode':mode,'authority_sha256':AUTH,'reviewed_by':ref('inputs','/root_profile_reviewer'),'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False}
def completion_fragment(profile,py,aliases,mode,plan_path):
 b=B(profile,py);completion_helper(b);common={'profile':profile,'root_plan_sha256':ref('workflow','/plan_sha256'),'recovery_mode':mode,'plan_path':plan_path,'target_source_sha256':pin(HERE/'target.py')['sha256'],**aliases}
 lock_only={k:common[k] for k in ('profile','root_plan_sha256','recovery_mode','plan_path','target_source_sha256','packet_profile_sha256')}
 lock_only['initial_production']={'files':{'execution-clearance.json':{'sha256':ref(aliases['initial_production']['files']['execution-clearance.json']['from'],aliases['initial_production']['files']['execution-clearance.json']['pointer']+'/sha256')}}}
 b.step('postjob-locks','completion',{**lock_only,'operation':'ensure-completion-locks','root_scope':root_scope(profile,mode,'ensure-completion-locks')},'COMPLETION_LOCKS_ENSURED',390,'completion-locks')
 observed=b.step('job-return','completion',{**common,'operation':'observe-job-completion','root_scope':root_scope(profile,mode,'observe-job-completion')},'ACTUAL_JOB_COMPLETION_AND_OLD6_RETURN_OBSERVED',450)
 return b.finish({'completed_return':observed['from']})
def original_session_fragment(profile,py,aliases,mode,plan_path):
 b=B(profile,py);completion_helper(b);b.helper('null-native-binding',HERE/'data.py',[])
 wifi=b.step('original6-fresh-wifi','completion',{'operation':'original-session-wifi','profile':profile,'root_plan_sha256':ref('workflow','/plan_sha256'),'recovery_mode':mode,'plan_path':plan_path,'root_scope':root_scope(profile,mode,'original-session-wifi'),'target_source_sha256':pin(HERE/'target.py')['sha256'],'clearance_sha256':aliases['clearance_sha256'],'expected_boot_id':aliases['expected_boot_id']},'ACTUAL_CURRENT_ORIGINAL6_WIFI_OBSERVED',180)
 q=b.step('original-session-null-binding','null-native-binding',{'operation':'bind-original-session-null-native','profile':profile,'root_plan_sha256':ref('workflow','/plan_sha256'),'reviewed_by':ref('inputs','/root_profile_reviewer'),'audit_binding':aliases['audit_binding'],'actual_old_audit':aliases['actual_old_audit'],'fresh_wifi':wifi},'RECOVERY_ORIGINAL_SESSION_BOUND_LOCAL_ONLY',30)
 b.helper('original-session',SESSION/'controller.py',[SESSION/n for n in ('target.py','normal_adapter.py','normal_target.py','rollback-audit.py','normal-session-smoke-launchfix.py')]);done=b.step('original-session','original-session',ref(q['from'],'/binding'),'ORIGINAL_SESSION_TARGET_OBSERVED',270,'original-session-proof',[{'pointer':'/target/normal6_rollback_verified_by_root','equals':True},{'pointer':'/target/no_gpu_workload_after_original_restore','equals':True}]);return b.finish({'original_session':done['from']})
