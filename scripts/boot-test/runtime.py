"""Common descriptor-driven runner lifecycle. No device-specific restore algorithm.
Only reviewed profile compilers/owners produce hardware and restoration evidence.
"""
import datetime,json,os,sys,time,urllib.parse,urllib.request
from pathlib import Path
import catalog,util as u
SDK_SHA='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
HERE=Path(__file__).resolve().parent
def at(doc,pointer):
 catalog.need(pointer=='' or pointer.startswith('/'),'finite JSON pointer')
 for part in pointer.split('/')[1:]:
  part=part.replace('~1','/').replace('~0','~');doc=doc[int(part)] if isinstance(doc,list) else doc[part]
 return doc

def expiry(lease):
 t=datetime.datetime.fromisoformat(lease['expires'].replace('Z','+00:00'));catalog.need(t.tzinfo is not None,'timezone-aware lease');return t

def gate(d,p,review,mode,seconds=None):
 basis=catalog.baseline(d,p,mode);lease=d.get('lease');catalog.need(isinstance(lease,dict) and lease['holder']==review['holder'],'owned lease required');remaining=(expiry(lease)-datetime.datetime.now(datetime.timezone.utc)).total_seconds();catalog.need(remaining>=(review['minimum_lease_seconds'] if seconds is None else seconds),'lease runtime/cleanup budget insufficient');return basis

class API:
 def __init__(self):
  path=HERE/'frozen-controller-ea3.py';raw=u.local(str(path),{'sha256':SDK_SHA,'bytes':path.stat().st_size})[1];m=type(sys)('frozen_api');m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);self.inner=m.API(m.config())
 def request(self,*a,**k):return self.inner.request(*a,**k)
 def release(self,device,holder):
  cfg=self.inner.c;path='/api/devices/'+urllib.parse.quote(device,safe='')+'/lease?holder='+urllib.parse.quote(holder,safe='');req=urllib.request.Request(cfg['url']+path,method='DELETE',headers={'Authorization':'Bearer '+cfg['token']})
  with urllib.request.urlopen(req,timeout=10) as r:b=r.read(4097)
  catalog.need(b.strip()==b'ok','bounded raw lease release response differs')

def select(api,p,review,transaction,mode,out):
 cap=api.request('/api/recovery',timeout=10);catalog.need(type(cap.get('schema')) is int and cap['schema']==1 and cap.get('per_job_oob_isolation') is True and cap.get('transaction_isolation') is True and mode in cap.get('modes',[]),'required controller isolation unavailable');base='/api/devices/'+p['device'];d=api.request(base,timeout=10);basis=catalog.baseline(d,p,mode);lease=d.get('lease');catalog.need(not lease or lease['holder']==review['holder'],'foreign lease cannot be acquired/renewed')
 if not lease or (expiry(lease)-datetime.datetime.now(datetime.timezone.utc)).total_seconds()<review['minimum_lease_seconds']:
  q={'holder':review['holder'],'ttl_sec':review['minimum_lease_seconds']+120};u.write(out/'LEASE-INTENT.json',{'device':p['device'],'request':q,'transaction':transaction,'expected_boot_id':d['boot_id'],'automatic_retry':False})
  try:l=api.request(base+'/lease',q,timeout=15)
  except BaseException as e:
   seen=None
   try:seen=api.request(base,timeout=10).get('lease')
   except Exception:pass
   u.write(out/'LEASE-AMBIGUOUS.json',{'error_type':type(e).__name__,'lease_readback':seen,'automatic_retry':False});raise
  u.write(out/'LEASE-RESPONSE.json',{k:l.get(k) for k in ('holder','expires')});remaining=(expiry(l)-datetime.datetime.now(datetime.timezone.utc)).total_seconds();catalog.need(l['holder']==review['holder'] and review['minimum_lease_seconds']<=remaining<=q['ttl_sec']+30,'actual lease holder/TTL differs');fresh=api.request(base,timeout=10);catalog.need(fresh['lease']==l and fresh['boot_id']==d['boot_id'],'lease/boot readback differs');d=fresh
 gate(d,p,review,mode);q={'mode':mode,'holder':review['holder'],'transaction':transaction};u.write(out/'MODE-INTENT.json',{'request':q,'current_boot_id':d['boot_id'],'automatic_retry':False});r=api.request(base+'/recovery-mode',q,timeout=25);u.write(out/'MODE-RESPONSE.json',{k:r.get(k) for k in ('schema','device','mode','holder','transaction','quiescent')});catalog.need(r=={'schema':1,'device':p['device'],**q,'quiescent':True},'quiescent transaction response differs');fresh=api.request(base,timeout=10);gate(fresh,p,review,mode);catalog.need(fresh['boot_id']==d['boot_id'] and fresh['effective_recovery_mode']==mode and fresh['recovery_transaction']==transaction and fresh['recovery_holder']==review['holder'],'selected transaction actual readback differs')
 if mode=='serial-assisted':
  o=api.request(base+'/oob',timeout=10);catalog.need(str(o.get('controller','')).startswith('oobd ') and o.get('serial_connected') is True and o.get('status') and not o.get('error'),'live serial-assisted route unavailable')
 return {'schema':'maclab.profile-isolation/1','selection':r,'baseline':basis,'api_model_is_not_target_board_proof':True,'oob_observed':mode=='serial-assisted','physical_recovery_confirmed':False}

def restored(plan,st,result,p,plan_sha,packet):
 rc=p['restore'];e=rc['runtime_evidence'];records=st['records'];ids=[x['id'] for x in plan['phases']];catalog.need(ids[-1]==e['final_assertion_phase'] and plan['phases'][-1]['kind']=='bind' and plan['phases'][-1].get('mutates') is False,'explicit final assertion must be last/nonmutating')
 if result.get('stop_reason'):return None
 if result['exit_code']==0:
  if st.get('blocker') or not all(records.get(n,{}).get('state')=='done' for n in ids):return None
 else:
  if not str(st.get('blocker','')).startswith(e['final_assertion_phase']+':') or records.get(ids[-1],{}).get('state')!='failed' or not all(records.get(n,{}).get('state')=='done' for n in ids[:-1]):return None
 verdict=records[e['verdict_phase']]['output'];catalog.need(verdict['restoration_verified'] is True,'actual restoration verdict missing');passed=verdict['passed'];catalog.need(type(passed) is bool,'honest typed test verdict');catalog.need(passed is (result['exit_code']==0),'runner exit/test assertion contradiction')
 if passed:catalog.need(verdict['original_outcome']=='pass' and not verdict.get('original_canceled'),'a failed/canceled job is never a pass')
 if not passed:catalog.need(verdict['original_outcome'] in {'tests_failed','unknown','booted_unhealthy','panicked','hung','boot_failed','stage_failed','build_failed','infra_error','canceled'} or verdict.get('original_canceled') is True,'actual nonpass outcome missing')
 audit=at(records[e['audit_phase']]['output'],e['audit_pointer']);catalog.need(audit['status']==rc['required_status'],'actual original restoration status differs')
 for ptr,expected in e['checks'].items():actual=at(audit,ptr);catalog.need(type(actual) is type(expected) and actual==expected,'actual restored-state assertion differs: '+ptr)
 binds=e['bindings'];catalog.need(at(audit,binds['packet'])==packet and at(audit,binds['plan_sha256'])==plan_sha,'actual audit packet/Plan differs')
 absent=e.get('absent_package_checks',{});catalog.need(set(absent)==set(p['original']['absent_packages']),'all originally absent packages need explicit actual proof')
 for name,condition in absent.items():catalog.need(at(audit,condition['pointer'])==condition['equals'],'originally absent package not proved absent: '+name)
 return {'passed':passed,'original_outcome':verdict['original_outcome'],'original_canceled':verdict.get('original_canceled',False),'boot_id':at(audit,binds['boot_id']),'audit_status':audit['status']}

def execute(prepared,authorization,state,api=None):
 out=Path(prepared);bundle=u.read_json(str(out/'INTAKE.json'));p,pp=catalog.load(bundle['catalog'],bundle['profile_id'],bundle['device'],True);catalog.runtime_contract(p);review=catalog.unique(catalog.read_pin(bundle['review']));catalog.need(review['status']=='ROOT_SOURCE_REVIEWED' and review['catalog']==bundle['catalog'] and review['profile']==pp,'retained source review differs');catalog.need(type(review['runtime_budget_seconds']) is int and 300<=review['runtime_budget_seconds']<=86400 and review['minimum_lease_seconds']>=review['runtime_budget_seconds']+300,'reviewed lifecycle budget');run_dir=out/('run-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+u.uuid.uuid4().hex[:8]);run_dir.mkdir(mode=0o700);started=time.monotonic()
 try:
  planpin=bundle['compiled']['plan'];plan=catalog.unique(catalog.read_pin(planpin));catalog.need(plan['inputs']['catalog_profile_sha256']==pp['sha256'] and plan['inputs']['profile_source_review_sha256']==bundle['review']['sha256'] and set(bundle['artifact_pins'])==set(p['candidate']['artifact_slots']) and plan['inputs']['source_artifact_intake']=={n:{k:v[k] for k in ('sha256','bytes')} for n,v in bundle['artifact_pins'].items()} and all(v['sha256']==p['candidate']['artifact_slots'][n]['sha256'] and v['bytes']==p['candidate']['artifact_slots'][n]['bytes'] for n,v in bundle['artifact_pins'].items()),'catalog/review/artifacts not bound to exact final Plan');source_pins={}
  for pin in [p['compiler']['source'],*p['compiler']['closure'],*[pin for role in p['sources'].values() for pin in [role['source'],*role['closure']]],*review['source_files']]:catalog.read_pin(pin,64*1024**2);source_pins[pin['path']]=pin
  catalog.validate_plan(plan,p,bundle['packet'],bundle['recovery_mode'],source_pins)
  for name,pin in bundle['artifact_pins'].items():u.local(pin['path'],pin,512*1024**2,False)
  runner=review['runner'];u.local(runner['path'],runner,64*1024**2,False);authpin,raw,_=u.local(authorization);auth=u.unique(raw);catalog.need(auth['schema']=='maclab.workflow-authorization/1' and auth['plan_sha256']==planpin['sha256'] and auth['device']==p['device'] and type(auth['approved_by']) is str and auth['approved_by'].strip(),'retained plan-bound authorization required');u.local(auth['evidence']['path'],auth['evidence']);until=datetime.datetime.fromisoformat(auth['valid_until'].replace('Z','+00:00'));catalog.need(until.tzinfo is not None and until>datetime.datetime.now(datetime.timezone.utc),'authorization expired');scopes={x['scope'] for x in plan['phases'] if x.get('mutates')};catalog.need(scopes<=set(auth['scopes'])<=set(review['allowed_scopes']),'authorization scope differs');storage=u.state_storage(state);check=u.process([runner['path'],'check','--plan',planpin['path']],run_dir,'check',30);catalog.need(check['exit_code']==0 and not check['stop_reason'],'actual runner check failed');checked=u.read_json(str(run_dir/'check.stdout'));catalog.need(checked['valid'] is True and checked['plan_sha256']==planpin['sha256'] and checked['device']==p['device'],'actual runner check identity differs');c=api or API();isolation=select(c,p,review,plan['id'],bundle['recovery_mode'],run_dir);u.write(run_dir/'START.json',{'plan':planpin,'authorization':authpin,'state':storage,'isolation':isolation,'automatic_retry':False});r=u.process([runner['path'],'run','--plan',planpin['path'],'--state',state,'--authorization',authorization],run_dir,'runner',review['runtime_budget_seconds']);result={'schema':'maclab.device-profile-run-result/1','device':p['device'],'plan':planpin,'runner':r,'elapsed_seconds':time.monotonic()-started,'status':'FAILED_OR_INCOMPLETE','lease_retained_for_recovery':True,'automatic_retry':False};u.write(run_dir/'RESULT.json',result)
  if not r.get('stop_reason') and (Path(state)/'state.json').exists():
   verified=u.process([runner['path'],'status','--plan',planpin['path'],'--state',state],run_dir,'status',30);catalog.need(verified['exit_code']==0 and not verified['stop_reason'],'actual runner status failed');st=u.read_json(str(Path(state)/'state.json'));catalog.need(st['plan_sha256']==planpin['sha256'] and st['device']==p['device'],'retained state identity differs');done=restored(plan,st,r,p,planpin['sha256'],bundle['packet'])
   if done is not None:
    d=c.request('/api/devices/'+p['device'],timeout=10);gate(d,p,review,bundle['recovery_mode'],1);catalog.need(d['boot_id']==done['boot_id'],'actual final original boot differs');u.write(run_dir/'LEASE-RELEASE-INTENT.json',{'holder':review['holder'],'device':p['device'],'restore':done,'automatic_retry':False})
    try:c.release(p['device'],review['holder'])
    except BaseException as e:
     observed=None
     try:observed=c.request('/api/devices/'+p['device'],timeout=10).get('lease')
     except Exception:pass
     u.write(run_dir/'LEASE-RELEASE-AMBIGUOUS.json',{'error_type':type(e).__name__,'lease_readback':observed,'automatic_retry':False});raise
    fresh=c.request('/api/devices/'+p['device'],timeout=10);catalog.need(not fresh.get('lease') or fresh['lease']['holder']!=review['holder'],'owned lease remains');result.update(status='PASSED_RESTORED_LEASE_RELEASED' if done['passed'] else 'TESTS_FAILED_RESTORED_LEASE_RELEASED',actual_verdict=done,lease_retained_for_recovery=False);u.replace(run_dir/'RESULT.json',result)
  return {**result,'run_output':str(run_dir)}
 except BaseException as e:
  failure={'schema':'maclab.profile-run-failure/1','status':'STOPPED_OR_INCOMPLETE','error_type':type(e).__name__,'reason':str(e)[:4096] if isinstance(e,(catalog.Refused,u.Stop)) else None,'private_run_output':str(run_dir),'elapsed_seconds':time.monotonic()-started,'runner_launch_intent_retained':(run_dir/'START.json').exists(),'automatic_retry':False,'lease_release_not_confirmed':True}
  # Preserve any original result; forensic failure recording cannot replace the
  # actual exception or trigger a runner/owner retry.
  try:
   u.write(run_dir/'FAILURE.json',failure)
   if not (run_dir/'RESULT.json').exists():u.write(run_dir/'RESULT.json',failure)
  except Exception:pass
  try:e.private_failure_output=str(run_dir)
  except Exception:pass
  raise
