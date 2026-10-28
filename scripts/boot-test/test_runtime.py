"""Typed cross-device lifecycle controls with explicit API/record simulations."""
import copy,datetime,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import intake,util
import catalog,runtime
import test_catalog as fixtures
class API:
 def __init__(self,p):self.p=p;self.calls=[];self.d={'name':p['device'],'kernel':p['original']['kernel'],'known_good':p['original']['kernel'],'state':'ready','alive':True,'boot_id':'CPU-original-boot','cmdline':'ordinary','facts':{'machine':'aarch64','dt_model':p['dt_model']},'lease':None}
 def release(self,device,holder):
  assert device==self.p['device'] and self.d['lease']['holder']==holder;self.calls.append(('DELETE '+device,holder));self.d['lease']=None
 def request(self,path,body=None,timeout=60):
  self.calls.append((path,body));base='/api/devices/'+self.p['device']
  if path=='/api/recovery':return {'schema':1,'modes':['network-only','serial-assisted'],'per_job_oob_isolation':True,'transaction_isolation':True}
  if path==base:return copy.deepcopy(self.d)
  if path==base+'/lease':self.d['lease']={'holder':body['holder'],'expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=body['ttl_sec'])).isoformat()};return self.d['lease']
  if path==base+'/recovery-mode':self.d.update(effective_recovery_mode=body['mode'],recovery_transaction=body['transaction'],recovery_holder=body['holder']);return {'schema':1,'device':self.p['device'],**body,'quiescent':True}
  if path==base+'/oob':return {'controller':'oobd CPU','status':'connected','serial_connected':True}
  raise AssertionError('unexpected namespace '+path)
class Runtime(unittest.TestCase):
 def setUp(self):fixtures.Catalog.setUp(self)
 def artifact(self,*a,**k):return fixtures.Catalog.artifact(self,*a,**k)
 def files(self,*a,**k):return fixtures.Catalog.files(self,*a,**k)
 def profile(self,*a,**k):return fixtures.Catalog.profile(self,*a,**k)
 def test_generic_m3_custom_profile_actually_invokes_runner_and_proves_absent_restore(self):
  p,artifact=self.profile('m3pro');cp,reviewpin=self.files(p);review=catalog.unique(catalog.read_pin(reviewpin));runner=self.P/'runner';runner.write_text("""#!/usr/bin/python3
import json,pathlib,hashlib,sys
args=sys.argv;path=pathlib.Path(args[args.index('--plan')+1]);raw=path.read_bytes();plan=json.loads(raw);h=hashlib.sha256(raw).hexdigest();rc=plan['inputs']['restoration_contract'];device=plan['device']
if args[1]=='run':
 state=pathlib.Path(args[args.index('--state')+1]);records={p['id']:{'state':'done','output':{}} for p in plan['phases']};e=rc['runtime_evidence'];records[e['audit_phase']]['output']={'target':{'status':rc['required_status'],'packet':'/var/lib/maclab/'+plan['id'],'root_plan_sha256':h,'boot_id':'CPU-original-boot','packages':{'omarchy-mac-boot':'absent'}}};records[e['verdict_phase']]['output']={'passed':True,'restoration_verified':True,'original_outcome':'pass'};(state/'state.json').write_text(json.dumps({'plan_sha256':h,'device':device,'records':records}));(path.parent.parent/'ACTUAL-RUNNER-LAUNCHED').write_text('CPU fixture ONLY')
print(json.dumps({'valid':True,'plan_sha256':h,'device':device}))
""");runner.chmod(0o700);review.update(runner=intake.pin(runner),runtime_budget_seconds=3600,minimum_lease_seconds=3900,allowed_scopes=[]);reviewpath=Path(reviewpin['path']);reviewpath.write_text(json.dumps(review));reviewpath.chmod(0o600);reviewpin=intake.pin(reviewpath);out=self.P/'output';request={'device':'m3pro','recovery_mode':'network-only','artifacts':{'linux-aurora':str(artifact)}};result=intake.run(cp,p['id'],request,reviewpin,out,'/var/lib/maclab/rc7-m3pro-CPU-exec',True);plan=result['compiled']['plan'];auth=self.P/'auth.json';intake.write(auth,{'schema':'maclab.workflow-authorization/1','plan_sha256':plan['sha256'],'device':'m3pro','approved_by':'CPU-only','evidence':reviewpin,'valid_until':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat(),'scopes':[]});api=API(p)
  def state(path):Path(path).mkdir(mode=0o700);return {'path':path,'filesystem':'CPU_FIXTURE_NOT_DURABLE'}
  with patch.object(util,'state_storage',state):r=runtime.execute(str(out),str(auth),str(self.P/'state'),api)
  self.assertEqual(r['status'],'PASSED_RESTORED_LEASE_RELEASED');self.assertTrue((out/'ACTUAL-RUNNER-LAUNCHED').exists());self.assertIsNone(api.d['lease']);self.assertEqual(api.calls[-2][0],'DELETE m3pro');self.assertFalse(any('/devices/m1/' in path for path,body in api.calls))
 def test_three_device_mode_lease_routes_are_data_driven(self):
  for device in ('m1','m1air','m3pro'):
   for mode in ('network-only','serial-assisted'):
    p,a=self.profile(device);api=API(p);out=self.P/(device+'-'+mode);out.mkdir(mode=0o700);review={'holder':'CPU-owner','minimum_lease_seconds':3900};doc=runtime.select(api,p,review,'rc7-'+device+'-CPU',mode,out);self.assertEqual(doc['selection']['device'],device);self.assertEqual(doc['baseline']['current_kernel'],p['original']['kernel']);self.assertFalse(any(path.startswith('/api/devices/m1/') for path,b in api.calls) if device!='m1' else False);self.assertEqual(sum(path.endswith('/oob') for path,b in api.calls),int(mode=='serial-assisted'));self.assertFalse(doc['physical_recovery_confirmed'])
 def records(self,device='m3pro',failed=False):
  p,a=self.profile(device);ids=p['restore']['phase_order'];plan={'phases':[{'id':n,'kind':'bind','mutates':False} for n in ids]};records={n:{'state':'done','output':{}} for n in ids};records['verdict']['output']={'restoration_verified':True,'passed':not failed,'original_outcome':'tests_failed' if failed else 'pass'};records['restore']['output']={'target':{'status':p['restore']['required_status'],'packet':'/var/lib/maclab/rc7-'+device+'-CPU','root_plan_sha256':'a'*64,'boot_id':'CPU-restored-boot','packages':{'omarchy-mac-boot':'absent'}}};st={'records':records,'blocker':''}
  if failed:records['final']['state']='failed';st['blocker']='final: tests_failed'
  return p,plan,st,{'exit_code':1 if failed else 0,'stop_reason':None}
 def test_custom_original_and_absent_boot_package_are_required_for_release(self):
  p,plan,st,result=self.records();out=runtime.restored(plan,st,result,p,'a'*64,'/var/lib/maclab/rc7-m3pro-CPU');self.assertTrue(out['passed']);bad=copy.deepcopy(st);bad['records']['restore']['output']['target']['packages']['omarchy-mac-boot']='unexpected-installed'
  with self.assertRaises(catalog.Refused):runtime.restored(plan,bad,result,p,'a'*64,'/var/lib/maclab/rc7-m3pro-CPU')
 def test_restored_failure_never_becomes_pass_and_earlier_failure_holds(self):
  p,plan,st,result=self.records(failed=True);out=runtime.restored(plan,st,result,p,'a'*64,'/var/lib/maclab/rc7-m3pro-CPU');self.assertFalse(out['passed']);self.assertEqual(out['original_outcome'],'tests_failed');st['records']['restore']['state']='failed';self.assertIsNone(runtime.restored(plan,st,result,p,'a'*64,'/var/lib/maclab/rc7-m3pro-CPU'))
 def test_incomplete_runtime_contract_is_unsupported(self):
  p,a=self.profile('m1air');del p['restore']['runtime_evidence']
  with self.assertRaisesRegex(catalog.Refused,'INCOMPLETE'):catalog.runtime_contract(p)
 def test_io_and_pidfd_utility_matches_reviewed_source(self):
  import hashlib
  self.assertEqual(hashlib.sha256((Path(__file__).parent/'util.py').read_bytes()).hexdigest(),'58afd36ed3f05a0cd3f52912639c4a6a680d62cb0c8f66c7452ba84e4f58a427')
if __name__=='__main__':unittest.main()
