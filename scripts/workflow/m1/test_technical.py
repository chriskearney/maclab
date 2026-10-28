import copy,datetime,importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('technical_observer',HERE/'technical.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Technical(unittest.TestCase):
 def binding(self):return {'profile':{'device':'m1','board':'apple,j293','packet':'/var/lib/maclab/rc7-m1-cpu-readiness-new','holder':'owner'},'root_plan_sha256':'a'*64,'expected_boot_id':'cpu-real-boot','expected_kernel':'7.2.11-6-1-ARCH','minimum_lease_seconds':2700}
 def api(self,error=False,drift=False):
  outer=self
  class API:
   reads=0
   def request(self,path,body=None,timeout=60):
    outer.assertIsNone(body)
    if path.endswith('/oob'):return {'controller':'oobd fixture','status':'' if error else 'connected','error':'No connection detected' if error else '', 'token':'SENTINEL-SECRET'}
    self.reads+=1;return {'name':'m1','state':'ready','alive':True,'tier':2,'boot_id':'wrong' if drift and self.reads==2 else 'cpu-real-boot','kernel':'7.2.11-6-1-ARCH','cmdline':'ordinary','facts':{'machine':'aarch64','compatible':['apple,j293'],'token':'SENTINEL-SECRET'},'oob':{'token':'SENTINEL-SECRET'},'token':'SENTINEL-SECRET','lease':{'holder':'owner','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat(),'token':'SENTINEL-SECRET'}}
  return API()
 def test_fresh_safe_projection_readonly_and_no_credentials(self):
  out=m.observe(self.binding(),self.api());self.assertEqual(out['status'],'FRESH_M1_TECHNICAL_READINESS_OBSERVED');self.assertNotIn('SENTINEL-SECRET',json.dumps(out));self.assertFalse(out['manual_saved_work_confirmed']);self.assertFalse(out['job_submitted'])
 def test_live_oob_failure_and_boot_drift_are_stops_not_cached_pass(self):
  for api in (self.api(error=True),self.api(drift=True)):
   with self.assertRaises(RuntimeError):m.observe(self.binding(),api)
 def test_network_calls_take_only_remaining_global_readiness_budget(self):
  base=self.api();timeouts=[]
  class Timed:
   def request(self,path,body=None,timeout=60):timeouts.append(timeout);return base.request(path,body,timeout)
  ticks=iter([100,100,108,119,120]);out=m.observe(self.binding(),Timed(),monotonic=lambda:next(ticks));self.assertEqual(timeouts,[10,10,1]);self.assertEqual(out['status'],'FRESH_M1_TECHNICAL_READINESS_OBSERVED')
  ticks=iter([100,121])
  with self.assertRaisesRegex(RuntimeError,'request deadline exceeded'):m.observe(self.binding(),Timed(),monotonic=lambda:next(ticks))
 def test_network_exception_does_not_export_configured_url_or_token(self):
  class Failed:
   def request(self,*a,**k):raise OSError('http://private.invalid/?token=SENTINEL-CREDENTIAL')
  with self.assertRaisesRegex(RuntimeError,'technical metadata request failed: OSError') as raised:m.observe(self.binding(),Failed())
  self.assertNotIn('SENTINEL',str(raised.exception));self.assertTrue(raised.exception.__suppress_context__)
 def test_slow_observation_or_too_short_phase_lease_refused(self):
  t=datetime.datetime.now(datetime.timezone.utc);times=iter([t,t+datetime.timedelta(seconds=21),t+datetime.timedelta(seconds=21)])
  with self.assertRaisesRegex(RuntimeError,'freshness bound'):m.observe(self.binding(),self.api(),lambda:next(times))
  b=self.binding();b['minimum_lease_seconds']=1900
  with self.assertRaisesRegex(RuntimeError,'cleanup lease budget'):m.observe(b,self.api())
if __name__=='__main__':unittest.main()
