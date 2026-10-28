import importlib.util,json,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('owner_invoker',HERE/'owner-invoke.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
s=importlib.util.spec_from_file_location('technical_cpu_fixture',HERE/'test_technical.py');fixture=importlib.util.module_from_spec(s);s.loader.exec_module(fixture)
class ImmediateAdmission(fixture.Technical):
 def test_actual_technical_observer_is_before_each_owner_call_and_failure_stops(self):
  b=self.binding();b.update(action='invoke-packet',entry='install',deadline_seconds=1900,root_scope={'root_plan_sha256':'a'*64});sdk,technical=m.sources();api=self.api();called=[]
  def invoke(binding,client):called.append('actual-owner-invoke');self.assertEqual(binding['entry'],'install');self.assertEqual(client.reads,2);return {'status':'M1_INVOKE_PACKET_OBSERVED','actual_exec':{'via':'agent','exit_code':0},'target':{'completion_claim':False}}
  sdk.run=invoke
  with patch.object(m,'sources',lambda:(sdk,technical)):
   out=m.run(b,api);self.assertEqual(called,['actual-owner-invoke']);self.assertFalse(out['completion_claim']);self.assertNotIn('SENTINEL-SECRET',json.dumps(out))
   with self.assertRaisesRegex(RuntimeError,'OOB route unhealthy'):m.run(b,self.api(error=True))
   self.assertEqual(len(called),1)
 def test_packet_c_observer_is_not_skipped_and_no_unreviewed_owner_entry(self):
  b=self.binding();b.update(action='invoke-packet',entry='rollback-packages',deadline_seconds=1900,root_scope={'root_plan_sha256':'a'*64});sdk,technical=m.sources();sdk.run=lambda binding,client:{'status':'OWNER_ONLY'}
  with patch.object(m,'sources',lambda:(sdk,technical)):
   with self.assertRaisesRegex(RuntimeError,'OOB route unhealthy'):m.run(b,self.api(error=True))
  b['entry']='arbitrary'
  with self.assertRaisesRegex(RuntimeError,'finite original owner'):m.run(b,self.api())
 def test_frozen_source_bytes_and_module_loader_real_pin(self):
  sdk,t=m.sources();self.assertEqual(sdk.__file__,str(HERE/'frozen-controller-ea3.py'));self.assertEqual(t.__file__,str(HERE/'technical.py'))
  with self.assertRaisesRegex(RuntimeError,'hash drift'):m.load('wrong','technical.py','0'*64)
if __name__=='__main__':unittest.main()
