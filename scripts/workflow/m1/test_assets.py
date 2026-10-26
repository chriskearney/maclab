import datetime,hashlib,importlib.util,json,shlex,unittest
from pathlib import Path
HERE=Path(__file__).parent
sp=importlib.util.spec_from_file_location('asset_source',HERE/'assets.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
class FiniteAssetTransport(unittest.TestCase):
 def b(self):return {'profile':{'device':'m1','packet':'/var/lib/maclab/rc7-m1-cpu-fixture-next','source_packet':'/var/lib/maclab/rc7-m1-cpu-fixture-source','holder':'cpu-owner'},'operation':'reuse-assets','expected_boot_id':'cpu-boot','packet_profile_sha256':'a'*64,'agent_parent':{'path':'/fixture/lab-agent','sha256':'b'*64,'bytes':100},'source_reviewed_by':'CPU source fixture','assets':[{'name':'candidate-files.jsonl','sha256':'c'*64,'bytes':5000000}]}
 def api(self,via='agent'):
  outer=self
  class API:
   def request(self,path,body=None,timeout=60):
    if body is None:return {'name':'m1','alive':True,'state':'ready','kernel':'7.2.11-6-1-ARCH','boot_id':'cpu-boot','lease':{'holder':'cpu-owner','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
    args=shlex.split(body['command']);outer.assertEqual(args[:4],['/usr/bin/python3','-E','-B','-c']);compile(args[4],'<actual-asset-remote>','exec');outer.assertLess(len(body['command'].encode()),120000);q=json.loads(args[5]);outer.assertEqual(q['agent_parent']['path'],'/fixture/lab-agent');return {'exit_code':0,'via':via,'stdout':'{"status":"EXACT_ASSETS_STAGED_ONLY"}','stderr':''}
  return API()
 def test_large_immutable_asset_is_metadata_only_no_network_payload(self):
  b=self.b();out=m.run(b,self.api());self.assertEqual(out['status'],'M1_ASSETS_STAGED_ONLY');self.assertFalse(out['completion_claim']);self.assertNotIn('base64',b['assets'][0])
 def test_actual_reviewed_owner_fits_fixed_one_file_transport(self):
  p=Path('/dev/shm/sf-m1-standing-authority-r1/transact-m1.py')
  if not p.exists():self.skipTest('private immutable source snapshot absent')
  raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();self.assertEqual(h,m.CODE['transact-m1.py']);b=self.b();b.update(operation='stage-input',assets=[{'name':'transact-m1.py','sha256':h,'bytes':len(raw),'source':{'path':str(p),'sha256':h,'bytes':len(raw)}}]);out=m.run(b,self.api());self.assertEqual(out['status'],'M1_ASSETS_STAGED_ONLY')
 def test_credential_leaf_and_unreviewed_owner_refused(self):
  b=self.b();b['assets'][0]['name']='id_ed25519'
  with self.assertRaisesRegex(RuntimeError,'unsupported named artifact'):m.run(b,self.api())
  b=self.b();b.update(operation='stage-input',assets=[{'name':'transact-m1.py','sha256':'0'*64,'bytes':3}])
  with self.assertRaisesRegex(RuntimeError,'unreviewed source code'):m.run(b,self.api())
 def test_serial_result_cannot_be_completed(self):
  out=m.run(self.b(),self.api('serial'));self.assertEqual(out['status'],'M1_ASSET_STAGE_FAILED');self.assertEqual(out['actual_exec']['via'],'serial')
