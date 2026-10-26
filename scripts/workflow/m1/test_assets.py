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
 def test_normal7_cannot_stage_install_owner_or_assets(self):
  b=self.b();b['expected_kernel']='7.2.11-7-1-ARCH'
  with self.assertRaisesRegex(RuntimeError,'only PacketC clearance'):m.run(b,self.api())
 def produced_binding(self):
  import base64
  b=self.b();p=HERE/'prepare.py';source=p.read_bytes();raw=b'{"fresh":"root-reviewed producer data"}';h=hashlib.sha256(raw).hexdigest();b.update(operation='stage-input',root_plan_sha256='d'*64,producer_source={'path':str(p),'sha256':hashlib.sha256(source).hexdigest(),'bytes':len(source)},producer_scope={'schema':'maclab.m1-producer-stage-scope/1','packet':b['profile']['packet'],'expected_boot_id':b['expected_boot_id'],'root_plan_sha256':'d'*64,'source_sha256':hashlib.sha256(source).hexdigest(),'file_name':'MIRROR-RECEIPT.json','file_sha256':h,'file_bytes':len(raw)},assets=[{'name':'MIRROR-RECEIPT.json','sha256':h,'bytes':len(raw),'base64':base64.b64encode(raw).decode()}]);return b
 def test_finite_fresh_proof_descriptor_stages_without_repeating_full_producer(self):
  b=self.produced_binding();out=m.run(b,self.api());self.assertEqual(out['status'],'M1_ASSETS_STAGED_ONLY');self.assertNotIn('files',b['producer_scope'])
 def test_stale_selected_producer_packet_plan_or_source_refused(self):
  for key in ('packet','root_plan_sha256','source_sha256','file_sha256'):
   b=self.produced_binding();b['producer_scope'][key]='f'*64
   with self.subTest(key=key),self.assertRaises(RuntimeError):m.run(b,self.api())
 def test_perrun_decision_and_fallback_files_must_not_be_reused_as_immutable(self):
  for name in ('OWNER-BACKUP-DECISIONS.json','FALLBACK-CONFIG-CLOSURE.json'):
   b=self.b();b['assets'][0]['name']=name
   with self.subTest(name=name),self.assertRaisesRegex(RuntimeError,'unsupported named artifact'):m.run(b,self.api())
 def test_serial_result_cannot_be_completed(self):
  out=m.run(self.b(),self.api('serial'));self.assertEqual(out['status'],'M1_ASSET_STAGE_FAILED');self.assertEqual(out['actual_exec']['via'],'serial')
