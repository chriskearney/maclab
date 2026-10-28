import base64,copy,importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('retention_data',HERE/'retention_bind.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class FreshBindings(unittest.TestCase):
 def fixture(self):
  d=Path('/dev/shm/sf-workflow-m1-backup-validation-r4/state/state.json')
  if not d.exists():self.skipTest('retained authentic offline proof fixture absent')
  r=json.loads(d.read_bytes());p=r['records']['cache-binding']['output']['profile'];main=r['records']['backup-collected']['output']['target'];old=Path('/dev/shm/sf-rc-m1-REPROBE-M5-APPEND-RETENTION-RECEIPT.json').read_bytes();return {'profile':p,'operation':'main','root_plan_sha256':r['plan_sha256'],'boot_id':main['boot_id'],'main_capture':main,'retained_candidate_receipts':[{'sha256':m.H(old),'raw_base64':base64.b64encode(old).decode()}]}
 def test_real_historical_capture_projects_request_without_completion_reuse(self):
  b=self.fixture();v=m.make(b);self.assertEqual(v['request']['source']['target_backup_receipt_sha256'],b['main_capture']['receipt_sha256']);self.assertEqual(len(v['request']['objects']),7);self.assertEqual(v['mode'],'main');self.assertEqual(v['request']['destination'].split('/')[-1],Path(b['profile']['packet']).name)
  self.assertEqual(v['request']['objects']['boot.bin.original']['allowed_retained_sources'][0]['sha256'],b['main_capture']['objects']['boot.bin.original']['sha256'])
 def test_raw_capture_and_stale_packet_refused(self):
  for change in ('receipt','packet'):
   b=self.fixture()
   if change=='receipt':b['main_capture']['receipt']['status']='FORGED'
   else:b['profile']['packet']+='-different'
   with self.assertRaisesRegex(RuntimeError,'capture mismatch'):m.make(b)
 def test_tampered_candidate_metadata_refused(self):
  b=self.fixture();b['retained_candidate_receipts'][0]['sha256']='0'*64
  with self.assertRaisesRegex(RuntimeError,'candidate receipt source drift'):m.make(b)
 def test_authentic_new_parent_and_supplement_can_bind_but_old_completion_cannot(self):
  b=self.fixture();b['profile']['supplement_source']={'sha256':'c29ae63f9de7169146318ed48c7cf0c14c3463af395aba0ffab0124f9ffa2bf6'};b['operation']='supplement';b['supplement_capture']=json.loads(Path('/dev/shm/sf-workflow-m1-supplement-validation-r6/state/state.json').read_bytes())['records']['supplement-collect']['output']['target'];b['actual_main_retention']=json.loads(Path('/dev/shm/sf-workflow-m1-main-retention-validation-r5/ACTUAL-M5-FETCH.json').read_bytes());v=m.make(b);self.assertEqual(v['request']['supplement']['parent_main_receipt_sha256'],'287e10569e62087aaf2f5ddbfcdf1d28925ea9f06e045399fbdfb9877051b146');b['root_plan_sha256']='f'*64
  with self.assertRaisesRegex(RuntimeError,'parent main receipt raw/identity mismatch'):m.make(b)
 def test_fetch_fixed_path_plan_hash_and_volume(self):
  b=self.fixture();r=json.loads(Path('/dev/shm/sf-workflow-m1-main-retention-validation-r5/state/state.json').read_bytes())['records']['main-retained']['output'];b.update(operation='fetch',mode='main',retention_result=r,storage_dev=16777237);v=m.make(b);self.assertEqual(v['receipt_sha256'],r['receipt_sha256']);r['receipt_path']='/Users/chriskearney/.ssh/id_ed25519'
  with self.assertRaisesRegex(RuntimeError,'newly retained receipt'):m.make(b)
if __name__=='__main__':unittest.main()
