import copy,hashlib,importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('fixed_compiler',HERE/'compile.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def pin(p):return m.pin(p)
class BackupGraph(unittest.TestCase):
 def recipe(self):
  p=Path('/home/chrisk/.cache/sf-coordination-20261025/maclab-workflow-m1/M1-COHORT-BACKUP-RECIPE.json')
  if not p.exists():self.skipTest('private reviewed source recipe absent')
  r=json.loads(p.read_bytes());r['supplement_source']=pin(HERE/'backup-supplement.py');r['independent_retention']={'closure_comparator':pin('/dev/shm/sf-m1-code-closure-compare-r1/compare.py'),'closure_baseline':pin('/dev/shm/sf-rc-m1-REPROBE-ACTUAL-READONLY-METADATA.json'),'m5_receipt_reader':pin('/dev/shm/sf-m5-receipt-reader-root-r2.py'),'retention_candidate_receipts':[pin('/dev/shm/sf-rc-m1-REPROBE-M5-APPEND-RETENTION-RECEIPT.json')]};return r
 def compile(self,r,t):
  out=Path(t)/'compiled';m.compile_profile(r,'/var/lib/maclab/rc7-m1-cpu-full-backup-source',out);return json.loads((out/'WORKFLOW.CLOSED.json').read_bytes())
 def test_concrete_recipe_compiles_closed_fresh_receipt_graph_and_go_validates(self):
  r=self.recipe()
  with tempfile.TemporaryDirectory(dir='/dev/shm') as t:
   p=self.compile(r,t);names=[x['id'] for x in p['phases']];self.assertIn('combined-actual-receipt',names);self.assertIn('source-closure-compared',names);self.assertLessEqual(len(names),100);self.assertIsNone(p['inputs']['root_profile_reviewer']);self.assertEqual(p['helpers']['m1']['closure'][-1]['sha256'],pin(HERE/'closure-collector.py')['sha256'])
   # Profiles in the original12 and extension are one final immutable value.
   for phase in p['phases']:
    if phase['kind']=='bind' and 'profile'in phase['template'] and phase['template']['profile'] is not None:self.assertEqual(phase['template']['profile'],p['inputs']['profile'])
   binary=Path('/dev/shm/lab-workflow-ea3fbfc')
   if binary.exists():
    run=subprocess.run([str(binary),'check','--plan',str(Path(t)/'compiled/WORKFLOW.CLOSED.json')],capture_output=True,text=True);self.assertEqual(run.returncode,0,run.stderr+run.stdout)
 def test_raw_capture_pin_projection_preserves_strict_comparator_shape(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as t:
   p=self.compile(self.recipe(),t);phase=next(x for x in p['phases'] if x['id']=='source-closure-compared-binding');self.assertEqual(set(phase['template']['current_capture_pin']),{'path','sha256','bytes'});self.assertNotIn('/current_capture_pin',phase['bind']);self.assertIn('/current_capture_pin/sha256',phase['bind'])
 def test_historical_capture_only_supplement_pin_cannot_compile_full_graph(self):
  r=self.recipe();r['supplement_source']['sha256']='20309a39fd82ac4869e330283a7b8e744ff5b1424868948e378a8395d61a0741'
  with tempfile.TemporaryDirectory(dir='/dev/shm') as t,self.assertRaisesRegex(RuntimeError,'current reviewed supplementary'):self.compile(r,t)
 def test_frozen_reader_or_comparator_drift_refused_without_target(self):
  for key in ('closure_comparator','m5_receipt_reader'):
   r=self.recipe();r['independent_retention'][key]['sha256']='0'*64
   with tempfile.TemporaryDirectory(dir='/dev/shm') as t,self.assertRaisesRegex(RuntimeError,'graph source drift'):self.compile(r,t)
if __name__=='__main__':unittest.main()
