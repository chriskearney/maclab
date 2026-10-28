import importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('assembly',HERE/'assemble.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class FullAssembly(unittest.TestCase):
 def compile(self):
  rp=Path('/dev/shm/sf-workflow-full-assembly-RECIPE.json')
  if not rp.exists():self.skipTest('private pinned source recipe absent')
  self.t=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(self.t.cleanup);out=Path(self.t.name)/'plan';recipe=json.loads(rp.read_bytes());recipe['supplement_source']=m.pin(HERE/'backup-supplement.py');result=m.compile_full(recipe,'/var/lib/maclab/rc7-m1-source-only-cpu-assembly',out);return json.loads((out/'WORKFLOW.FULL.CLOSED.json').read_bytes()),result
 def test_exact_complete_success_sequence_is_closed_and_go_valid(self):
  p,r=self.compile();self.assertEqual(len(p['phases']),241);self.assertTrue(r['default_closed']);self.assertFalse(r['runtime_qualified']);ids=[x['id'] for x in p['phases']]
  order=['preflight','initial-technical','initial-esp','namespace-preinstall','namespace-manifest','target-cache','combined-actual-receipt','esp-writer-hold-writer','esp-writer-sf-apply','esp-writer-pre-apply','resolved-preflight','package-produced','install-packages','postinstall-observed','candidate-double-retained','installer-entry','installed-job','job-return','normal-smoke','normal7-capture','normal-inverse-default6','packet-c-produced','rollback-packages','old-payload-inventory','esp-inverse-restore-arranged-default','esp-inverse-fallback-inverse','original-mtime-inverse','original-return-wait6','original-session','esp-final-unhold','esp-final-catchup','esp-final-restore-pre','esp-final-restore-sf','final-original-audit']
  # Old payload inventory is intentionally after fallback inversion: it observes
  # original files/metadata against the restored SF.after menu before mtime CAS.
  order.remove('old-payload-inventory');order.insert(order.index('original-mtime-inverse'),'old-payload-inventory');self.assertEqual([ids.index(x) for x in order],sorted(ids.index(x) for x in order))
  self.assertIsNone(p['inputs']['root_profile_reviewer']);self.assertFalse(p['inputs']['root_emit_package_clearance']);self.assertFalse(p['inputs']['root_emit_packet_c_clearance']);self.assertFalse(any(x.get('recovery') for x in p['phases']))
  binary=Path('/dev/shm/lab-workflow-full-assembly-source')
  if binary.exists():
   q=subprocess.run([str(binary),'check','--plan',r['plan']['path']],capture_output=True,text=True);self.assertEqual(q.returncode,0,q.stdout+q.stderr)
 def test_selected_staging_has_no_repeated_producer_and_large_ledgers_stay_local(self):
  p,r=self.compile();producer=next(x for x in p['phases'] if x['id']=='package-produced-binding');docs=producer['template']['documents']
  for n in ('candidate-files.jsonl','old-package-files.jsonl','linux-aurora.files.sha256','OUTPUT-CEILING-PROOF.json'):self.assertEqual(set(docs[n]),{'path','sha256','bytes'})
  stages=[x for x in p['phases'] if x['id'].startswith('input-') and x['kind']=='bind'];self.assertEqual(len(stages),12)
  for x in stages:self.assertNotIn('produced',x['template']);self.assertEqual(len(x['template']['assets']),1);self.assertIn('/assets/0/base64',x['bind']);self.assertIn('producer_scope',x['template'])
  job=next(x for x in p['phases'] if x['id']=='installed-job');self.assertEqual(job['m1_submission_admission']['agent_sha256'],{'from':'preflight','pointer':'/target/current/agent_parent/sha256'})
 def test_three_large_main_consumers_use_verified_local_envelope_only(self):
  p,r=self.compile();by={x['id']:x for x in p['phases']}
  for name in ('package-produced-binding','capture-context-binding','rollback-context-binding'):self.assertEqual(by[name]['bind']['/main_capture'],{'from':'backup-collected','pointer':'/envelope'})
  for name in ('main-retention-binding-input','supplement-retention-binding-input'):
   self.assertEqual(set(by[name]['template']['main_capture']),{'receipt','receipt_base64','receipt_sha256','source_freeze_sha256'});self.assertNotIn('/main_capture',by[name]['bind'])
  for name in ('supplement-stage-binding','supplement-capture-binding','supplement-collect-binding'):self.assertEqual(set(by[name]['template']['main_collection']),{'receipt','receipt_base64','receipt_sha256','source_freeze_sha256'})
 def test_runtime_paths_bind_actual_plan_and_current_boot_not_old_completion(self):
  p,r=self.compile();by={x['id']:x for x in p['phases']};self.assertEqual(by['package-produced-binding']['template']['plan_path'],r['plan']['path']);self.assertEqual(by['packet-c-produced-binding']['bind']['/expected_boot_id'],{'from':'normal-wait7','pointer':'/boot_id'});self.assertEqual(by['capture-context-binding']['template']['operation'],'build-capture-context');self.assertEqual(by['rollback-context-binding']['template']['operation'],'build');self.assertIn('/target/files/packet-c-clearance.json/sha256',str(by['actual-packet-c-receipt-pins']['bind']))
if __name__=='__main__':unittest.main()
