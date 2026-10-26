"""Actual bounded child diagnostics and post-run failure evidence; no API calls."""
import hashlib,json,os,unittest
from pathlib import Path
from unittest.mock import patch
import intake,catalog,runtime,util
import test_catalog as fixtures
import test_runtime as rt
class Diagnostics(unittest.TestCase):
 def setUp(self):fixtures.Catalog.setUp(self)
 def artifact(self,*a,**k):return fixtures.Catalog.artifact(self,*a,**k)
 def profile(self,*a,**k):return fixtures.Catalog.profile(self,*a,**k)
 def files(self,*a,**k):return fixtures.Catalog.files(self,*a,**k)
 def test_actual_metadata_refusal_retains_raw_child_output_and_empty_stderr(self):
  p,a=self.profile();p['candidate']['artifact_slots']['linux-aurora']['metadata']['pkgver']='2-1';p['candidate']['artifact_slots']['linux-aurora']['version']='2-1';cp,r=self.files(p);out=self.P/'bad-source'
  with self.assertRaisesRegex(catalog.Refused,'metadata refused'):intake.run(cp,p['id'],{'device':'m1','recovery_mode':'network-only','artifacts':{'linux-aurora':str(a)}},r,out)
  record=json.loads((out/'metadata-process-linux-aurora.json').read_bytes());self.assertEqual(record['exit_code'],2);self.assertFalse(record['automatic_retry']);raw=(out/'metadata-linux-aurora.stdout').read_bytes();self.assertEqual(json.loads(raw)['status'],'SOURCE_METADATA_REFUSED');self.assertIn('metadata mismatch',json.loads(raw)['reason']);self.assertEqual(record['stdout']['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(record['stderr']['bytes'],0)
 def test_real_child_stderr_and_exit_are_retained_before_parse(self):
  p,a=self.profile();cp,r=self.files(p);review=catalog.unique(catalog.read_pin(r));helper=self.P/'refusing-helper.py';helper.write_text("import sys\nprint('actual stdout protocol failure')\nprint('actual stderr detail',file=sys.stderr)\nsys.exit(17)\n");helper.chmod(0o600);review['metadata_helper']=intake.pin(helper);out=self.P/'real-stderr';out.mkdir(mode=0o700)
  with self.assertRaisesRegex(catalog.Refused,'metadata refused'):intake.metadata(p,{'artifacts':{'linux-aurora':str(a)}},review,out)
  record=json.loads((out/'metadata-process-linux-aurora.json').read_bytes());self.assertEqual(record['exit_code'],17);raw=(out/'metadata-linux-aurora.stderr').read_bytes();self.assertEqual(raw,b'actual stderr detail\n');self.assertEqual(record['stderr']['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(record['stdout']['bytes'],len(b'actual stdout protocol failure\n'))
 def test_metadata_process_failure_preserves_exception_and_actual_logs(self):
  p,a=self.profile();cp,r=self.files(p);out=self.P/'child-incomplete';review=catalog.unique(catalog.read_pin(r));out.mkdir(mode=0o700)
  def incomplete(argv,o,stem,timeout):
   (o/(stem+'.stdout')).write_text('ACTUAL PARTIAL');(o/(stem+'.stderr')).write_text('bounded fixture detail');raise util.Stop('CPU owned child incomplete')
  with patch.object(util,'process',incomplete):
   with self.assertRaisesRegex(util.Stop,'owned child incomplete'):intake.metadata(p,{'artifacts':{'linux-aurora':str(a)}},review,out)
  self.assertEqual(json.loads((out/'metadata-process-linux-aurora.json').read_bytes())['status'],'METADATA_PROCESS_INCOMPLETE');self.assertEqual((out/'metadata-linux-aurora.stdout').read_text(),'ACTUAL PARTIAL')
 def test_existing_runner_result_and_real_exception_survive_postrun_diagnostic(self):
  # Reuse the actual subprocess runner fixture, injecting only a validation
  # refusal AFTER runner completion and RESULT retention. Its assertion is
  # deliberately bypassed by this expected refusal; no real target is used.
  fixture=rt.Runtime('test_generic_m3_custom_profile_actually_invokes_runner_and_proves_absent_restore');fixture.setUp()
  try:
   with patch.object(runtime,'restored',side_effect=catalog.Refused('CPU final proof mismatch')):
    with self.assertRaisesRegex(catalog.Refused,'CPU final proof mismatch') as seen:fixture.test_generic_m3_custom_profile_actually_invokes_runner_and_proves_absent_restore()
   path=Path(seen.exception.private_failure_output);failure=json.loads((path/'FAILURE.json').read_bytes());original=json.loads((path/'RESULT.json').read_bytes());self.assertEqual(failure['reason'],'CPU final proof mismatch');self.assertTrue(failure['runner_launch_intent_retained']);self.assertEqual(original['status'],'FAILED_OR_INCOMPLETE');self.assertEqual(original['runner']['exit_code'],0);self.assertFalse(failure['automatic_retry']);self.assertTrue((path/'runner.stdout').exists());self.assertFalse((path/'LEASE-RELEASE-INTENT.json').exists())
  finally:fixture.doCleanups()
 def test_diagnostic_reader_rejects_symlink_and_writable_log(self):
  p=self.P/'log';p.write_bytes(b'');p.chmod(0o600);row,raw=intake.diagnostic_log(p);self.assertEqual(row['bytes'],0);p.chmod(0o644)
  with self.assertRaises(catalog.Refused):intake.diagnostic_log(p)
  link=self.P/'link';link.symlink_to(p)
  with self.assertRaises(catalog.Refused):intake.diagnostic_log(link)
if __name__=='__main__':unittest.main()
