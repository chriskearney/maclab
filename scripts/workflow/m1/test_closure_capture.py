import hashlib,importlib.util,json,shlex,shutil,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('closure_controller',HERE/'controller.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class BoundedClosureCapture(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/dev/shm');self.root=Path(self.tmp.name);shutil.copyfile(HERE/'closure-collector.py',self.root/'closure-collector.py');raw=(HERE/'closure-collector.py').read_bytes();self.pin={'path':str(HERE/'closure-collector.py'),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
  # Small semantic fixture; separate actual saved-capture sizing below.
  self.actual={'status':'CAPTURED','STOP':[],'boot_id':'cpu-fixture-boot','kernel':'old6','board':'apple,j293','old_module_tree_sha256':'a'*64,'all_vendor_and_local_hook_sources':{},'closure_files':{},'fallback_config_directories':{}}
 def tearDown(self):self.tmp.cleanup()
 def binding(self):return {'action':'collect-closure','profile':{'device':'m1','board':'apple,j293','closure_collector':self.pin},'expected_boot_id':None,'expected_kernel':'old6','deadline_seconds':180}
 def fake(self,via='agent',exit_code=0):
  outer=self
  class API:
   def request(self,path,body=None,timeout=60):
    if body is None:return {'name':'m1','state':'ready','alive':True,'kernel':'old6','boot_id':'cpu-fixture-boot'}
    argv=shlex.split(body['command']);outer.assertEqual(argv[:4],['/usr/bin/python3','-E','-B','-c']);compile(argv[4],'<exact-remote-wrapper>','exec');outer.assertIn("['/usr/bin/pacman-conf',key]",argv[4]);outer.assertLess(len(body['command'].encode()),120000)
    return {'exit_code':exit_code,'via':via,'stdout':json.dumps({'collector_stdout':json.dumps(outer.actual),'pacman_conf':{k:{'exit_code':0,'stdout':'','stderr':''} for k in ['HookDir','NoExtract','NoUpgrade']}}),'stderr':''}
  return API()
 def test_fixed_collector_actual_raw_capture_pin_and_small_summary(self):
  with patch.object(c,'__file__',str(self.root/'controller.py')):out=c.run(self.binding(),self.fake())
  self.assertEqual(out['status'],'M1_CLOSURE_OBSERVED');self.assertFalse(out['readiness_claim']);capture=out['capture'];raw=Path(capture['path']).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),capture['sha256']);self.assertLess(len(json.dumps(out).encode()),4096);self.assertNotIn('collector_stdout',out)
 def test_serial_raw_evidence_is_retained_without_success(self):
  with patch.object(c,'__file__',str(self.root/'controller.py')):out=c.run(self.binding(),self.fake(via='serial'))
  self.assertEqual(out['status'],'M1_CLOSURE_CAPTURE_FAILED');self.assertIn('serial',Path(out['capture']['path']).read_text())
 def test_actual_retained_capture_size_is_not_repropagated(self):
  actual=Path('/dev/shm/sf-rc-m1-REPROBE-ACTUAL-READONLY-METADATA.json')
  if not actual.exists():self.skipTest('private historical sizing evidence unavailable')
  record=json.loads(actual.read_bytes());self.actual=json.loads(record['stdout']);self.actual.update(boot_id='cpu-fixture-boot',kernel='old6',board='apple,j293')
  with patch.object(c,'__file__',str(self.root/'controller.py')):out=c.run(self.binding(),self.fake())
  self.assertGreater(out['capture']['bytes'],150000);self.assertLess(len(json.dumps(out).encode()),8192)
