import hashlib,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('retention_wrapper',HERE/'retention.py');wrapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(wrapper)
class WrapperComposition(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/dev/shm');self.root=Path(self.tmp.name)
  for name,pin in wrapper.PINS.items():
   shutil.copyfile(HERE/'retention-core'/name,self.root/name);(self.root/name).chmod(0o600);self.assertEqual(hashlib.sha256((self.root/name).read_bytes()).hexdigest(),pin)
 def tearDown(self):self.tmp.cleanup()
 def request(self):
  # CPU-only receipt/request shape; no real target evidence or API call.
  names={'boot.bin.original','kernel6.uki.original','limine.conf.original','kernel6-tree.tar.zst','boot-inputs.original.tar','state.original.json','kernel6-tree.original.jsonl'}
  objects={n:{'sha256':'a'*64,'bytes':8} for n in names};r={'schema':'maclab.rc-m1-original-backup/1','status':'LOCAL_BACKUP_VERIFIED_ONLY','device':'m1','packet':'/var/lib/maclab/rc7-m1-cpu-wrapper-fixture','boot_id':'11111111-2222-3333-4444-555555555555','reopen_readback':True,'objects':objects}
  q={'schema':'maclab.retention-reuse-request/1','root_plan_sha256':'b'*64,'source_freeze_sha256':'c'*64,'source':{'device':'m1','packet':r['packet'],'boot_id':r['boot_id'],'target_backup_receipt_sha256':'d'*64,'target_backup_receipt':r},'destination':'/Users/chriskearney/.local/share/maclab/recovery-retained/rc7-m1-cpu-wrapper-fixture','objects':{n:{**pin,'allowed_retained_sources':[]} for n,pin in objects.items()}}
  return {'request':q,'root_plan_sha256':'b'*64,'source_holder':'cpu-owner','mode':'main'}
 def test_actual_pinned_imports_fixed_cli_request_sha_and_private_dependencies(self):
  b=self.request();seen=[]
  def cpu(module,argv):
   seen.append(argv);self.assertEqual(module.rr.__file__,str(self.root/'reuse_remote.py'));self.assertEqual(module.FROZEN,str(module.FROZEN) and self.root/'retention-dependencies/mirror-m5-ssh.py')
   module.load_module('cpu_only_frozen_import',module.FROZEN,module.FROZEN_SHA)
   raw=Path(argv[argv.index('--request')+1]).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),argv[argv.index('--request-sha256')+1]);self.assertEqual(json.loads(raw),b['request']);self.assertEqual(argv[-2:],['--source-holder','cpu-owner']);self.assertNotIn('--append-supplement',argv)
   self.assertEqual(hashlib.sha256((module.FROZEN.parent/'v1-executed-source/retain-controller.py').read_bytes()).hexdigest(),module.READER_SHA)
  original=list(sys.argv);wrapper.run(b,here=self.root/'retention.py',executor=cpu);self.assertEqual(sys.argv,original);self.assertEqual(len(seen),1)
 def test_wrong_plan_and_changed_source_refused_before_execution(self):
  b=self.request();b['root_plan_sha256']='f'*64
  with self.assertRaisesRegex(RuntimeError,'workflow identity binding'):wrapper.run(b,here=self.root/'retention.py',executor=lambda *_:self.fail('unexpected executor'))
  # Each attempt owns its fresh directory; retrying an already prepared prefix
  # is not silently adopted by the primitive or this wrapper.
 def test_changed_closure_rejected(self):
  (self.root/'reuse_remote.py').write_bytes(b'forged')
  with self.assertRaisesRegex(RuntimeError,'closure SHA mismatch'):wrapper.run(self.request(),here=self.root/'retention.py',executor=lambda *_:self.fail('unexpected executor'))
 def test_false_success_not_created_on_core_failure(self):
  def failed(module,argv):raise RuntimeError('actual core failure fixture')
  with self.assertRaisesRegex(RuntimeError,'actual core failure'):wrapper.run(self.request(),here=self.root/'retention.py',executor=failed)
  self.assertTrue((self.root/'retention-request.json').exists());self.assertFalse((self.root/'SUCCESS.json').exists())
if __name__=='__main__':unittest.main()
