import base64,datetime,hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('prepare',HERE/'prepare.py');prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)
class FreshBindingTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/dev/shm');root=Path(self.tmp.name)
  def pin(name,value):
   b=value if isinstance(value,bytes) else json.dumps(value).encode();p=root/name;p.write_bytes(b);return {'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)}
  authority=pin('authority.json',{'authorization_is_persistent':True,'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False})
  rows=[{'relative':('packages' if i<5 else 'rollback-packages')+'/p'+str(i),'sha256':str(i)*64,'bytes':100+i} for i in range(10)]
  p={'device':'m1','board':'apple,j293','packet':'/var/lib/maclab/rc7-m1-cpu-fixture-next','holder':'cpu-owner','old_kernel':'7.2.11-6-1-ARCH','authority_source':authority,'old_module_tree_sha256':'d'*64,'target_adapter':{'sha256':'e'*64},'archives':rows,'original_file_pins':{'/fixture/private-file':{'sha256':'a'*64}}}
  current={'boot_id':'actual-cpu-fixture-boot','kernel':p['old_kernel'],'original_guard_mismatches':[],'old_module_tree_sha256':'d'*64,'module_markers':{'/fixture/.maclab-job':False},'files':{'/fixture/private-file':{'sha256':'a'*64,'bytes':7}}};target={'profile_sha256':hashlib.sha256(json.dumps(p,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'boot_id':current['boot_id'],'current':current,'files':{r['relative']:{'sha256':r['sha256'],'bytes':r['bytes']} for r in rows}}
  obs={'source_sha256':'e'*64,'status':'M1_INVENTORY_CACHE_OBSERVED','device':'m1','boot_id':current['boot_id'],'kernel':p['old_kernel'],'target':target,'actual_exec':{'exit_code':0,'via':'agent','stdout':json.dumps(target),'stderr':''}}
  coordinator={'state':'ready','alive':True,'boot_id':current['boot_id'],'kernel':p['old_kernel'],'lease':{'holder':'cpu-owner','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
  self.binding={'profile':p,'preflight':obs,'root_profile_reviewer':'CPU source-review fixture only','coordinator_state':coordinator,'templates':{'backup_spec':pin('spec.json',{'schema':'maclab.rc-m1-original-backup-spec/1','device':'m1','board':'apple,j293','old_release':p['old_kernel'],'expected_boot_id':None,'original_file_pins':{}}),'backup_clearance':pin('clearance.json',{'schema':'maclab.rc-m1-backup-clearance/1','backup_authorized':False,'boot_authorized':False}),'backup_source':pin('backup.py',b'# CPU source pin fixture\n')}}
 def tearDown(self):self.tmp.cleanup()
 def sync_raw(self):self.binding['preflight']['actual_exec']['stdout']=json.dumps(self.binding['preflight']['target'])
 def test_fresh_binding_never_copies_old_receipts_or_claims_boot(self):
  out=prepare.make(self.binding);self.assertFalse(out['historical_backup_or_boot_receipts_copied']);self.assertFalse(out['manual_saved_work_confirmed']);self.assertFalse(out['package_or_boot_authorization']);self.assertEqual(set(out['files']),{'backup-spec.json','backup-clearance.json','backup-m1.py','STANDING-BOOT-AUTHORITY.json','BACKUP-SOURCE-FREEZE.json'})
  clear=json.loads(base64.b64decode(out['files']['backup-clearance.json']['base64']));self.assertEqual(clear['expected_boot_id'],'actual-cpu-fixture-boot');self.assertTrue(clear['backup_authorized']);self.assertFalse(clear['boot_authorized'])
 def test_source_review_gate_is_real(self):
  self.binding['root_profile_reviewer']=None
  with self.assertRaisesRegex(RuntimeError,'source gate remains closed'):prepare.make(self.binding)
 def test_raw_exec_and_decoded_evidence_cannot_diverge(self):
  self.binding['preflight']['target']['current']['original_guard_mismatches']=['forged']
  with self.assertRaisesRegex(RuntimeError,'raw exec/decoded'):prepare.make(self.binding)
 def test_guard_or_module_marker_failure_blocks_binding(self):
  self.binding['preflight']['target']['current']['original_guard_mismatches']=['changed'];self.sync_raw()
  with self.assertRaisesRegex(RuntimeError,'original-state guards'):prepare.make(self.binding)
  self.binding['preflight']['target']['current']['original_guard_mismatches']=[];self.binding['preflight']['target']['current']['module_markers']['/fixture/.maclab-job']=True;self.sync_raw()
  with self.assertRaisesRegex(RuntimeError,'ownership conflict'):prepare.make(self.binding)
 def test_serial_and_stale_boot_refused(self):
  self.binding['preflight']['actual_exec']['via']='serial'
  with self.assertRaisesRegex(RuntimeError,'agent transport'):prepare.make(self.binding)
  self.binding['preflight']['actual_exec']['via']='agent';self.binding['preflight']['boot_id']='other'
  with self.assertRaisesRegex(RuntimeError,'normal old6 identity'):prepare.make(self.binding)
 def test_missing_or_changed_cached_split_refused(self):
  files=self.binding['preflight']['target']['files'];files.pop(next(iter(files)));self.sync_raw()
  with self.assertRaisesRegex(RuntimeError,'complete target cache'):prepare.make(self.binding)
 def test_short_or_foreign_lease_cannot_be_called_reviewed(self):
  self.binding['coordinator_state']['lease']['expires']=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=1)).isoformat()
  with self.assertRaisesRegex(RuntimeError,'lease insufficient'):prepare.make(self.binding)
