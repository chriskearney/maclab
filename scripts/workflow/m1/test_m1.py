import contextlib,datetime,hashlib,importlib.util,json,os,re,stat,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('target',HERE/'target.py');target=importlib.util.module_from_spec(spec);spec.loader.exec_module(target)
spec=importlib.util.spec_from_file_location('controller',HERE/'controller.py');controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)

class CacheTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/dev/shm');self.root=Path(self.tmp.name);self.source=self.root/'source';self.packet=self.root/'next';self.source.mkdir(mode=0o700);rows=[]
  for folder in ['packages','rollback-packages']:
   (self.source/folder).mkdir(mode=0o700)
   for i in range(5):
    b=(folder+str(i)).encode()*4096;p=self.source/folder/('package-'+str(i));p.write_bytes(b);p.chmod(0o600);rows.append({'relative':folder+'/'+p.name,'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)})
  self.profile={'schema':'maclab.m1-cohort-profile/1','device':'m1','board':'apple,j293','packet':str(self.packet),'source_packet':str(self.source),'old_kernel':'7.2.11-6-1-ARCH','candidate_kernel':'7.2.11-7-1-ARCH','archives':rows}
  self.uid=os.geteuid();self.match=patch.object(target,'PACKET',re.compile('^'+re.escape(str(self.root))+'/(source|next)$'));self.match.start()
 def tearDown(self):self.match.stop();self.tmp.cleanup()
 def stage(self):return target.stage_cache(self.profile,{},time.monotonic()+10,uid=self.uid)
 def test_one_local_pass_no_retransfer_or_hardlink(self):
  out=self.stage();self.assertEqual(out['archive_network_bytes'],0);self.assertEqual(len(out['files']),10)
  for r in self.profile['archives']:
   a=self.source/r['relative'];b=self.packet/r['relative'];self.assertEqual(a.read_bytes(),b.read_bytes());self.assertNotEqual(a.stat().st_ino,b.stat().st_ino)
  out2=self.stage();self.assertTrue(all(r['reused'] for r in out2['files'].values()))
 def test_corrupt_source_fails_before_archive_commit(self):
  r=self.profile['archives'][0];(self.source/r['relative']).write_bytes(b'wrong')
  with self.assertRaisesRegex(RuntimeError,'source archive drift'):self.stage()
  self.assertFalse((self.packet/r['relative']).exists())
 def test_existing_corrupt_destination_is_never_replaced(self):
  self.stage();r=self.profile['archives'][0];p=self.packet/r['relative'];p.write_bytes(b'wrong')
  with self.assertRaisesRegex(RuntimeError,'hash/size mismatch'):self.stage()
  self.assertEqual(p.read_bytes(),b'wrong')
 def test_symlink_fifo_and_device_never_opened_for_data(self):
  for name,path in [('symlink',self.root/'link'),('fifo',self.root/'fifo')]:
   os.symlink('/etc/passwd',path) if name=='symlink' else os.mkfifo(path,0o600)
   with self.assertRaisesRegex(RuntimeError,'unsafe/nonregular'):
    with target.held_regular(path,uid=self.uid):self.fail('nonregular data opened')
  with self.assertRaisesRegex(RuntimeError,'unsafe/nonregular'):
   with target.held_regular('/dev/null',uid=0):self.fail('device opened for data')
 def prepare_partial(self):
  self.packet.mkdir(mode=0o700);p=target.exact_profile(self.profile);target.write_once(self.packet/'CACHE-PROFILE.json',{'profile_sha256':p,'source_packet':str(self.source)});(self.packet/'.cache.lock').touch(mode=0o600);row=self.profile['archives'][0];folder=self.packet/'packages';folder.mkdir(mode=0o700);part=folder/('.'+Path(row['relative']).name+'.part');part.write_bytes((self.source/row['relative']).read_bytes()[:1234]);part.chmod(0o600);s=part.stat();receipt=folder/('.'+Path(row['relative']).name+'.owned.json');target.write_once(receipt,{'profile_sha256':p,'relative':row['relative'],'sha256':row['sha256'],'inode':[s.st_dev,s.st_ino]});return row,part,receipt
 def test_owned_partial_resume_full_prefix_hash(self):
  row,p,_=self.prepare_partial();out=self.stage();self.assertEqual(out['files'][row['relative']]['method'],'resumed-copy');self.assertEqual((self.packet/row['relative']).read_bytes(),(self.source/row['relative']).read_bytes())
 def test_corrupt_partial_stops_without_deletion(self):
  _,p,_=self.prepare_partial();p.write_bytes(b'bad prefix')
  with self.assertRaisesRegex(RuntimeError,'prefix mismatch'):self.stage()
  self.assertEqual(p.read_bytes(),b'bad prefix')
 def test_missing_partial_owner_is_not_adopted(self):
  _,p,receipt=self.prepare_partial();receipt.unlink()
  with self.assertRaisesRegex(RuntimeError,'unrecorded partial'):self.stage()
  self.assertTrue(p.exists())
 def test_foreign_inode_owner_refused(self):
  _,p,receipt=self.prepare_partial();old=p.read_bytes();p.unlink();p.write_bytes(old);p.chmod(0o600)
  # Filesystems may reuse the just-deleted inode; force a wrong recorded ID.
  x=json.loads(receipt.read_bytes());x['inode'][1]+=10000;receipt.write_text(json.dumps(x))
  with self.assertRaisesRegex(RuntimeError,'partial inode owner drift'):self.stage()
 def test_nonempty_foreign_packet_never_adopted(self):
  self.packet.mkdir(mode=0o700);(self.packet/'userfile').write_bytes(b'keep')
  with self.assertRaisesRegex(RuntimeError,'refuse adoption'):self.stage()
  self.assertEqual((self.packet/'userfile').read_bytes(),b'keep')
 def test_source_identity_drift_detected(self):
  r=self.profile['archives'][0];p=self.source/r['relative']
  with self.assertRaisesRegex(RuntimeError,'path/inode drift'):
   with target.held_regular(p,uid=self.uid):p.rename(p.with_suffix('.old'));p.write_bytes(b'new same path');p.chmod(0o600)

class ContractTests(unittest.TestCase):
 def test_wrong_model_or_packet_refused(self):
  for p in [{'schema':'wrong','device':'m1','board':'apple,j293'},{'schema':'maclab.m1-cohort-profile/1','device':'m3pro','board':'apple,j516s'}]:
   with self.assertRaisesRegex(RuntimeError,'wrong supported profile'):target.exact_profile(p)
 def test_controller_fresh_idle_lease_required(self):
  p={'device':'m1','holder':'coordinator'};b={'expected_boot_id':'actual','expected_kernel':'old6'};d={'name':'m1','state':'ready','alive':True,'boot_id':'actual','kernel':'old6','lease':{'holder':'coordinator','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
  self.assertIs(controller.state_gate(d,p,b,True),d)
  for key,val in [('boot_id','stale'),('active_job','other'),('lease',{'holder':'other'}),('state','busy')]:
   bad={**d,key:val}
   with self.assertRaises(RuntimeError):controller.state_gate(bad,p,b,True)
 def test_source_pin_cannot_be_changed(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as d:
   p=Path(d)/'source.py';p.write_bytes(b'actual');pin={'path':str(p),'bytes':6,'sha256':hashlib.sha256(b'actual').hexdigest()};self.assertEqual(controller.read_pin(pin),b'actual');p.write_bytes(b'forged')
   with self.assertRaisesRegex(RuntimeError,'source hash drift'):controller.read_pin(pin)
if __name__=='__main__':unittest.main()

class ReviewedRegressions(unittest.TestCase):
 def test_cache_lock_fifo_and_device_are_refused_before_data_open(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as d:
   p=Path(d)/'lock';os.mkfifo(p,0o600)
   with self.assertRaisesRegex(RuntimeError,'unsafe cache lock object'):target.cache_lock(p,os.geteuid())
   p.unlink();os.symlink('/dev/null',p)
   with self.assertRaisesRegex(RuntimeError,'unsafe cache lock object'):target.cache_lock(p,os.geteuid())
 def test_serial_success_retained_as_failure(self):
  pin={'path':str(HERE/'target.py'),'sha256':hashlib.sha256((HERE/'target.py').read_bytes()).hexdigest(),'bytes':(HERE/'target.py').stat().st_size}
  p={'device':'m1','target_adapter':pin};binding={'profile':p,'action':'inventory-cache','expected_boot_id':'actual','expected_kernel':'old6','deadline_seconds':3}
  class Fake:
   def request(self,path,body=None,timeout=60):
    if body is None:return {'name':'m1','state':'ready','alive':True,'kernel':'old6','boot_id':'actual'}
    return {'exit_code':0,'stdout':'{}','stderr':'','via':'serial'}
  out=controller.run(binding,Fake());self.assertEqual(out['status'],'M1_TARGET_FAILED');self.assertEqual(out['actual_exec']['via'],'serial')

class LeaseBudgetRegression(unittest.TestCase):
 def test_same_holder_short_remaining_lease_is_not_enough(self):
  p={'device':'m1','holder':'coordinator'};b={'expected_boot_id':'actual','expected_kernel':'old6'};d={'name':'m1','state':'ready','alive':True,'boot_id':'actual','kernel':'old6','lease':{'holder':'coordinator','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=1)).isoformat()}}
  with self.assertRaisesRegex(RuntimeError,'expire inside phase'):controller.state_gate(d,p,b,True,990)
  d['lease']['expires']=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=1000)).isoformat();controller.state_gate(d,p,b,True,990)

class PreparedFileRealFS(unittest.TestCase):
 def setUp(self):CacheTests.setUp(self)
 def tearDown(self):CacheTests.tearDown(self)
 def fixture(self):
  import base64
  source=b'# CPU backup source fixture\n';authority=b'{"CPU":"authority fixture"}'
  self.profile['backup_source']={'sha256':hashlib.sha256(source).hexdigest(),'bytes':len(source)};self.profile['authority_source']={'sha256':hashlib.sha256(authority).hexdigest(),'bytes':len(authority)}
  target.stage_cache(self.profile,{},time.monotonic()+10,uid=self.uid)
  raw={'backup-m1.py':source,'STANDING-BOOT-AUTHORITY.json':authority,'backup-spec.json':b'{}','backup-clearance.json':b'{}','BACKUP-SOURCE-FREEZE.json':b'{}'}
  files={n:{'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'base64':base64.b64encode(b).decode()} for n,b in raw.items()}
  return {'expected_boot_id':'cpu-boot','prepared_inputs':{'packet':self.profile['packet'],'boot_id':'cpu-boot','files':files}}
 def test_fixed_prepared_closure_writes_once_reuses_exact(self):
  request=self.fixture();out=target.stage_prepared(self.profile,request,time.monotonic()+10,'backup',uid=self.uid);self.assertEqual(out['status'],'EXACT_INPUTS_STAGED_ONLY');self.assertFalse(out['package_changes'])
  again=target.stage_prepared(self.profile,request,time.monotonic()+10,'backup',uid=self.uid);self.assertTrue(all(x['reused_exact_input'] for x in again['files'].values()))
 def test_foreign_partial_input_is_not_overwritten(self):
  request=self.fixture();p=self.packet/'backup-m1.py';p.write_bytes(b'partial untrusted bytes');p.chmod(0o600)
  with self.assertRaisesRegex(RuntimeError,'hash/size mismatch'):target.stage_prepared(self.profile,request,time.monotonic()+10,'backup',uid=self.uid)
  self.assertEqual(p.read_bytes(),b'partial untrusted bytes')
 def test_extra_or_replaced_source_rejected_before_writes(self):
  request=self.fixture();request['prepared_inputs']['files']['credential']={'sha256':'a'*64,'bytes':1,'base64':'eA=='}
  with self.assertRaisesRegex(RuntimeError,'exact prepared input closure'):target.stage_prepared(self.profile,request,time.monotonic()+10,'backup',uid=self.uid)
  self.assertFalse((self.packet/'backup-m1.py').exists())
