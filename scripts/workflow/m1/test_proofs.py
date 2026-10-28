import base64,copy,datetime,hashlib,importlib.util,json,os,shlex,shutil,signal,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('proof_source',HERE/'proofs.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class ProofControls(unittest.TestCase):
 def test_original_observer_stdout_descriptor_preserves_genuine_bytes(self):
  o={'schema':'maclab.m1-initial-esp-observation/1','status':'ACTUAL_ORIGINAL_ESP_READONLY_OBSERVED','packet':'/var/lib/maclab/rc7-m1-cpu-proof-new','boot_id':'original-boot','kernel':'7.2.11-6-1-ARCH','root_plan_sha256':'a'*64,'target_mutations':False};raw=json.dumps(o,indent=4)+'  \n';b={'operation':'describe-initial-esp','packet':o['packet'],'expected_boot_id':o['boot_id'],'root_plan_sha256':'a'*64,'actual_observation':{'status':'M1_INITIAL_ESP_OBSERVED','actual_exec':{'via':'agent','exit_code':0,'stderr':'','stdout':raw},'target':o}};r=m.run(b);self.assertEqual(base64.b64decode(r['descriptor']['raw_base64']),raw.encode());self.assertEqual(r['descriptor']['sha256'],m.H(raw.encode()));self.assertFalse(r['completion_claim']);b['actual_observation']['target']['boot_id']='forged'
  with self.assertRaisesRegex(RuntimeError,'stdout identity mismatch'):m.run(b)
 def guarded(self,t):
  esp=Path('/dev/shm/m1-esp-fragment-source-r4/esp.py')
  if not esp.exists():self.skipTest('reviewed ESP closure absent')
  root=Path(t);shutil.copyfile(HERE/'proofs.py',root/'proofs.py');shutil.copyfile(esp,root/'esp.py');shutil.copyfile(HERE/'frozen-controller-ea3.py',root/'frozen-controller-ea3.py')
  with patch.object(m,'__file__',str(root/'proofs.py')):e,_=m.load()
  regular=e.regular;e.regular=lambda p,cap=1048576,root=True:regular(p,cap,False)
  def private(p):
   for d in [Path(p),*Path(p).parents]:
    s=d.lstat();m.need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.geteuid()) and not s.st_mode&0o022,'unsafe fixture ancestry')
  e.private=private;return e
 def test_actual_regular_receipts_hash_and_terminal_drift(self):
  with tempfile.TemporaryDirectory(dir='/run/user/'+str(os.geteuid())) as t:
   e=self.guarded(t);p=Path(t)/'packet';(p/'writer-persistent-hold').mkdir(parents=True);f=p/'writer-persistent-hold/APPLIED.json';data=b'{"actual":"owned mask proof"}\n';f.write_bytes(data);out=m.read_files(e,p,{'writer-persistent-hold/APPLIED.json':None});self.assertEqual(base64.b64decode(out['writer-persistent-hold/APPLIED.json']['base64']),data)
   with self.assertRaisesRegex(RuntimeError,'existing phase pin'):m.read_files(e,p,{'writer-persistent-hold/APPLIED.json':{'sha256':'f'*64,'bytes':len(data)}})
   regular=e.regular;count=[0]
   def change(path,*args):
    count[0]+=1
    if count[0]==2:f.write_bytes(data+b' ')
    return regular(path,*args)
   e.regular=change
   with self.assertRaisesRegex(RuntimeError,'terminal proof drift'):m.read_files(e,p,{'writer-persistent-hold/APPLIED.json':None})
 def test_fifo_and_symlink_are_refused_before_data_open(self):
  with tempfile.TemporaryDirectory(dir='/run/user/'+str(os.geteuid())) as t:
   e=self.guarded(t);p=Path(t)/'packet';(p/'writer-persistent-hold').mkdir(parents=True);f=p/'writer-persistent-hold/APPLIED.json';os.mkfifo(f)
   with self.assertRaises(RuntimeError):m.read_files(e,p,{'writer-persistent-hold/APPLIED.json':None})
   f.unlink();f.symlink_to('/dev/zero')
   with self.assertRaises(RuntimeError):m.read_files(e,p,{'writer-persistent-hold/APPLIED.json':None})
 def test_actual_owned_group_alive_refuses_then_reaped_group_proves_empty(self):
  owner=Path('/dev/shm/sf-m1-standing-authority-r1/transact-m1.py')
  if not owner.exists():self.skipTest('reviewed owner source absent')
  with tempfile.TemporaryDirectory(dir='/run/user/'+str(os.geteuid())) as t:
   e=self.guarded(t);p=Path(t)/'packet';(p/'transaction-receipts').mkdir(parents=True);shutil.copyfile(owner,p/'transact-m1.py');child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);r={'pid':child.pid,'pgid':child.pid,'sid':child.pid,'per_regular_file_limit_bytes':64413696,'argv':['/usr/bin/pacman','-U','--noconfirm','--',*[str(p/'packages'/('pkg'+str(i))) for i in range(5)]]};f=p/'transaction-receipts/PACMAN-OWNED-GROUP.json';f.write_text(json.dumps(r))
   try:
    with self.assertRaisesRegex(RuntimeError,'remains live'):m.drained_groups(e,p)
   finally:
    os.killpg(child.pid,signal.SIGTERM);child.wait(timeout=5)
   out=m.drained_groups(e,p);self.assertIs(out['transaction-receipts/PACMAN-OWNED-GROUP.json']['live'],False);self.assertEqual(out['packet-c-receipts/PACMAN-OWNED-GROUP.json'],{'absent':True});r['argv'][4]='/var/lib/maclab/old-foreign-packet/pkg';f.write_text(json.dumps(r))
   with self.assertRaisesRegex(RuntimeError,'finite package group argv'):m.drained_groups(e,p)
 def b(self):return {'operation':'read-current-files','profile':{'device':'m1','board':'apple,j293','packet':'/var/lib/maclab/rc7-m1-cpu-proof-new','source_packet':'/var/lib/maclab/rc7-m1-cpu-proof-source','holder':'owner','agent_parent':{'path':'/usr/local/bin/lab-agent','sha256':'b'*64,'bytes':100}},'expected_boot_id':'cpu-boot','expected_kernel':'7.2.11-6-1-ARCH','root_plan_sha256':'a'*64,'packet_profile_sha256':'c'*64,'files':{'writer-persistent-hold/APPLIED.json':None}}
 def test_non_receipt_keys_and_outside_paths_never_admitted(self):
  for name in ('../id_ed25519','STANDING-BOOT-AUTHORITY.json','/etc/shadow','transact-m1.py'):
   b=self.b();b['files']={name:None}
   with self.assertRaisesRegex(RuntimeError,'finite proof leaves'):m.validate(b)
 def test_actual_rpc_projection_and_foreign_response_retains_failed_evidence(self):
  for wrong in (False,True):
   b=self.b();outer=self
   class API:
    def request(self,path,body=None,timeout=60):
     if body is None:return {'name':'m1','state':'ready','alive':True,'boot_id':'cpu-boot','kernel':'7.2.11-6-1-ARCH','lease':{'holder':'owner','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
     args=shlex.split(body['command']);outer.assertLess(len(body['command'].encode()),120000);compile(args[4],'<actual-proof-wire>','exec');raw=b'{}';o={'schema':'maclab.m1-proof-read/1','status':'ACTUAL_CURRENT_PACKET_PROOFS_READ_ONLY','packet':'wrong' if wrong else b['profile']['packet'],'boot_id':'cpu-boot','kernel':b['expected_kernel'],'root_plan_sha256':'a'*64,'target_mutations':False,'files':{'writer-persistent-hold/APPLIED.json':{'base64':base64.b64encode(raw).decode(),'sha256':m.H(raw),'bytes':2,'identity':[1,2,33152,0,0,2,3,4]}}};return {'via':'agent','exit_code':0,'stderr':'','stdout':json.dumps(o)}
   with tempfile.TemporaryDirectory(dir='/run/user/'+str(os.geteuid())) as t:
    self.guarded(t)
    with patch.object(m,'__file__',str(Path(t)/'proofs.py')):out=m.run(b,API())
   self.assertEqual(out['status'],'M1_PROOF_READ_FAILED' if wrong else 'M1_CURRENT_PACKET_PROOFS_OBSERVED');self.assertEqual(out['actual_exec']['exit_code'],0)
if __name__=='__main__':unittest.main()
