import hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('controller_capture',HERE/'controller.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Capture(unittest.TestCase):
 def test_existing_primitive_retains_whole_envelope_private_and_reopens(self):
  value={'actual_exec':{'via':'agent','exit_code':0,'stdout':'{"receipt":{"mtime_ns":1793026027181000123}}','stderr':''},'target':{'receipt':{'mtime_ns':1793026027181000123}},'status':'M1_COLLECT_BACKUP_OBSERVED','source_sha256':'a'*64}
  with tempfile.TemporaryDirectory(dir='/dev/shm') as td:
   p=Path(td)/'collect-backup-envelope.json';d=m.write_capture(p,value);self.assertEqual(p.stat().st_mode&0o777,0o600);self.assertEqual(p.stat().st_uid,os.geteuid());self.assertEqual(json.loads(m.read_pin({k:d[k] for k in ('path','sha256','bytes')})),value);self.assertNotIn('envelope',json.loads(p.read_bytes()));self.assertEqual(d['sha256'],hashlib.sha256(p.read_bytes()).hexdigest());self.assertFalse(d['independent_retention_claim'])
   with self.assertRaises(FileExistsError):m.write_capture(p,value)
 def test_real_collect_dispatch_preserves_full_output_and_adds_only_typed_local_pin(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as td:
   root=Path(td);target=root/'target.py';target.write_bytes((HERE/'target.py').read_bytes());raw=target.read_bytes();pin={'path':str(target),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)};result={'via':'agent','exit_code':0,'stderr':'','stdout':'{"status":"ACTUAL_BACKUP_COLLECTED_ONLY","receipt":{"mtime_ns":1793026027181000123}}'}
   class API:
    def request(self,path,body=None,timeout=None):
     if path=='/api/devices/m1':return {'name':'m1','state':'ready','alive':True,'kernel':'7.2.11-6-1-ARCH','boot_id':'boot6','active_job':None,'queued':False}
     if path=='/api/devices/m1/exec':return result
     raise AssertionError(path)
   old=m.__file__;m.__file__=str(root/'controller.py')
   try:out=m.run({'profile':{'device':'m1','target_adapter':pin},'action':'collect-backup','expected_boot_id':'boot6','expected_kernel':'7.2.11-6-1-ARCH','deadline_seconds':300},API())
   finally:m.__file__=old
   self.assertEqual(set(out['envelope']),{'path','sha256','bytes'});self.assertEqual(Path(out['envelope']['path']).name,'collect-backup-envelope.json');retained=json.loads(m.read_pin(out['envelope']));self.assertEqual(retained,{k:v for k,v in out.items() if k!='envelope'});self.assertEqual(retained['actual_exec'],result);self.assertEqual(retained['target'],json.loads(result['stdout']))
 def test_existing_fifo_and_symlink_are_refused_without_read(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as td:
   p=Path(td)/'collect-backup-envelope.json';os.mkfifo(p,0o600)
   with self.assertRaises(FileExistsError):m.write_capture(p,{})
   p.unlink();p.symlink_to('/dev/zero')
   with self.assertRaises(FileExistsError):m.write_capture(p,{})
 def test_descriptor_reader_refuses_symlink_fifo_and_mutated_bytes(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as td:
   p=Path(td)/'collect-backup-envelope.json';d=m.write_capture(p,{'genuine':'fresh'});pin={k:d[k] for k in ('path','sha256','bytes')};p.write_text('{"forged":"fresh"}\n')
   with self.assertRaises(RuntimeError):m.read_pin(pin)
   p.unlink();os.mkfifo(p,0o600)
   with self.assertRaises(RuntimeError):m.read_pin(pin)
   p.unlink();p.symlink_to('/dev/zero')
   with self.assertRaises(RuntimeError):m.read_pin(pin)
if __name__=='__main__':unittest.main()
