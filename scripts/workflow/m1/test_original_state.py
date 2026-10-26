import base64,contextlib,hashlib,importlib.util,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('fresh_state_target',HERE/'target.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class ActualOriginalState(unittest.TestCase):
 def test_exact_actual_state_raw_descriptor_and_changed_bytes_refused(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as t:
   p=Path(t);d=p/'original-backup';d.mkdir();raw=b'{"full_original_metadata":{"fresh":1793027000123456789}}';f=d/'state.original.json';f.write_bytes(raw);pin={'sha256':m.digest(raw),'bytes':len(raw)};r={'device':'m1','packet':str(p),'boot_id':'cpu-boot','status':'LOCAL_BACKUP_VERIFIED_ONLY','old_module_tree_sha256':'a'*64,'script_sha256':'b'*64,'objects':{'state.original.json':pin}};rr=json.dumps(r).encode();(d/'BACKUP-RECEIPT.json').write_bytes(rr);(p/'BACKUP-SOURCE-FREEZE.json').write_bytes(b'{}');profile={'packet':str(p),'device':'m1','old_module_tree_sha256':'a'*64,'backup_source':{'sha256':'b'*64}};request={'expected_boot_id':'cpu-boot','receipt_sha256':m.digest(rr)};held=m.held_regular;verify=m.verify
   @contextlib.contextmanager
   def fixture_uid(path,bound=m.MAX_JSON,uid=0):
    with held(path,bound,os.geteuid()) as value:yield value
   # Only root UID/packet location are remapped; actual O_PATH/read/hash and
   # final inode checks plus object collection run unchanged on real files.
   with patch.object(m,'verify_owned_packet',lambda p:Path(p['packet'])),patch.object(m,'held_regular',fixture_uid),patch.object(m,'verify',lambda path,pin,deadline:verify(path,pin,deadline,os.geteuid())):
    out=m.collect_capture(profile,request,time.monotonic()+10,'backup');self.assertEqual(base64.b64decode(out['original_state']['base64']),raw);self.assertEqual(out['original_state']['sha256'],pin['sha256']);self.assertEqual(out['original_state']['bytes'],len(raw));f.write_bytes(raw+b' ')
    with self.assertRaises(RuntimeError):m.collect_capture(profile,request,time.monotonic()+10,'backup')
 def test_historical_backup_decision_is_not_reusable_asset(self):
  s=importlib.util.spec_from_file_location('asset_policy',HERE/'assets.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a);self.assertNotIn('OWNER-BACKUP-DECISIONS.json',a.IMMUTABLE);self.assertNotIn("'OWNER-BACKUP-DECISIONS.json'",a.REMOTE)
if __name__=='__main__':unittest.main()
