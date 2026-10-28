"""Actual relocatable packaging/entry controls; help only, no API/target work."""
import hashlib,json,os,subprocess,tarfile,tempfile,unittest
from pathlib import Path
import bundle,catalog
HERE=Path(__file__).parent
class Bundle(unittest.TestCase):
 def test_reproducible_bundle_and_relocated_real_entry(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as t:
   p=Path(t);a=bundle.make(HERE,p/'a.tgz');b=bundle.make(HERE,p/'b.tgz');self.assertEqual(a['sha256'],b['sha256']);dest=p/'unrelated-prefix';dest.mkdir()
   with tarfile.open(p/'a.tgz') as tar:
    for member in tar:
     self.assertTrue(member.isfile());self.assertFalse(Path(member.name).is_absolute());data=tar.extractfile(member).read();q=dest/member.name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(data);q.chmod(member.mode)
   for n,row in a['manifest']['files'].items():self.assertEqual(hashlib.sha256((dest/n).read_bytes()).hexdigest(),row['sha256'])
   r=subprocess.run([str(dest/'bin/lab-boot-test'),'--help'],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'--catalog-descriptor',r.stdout);self.assertIn(b'--execute',r.stdout);self.assertFalse(a['manifest']['profiles_bundled']);self.assertFalse(a['manifest']['hardware_qualification'])
 def test_nonregular_source_refused_before_output(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm') as t:
   p=Path(t)
   for n in bundle.SOURCES:(p/n).symlink_to(HERE/n)
   with self.assertRaises(catalog.Refused):bundle.make(p,p/'out.tgz')
   self.assertFalse((p/'out.tgz').exists())
if __name__=='__main__':unittest.main()
