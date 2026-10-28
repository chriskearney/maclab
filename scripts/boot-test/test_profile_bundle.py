"""Real local filesystem/archive controls; no network, target or helper execution."""
import errno,io,json,os,sys,tarfile,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
import profile_bundle as b
class Bundle(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.src=self.root/'source';self.src.mkdir(mode=0o700);self.archive=self.root/'package.tar.gz';self.dest=self.root/'installed';self.data=b'hello exact source\n';self.files={'compiler.py':self.data,'recipe.json':(json.dumps({'owner_order':{'z':1,'a':2},'tool':{'path':str(self.src/'compiler.py'),'sha256':b.H(self.data),'bytes':len(self.data)},'unrelated_literal':'/session/source/literal'},indent=2)+'\n').encode()}
  for n,v in self.files.items():(self.src/n).write_bytes(v);(self.src/n).chmod(0o600)
  (self.src/'COMPONENTS.json').write_bytes(b.json_bytes({'schema':'maclab.m1-source-components/1','roles':{},'freezes':{},'files':{n:{'sha256':b.H(v),'bytes':len(v)} for n,v in self.files.items()}}));(self.src/'EXTERNAL-PREREQUISITES.json').write_bytes(b.json_bytes({'schema':'maclab.profile-external-prerequisites/1','pins':[]}));(self.src/'components/postinstall').mkdir(parents=True,mode=0o700)
  c=b.json_bytes({'source':{'path':str(self.src/'compiler.py'),'sha256':b.H(self.data),'bytes':len(self.data)},'closure':[]});(self.src/'components/postinstall/CONTRACT.json').write_bytes(c)
  m=b.u.read_json(str(self.src/'COMPONENTS.json'));m['files']['components/postinstall/CONTRACT.json']={'sha256':b.H(c),'bytes':len(c)};(self.src/'COMPONENTS.json').write_bytes(b.json_bytes(m));self.pin=b.pack(self.src,self.archive)['archive']
 def install(self,**kw):return b.install(self.archive,self.pin,self.dest,True,**kw)
 def rewrite(self,change):
  with tarfile.open(self.archive,'r:gz') as t:members=[(x.name,t.extractfile(x).read()) for x in t]
  members=change(members)
  out=self.root/'altered.tar.gz'
  with tarfile.open(out,'w:gz') as t:
   for n,raw in members:
    x=tarfile.TarInfo(n);x.size=len(raw);x.mode=0o600;t.addfile(x,io.BytesIO(raw))
  return out,b.u.local(str(out),limit=b.MAXTOTAL,contents=False)[0]
 def test_roundtrip_descriptor_relocation_not_arbitrary_text(self):
  r=self.install();d=b.u.read_json(str(self.dest/'recipe.json'));self.assertEqual(d['tool']['path'],str(self.dest/'compiler.py'));self.assertEqual(d['unrelated_literal'],'/session/source/literal');self.assertEqual(list(d['owner_order']),['z','a']);self.assertEqual((self.dest/'compiler.py').read_bytes(),self.data);self.assertTrue(r['fsync_and_full_reopen_verified']);self.assertFalse(r['durable_installation']);self.assertFalse(r['approval_created'])
 def test_volatile_install_never_durable(self):
  with self.assertRaisesRegex(Exception,'durable'):b.install(self.archive,self.pin,self.dest)
  self.assertFalse(self.dest.exists())
 def test_source_tamper_refuses_pack(self):
  (self.src/'compiler.py').write_bytes(b'changed')
  with self.assertRaises(Exception):b.pack(self.src,self.root/'bad.tar.gz')
 def test_source_symlink_refused(self):
  (self.src/'compiler.py').unlink();(self.src/'compiler.py').symlink_to(self.src/'recipe.json')
  with self.assertRaises(Exception):b.pack(self.src,self.root/'bad.tar.gz')
 def test_archive_tamper_refused_before_prefix(self):
  with self.archive.open('ab') as f:f.write(b'changed')
  with self.assertRaises(Exception):self.install()
  self.assertFalse(self.dest.exists())
 def test_member_hash_and_missing_and_extra_refuse(self):
  for transform in (lambda xs:[(n,b'changed' if n=='compiler.py' else v) for n,v in xs],lambda xs:[x for x in xs if x[0]!='compiler.py'],lambda xs:xs+[('extra.py',b'not listed')]):
   p,pin=self.rewrite(transform)
   with self.assertRaises(Exception):b.install(p,pin,self.dest,True)
   self.assertFalse(self.dest.exists());p.unlink()
 def test_traversal_and_duplicate_refuse(self):
  for transform in (lambda xs:xs+[('../escape',b'unsafe')],lambda xs:xs+[xs[1]]):
   p,pin=self.rewrite(transform)
   with self.assertRaises(Exception):b.install(p,pin,self.dest,True)
   self.assertFalse(self.dest.exists());p.unlink()
 def test_fsync_eio_no_success_no_adoption_no_retry(self):
  calls=[]
  def fail(fd):calls.append(fd);raise OSError(errno.EIO,'synthetic storage failure')
  with self.assertRaises(OSError):self.install(sync=fail)
  self.assertEqual(len(calls),1);self.assertTrue(self.dest.exists());self.assertFalse((self.dest/'INSTALLATION.json').exists())
  with self.assertRaisesRegex(Exception,'new source prefix'):self.install()
 def test_existing_namespace_never_overwritten(self):
  self.dest.mkdir();(self.dest/'sentinel').write_bytes(b'keep')
  with self.assertRaises(Exception):self.install()
  self.assertEqual((self.dest/'sentinel').read_bytes(),b'keep')
 def test_wrong_relocation_preimage_refused(self):
  def change(xs):
   out=[]
   for n,v in xs:
    if n=='PACKAGE.json':m=b.u.unique(v);m['relocations'][0]['expected_path']='/foreign/source';v=b.json_bytes(m)
    out.append((n,v))
   return out
  p,pin=self.rewrite(change)
  with self.assertRaises(Exception):b.install(p,pin,self.dest,True)
  self.assertFalse(self.dest.exists())
 def test_chunk_sync_and_final_readback(self):
  large=b'X'*(2*1048576+7);calls=[];p=self.root/'large'
  def sync(fd):calls.append(fd);os.fsync(fd)
  pin=b.create(p,large,sync);self.assertEqual(len(calls),4);self.assertEqual(pin['sha256'],b.H(large));self.assertEqual(p.read_bytes(),large)
 def test_closed_profile_generated_without_approval(self):
  docs={'PROFILE-TEMPLATE.json':{'execution_ready':False,'id':'fixture'},'PROFILE-BINDING.json':{'schema':'maclab.source-profile-binding/1','compiler':'compiler.py','call':'compile_device','sources':{n:{'source':'compiler.py','closure':[]} for n in ('capture','owner','rollback','final_restore')}}}
  m=b.u.read_json(str(self.src/'COMPONENTS.json'))
  for n,d in docs.items():
   raw=b.json_bytes(d);(self.src/n).write_bytes(raw);m['files'][n]={'sha256':b.H(raw),'bytes':len(raw)}
  (self.src/'COMPONENTS.json').write_bytes(b.json_bytes(m));p=self.root/'with-profile.tar.gz';pin=b.pack(self.src,p)['archive'];r=b.install(p,pin,self.dest,True)
  profile=b.u.read_json(str(self.dest/'profile.CLOSED.json'));catalog=b.u.read_json(str(self.dest/'catalog.CLOSED.json'));self.assertFalse(profile['execution_ready']);self.assertEqual(catalog['status'],'PENDING_ROOT_SOURCE_REVIEW');self.assertEqual(profile['compiler']['source']['path'],str(self.dest/'compiler.py'));self.assertEqual(profile['compiler']['source']['sha256'],b.H(self.data));self.assertEqual(catalog['profiles']['fixture'],r['files']['profile.CLOSED.json']);self.assertFalse(r['profile_execution_ready_created']);self.assertFalse(r['approval_created'])
if __name__=='__main__':unittest.main()
