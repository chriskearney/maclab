import hashlib,importlib.util,io,json,os,struct,subprocess,tempfile,tarfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('metadata',HERE/'metadata.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Metadata(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(self.t.cleanup);self.p=Path(self.t.name)/'pkg.tar.zst'
 def archive(self,items,info=b'pkgname = linux-aurora\npkgver = 1-1\narch = aarch64\n',kind='arch-package'):
  with tarfile.open(self.p,'w:zst') as t:
   if info is not None:
    x=tarfile.TarInfo('.PKGINFO');x.size=len(info);t.addfile(x,io.BytesIO(info))
   for name,data,typ in items:
    x=tarfile.TarInfo(name);x.type=typ;x.size=len(data) if typ==tarfile.REGTYPE else 0;x.linkname='outside';t.addfile(x,io.BytesIO(data) if x.size else None)
  b=self.p.read_bytes();return {'kind':kind,'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':{'pkgname':'linux-aurora','pkgver':'1-1','arch':'aarch64'}}
 def test_real_zstd_archive_metadata_and_image_config_provider_hashes(self):
  image=bytearray(64);image[56:60]=b'ARM\x64';elf=bytearray(64);elf[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',elf,18,183);cfg=b'CONFIG_DRM_ASAHI=y\n';rows=[('usr/lib/modules/k/vmlinuz',bytes(image),tarfile.REGTYPE),('usr/lib/modules/k/build/.config',cfg,tarfile.REGTYPE),('usr/lib/libvulkan_asahi.so',bytes(elf),tarfile.REGTYPE)];slot=self.archive(rows);slot['expected_payload']={n:{'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'role':role,**({'required_config':{'CONFIG_DRM_ASAHI':'y'}} if role=='kernel-config' else {})} for (n,b,t),role in zip(rows,['arm64-image','kernel-config','aarch64-elf'])};out=m.scan(self.p,slot);self.assertEqual(out['package']['pkgver'],'1-1');self.assertEqual(len(out['payload']),3);self.assertFalse(out['runtime_execution_proved']);self.assertFalse(any((self.p.parent/'usr').glob('*')))
 def test_wrong_version_arch_and_duplicate_pkginfo_fields_refused(self):
  for info in (b'pkgname = linux-aurora\npkgver = 2-1\narch = aarch64\n',b'pkgname = linux-aurora\npkgver = 1-1\narch = x86_64\n',b'pkgname = linux-aurora\npkgname = linux-aurora\npkgver = 1-1\narch = aarch64\n'):
   slot=self.archive([],info)
   with self.assertRaises(m.Refused):m.scan(self.p,slot)
 def test_traversal_duplicate_special_and_pkginfo_symlink_refused(self):
  for rows,info in [([('../escape',b'x',tarfile.REGTYPE)],b'pkgname = linux-aurora\npkgver = 1-1\narch = aarch64\n'),([('x',b'a',tarfile.REGTYPE),('./x',b'b',tarfile.REGTYPE)],None),([('fifo',b'',tarfile.FIFOTYPE)],None),([('.PKGINFO',b'',tarfile.SYMTYPE)],None)]:
   slot=self.archive(rows,info)
   with self.assertRaises(m.Refused):m.scan(self.p,slot)
 def test_corrupt_stream_and_source_hash_refused(self):
  slot=self.archive([]);self.p.write_bytes(b'not a tar stream');slot.update(bytes=self.p.stat().st_size,sha256=hashlib.sha256(self.p.read_bytes()).hexdigest())
  with self.assertRaises(Exception):m.scan(self.p,slot)
  slot=self.archive([]);slot['sha256']='0'*64
  with self.assertRaisesRegex(m.Refused,'hash'):m.scan(self.p,slot)
 def test_expected_payload_missing_or_invalid_image_provider_config_refused(self):
  for role,raw,extra in [('arm64-image',b'x'*64,{}),('aarch64-elf',b'x'*64,{}),('kernel-config',b'CONFIG_X=n\n',{'required_config':{'CONFIG_X':'y'}})]:
   slot=self.archive([('payload',raw,tarfile.REGTYPE)]);slot['expected_payload']={'payload':{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'role':role,**extra}}
   with self.assertRaises(m.Refused):m.scan(self.p,slot)
  slot=self.archive([]);slot['expected_payload']={'missing':{'sha256':'0'*64,'bytes':1}}
  with self.assertRaises(m.Refused):m.scan(self.p,slot)
 def test_four_regular_stage2_members_no_esp_execution_claim(self):
  rows=[(n,n.encode(),tarfile.REGTYPE) for n in ('manifest.json','original.bin','candidate.bin','core.py')];slot=self.archive(rows,None,'stage2-bundle');slot['members']=[n for n,b,t in rows];slot['expected_payload']={n:{'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)} for n,b,t in rows};out=m.scan(self.p,slot);self.assertFalse(out['loader_execution_proved']);self.assertTrue(out['live_stage1_stage2_tag_proof_required'])
 def test_provider_ledger_is_parsed_and_exactly_bound(self):
  raw=(json.dumps({'path':'usr/lib/libnative.so','sha256':'a'*64,'bytes':128})+'\n').encode();self.p.write_bytes(raw);slot={'kind':'provider-ledger','sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'providers':{'usr/lib/libnative.so':{'sha256':'a'*64,'bytes':128}}};self.assertEqual(m.scan(self.p,slot)['ledger_entries'],1);slot['providers']['usr/lib/libnative.so']['sha256']='b'*64
  with self.assertRaises(m.Refused):m.scan(self.p,slot)
 def test_cli_child_limits_real_scan_and_no_extract(self):
  slot=self.archive([]);r=subprocess.run(['/usr/bin/python3','-E',str(HERE/'metadata.py'),'--artifact',str(self.p),'--slot',json.dumps(slot)],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertFalse(json.loads(r.stdout)['runtime_execution_proved'])
if __name__=='__main__':unittest.main()
