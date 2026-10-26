import copy,datetime,hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('installed_adapter',HERE/'installed.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def pin(p):b=Path(p).read_bytes();return {'path':str(p),'sha256':m.H(b),'bytes':len(b)}
class InstalledNamespace(unittest.TestCase):
 def binding(self):
  p={'device':'m1','packet':'/var/lib/maclab/rc7-m1-cpu-new-transaction','holder':'cpu-owner'}
  return {'profile':p,'source_reviewed_by':'CPU scoped reviewer','root_plan_sha256':'a'*64,'root_scope':{'packet':p['packet'],'operation':'freeze-preinstall','root_plan_sha256':'a'*64,'authority_sha256':m.AUTH,'reviewed_by':'CPU scoped reviewer'}}
 def source(self,t):
  root=Path(t)/'frozen';root.mkdir();src=root/'old-source';(src/'preinstall/m1').mkdir(parents=True)
  values={'baseline-job.json':json.dumps({'id':'j-real-original','spec':{'device':'m1'}}).encode(),'dmesg-errors.txt':b'','omt-report.json':b'{"original":true}','omt-status.json':b'{"existing":"fails"}'}
  pins={}
  for n,v in values.items():(src/'preinstall/m1'/n).write_bytes(v);pins[n]=pin(src/'preinstall/m1'/n)
  (src/'PINS.preinstall').write_text(''.join(pins[n]['sha256']+'  preinstall/m1/'+n+'\n' for n in sorted(pins)))
  b=self.binding();b.update(action='freeze-preinstall',frozen_root=str(root),source_release='old-source',source_baseline_job='j-real-original',source_pins=pin(src/'PINS.preinstall'),preinstall_pins=pins);return b,values
 def test_real_writeonce_baseline_copy_preserves_all_original_bytes(self):
  with tempfile.TemporaryDirectory(dir="/run/user/"+str(os.geteuid())) as t:
   b,values=self.source(t);out=m.run(b);d=Path(b['frozen_root'])/Path(b['profile']['packet']).name
   for n,v in values.items():self.assertEqual((d/'preinstall/m1'/n).read_bytes(),v)
   self.assertEqual((d/'PINS.preinstall').read_bytes(),Path(b['source_pins']['path']).read_bytes());self.assertFalse(out['new_baseline_claim']);self.assertFalse(out['reference_changes'])
   with self.assertRaisesRegex(RuntimeError,'already exists'):m.run(b)
 def test_changed_or_wrong_original_baseline_refused_before_namespace_write(self):
  with tempfile.TemporaryDirectory(dir="/run/user/"+str(os.geteuid())) as t:
   b,_=self.source(t);Path(b['preinstall_pins']['omt-report.json']['path']).write_bytes(b'{"tampered":true}')
   with self.assertRaises(RuntimeError):m.run(b)
   self.assertFalse((Path(b['frozen_root'])/Path(b['profile']['packet']).name).exists())
  with tempfile.TemporaryDirectory(dir="/run/user/"+str(os.geteuid())) as t:
   b,_=self.source(t);b['source_baseline_job']='fabricated-new-baseline'
   with self.assertRaisesRegex(RuntimeError,'actual original baseline job'):m.run(b)
 def test_nonregular_original_no_open_or_namespace_adoption(self):
  with tempfile.TemporaryDirectory(dir="/run/user/"+str(os.geteuid())) as t:
   b,_=self.source(t);p=Path(b['preinstall_pins']['omt-report.json']['path']);p.unlink();os.mkfifo(p)
   with self.assertRaisesRegex(RuntimeError,'not bounded source'):m.run(b)
   self.assertFalse((Path(b['frozen_root'])/Path(b['profile']['packet']).name).exists())
 def test_expectation_changes_only_release_and_retains_real_payload(self):
  with tempfile.TemporaryDirectory(dir="/run/user/"+str(os.geteuid())) as t:
   t=Path(t);payload=b'payload unchanged\n';p=t/'payload';p.write_bytes(payload);value={'schema':'maclab.installed-manifest/2','release':'old-source','kernel':{'release':m.KERNEL,'vmlinuz_sha256':'95b73368323e7886450369746d123cd24ab6c156704ecb2f7824eee22ee82e25','payload_manifest_sha256':m.H(payload)},'macs':{'m1':{'board':'apple,j293'}},'artifacts':[{'sha256':'b'*64}]};f=t/'manifest';f.write_text(json.dumps(value));b=self.binding();b.update(action='prepare-expectation',source_manifest=pin(f),payload=pin(p));cwd=os.getcwd();os.chdir(t)
   try:out=m.run(b)
   finally:os.chdir(cwd)
   expected=copy.deepcopy(value);expected['release']=Path(b['profile']['packet']).name;self.assertEqual(out['manifest_value'],expected);self.assertEqual(Path(out['payload']['path']).read_bytes(),payload)
 def api_binding(self):
  b=self.binding();b.update(action='freeze-entry',expected_boot_id='fresh-real-boot',installed_manifest_sha256='d'*64,postinstall={'packet':b['profile']['packet'],'installed_manifest_sha256':'d'*64,'candidate_uki':{'sha256':'e'*64,'bytes':60703744},'menus':{'temp6_sha256':'f'*64}});b['root_scope']['operation']='freeze-entry';return b
 def api(self,mutate=None):
  parent=self
  class API:
   def request(self,path,body=None,timeout=60):
    if path=='/api/devices/m1':return {'name':'m1','state':'ready','alive':True,'boot_id':'fresh-real-boot','kernel':'7.2.11-6-1-ARCH','cmdline':'ordinary','lease':{'holder':'cpu-owner','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
    parent.assertEqual(path,'/api/installed/rc7-m1-cpu-new-transaction/entry/m1');entry={'schema':'maclab.installer-entry/1','device':'m1','release':'rc7-m1-cpu-new-transaction','captured_boot_id':'fresh-real-boot','uki_sha256':'e'*64,'uki_sections':{'.linux':{'sha256':'95b73368323e7886450369746d123cd24ab6c156704ecb2f7824eee22ee82e25'},'.uname':{'text':m.KERNEL}},'limine_conf_sha256':'f'*64,'protocol':'efi','cmdline':'ordinary'}
    if mutate:mutate(entry)
    return {'device':'m1','release':'rc7-m1-cpu-new-transaction','entry':entry,'entry_sha256':'1'*64}
  return API()
 def test_actual_api_entry_crossbound_to_observed_kernel_boot_and_menu(self):
  b=self.api_binding();self.assertEqual(m.run(b,self.api())['status'],'SUPPORTED_INSTALLED_FREEZE_ENTRY_OBSERVED')
  for key in ('captured_boot_id','uki_sha256','limine_conf_sha256'):
   with self.subTest(key=key),self.assertRaises(RuntimeError):m.run(b,self.api(lambda e:e.update({key:'wrong'})))
 def test_forbidden_promote_and_false_postinstall_identity_refused(self):
  b=self.api_binding();b['action']='promote'
  with self.assertRaisesRegex(RuntimeError,'finite supported'):m.run(b,self.api())
  b=self.api_binding();b['postinstall']['packet']+='-stale'
  with self.assertRaisesRegex(RuntimeError,'actual accepted candidate'):m.run(b,self.api())
if __name__=='__main__':unittest.main()
