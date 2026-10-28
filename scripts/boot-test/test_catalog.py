"""Synthetic three-model registry and real metadata/compile controls; no Macs."""
import copy,hashlib,io,json,os,sys,tarfile,tempfile,unittest
from pathlib import Path
import catalog,intake
HERE=Path(__file__).parent
def save(path,x):path.write_text(json.dumps(x));path.chmod(0o600);return intake.pin(path)
class Catalog(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(self.t.cleanup);self.P=Path(self.t.name);self.compiler=self.P/'compiler.py';self.compiler.write_text("""import json,hashlib
from pathlib import Path
def compile_device(recipe,packet,out,mode):
 p=recipe['device_profile'];o=Path(out);o.mkdir(mode=0o700);plan={'schema':'maclab.workflow/1','id':Path(packet).name,'device':p['device'],'inputs':{'recovery_mode':mode,'recovery_transaction':Path(packet).name,'restoration_contract':p['restore'],'actual_requested_artifacts':recipe['reviewed_artifact_inputs']},'helpers':{},'phases':[{'id':n,'kind':'bind','timeout_sec':2,'mutates':False,'template':{}} for n in p['restore']['phase_order']]};raw=json.dumps(plan).encode();f=o/'plan.json';f.write_bytes(raw);return {'plan':{'path':str(f),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}}
""");self.source=intake.pin(self.compiler)
 def artifact(self,version='1-1'):
  p=self.P/('kernel-'+version+'.pkg.tar.zst');raw=('pkgname = linux-aurora\npkgver = '+version+'\narch = aarch64\n').encode()
  with tarfile.open(p,'w:zst') as t:x=tarfile.TarInfo('.PKGINFO');x.size=len(raw);t.addfile(x,io.BytesIO(raw))
  pin=intake.pin(p);return p,{'kind':'arch-package','sha256':pin['sha256'],'bytes':pin['bytes'],'version':version,'metadata':{'pkgname':'linux-aurora','pkgver':version,'arch':'aarch64'}}
 def profile(self,device='m1',version='1-1'):
  board,model,old={'m1':('apple,j293','Apple M1 Pro13','old6'),'m1air':('apple,j313','Apple M1 Air','old6'),'m3pro':('apple,j516s','Apple M3 Pro16','custom7876')}[device];artifact,slot=self.artifact(version);p={'schema':'maclab.device-test-profile/1','id':'CPU-'+device+'-'+version,'device':device,'board':board,'soc':'CPU-source-fixture','dt_model':model,'execution_ready':True,'original':{'kind':'custom-current-state' if device=='m3pro' else 'installed','kernel':old,'package_versions':{'linux-aurora':'original'},'absent_packages':['omarchy-mac-boot'] if device=='m3pro' else []},'candidate':{'kernel':'new7','artifact_slots':{'linux-aurora':slot},'input_roles':{'kernel':'linux-aurora','mesa_packages':[]}},'sources':{n:{'source':self.source,'closure':[]} for n in ('capture','owner','rollback','final_restore')},'recovery_modes':['network-only','serial-assisted'],'compiler':{'source':self.source,'closure':[],'call':'compile_device'},'restore':{'strategy':'CPU-custom-absent' if device=='m3pro' else 'CPU-installed','phase_order':['install','test','restore','verdict','final'],'final_kernel':old,'required_status':'CPU_ORIGINAL_VERIFIED','boot_package_must_be_absent':device=='m3pro','runtime_evidence':{'audit_phase':'restore','audit_pointer':'/target','verdict_phase':'verdict','final_assertion_phase':'final','checks':{'/status':'CPU_ORIGINAL_VERIFIED'},'bindings':{'packet':'/packet','plan_sha256':'/root_plan_sha256','boot_id':'/boot_id'},'absent_package_checks':{'omarchy-mac-boot':{'pointer':'/packages/omarchy-mac-boot','equals':'absent'}} if device=='m3pro' else {}}}};return p,artifact
 def files(self,p):
  profile=save(self.P/(p['id']+'.json'),p);cat=save(self.P/(p['id']+'-catalog.json'),{'schema':'maclab.device-test-catalog/1','status':'ROOT_SOURCE_REVIEWED','reviewed_by':'CPU-fixture-only','profiles':{p['id']:profile}});recipe=save(self.P/(p['id']+'-recipe.json'),{});review=save(self.P/(p['id']+'-review.json'),{'schema':'maclab.boot-test-profile-source-review/1','status':'ROOT_SOURCE_REVIEWED','catalog':cat,'profile':profile,'device':p['device'],'reviewed_by':'CPU-fixture-only','compiler':self.source,'source_files':[],'metadata_helper':intake.pin(HERE/'metadata.py'),'python':intake.pin(Path(sys.executable).resolve()),'recipe':recipe,'holder':'CPU-owner'});return cat,review
 def test_exact_three_models_custom_kernel_and_package_absence(self):
  for device in ('m1','m1air','m3pro'):
   p,a=self.profile(device);cp,r=self.files(p);got,pp=catalog.load(cp,p['id'],device,True);d={'name':device,'kernel':p['original']['kernel'],'state':'ready','alive':True,'cmdline':'root=ordinary','facts':{'machine':'aarch64','dt_model':p['dt_model']}};out=catalog.baseline(d,p,'network-only');self.assertEqual(out['device'],device);self.assertEqual(got['restore']['boot_package_must_be_absent'],device=='m3pro')
   bad=copy.deepcopy(d);bad['facts']['compatible']=['apple,j999']
   with self.assertRaises(catalog.Refused):catalog.baseline(bad,p,'network-only')
 def test_catalog_does_not_imply_ready_and_never_substitutes_m1(self):
  p,a=self.profile('m1air');p['execution_ready']=False;cp,r=self.files(p)
  with self.assertRaisesRegex(catalog.Refused,'PENDING_ADAPTER'):catalog.load(cp,p['id'],'m1air',True)
  with self.assertRaisesRegex(catalog.Refused,'SUBSTITUTION|substitution'):catalog.load(cp,p['id'],'m1',False)
 def test_metadata_then_real_compiler_accepts_new_reviewed_tuple_as_data(self):
  source_hash=hashlib.sha256(self.compiler.read_bytes()).hexdigest();hashes=[]
  for version in ('1-1','2-1'):
   p,a=self.profile('m3pro',version);cp,r=self.files(p);req={'schema':'maclab.boot-test-request/2','device':'m3pro','recovery_mode':'network-only','artifacts':{'linux-aurora':str(a)}};result=intake.run(cp,p['id'],req,r,self.P/('out-'+version),'/var/lib/maclab/rc7-m3pro-cpu-'+version,True);plan=catalog.unique(catalog.read_pin(result['compiled']['plan']));self.assertEqual(plan['inputs']['actual_requested_artifacts']['linux-aurora']['sha256'],p['candidate']['artifact_slots']['linux-aurora']['sha256']);self.assertEqual(plan['inputs']['restoration_contract']['final_kernel'],'custom7876');self.assertEqual([v['kind'] for v in plan['phases'][:2]],['cache','upload']);hashes.append(result['compiled']['plan']['sha256'])
  self.assertNotEqual(*hashes);self.assertEqual(hashlib.sha256(self.compiler.read_bytes()).hexdigest(),source_hash)
 def test_absent_package_and_current_model_contract_mismatches_refuse(self):
  p,a=self.profile('m3pro');p['original']['package_versions']['omarchy-mac-boot']='unexpected'
  with self.assertRaises(catalog.Refused):catalog.profile_shape(p)
  p,a=self.profile('m3pro');d={'name':'m3pro','kernel':'old6','facts':{'machine':'aarch64','dt_model':p['dt_model']}}
  with self.assertRaises(catalog.Refused):catalog.baseline(d,p,'network-only')
 def test_descriptor_hash_symlink_and_duplicate_json_refuse(self):
  p,a=self.profile();cp,r=self.files(p);bad=copy.deepcopy(cp);bad['sha256']='0'*64
  with self.assertRaises(catalog.Refused):catalog.load(bad,p['id'],'m1')
  link=self.P/'link';link.symlink_to(cp['path']);bad={**cp,'path':str(link)}
  with self.assertRaises(catalog.Refused):catalog.read_pin(bad)
  with self.assertRaises(catalog.Refused):catalog.unique('{"a":1,"a":2}')
 def test_restore_contract_and_unreviewed_source_phase_refuse(self):
  p,a=self.profile();plan={'schema':'maclab.workflow/1','device':'m1','id':'rc7-m1-cpu','inputs':{'recovery_mode':'network-only','recovery_transaction':'rc7-m1-cpu','restoration_contract':p['restore']},'helpers':{},'phases':[{'id':n} for n in ['install','restore','test','final']]}
  with self.assertRaises(catalog.Refused):catalog.validate_plan(plan,p,'/var/lib/maclab/rc7-m1-cpu','network-only',{})
  plan['phases']=[{'id':n} for n in p['restore']['phase_order']];plan['helpers']={'foreign':{'python':self.source,'source':self.source}}
  with self.assertRaisesRegex(catalog.Refused,'unreviewed'):catalog.validate_plan(plan,p,'/var/lib/maclab/rc7-m1-cpu','network-only',{})
if __name__=='__main__':unittest.main()
