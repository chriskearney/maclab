import copy,datetime,hashlib,importlib.util,json,os,shlex,shutil,tempfile,types,unittest
from unittest.mock import patch
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('finite_resolver',HERE/'resolver.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Resolver(unittest.TestCase):
 def typed(self,corrupt=False):
  path=Path('/dev/shm/sf-rc-m1-reprobe-execution-root/candidate-files.jsonl')
  if not path.exists():self.skipTest('actual reviewed ledger fixture absent')
  raw=path.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),m.LEDGER)
  class Typed:
   def digest(self,p):return hashlib.sha256(raw).hexdigest()
   def read_regular(self,p,bound=0,keep=False):
    if p.name=='candidate-files.jsonl':return types.SimpleNamespace(st_size=len(raw)),m.H(raw),raw
    row=next(x for x in m.ROWS if x['file']==p.name);return types.SimpleNamespace(st_size=row['bytes']),'0'*64 if corrupt else row['sha256'],None
  return Typed()
 def execute(self,P,extra=False,deny=False,patterns=None,hookdir='/etc/pacman.d/hooks/'):
  outer=self
  def run(argv,timeout):
   if argv[0]=='/usr/bin/pacman-conf':out=(hookdir+'\n') if argv[1]=='HookDir' else '\n'.join((patterns or {}).get(argv[1],[]));return {'exit_code':0,'stdout':out,'stderr':''}
   outer.assertEqual(argv[:8],['/usr/bin/pacman','-U','--noconfirm','--print','--print-format','%n|%v|%l','--',str(P/'packages'/m.ROWS[0]['file'])]);outer.assertNotIn('-dd',argv);outer.assertNotIn('--overwrite',argv);out='\n'.join('|'.join((x['name'],x['version'],str(P/'packages'/x['file']))) for x in m.ROWS)+('\nextra-dependency|1|extra' if extra else '');return {'exit_code':1 if deny else 0,'stdout':out,'stderr':'invalid package signature' if deny else ''}
  return run
 def test_real_candidate_ledger_with_fresh_namespace_and_normal_pacman_argv(self):
  P=Path('/var/lib/maclab/rc7-m1-cpu-fresh-resolver');seen=[];r=m.resolve(P,self.typed(),self.execute(P),seen);self.assertEqual(r['status'],'READ_ONLY_EXACT_FIVE_RESOLVED');self.assertEqual(len(r['resolved']),5);self.assertNotIn('spec_sha256',r);self.assertEqual(len(seen),4)
 def test_dependency_signature_or_added_targets_fail_with_actual_output_retained(self):
  for opts in ({'deny':True},{'extra':True}):
   P=Path('/var/lib/maclab/rc7-m1-cpu-fresh-resolver');seen=[]
   with self.assertRaises(RuntimeError):m.resolve(P,self.typed(),self.execute(P,**opts),seen)
   self.assertEqual(len(seen),4);self.assertIn('actual',seen[-1])
 def test_configured_payload_exclusion_or_new_hook_directory_stops_before_resolution(self):
  P=Path('/var/lib/maclab/rc7-m1-cpu-fresh-resolver')
  for opts in ({'patterns':{'NoExtract':['usr/lib/*']}},{'hookdir':'/new/unreviewed/hooks/'}):
   seen=[]
   with self.assertRaises(RuntimeError):m.resolve(P,self.typed(),self.execute(P,**opts),seen)
   self.assertEqual(len(seen),3)
 def test_actual_fnmatch_negative_patterns_preserve_ordered_semantics(self):
  self.assertTrue(m.affected('usr/lib/x',['usr/lib/*']));self.assertFalse(m.affected('usr/lib/x',['usr/lib/*','!usr/lib/x']));self.assertTrue(m.affected('usr/lib/x',['!usr/lib/x','usr/lib/*']))
 def test_exact_archive_drift_stops_before_package_resolution(self):
  P=Path('/var/lib/maclab/rc7-m1-cpu-fresh-resolver');seen=[]
  with self.assertRaisesRegex(RuntimeError,'archive mismatch'):m.resolve(P,self.typed(True),self.execute(P),seen)
  self.assertEqual(len(seen),3)
 def test_actual_wire_compiles_and_crossbinds_candidate_result(self):
  esp=Path('/dev/shm/m1-esp-fragment-source-r4/esp.py')
  if not esp.exists():self.skipTest('reviewed ESP closure absent')
  b={'schema':'maclab.m1-resolver-binding/1','profile':{'device':'m1','board':'apple,j293','packet':'/var/lib/maclab/rc7-m1-cpu-fresh-resolver','source_packet':'/var/lib/maclab/rc7-m1-cpu-source-retained','holder':'owner','agent_parent':{'path':'/usr/local/bin/lab-agent','sha256':'b'*64,'bytes':100}},'root_plan_sha256':'a'*64,'packet_profile_sha256':'c'*64,'expected_boot_id':'cpu-boot'};P=Path(b['profile']['packet']);result=m.resolve(P,self.typed(),self.execute(P),[]);outer=self
  class API:
   def request(self,path,body=None,timeout=60):
    if body is None:return {'name':'m1','state':'ready','alive':True,'boot_id':'cpu-boot','kernel':'7.2.11-6-1-ARCH','lease':{'holder':'owner','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
    args=shlex.split(body['command']);outer.assertLess(len(body['command'].encode()),120000);compile(args[4],'<actual-resolver-wire>','exec');o={'schema':'maclab.m1-resolver-observation/1','status':'READ_ONLY_EXACT_FIVE_RESOLVED','packet':b['profile']['packet'],'boot_id':'cpu-boot','kernel':'7.2.11-6-1-ARCH','root_plan_sha256':'a'*64,'target_mutations':False,'result':result};return {'exit_code':0,'via':'agent','stderr':'','stdout':json.dumps(o)}
  with tempfile.TemporaryDirectory(dir='/run/user/'+str(os.geteuid())) as t:
   root=Path(t)
   for source,name in [(HERE/'resolver.py','resolver.py'),(HERE/'proofs.py','proofs.py'),(esp,'esp.py'),(HERE/'frozen-controller-ea3.py','frozen-controller-ea3.py')]:shutil.copyfile(source,root/name)
   with patch.object(m,'__file__',str(root/'resolver.py')):
    self.assertEqual(m.run(b,API())['status'],'M1_READONLY_RESOLVER_OBSERVED');result['candidate_table_sha256']='f'*64;failed=m.run(b,API());self.assertEqual(failed['status'],'M1_RESOLVER_FAILED');self.assertEqual(failed['actual_exec']['exit_code'],0)
if __name__=='__main__':unittest.main()
