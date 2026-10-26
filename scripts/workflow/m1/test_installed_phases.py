import importlib.util,json,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('installed_graph',HERE/'installed_phases.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Fragments(unittest.TestCase):
 def test_real_same_cohort_namespace_prefix_precedes_first_target_mutation(self):
  root=Path('/home/chrisk/.local/share/maclab/frozen/rc7-m1-cohort-reprobe-20261026-r1');source=Path('/dev/shm/sf-rc-m1-reprobe-execution-root')
  if not root.exists():self.skipTest('private source fixture absent')
  c=m.load('compile');p={'device':'m1','packet':'/var/lib/maclab/rc7-m1-cpu-namespace-new','holder':'cpu-fixture'};r={'source_manifest':c.pin(source/'manifest.json'),'payload':c.pin(source/'linux-aurora.files.sha256'),'frozen_root':str(root.parent),'source_release':root.name,'source_baseline_job':'j1025-191846-9ec6','source_pins':c.pin(root/'PINS.preinstall'),'preinstall_pins':{n:c.pin(root/'preinstall/m1'/n) for n in ('baseline-job.json','dmesg-errors.txt','omt-report.json','omt-status.json')}};plan={'inputs':{'root_profile_reviewer':None},'helpers':{},'phases':[{'id':'preflight-binding'},{'id':'preflight'},{'id':'first-target-mutation'}]}
  with tempfile.TemporaryDirectory(dir='/dev/shm') as t:
   e=m.namespace(plan,p,r,c.pin('/usr/bin/python3'),Path(t)/'expectation');names=[x['id'] for x in plan['phases']];self.assertLess(names.index('namespace-manifest'),names.index('first-target-mutation'));self.assertEqual(e['changed_fields'],['release']);self.assertEqual(e['release'],Path(p['packet']).name);self.assertIsNone(plan['inputs']['root_profile_reviewer']);self.assertFalse(e['reference_changes']);self.assertEqual(len(plan['phases']),11)
 def test_job_is_exact_unchanged_three_builtins_and_has_separate_return_guard(self):
  p={'device':'m1','packet':'/var/lib/maclab/rc7-m1-cpu-namespace-new','holder':'cpu-fixture'};plan={'phases':[]};e={'manifest':{'sha256':'a'*64}};o=m.job(plan,p,e,'actual-native-postinstall','/target');job=next(x for x in plan['phases'] if x['id']=='installed-job-binding')['template'];self.assertEqual([x['builtin'] for x in job['tests']],['boot-health','gui-smoke','omarchy-m-test']);self.assertEqual(job['tests'][2]['timeout_sec'],900);self.assertEqual(set(job),{'device','holder','installed_manifest','tests'});self.assertEqual(o['job_return'],'job-return');self.assertEqual(plan['phases'][-1]['checks'][0]['equals'],'ACTUAL_INSTALLED_JOB_AND_NORMAL6_RETURN_OBSERVED')
if __name__=='__main__':unittest.main()
