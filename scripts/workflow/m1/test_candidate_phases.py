import importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).parent
s=importlib.util.spec_from_file_location('candidate_graph',HERE/'candidate_phases.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class CandidateGraph(unittest.TestCase):
 def test_frozen_source_fullclosure_and_actual_receipt_bindings(self):
  contract=Path('/dev/shm/sf-m1-postinstall-reusable-r2/CONTRACT.json')
  if not contract.exists():self.skipTest('private reviewed source contract absent')
  p={'device':'m1','board':'apple,j293','packet':'/var/lib/maclab/rc7-m1-cpu-candidate-new','source_packet':'/var/lib/maclab/rc7-m1-cpu-old-source','holder':'fixture'};plan={'helpers':{},'phases':[]};out=m.append(plan,p,m.pin('/usr/bin/python3'),m.pin(contract),'actual-producer','fallback-bound');self.assertEqual(len(plan['phases']),6);self.assertEqual(plan['helpers']['postinstall']['source']['sha256'],m.SOURCE);self.assertEqual(out['postinstall_pointer'],'/target');last=plan['phases'][-2];self.assertEqual(last['bind']['/inputs/original_m5_receipt/raw_base64'],{'from':'combined-actual-receipt','pointer':'/observed/raw_base64'});self.assertNotIn('candidate_uki',last['template']['inputs']);self.assertTrue(plan['phases'][-1]['mutates']);self.assertEqual(plan['phases'][-1]['timeout_sec'],1500)
 def test_source_contract_drift_refuses_before_graph_changes(self):
  contract=Path('/dev/shm/sf-m1-postinstall-reusable-r2/CONTRACT.json')
  if not contract.exists():self.skipTest('private source absent')
  pin=m.pin(contract);pin['sha256']='f'*64;plan={'helpers':{},'phases':[]}
  with self.assertRaisesRegex(RuntimeError,'contract drift'):m.append(plan,{},None,pin,'p','f')
  self.assertEqual(plan['phases'],[])
if __name__=='__main__':unittest.main()
