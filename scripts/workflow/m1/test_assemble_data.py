import copy,hashlib,importlib.util,json,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('projection',Path(__file__).with_name('assemble_data.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
P='/var/lib/maclab/rc7-m1-cpu-projection-test';PLAN='a'*64
class Projection(unittest.TestCase):
 def base(self,op):return {'operation':op,'profile':{'device':'m1','board':'apple,j293','packet':P},'root_plan_sha256':PLAN}
 def receipt(self):return {'status':'ACTUAL_ORIGINAL6_SESSION_AND_ROLLBACK_VERIFIED','normal6_rollback_verified_by_root':True,'schema':'maclab.m1-original-session-proof/1','packet':P,'device':'m1','boot_id':'actual-original-boot','kernel':m.OLD,'root_plan_sha256':PLAN,'no_gpu_workload_after_original_restore':True}
 def test_actual_unsorted_owner_dump_survives_go_map_reordering(self):
  actual=self.receipt();raw=json.dumps(actual,separators=(',',':'));go=json.loads(json.dumps(actual,sort_keys=True));q=self.base('final-return-evidence');q['session']={'status':'ORIGINAL_SESSION_TARGET_OBSERVED','target':go,'actual_exec':{'via':'agent','exit_code':0,'stderr':'','stdout':raw}};r=m.run(q);self.assertEqual(r['normal_proof_sha256'],hashlib.sha256((json.dumps(actual,indent=2)+'\n').encode()).hexdigest());self.assertNotEqual(r['normal_proof_sha256'],hashlib.sha256((json.dumps(go,indent=2)+'\n').encode()).hexdigest());self.assertFalse(r['completion_claim'])
  for k,v in [('via','serial'),('exit_code',1),('stderr','warning'),('stdout','{}')]:
   bad=copy.deepcopy(q);bad['session']['actual_exec'][k]=v
   with self.assertRaises(RuntimeError):m.run(bad)
 def test_session_binding_actual_manifest_hash_boot_and_scope(self):
  manifest={'device':'m1','board':'apple,j293','expected_kernel':m.NEW,'expected_boot_id':'boot7','token':'1'*64,'approved':True,'source_review':'accepted-by-root','wifi_interface':'wlan0','wifi_mac':'00:11:22:33:44:55'};audit={'packet':P,'root_plan_sha256':PLAN,'operation':'inventory','expected_boot_id':'boot7','expected_kernel':m.NEW,'metadata_observation':None};q={**self.base('session-binding'),'audit_binding':audit,'manifest':manifest,'manifest_sha256':hashlib.sha256((json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()).hexdigest(),'session_operation':'capture-normal7-proof','reviewed_by':'CPU ONLY'};r=m.run(q);self.assertEqual(r['binding']['normal7']['manifest_path'],P+'/normal-smoke-'+'1'*16+'.json');self.assertFalse(r['binding']['root_scope']['manual_saved_work_confirmed'])
  for field,value in [('manifest_sha256','b'*64),('session_operation','arbitrary')]:
   bad=copy.deepcopy(q);bad[field]=value
   with self.assertRaises(RuntimeError):m.run(bad)
  bad=copy.deepcopy(q);bad['audit_binding']['expected_kernel']=m.OLD
  with self.assertRaises(RuntimeError):m.run(bad)
 def test_genuine_b9c_clean_list_allows_final_session_dictionary_does_not(self):
  manifest={'device':'m1','board':'apple,j293','expected_kernel':m.NEW,'expected_boot_id':'boot7','token':'1'*64,'approved':True,'source_review':'accepted-by-root','wifi_interface':'wlan0','wifi_mac':'00:11:22:33:44:55'};audit={'packet':P,'root_plan_sha256':PLAN,'operation':'inventory','expected_boot_id':'boot6','expected_kernel':m.OLD,'metadata_observation':None};actual={'packet':P,'root_plan_sha256':PLAN,'boot_id':'boot6','kernel':m.OLD,'status':'ORIGINAL_ROLLBACK_INVENTORY_ONLY','state_diffs':[],'response_binding':{'schema':'maclab.m1-normal-response-binding/1','packet':P,'boot_id':'boot6','kernel':m.OLD,'root_plan_sha256':PLAN,'action':'original-inventory','entry':'inventory'}};q={**self.base('session-binding'),'audit_binding':audit,'manifest':manifest,'manifest_sha256':hashlib.sha256((json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()).hexdigest(),'session_operation':'verify-original-session','reviewed_by':'CPU ONLY','actual_old_audit':actual,'capture':{'packet':P,'root_plan_sha256':PLAN,'boot_id':'boot7','kernel':m.NEW,'status':'ACTUAL_CURRENT_NORMAL7_PROOF_CAPTURED','no_new_workload':True,'sha256':'b'*64}};r=m.run(q);self.assertEqual(r['binding']['old_payload_observation_sha256'],hashlib.sha256((json.dumps({k:v for k,v in actual.items() if k!='response_binding'},sort_keys=True,indent=2)+'\n').encode()).hexdigest())
  for tag in (None,{**actual['response_binding'],'entry':'wrong'},{**actual['response_binding'],'boot_id':'old'}):
   bad=copy.deepcopy(q);bad['actual_old_audit']['response_binding']=tag
   with self.assertRaises(RuntimeError):m.run(bad)
  for rows in ({},[{'path':'/boot/efi/limine.conf','difference':'mtime'}]):
   bad=copy.deepcopy(q);bad['actual_old_audit']['state_diffs']=rows
   with self.assertRaises(RuntimeError):m.run(bad)
 def test_marker_projection_keeps_authentic_stdout_not_placeholder(self):
  raw='{"old_base_sha256":"proof","exact_owned_marker":true}';q={**self.base('marker-context'),'observed':{'boot_id':'boot7','source_sha256':'c'*64,'actual_exec':{'stdout':raw},'target':{'status':'OWNER_EXIT_ONLY_REQUIRES_INDEPENDENT_RECEIPT_VALIDATION'}},'invocation':{'entry':'verify-modules','profile':{'packet':P},'expected_boot_id':'boot7','expected_kernel':m.NEW,'root_scope':{'root_plan_sha256':PLAN}},'owned_marker_receipt_sha256':'d'*64};r=m.run(q);self.assertEqual(r['actual_exec']['stdout'],raw);self.assertNotIn('target',r)
if __name__=='__main__':unittest.main()
