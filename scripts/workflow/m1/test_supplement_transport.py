import base64,datetime,hashlib,importlib.util,json,shlex,unittest
from pathlib import Path
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('supplement_transport',HERE/'supplement.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FixedContinuationTests(unittest.TestCase):
 def binding(self,op='stage'):
  r={'schema':'maclab.rc-m1-original-backup/1','status':'LOCAL_BACKUP_VERIFIED_ONLY','packet':'/var/lib/maclab/rc7-m1-cpu-fixture-supplement','boot_id':'cpu-boot','script_sha256':'67a36275efc2c188599a03ab850b02ad6f0b8b7d8b61fb0cba22b5c0339258a4'};raw=json.dumps(r).encode();source=(HERE/'backup-supplement.py').read_bytes()
  return {'operation':op,'profile':{'device':'m1','packet':r['packet'],'source_packet':'/var/lib/maclab/rc7-m1-cpu-fixture-source','holder':'cpu-owner'},'main_collection':{'receipt_base64':base64.b64encode(raw).decode(),'receipt_sha256':hashlib.sha256(raw).hexdigest(),'receipt':r,'source_freeze_sha256':'a'*64},'expected_boot_id':'cpu-boot','source_root_plan_sha256':'b'*64,'source_reviewed_by':'CPU fixture source review','supplement_source':{'path':str(HERE/'backup-supplement.py'),'sha256':hashlib.sha256(source).hexdigest(),'bytes':len(source)},'agent_parent':{'path':'/fixture/lab-agent','sha256':'e'*64,'bytes':100},'old_boot_bin':{'sha256':'c'*64,'bytes':100}}
 def fake(self,via='agent',exit_code=0):
  outer=self
  class API:
   def request(self,path,body=None,timeout=60):
    if body is None:return {'name':'m1','state':'ready','alive':True,'boot_id':'cpu-boot','kernel':'7.2.11-6-1-ARCH','lease':{'holder':'cpu-owner','expires':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
    argv=shlex.split(body['command']);outer.assertEqual(argv[:4],['/usr/bin/python3','-E','-B','-c']);compile(argv[4],'<actual-fixed-remote>','exec');payload=json.loads(argv[5]);outer.assertEqual(payload['operation'],'stage');outer.assertEqual(hashlib.sha256(base64.b64decode(payload['source_base64'],validate=True)).hexdigest(),m.SUPPLEMENT_SHA);outer.assertFalse(payload['scope']['manual_saved_work_confirmed']);outer.assertEqual(payload['scope']['main_receipt_sha256'],outer.binding()['main_collection']['receipt_sha256']);outer.assertLess(len(body['command'].encode()),120000)
    return {'exit_code':exit_code,'via':via,'stdout':'{"status":"SUPPLEMENT_INPUTS_STAGED_ONLY"}','stderr':''}
  return API()
 def test_fixed_stage_payload_uses_actual_main_hash_no_oldprofile_rewrite(self):
  out=m.run(self.binding(),self.fake());self.assertEqual(out['status'],'M1_SUPPLEMENT_STAGE_OBSERVED');self.assertEqual(out['target']['status'],'SUPPLEMENT_INPUTS_STAGED_ONLY')
 def test_wrong_raw_main_or_source_refused_before_rpc(self):
  b=self.binding();b['main_collection']['receipt_sha256']='0'*64
  with self.assertRaisesRegex(RuntimeError,'main capture binding drift'):m.run(b,object())
  b=self.binding();b['supplement_source']['sha256']='0'*64
  with self.assertRaisesRegex(RuntimeError,'source hash drift'):m.run(b,object())
 def test_serial_or_failed_result_retains_failure(self):
  for via,code in [('serial',0),('agent',2)]:
   out=m.run(self.binding(),self.fake(via,code));self.assertEqual(out['status'],'M1_SUPPLEMENT_FAILED');self.assertEqual(out['actual_exec']['via'],via)
