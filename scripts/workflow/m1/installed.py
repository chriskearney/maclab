#!/usr/bin/env python3
"""Fixed M1 installed namespace/API adapter; never promotes a reference.
Copies genuine preinstall comparison bytes unchanged into a fresh write-once
namespace; this is reuse of a historical comparison, never a fresh baseline.
"""
import argparse,base64,hashlib,json,os,re,stat
from pathlib import Path
SDK_SHA='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
AUTH='162bea41d6318294489e5eb889f937751a4ba4e5ff6298c19a3efc011cbf2365'
LEAVES={'baseline-job.json','dmesg-errors.txt','omt-report.json','omt-status.json'}
KERNEL='7.2.11-7-1-ARCH'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def raw(j):return (json.dumps(j,indent=2)+'\n').encode()
def sdk():
 import sys
 p=Path(__file__).with_name('frozen-controller-ea3.py');b=p.read_bytes();need(H(b)==SDK_SHA,'accepted transport source changed');m=type(sys)('installed_transport');exec(compile(b,str(p),'exec'),m.__dict__);return m
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def checked_dir(p):
 for d in [p,*p.parents]:
  s=d.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.geteuid()) and not s.st_mode&0o022,'unsafe frozen store ancestry')
def put(p,b):
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(b)
  while view:n=os.write(fd,view);need(n>0,'short frozen write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 need(sdk().read_pin({'path':str(p),'sha256':H(b),'bytes':len(b)})==b,'frozen output readback mismatch');syncdir(p.parent)
def common(b):
 p=b['profile'];need(p['device']=='m1' and p['packet'].startswith('/var/lib/maclab/rc7-m1-'),'reviewed M1 transaction only');release=Path(p['packet']).name
 need(re.fullmatch('rc7-m1-[a-z0-9-]{8,96}',release) and b.get('source_reviewed_by'),'fresh reviewed namespace required');return p,release
def prepare_expectation(b):
 p,release=common(b);c=sdk();m=json.loads(c.read_pin(b['source_manifest']));payload=c.read_pin(b['payload'])
 need(m['schema']=='maclab.installed-manifest/2' and m['kernel']['release']==KERNEL and m['kernel']['vmlinuz_sha256']=='95b73368323e7886450369746d123cd24ab6c156704ecb2f7824eee22ee82e25','exact reviewed candidate Image required')
 need(H(payload)==m['kernel']['payload_manifest_sha256'] and m['macs']['m1']['board']=='apple,j293','candidate payload/model mismatch')
 need(m['release']!=release,'fresh namespace must differ from source');old=m['release'];m['release']=release
 # All archive/mtree/Image/m1n1/DTB pins remain byte-for-byte equivalent data.
 manifest=raw(m);out=Path.cwd()/'fresh-installed-manifest.json';pay=Path.cwd()/'fresh-installed-payload.sha256';put(out,manifest);put(pay,payload)
 return {'status':'FRESH_EXPECTATION_PREPARED_LOCAL_ONLY','packet':p['packet'],'release':release,'manifest':{'path':str(out),'sha256':H(manifest),'bytes':len(manifest)},'payload':{'path':str(pay),'sha256':H(payload),'bytes':len(payload)},'manifest_value':m,'source_release':old,'changed_fields':['release'],'new_baseline_claim':False,'reference_changes':False}
def freeze_preinstall(b):
 p,release=common(b);c=sdk();scope=b['root_scope'];need(scope['root_plan_sha256']==b['root_plan_sha256'] and re.fullmatch('[0-9a-f]{64}',b['root_plan_sha256']) and scope['packet']==p['packet'] and scope['operation']=='freeze-preinstall' and scope['authority_sha256']==AUTH and scope['reviewed_by'],'scope/standing authority required')
 base=Path(b['frozen_root']);need(base.is_absolute() and str(base)==str(base.resolve(strict=True)),'actual canonical frozen store required');checked_dir(base)
 source_release=b['source_release'];need(re.fullmatch('[a-zA-Z0-9_.-]+',source_release) and source_release!=release,'distinct original source namespace required');src=base/source_release;checked_dir(src)
 pins=b['preinstall_pins'];need(set(pins)==LEAVES and Path(b['source_pins']['path'])==src/'PINS.preinstall','exact original preinstall closure required');pinraw=c.read_pin(b['source_pins']);declared={}
 for line in pinraw.decode().splitlines():
  if not line or line.startswith('#'):continue
  h,rel=line.split(None,1);need(re.fullmatch('[0-9a-f]{64}',h) and rel not in declared,'invalid/duplicate original baseline pin');declared[rel]=h
 need(set(declared)=={'preinstall/m1/'+x for x in LEAVES},'unreviewed preinstall namespace shape')
 files={}
 for name,pin in pins.items():
  need(Path(pin['path'])==src/'preinstall/m1'/name and declared['preinstall/m1/'+name]==pin['sha256'],'original baseline path/hash mismatch');files[name]=c.read_pin(pin)
 baseline=json.loads(files['baseline-job.json']);need(baseline.get('id')==b['source_baseline_job'] and baseline['spec']['device']=='m1','actual original baseline job mismatch')
 dest=base/release;need(not os.path.lexists(dest),'fresh frozen namespace already exists; reconcile, never overwrite');dest.mkdir(mode=0o700);syncdir(base);(dest/'preinstall').mkdir(mode=0o700);(dest/'preinstall/m1').mkdir(mode=0o700);syncdir(dest/'preinstall');syncdir(dest)
 intent={'schema':'maclab.preinstall-byte-reuse/1','packet':p['packet'],'root_plan_sha256':b['root_plan_sha256'],'source_release':source_release,'source_baseline_job':b['source_baseline_job'],'source_pins_sha256':H(pinraw),'files':{n:{'sha256':H(v),'bytes':len(v)} for n,v in files.items()},'fresh_baseline_claim':False,'reference_changes':False,'source_reviewed_by':b['source_reviewed_by']}
 put(dest/'PREINSTALL-REUSE-INTENT.json',raw(intent))
 for name,data in sorted(files.items()):put(dest/'preinstall/m1'/name,data)
 # Publish exactly the old declaration last. The server still independently
 # pin-checks every comparison file. No baseline/report/status is synthesized.
 put(dest/'PINS.preinstall',pinraw);put(dest/'PREINSTALL-REUSE-COMPLETE.json',raw(intent))
 return {'status':'GENUINE_PREINSTALL_BYTES_FROZEN','packet':p['packet'],'release':release,'source_release':source_release,'source_baseline_job':b['source_baseline_job'],'preinstall_pins_sha256':H(pinraw),'retained_files':intent['files'],'new_baseline_claim':False,'reference_changes':False}
def api_action(b,client=None):
 p,release=common(b);c=sdk();action=b['action'];need(action in ('freeze-manifest','freeze-entry'),'finite supported installed API only');scope=b['root_scope'];need(scope['packet']==p['packet'] and scope['operation']==action and scope['root_plan_sha256']==b['root_plan_sha256'] and re.fullmatch('[0-9a-f]{64}',b['root_plan_sha256']) and scope['authority_sha256']==AUTH and scope['reviewed_by'],'scoped reviewed operation required')
 api=client or c.API(c.config());d=api.request('/api/devices/m1');c.state_gate(d,p,{'expected_boot_id':b['expected_boot_id'],'expected_kernel':'7.2.11-6-1-ARCH'},True,510);need('maclab.job=' not in d.get('cmdline',''),'ordinary baseline required')
 if action=='freeze-manifest':
  e=b['expectation'];need(e['status']=='FRESH_EXPECTATION_PREPARED_LOCAL_ONLY' and e['packet']==p['packet'] and e['release']==release,'fresh expectation binding required')
  for key in ('manifest','payload'):need(b[key+'_artifact']==e[key]['sha256'],'uploaded exact expectation artifact required')
  result=api.request('/api/installed/'+release+'/manifest',{'manifest':b['manifest_artifact'],'payload':b['payload_artifact'],'approved_by':[scope['reviewed_by']]},420)
  need(result['release']==release and result['manifest_sha256']==e['manifest']['sha256'],'server frozen expectation identity mismatch')
 else:
  observed=b['postinstall'];need(observed['packet']==p['packet'] and observed['installed_manifest_sha256']==b['installed_manifest_sha256'],'actual accepted candidate observation required');need(observed['candidate_uki']['bytes']<=64413696,'candidate output ceiling')
  result=api.request('/api/installed/'+release+'/entry/m1',{},420);entry=result['entry'];need(result['device']=='m1' and result['release']==release and entry['schema']=='maclab.installer-entry/1' and entry['device']=='m1' and entry['release']==release and entry['captured_boot_id']==b['expected_boot_id'],'actual fresh installer entry capture required')
  need(entry['uki_sha256']==observed['candidate_uki']['sha256'] and entry['uki_sections']['.linux']['sha256']=='95b73368323e7886450369746d123cd24ab6c156704ecb2f7824eee22ee82e25' and entry['uki_sections']['.uname']['text']==KERNEL,'server installer entry differs from reviewed candidate')
  need(entry['limine_conf_sha256']==observed['menus']['temp6_sha256'] and entry['protocol']=='efi' and 'maclab.job=' not in entry['cmdline'],'frozen menu/ordinary entry drift')
 return {'status':'SUPPORTED_INSTALLED_'+action.upper().replace('-','_')+'_OBSERVED','packet':p['packet'],'release':release,'actual_api_response':result,'installed_manifest_sha256':b.get('installed_manifest_sha256',b.get('expectation',{}).get('manifest',{}).get('sha256')),'reference_changes':False,'boot_test_pass':False}
def observe_return(b,client=None):
 p,release=common(b);c=sdk();api=client or c.API(c.config());expected=b['job_result'];jobid=expected['id'];need(re.fullmatch('j[0-9-]+[a-f0-9]*',jobid),'actual job id required')
 actual=api.request('/api/jobs/'+jobid);need(actual['id']==jobid and actual['spec']==expected['spec'] and actual['result']==expected['result'] and actual['state']=='done' and actual['outcome']=='pass' and not actual.get('canceled'),'actual retained successful job mismatch')
 spec=actual['spec'];need(spec['device']=='m1' and spec['holder']==p['holder'] and spec['installed_manifest']==b['installed_manifest_sha256'] and not any(spec.get(k) for k in ('kernel','source','build','baseline','publish','omt_allow','mesa')),'exact unwaived installed job required')
 tests=spec['tests'];need(len(tests)==3 and [(t['name'],t.get('builtin'),bool(t.get('gui'))) for t in tests]==[('boot-health','boot-health',False),('gui-smoke','gui-smoke',True),('omarchy-m-test','omarchy-m-test',True)] and tests[2]['timeout_sec']==900 and not any(t.get('script') for t in tests),'unchanged three builtins required')
 result=actual['result'];ir=result['installed'];need(result['booted'] is True and result['boot_kernel']==KERNEL and not result.get('fell_back') and not result.get('recovery') and ir['release']==release and ir['manifest_sha256']==b['installed_manifest_sha256'] and ir['installer_entry_sha256']==b['installer_entry_sha256'],'candidate job/installer mismatch')
 need(ir['verdicts']=={'before':'MATCH','booted':'MATCH','after':'MATCH'} and ir['omt']=='NO_REGRESSION' and ir['dmesg']=='NONE_NEW' and not ir.get('kernel_log_fatal'),'actual identity/regression verdicts required')
 d=api.request('/api/devices/m1');c.state_gate(d,p,{'expected_boot_id':d['boot_id'],'expected_kernel':'7.2.11-6-1-ARCH'},True,900);need(d['boot_id']!=b['prejob_boot_id'] and 'maclab.job=' not in d.get('cmdline',''),'genuine changed-UUID ordinary old6 return required')
 return {'status':'ACTUAL_INSTALLED_JOB_AND_NORMAL6_RETURN_OBSERVED','packet':p['packet'],'job':jobid,'boot_id':d['boot_id'],'kernel':d['kernel'],'cmdline':d['cmdline'],'ready_idle':True,'installed_manifest_sha256':b['installed_manifest_sha256'],'installer_entry_sha256':b['installer_entry_sha256'],'actual_device':d,'actual_job_result_sha256':H(raw(actual)),'reference_changes':False}
def run(b,client=None):
 action=b['action']
 if action=='observe-job-return':return observe_return(b,client)
 if action=='prepare-expectation':return prepare_expectation(b)
 if action=='freeze-preinstall':return freeze_preinstall(b)
 return api_action(b,client)
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())),separators=(',',':')))
