#!/usr/bin/env python3
"""Typed reviewed-profile artifact intake and compiled-runner entrypoint.
Inspection/compilation are local; --execute explicitly enables reviewed API work.
A profile is never executable merely because its catalog entry exists.
"""
import argparse,hashlib,importlib.util,json,os,stat,subprocess,sys,time
from pathlib import Path
import catalog,util as u
HERE=Path(__file__).resolve().parent
def pin(p):
 p=Path(p);raw=p.read_bytes();return {'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
def write(p,x):
 raw=(json.dumps(x,indent=2,sort_keys=True)+'\n').encode();catalog.need(len(raw)<=catalog.LIMIT,'bounded local output');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:catalog.need(os.write(fd,raw)==len(raw),'output short write');os.fsync(fd)
 finally:os.close(fd)
 d=os.open(Path(p).parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);r=pin(p);catalog.need(catalog.read_pin(r)==raw,'output readback mismatch');return r

def replace(p,x):
 p=Path(p);tmp=p.with_name(p.name+'.new');pin=write(tmp,x);os.replace(tmp,p);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);return {**pin,'path':str(p)}

def diagnostic_log(path):
 p=Path(path);meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(meta);catalog.need(stat.S_ISREG(a.st_mode) and a.st_uid==os.geteuid() and not a.st_mode&0o077 and 0<=a.st_size<=8*1024**2,'private bounded diagnostic file');fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:raw=os.read(fd,a.st_size+1);identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns);catalog.need(len(raw)==a.st_size and identity(os.fstat(fd))==identity(a)==identity(p.lstat()),'diagnostic log drift')
  finally:os.close(fd)
  return {'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},raw
 finally:os.close(meta)

def metadata(profile,request,review,out):
 slots=catalog.request_slots(request,profile);helper=review['metadata_helper'];catalog.read_pin(helper);python=review['python'];catalog.read_pin(python,64*1024**2);reports={}
 for name,p in slots.items():
  expected=profile['candidate']['artifact_slots'][name];slot=out/('slot-'+name+'.json');sp=write(slot,expected);argv=[python['path'],'-E','-B',helper['path'],'--artifact',p['path'],'--slot-file',str(slot),'--slot-file-sha256',sp['sha256']];stem='metadata-'+name
  try:record=u.process(argv,out,stem,50)
  except BaseException as e:
   try:write(out/('metadata-process-'+name+'.json'),{'status':'METADATA_PROCESS_INCOMPLETE','error_type':type(e).__name__,'automatic_retry':False,'private_stdout':str(out/(stem+'.stdout')),'private_stderr':str(out/(stem+'.stderr'))})
   except Exception:pass
   raise
  stdout_pin,stdout=diagnostic_log(out/(stem+'.stdout'));stderr_pin,stderr=diagnostic_log(out/(stem+'.stderr'))
  record.update(stdout=stdout_pin,stderr=stderr_pin,automatic_retry=False);write(out/('metadata-process-'+name+'.json'),record);catalog.need(record['exit_code']==0 and not record['stop_reason'],'artifact metadata refused: '+name);catalog.need(len(stdout)<=512*1024 and len(stderr)<=65536,'metadata helper output bound');doc=catalog.unique(stdout);catalog.need(doc['sha256']==expected['sha256'] and doc['bytes']==expected['bytes'] and doc['kind']==expected['kind'] and doc['runtime_execution_proved'] is False,'metadata result identity differs');reports[name]=doc
 return slots,reports

def associations(p,reports):
 manifest=p['candidate'].get('build_identity')
 if manifest is None:return {'image_config_build_association':'not-proved-by-intake','provider_runtime_proved':False,'loader_runtime_proved':False}
 b=catalog.unique(catalog.read_pin(manifest));catalog.need(b['kernel_release']==p['candidate']['kernel'] and len(b['source_commit'])==40 and all(x in '0123456789abcdef' for x in b['source_commit']),'reviewed build manifest kernel/source differs');found={}
 for result in reports.values():
  for path,row in result.get('payload',{}).items():
   if row['role'] in ('arm64-image','kernel-config'):catalog.need(row['role'] not in found,'ambiguous Image/config association');found[row['role']]=row['sha256']
 catalog.need(found.get('arm64-image')==b['image_sha256'] and found.get('kernel-config')==b['config_sha256'],'reviewed build association differs from actual archive bytes');return {'image_config_build_association':'exact-reviewed-build-manifest','build_manifest_sha256':manifest['sha256'],'source_commit':b['source_commit'],'provider_runtime_proved':False,'loader_runtime_proved':False}

def compile_selected(p,request,review,slots,reports,packet,out):
 catalog.need(p['execution_ready'] is True,'UNSUPPORTED_PROFILE_PENDING_ADAPTER: source intake only');catalog.runtime_contract(p);c=p['compiler'];catalog.need(review['compiler']==c['source'],'reviewed compiler profile mismatch');approved={}
 role_sources=[pin for role in p['sources'].values() for pin in [role['source'],*role['closure']]]
 for descriptor in [c['source'],*c['closure'],*role_sources,*review['source_files']]:catalog.read_pin(descriptor,64*1024**2);catalog.need(descriptor['path'] not in approved or approved[descriptor['path']]==descriptor,'conflicting source descriptor');approved[descriptor['path']]=descriptor
 recipe=catalog.unique(catalog.read_pin(review['recipe']));recipe['holder']=review['holder'];recipe['source_reviewed_by']=review['reviewed_by'];recipe['device_profile']=p;recipe['reviewed_artifact_inputs']=slots;recipe['reviewed_artifact_metadata']=reports
 if c['call']=='compile_oneshot':
  # Legacy owner assertions are fixed to one reviewed package cohort. A new tuple
  # cannot silently inherit it; only a data-bound compile_device adapter may do so.
  old=catalog.unique(catalog.read_pin(recipe['transaction_spec']));rows={v['name']:v for v in old['candidate_packages']};packages={n:a for n,a in p['candidate']['artifact_slots'].items() if a['kind']=='arch-package'};catalog.need(set(rows)==set(packages) and all(rows[n]['sha256']==a['sha256'] and rows[n]['bytes']==a['bytes'] and rows[n]['version']==a['version'] for n,a in packages.items()) and len(packages)==len(slots),'UNSUPPORTED_ARTIFACT_TUPLE_FOR_FIXED_ADAPTER')
 raw=catalog.read_pin(c['source']);module=type(sys)('reviewed_device_compiler');module.__file__=c['source']['path'];exec(compile(raw,module.__file__,'exec'),module.__dict__);function=getattr(module,c['call']);result=function(recipe,packet,str(out/'compiled'),request['recovery_mode']);plan=catalog.unique(catalog.read_pin(result['plan']))
 if c['call']=='compile_oneshot':plan['inputs']['restoration_contract']=p['restore']
 catalog.validate_plan(plan,p,packet,request['recovery_mode'],approved)
 plan['inputs']['root_profile_reviewer']=review['reviewed_by']
 for field in ('root_emit_package_clearance','root_emit_packet_c_clearance'):
  if field in plan['inputs']:plan['inputs'][field]=True
 phases=[]
 for index,(name,artifact) in enumerate(sorted(slots.items())):
  id='intake-%02d'%index;phases += [{'id':id+'-cache','kind':'cache','timeout_sec':120,'mutates':False,'file':artifact},{'id':id+'-upload','kind':'upload','timeout_sec':300,'mutates':False,'input_phase':id+'-cache'}]
 catalog.need(len(phases)+len(plan['phases'])<=256,'intake/adapter phase ceiling');plan['phases']=phases+plan['phases'];plan['inputs']['catalog_profile_sha256']=review['profile']['sha256'];plan['inputs']['profile_source_review_sha256']=review['_descriptor_sha256'];plan['inputs']['source_artifact_intake']={n:{k:v[k] for k in ('sha256','bytes')} for n,v in slots.items()};target=Path(result['plan']['path']);pp=replace(target,plan);return {'plan':pp,'phase_count':len(plan['phases']),'original_kernel':p['original']['kernel'],'package_presence_policy':p['original'],'restoration_contract':p['restore'],'adapter_call':c['call'],'ordinary_gpu_or_loader_qualification_claimed':False}

def run(catalog_pin,profile_id,request,review_pin,out,packet=None,compile_plan=False):
 start=time.monotonic();p,pp=catalog.load(catalog_pin,profile_id,request['device'],False);catalog.need(request['recovery_mode'] in p['recovery_modes'],'explicit supported recovery mode');review=catalog.unique(catalog.read_pin(review_pin));review['_descriptor_sha256']=review_pin['sha256'];catalog.need(review['schema']=='maclab.boot-test-profile-source-review/1' and review['status']=='ROOT_SOURCE_REVIEWED' and review['catalog']==catalog_pin and review['profile']==pp and review['device']==p['device'] and review['reviewed_by'],'exact source-reviewed profile/catalog mapping');request=catalog.normalize_request(request,p);out=Path(out);out.mkdir(mode=0o700,parents=False,exist_ok=False);slots,reports=metadata(p,request,review,out);result={'schema':'maclab.boot-test-profile-intake/1','device':p['device'],'profile_id':profile_id,'profile':pp,'catalog':catalog_pin,'review':review_pin,'packet':packet,'recovery_mode':request['recovery_mode'],'artifact_pins':slots,'metadata':reports,'associations':associations(p,reports),'execution_ready':p['execution_ready'],'target_actions':False,'api_calls':False,'hardware_qualification':False}
 if compile_plan:
  catalog.need(packet and Path(packet).name.startswith('rc7-'+p['device']+'-') and Path(packet).parent==Path('/var/lib/maclab'),'finite matching new device packet');result['compiled']=compile_selected(p,request,review,slots,reports,packet,out)
 result['seconds']=time.monotonic()-start;write(out/'INTAKE.json',result);return result
def local_json(path):
 p=Path(path).absolute();fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  import stat
  s=os.fstat(fd);catalog.need(stat.S_ISREG(s.st_mode) and s.st_uid in (0,os.geteuid()) and not s.st_mode&0o022 and 0<s.st_size<=catalog.LIMIT,'bounded owned input JSON');raw=os.read(fd,s.st_size+1);identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns);catalog.need(len(raw)==s.st_size and identity(os.fstat(fd))==identity(s)==identity(p.lstat()),'input JSON changed');return catalog.unique(raw)
 finally:os.close(fd)
if __name__=='__main__':
 if len(sys.argv)>1 and sys.argv[1]=='profile-bundle':
  import profile_bundle
  profile_bundle.main(sys.argv[2:]);raise SystemExit(0)
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--catalog-descriptor');a.add_argument('--profile');a.add_argument('--request');a.add_argument('--device');a.add_argument('--recovery-mode',choices=('network-only','serial-assisted'));a.add_argument('--kernel');a.add_argument('--kernel-headers');a.add_argument('--bootloader');a.add_argument('--mesa-package',action='append',default=[]);a.add_argument('--artifact',action='append',default=[]);a.add_argument('--review-descriptor');a.add_argument('--out');a.add_argument('--packet');a.add_argument('--compile',action='store_true');a.add_argument('--prepared');a.add_argument('--execute',action='store_true');a.add_argument('--authorization');a.add_argument('--state');x=a.parse_args()
 try:
  if x.prepared:
   catalog.need(x.execute and x.authorization,'explicit execute and plan-bound authorization required');import runtime
   bundle=local_json(Path(x.prepared)/'INTAKE.json');state=x.state or str(Path.home()/'.local/share/maclab/workflows'/Path(bundle['packet']).name);result=runtime.execute(x.prepared,x.authorization,state)
  else:
   catalog.need(x.catalog_descriptor and x.profile and x.review_descriptor and x.out,'exact catalog/profile/source review/output required');request=local_json(x.request) if x.request else {'schema':'maclab.boot-test-request/2'}
   for name in ('device','recovery_mode','kernel','kernel_headers','bootloader'):
    value=getattr(x,name)
    if value is not None:catalog.need(name not in request or request[name]==value,'request/CLI identity mismatch');request[name]=value
   for values,key in ((x.mesa_package,'mesa_packages'),(x.artifact,'artifacts')):
    for pair in values:
     catalog.need('=' in pair,'named artifact requires name=path');name,path=pair.split('=',1);request.setdefault(key,{});catalog.need(name not in request[key],'duplicate named artifact');request[key][name]=path
   result=run(local_json(x.catalog_descriptor),x.profile,request,local_json(x.review_descriptor),x.out,x.packet,x.compile or x.execute)
   if x.execute:
    catalog.need(x.authorization,'existing plan-bound authorization required; prepared data retained');import runtime
    state=x.state or str(Path.home()/'.local/share/maclab/workflows'/Path(x.packet).name);result=runtime.execute(x.out,x.authorization,state)
  print(json.dumps(result,separators=(',',':')))
  if x.execute:raise SystemExit(0 if result['status']=='PASSED_RESTORED_LEASE_RELEASED' else 1)
 except Exception as e:
  print('profile-intake: '+(str(e) if isinstance(e,catalog.Refused) else type(e).__name__),file=sys.stderr)
  if getattr(e,'private_failure_output',None):print('private failure output: '+e.private_failure_output,file=sys.stderr)
  raise SystemExit(2)
