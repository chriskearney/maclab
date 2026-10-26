#!/usr/bin/env python3
"""Finite fresh-P readonly ALPM resolution without a final-spec dependency.
Normal package dependencies/signatures stay enabled. No install/boot action.
"""
import argparse,base64,ctypes,hashlib,json,os,re,shlex,sys,types,zlib
from pathlib import Path
ESP='ae0e01c7f6a2c2c84ec9944cee255f814b5788c6045b48ec1f4f1a76907d06df'
SDK='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
TYPED='8b50af1dfa8da0e01056f7e3f523fb87365b5757e2fc4e55f63fffc62a3d857f'
LEDGER='c831b5563600290cb850fde2c29bc4b60b7c71b881239df5bb9c73544ee9507c'
ROWS=[{'name': 'linux-aurora', 'file': 'linux-aurora-7.2.11.aurora7-1-aarch64.pkg.tar.zst', 'sha256': 'e798ed200ef313c581fe9f0d408fb1cf9cce1721347d2b094b0b08825421a86c', 'bytes': 47454979, 'version': '7.2.11.aurora7-1'}, {'name': 'linux-aurora-headers', 'file': 'linux-aurora-headers-7.2.11.aurora7-1-aarch64.pkg.tar.zst', 'sha256': '7d7763afd761d7edfc6f1a390ae3a5523908908ebb5a7516b1669f732a6e8c1a', 'bytes': 32459028, 'version': '7.2.11.aurora7-1'}, {'name': 'mesa-aurora', 'file': 'mesa-aurora-1:26.3.0_devel.20261025.231095.7c86130d26c-1-aarch64.pkg.tar.zst', 'sha256': '7dc3e016b4edf218eefd19ff4cd358ee9a4f78b2b9282815637c687e185ce8bb', 'bytes': 6518521, 'version': '1:26.3.0_devel.20261025.231095.7c86130d26c-1'}, {'name': 'vulkan-aurora', 'file': 'vulkan-aurora-1:26.3.0_devel.20261025.231095.7c86130d26c-1-aarch64.pkg.tar.zst', 'sha256': '38750b65df6db38e3f7b83b0236424cfe9d1573929ca0442865cc55564f3c252', 'bytes': 4218878, 'version': '1:26.3.0_devel.20261025.231095.7c86130d26c-1'}, {'name': 'omarchy-mac-boot', 'file': 'omarchy-mac-boot-20261026-1-aarch64.pkg.tar.zst', 'sha256': 'b87ce2f882e1e6039a49fdd37d77e03335a4fc19518075937fc99eb8d1191274', 'bytes': 92970, 'version': '20261026-1'}]
PROOFS='d31a8fed9533b161a8ddfdbd0b7c41e7638b461a43eee3c26c01cd3981bececd'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(raw):return hashlib.sha256(raw).hexdigest()
def module(raw,name,path):
 m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def guard():
 # Reuse the already reviewed metadata-first exact-source loader.
 p=Path(__file__).with_name('proofs.py');meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  import stat
  st=os.fstat(meta);need(stat.S_ISREG(st.st_mode) and st.st_size<=65536,'bounded proof loader');fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:raw=os.pread(fd,st.st_size+1,0);need(len(raw)==st.st_size and H(raw)==PROOFS,'reviewed proof loader changed')
  finally:os.close(fd)
 finally:os.close(meta)
 return module(raw,'resolver_loader',p).load()
libc=ctypes.CDLL(None);libc.fnmatch.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int];libc.fnmatch.restype=ctypes.c_int
def affected(path,patterns):
 effect=False
 for raw in patterns:
  negate=raw.startswith('!');pattern=raw[1:] if negate else raw
  if libc.fnmatch(pattern.encode(),path.encode(),0)==0:effect=not negate
 return effect

def resolve(P,typed,execute,observations):
 _,ledger_sha,ledger_raw=typed.read_regular(P/'candidate-files.jsonl',16777216,True);need(ledger_sha==LEDGER,'exact candidate payload ledger');records=[json.loads(x) for x in ledger_raw.splitlines()];wanted={x['name'] for x in ROWS};paths=[x['path'] for x in records if x['package'] in wanted and x['type']!='d'];directives={}
 def command(argv,timeout):
  r=execute(argv,timeout);observations.append({'argv':argv,'actual':r});need(r['exit_code']==0 and len(r['stdout'])<=65536 and len(r['stderr'])<=65536,'normal readonly ALPM query refused; actual output retained');return r['stdout']
 for name in ('HookDir','NoUpgrade','NoExtract'):directives[name]=[line for line in command(['/usr/bin/pacman-conf',name],20).splitlines() if line]
 need(directives['HookDir']==['/etc/pacman.d/hooks/'],'new configured HookDir requires source review')
 impacts={key:[path for path in paths if affected(path,directives[key])] for key in ('NoUpgrade','NoExtract')};need(not any(impacts.values()),'NoUpgrade/NoExtract affects exact candidate payload; never bypass owner policy')
 files=[]
 for row in ROWS:
  p=P/'packages'/row['file'];st,h,_=typed.read_regular(p,64*1024**2);need(h==row['sha256'] and st.st_size==row['bytes'],'staged exact archive mismatch');files.append(str(p))
 argv=['/usr/bin/pacman','-U','--noconfirm','--print','--print-format','%n|%v|%l','--',*files];parsed=[line.split('|') for line in command(argv,90).splitlines() if line];expected=[[row['name'],row['version'],str(P/'packages'/row['file'])] for row in ROWS];need(sorted(parsed)==sorted(expected),'resolved targets drift/additional dependency; no install')
 for row in ROWS:
  st,h,_=typed.read_regular(P/'packages'/row['file'],64*1024**2);need(h==row['sha256'] and st.st_size==row['bytes'],'staged archive changed during normal resolution')
 return {'status':'READ_ONLY_EXACT_FIVE_RESOLVED','candidate_table_sha256':H(json.dumps(ROWS,sort_keys=True,separators=(',',':')).encode()),'candidate_ledger_sha256':LEDGER,'argv':argv,'resolved':parsed,'NoUpgrade_NoExtract':{k:directives[k] for k in ('NoUpgrade','NoExtract')},'HookDir':directives['HookDir'],'candidate_paths_affected':impacts,'install':False,'boot':False,'scope':'normal dependency/signature admission, not full file-conflict/hooks/runtime qualification'}

def validate(b):
 p=b['profile'];need(b['schema']=='maclab.m1-resolver-binding/1' and p['device']=='m1' and p['board']=='apple,j293' and p['holder'],'finite normal M1 resolver');pattern='/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}';need(re.fullmatch(pattern,p['packet']) and re.fullmatch(pattern,p['source_packet']) and p['packet']!=p['source_packet'] and re.fullmatch('[0-9a-f]{64}',b['root_plan_sha256']) and re.fullmatch('[0-9a-f]{64}',b['packet_profile_sha256']),'fresh packet/Plan/profile');return p

def target(b):
 p=validate(b);need(H(_ESP_SOURCE)==ESP,'reviewed guard');e=module(_ESP_SOURCE,'resolver_guard','esp.py');P=Path(p['packet']);need(os.geteuid()==0 and os.uname().machine=='aarch64','native root resolver');e.direct_agent_parent(p['agent_parent']);e.private(P)
 def live():need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==b['expected_boot_id'] and os.uname().release=='7.2.11-6-1-ARCH' and Path('/proc/device-tree/compatible').read_bytes().split(b'\0')[0]==b'apple,j293' and b'maclab.job=' not in Path('/proc/cmdline').read_bytes() and not os.path.lexists('/var/lib/pacman/db.lck'),'normal idle original6 resolver identity')
 live();raw,_=e.regular(P/'CACHE-PROFILE.json',65536);need(json.loads(raw)=={'profile_sha256':b['packet_profile_sha256'],'source_packet':p['source_packet']},'owned fresh packet marker');source,_=e.pin(P/'verify-package-files.py',TYPED,65536);typed=module(source,'resolver_typed',P/'verify-package-files.py');observations=[]
 try:result=resolve(P,typed,e.bounded_command,observations);live()
 except Exception as exc:result={'status':'READ_ONLY_RESOLUTION_REFUSED','error_type':type(exc).__name__,'error':str(exc),'install':False,'boot':False}
 return {'schema':'maclab.m1-resolver-observation/1','status':result['status'],'packet':str(P),'boot_id':b['expected_boot_id'],'kernel':'7.2.11-6-1-ARCH','root_plan_sha256':b['root_plan_sha256'],'result':result,'commands':observations,'target_mutations':False}

def run(b,client=None):
 p=validate(b);e,eraw=guard();here=Path(__file__).parent;sraw,_=e.pin(here/'frozen-controller-ea3.py',SDK,65536,False);s=module(sraw,'resolver_sdk',here/'frozen-controller-ea3.py');c=client or s.API(s.config());d=c.request('/api/devices/m1');s.state_gate(d,p,{'expected_boot_id':b['expected_boot_id'],'expected_kernel':'7.2.11-6-1-ARCH'},True,390);source,_=e.regular(__file__,65536,False);command=shlex.join(['/usr/bin/python3','-E','-B','-c','import base64,zlib\n_ESP_SOURCE=zlib.decompress(base64.b64decode('+repr(base64.b64encode(zlib.compress(eraw)).decode())+'))\n'+source.decode(),'--request-json',json.dumps(b,separators=(',',':'))]);need(len(command.encode())<=120000,'fixed resolver command ceiling');r=c.request('/api/devices/m1/exec',{'command':command,'timeout_sec':300},390)
 try:
  need(r['via']=='agent' and r['exit_code']==0 and not r['stderr'],'resolver RPC exit/transport/stderr');o=json.loads(r['stdout']);need(o['schema']=='maclab.m1-resolver-observation/1' and o['status']=='READ_ONLY_EXACT_FIVE_RESOLVED' and o['packet']==p['packet'] and o['boot_id']==b['expected_boot_id'] and o['root_plan_sha256']==b['root_plan_sha256'] and o['kernel']=='7.2.11-6-1-ARCH' and o['target_mutations'] is False,'actual resolver response refused/mismatched')
  result=o['result'];expected=[[row['name'],row['version'],str(Path(p['packet'])/'packages'/row['file'])] for row in ROWS];need(result['status']=='READ_ONLY_EXACT_FIVE_RESOLVED' and result['candidate_ledger_sha256']==LEDGER and result['candidate_table_sha256']==H(json.dumps(ROWS,sort_keys=True,separators=(',',':')).encode()) and result['install'] is False and result['boot'] is False and sorted(result['resolved'])==sorted(expected) and result['HookDir']==['/etc/pacman.d/hooks/'] and result['candidate_paths_affected']=={'NoUpgrade':[],'NoExtract':[]},'actual resolver candidate/policy result mismatch')
 except Exception as exc:return {'status':'M1_RESOLVER_FAILED','actual_exec':r,'completion_claim':False,'response_error':type(exc).__name__+': '+str(exc)}
 return {'status':'M1_READONLY_RESOLVER_OBSERVED','packet':p['packet'],'boot_id':b['expected_boot_id'],'root_plan_sha256':b['root_plan_sha256'],'actual_exec':r,'target':o,'source_sha256':H(source),'completion_claim':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();g=a.add_mutually_exclusive_group(required=True);g.add_argument('--binding',type=Path);g.add_argument('--request-json');x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())) if x.binding else target(json.loads(x.request_json)),separators=(',',':')))
