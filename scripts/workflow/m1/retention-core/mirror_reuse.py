#!/usr/bin/env python3
"""Reviewed-request-only retention; no installed/boot completion is reusable."""
if not __debug__:
    raise RuntimeError('optimized Python forbidden')
import sys
sys.dont_write_bytecode = True
import argparse, ast, base64, datetime, hashlib, importlib.util, json, os, re
import shlex, signal, subprocess, time, urllib.request
from pathlib import Path
import reuse_remote as rr

FROZEN = Path('/dev/shm/sf-rc-m1-reprobe-retention-source-r1/mirror-m5-ssh.py')
FROZEN_SHA = '2da24f72f7e240d9a0d0c8892df0a0095bd942995c107216960a3b834efcf9ab'
READER_SHA = '66ee32ba1561e7637eb27fe460330645c50d211280adf55167de24a2d29af71d'
NAMES = rr.NAMES
END = 0
METRICS = {'api_calls':0,'state_reads':0,'typed_read_calls':0,
           'typed_chunk_reads':0,'typed_final_full_hashes':0,
           'ssh_actions':{},'fresh_stream_bytes':0,'reused_bytes':0}

def H(data): return hashlib.sha256(data).hexdigest()
def need(v, why): rr.need(v, why)
def sha(v): return isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
def load_module(name, path, digest):
    need(H(path.read_bytes()) == digest, 'frozen source mismatch')
    sp = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
    return m

def validate(q):
    need(q['schema'] == 'maclab.retention-reuse-request/1'
         and sha(q['root_plan_sha256']), 'reviewed root plan binding required')
    s = q['source']; r = s['target_backup_receipt']
    need(s['device'] == 'm1' and re.fullmatch('/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}', s['packet'])
         and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', s['boot_id'])
         and sha(s['target_backup_receipt_sha256']), 'fresh source identity required')
    need(r['schema'] == 'maclab.rc-m1-original-backup/1'
         and r['status'] == 'LOCAL_BACKUP_VERIFIED_ONLY'
         and r['device'] == s['device'] and r['packet'] == s['packet']
         and r['boot_id'] == s['boot_id'] and r['reopen_readback'] is True,
         'fresh successful original capture required')
    need(set(r['objects']) == NAMES and set(q['objects']) == NAMES,
         'exact seven original backup objects required')
    root = Path(q['destination'])
    need(root.name == Path(s['packet']).name, 'packet namespace mismatch')
    need(sha(q['source_freeze_sha256']), 'reviewed backup source freeze required')
    total = 0
    for name, pin in r['objects'].items():
        need(sha(pin['sha256']) and type(pin['bytes']) is int
             and 0 < pin['bytes'] <= 2 * 1024**3, 'bounded object pin required')
        item = q['objects'][name]
        need(item['sha256'] == pin['sha256'] and item['bytes'] == pin['bytes'],
             'fresh manifest/object mismatch')
        rr.paths(root, name, item['allowed_retained_sources'])
        for c in item['allowed_retained_sources']:
            need(set(c) == {'path', 'sha256', 'bytes'} and sha(c['sha256'])
                 and type(c['bytes']) is int and 0 < c['bytes'] <= 2 * 1024**3,
                 'invalid explicit retained source pin')
        total += pin['bytes']
    need(total <= 3 * 1024**3, 'total retention cap')
    return s, r, root, total

def validate_supplement(q, s, root):
    x=q['supplement'];sr=x['target_receipt'];parent=x['parent_main_receipt']
    need(sha(x['target_receipt_sha256']) and sha(x['parent_main_receipt_sha256']), 'supplement/parent hash required')
    need(sr['schema']=='maclab.rc-m1-backup-supplement/1'
         and sr['status']=='LOCAL_SUPPLEMENT_VERIFIED_ONLY' and sr['device']=='m1'
         and sr['packet']==s['packet'] and sr['boot_id']==s['boot_id']
         and sr['v1_target_receipt_sha256']==s['target_backup_receipt_sha256']
         and sr['supplement_directory']==s['packet']+'/original-boot-supplement-r2'
         and sr['historical_mtime_difference_recorded'] is True
         and sr['package_mutation'] is False and sr['reboot'] is False
         and sha(sr['supplement_script_sha256']), 'fresh r2 supplement required')
    need(set(sr['objects'])==rr.SUPPLEMENT_NAMES and set(x['objects'])==rr.SUPPLEMENT_NAMES,
         'exact two supplemental backup objects required')
    need(sr['objects']['boot.bin.old.original']=={'sha256':'fc1da19d9a13b47304866ed42c52683901fd31dc7521e15e235b956b8e379e4d','bytes':9707724},'original whole .old pin mismatch')
    need(sr['objects']['boot-metadata.original.json']['bytes']<=262144
         and sum(p['bytes'] for p in s['target_backup_receipt']['objects'].values())
         +sum(p['bytes'] for p in sr['objects'].values())+524288<=3*1024**3,
         'combined retention byte cap')
    for name,pin in sr['objects'].items():
        item=x['objects'][name]
        need(sha(pin['sha256']) and type(pin['bytes']) is int and 0<pin['bytes']<=2*1024**3
             and item['sha256']==pin['sha256'] and item['bytes']==pin['bytes'], 'supplement object mismatch')
        rr.paths(root,name,item['allowed_retained_sources'])
        for c in item['allowed_retained_sources']:
            need(set(c)=={'path','sha256','bytes'} and sha(c['sha256'])
                 and type(c['bytes']) is int and 0<c['bytes']<=2*1024**3,'bad retained supplement candidate')
    need(parent['schema']=='maclab.rc-m1-independent-remote-retention/1'
         and parent['status']=='INDEPENDENT_REMOTE_RETENTION_VERIFIED'
         and parent['packet']==s['packet'] and parent['boot_id']==s['boot_id']
         and parent['root_plan_sha256']==q['root_plan_sha256']
         and parent['v1_target_receipt_sha256']==s['target_backup_receipt_sha256']
         and parent['v1_source_freeze_sha256']==q['source_freeze_sha256']
         and set(parent['groups'])=={'main'}
         and set(parent['groups']['main'])==NAMES|{'BACKUP-RECEIPT.json'}
         and parent['destination']['storage']['root']==str(root), 'fresh parent main retention mismatch')
    for phase in ('source_start','source_end'):
        need(parent[phase]['boot_id']==s['boot_id'] and parent[phase]['device']=='m1'
             and parent[phase]['kernel']=='7.2.11-6-1-ARCH' and parent[phase]['idle'] is True,
             'parent belongs to another completion/boot')
    for name,p in parent['groups']['main'].items():
        want=q['source']['target_backup_receipt']['objects'].get(name)
        if want:need(p['sha256']==want['sha256'] and p['bytes']==want['bytes'],'parent main object mismatch')
        need(p['remote_path']==str(root/'main'/name) and p['source_path']==s['packet']+'/original-backup/'+name
             and p['source_full_hash_match'] is True and p['remote_fsync_reopen_match'] is True,
             'parent object provenance mismatch')
    data=(json.dumps(parent,sort_keys=True,indent=2)+'\n').encode()
    need(H(data)==x['parent_main_receipt_sha256'], 'parent canonical raw receipt hash mismatch')
    return x,sr,parent,data

REMOTE_MAIN = r'''
def main():
 import base64,socket
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(RuntimeError('bounded remote timeout')))
 signal.alarm(1800);os.umask(0o077)
 action,root=sys.argv[1],Path(sys.argv[2])
 need(sys.platform=='darwin' and Path.home()==Path('/Users/chriskearney'),'M5 Darwin identity required')
 need(root.parent==BASE and re.fullmatch('rc7-m1-[a-z0-9-]{8,96}',root.name),'fresh reviewed root required')
 if action=='init':
  safe_directory(BASE);need(not os.path.lexists(root),'namespace already exists')
  fs=os.statvfs(BASE);need(fs.f_bavail*fs.f_frsize>=int(sys.argv[3])+128*1024**2,'M5 free-space reserve')
  root.mkdir(mode=0o700)
  for group in ['main','supplement']:(root/group).mkdir(mode=0o700)
  syncdir(root);syncdir(BASE)
  print(json.dumps({'root':str(root),'storage_dev':root.stat().st_dev,'uid':os.getuid(),'mode':stat.S_IMODE(root.stat().st_mode),'hostname':socket.gethostname(),'os':sys.platform,'controller_different_identity':True}));return
 safe_directory(root)
 if action=='observe':
  print(json.dumps({'mode':stat.S_IMODE(root.stat().st_mode),'uid':root.stat().st_uid,'storage_dev':root.stat().st_dev}));return
 rel=sys.argv[3];p=root/rel
 need(rel in ['MIRROR-RECEIPT.json','supplement/RETENTION-RECEIPT.json'] or (Path(rel).parent==Path('main') and Path(rel).name in NAMES|{'BACKUP-RECEIPT.json'}) or (Path(rel).parent==Path('supplement') and Path(rel).name in SUPPLEMENT_NAMES|{'SUPPLEMENT-RECEIPT.json'}),'explicit object name required')
 size,sha=int(sys.argv[4]),sys.argv[5]
 need(0<size<=2*1024**3 and re.fullmatch('[0-9a-f]{64}',sha),'bad object pin')
 if action=='reuse':
  candidates=json.loads(base64.b64decode(sys.argv[6],validate=True));paths(root,Path(rel).name,candidates);result=None
  for c in candidates:
   if c['sha256']!=sha or c['bytes']!=size:continue
   result=reuse(Path(c['path']),p,size,sha)
   if result is not None:break
  print(json.dumps({'reused':result is not None,'proof':result}));return
 if action=='write':result=store(p,size,sha,sys.stdin.buffer)
 elif action=='verify':result=verify(p,size,sha)
 else:raise RuntimeError('unknown action')
 print(json.dumps(result))
if __name__=='__main__':main()
'''

def api(c, path, body=None, timeout=75):
    need(time.monotonic() < END, 'controller deadline')
    METRICS['api_calls']+=1
    if path=='/api/devices/m1':METRICS['state_reads']+=1
    req = urllib.request.Request(c['url'].rstrip('/') + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization':'Bearer '+c['token'],'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=max(1,min(timeout,END-time.monotonic()))) as f:
        raw = f.read(1048577); need(len(raw) <= 1048576, 'API response cap')
    return json.loads(raw)

def state(c, s, holder, remaining):
    d = api(c, '/api/devices/m1'); lease = d.get('lease') or {}
    need(d['name']=='m1' and d['alive'] and d['state']=='ready'
         and not d.get('active_job') and not d.get('queued')
         and d['boot_id']==s['boot_id'] and d['kernel']=='7.2.11-6-1-ARCH'
         and lease.get('holder')==holder, 'fresh boot/idle/lease mismatch')
    end=datetime.datetime.fromisoformat(lease['expires'].replace('Z','+00:00'))
    need((end-datetime.datetime.now(datetime.timezone.utc)).total_seconds()>=remaining,
         'lease too short')
    return {'device':'m1','boot_id':d['boot_id'],'kernel':d['kernel'],'lease':lease,'idle':True}

def main():
    global END
    ap=argparse.ArgumentParser();ap.add_argument('--request',type=Path,required=True)
    ap.add_argument('--request-sha256',required=True);ap.add_argument('--source-holder',required=True)
    ap.add_argument('--append-supplement',action='store_true')
    a=ap.parse_args();raw=a.request.read_bytes();need(len(raw)<=262144 and H(raw)==a.request_sha256,'reviewed request hash mismatch')
    q=json.loads(raw);s,r,root,total=validate(q);began=time.monotonic();END=began+1800
    m=load_module('frozen_m5',FROZEN,FROZEN_SHA)
    reader_bytes=(FROZEN.parent/'v1-executed-source/retain-controller.py').read_bytes()
    need(H(reader_bytes)==READER_SHA,'typed reader source mismatch')
    assignments=[n for n in ast.parse(reader_bytes).body if isinstance(n,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=='REMOTE_READ' for t in n.targets)]
    need(len(assignments)==1,'typed source literal missing');typed_source=ast.literal_eval(assignments[0].value)
    # Keep frozen write/verify routines, replacing only action dispatch with the
    # explicit new namespace/reuse action. No historical transaction is invoked.
    m.REMOTE=m.REMOTE[:m.REMOTE.index('def main():')]+Path(rr.__file__).read_text()+REMOTE_MAIN
    m.ROOT=str(root);m.END=END
    original_start_ssh=m.start_ssh
    def counted_start_ssh(action,args):
        METRICS['ssh_actions'][action]=METRICS['ssh_actions'].get(action,0)+1
        return original_start_ssh(action,args)
    m.start_ssh=counted_start_ssh
    for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT): signal.signal(sig,m.cancel)
    config=json.loads((Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/'maclab/client.json').read_bytes())
    c={'url':os.environ.get('MACLAB_URL',config['url']),'token':os.environ.get('MACLAB_TOKEN',config['token'])}
    start=state(c,s,a.source_holder,1900)
    def read(path,off,n,final=False):
        METRICS['typed_read_calls']+=1
        METRICS['typed_final_full_hashes' if final else 'typed_chunk_reads']+=1
        state(c,s,a.source_holder,60)
        command=shlex.join(['/usr/bin/python3','-E','-B','-c',typed_source,path,str(off),str(n),'1' if final else '0'])
        e=api(c,'/api/devices/m1/exec',{'command':command,'timeout_sec':300 if final else 30},340 if final else 70)
        need(e['via']=='agent' and e['exit_code']==0 and not e['stderr'] and len(e['stdout'])<=1048576,'typed source read failed')
        return json.loads(e['stdout'])
    receipt_path=s['packet']+'/original-backup/BACKUP-RECEIPT.json'
    first=read(receipt_path,0,262144);blob=base64.b64decode(first['data'],validate=True)
    need(first['offset']==0 and first['length']==first['identity'][5]==len(blob)
         and H(blob)==s['target_backup_receipt_sha256'] and json.loads(blob)==r,'actual fresh receipt mismatch')
    tail=read(receipt_path,len(blob),0,True)
    need(tail['identity']==first['identity'] and tail['sha256']==H(blob),'fresh receipt changed')
    need(total+len(blob)<=3*1024**3,'main retention byte cap')
    append=None
    if a.append_supplement:
        x,sr,parent,parent_bytes=validate_supplement(q,s,root);append=(x,sr,parent)
        observed=m.control('observe',[]);storage=parent['destination']['storage']
        need(observed=={k:storage[k] for k in ('mode','uid','storage_dev')},'M5 namespace identity drift')
        par=m.control('verify',['MIRROR-RECEIPT.json',str(len(parent_bytes)),H(parent_bytes)])
        need(par['sha256']==H(parent_bytes) and par['fsync_reopen_match'],'actual parent receipt mismatch')
        for n,pin in parent['groups']['main'].items():
            actual=read(pin['source_path'],pin['bytes'],0,True)
            remote=m.control('verify',['main/'+n,str(pin['bytes']),pin['sha256']])
            need(actual['identity']==pin['source_identity'] and actual['sha256']==pin['sha256']
                 and remote['identity']==pin['remote_identity'] and remote['sha256']==pin['sha256'],
                 'fresh parent main object changed')
        srpath=s['packet']+'/original-boot-supplement-r2/SUPPLEMENT-RECEIPT.json'
        current=read(srpath,0,262144);sb=base64.b64decode(current['data'],validate=True)
        need(current['offset']==0 and current['length']==current['identity'][5]==len(sb)
             and H(sb)==x['target_receipt_sha256'] and json.loads(sb)==sr,'actual fresh supplement mismatch')
        current_end=read(srpath,len(sb),0,True)
        need(current_end['identity']==current['identity'] and current_end['sha256']==H(sb),'supplement changed')
        pins={**sr['objects'],'SUPPLEMENT-RECEIPT.json':{'sha256':H(sb),'bytes':len(sb)}}
        group='supplement';source_root=s['packet']+'/original-boot-supplement-r2/'
        object_requests=x['objects']
    else:
        storage=m.control('init',[str(total+len(blob))])
        pins={**r['objects'],'BACKUP-RECEIPT.json':{'sha256':H(blob),'bytes':len(blob)}}
        group='main';source_root=s['packet']+'/original-backup/';object_requests=q['objects']
    proofs={}
    for name,pin in pins.items():
        path=source_root+name;rel=group+'/'+name
        initial=read(path,pin['bytes'],0,True)
        need(initial['identity'][5]==pin['bytes'] and initial['sha256']==pin['sha256'],'fresh source full hash mismatch')
        reused=None
        if name in NAMES|rr.SUPPLEMENT_NAMES:
            candidates=object_requests[name]['allowed_retained_sources']
            result=m.control('reuse',[rel,str(pin['bytes']),pin['sha256'],base64.b64encode(json.dumps(candidates).encode()).decode()])
            reused=result['proof'] if result['reused'] else None
        if reused is None:
            p=m.start_ssh('write',[rel,str(pin['bytes']),pin['sha256']]);offset=0;h=hashlib.sha256()
            try:
                while offset<pin['bytes']:
                    part=read(path,offset,min(262144,pin['bytes']-offset));data=base64.b64decode(part['data'],validate=True)
                    need(part['identity']==initial['identity'] and part['offset']==offset
                         and part['length']==len(data)==min(262144,pin['bytes']-offset),'source stream drift')
                    m.send(p,data);offset+=len(data);h.update(data)
                need(h.hexdigest()==pin['sha256'],'stream hash mismatch');remote=m.finish(p)
            finally:m.stop(p)
            method={'reused_from':None,'transferred_bytes':pin['bytes'],'reuse_method':None}
        else:
            remote={'identity':reused['identity'],'sha256':reused['sha256'],'bytes':reused['bytes'],'fsync_reopen_match':True}
            method={k:reused[k] for k in ('reused_from','reused_source_identity','transferred_bytes','reuse_method')}
        need(remote['fsync_reopen_match'] and remote['sha256']==pin['sha256'] and remote['bytes']==pin['bytes'],'remote readback mismatch')
        final=read(path,pin['bytes'],0,True)
        need(final['identity']==initial['identity'] and final['sha256']==pin['sha256'],'source changed during retention')
        proofs[name]={**pin,**method,'source_path':path,'source_identity':initial['identity'],'source_full_hash_match':True,'remote_path':str(root/rel),'remote_identity':remote['identity'],'remote_fsync_reopen_match':True}
        METRICS['fresh_stream_bytes']+=method['transferred_bytes']
        if method['reused_from'] is not None:METRICS['reused_bytes']+=pin['bytes']
    for name,pin in proofs.items():
        final=read(pin['source_path'],pin['bytes'],0,True)
        actual=m.control('verify',[group+'/'+name,str(pin['bytes']),pin['sha256']])
        need(final['identity']==pin['source_identity'] and final['sha256']==pin['sha256']
             and actual['identity']==pin['remote_identity'] and actual['sha256']==pin['sha256']
             and actual['fsync_reopen_match'],'terminal source/M5 identity mismatch')
    if append is not None:
        x,sr,parent=append
        for name,pin in parent['groups']['main'].items():
            final=read(pin['source_path'],pin['bytes'],0,True)
            actual=m.control('verify',['main/'+name,str(pin['bytes']),pin['sha256']])
            need(final['identity']==pin['source_identity'] and final['sha256']==pin['sha256']
                 and actual['identity']==pin['remote_identity'] and actual['sha256']==pin['sha256']
                 and actual['fsync_reopen_match'],'terminal parent main changed')
        par=m.control('verify',['MIRROR-RECEIPT.json',str(len(parent_bytes)),H(parent_bytes)])
        need(par['sha256']==H(parent_bytes) and par['fsync_reopen_match'],'parent main receipt changed')
    end=state(c,s,a.source_holder,60)
    result={'schema':'maclab.rc-m1-independent-remote-retention/1','status':'INDEPENDENT_REMOTE_RETENTION_VERIFIED','backend':'remote-ssh-m5','device':'m1','packet':s['packet'],'boot_id':s['boot_id'],'root_plan_sha256':q['root_plan_sha256'],'reuse_request_sha256':H(raw),'v1_target_receipt_sha256':H(blob),'v1_source_freeze_sha256':q['source_freeze_sha256'],'fresh_target_receipt_sha256':H(blob),'mirror_source_sha256':H(Path(__file__).read_bytes()),'reuse_primitive_sha256':H(Path(rr.__file__).read_bytes()),'frozen_adapter_sha256':FROZEN_SHA,'typed_reader_sha256':READER_SHA,'source_start':start,'source_end':end,'destination':{'device':'m5','ssh_route':m.SSH,'storage':storage,'identity_basis':'root-verified distinct Darwin M5 known-host SSH route; no Linux machine-id claim'},'groups':{'main':proofs},'original_file_pins':r['original_file_pins'],'old_module_tree_sha256':r['old_module_tree_sha256'],'rollback_copy_pins':{**r['rollback_copy_pins'],'original-backup/BACKUP-RECEIPT.json':H(blob)},'controller_ram_transport_only':True,'controller_durable_copy_claimed':False,'cas_claimed':False,'package_mutation':False,'reboot':False,'historical_completion_reused':False}
    receipt_rel='MIRROR-RECEIPT.json'
    if append is not None:
        x,sr,parent=append
        # Parent is the actual new-generation main receipt verified above, never
        # a historical completion. Only bytes may originate from old namespaces.
        result={**parent,'groups':{'main':parent['groups']['main'],'supplement':proofs},
          'mirror_source_sha256':H(Path(__file__).read_bytes()),'source_end':end,
          'append_only':True,'actual_main_receipt_unchanged':True,
          'parent_main_remote_receipt_sha256':x['parent_main_receipt_sha256'],
          'parent_main_remote_receipt_path':str(root/'MIRROR-RECEIPT.json'),
          'main_mirror_source_sha256':parent['mirror_source_sha256'],
          'supplement_target_receipt_sha256':x['target_receipt_sha256'],
          'supplement_source_sha256':sr['supplement_script_sha256'],
          'append_destination_root_observation':observed,
          'append_request_sha256':H(raw),'historical_completion_reused':False}
        receipt_rel='supplement/RETENTION-RECEIPT.json'
    result['retention_metrics_before_final_receipt_write']={**METRICS,
      'elapsed_seconds':time.monotonic()-began,
      'scope':'this invocation only; actual call attempts, not successful replies or estimated savings; final receipt write excluded'}
    data=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode();need(len(data)<=262144,'receipt cap')
    p=m.start_ssh('write',[receipt_rel,str(len(data)),H(data)])
    try:m.send(p,data);done=m.finish(p);need(done['sha256']==H(data) and done['fsync_reopen_match'],'receipt readback failed')
    finally:m.stop(p)
    print(json.dumps({'status':result['status'],'receipt_path':str(root/receipt_rel),'receipt_sha256':H(data),'receipt_bytes':len(data),'transferred_bytes':sum(x['transferred_bytes'] for x in proofs.values()),'reused_objects':[n for n,x in proofs.items() if x['reused_from']],'historical_completion_reused':False,
      'retention_metrics':{**METRICS,'elapsed_seconds':time.monotonic()-began,
        'scope':'this invocation only; SSH call attempts and elapsed include final receipt write; stream/reused bytes count object payload only, excluding receipt payload and protocol overhead; typed-read attempts count before state guard'}}))

if __name__=='__main__':main()
