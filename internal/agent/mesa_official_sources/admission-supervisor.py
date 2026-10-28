#!/usr/bin/env python3
"""Root-reviewed target supervisor for two frozen tiny GPU correctness controls.

Source preparation only until root allocates m1 and explicitly executes it.
No controller API, package install, boot, service or reference mutations. Raw
journal/child logs stay in a root-only owned tree. This is not a benchmark run.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import sys
import subprocess
import tarfile
import time
sys.dont_write_bytecode=True

COMMIT='e81d80938876c906b64c4e3f31f76c6c33ba95b1'
ARCHIVE_SHA='f209493b34e13e2985b1752c147a33a9a45e3e2eac99eb9606ae5a664c252f99'
ARCHIVE_BYTES=372821
HELPER_SHA='059ccbce35f2154bc4c62984bddcbb1c4dabd6ad8e4d580482233412f52a8af0'
SOURCE_SHA='bc615d52a927d0b26e20e31bf699176c19e127c5cfcfb5e5b52f2d648a13677b'
KERNEL='7.2.11-6-1-ARCH'
SMOKE_SHA='2c5361c369584545d2165c68b180b418278094563d219b0aeeea774c3bc1ee2d'
LOG_CAP=4*1024**2
REPORT_CAP=4*1024**2
LINE_CAP=128*1024
WALL_SECONDS=140
HASH=re.compile(r'[0-9a-f]{64}\Z')
FAULTS={'gpu':re.compile(r'(?:asahi|agx|borealis|honeykrisp|drm).*(?:fault|timed? ?out|timeout|hang|reset|error|failed)',re.I),
        'dart':re.compile(r'(?:apple-dart|\bdart\b).*(?:fault|error|invalid|timeout)',re.I),
        'oom':re.compile(r'Out of memory:|oom-kill:|Killed process \d+',re.I),
        'kernel':re.compile(r'WARNING:|KASAN:|BUG:|Oops:|Kernel panic|use.after.free|soft lockup|blocked for more than|RCU.*stall',re.I)}

class Stop(RuntimeError):pass

def need(value,reason):
    if not value:raise Stop(reason)

def sha(path):
    with open(path,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def private_write(path,data):
    if not isinstance(data,bytes):data=(json.dumps(data,indent=2,sort_keys=True)+'\n').encode()
    need(len(data)<=REPORT_CAP,'receipt-budget')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    need(Path(path).read_bytes()==data,'receipt-readback')

def capture(command,limit=LOG_CAP,timeout=10):
    """Bounded finite read-only commands; never shell/capture_output unbounded."""
    proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},start_new_session=True)
    selector=selectors.DefaultSelector();buffers={};started=time.monotonic()
    try:
        for stream in (proc.stdout,proc.stderr):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ);buffers[stream]=bytearray()
        while selector.get_map() or proc.poll() is None:
            need(time.monotonic()-started<timeout,'metadata-command-timeout')
            for key,_ in selector.select(0.05):
                data=os.read(key.fd,16384)
                if not data:selector.unregister(key.fileobj);continue
                buffers[key.fileobj].extend(data);need(len(buffers[key.fileobj])<=limit,'metadata-command-budget')
        need(proc.wait(timeout=1)==0,'metadata-command-failed')
        need(not buffers[proc.stderr],'metadata-command-stderr')
        return bytes(buffers[proc.stdout])
    finally:kill_group(proc);selector.close()

def group_members(pgid):
    paths=list(Path('/proc').iterdir());need(len(paths)<=8192,'process-inventory-budget')
    result=[]
    for path in paths:
        if not path.name.isdecimal():continue
        try:
            fields=(path/'stat').read_text().rsplit(')',1)[1].split()
            if int(fields[2])==pgid and fields[0]!='Z':result.append((int(path.name),fields[19]))
        except (OSError,IndexError,ValueError):continue
    return result

def kill_group(proc):
    if proc is None:return
    try:os.killpg(proc.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:proc.wait(timeout=2)
    except subprocess.TimeoutExpired:pass
    try:os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    try:proc.wait(timeout=3)
    except subprocess.TimeoutExpired:raise Stop('owned-leader-still-running') from None
    deadline=time.monotonic()+2
    while group_members(proc.pid):
        need(time.monotonic()<deadline,'owned-descendant-still-running');time.sleep(0.02)

def file_pin(path):
    p=Path(path);s=p.stat();need(stat.S_ISREG(s.st_mode),'protected-file-type')
    return {'sha256':sha(p),'bytes':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,
            'link_sha256':hashlib.sha256(os.readlink(p).encode()).hexdigest() if p.is_symlink() else None}

def tree_pin(path):
    """Hash only explicit reviewed roots; links are recorded, never followed."""
    p=Path(path);need(p.is_dir() and not p.is_symlink(),'protected-tree-type')
    records={};total=0
    for f in sorted(p.rglob('*')):
        need(len(records)<20000,'protected-tree-file-budget');s=f.lstat();name=str(f.relative_to(p))
        item={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
        if stat.S_ISLNK(s.st_mode):item['link_sha256']=hashlib.sha256(os.readlink(f).encode()).hexdigest()
        elif stat.S_ISREG(s.st_mode):
            total+=s.st_size;need(total<=8*1024**3,'protected-tree-byte-budget');item.update(bytes=s.st_size,sha256=sha(f))
        else:need(stat.S_ISDIR(s.st_mode),'protected-tree-special-file')
        records[name]=item
    data=json.dumps(records,sort_keys=True,separators=(',',':')).encode()
    return {'sha256':hashlib.sha256(data).hexdigest(),'entries':len(records),'bytes':total}

def private_state(paths,secret):
    """Never return/log key bytes, names, hashes or directory contents."""
    state={};total=0;count=0
    for root in paths:
        p=Path(root);entries=[p,*sorted(p.rglob('*'))] if p.exists() and p.is_dir() else [p]
        for f in entries:
            count+=1;need(count<=1024,'normal-state-file-budget')
            if not f.exists() and not f.is_symlink():state[str(f)]=None;continue
            s=f.lstat();item=[stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid]
            if stat.S_ISLNK(s.st_mode):item.append(hmac.new(secret,os.readlink(f).encode(),'sha256').digest())
            elif stat.S_ISREG(s.st_mode):
                total+=s.st_size;need(total<=8*1024**2,'normal-state-byte-budget')
                with f.open('rb') as source:
                    h=hmac.new(secret,digestmod='sha256')
                    for block in iter(lambda:source.read(1024**2),b''):h.update(block)
                item.extend([s.st_size,h.digest()])
            else:need(stat.S_ISDIR(s.st_mode),'normal-state-special-file')
            state[str(f)]=item
    return state

def validate_plan(p):
    required={'schema_version','prefix','gui_uid','gui_gid','boot_id','config_sha256','cmdline_sha256','pacman_q_sha256',
              'files','trees','normal_state_paths','installed_tester_root','installed_tester_entrypoint',
              'implementation_sha256','loader_sha256','provider_ownership_sha256','render_node','render_node_pin','known_good','accepted_reference_receipt_sha256','allocation'}
    need(isinstance(p,dict) and set(p)==required,'plan-keys')
    need(type(p['schema_version']) is int and p['schema_version']==1,'plan-version')
    need(re.fullmatch(r'/var/tmp/sf-official-gpu-smoke-[0-9a-f]{16}',p['prefix']),'owned-prefix-format')
    need(type(p['gui_uid']) is int and p['gui_uid']>0 and type(p['gui_gid']) is int and p['gui_gid']>0,'gui-identity')
    need(re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',p['boot_id']),'boot-id-pin')
    for key in ('config_sha256','cmdline_sha256','pacman_q_sha256','implementation_sha256','loader_sha256','provider_ownership_sha256','accepted_reference_receipt_sha256'):
        need(isinstance(p[key],str) and HASH.fullmatch(p[key]),'missing-reviewed-pin')
    need(p['allocation']=={'device':'m1','holder':'official-gpu-mbp-63a085f4','scope':'tiny-smoke-only','maintenance_fence':'closed'},'allocation-scope')
    need(isinstance(p['known_good'],dict) and set(p['known_good'])=={'path','field','expected'},'known-good-spec')
    need(p['known_good']['path'] in ('/etc/maclab/agent.json','/var/lib/maclab/agent.json','/var/lib/maclab/known-good.json') and p['known_good']['field'] in ('known_good','knownGood','kernel') and p['known_good']['expected']==KERNEL,'known-good-pin')
    need(isinstance(p['files'],dict) and 5<=len(p['files'])<=128,'file-pins')
    mandatory={'/boot/efi/limine.conf','/boot/efi/m1n1/boot.bin','/usr/lib/libvulkan_asahi.so','/usr/lib/libvulkan.so.1',p['known_good']['path'],p['installed_tester_entrypoint']}
    need(mandatory<=set(p['files']),'missing-protected-file')
    need(any(n.startswith('/boot/efi/') and n.endswith('.efi') for n in p['files']),'missing-uki-pins')
    for name,pin in p['files'].items():
        need(name.startswith('/') and '..' not in Path(name).parts,'protected-file-path')
        allowed=name.startswith('/boot/') or name in ('/usr/lib/libvulkan_asahi.so','/usr/lib/libvulkan.so.1','/etc/default/limine','/etc/default/update-m1n1','/etc/m1n1.conf','/var/lib/maclab/known-good.json.prev',p['known_good']['path'],p['installed_tester_entrypoint'])
        need(allowed,'unreviewed-protected-path')
        need(set(pin)=={'sha256','bytes','mode','uid','gid','link_sha256'} and HASH.fullmatch(pin['sha256']),'file-pin-fields')
        need(all(type(pin[k]) is int and pin[k]>=0 for k in ('bytes','mode','uid','gid')),'file-pin-types')
        need(pin['link_sha256'] is None or HASH.fullmatch(pin['link_sha256']),'link-pin')
    need(p['files']['/usr/lib/libvulkan_asahi.so']['sha256']==p['implementation_sha256'] and p['files']['/usr/lib/libvulkan.so.1']['sha256']==p['loader_sha256'],'provider-file-pin')
    need(isinstance(p['trees'],dict) and 2<=len(p['trees'])<=12,'tree-pins')
    need('/usr/lib/modules/'+KERNEL in p['trees'] and p['installed_tester_root'] in p['trees'],'missing-module-or-tester-tree')
    for name,pin in p['trees'].items():
        need((name.startswith('/usr/lib/modules/') or name==p['installed_tester_root']) and '..' not in Path(name).parts and set(pin)=={'sha256','entries','bytes'} and HASH.fullmatch(pin['sha256']),'tree-pin-fields')
    need(re.fullmatch(r'/dev/dri/renderD[0-9]+',p['render_node']) and isinstance(p['render_node_pin'],dict) and set(p['render_node_pin'])=={'major','minor','mode','uid','gid'},'drm-node-pin')
    need(all(type(v) is int and v>=0 for v in p['render_node_pin'].values()),'drm-node-pin-types')
    need(isinstance(p['normal_state_paths'],list) and 1<=len(p['normal_state_paths'])<=4,'normal-state-spec')
    return p

def protected_state(p):
    need(os.uname().machine=='aarch64' and os.uname().release==KERNEL,'target-kernel-or-architecture')
    need(b'apple,j293\0' in Path('/proc/device-tree/compatible').read_bytes(),'target-board')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot_id'],'target-boot-drift')
    config=gzip.decompress(Path('/proc/config.gz').read_bytes());need(len(config)<4*1024**2,'kernel-config-budget')
    need(hashlib.sha256(config).hexdigest()==p['config_sha256'] and sha('/proc/cmdline')==p['cmdline_sha256'],'running-kernel-pin')
    need(hashlib.sha256(capture(['pacman','-Q'],limit=1024**2)).hexdigest()==p['pacman_q_sha256'],'package-set-drift')
    need(hashlib.sha256(capture(['pacman','-Qo','/usr/lib/libvulkan_asahi.so','/usr/lib/libvulkan.so.1'],limit=16384)).hexdigest()==p['provider_ownership_sha256'],'provider-package-owner-drift')
    node=Path(p['render_node']).stat();need(stat.S_ISCHR(node.st_mode),'drm-node-type')
    need({'major':os.major(node.st_rdev),'minor':os.minor(node.st_rdev),'mode':stat.S_IMODE(node.st_mode),'uid':node.st_uid,'gid':node.st_gid}==p['render_node_pin'],'drm-node-drift')
    account=pwd.getpwuid(p['gui_uid']);need(account.pw_gid==p['gui_gid'],'gui-account-drift')
    home=Path(account.pw_dir);need(home.is_dir() and str(home).startswith('/home/'),'gui-home')
    need(str(home/'.local/state/omarchy-m-test') in p['normal_state_paths'],'normal-state-missing')
    need(all(Path(n).is_relative_to(home) and '..' not in Path(n).parts for n in p['normal_state_paths']),'normal-state-outside-home')
    need(Path(p['installed_tester_root']).is_relative_to(home) and Path(p['installed_tester_entrypoint']).is_relative_to(home),'installed-tester-path')
    current={name:file_pin(name) for name in p['files']};need(current==p['files'],'protected-file-drift')
    trees={name:tree_pin(name) for name in p['trees']};need(trees==p['trees'],'protected-tree-drift')
    discovered={str(f) for base,pattern in (('/boot/efi/EFI','*.efi'),('/boot/efi/maclab','*.efi'),('/boot/efi/m1n1','boot.bin*'),('/boot','vmlinuz*'),('/boot','Image*'),('/boot/efi','Image*')) for f in Path(base).rglob(pattern) if f.is_file()}
    need(discovered<=set(p['files']),'unfrozen-boot-file')
    module_roots={str(x) for x in Path('/usr/lib/modules').iterdir() if x.is_dir() and not x.is_symlink()}
    need(module_roots<=set(p['trees']),'unfrozen-module-tree')
    raw=json.loads(Path(p['known_good']['path']).read_text());need(raw.get(p['known_good']['field'])==KERNEL,'agent-known-good-drift')
    return {'boot_matches':True,'kernel_config_matches':True,'package_set_matches':True,'files_match':True,'trees_match':True,'agent_known_good_matches':True}

def inspect_archive(archive):
    source=Path(archive);need(source.is_file() and not source.is_symlink() and source.stat().st_size==ARCHIVE_BYTES,'archive-size-or-type')
    data=source.read_bytes();need(len(data)==ARCHIVE_BYTES and hashlib.sha256(data).hexdigest()==ARCHIVE_SHA,'archive-pin')
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
        members=t.getmembers();regular=[m for m in members if m.isfile()];need(len(regular)==67,'archive-file-count')
        for m in members:
            need((m.name.startswith('omarchy-m-test/') or (m.isdir() and m.name=='omarchy-m-test')) and '..' not in Path(m.name).parts and not Path(m.name).is_absolute(),'archive-path')
            need(m.isdir() or m.isfile(),'archive-link-or-special')
            need(m.mode in (0o644,0o755),'archive-permissions')
        need(len({m.name for m in members})==len(members),'archive-duplicate')
        helper=t.extractfile('omarchy-m-test/omarchy_m_test/gpu_native/bin/gpu-benchmark-vulkan').read()
        need(hashlib.sha256(helper).hexdigest()==HELPER_SHA,'archive-helper-pin')
    return data

def stage(p,archive,smoke,smoke_sha):
    need(smoke_sha==SMOKE_SHA and sha(smoke)==smoke_sha,'smoke-source-pin')
    data=inspect_archive(archive);prefix=Path(p['prefix']);need(not prefix.exists() and not prefix.is_symlink(),'prefix-preexists')
    prefix.mkdir(mode=0o755);os.chown(prefix,0,0);os.chmod(prefix,0o755);owned=prefix/'root';owned.mkdir(mode=0o700);os.chown(owned,0,0);os.chmod(owned,0o700)
    private_write(owned/'owner.json',{'prefix':str(prefix),'scope':'tiny-smoke-only','source_commit':COMMIT})
    payload=prefix/'payload';payload.mkdir(mode=0o755);os.chown(payload,0,0);os.chmod(payload,0o755)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
        for m in t.getmembers():
            target=payload/m.name
            if m.isdir():target.mkdir(mode=0o755,parents=True,exist_ok=True)
            else:
                target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
                with t.extractfile(m) as source,target.open('xb') as dest:shutil.copyfileobj(source,dest);dest.flush();os.fsync(dest.fileno())
                os.chmod(target,m.mode);need(sha(target)==hashlib.sha256(t.extractfile(m).read()).hexdigest(),'payload-readback')
    for member in [payload,*payload.rglob('*')]:
        os.chown(member,0,0)
        if member.is_dir():os.chmod(member,0o755)
    target=prefix/'smoke.py';shutil.copyfile(smoke,target);os.chown(target,0,0);os.chmod(target,0o644);need(sha(target)==smoke_sha,'smoke-readback')
    run=prefix/'run';run.mkdir(mode=0o700);os.chmod(run,0o700);os.chown(run,p['gui_uid'],p['gui_gid'])
    for name in ('home','tmp','state','cache','config','data','reports'):
        path=run/name;path.mkdir(mode=0o700);os.chmod(path,0o700);os.chown(path,p['gui_uid'],p['gui_gid'])
    return prefix,payload/'omarchy-m-test'

def verify_staged(archive_bytes,payload):
    expected={}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes),mode='r:gz') as t:
        for m in t.getmembers():
            if m.isfile():expected[m.name]={'sha256':hashlib.sha256(t.extractfile(m).read()).hexdigest(),'mode':m.mode}
    actual={}
    for f in (payload.parent).rglob('*'):
        need(not f.is_symlink(),'staged-payload-link')
        st=f.stat();need(st.st_uid==0 and st.st_gid==0,'staged-payload-owner')
        if f.is_file():actual[str(f.relative_to(payload.parent))]={'sha256':sha(f),'mode':stat.S_IMODE(st.st_mode)}
        else:need(f.is_dir() and stat.S_IMODE(st.st_mode)==0o755,'staged-payload-directory')
    need(actual==expected,'staged-payload-drift')

def cursor():
    data=capture(['journalctl','-k','-b','-n','1','-o','json','--show-cursor','--no-pager'])
    records=[]
    for line in data.splitlines():
        if line.startswith(b'{'):records.append(json.loads(line))
    need(records and isinstance(records[-1].get('__CURSOR'),str),'journal-cursor-unavailable')
    value=records[-1]['__CURSOR'];need(1<=len(value)<=4096 and '\n' not in value and '\x00' not in value,'journal-cursor-invalid')
    return value

class Journal:
    def __init__(self,boot):self.boot=boot.replace('-','');self.pending=bytearray();self.categories=set();self.records=0
    def consume(self,data):
        self.pending.extend(data);need(len(self.pending)<=LOG_CAP,'journal-pending-budget')
        while b'\n' in self.pending:
            line,_,rest=self.pending.partition(b'\n');self.pending=bytearray(rest)
            need(len(line)<=LINE_CAP,'journal-line-budget')
            if not line:continue
            try:record=json.loads(line)
            except ValueError:raise Stop('journal-invalid-json') from None
            need(record.get('_BOOT_ID')==self.boot,'journal-boot-drift')
            message=record.get('MESSAGE','')
            if isinstance(message,list):
                need(len(message)<=LINE_CAP and all(type(x) is int and 0<=x<256 for x in message),'journal-message-type');message=bytes(message).decode(errors='replace')
            need(isinstance(message,str),'journal-message-type');self.records+=1
            self.categories.update(name for name,pattern in FAULTS.items() if pattern.search(message))
            need(not self.categories,'new-kernel-fault')

def health_snapshot(payload):
    # Import only pure stdlib host-operation definitions; no Vulkan library/API.
    import importlib.util
    path=payload/'omarchy_m_test/gpu_native/launcher.py';spec=importlib.util.spec_from_file_location('frozen_gpu_health',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    value=module.snapshot();need(module.guard(value) is None,'health-guard');return value

def start_gate(payload):
    h=health_snapshot(payload);need(h.get('temperatures_mc') and max(h['temperatures_mc'])<=60000,'start-temperature');return h

def inspect_helpers(p,payload,members,seen):
    expected=(payload/'omarchy_m_test/gpu_native/bin/gpu-benchmark-vulkan').resolve()
    provider_paths={'implementation':Path('/usr/lib/libvulkan_asahi.so').resolve(),'loader':Path('/usr/lib/libvulkan.so.1').resolve()}
    for pid,birth in members:
        proc=Path('/proc')/str(pid)
        try:
            if (proc/'exe').resolve()!=expected:continue
            args=(proc/'cmdline').read_bytes().rstrip(b'\0').split(b'\0');decoded=[a.decode() for a in args]
            allowed=([str(expected),'--workload','submit-single','--negative-control'],[str(expected),'--workload','bo-lifetime'])
            need(decoded in allowed,'unexpected-native-workload')
            need(proc.stat().st_uid==p['gui_uid'] and sha(proc/'exe')==HELPER_SHA,'native-helper-identity')
            key=(pid,birth);entry=seen.setdefault(key,{'workload':decoded[2],'negative':len(decoded)==4,'roles':set(),'render_node_observed':False})
            for fd in list((proc/'fd').iterdir())[:256]:
                try:
                    st=fd.stat()
                    if stat.S_ISCHR(st.st_mode) and (os.major(st.st_rdev),os.minor(st.st_rdev))==(p['render_node_pin']['major'],p['render_node_pin']['minor']):entry['render_node_observed']=True
                except FileNotFoundError:continue
            for line in (proc/'maps').read_text().splitlines():
                name=line.split()[-1]
                if not name.startswith('/'):continue
                path=Path(name).resolve()
                for role,frozen in provider_paths.items():
                    if path==frozen:
                        need(sha(path)==p[role+'_sha256'],'mapped-provider-drift');entry['roles'].add(role)
        except FileNotFoundError:continue
    need(len(seen)<=2,'unexpected-extra-helper')

def supervise(p,payload,command,logs,health_fn=health_snapshot,journal_cursor=None):
    """One bounded child PGID plus one owned privileged cursor-follow PGID."""
    selector=selectors.DefaultSelector();process=None;watch=None;streams={};sizes={};journal=Journal(p['boot_id']);seen={};started=time.monotonic();samples=[]
    try:
        watch=subprocess.Popen(['journalctl','-k','-b','--after-cursor='+journal_cursor,'-f','-o','json','--no-pager','--all'],
                               stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                               env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                                 env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        for name,stream in (('journal.jsonl',watch.stdout),('journal.stderr',watch.stderr),('child.stdout',process.stdout),('child.stderr',process.stderr)):
            out=open(logs/name,'xb');os.chmod(logs/name,0o600);streams[name]=out;sizes[name]=0
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        next_health=0
        while process.poll() is None:
            now=time.monotonic();need(now-started<WALL_SECONDS,'outer-smoke-timeout');need(watch.poll() is None,'journal-monitor-exited')
            if now>=next_health:
                h=health_fn(payload);samples.append(h);need(len(samples)<=600,'health-sample-budget')
                need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot_id'],'unexpected-reboot')
                inspect_helpers(p,payload,group_members(process.pid),seen);next_health=now+0.1
                report=Path(p['prefix'])/'run/reports/first-smoke.json'
                if report.exists():need(report.stat().st_size<=REPORT_CAP,'smoke-report-budget')
            for key,_ in selector.select(0.02):
                data=os.read(key.fd,16384)
                if not data:selector.unregister(key.fileobj);continue
                name=key.data;sizes[name]+=len(data);need(sizes[name]<=LOG_CAP,'private-log-budget');streams[name].write(data)
                if name=='journal.jsonl':journal.consume(data)
                elif name=='journal.stderr':raise Stop('journal-monitor-stderr')
        need(process.wait(timeout=1)==0,'smoke-child-failed')
        # Mandatory complete after-cursor rescan closes the last-read/exit race;
        # unlike rolling counts, every new record since the authentic cursor is checked.
        final=capture(['journalctl','-k','-b','--after-cursor='+journal_cursor,'-o','json','--no-pager','--all'],limit=LOG_CAP,timeout=10)
        final_journal=Journal(p['boot_id']);final_journal.consume(final);need(not final_journal.pending,'journal-truncated-final')
        private_write(logs/'journal-final.jsonl',final)
        need(len(seen)==2,'native-helper-observation-incomplete')
        ordered=list(seen.values());need([(x['workload'],x['negative']) for x in ordered]==[('submit-single',True),('bo-lifetime',False)],'native-helper-order')
        need(all(x['roles']=={'loader','implementation'} and x['render_node_observed'] for x in ordered),'native-provider-observation-incomplete')
        return {'child_exit':0,'journal_new_records':final_journal.records,'new_fault_categories':[],
                'helpers':[{'workload':x['workload'],'negative':x['negative'],'loader_observed':True,'implementation_observed':True,'render_node_observed':True} for x in ordered],
                'health_samples':samples,'elapsed_ms':int((time.monotonic()-started)*1000)}
    finally:
        progress={'elapsed_ms':int((time.monotonic()-started)*1000),'journal_records_seen':journal.records,'fault_categories':sorted(journal.categories),'helpers':[{'workload':x['workload'],'negative':x['negative'],'roles':sorted(x['roles']),'render_node_observed':x['render_node_observed']} for x in seen.values()]}
        try:kill_group(process)
        finally:
            kill_group(watch);selector.close()
            for out in streams.values():out.flush();os.fsync(out.fileno());out.close()
            private_write(logs/'observer-progress.json',progress)

def smoke_result(path,p,payload):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=REPORT_CAP,'smoke-result-file')
    value=json.loads(path.read_text());need(value.get('status')=='pass' and value.get('source_commit')==COMMIT,'smoke-result-status')
    controls=value.get('controls');need(isinstance(controls,list) and len(controls)==2,'smoke-control-count')
    sys.path.insert(0,str(payload))
    from omarchy_m_test import gpu_benchmark as gpu
    clean=[]
    for run,workload,negative,operations,queries in zip(controls,('submit-single','bo-lifetime'),(True,False),(1,32),(1,32)):
        need(run.get('status')=='pass' and run.get('workload')==workload and run.get('negative') is negative,'smoke-control-kind')
        need(run.get('reason')==('negative-control-detected' if negative else 'completed'),'smoke-control-reason')
        identity=run.get('identity',{});need(run.get('helper_sha256')==HELPER_SHA and identity.get('source_sha256')==SOURCE_SHA,'smoke-source-identity')
        need(all(gpu.integer(identity.get(k)) for k in gpu.IDENTITY_INTS) and identity['protocol']==1 and identity['suite']==1,'smoke-identity-types')
        need(gpu.GPU_NAME.fullmatch(identity.get('device_name','')) and identity['device_name'].startswith('Apple M1 (G13G ') and identity['vendor_id']==0x10005 and identity['driver_id']==26 and identity['api_version']>=4202496 and identity['device_type']==1,'smoke-native-identity')
        metrics=run.get('measurements',{});required=[k for k in gpu.RESULT_INTS if k!='gpu_timestamp_ns']
        need(all(gpu.integer(metrics.get(k)) for k in required),'smoke-measurement-types')
        need(metrics.get('operations')==operations and metrics.get('mismatches')==(1 if negative else 0),'smoke-oracle')
        need(0<metrics['owned_bytes_peak']<=1024**2 and metrics['width']==0 and metrics['height']==0,'tiny-allocation-bound')
        ts=metrics.get('gpu_timestamp_status')
        if ts=='supported':
            need(36<=identity['timestamp_bits']<=64 and metrics['gpu_timestamp_queries']==queries and gpu.integer(metrics.get('gpu_timestamp_ns')),'smoke-timestamp-proof')
        else:
            need(ts=='unsupported' and identity['timestamp_bits']==0 and metrics['gpu_timestamp_queries']==0 and 'gpu_timestamp_ns' not in metrics,'smoke-timestamp-unsupported')
        libraries=run.get('driver_libraries',[]);need(len(libraries)==2,'smoke-provider-count')
        roles={x['role']:x['sha256'] for x in libraries};need(roles=={'implementation':p['implementation_sha256'],'loader':p['loader_sha256']},'smoke-provider-proof')
        record={'workload':workload,'negative':negative,'status':'pass','reason':run['reason'],'helper_sha256':HELPER_SHA,
                'identity':{**{k:identity[k] for k in gpu.IDENTITY_INTS},'device_name':identity['device_name'],'source_sha256':SOURCE_SHA},
                'measurements':{**{k:metrics[k] for k in required},'gpu_timestamp_status':ts},
                'driver_libraries':[{'role':role,'sha256':roles[role]} for role in ('implementation','loader')],
                'kernel_fault_log_available':run.get('kernel_fault_log_available') is True}
        if ts=='supported':record['measurements']['gpu_timestamp_ns']=metrics['gpu_timestamp_ns']
        for key in ('before','after'):
            if key in run:record[key]=gpu.health(run[key])
        samples=run.get('health_samples',[]);need(isinstance(samples,list) and len(samples)<=200,'smoke-health-count')
        record['health_samples']=[gpu.health(x) for x in samples];clean.append(record)
    return {'scope':'Private tiny correctness controls; no performance/RC claim','status':'pass','source_commit':COMMIT,'controls':clean}

def execute(p,archive,smoke,smoke_sha):
    need(os.geteuid()==0,'root-supervisor-required');validate_plan(p);need(not Path(p['prefix']).exists(),'prefix-preexists')
    before=protected_state(p);secret=os.urandom(32);normal=private_state(p['normal_state_paths'],secret)
    archive_bytes=inspect_archive(archive);prefix,payload=stage(p,archive,smoke,smoke_sha);verify_staged(archive_bytes,payload);logs=prefix/'root';receipt={'scope':'tiny MBP correctness only; no performance/RC claim','source_commit':COMMIT,'status':'fail','before':before}
    try:
        start=start_gate(payload);c=cursor();private_write(logs/'journal-cursor.json',{'cursor':c,'boot_id':p['boot_id']});receipt['cursor_sha256']=hashlib.sha256(c.encode()).hexdigest()
        run=prefix/'run';env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1','HOME':str(run/'home'),'TMPDIR':str(run/'tmp'),
                            'XDG_STATE_HOME':str(run/'state'),'XDG_CACHE_HOME':str(run/'cache'),'XDG_CONFIG_HOME':str(run/'config'),'XDG_DATA_HOME':str(run/'data')}
        command=['setpriv','--reuid',str(p['gui_uid']),'--regid',str(p['gui_gid']),'--init-groups','env','-i',*[k+'='+v for k,v in env.items()],
                 'python3','-B',str(prefix/'smoke.py'),'--payload',str(payload),'--implementation-sha256',p['implementation_sha256'],'--loader-sha256',p['loader_sha256'],'--output',str(run/'reports/first-smoke.json')]
        receipt['supervision']=supervise(p,payload,command,logs,journal_cursor=c)
        result=smoke_result(run/'reports/first-smoke.json',p,payload);health_snapshot(payload)
        verify_staged(archive_bytes,payload);need(sha(prefix/'smoke.py')==SMOKE_SHA,'staged-smoke-drift')
        receipt['after']=protected_state(p);need(private_state(p['normal_state_paths'],secret)==normal,'normal-state-drift')
        need(not any((run/'state').iterdir()),'unexpected-signing-state')
        private_write(logs/'reviewed-smoke.json',result)
        receipt.update(status='pass',normal_user_state_unchanged=True,disposable_state_empty=True,protected_state_unchanged=True,
                       cleanup='owned processes reaped; prefix retained for controller verified retrieval')
    except BaseException as error:
        receipt['reason']=str(error) if isinstance(error,Stop) else 'supervisor-exception'
        try:receipt['after']=protected_state(p)
        except BaseException:receipt['post_protected_check_failed']=True
        receipt['normal_user_state_unchanged']=private_state(p['normal_state_paths'],secret)==normal
        raise
    finally:
        private_write(logs/'receipt.json',receipt)
    return receipt

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--archive',required=True);parser.add_argument('--smoke',required=True);parser.add_argument('--smoke-sha256',required=True)
    parser.add_argument('--execute-tiny-smoke',action='store_true');args=parser.parse_args()
    need(Path(args.plan).stat().st_size<=1024**2 and Path(args.smoke).stat().st_size<=65536,'input-file-budget')
    need(HASH.fullmatch(args.plan_sha256) and sha(args.plan)==args.plan_sha256,'reviewed-plan-pin')
    p=validate_plan(json.loads(Path(args.plan).read_text()));inspect_archive(args.archive);need(args.smoke_sha256==SMOKE_SHA and sha(args.smoke)==args.smoke_sha256,'reviewed-smoke-pin')
    if not args.execute_tiny_smoke:print('Static plan/archive/source pins valid; no target metadata or GPU operation performed.');return
    result=execute(p,args.archive,args.smoke,args.smoke_sha256);print('Private tiny smoke '+result['status']+'; no benchmark or release qualification claimed.')

if __name__=='__main__':
    try:main()
    except Stop as error:print('Stopped: '+str(error));raise SystemExit(2)
