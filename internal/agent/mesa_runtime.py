#!/usr/bin/env python3
"""Job-owned staged Mesa probes. No installation, session or baseline mutation.

The agent supplies a root-owned plan bound to the actual job boot and staged
manifest. No arbitrary executable/command or provider bypass is accepted.
"""
import argparse, glob, hashlib, json, os, pwd, re, selectors, signal, stat, subprocess, sys, time
from pathlib import Path

MAX_FILE=512*1024*1024
CAP=4*1024*1024
FAULT=re.compile(r'BUG:|Oops:|Kernel panic|soft lockup|RCU.*stall|WARNING:|(?:asahi|agx|gpu).*(?:fault|timed? ?out|reset|hang)|(?:DART|apple-dart).*fault|AOP.*(?:crash|panic)|Out of memory:|oom-kill:|I/O error|BTRFS.*(?:error|corrupt)|GPU memory accounting underflow|Bad rss-counter state|Vm::Drop: deferred user unmap failed|VM create: closing unpublished VM failed',re.I)
SOFTWARE=re.compile(r'llvmpipe|softpipe|lavapipe|swrast|software raster|MoltenVK',re.I)
GRAPHICS=re.compile(r'^(?:lib(?:vulkan|EGL|GLX|GLdispatch|GLES|OpenGL|GL\.|gallium|gbm|VkLayer|LLVM|drm)|.*_(?:dri|gbm)\.so|asahi.*\.so)')
class Stop(RuntimeError):pass
def need(value,msg):
    if not value:raise Stop(msg)
def info(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def sha(path):
    held=fd=None
    try:
        held=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC);a=os.fstat(held)
        need(stat.S_ISREG(a.st_mode) and 0<=a.st_size<=MAX_FILE,'nonregular/oversize hash')
        fd=os.open('/proc/self/fd/'+str(held),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
        need(info(os.fstat(fd))==info(a),'hash reopen drift');h=hashlib.sha256();n=0;deadline=time.monotonic()+10
        while True:
            need(time.monotonic()<deadline,'hash deadline');b=os.read(fd,1024*1024)
            if not b:break
            n+=len(b);need(n<=MAX_FILE,'hash bytes');h.update(b)
        need(n==a.st_size and info(os.fstat(fd))==info(a) and info(os.stat(path,follow_symlinks=False))==info(a),'hash path/content drift')
        return h.hexdigest()
    finally:
        if fd is not None:os.close(fd)
        if held is not None:os.close(held)
def capture(argv,timeout=5,limit=CAP,env=None):
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=env or {'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    sel=selectors.DefaultSelector();data={'out':bytearray(),'err':bytearray()};deadline=time.monotonic()+timeout
    try:
        for name,stream in (('out',p.stdout),('err',p.stderr)):
            os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,name)
        while sel.get_map():
            need(time.monotonic()<deadline,'capture timeout: '+argv[0])
            for key,_ in sel.select(.05):
                chunk=os.read(key.fd,16384)
                if not chunk:sel.unregister(key.fileobj);continue
                data[key.data].extend(chunk);need(len(data[key.data])<=limit,'capture budget')
        code=p.wait(timeout=max(.01,deadline-time.monotonic()));need(code==0 and not data['err'],'capture failed: '+argv[0]);return bytes(data['out'])
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:p.wait(timeout=.2)
            except subprocess.TimeoutExpired:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=2)
        sel.close();p.stdout.close();p.stderr.close()

def save(path,value):
    data=value if isinstance(value,bytes) else (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with open(path,'xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.chmod(path,0o600)
def render_node():
    s=Path('/dev/dri/renderD128').lstat();need(stat.S_ISCHR(s.st_mode) and os.major(s.st_rdev)==226 and os.minor(s.st_rdev)==128,'native render node missing/type');return {'major':226,'minor':128,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
def identity(plan):
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['boot_id'],'unexpected reboot')
    need(Path('/proc/sys/kernel/osrelease').read_text().strip()==plan['kernel'],'kernel drift')
    need(hashlib.sha256(Path('/proc/cmdline').read_bytes()).hexdigest()==plan['cmdline_sha256'],'cmdline drift')
    if 'render_node_pin' in plan:need(render_node()==plan['render_node_pin'],'render node identity drift')
    need(('maclab.job='+plan['job']) in Path('/proc/cmdline').read_text().split(),'not actual job boot')
def verify_manifest(plan,m):
    need(sha(plan['manifest_path'])==plan['manifest_sha256'],'manifest drift')
    need(m['schema']==1 and m['job']==plan['job'],'manifest identity')
    prefix=Path(m['prefix']);root=Path(m['root']);need(root==prefix/'root' and prefix.name==plan['job'],'owned prefix')
    for p in (prefix,root):
        st=p.lstat();mode=0o750 if p==prefix else 0o755;need(stat.S_ISDIR(st.st_mode) and not p.is_symlink() and st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode,'prefix ownership')
    need(prefix.stat().st_gid==plan['gui_gid'],'private prefix GUI group')
    for rel,f in m['files'].items():
        path=root/rel;need(not rel.startswith('/') and '..' not in Path(rel).parts,'manifest traversal')
        if f.get('link'):
            need(path.is_symlink() and os.readlink(path)==f['link'],'staged alias drift')
            target=path.resolve(strict=True);need(target.is_relative_to(root),'staged alias escape')
        else:need(sha(path)==f['sha256'],'staged file drift: '+rel)
    for name in ('egl','gallium','vulkan'):
        f=m['files'][m['providers'][name]];need(not f.get('link') and f.get('sha256'),'provider not canonical regular')
    for api in ('gl','vulkan'):need(sha(m['probes'][api]['path'])==m['probes'][api]['sha256'],'probe drift')
    need(sha(m['vulkan_json'])==m['vulkan_json_sha256'] and sha(m['egl_json'])==m['egl_json_sha256'],'derived descriptor bytes drift')
    need(json.loads(Path(m['vulkan_json']).read_text())['ICD']['library_path']==str(root/m['providers']['vulkan']),'Vulkan descriptor drift')
    need(json.loads(Path(m['egl_json']).read_text())['ICD']['library_path']==str(root/m['providers']['egl']),'EGL descriptor drift')
def system_pins():
    result={}
    for p in Path('/usr/lib').glob('*.so*'):
        if not GRAPHICS.match(p.name):continue
        path=p.resolve(strict=True);need(path.is_relative_to('/usr/lib'),'system graphics alias escape')
        st=path.stat();need(stat.S_ISREG(st.st_mode),'system graphics nonregular')
        result[str(path)]={'sha256':sha(path),'size':st.st_size,'dev':st.st_dev,'inode':st.st_ino}
        need(len(result)<=256,'graphics baseline budget')
    need(result,'no system graphics loaders');return result
def verify_system(pins):
    for p,v in pins.items():
        st=os.stat(p,follow_symlinks=False);need(stat.S_ISREG(st.st_mode) and st.st_dev==v['dev'] and st.st_ino==v['inode'] and st.st_size==v['size'] and sha(p)==v['sha256'],'system loader/provider drift')
def child_env(plan,m):
    run=Path(m['prefix'])/'run';env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':str(run/'home'),'TMPDIR':str(run/'tmp'),'XDG_CACHE_HOME':str(run/'cache'),'XDG_CONFIG_HOME':str(run/'config'),'XDG_DATA_HOME':str(run/'data'),'XDG_STATE_HOME':str(run/'state')}
    for k in ('XDG_RUNTIME_DIR','WAYLAND_DISPLAY','DISPLAY','DBUS_SESSION_BUS_ADDRESS','XDG_SESSION_TYPE'):
        if k in plan['gui_env']:env[k]=plan['gui_env'][k]
    lib=str(Path(m['root'])/'usr/lib');env.update({'LD_LIBRARY_PATH':lib+':/usr/lib','VK_DRIVER_FILES':m['vulkan_json'],'VK_ICD_FILENAMES':m['vulkan_json'],'__EGL_VENDOR_LIBRARY_FILENAMES':m['egl_json'],'LIBGL_DRIVERS_PATH':lib+'/dri','GBM_BACKENDS_PATH':lib+'/gbm'})
    return env
def health(plan):
    temps=[int(Path(p).read_text())/1000 for p in glob.glob('/sys/class/thermal/thermal_zone*/temp')]
    need(temps and all(-20<=t<85 for t in temps),'thermal admission/stop')
    mem={k:int(v.split()[0]) for k,v in (l.split(':',1) for l in Path('/proc/meminfo').read_text().splitlines())};need(mem['MemAvailable']>max(2*1024*1024,mem['MemTotal']//4),'memory reserve')
    gui={'PATH':'/usr/bin:/bin','LC_ALL':'C',**plan['gui_env']};prefix=['runuser','-u',plan['gui_user'],'--','env','-i',*[k+'='+v for k,v in gui.items()]]
    mons=json.loads(capture(prefix+['hyprctl','-j','monitors']));need(mons and all(x['width']>0 and x['height']>0 and not x.get('disabled',False) for x in mons),'inactive display')
    keys=('name','width','height','refreshRate','scale','transform','disabled');mon=sorted([{k:x.get(k) for k in keys} for x in mons],key=lambda x:x['name'])
    wifi=[l for l in capture(['nmcli','-t','-f','DEVICE,TYPE,STATE','device']).decode().splitlines() if ':wifi:connected' in l];need(wifi,'no connected Wi-Fi')
    return {'cpu_online':Path('/sys/devices/system/cpu/online').read_text().strip(),'monitors':mon,'wifi':sorted(wifi)}
def cursor():
    data=capture(['journalctl','-k','-b','-n','1','-o','json','--show-cursor','--no-pager']);records=[json.loads(x) for x in data.splitlines() if x.startswith(b'{')];need(records and isinstance(records[-1].get('__CURSOR'),str),'missing fresh journal cursor');value=records[-1]['__CURSOR'];need(1<=len(value)<=4096 and '\n' not in value and '\0' not in value,'invalid journal cursor');return value
def scan_journal(start,boot):
    data=capture(['journalctl','-k','-b','--after-cursor='+start,'-o','json','--no-pager','--all'])
    validate_journal(data,boot);return data
def validate_journal(data,boot):
    lines=data.splitlines();need(len(lines)<=20000,'journal record budget')
    for line in lines:
        x=json.loads(line);need(x.get('_BOOT_ID')==boot.replace('-',''),'journal boot mismatch');msg=x.get('MESSAGE')
        if isinstance(msg,list):
            need(len(msg)<=65536 and all(type(v)is int and 0<=v<256 for v in msg),'journal byte message schema');msg=bytes(msg).decode(errors='replace')
        need(isinstance(msg,str),'journal message schema');need(not FAULT.search(msg),'fresh kernel/GPU fault: '+msg[:200])
CGROUP_ROOT=Path('/sys/fs/cgroup/system.slice')
PROPS=('LoadState','Description','Transient','User','Group','Type','RemainAfterExit','KillMode','SendSIGKILL','RuntimeMaxUSec','ActiveState','SubState','ControlGroup','InvocationID','MainPID','ExecMainCode','ExecMainStatus','Result')
def unit_state(unit):
    text=capture(['systemctl','show',unit,*['--property='+x for x in PROPS]]).decode();v=dict(x.split('=',1) for x in text.splitlines());need(set(v)==set(PROPS),'unit property schema');return v
def terminal(v):return v.get('ActiveState')=='active' and v.get('SubState')=='exited' and v.get('MainPID')=='0' and v.get('ExecMainCode')=='1' and v.get('ExecMainStatus')=='0' and v.get('Result')=='success'
def owner(v,plan,unit,desc,inv=None):
    req={'LoadState':'loaded','Description':desc,'Transient':'yes','User':str(plan['gui_uid']),'Group':str(plan['gui_gid']),'Type':'exec','RemainAfterExit':'yes','KillMode':'control-group','SendSIGKILL':'yes','RuntimeMaxUSec':'20s'}
    need(all(v.get(k)==x for k,x in req.items()),'transient owner contract');need(re.fullmatch('[0-9a-f]{32}',v.get('InvocationID','')),'invocation missing')
    if inv:need(v['InvocationID']==inv,'invocation drift')
    need(v['ControlGroup']=='/system.slice/'+unit or (inv is not None and v['ControlGroup']=='' and terminal(v)),'unit cgroup owner')
    return v['InvocationID']
def members(unit,v,plan,desc,inv):
    root=CGROUP_ROOT/unit
    if not root.exists():
        fresh=unit_state(unit);owner(fresh,plan,unit,desc,inv);need(terminal(fresh),'missing cgroup without fresh terminal success');return [],fresh
    need(root.is_dir() and not root.is_symlink(),'cgroup path');files=[root/'cgroup.procs',*root.glob('**/cgroup.procs')];need(len(files)<=32,'cgroup depth budget');pids=set()
    for p in files:
        text=p.read_text();need(len(text)<32768,'cgroup members budget');pids.update(int(x) for x in text.split())
    need(len(pids)<=128,'cgroup PID budget');live=[]
    for p in pids:
        try:
            fields=Path('/proc',str(p),'stat').read_text().rsplit(')',1)[1].split()
            if fields[0]!='Z':live.append(p)
        except FileNotFoundError:pass
    return live,v
class MappedGone(FileNotFoundError):
    def __init__(self,mapping):self.mapping=dict(mapping);super().__init__('owned mapped process vanished')
def proc_birth(pid):
    raw=Path('/proc',str(pid),'stat').read_bytes();need(len(raw)<16384,'process stat budget');return int(raw.rsplit(b') ',1)[1].split()[19])
def map_signature(mapping):return tuple(mapping[x] for x in ('range','perms','offset','path','maps_device','inode','deleted'))
def current_mapping(mapping):
    pid=mapping['pid'];birth=mapping['birth']
    try:
        need(proc_birth(pid)==birth,'mapped PID reused');text=Path('/proc',str(pid),'maps').read_text();need(len(text)<=8*1024*1024,'maps budget');rows=[]
        for line in text.splitlines():
            f=line.split(None,5)
            if f and f[0]==mapping['range']:
                need(len(f)==6,'mapped row became anonymous');p=f[5];deleted=p.endswith(' (deleted)');p=p.removesuffix(' (deleted)');rows.append({'range':f[0],'perms':f[1],'offset':int(f[2],16),'path':p,'maps_device':f[3],'inode':int(f[4]),'deleted':deleted})
        need(len(rows)==1 and map_signature(rows[0])==map_signature(mapping),'mapped range/perms/offset/path replaced');need(proc_birth(pid)==birth,'PID changed during map check')
    except FileNotFoundError as e:raise MappedGone(mapping) from e

def hash_held(meta):
    before=os.fstat(meta);need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=MAX_FILE,'mapped/live nonregular or oversize');ident=info(before);fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(info(os.fstat(fd))==ident,'mapped hash reopen drift');h=hashlib.sha256();n=0;deadline=time.monotonic()+10
        while n<=before.st_size:
            need(time.monotonic()<deadline,'mapped hash deadline');b=os.read(fd,min(1024*1024,before.st_size+1-n))
            if not b:break
            n+=len(b);h.update(b)
        need(n==before.st_size and info(os.fstat(fd))==ident and info(os.fstat(meta))==ident,'mapped content/metadata changed');return h.hexdigest()
    finally:os.close(fd)
class MapWitnesses:
    def __init__(self):self.hashes={};self.bindings={}
    def key(self,row):return (row['pid'],row['birth'],map_signature(row))
    def digest(self,meta,row):
        ident=info(os.fstat(meta));key=(row['pid'],row['birth'],ident)
        if key in self.hashes:
            held,digest=self.hashes[key];need(info(os.fstat(held))==ident,'retained witness metadata changed');return digest
        need(len(self.hashes)<128,'provider witness descriptor budget');digest=hash_held(meta);self.hashes[key]=(os.dup(meta),digest);return digest
    def commit(self,row,mapped,live):
        key=self.key(row);value=(mapped,live);need(key not in self.bindings or self.bindings[key]==value,'mapped/live descriptor changed');self.bindings[key]=value
    def close(self):
        for fd,_ in self.hashes.values():os.close(fd)
        self.hashes.clear();self.bindings.clear()

def bind_mapping(row,expected_sha,witnesses,reference=None,check_current=True):
    mapped=live=None
    try:
        if check_current:current_mapping(row)
        try:
            # This is the ONLY followed magic link; it is a validated kernel
            # PID/VMA reference. O_PATH never invokes character-device open.
            mapped=os.open('/proc/'+str(row['pid'])+'/map_files/'+row['range'],os.O_PATH|os.O_CLOEXEC) if reference is None else reference(row['range'],row['path'])
        except FileNotFoundError as error:
            if check_current:current_mapping(row)
            raise Stop('mapped range disappeared while PID remains') from error
        live=os.open(row['path'],os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC);a=os.fstat(mapped);b=os.fstat(live)
        need(stat.S_ISREG(a.st_mode) and stat.S_ISREG(b.st_mode) and info(a)==info(b) and a.st_ino==row['inode'],'mapped descriptor/live path full identity mismatch')
        key=witnesses.key(row)
        if key in witnesses.bindings:need(witnesses.bindings[key]==(info(a),info(b)),'committed descriptor identity drift')
        actual=witnesses.digest(mapped,row);current=witnesses.digest(live,row);need(actual==current==expected_sha,'mapped/live/pinned bytes mismatch')
        need(info(os.fstat(mapped))==info(a) and info(os.fstat(live))==info(b) and info(os.stat(row['path'],follow_symlinks=False))==info(b),'mapped/live path metadata drift')
        if check_current:current_mapping(row)
        witnesses.commit(row,info(a),info(b));return {'range':row['range'],'perms':row['perms'],'offset':row['offset'],'maps_device':row['maps_device'],'maps_inode':row['inode'],'actual_device':a.st_dev,'actual_inode':a.st_ino,'path':row['path'],'sha256':actual}
    except FileNotFoundError as error:
        if isinstance(error,MappedGone):raise
        if check_current:current_mapping(row)
        raise Stop('live regular provider pathname vanished') from error
    finally:
        if mapped is not None:os.close(mapped)
        if live is not None:os.close(live)

def graphics_maps(text,manifest,pins,pid=None,mapped_reference=None,evidence=None,witnesses=None,birth=None):
    need(len(text)<=8*1024*1024,'maps budget');root=Path(manifest['root']);found=set();system=False;own=witnesses is None
    if own:witnesses=MapWitnesses()
    try:
        for line in text.splitlines():
            f=line.split(None,5)
            if len(f)<6 or not f[5].startswith('/'):continue
            path=f[5];base=Path(path.removesuffix(' (deleted)')).name
            if not GRAPHICS.match(base) and '/dri/' not in path and '/gbm/' not in path and not Path(path).is_relative_to(root/'usr/lib'):continue
            need(not path.endswith(' (deleted)'),'deleted graphics map');st=os.stat(path,follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):continue
            need(re.fullmatch('[0-9a-f]+-[0-9a-f]+',f[0]) and re.fullmatch('[0-9a-f]+:[0-9a-f]+',f[3]) and f[4].isdecimal() and re.fullmatch('[r-][w-][x-][ps]',f[1]) and re.fullmatch('[0-9a-f]+',f[2]),'mapped range/device/inode schema')
            lo,hi=(int(x,16) for x in f[0].split('-'));need(lo<hi,'empty map range');need(mapped_reference is not None or (type(pid)is int and pid>0 and type(birth)is int),'missing owned mapped-file reference')
            row={'range':f[0],'perms':f[1],'offset':int(f[2],16),'path':path,'maps_device':f[3],'inode':int(f[4]),'deleted':False,'pid':pid if pid is not None else 1,'birth':birth if birth is not None else 1}
            if Path(path).is_relative_to(root):
                rel=str(Path(path).relative_to(root));v=manifest['files'].get(rel);need(v and not v.get('link') and v.get('sha256'),'unfrozen staged map');expected=v['sha256'];found.add(rel)
            else:
                need(path in pins,'unfrozen external graphics map');expected=pins[path]['sha256']
                if re.match(r'libgallium|libEGL_mesa|libvulkan_asahi',base):system=True
            proof=bind_mapping(row,expected,witnesses,mapped_reference,check_current=mapped_reference is None)
            if evidence is not None:evidence.append(proof)
        return found,system
    finally:
        if own:witnesses.close()

def allow_owned_exit(mapping,seen,witnesses):
    key=(mapping['pid'],mapping['birth']);need(key in seen.get('complete',set()) and witnesses.key(mapping) in witnesses.bindings,'vanished child without prior complete exact-range witness')
    try:proc_birth(mapping['pid'])
    except FileNotFoundError:return {'pid':mapping['pid'],'birth':mapping['birth'],'range':mapping['range']}
    raise Stop('mapped PID remains or was reused')

def observe(pids,tool,m,pins,seen,expected_uid,required,witnesses):
    for pid in pids:
        try:
            birth=proc_birth(pid);exe=os.readlink('/proc/'+str(pid)+'/exe')
            if exe!=tool['path']:continue
            need(sha(exe)==tool['sha256'],'actual probe executable drift');status=Path('/proc',str(pid),'status').read_text();uid=re.search(r'^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$',status,re.M);need(uid and all(int(x)==expected_uid for x in uid.groups()),'probe UID drift');proof=[]
            try:f,s=graphics_maps(Path('/proc',str(pid),'maps').read_text(),m,pins,pid=pid,birth=birth,evidence=proof,witnesses=witnesses)
            except MappedGone as error:
                seen.setdefault('pending_exits',[]).append(allow_owned_exit(error.mapping,seen,witnesses));continue
            need(proc_birth(pid)==birth and os.readlink('/proc/'+str(pid)+'/exe')==tool['path'],'probe process identity drift');render=False
            for fd in Path('/proc',str(pid),'fd').iterdir():
                try:
                    st=fd.stat()
                    if stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev)==226 and os.minor(st.st_rdev)==128:render=True
                except FileNotFoundError:pass
            need(proc_birth(pid)==birth,'probe birth changed after fd observation')
            seen['files'].update(f);seen['system']|=s;seen['render_node']|=render;key=str(pid)+':'+str(birth);item=seen.setdefault('processes',{}).setdefault(key,{'pid':pid,'starttime':birth,'uid':expected_uid,'executable':exe,'sha256':tool['sha256'],'mapped_references':{}})
            for witness in proof:item['mapped_references'][witness['range']]=witness
            if required<=f and render and not s:seen.setdefault('complete',set()).add((pid,birth))
        except MappedGone:raise
        except FileNotFoundError as error:
            # Only MappedGone with an exact previously committed range can be
            # provisional. Other first/new-birth/metadata disappearances STOP.
            raise Stop('owned process vanished outside an exact committed mapping') from error

def admit_probe(api,text,seen,m):
    need(not SOFTWARE.search(text),'software/non-native renderer')
    renderer=re.search(r'^(?:Renderer|Device): (Apple (?:M[1-5]|A[0-9]{2})[^\n]*)$',text,re.M);need(renderer,'native Apple renderer absent')
    need(re.search(r'^PASS: [1-9][0-9]* runs in [0-9.]+ s, 0 with wrong pixels\s*$',text,re.M),'pixel correctness failed')
    roles={'egl','gallium'} if api=='gl' else {'vulkan'};need(all(m['providers'][x] in seen['files'] for x in roles) and seen['render_node'] and not seen['system'] and seen.get('complete'),'staged native implementation/renderfd not observed')
    return renderer.group(1)

def stop_owned(unit,plan,desc,inv):
    state=unit_state(unit)
    if state['LoadState']=='not-found':return
    owner(state,plan,unit,desc,inv);capture(['systemctl','stop',unit],timeout=8)
    root=CGROUP_ROOT/unit
    need(not root.exists() or all(not p.read_text().split() for p in [root/'cgroup.procs',*root.glob('**/cgroup.procs')]),'cleanup left cgroup members')

def probe(api,plan,m,pins,env,out):
    tool=m['probes'][api];unit='maclab-mesa-'+plan['job']+'-'+api+'.service';desc='maclab-mesa:'+plan['job']+':'+tool['sha256'];stdout=out/(api+'.stdout');stderr=out/(api+'.stderr');save(stdout,b'');save(stderr,b'');start=cursor();inv=None;attempt=False;v=None;seen={'files':set(),'system':False,'render_node':False};before=health(plan);deadline=time.monotonic()+30;witnesses=MapWitnesses();required={m['providers'][role] for role in ({'egl','gallium'} if api=='gl' else {'vulkan'})}
    need(unit_state(unit)['LoadState']=='not-found','unit preexists')
    cmd=['systemd-run','--quiet','--unit='+unit,'--property=Type=exec','--property=Description='+desc,'--property=User='+str(plan['gui_uid']),'--property=Group='+str(plan['gui_gid']),'--property=RemainAfterExit=yes','--property=KillMode=control-group','--property=SendSIGKILL=yes','--property=TimeoutStopSec=5s','--property=RuntimeMaxSec=20s','--property=LimitFSIZE=4194304','--property=UMask=0077','--property=NoNewPrivileges=yes','--property=ProtectHome=read-only','--property=ProtectSystem=strict','--property=ReadWritePaths='+str(Path(m['prefix'])/'run'),'--property=ProtectKernelTunables=yes','--property=ProtectKernelModules=yes','--property=ProtectControlGroups=yes','--property=StandardOutput=append:'+str(stdout),'--property=StandardError=append:'+str(stderr),'/usr/bin/env','-i',*[k+'='+v for k,v in env.items()],tool['path'],'3']
    try:
        attempt=True;capture(cmd,timeout=10);v=unit_state(unit);inv=owner(v,plan,unit,desc);save(out/(api+'.unit-start.json'),v);next_health=0
        while True:
            need(time.monotonic()<deadline,'probe timeout');identity(plan);v=unit_state(unit);owner(v,plan,unit,desc,inv);pids,v=members(unit,v,plan,desc,inv)
            if not terminal(v):observe(pids,tool,m,pins,seen,plan['gui_uid'],required,witnesses)
            scan_journal(start,plan['boot_id'])
            if time.monotonic()>=next_health:need(health(plan)==before,'display/network/CPU drift');next_health=time.monotonic()+1
            need(stdout.stat().st_size<=CAP and stderr.stat().st_size<=CAP,'probe log budget')
            if terminal(v):need(not pids,'terminal descendants');save(out/(api+'.unit-terminal.json'),v);break
            need(v['ActiveState']=='active' and v['SubState']=='running','probe not running');time.sleep(.03)
        need(terminal(v),'pending disappearance without genuine successful workload exit')
        renderer_name=admit_probe(api,stdout.read_text()+stderr.read_text(),seen,m)
        return {'verdict':'NATIVE_STAGED','renderer':renderer_name,'mapped_files':sorted(seen['files']),'processes':list(seen.get('processes',{}).values()),'render_node_observed':True,'invocation_id':inv,'unit':unit,'journal_cursor':start,'validated_normal_exits':seen.get('pending_exits',[]),'already_reaped_observation':bool(seen.get('pending_process_exit'))}
    finally:
        try:
            if attempt:
                try:
                    state=unit_state(unit)
                    if state['LoadState']!='not-found':owner(state,plan,unit,desc,inv);save(out/(api+'.unit-before-stop.json'),state)
                finally:stop_owned(unit,plan,desc,inv)

        finally:
            try:
                raw=scan_journal(start,plan['boot_id']);save(out/(api+'.journal-final.jsonl'),raw);identity(plan)
            finally:witnesses.close()

def run(plan,out):
    need(os.geteuid()==0 and plan['gui_uid']>0 and plan['gui_gid']>0,'root supervisor/nonroot child required');plan['render_node_pin']=render_node();account=pwd.getpwnam(plan['gui_user']);need((account.pw_uid,account.pw_gid,account.pw_dir)==(plan['gui_uid'],plan['gui_gid'],plan['gui_home']),'GUI account drift');need(plan['gui_env'].get('XDG_RUNTIME_DIR')=='/run/user/'+str(plan['gui_uid']),'GUI runtime directory drift');identity(plan);m=json.loads(Path(plan['manifest_path']).read_text());verify_manifest(plan,m)
    runroot=Path(m['prefix'])/'run';runroot.mkdir(mode=0o700);os.chown(runroot,plan['gui_uid'],plan['gui_gid'])
    for name in ('home','tmp','cache','config','data','state','reports'):
        p=runroot/name;p.mkdir(mode=0o700);os.chown(p,plan['gui_uid'],plan['gui_gid'])
    pins=system_pins();env=child_env(plan,m);before=health(plan);packages=capture(['pacman','-Q']);result={'schema':1,'mode':'staged','semantics':'staged diagnostic; desktop kept installed Mesa; not installed-desktop qualification','job':plan['job'],'boot_id':plan['boot_id'],'kernel':plan['kernel'],'manifest_sha256':plan['manifest_sha256'],'provider':{},'packages':m['packages'],'verdict':'INCOMPLETE','cleanup_verified':False}
    try:
        for api in ('gl','vulkan'):result['provider'][api]=probe(api,plan,m,pins,env,out)
        if plan.get('official_gpu'):
            from mesa_official import run_official
            result['official']=run_official(plan,m,out,env,pins)
            need(result['official'].get('status')=='PASS' and result['official'].get('native_invocations')==65 and result['official'].get('signature_verified') is True,'official suite incomplete')
        verify_manifest(plan,m);verify_system(pins);identity(plan);need(health(plan)==before and capture(['pacman','-Q'])==packages,'postflight desktop/package drift');result['cleanup_verified']=True;result['verdict']='PASS';return result
    except BaseException as e:result['error']=str(e);result['verdict']='FAIL';raise
    finally:save(out/'mesa-result.json',result)
def cancelled(sig,frame):raise Stop('canceled: '+str(sig))
def main():
    p=argparse.ArgumentParser();p.add_argument('plan');p.add_argument('out');a=p.parse_args();signal.signal(signal.SIGTERM,cancelled);signal.signal(signal.SIGINT,cancelled);signal.signal(signal.SIGHUP,cancelled)
    st=Path(a.plan).lstat();need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,'runtime plan ownership');run(json.loads(Path(a.plan).read_text()),Path(a.out))
if __name__=='__main__':main()
