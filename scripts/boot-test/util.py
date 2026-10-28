"""Unchanged finite local I/O/process primitives from reviewed frontend R1."""
import datetime,hashlib,json,os,selectors,signal,stat,subprocess,sys,time,uuid
from pathlib import Path
MAXJSON=4*1024**2

class Stop(RuntimeError):pass

def need(v,msg):
 if not v:raise Stop(msg)

def H(b):return hashlib.sha256(b).hexdigest()

def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()

def unique(raw):
 def pairs(items):
  out={}
  for k,v in items:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs)

def key(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def local(path,want=None,limit=MAXJSON,contents=True):
 p=Path(path);need(p.is_absolute() and str(p)==str(path) and '..' not in p.parts,'absolute canonical local path required');fd=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_uid in (0,os.geteuid()) and not a.st_mode&0o022 and 0<a.st_size<=limit,'bounded owned regular local file required')
  if want:need(a.st_size==want['bytes'],'local file length differs from reviewed artifact')
  r=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   h=hashlib.sha256();parts=[];count=0
   while count<a.st_size:
    b=os.read(r,min(1048576,a.st_size-count));need(b,'truncated local file');h.update(b);count+=len(b)
    if contents:parts.append(b)
   need(not os.read(r,1) and key(os.fstat(r))==key(a)==key(p.lstat()),'local file changed while reading')
  finally:os.close(r)
  pin={'path':str(p),'sha256':h.hexdigest(),'bytes':a.st_size}
  if want:need(pin['sha256']==want['sha256'],'local file hash differs from reviewed artifact')
  return pin,b''.join(parts),key(a)
 finally:os.close(fd)

def read_json(path,want=None):return unique(local(path,want)[1])

def write(path,value):
 raw=canonical(value);need(len(raw)<=MAXJSON,'bounded JSON output');p=Path(path);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:need(os.write(fd,raw)==len(raw),'short output write');os.fsync(fd)
 finally:os.close(fd)
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);need(local(str(p))[1]==raw,'output fsync/readback differs');return {'path':str(p),'sha256':H(raw),'bytes':len(raw)}

def replace(path,value):
 p=Path(path);tmp=p.with_name(p.name+'.new-'+uuid.uuid4().hex);pin=write(tmp,value);os.replace(tmp,p);fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);return {'path':str(p),'sha256':pin['sha256'],'bytes':pin['bytes']}

def state_storage(path):
 p=Path(path);need(p.is_absolute() and '..' not in p.parts,'absolute state path required');parent=p.parent;parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 for v in (parent,*parent.parents):
  s=v.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.geteuid()) and (not s.st_mode&0o022 or str(v) in ('/tmp','/dev/shm') and s.st_uid==0 and s.st_mode&stat.S_ISVTX),'unsafe state ancestry')
 mounts=[]
 for line in Path('/proc/self/mountinfo').read_text().splitlines():
  a,b=line.split(' - ',1);m=a.split()[4].replace('\\040',' ');kind=b.split()[0]
  if str(parent)==m or str(parent).startswith(m.rstrip('/')+'/'):mounts.append((len(m),kind))
 kind=max(mounts)[1];need(kind not in ('tmpfs','ramfs'),'state filesystem is volatile; choose an explicit durable controller path')
 need(not p.exists(),'state already exists; do not automatically retry/resume this frontend');p.mkdir(mode=0o700);probe=p/'.fsync-probe';pin=write(probe,{'state_storage_probe':True});probe.unlink();fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);return {'path':str(p),'filesystem':kind,'fsync_reopen_probe':True,'prior_btrfs_eio_repaired':False}

def group_members(pgid):
 out=[]
 for entry in Path('/proc').iterdir():
  if not entry.name.isdecimal():continue
  try:
   fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
   if int(fields[2])==pgid and fields[0]!='Z':out.append(int(entry.name))
  except (OSError,ValueError,IndexError):continue
 return out

def process(argv,out,stem,timeout):
 # Observe exit without reaping. The retained leader PID pins the owned PGID
 # until all group members drain, so cleanup cannot signal a recycled group.
 need(hasattr(os,'pidfd_open') and hasattr(os,'P_PIDFD'),'pidfd ownership support required')
 start=time.monotonic();sel=selectors.DefaultSelector();streams={};counts={};reason=None;interrupted=[];handlers={};p=None;pf=None;term=None
 def exited():return os.waitid(os.P_PIDFD if pf is not None else os.P_PID,pf if pf is not None else p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
 def send(sig,whole=False):
  try:
   if whole:os.killpg(p.pid,sig)
   elif pf is not None:signal.pidfd_send_signal(pf,sig)
   else:os.kill(p.pid,sig)
  except ProcessLookupError:pass
 try:
  for name in ('stdout','stderr'):
   path=Path(out)/(stem+'.'+name);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);streams[name]=os.fdopen(fd,'wb');counts[name]=0
  p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);pf=os.pidfd_open(p.pid,0)
  for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):handlers[sig]=signal.getsignal(sig);signal.signal(sig,lambda s,f:interrupted.append(s))
  for name,pipe in [('stdout',p.stdout),('stderr',p.stderr)]:sel.register(pipe,selectors.EVENT_READ,name)
  deadline=start+timeout
  while sel.get_map() or not exited() or group_members(p.pid):
   dead=exited();members=group_members(p.pid)
   if dead and members:reason=reason or 'runner-descendants-live-after-exit'
   if (interrupted or time.monotonic()>deadline or reason) and term is None:
    reason=reason or ('interrupted' if interrupted else 'runtime-budget-exceeded');send(signal.SIGTERM,dead);term=time.monotonic()
   if term is not None and time.monotonic()-term>45:send(signal.SIGKILL,True)
   if term is not None and time.monotonic()-term>50:
    reason=reason or 'cleanup-deadline-exceeded'
    for k in list(sel.get_map().values()):sel.unregister(k.fileobj);k.fileobj.close()
    break
   for k,_ in sel.select(.2):
    b=os.read(k.fileobj.fileno(),65536)
    if not b:sel.unregister(k.fileobj);k.fileobj.close();continue
    name=k.data;counts[name]+=len(b)
    if counts[name]<=8*1024**2:streams[name].write(b)
    else:reason='bounded-runner-output-exceeded'
  need(exited() and not group_members(p.pid),'owned runner group not drained; no completion claim');code=p.wait(timeout=5);return {'argv':argv,'exit_code':code,'seconds':time.monotonic()-start,'stop_reason':reason,'output_bytes':counts,'owned_group_live_after':[]}
 finally:
  try:
   if p is not None and p.returncode is None:
    send(signal.SIGTERM,exited());until=time.monotonic()+45
    while time.monotonic()<until and (not exited() or group_members(p.pid)):time.sleep(.05)
    if not exited() or group_members(p.pid):
     send(signal.SIGKILL,True);until=time.monotonic()+5
     while time.monotonic()<until and (not exited() or group_members(p.pid)):time.sleep(.05)
    need(exited() and not group_members(p.pid),'owned group cleanup incomplete');p.wait(timeout=5)
  finally:
   if pf is not None:os.close(pf)
   try:
    for f in streams.values():f.flush();os.fsync(f.fileno());f.close()
   finally:
    for sig,h in handlers.items():signal.signal(sig,h)
    sel.close()
