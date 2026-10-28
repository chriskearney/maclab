"""One-job parent-abort guardian. Kernel subreaper owns orphaned descendants."""
import ctypes,errno,hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
WORK_SECONDS=145;CLEANUP_SECONDS=15

def need(v,msg):
 if not v:raise RuntimeError(msg)
def ps(pid):
 try:
  s=Path('/proc',str(pid),'stat').read_bytes().rsplit(b')',1)[1].split();return {'pid':pid,'state':s[0].decode(),'ppid':int(s[1]),'birth':int(s[19])}
 except (FileNotFoundError,ProcessLookupError):return None
def children():
 rows={}
 for d in Path('/proc').iterdir():
  if d.name.isdigit():
   v=ps(int(d.name))
   if v:rows[v['pid']]=v
 owned={os.getpid()};out={};changed=True
 while changed:
  changed=False
  for pid,row in rows.items():
   if pid not in owned and row['ppid'] in owned:owned.add(pid);out[pid]=row;changed=True
 return out

def send_owned(row,sig):
 # Hold kernel PID identity before any signal, never kill an unowned PGID.
 fd=os.pidfd_open(row['pid'])
 try:
  current=ps(row['pid']);need(current and current['birth']==row['birth'],'owned child PID changed');signal.pidfd_send_signal(fd,sig)
 except ProcessLookupError:pass
 finally:os.close(fd)
def reap():
 while True:
  try:pid,status=os.waitpid(-1,os.WNOHANG)
  except ChildProcessError:return
  if not pid:return

def drain(deadline):
 # All live descendants originate after subreaper activation. Kernel adoption
 # closes the spawn/reparent race even when a worker dies before recording PGID.
 first=True
 while time.monotonic()<deadline:
  rows=children()
  for row in rows.values():
   if row['state'] not in ('Z','X'):
    try:send_owned(row,signal.SIGTERM if first else signal.SIGKILL)
    except ProcessLookupError:pass
  first=False;reap()
  if not children():return []
  time.sleep(.05)
 return list(children())
def receipt(out,value):
 st=out.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and not st.st_mode&0o022,'owned guardian output');p=out/'native-supervisor.json';raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:os.write(fd,raw);os.fsync(fd)
 finally:os.close(fd)
 d=os.open(out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
def run(worker_source,parent_pid,out):
 parent=ps(parent_pid);need(parent and parent['state'] not in ('Z','X') and os.getppid()==parent_pid,'actual waiting Script parent');libc=ctypes.CDLL(None,use_errno=True);need(libc.prctl(36,1,0,0,0)==0,'kernel subreaper unavailable');need(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'pidfd signaling unavailable')
 def interrupted(*args):raise RuntimeError('guardian termination requested')
 for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
 p=subprocess.Popen(['/usr/bin/python3','-E','-c',worker_source],start_new_session=True)
 try:pidfd=os.pidfd_open(p.pid)
 except BaseException:
  # Unreaped direct child PID cannot recycle; stop before losing ownership.
  p.terminate()
  try:p.wait(timeout=8)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
  drain(time.monotonic()+7);raise
 deadline=time.monotonic()+WORK_SECONDS;failure=None;worker_code=None;remaining=[]
 try:
  try:
   while True:
    old=ps(parent_pid)
    if old is None or old['birth']!=parent['birth'] or old['state'] in ('Z','X') or os.getppid()!=parent_pid:failure='actual Script parent exited';break
    worker_code=p.poll()
    if worker_code is not None:break
    if time.monotonic()>=deadline:failure='bounded worker deadline';break
    time.sleep(.05)
  except BaseException as e:failure=failure or 'guardian observation error: '+type(e).__name__
  if failure is not None:
   try:signal.pidfd_send_signal(pidfd,signal.SIGTERM)
   except ProcessLookupError:pass
   try:worker_code=p.wait(timeout=8)
   except subprocess.TimeoutExpired:
    try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
    except ProcessLookupError:pass
    try:worker_code=p.wait(timeout=2)
    except subprocess.TimeoutExpired:worker_code=None;failure=failure or 'worker exit unknown'
  try:
   live=[r for r in children().values() if r['state'] not in ('Z','X')]
   if live and failure is None:failure='worker left owned live descendants'
   remaining=drain(time.monotonic()+max(1,CLEANUP_SECONDS-8))
  except BaseException as e:failure=failure or 'guardian cleanup unknown: '+type(e).__name__;remaining=['UNKNOWN']
  if worker_code!=0:failure=failure or 'worker exited nonzero'
  if remaining:failure=failure or 'owned descendants remain'
  value={'schema':'maclab.native-job-supervisor/1','status':'pass' if failure is None else 'failed','worker_exit_code':worker_code,'first_failure':failure,'owned_descendants_after':remaining,'parent_pid':parent_pid,'parent_birth':parent['birth'],'parent_abort_guard':True,'kernel_subreaper':True,'job_graphics_compatibility_only':True,'ordinary_login_qualification':False};receipt(out,value);return 0 if failure is None else 1
 finally:os.close(pidfd)
