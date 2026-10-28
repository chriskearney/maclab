"""CPU-only admission/lifetime controls; importing this module opens no GPU."""
import contextlib, errno, importlib.util, json, os, signal, stat, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from unittest import mock
spec=importlib.util.spec_from_file_location('mr',Path(__file__).with_name('mesa_runtime.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class RuntimeTests(unittest.TestCase):
 def test_special_inode_never_data_opened(self):
  with tempfile.TemporaryDirectory() as d:
   fifo=Path(d)/'fifo';os.mkfifo(fifo);real=os.open
   for p in ('/dev/null',str(fifo)):
    calls=[]
    def checked(path,flags,*a):calls.append((str(path),flags));return real(path,flags,*a)
    with mock.patch.object(m.os,'open',checked),self.assertRaises(m.Stop):m.sha(p)
    self.assertTrue(calls);self.assertTrue(all(flags&os.O_PATH for _,flags in calls))
 def test_regular_and_alias_hash(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'regular';p.write_bytes(b'known');self.assertEqual(m.sha(p),m.hashlib.sha256(b'known').hexdigest());alias=Path(d)/'alias';alias.symlink_to(p)
   with self.assertRaises(m.Stop):m.sha(alias)
 def test_fresh_faults_and_wrong_boot_rejected(self):
  good={'_BOOT_ID':'ab'*16,'MESSAGE':'ordinary event'};m.validate_journal((json.dumps(good)+'\n').encode(),'ab'*16)
  for text in ('apple-dart 123.dart: DART fault at 0x123','asahi: GPU timeout','WARNING: kernel issue','GPU memory accounting underflow'):
   bad={**good,'MESSAGE':text}
   with self.assertRaises(m.Stop):m.validate_journal((json.dumps(bad)+'\n').encode(),'ab'*16)
  with self.assertRaises(m.Stop):m.validate_journal((json.dumps(good)+'\n').encode(),'cd'*16)
 def test_correctness_and_actual_provider_required(self):
  manifest={'providers':{'egl':'usr/lib/libEGL_mesa.so','gallium':'usr/lib/libgallium-x.so','vulkan':'usr/lib/libvulkan_asahi.so'}};seen={'files':set(manifest['providers'].values()),'render_node':True,'system':False,'complete':{(1,1)}};text='Renderer: Apple M1 (G13G B1)\nPASS: 4 runs in 3.0 s, 0 with wrong pixels\n';self.assertIn('Apple M1',m.admit_probe('gl',text,seen,manifest))
  for bad in (text.replace('0 with','1 with'),text.replace('Apple M1','llvmpipe'),text.replace('PASS:','DONE:')):
   with self.assertRaises(m.Stop):m.admit_probe('gl',bad,seen,manifest)
  for change in ({'render_node':False},{'system':True},{'files':{'usr/lib/libEGL_mesa.so'}}):
   with self.assertRaises(m.Stop):m.admit_probe('gl',text,{**seen,**change},manifest)
 def test_mapped_regular_unknown_drift_and_deleted(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)/'root';p=root/'usr/lib/libvulkan_asahi.so';p.parent.mkdir(parents=True);p.write_bytes(b'VK');st=p.stat();line=f'1000-2000 r-xp 0000 {os.major(st.st_dev):x}:{os.minor(st.st_dev):x} {st.st_ino} {p}\n';manifest={'root':str(root),'files':{'usr/lib/libvulkan_asahi.so':{'sha256':m.sha(p)}}};found,system=m.graphics_maps(line,manifest,{},mapped_reference=lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW));self.assertEqual(found,{'usr/lib/libvulkan_asahi.so'});self.assertFalse(system)
   fake_device=line.split();fake_device[3]='00:24';changed=' '.join(fake_device)+'\n';found,_=m.graphics_maps(changed,manifest,{},mapped_reference=lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW));self.assertEqual(found,{'usr/lib/libvulkan_asahi.so'})
   with self.assertRaises(m.Stop):m.graphics_maps(changed,manifest,{})
   from types import SimpleNamespace
   wrong=SimpleNamespace(st_dev=st.st_dev+1,st_ino=st.st_ino,st_mode=st.st_mode,st_size=st.st_size,st_mtime_ns=st.st_mtime_ns,st_ctime_ns=st.st_ctime_ns,st_uid=st.st_uid,st_gid=st.st_gid)
   with mock.patch.object(m.os,'fstat',return_value=wrong),self.assertRaises(m.Stop):m.graphics_maps(changed,manifest,{},mapped_reference=lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW))
   foreign=Path(d)/'other';foreign.write_bytes(b'VK')
   with self.assertRaises(m.Stop):m.graphics_maps(changed,manifest,{},mapped_reference=lambda r,p:os.open(foreign,os.O_PATH|os.O_NOFOLLOW))
   for text in (line.replace(str(st.st_ino),str(st.st_ino+1)),line.rstrip()+' (deleted)\n'):
    with self.assertRaises(m.Stop):m.graphics_maps(text,manifest,{},mapped_reference=lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW))
   q=Path(d)/'libvulkan_unknown.so';q.write_bytes(b'unknown');st=q.stat();line=f'1000-2000 r-xp 0000 {os.major(st.st_dev):x}:{os.minor(st.st_dev):x} {st.st_ino} {q}\n'
   with self.assertRaises(m.Stop):m.graphics_maps(line,manifest,{},mapped_reference=lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW))
 def test_clean_child_environment(self):
  p={'gui_env':{'XDG_RUNTIME_DIR':'/run/user/1000','LIBGL_ALWAYS_SOFTWARE':'1','LD_PRELOAD':'bad'}};manifest={'prefix':'/owned/job','root':'/owned/job/root','vulkan_json':'/owned/job/vulkan.json','egl_json':'/owned/job/egl.json'};env=m.child_env(p,manifest);self.assertNotIn('LIBGL_ALWAYS_SOFTWARE',env);self.assertNotIn('LD_PRELOAD',env);self.assertEqual(env['VK_DRIVER_FILES'],manifest['vulkan_json']);self.assertEqual(env['RENDER_CHECK_RENDERER'],'Apple');self.assertEqual(env['RENDER_CHECK_DEVICE'],'Apple')
 def state(self,plan,unit,desc,inv='a'*32,terminal=False):
  return {'LoadState':'loaded','Description':desc,'Transient':'yes','User':str(plan['gui_uid']),'Group':str(plan['gui_gid']),'Type':'exec','RemainAfterExit':'yes','KillMode':'control-group','SendSIGKILL':'yes','RuntimeMaxUSec':'20s','ActiveState':'active','SubState':'exited' if terminal else 'running','ControlGroup':'' if terminal else '/system.slice/'+unit,'InvocationID':inv,'MainPID':'0' if terminal else '42','ExecMainCode':'1' if terminal else '0','ExecMainStatus':'0','Result':'success'}
 def test_missing_cgroup_requires_fresh_same_invocation_terminal(self):
  plan={'gui_uid':1000,'gui_gid':1000};unit='owned.service';desc='owned';running=self.state(plan,unit,desc);done=self.state(plan,unit,desc,terminal=True)
  with tempfile.TemporaryDirectory() as d,mock.patch.object(m,'CGROUP_ROOT',Path(d)),mock.patch.object(m,'unit_state',return_value=done):
   pids,actual=m.members(unit,running,plan,desc,'a'*32);self.assertEqual(pids,[]);self.assertEqual(actual['SubState'],'exited')
  for bad in (running,{**done,'InvocationID':'b'*32},{**done,'ExecMainStatus':'1'}):
   with tempfile.TemporaryDirectory() as d,mock.patch.object(m,'CGROUP_ROOT',Path(d)),mock.patch.object(m,'unit_state',return_value=bad),self.assertRaises(m.Stop):m.members(unit,running,plan,desc,'a'*32)
 def test_capture_enforces_real_cpu_timeout_and_output_cap(self):
  with self.assertRaises(m.Stop):m.capture([sys.executable,'-c','import time;time.sleep(5)'],timeout=.1)
  with self.assertRaises(m.Stop):m.capture([sys.executable,'-c','print("x"*100000)'],limit=100)
 def test_actual_signal_runs_owned_cleanup_and_preserves_failure(self):
  source=str(Path(__file__).with_name('mesa_runtime.py'))
  with tempfile.TemporaryDirectory() as d:
   program=r'''
import importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('mr',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
out=Path(sys.argv[2]);child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True);(out/'child.pid').write_text(str(child.pid));plan={'job':'j1026-010203-abcd','gui_uid':os.getuid(),'gui_gid':os.getgid(),'boot_id':'a'*32};manifest={'prefix':str(out),'providers':{'egl':'egl','gallium':'gallium','vulkan':'vulkan'},'probes':{'gl':{'path':'/approved/probe','sha256':'f'*64}}};unit='maclab-mesa-'+plan['job']+'-gl.service';desc='maclab-mesa:'+plan['job']+':'+'f'*64;calls=[0]
def state(u):
 calls[0]+=1
 if calls[0]==1:return {'LoadState':'not-found'}
 return {'LoadState':'loaded','Description':desc,'Transient':'yes','User':str(os.getuid()),'Group':str(os.getgid()),'Type':'exec','RemainAfterExit':'yes','KillMode':'control-group','SendSIGKILL':'yes','RuntimeMaxUSec':'20s','ActiveState':'active','SubState':'running','ControlGroup':'/system.slice/'+unit,'InvocationID':'a'*32,'MainPID':str(child.pid),'ExecMainCode':'0','ExecMainStatus':'0','Result':'success'}
def capture(argv,**kw):
 if argv[:2]==['systemctl','stop']:
  os.killpg(child.pid,signal.SIGTERM);child.wait(timeout=2);(out/'cleanup').write_text('stopped');return b''
 return b''
m.unit_state=state;m.capture=capture;m.cursor=lambda:'cursor';m.health=lambda p:{};m.identity=lambda p:None;m.scan_journal=lambda *a:b'';m.members=lambda *a:([child.pid],state(unit));m.observe=lambda *a:None;m.CGROUP_ROOT=out/'absent';signal.signal(signal.SIGTERM,m.cancelled);signal.signal(signal.SIGHUP,m.cancelled)
(out/'ready').write_text('yes')
try:m.probe('gl',plan,manifest,{}, {},out)
except BaseException:(out/'failed').write_text('notpass');raise
'''
   p=subprocess.Popen([sys.executable,'-c',program,source,d],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   try:
    deadline=time.monotonic()+3
    while not (Path(d)/'gl.unit-start.json').exists() and time.monotonic()<deadline:time.sleep(.01)
    self.assertTrue((Path(d)/'gl.unit-start.json').exists());p.send_signal(signal.SIGTERM);self.assertNotEqual(p.wait(timeout=5),0);self.assertEqual((Path(d)/'cleanup').read_text(),'stopped');self.assertTrue((Path(d)/'failed').exists())
   finally:
    if p.poll() is None:p.kill();p.wait()
    pidfile=Path(d)/'child.pid'
    if pidfile.exists():
     try:os.killpg(int(pidfile.read_text()),signal.SIGKILL)
     except ProcessLookupError:pass

class MapLifetimeControls(unittest.TestCase):
 def mapping(self,p):return {'pid':123,'birth':456,'range':'1000-2000','perms':'r-xp','offset':0,'path':str(p),'maps_device':'00:24','inode':p.stat().st_ino,'deleted':False}
 def test_retained_cache_hashes_once_but_rechecks_exact_ranges(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'libvulkan_asahi.so';p.write_bytes(b'checked bytes');row=self.mapping(p);w=m.MapWitnesses();real=m.hash_held;reads=[]
   def digest(fd):reads.append(fd);return real(fd)
   try:
    with mock.patch.object(m,'hash_held',digest),mock.patch.object(m,'current_mapping') as checked:
     for _ in range(3):m.bind_mapping(row,m.sha(p),w,lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW))
     self.assertEqual(len(reads),1);self.assertEqual(checked.call_count,6);self.assertTrue(w.bindings);self.assertTrue(w.hashes)
    p.write_bytes(b'changed bytes')
    with self.assertRaises(m.Stop):m.bind_mapping(row,m.hashlib.sha256(b'checked bytes').hexdigest(),w,lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW),check_current=False)
   finally:w.close()
   self.assertEqual(w.hashes,{})
 def test_completion_requires_prior_complete_same_birth_exact_range_and_fixed_grace(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'libEGL_mesa.so';p.write_bytes(b'known');row=self.mapping(p);w=m.MapWitnesses()
   try:
    m.bind_mapping(row,m.sha(p),w,lambda r,p:os.open(p,os.O_PATH|os.O_NOFOLLOW),check_current=False);seen={'complete':{(123,456)},'env_complete':{(123,456)}};c=m.CompletionState()
    with mock.patch.object(m.time,'monotonic',return_value=10):c.begin(123,456,'retired',seen,w,row)
    with mock.patch.object(m.time,'monotonic',return_value=12):c.begin(123,456,'other',seen,w,row)
    self.assertEqual(c.deadline,15)
    with mock.patch.object(m.time,'monotonic',return_value=16),self.assertRaises(m.Stop):c.check()
    for edits in ({'birth':457},{'range':'2000-3000'}):
     with self.assertRaises(m.Stop):m.CompletionState().begin(123,456,'retired',seen,w,{**row,**edits})
    with self.assertRaises(m.Stop):m.CompletionState().begin(123,456,'retired',{'complete':set()},w,row)
    c=m.CompletionState();c.remember([row],123,456);self.assertIsNone(c.deadline)
    replacement={**row,'path':str(p)+'-different'}
    # Even an otherwise pinned new provider cannot overwrite the first complete
    # address witness before an old-range retirement event gets delivered.
    w.bindings[w.key(replacement)]=w.bindings[w.key(row)]
    c.remember([replacement],123,456)
    with self.assertRaises(m.Stop):c.check_addresses([replacement])
    c=m.CompletionState();c.begin(123,456,'retired',seen,w,row)
    with self.assertRaises(m.Stop):c.check_addresses([replacement])
   finally:w.close()
 def test_no_first_or_cross_process_combined_provider_pass(self):
  manifest={'providers':{'egl':'EGL','gallium':'Gallium','vulkan':'VK'}};text='Renderer: Apple M1\nPASS: 3 runs in 3.0 s, 0 with wrong pixels\n';seen={'files':{'EGL','Gallium'},'render_node':True,'system':False,'complete':set()}
  with self.assertRaises(m.Stop):m.admit_probe('gl',text,seen,manifest)
  self.assertFalse(m.terminal({'ActiveState':'active','SubState':'exited','MainPID':'0','ExecMainCode':'1','ExecMainStatus':'1','Result':'success'}))



class RuntimeFollowupControls(unittest.TestCase):
 def test_nonregular_graphics_path_stops_before_data_open(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'libvulkan_unknown.so';os.mkfifo(p);line=f'1000-2000 r-xp 0 00:24 {p.lstat().st_ino} {p}\n';real=os.open;calls=[]
   def opened(p,f,*a):calls.append((str(p),f));return real(p,f,*a)
   with mock.patch.object(m.os,'open',opened),self.assertRaises(m.Stop):m.graphics_maps(line,{'root':str(Path(d)/'root'),'files':{}},{},pid=123,birth=456)
   self.assertEqual(calls,[])
 def test_proc_esrch_is_typed_and_unrelated_errors_stay_errors(self):
  import errno
  for leaf in ('stat','status','maps','environ','cmdline'):
   with mock.patch.object(Path,'read_bytes',side_effect=ProcessLookupError(errno.ESRCH,'gone')),self.assertRaises(m.ProcUnavailable) as e:m.proc_read(123,leaf,456)
   self.assertEqual((e.exception.pid,e.exception.birth,e.exception.phase,e.exception.errno),(123,456,leaf,errno.ESRCH))
  with mock.patch.object(Path,'read_bytes',side_effect=PermissionError('denied')),self.assertRaises(PermissionError):m.proc_read(123,'maps',456)
 def test_complete_requires_checked_banner_and_actual_environment(self):
  self.assertTrue(m.work_banner('gl','gl-render-check: 64x64 clear + 48x48 triangle, 3 s\n'))
  for t in ('gl-render-check: 64x64 clear + 48x48 triangle, 3 s (no check)','gl-render-check: 64x64 clear + 48x48 triangle, 1 s'):
   self.assertFalse(m.work_banner('gl',t))
  with mock.patch.object(m,'proc_read',return_value=b'RENDER_CHECK_RENDERER=llvmpipe\0'),self.assertRaises(m.Stop):m.probe_environment(123,456,{'RENDER_CHECK_RENDERER':'Apple'})
 def lifecycle(self,missing=False,wrong=False,drift=False,no_oracle=False,exitcode=0,exec_drift=False,during_scan=False,statusrace=False):
  # Real CPU process, mmap/unmap, PID/birth/status/environ/exe and exit. Only
  # inaccessible map_files opening and the absent GPU render descriptor are
  # substituted. This is not a native-driver/device qualification fixture.
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)/'root';lib=root/'usr/lib/libvulkan_asahi.so';lib.parent.mkdir(parents=True);lib.write_bytes(b'x'*4096);other=lib.with_name('libvulkan_unknown.so');other.write_bytes(b'y'*4096)
   program="""import mmap,os,sys,time
f=open(os.environ['TEST_LIBRARY'],'rb');v=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
print('vk-render-check: 64x64 clear + 48x48 triangle, 3 s',flush=True)
sys.stdin.buffer.read(1);v.close()
if os.environ['TEST_WRONG']=='1':g=open(os.environ['TEST_OTHER'],'rb');v=mmap.mmap(g.fileno(),0,access=mmap.ACCESS_READ)
if os.environ['TEST_EXEC']=='1':os.execv(sys.executable,[sys.executable,'-c','import time;time.sleep(5)'])
print('retired',flush=True);sys.stdin.buffer.read(1)
if os.environ['TEST_ORACLE']=='1':print('Device: Apple M1\\nPASS: 3 runs in 3.0 s, 0 with wrong pixels',flush=True)
sys.exit(int(os.environ['TEST_EXIT']))
"""
   script=Path(d)/'3';script.write_text(program);tool={'path':str(Path(sys.executable).resolve())};tool['sha256']=m.sha(tool['path']);env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONCOERCECLOCALE':'0','TEST_LIBRARY':str(lib),'TEST_OTHER':str(other),'TEST_WRONG':str(int(wrong)),'TEST_EXEC':str(int(exec_drift)),'TEST_ORACLE':str(int(not no_oracle)),'TEST_EXIT':str(exitcode),'RENDER_CHECK_RENDERER':'Apple','RENDER_CHECK_DEVICE':'Apple'}
   proc=subprocess.Popen([tool['path'],'3'],cwd=d,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);w=m.MapWitnesses();seen={'leader':proc.pid,'files':set(),'system':False,'render_node':False};c=m.CompletionState();manifest={'root':str(root),'files':{'usr/lib/libvulkan_asahi.so':{'sha256':m.sha(lib)}},'providers':{'vulkan':'usr/lib/libvulkan_asahi.so'}};real=os.open
   def opened(path,flags,*a):
    if str(path).startswith(f'/proc/{proc.pid}/map_files/'):
     maps=Path(f'/proc/{proc.pid}/maps').read_text();rg=str(path).rsplit('/',1)[1];line=next((x for x in maps.splitlines() if x.split()[0]==rg),None)
     if line is None:raise FileNotFoundError(2,'retired')
     return real(line.split(None,5)[5],flags|os.O_NOFOLLOW,*a)
    return real(path,flags,*a)
   try:
    text=proc.stdout.readline().decode();self.assertTrue(m.work_banner('vulkan',text))
    with mock.patch.object(m.os,'open',opened),mock.patch.object(m,'probe_render_node',return_value=True):
     if not missing:m.observe([proc.pid],tool,manifest,{},seen,os.getuid(),set(manifest['providers'].values()),w,env,'vulkan',text,c)
     if not missing:self.assertTrue(seen.get('complete'))
     if drift:lib.write_bytes(b'z'*4096)
     def retire():proc.stdin.write(b'u');proc.stdin.flush();self.assertEqual(proc.stdout.readline(),b'retired\n')
     realcheck=m.current_mapping;realread=Path.read_bytes;fired=[]
     def check(row):
      if not fired:fired.append(True);retire()
      return realcheck(row)
     def read(path):
      if str(path)==f'/proc/{proc.pid}/status' and not fired:fired.append(True);raise ProcessLookupError(errno.ESRCH,'transient owned status')
      return realread(path)
     if not during_scan:
      if exec_drift:proc.stdin.write(b'u');proc.stdin.flush();time.sleep(.05)
      else:retire()
     with contextlib.ExitStack() as stack:
      if during_scan:stack.enter_context(mock.patch.object(m,'current_mapping',check))
      if statusrace:stack.enter_context(mock.patch.object(Path,'read_bytes',read))
      m.observe([proc.pid],tool,manifest,{},seen,os.getuid(),set(manifest['providers'].values()),w,env,'vulkan',text,c)
     if missing:m.admit_probe('vulkan',text+'Device: Apple M1\nPASS: 3 runs in 3.0 s, 0 with wrong pixels\n',seen,manifest)
     self.assertTrue(c.events)
     proc.stdin.write(b'e');proc.stdin.flush();tail,err=proc.communicate(timeout=2);self.assertEqual(err,b'');c.check();w.verify_live();m.need(m.terminal({'ActiveState':'active','SubState':'exited','MainPID':'0','ExecMainCode':'1','ExecMainStatus':str(proc.returncode),'Result':'success'}),'genuine nonzero process exit');m.admit_probe('vulkan',text+tail.decode(),seen,manifest)
     self.assertTrue(m.terminal_process(proc.pid,next(iter(seen['complete']))[1]))
   finally:
    w.close()
    if proc.poll() is None:proc.kill();proc.wait(timeout=2)
    for f in (proc.stdin,proc.stdout,proc.stderr):
     if f and not f.closed:f.close()
 def test_actual_alive_unmap_can_complete_with_same_birth_proof(self):self.lifecycle()
 def test_actual_range_retires_during_mapping_scan_and_must_rescan(self):self.lifecycle(during_scan=True)
 def test_actual_observer_esrch_status_retries_full_owned_boundary(self):self.lifecycle(statusrace=True)
 def test_actual_unmap_missing_first_witness_cannot_pass(self):
  with self.assertRaises((m.Stop,AssertionError)):self.lifecycle(missing=True)
 def test_actual_new_unknown_provider_and_live_file_drift_cannot_pass(self):
  for kw in ({'wrong':True},{'drift':True}):
   with self.subTest(kw=kw),self.assertRaises(m.Stop):self.lifecycle(**kw)
 def test_actual_same_birth_exec_drift_cannot_pass(self):
  with self.assertRaises(m.Stop):self.lifecycle(exec_drift=True)
 def test_actual_nonzero_and_missing_oracle_cannot_pass(self):
  for kw in ({'exitcode':7},{'no_oracle':True}):
   with self.subTest(kw=kw),self.assertRaises((m.Stop,AssertionError)):self.lifecycle(**kw)



class OfficialIdentityControls(unittest.TestCase):
 def fixture(self,d):
  home=Path(d);state=home/'.local/state';keydir=state/'omarchy-m-test';keydir.mkdir(parents=True,mode=0o700);os.chmod(keydir,0o700);private=keydir/'machine-key';public=keydir/'machine-key.pub';private.write_bytes(b'never read private fixture');private.chmod(0o600);public.write_bytes(b'ssh-ed25519 TEST-FIXTURE-PUBLIC\n');public.chmod(0o644);return {'gui_home':str(home),'gui_uid':os.getuid(),'gui_gid':os.getgid(),'signing_state_home':str(state),'signing_public_sha256':m.sha(public),'manifest_path':str(home/'private/job/manifest.json')},private,public
 def capture(self,p):
  read=Path.read_bytes
  def bytes_(path):return b'apple,j313\0apple,t8103\0apple,arm-platform\0' if str(path)=='/proc/device-tree/compatible' else read(path)
  with mock.patch.object(Path,'read_bytes',bytes_),mock.patch.object(m,'render_node',return_value={'path':'/dev/dri/renderD128','major':226,'minor':128,'mode':0o666,'uid':0,'gid':987,'dev':7,'inode':9}):return m.capture_official_identity(p)
 def test_explicit_existing_signing_identity_never_opens_private_or_creates(self):
  with tempfile.TemporaryDirectory() as d:
   p,private,public=self.fixture(d);real=os.open;seen=[]
   def opened(path,flags,*a):seen.append((str(path),flags));return real(path,flags,*a)
   with mock.patch.object(m.os,'open',opened):identity=self.capture(p)
   self.assertTrue(seen);self.assertFalse(any(path==str(private) or flags&(os.O_CREAT|os.O_TRUNC|os.O_WRONLY) for path,flags in seen));self.assertEqual(identity['signing']['state_home'],p['signing_state_home']);self.assertEqual(identity['signing']['public_sha256'],p['signing_public_sha256']);self.assertEqual(identity['device']['board'],'j313');self.assertEqual(identity['device']['soc'],'t8103');self.assertEqual(identity['device']['render_node']['minor'],128)
 def test_missing_wrong_private_prefix_or_drift_identity_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   p,private,public=self.fixture(d);before=self.capture(p)
   for change in ({'signing_state_home':''},{'signing_state_home':str(Path(p['gui_home'])/'../outside')},{'signing_public_sha256':'0'*64},{'signing_state_home':str(Path(p['manifest_path']).parent/'state')},{'gui_uid':p['gui_uid']+1}):
    with self.subTest(change=change),self.assertRaises((m.Stop,OSError)):self.capture({**p,**change})
   private.chmod(0o644)
   with self.assertRaises(m.Stop):self.capture(p)
   private.chmod(0o600);public.write_bytes(b'changed public')
   with self.assertRaises(m.Stop):self.capture(p)
 def test_signing_symlinks_never_followed(self):
  with tempfile.TemporaryDirectory() as d:
   p,private,public=self.fixture(d);public.unlink();public.symlink_to(private)
   with self.assertRaises(m.Stop):self.capture(p)

if __name__=='__main__':unittest.main()
