#!/usr/bin/env python3
"""Fixed --binding composition for exact independently reviewed M5 retention.
Only dependency paths and literal CLI arguments adapt; retained core bytes and
all target/remote identity, hashes, budgets, independent-copy checks stay intact.
"""
import argparse,hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
PINS={'mirror_reuse.py':'099baa9be7766bbf4025c6740099d4c372b424b03792cc58ed0f5a2ef540dc49','reuse_remote.py':'01e7a921ae724a2eed00c1a3041c6657c8296da790f4cf248820be546bcc0d61','mirror-m5-ssh.py':'2da24f72f7e240d9a0d0c8892df0a0095bd942995c107216960a3b834efcf9ab','retain-controller.py':'66ee32ba1561e7637eb27fe460330645c50d211280adf55167de24a2d29af71d'}
def need(v,msg):
 if not v:raise RuntimeError(msg)
def pinned(path,expected):
 meta=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(meta);need(stat.S_ISREG(s.st_mode) and not s.st_mode&0o022 and s.st_size<=1048576,'unsafe retention closure')
  fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   b=os.read(fd,s.st_size+1);key=lambda t:(t.st_dev,t.st_ino,t.st_mode,t.st_uid,t.st_gid,t.st_size,t.st_mtime_ns,t.st_ctime_ns);need(len(b)==s.st_size and key(os.fstat(fd))==key(s)==key(Path(path).lstat()),'retention closure drift')
  finally:os.close(fd)
  need(hashlib.sha256(b).hexdigest()==expected,'retention closure SHA mismatch');return b
 finally:os.close(meta)
def write_new(path,b):
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(b)
  while view:n=os.write(fd,view);need(n>0,'short request write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 need(path.read_bytes()==b,'request/dependency reopened bytes mismatch');d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(d)
 finally:os.close(d)
def load(name,path,expected):
 b=pinned(path,expected);m=type(sys)(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(b,str(path),'exec'),m.__dict__);return m

def run(binding,here=None,executor=None):
 here=Path(here or __file__).parent
 # Go RunHelper places the explicit closure flat in its private attempt dir.
 # Normal source-tree CPU validation may select the tracked core subdirectory.
 core=here if (here/'mirror_reuse.py').exists() else here/'retention-core'
 blobs={n:pinned(core/n,h) for n,h in PINS.items()}
 rr=load('reuse_remote',core/'reuse_remote.py',PINS['reuse_remote.py']);mirror=load('reviewed_mirror_reuse',core/'mirror_reuse.py',PINS['mirror_reuse.py'])
 # Preserve the frozen old adapter's expected directory structure using only
 # these exact copied bytes. No historical main() or old state gate is invoked.
 dep=here/'retention-dependencies';dep.mkdir(mode=0o700);sub=dep/'v1-executed-source';sub.mkdir(mode=0o700)
 write_new(dep/'mirror-m5-ssh.py',blobs['mirror-m5-ssh.py']);write_new(sub/'retain-controller.py',blobs['retain-controller.py'])
 mirror.FROZEN=dep/'mirror-m5-ssh.py'  # path-only adaptation, SHA constant unchanged
 request=binding['request'];need(request['root_plan_sha256']==binding['root_plan_sha256'],'actual workflow identity binding mismatch')
 need(binding['mode'] in ('main','supplement') and binding['source_holder'],'explicit retention mode/holder required')
 mirror.validate(request)
 if binding['mode']=='supplement':mirror.validate_supplement(request,request['source'],Path(request['destination']))
 raw=(json.dumps(request,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=262144,'bounded retention request required');path=here/'retention-request.json';write_new(path,raw)
 argv=[str(core/'mirror_reuse.py'),'--request',str(path),'--request-sha256',hashlib.sha256(raw).hexdigest(),'--source-holder',binding['source_holder']]
 if binding['mode']=='supplement':argv.append('--append-supplement')
 before=sys.argv
 try:
  sys.argv=argv
  # CPU tests may inspect the actual loaded module and exact prepared CLI;
  # runtime always invokes the unchanged reviewed core's main function.
  return mirror.main() if executor is None else executor(mirror,argv)
 finally:sys.argv=before
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();run(json.loads(x.binding.read_bytes()))
