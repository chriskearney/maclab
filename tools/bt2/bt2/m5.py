#!/usr/bin/env python3
"""Generic M5 off-controller retention for bt2 runs.

Each run gets a NEW private directory under the existing M5 retention base:
  /Users/chriskearney/.local/share/maclab/recovery-retained/bt2-<run-id>/
Files are written once (O_EXCL), fsynced, reopened and hash-verified on the M5.
Never reinitialises, adopts or overwrites an existing directory or file.
Transport: strict known-host SSH alias 'm5' (BatchMode, StrictHostKeyChecking=yes).
"""
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import time

BASE = '/Users/chriskearney/.local/share/maclab/recovery-retained'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlias=m5',
       '-o', 'ConnectTimeout=10', 'chriskearney@m5.local']
RUN_RE = re.compile(r'^[a-z0-9][a-z0-9-]{3,80}$')
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$')

REMOTE = r'''
import hashlib,json,os,stat,sys,socket
from pathlib import Path
BASE=Path(%(base)r)
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns]
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def safe(p):
 for q in [p,*p.parents]:
  if not os.path.lexists(q):continue
  s=q.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'unsafe ancestry '+str(q)
def verify(path,size,sha):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd);assert stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600 and st.st_size==size
  h=hashlib.sha256();n=0
  while True:
   b=os.read(fd,1048576)
   if not b:break
   h.update(b);n+=len(b)
  assert n==size and h.hexdigest()==sha,'remote hash mismatch'
 finally:os.close(fd)
 return {'path':str(path),'sha256':sha,'bytes':size,'identity':ident(os.lstat(path)),'fsync_reopen_match':True}
def main():
 assert sys.platform=='darwin'
 os.umask(0o077)
 action=sys.argv[1];root=BASE/sys.argv[2];assert root.parent==BASE
 if action=='init':
  safe(BASE);assert not os.path.lexists(root),'run root exists; never adopt'
  fs=os.statvfs(BASE);need=int(sys.argv[3]);assert fs.f_bavail*fs.f_frsize>=need+256*1024**2,'M5 space'
  root.mkdir(mode=0o700);syncdir(BASE)
  s=root.stat();print(json.dumps({'root':str(root),'dev':s.st_dev,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'free_bytes':fs.f_bavail*fs.f_frsize,'hostname':socket.gethostname()}));return
 safe(root);name=sys.argv[3];assert '/' not in name and name not in ('.','..');path=root/name
 size=int(sys.argv[4]);sha=sys.argv[5]
 if action=='write':
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   h=hashlib.sha256();n=0
   while n<size:
    b=sys.stdin.buffer.read(min(1048576,size-n));assert b,'truncated stream'
    os.write(fd,b);h.update(b);n+=len(b)
   assert not sys.stdin.buffer.read(1),'extra data';os.fsync(fd);assert h.hexdigest()==sha
  finally:os.close(fd)
  syncdir(root);print(json.dumps(verify(path,size,sha)));return
 if action=='verify':print(json.dumps(verify(path,size,sha)));return
 raise SystemExit('unknown action')
main()
''' % {'base': BASE}


class M5Error(RuntimeError):
    pass


def _run(args, data=None, timeout=600):
    cmd = shlex.join(['/usr/bin/python3', '-E', '-B', '-c', REMOTE, *args])
    p = subprocess.Popen([*SSH, cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True)
    try:
        out, err = p.communicate(input=data, timeout=timeout)
    except BaseException:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        raise
    if p.returncode != 0:
        raise M5Error('M5 %s refused: %s' % (args[0], err.decode(errors='replace')[-800:]))
    return json.loads(out)


class Retainer:
    """One retention root per run. init() once, then put() files (each name once)."""

    def __init__(self, run_id, runner=_run):
        if not RUN_RE.match(run_id):
            raise M5Error('bad run id')
        self.root = 'bt2-' + run_id
        self.runner = runner
        self.storage = None

    def init(self, expected_bytes):
        self.storage = self.runner(['init', self.root, str(int(expected_bytes))], timeout=60)
        s = self.storage
        if not (s['mode'] == 0o700 and s['uid'] == 501 and s['gid'] == 20):
            raise M5Error('unexpected M5 storage identity: %r' % s)
        return s

    def put(self, name, data):
        if not NAME_RE.match(name):
            raise M5Error('bad retained name')
        sha = hashlib.sha256(data).hexdigest()
        res = self.runner(['write', self.root, name, str(len(data)), sha], data=data,
                          timeout=max(120, len(data) // (4 * 1024 * 1024) + 120))
        if res['sha256'] != sha or res['bytes'] != len(data) or not res['fsync_reopen_match']:
            raise M5Error('M5 write verification mismatch for ' + name)
        again = self.runner(['verify', self.root, name, str(len(data)), sha], timeout=120)
        if again['sha256'] != sha or again['identity'] != res['identity']:
            raise M5Error('M5 reverify mismatch for ' + name)
        return {'name': name, 'remote_path': res['path'], 'sha256': sha, 'bytes': len(data),
                'identity': res['identity'], 'at': time.time()}
