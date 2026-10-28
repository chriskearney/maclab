"""Explicit reviewed relative source set. Never rewrites source text/target paths."""
import hashlib,json,os,re,stat
from pathlib import Path
ROLES={'mode':'components/mode','native':'components/native','stage':'components/native-stage','normal':'components/normal-return','postjob':'components/completion','writer':'components/writer','esp':'components/esp','legacy_normal':'components/legacy-normal','session':'components/session','rollback':'components/rollback','observer':'components/observer','expected_menu':'components/expected-menu','postinstall':'components/postinstall'}
def need(v,msg):
 if not v:raise RuntimeError(msg)
def unique(raw):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate source set field');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs)
def read(path,want):
 meta=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(meta);key=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns);need(stat.S_ISREG(a.st_mode) and a.st_uid in (0,os.geteuid()) and not a.st_mode&0o022 and a.st_size==want['bytes']<=64*1024**2,'owned bounded source only');fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   chunks=[];count=0
   while count<a.st_size:
    chunk=os.read(fd,min(1048576,a.st_size-count));need(chunk,'source truncated');chunks.append(chunk);count+=len(chunk)
   b=b''.join(chunks);need(not os.read(fd,1) and key(os.fstat(fd))==key(a)==key(Path(path).lstat()),'source inode drift')
  finally:os.close(fd)
  need(hashlib.sha256(b).hexdigest()==want['sha256'],'reviewed source digest differs');return b
 finally:os.close(meta)
class Sources:
 def __init__(self,root,descriptor):
  self.root=Path(root).absolute();need('..' not in self.root.parts,'canonical source root');
  for parent in (self.root,*self.root.parents):
   meta=parent.lstat();need(stat.S_ISDIR(meta.st_mode) and meta.st_uid in (0,os.geteuid()) and (not meta.st_mode&0o022 or str(parent) in ('/tmp','/dev/shm') and meta.st_mode&stat.S_ISVTX),'unsafe source ancestry')
  need(descriptor['path']==str(self.root/'COMPONENTS.json'),'source manifest must belong to this installed bundle');doc=unique(read(Path(descriptor['path']),descriptor));need(doc['schema']=='maclab.m1-source-components/1' and doc['roles']==ROLES and 1<=len(doc['files'])<=512,'exact finite component roles required');self.files={};self.freezes=doc['freezes']
  for name,row in doc['files'].items():
   need(not Path(name).is_absolute() and '..' not in Path(name).parts and str(Path(name))==name and re.fullmatch('[0-9a-f]{64}',row['sha256']) and type(row['bytes']) is int and 0<row['bytes']<=64*1024**2,'finite source leaf');path=self.root/name;self.files[path]={**row,'path':str(path)}
  for role,relative in ROLES.items():setattr(self,role,self.root/relative)
 def pin(self,path):
  path=Path(path).absolute();need('..' not in path.parts and path in self.files,'source outside explicit installed manifest');row=self.files[path];
  for parent in path.parents:
   meta=parent.lstat();need(stat.S_ISDIR(meta.st_mode) and meta.st_uid in (0,os.geteuid()) and not meta.st_mode&0o022,'unsafe component file ancestry')
   if parent==self.root:break
  read(path,row);return row
 def freeze(self,role):
  relative='compiler/producer/SOURCE-FREEZE.json' if role=='producer' else ROLES[role]+'/SOURCE-FREEZE.json';need(self.freezes[role]==relative,'fixed component freeze location');return self.pin(self.root/relative)['sha256']
