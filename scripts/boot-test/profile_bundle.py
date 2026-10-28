#!/usr/bin/env python3
"""Pack/install a finite reviewed source closure. Installation grants no execution approval."""
if not __debug__:raise RuntimeError('optimized Python forbidden')
import argparse,copy,gzip,hashlib,io,json,os,re,stat,tarfile
from pathlib import Path
import util as u
MAXFILE=64*1024**2;MAXTOTAL=256*1024**2;MAXCOUNT=512;MAXMETA=1024**2
H=u.H;need=u.need

def relative(value):
 p=Path(value);need(isinstance(value,str) and value and not p.is_absolute() and '..' not in p.parts and str(p)==value and all(x not in ('','.','..') for x in p.parts),'canonical relative member required');return p

def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)

def ancestry(p):
 need(p.is_absolute() and str(p)==str(p.absolute()) and '..' not in p.parts,'absolute canonical install path required')
 for v in (p,*p.parents):
  s=v.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.geteuid()) and (not s.st_mode&0o022 or str(v) in ('/tmp','/dev/shm') and s.st_uid==0 and s.st_mode&stat.S_ISVTX),'unsafe source/install ancestry')

def filesystem(p):
 mounts=[]
 for line in Path('/proc/self/mountinfo').read_text().splitlines():
  a,b=line.split(' - ',1);m=a.split()[4].replace('\\040',' ')
  if str(p)==m or str(p).startswith(m.rstrip('/')+'/'):mounts.append((len(m),b.split()[0]))
 need(mounts,'filesystem provenance unavailable');return max(mounts)[1]

def create(path,raw,sync=os.fsync):
 """Checked bounded writes; no retry, adoption or success receipt after any EIO."""
 need(0<len(raw)<=MAXFILE,'finite nonempty source file');ancestry(path.parent)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  for offset in range(0,len(raw),1048576):
   piece=memoryview(raw)[offset:offset+1048576]
   while piece:
    n=os.write(fd,piece);need(n>0,'short source write');piece=piece[n:]
   sync(fd)
  sync(fd)
 finally:os.close(fd)
 syncdir(path.parent);pin,back,_=u.local(str(path),limit=MAXFILE);need(back==raw,'installed file reopen differs');return pin

def json_bytes(doc):return (json.dumps(doc,sort_keys=True,indent=2)+'\n').encode()

def pointer(doc,path,value=None,write=False):
 need(path.startswith('/'),'explicit JSON pointer required');parts=path[1:].split('/');x=doc
 for item in parts[:-1]:
  key=item.replace('~1','/').replace('~0','~');x=x[int(key)] if isinstance(x,list) else x[key]
 key=parts[-1].replace('~1','/').replace('~0','~')
 if write:
  if isinstance(x,list):x[int(key)]=value
  else:x[key]=value
 else:return x[int(key)] if isinstance(x,list) else x[key]

def descriptor_relocations(doc,base,at=''):
 """Only descriptor path leaves; arbitrary strings/source text never relocate."""
 out=[]
 if isinstance(doc,dict):
  if all(k in doc for k in ('path','sha256','bytes')) and isinstance(doc['path'],str) and doc['path'].startswith(str(base)+'/'):
   rel=str(Path(doc['path']).relative_to(base));relative(rel);out.append({'pointer':at+'/path','relative':rel,'expected_path':doc['path']})
  for k,v in doc.items():out+=descriptor_relocations(v,base,at+'/'+str(k).replace('~','~0').replace('/','~1'))
 elif isinstance(doc,list):
  for i,v in enumerate(doc):out+=descriptor_relocations(v,base,at+'/'+str(i))
 return out

def pack(source,out):
 source=Path(source).absolute();out=Path(out).absolute();ancestry(source);ancestry(out.parent);manifest=u.read_json(str(source/'COMPONENTS.json'));need(manifest['schema']=='maclab.m1-source-components/1','explicit component source manifest required');files={};relocations=[]
 for name,row in manifest['files'].items():
  relative(name);pin,raw,_=u.local(str(source/name),row,MAXFILE);files[name]=(raw,0o600)
 # Explicit generated metadata joins the resource archive; raw historical freezes
 # are already in files and are never rewritten during install.
 for name in ('COMPONENTS.json','EXTERNAL-PREREQUISITES.json'):
  pin,raw,_=u.local(str(source/name),limit=MAXMETA);files[name]=(raw,0o600)
 for name in ('recipe.json','components/postinstall/CONTRACT.json'):
  raw=files[name][0];doc=u.unique(raw)
  for r in descriptor_relocations(doc,source):
   need(r['relative'] in files,'descriptor refers to absent bundled member');target=files[r['relative']][0]
   # Find exact enclosing descriptor rather than relocating a coincidental string.
   parent=r['pointer'].rsplit('/',1)[0];owner=pointer(doc,parent) if parent else doc
   need(owner['sha256']==H(target) and owner['bytes']==len(target),'relocation descriptor content mismatch');relocations.append({'file':name,**r})
 need(1<=len(files)<=MAXCOUNT and sum(len(v[0]) for v in files.values())<=MAXTOTAL,'source closure count/size bound')
 package={'schema':'maclab.reviewed-source-package/1','source_root':str(source),'files':{n:{'sha256':H(raw),'bytes':len(raw),'mode':mode} for n,(raw,mode) in sorted(files.items())},'relocations':relocations,'approval_created':False,'profile_execution_ready_created':False}
 raw=json_bytes(package);need(len(raw)<=MAXMETA,'package metadata bound');fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False) as f:
   with gzip.GzipFile(fileobj=f,mode='wb',filename='',mtime=0) as gz:
    with tarfile.open(fileobj=gz,mode='w|',format=tarfile.USTAR_FORMAT) as t:
     for name,b in [('PACKAGE.json',raw),*((n,v[0]) for n,v in sorted(files.items()))]:
      x=tarfile.TarInfo(name);x.uid=x.gid=x.mtime=0;x.mode=0o600;x.size=len(b);t.addfile(x,io.BytesIO(b))
   f.flush();os.fsync(fd)
 finally:os.close(fd)
 syncdir(out.parent);pin,_,_=u.local(str(out),limit=MAXTOTAL,contents=False);return {'archive':pin,'package_sha256':H(raw),'files':len(files),'expanded_bytes':sum(len(v[0]) for v in files.values()),'execution_approval_created':False}

def install(archive,want,prefix,validation_only=False,sync=os.fsync):
 prefix=Path(prefix).absolute();ancestry(prefix.parent);need(not prefix.exists() and not prefix.is_symlink(),'new source prefix required; no overwrite/resume');kind=filesystem(prefix.parent);need(validation_only or kind not in ('tmpfs','ramfs'),'source installation must be durable; validation-only is not executable approval')
 pin,raw,_=u.local(str(Path(archive).absolute()),want,MAXTOTAL);files={};metadata=None;total=0
 # Read bounded members in memory, not extractall: no links/devices/path traversal.
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
  for i,x in enumerate(t):
   relative(x.name);need(i<=MAXCOUNT and x.isfile() and not x.pax_headers and 0<x.size<=MAXFILE and x.name not in files,'finite unique regular source archive member');need(total+x.size<=MAXTOTAL,'expanded source package limit');f=t.extractfile(x);b=f.read(x.size+1);need(len(b)==x.size,'truncated archive member');total+=len(b)
   if metadata is None:
    need(i==0 and x.name=='PACKAGE.json' and len(b)<=MAXMETA,'package manifest must be first');metadata=u.unique(b);need(metadata['schema']=='maclab.reviewed-source-package/1' and metadata['approval_created'] is False and metadata['profile_execution_ready_created'] is False,'not an approval-producing package');need(1<=len(metadata['files'])<=MAXCOUNT and len(metadata['relocations'])<=1024,'finite package manifest');continue
   need(x.name in metadata['files'],'unlisted source member');row=metadata['files'][x.name];need(row['mode']==0o600 and row['bytes']==len(b) and row['sha256']==H(b),'source member digest/length differs');files[x.name]=b
 need(metadata is not None and set(files)==set(metadata['files']),'missing source package member')
 need(Path(metadata['source_root']).is_absolute(),'canonical original source root');seen=set()
 for r in metadata['relocations']:
  need(set(r)=={'file','pointer','relative','expected_path'},'finite exact relocation fields');relative(r['relative']);need(r['file'] in ('recipe.json','components/postinstall/CONTRACT.json') and r['relative'] in files and (r['file'],r['pointer']) not in seen,'explicit descriptor relocation only');need(r['pointer'].endswith('/path'),'descriptor path pointer required');seen.add((r['file'],r['pointer']));need(r['expected_path']==str(Path(metadata['source_root'])/r['relative']),'relocation origin differs')
  doc=u.unique(files[r['file']]);need(pointer(doc,r['pointer'])==r['expected_path'],'descriptor preimage differs');owner=pointer(doc,r['pointer'].rsplit('/',1)[0]);need(owner['sha256']==H(files[r['relative']]) and owner['bytes']==len(files[r['relative']]),'descriptor target differs');pointer(doc,r['pointer'],str(prefix/r['relative']),True);files[r['file']]=(json.dumps(doc,indent=2)+'\n').encode()
 components=u.unique(files['COMPONENTS.json']);need(components['schema']=='maclab.m1-source-components/1','expected source manifest');components['files']={n:{'sha256':H(b),'bytes':len(b)} for n,b in files.items() if n not in ('COMPONENTS.json','EXTERNAL-PREREQUISITES.json')};files['COMPONENTS.json']=json_bytes(components)
 prereq=u.unique(files['EXTERNAL-PREREQUISITES.json']);need(prereq['schema']=='maclab.profile-external-prerequisites/1' and len(prereq['pins'])<=32,'finite durable baseline prerequisites')
 for row in prereq['pins']:u.local(row['path'],row,MAXFILE,False)
 prefix.mkdir(mode=0o700);syncdir(prefix.parent);installed={}
 # Partial prefix is deliberately retained after any failed write, never adopted.
 try:
  for name,b in sorted(files.items()):
   p=prefix/relative(name);missing=[];q=p.parent
   while not q.exists():missing.append(q);q=q.parent
   for q in reversed(missing):q.mkdir(mode=0o700);syncdir(q.parent)
   installed[name]=create(p,b,sync)
  if 'PROFILE-BINDING.json' in installed:
   binding=u.unique(files['PROFILE-BINDING.json']);profile=u.unique(files['PROFILE-TEMPLATE.json']);need(binding['schema']=='maclab.source-profile-binding/1' and binding['call'] in ('compile_oneshot','compile_device') and set(binding['sources'])=={'capture','owner','rollback','final_restore'} and profile['execution_ready'] is False,'closed finite profile binding')
   def member(name):
    relative(name);need(name in installed,'profile source must belong to installed manifest');return installed[name]
   profile['sources']={role:{'source':member(row['source']),'closure':[member(n) for n in row['closure']]} for role,row in binding['sources'].items()};profile['compiler']={'source':member(binding['compiler']),'call':binding['call'],'closure':[v for n,v in sorted(installed.items()) if n!=binding['compiler']],'resources':installed['COMPONENTS.json']}
   installed['profile.CLOSED.json']=create(prefix/'profile.CLOSED.json',json_bytes(profile),sync)
   catalog={'schema':'maclab.device-test-catalog/1','status':'PENDING_ROOT_SOURCE_REVIEW','reviewed_by':'PENDING','profiles':{profile['id']:installed['profile.CLOSED.json']}}
   installed['catalog.CLOSED.json']=create(prefix/'catalog.CLOSED.json',json_bytes(catalog),sync)
  receipt={'schema':'maclab.source-package-installation/1','archive':pin,'prefix':str(prefix),'filesystem':kind,'validation_only':validation_only,'durable_installation':not validation_only,'approval_created':False,'profile_execution_ready_created':False,'fsync_and_full_reopen_verified':True,'prior_btrfs_eio_repaired':False,'components':installed['COMPONENTS.json'],'recipe':installed['recipe.json'],'files':installed,'descriptor_relocations':metadata['relocations']}
  create(prefix/'INSTALLATION.json',json_bytes(receipt),sync);return receipt
 except BaseException:
  # No second writes, cleanup, retry or success marker on uncertain storage.
  raise

def main(argv=None):
 a=argparse.ArgumentParser(description=__doc__);s=a.add_subparsers(dest='command',required=True);p=s.add_parser('pack');p.add_argument('--source',required=True);p.add_argument('--output',required=True);i=s.add_parser('install');i.add_argument('--archive',required=True);i.add_argument('--sha256',required=True);i.add_argument('--bytes',type=int,required=True);i.add_argument('--prefix',required=True);i.add_argument('--validation-only',action='store_true');x=a.parse_args(argv)
 result=pack(x.source,x.output) if x.command=='pack' else install(x.archive,{'sha256':x.sha256,'bytes':x.bytes},x.prefix,x.validation_only);print(json.dumps(result,separators=(',',':')))
if __name__=='__main__':main()
