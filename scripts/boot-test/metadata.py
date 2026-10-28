#!/usr/bin/env python3
"""Bounded source artifact metadata. Lists/reads; NEVER extracts or executes files."""
import argparse,hashlib,json,os,re,resource,stat,struct,tarfile,time
from pathlib import Path
MAX_ENTRIES=50000;MAX_TOTAL=4*1024**3;MAX_INFO=65536;MAX_MEMBER=256*1024**2
class Refused(RuntimeError):pass
def need(v,msg):
 if not v:raise Refused(msg)
def unique(raw):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs)
def normal(name):
 while name.startswith('./'):name=name[2:]
 if name in ('','.'):return ''
 need(len(name)<=4096 and not name.startswith('/') and '\x00' not in name and all(x not in ('','..','.') for x in name.rstrip('/').split('/')),'unsafe archive member path');return name.rstrip('/')
def pkginfo(raw):
 need(len(raw)<=MAX_INFO and b'\0' not in raw,'bounded text PKGINFO');values={}
 for line in raw.decode('utf-8').splitlines():
  if not line or line.startswith('#'):continue
  need(' = ' in line,'invalid PKGINFO record');k,v=line.split(' = ',1)
  if k in ('pkgname','pkgver','arch','size','builddate','pkgbase'):
   need(k not in values,'duplicate singular PKGINFO field');values[k]=v
 need(all(k in values for k in ('pkgname','pkgver','arch')),'missing PKGINFO identity');need(re.fullmatch('[a-zA-Z0-9@_.+-]{1,128}',values['pkgname']) and 1<=len(values['pkgver'])<=200 and values['arch'] in ('aarch64','any'),'package identity/architecture unsupported');return values

def config_values(raw,required):
 need(raw and len(raw)<=2*1024**2 and b'\0' not in raw,'invalid bounded source config');values={}
 for line in raw.decode('utf-8').splitlines():
  if line.startswith('CONFIG_') and '=' in line:k,v=line.split('=',1)
  elif line.startswith('# CONFIG_') and line.endswith(' is not set'):k,v=line[2:-11],'n'
  else:continue
  need(k not in values,'duplicate kernel config setting');values[k]=v
 need(all(values.get(k)==v for k,v in required.items()),'reviewed kernel config setting differs');return values

def content(t,m,limit):
 need(m.isfile() and 0<=m.size<=limit,'metadata member must be bounded regular file');f=t.extractfile(m);need(f is not None,'archive member unreadable');h=hashlib.sha256();count=0;prefix=b'';parts=[]
 while count<m.size:
  b=f.read(min(1048576,m.size-count));need(b,'truncated selected member');h.update(b);count+=len(b)
  if len(prefix)<64:prefix+=b[:64-len(prefix)]
  if limit<=2*1024**2:parts.append(b)
 need(not f.read(1),'selected member exceeds header');return {'sha256':h.hexdigest(),'bytes':count,'prefix':prefix},b''.join(parts)

def scan(path,slot):
 start=time.monotonic();p=Path(path);fd=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,os.geteuid()) and not before.st_mode&0o022 and before.st_size==slot['bytes']<=512*1024**2,'exact owned regular source required');r=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   h=hashlib.sha256()
   while True:
    b=os.read(r,1048576)
    if not b:break
    h.update(b)
   need(h.hexdigest()==slot['sha256'],'artifact hash mismatch');os.lseek(r,0,0);kind=slot['kind'];result={'schema':'maclab.artifact-source-metadata/1','kind':kind,'sha256':h.hexdigest(),'bytes':before.st_size,'runtime_execution_proved':False}
   if kind in ('arch-package','stage2-bundle'):
    selected=slot.get('expected_payload',{});need(type(selected) is dict and len(selected)<=32,'finite payload identity selectors');seen=set();count=0;total=0
    if kind=='stage2-bundle':need(len(slot['members'])==4 and set(selected)==set(slot['members']),'exact four-member Stage2 payload hashes required')
    ledger=hashlib.sha256();found={};info=None
    with os.fdopen(os.dup(r),'rb') as file,tarfile.open(fileobj=file,mode='r|*') as t:
     for member in t:
      need(time.monotonic()-start<=45,'metadata wall budget');name=normal(member.name)
      if not name:need(member.isdir(),'only root directory may have empty name');continue
      need(name not in seen,'duplicate archive member');seen.add(name);count+=1;total+=member.size;need(count<=MAX_ENTRIES and 0<=member.size<=MAX_TOTAL and total<=MAX_TOTAL,'archive count/declared-size limit');need(member.isfile() or member.isdir() or member.issym() or member.islnk(),'unsupported special archive member')
      if kind=='stage2-bundle':need(member.isfile(),'Stage2 bundle only regular members')
      ledger.update((json.dumps({'path':name,'type':member.type.decode('ascii'),'mode':member.mode,'size':member.size,'link':member.linkname},sort_keys=True,separators=(',',':'))+'\n').encode())
      if name=='.PKGINFO':
       meta,raw=content(t,member,MAX_INFO);info=pkginfo(raw)
      if name in selected:
       expected=selected[name]
       if name!='.PKGINFO':meta,raw=content(t,member,min(MAX_MEMBER,expected['bytes']))
       need(meta['sha256']==expected['sha256'] and meta['bytes']==expected['bytes'],'selected payload/build/provider identity differs');role=expected.get('role','content');need(role in ('content','arm64-image','aarch64-elf','kernel-config'),'unsupported payload identity role')
       if role=='arm64-image':need(meta['bytes']>=64 and meta['prefix'][56:60]==b'ARM\x64','invalid ARM64 Linux Image header')
       elif role=='aarch64-elf':need(meta['prefix'][:5]==b'\x7fELF\x02' and meta['prefix'][5]==1 and struct.unpack_from('<H',meta['prefix'],18)[0]==183,'non-native provider ELF')
       elif role=='kernel-config':
        config_values(raw,expected.get('required_config',{}))
       found[name]={'sha256':meta['sha256'],'bytes':meta['bytes'],'role':role}
    need(set(found)==set(selected),'reviewed payload member missing');result.update(entries=count,declared_bytes=total,archive_listing_sha256=ledger.hexdigest(),payload=found)
    if kind=='arch-package':need(info is not None and all(info.get(k)==v for k,v in slot['metadata'].items()),'reviewed package metadata mismatch');result['package']=info
    else:need(info is None and set(seen)==set(slot['members']),'stage2 bundle exact member contract mismatch');result['loader_execution_proved']=False;result['live_stage1_stage2_tag_proof_required']=True
   elif kind in ('kernel-config','provider-ledger'):
    need(before.st_size<=2*1024**2,'bounded source sidecar');raw=os.pread(r,before.st_size,0);need(b'\0' not in raw,'text source sidecar required');result['source_sidecar_only']=True
    if kind=='kernel-config':config_values(raw,slot.get('required_config',{}))
    if kind=='provider-ledger':
     rows=[unique(line) for line in raw.splitlines() if line.strip()];need(0<len(rows)<=50000,'finite provider ledger');seen=set()
     for row in rows:
      name=normal(row['path']);need(name not in seen and re.fullmatch('[0-9a-f]{64}',row['sha256']) and type(row['bytes']) is int and 0<row['bytes']<=MAX_MEMBER,'provider ledger entry invalid');seen.add(name)
     if 'providers' in slot:need({row['path']:{k:row[k] for k in ('sha256','bytes')} for row in rows}==slot['providers'],'reviewed provider ledger mismatch')
     result['ledger_entries']=len(rows)
   elif kind in ('kernel-image','opaque-reviewed'):
    if kind=='kernel-image':need(os.pread(r,4,56)==b'ARM\x64','ARM64 Image header required')
   else:raise Refused('unsupported source artifact kind')
   need(identity(os.fstat(r))==identity(before)==identity(p.lstat()),'artifact mutated during metadata scan');return result
  finally:os.close(r)
 finally:os.close(fd)
if __name__=='__main__':
 resource.setrlimit(resource.RLIMIT_CPU,(30,31));resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2));p=argparse.ArgumentParser();p.add_argument('--artifact',required=True);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--slot');g.add_argument('--slot-file');p.add_argument('--slot-file-sha256');a=p.parse_args()
 try:
  raw=a.slot
  if a.slot_file:
   fd=os.open(a.slot_file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
   try:
    st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid in (0,os.geteuid()) and not st.st_mode&0o022 and 0<st.st_size<=1048576,'bounded owned slot JSON');raw=os.read(fd,st.st_size+1);need(len(raw)==st.st_size and hashlib.sha256(raw).hexdigest()==a.slot_file_sha256,'slot JSON hash/size mismatch')
   finally:os.close(fd)
  print(json.dumps(scan(a.artifact,unique(raw)),separators=(',',':')))
 except Exception as e:print(json.dumps({'status':'SOURCE_METADATA_REFUSED','error_type':type(e).__name__,'reason':str(e) if isinstance(e,Refused) else None},separators=(',',':')));raise SystemExit(2)
