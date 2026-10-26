#!/usr/bin/env python3
"""Finite immediate-readiness wrapper; exact package owners remain unchanged.
Re-executes fresh technical observation at each actual install/PacketC attempt,
then delegates to the reviewed direct-agent execv transport. No cached gate.
"""
import argparse,hashlib,json,os,stat,types
from pathlib import Path
SDK='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
TECH='ff997259d1371c5fff49557218d469b9041127365d930bae3d81dfc3545284e7'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def load(name,filename,want):
 p=Path(__file__).with_name(filename);meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(meta);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,os.geteuid()) and not before.st_mode&0o022 and before.st_size<=1048576,'unsafe reviewed invocation source');fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:raw=os.pread(fd,before.st_size+1,0);need(len(raw)==before.st_size and key(os.fstat(fd))==key(before)==key(p.lstat()) and H(raw)==want,'invocation source identity/hash drift')
  finally:os.close(fd)
 finally:os.close(meta)
 m=types.ModuleType(name);m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__);return m
def sources():return load('fixed_owner_sdk','frozen-controller-ea3.py',SDK),load('fixed_technical','technical.py',TECH)
def run(b,api=None):
 need(b['action']=='invoke-packet' and b['entry'] in ('install','rollback-packages') and b['deadline_seconds']==1900,'finite original owner invocation only')
 need(b['expected_kernel']=='7.2.11-6-1-ARCH' if b['entry']=='install' else b['expected_kernel'] in ('7.2.11-6-1-ARCH','7.2.11-7-1-ARCH'),'owner phase kernel mismatch')
 s,t=sources();client=api or s.API(s.config());observed=t.observe({'profile':b['profile'],'root_plan_sha256':b['root_scope']['root_plan_sha256'],'expected_boot_id':b['expected_boot_id'],'expected_kernel':b['expected_kernel'],'minimum_lease_seconds':1990},client)
 # The call is deliberately adjacent. SDK performs its own fresh live state,
 # lease and exact source/scope gates before unchanged direct-agent execv.
 out=s.run(b,client);return {**out,'fresh_invocation_technical':observed,'invocation_source_sha256':H(Path(__file__).read_bytes()),'completion_claim':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())),separators=(',',':')))
