#!/usr/bin/env python3
"""Create a reproducible, relocatable frontend resource archive; never install/run."""
import argparse,gzip,hashlib,io,json,os,tarfile
from pathlib import Path
import catalog
SOURCES=('intake.py','catalog.py','metadata.py','runtime.py','util.py','frozen-controller-ea3.py','profile_bundle.py')
LAUNCHER=b'''#!/usr/bin/python3
import os,sys
from pathlib import Path
entry=Path(__file__).resolve().parent.parent/'share/maclab/boot-test/intake.py'
os.execv('/usr/bin/python3',['/usr/bin/python3','-E','-B',str(entry),*sys.argv[1:]])
'''
def make(root,out):
 root=Path(root);out=Path(out);files={}
 for name in SOURCES:
  p=root/name;s=p.lstat();pin={'path':str(p.absolute()),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':s.st_size};files['share/maclab/boot-test/'+name]=catalog.read_pin(pin)
 files['bin/lab-boot-test']=LAUNCHER
 manifest={'schema':'maclab.boot-test-resource-bundle/1','requires':'Linux Python >=3.14 (compression.zstd), reviewed lab-workflow runner and explicit reviewed catalog descriptors','files':{n:{'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'mode':0o755 if n.startswith('bin/') else 0o644} for n,b in sorted(files.items())},'profiles_bundled':False,'hardware_qualification':False}
 files['share/maclab/boot-test/BUNDLE.json']=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode()
 fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:
  with gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0) as gz:
   with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as tar:
    for n,b in sorted(files.items()):
     info=tarfile.TarInfo(n);info.size=len(b);info.mode=0o755 if n.startswith('bin/') else 0o644;info.uid=info.gid=info.mtime=0;info.uname=info.gname='';tar.addfile(info,io.BytesIO(b))
  f.flush();os.fsync(f.fileno())
 d=os.open(out.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);raw=out.read_bytes();return {'path':str(out.absolute()),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'manifest':manifest}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',default=str(Path(__file__).resolve().parent));p.add_argument('--output',required=True);a=p.parse_args();print(json.dumps(make(a.source_root,a.output),sort_keys=True))
