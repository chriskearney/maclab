#!/usr/bin/env python3
"""PROPOSED bounded M1 read-only metadata capture; no API/SSH/staging/controls."""
if not __debug__:raise RuntimeError('optimized Python refused')
from pathlib import Path
import base64,datetime,gzip,hashlib,json,os,re,shlex,signal,stat,subprocess,time
DEADLINE=time.monotonic()+90
def read_regular(p,max_bytes=256*1024**2,keep=False):
 # O_PATH cannot block on a FIFO/device. Reopen only its held regular inode.
 meta=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(meta);assert stat.S_ISREG(a.st_mode) and a.st_size<=max_bytes,'not a bounded regular file'
  key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid)
  fd=os.open('/proc/self/fd/'+str(meta),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  with os.fdopen(fd,'rb') as f:
   assert key(os.fstat(f.fileno()))==key(a),'reopened inode drift'
   h=hashlib.sha256();n=0;data=bytearray() if keep else None
   while n<=a.st_size:
    b=f.read(min(1048576,a.st_size+1-n))
    if not b:break
    h.update(b);n+=len(b)
    if data is not None:data.extend(b)
   assert n==a.st_size and key(os.fstat(f.fileno()))==key(a),'file changed or exceeded read bound'
  assert key(os.lstat(p))==key(a),'path/inode drift'
  return a,h.hexdigest(),bytes(data) if data is not None else None
 finally:os.close(meta)

def digest(p):return read_regular(p)[1]

def tree(root):
 """No symlink following. Backup identity, not candidate expectations."""
 root=Path(root);assert root.is_dir() and not root.is_symlink();rows={};total=0
 for base,dirs,files in os.walk(root,followlinks=False):
  for name in ['.']+dirs+files if Path(base)==root else dirs+files:
   p=Path(base) if name=='.' else Path(base)/name;rel=str(p.relative_to(root));s=p.lstat();r={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
   if stat.S_ISLNK(s.st_mode):r.update(type='l',target=os.readlink(p))
   elif stat.S_ISDIR(s.st_mode):r['type']='d'
   elif stat.S_ISREG(s.st_mode):r.update(type='f',sha256=digest(p),bytes=s.st_size);total+=s.st_size
   else:raise RuntimeError('unexpected module tree object '+rel)
   rows[rel]=r;assert len(rows)<=100000 and total<=2*1024**3,'module tree bound exceeded'
 return rows

def tree_sha(rows):return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def check_time():
 if DEADLINE and time.monotonic()>DEADLINE:raise RuntimeError('backup deadline exceeded')

def command(args,out=None,timeout=180):
 import selectors
 check_time();remain=max(1,min(timeout,int(DEADLINE-time.monotonic()) if DEADLINE else timeout));end=time.monotonic()+remain
 assert out is None,'command output files must use explicit owned writer'
 p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ,'out');sel.register(p.stderr,selectors.EVENT_READ,'err');buffers={'out':bytearray(),'err':bytearray()}
 try:
  while sel.get_map():
   if time.monotonic()>end:raise RuntimeError('command deadline: '+args[0])
   for k,_ in sel.select(min(.2,max(.001,end-time.monotonic()))):
    data=os.read(k.fileobj.fileno(),8192)
    if not data:sel.unregister(k.fileobj);continue
    buffers[k.data].extend(data)
    if len(buffers[k.data])>65536:raise RuntimeError('command output cap: '+args[0])
  code=p.wait(timeout=max(.001,end-time.monotonic()))
  if code:raise RuntimeError('command failed: '+args[0]+': '+buffers['err'][:1024].decode(errors='replace'))
  return bytes(buffers['out'])
 finally:
  sel.close()
  if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
  p.wait();p.stdout.close();p.stderr.close()

def unit_states(units):
 out={}
 for u in units:
  raw=command(['/usr/bin/systemctl','show',u,'--no-pager','--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths'],timeout=10).decode()
  fields=dict(x.split('=',1) for x in raw.splitlines() if '=' in x)
  assert fields.get('Id')==u and fields.get('LoadState') in ['loaded','not-found','masked'],'unit query ambiguous'
  out[u]=fields
 return out

PACKAGE_NAMES=['linux-aurora', 'linux-aurora-headers', 'mesa-aurora', 'vulkan-aurora', 'omarchy-mac-boot', 'm1n1-aurora', 'uboot-asahi']
CLOSURE_PATHS=['/etc/default/limine', '/etc/default/update-m1n1', '/etc/limine-entry-tool.conf', '/etc/limine-entry-tool.d/omarchy-defaults.conf', '/etc/limine-entry-tool.d/omarchy-uki.conf', '/etc/m1n1.conf', '/etc/pacman.d/hooks/10-limine-snapper-lock.hook', '/etc/pacman.d/hooks/10-linux-modules-post.hook', '/etc/pacman.d/hooks/10-linux-modules-pre.hook', '/etc/pacman.d/hooks/11-omarchy-mac-saved-modules.hook', '/etc/pacman.d/hooks/36-systemd-modules-load.hook', '/etc/pacman.d/hooks/60-depmod.hook', '/etc/pacman.d/hooks/60-limine-mkinitcpio-remove-pre.hook', '/etc/pacman.d/hooks/60-mkinitcpio-remove.hook', '/etc/pacman.d/hooks/80-limine-efi-deploy.hook', '/etc/pacman.d/hooks/90-limine-mkinitcpio-remove-post.hook', '/etc/pacman.d/hooks/90-mkinitcpio-apple-install.hook', '/etc/pacman.d/hooks/90-mkinitcpio-install.hook', '/etc/pacman.d/hooks/91-omarchy-mac-boot-initramfs.hook', '/etc/pacman.d/hooks/95-m1n1-install.hook', '/etc/pacman.d/hooks/95-omarchy-mac-dtb-overlays.hook', '/etc/systemd/system/linux-modules-cleanup.service', '/etc/systemd/system/linux-modules-cleanup.service.d/zz-keep-local-kernels.conf', '/run/systemd/system/linux-modules-cleanup.service', '/usr/bin/update-m1n1', '/usr/lib/asahi-boot/m1n1.bin', '/usr/lib/asahi-boot/u-boot-nodtb.bin', '/usr/lib/limine/limine-common-functions', '/usr/lib/systemd/system/linux-modules-cleanup.service', '/usr/lib/tmpfiles.d/linux-modules-cleanup.conf', '/usr/share/libalpm/hooks/10-limine-snapper-lock.hook', '/usr/share/libalpm/hooks/10-linux-modules-post.hook', '/usr/share/libalpm/hooks/10-linux-modules-pre.hook', '/usr/share/libalpm/hooks/11-omarchy-mac-saved-modules.hook', '/usr/share/libalpm/hooks/36-systemd-modules-load.hook', '/usr/share/libalpm/hooks/60-depmod.hook', '/usr/share/libalpm/hooks/60-limine-mkinitcpio-remove-pre.hook', '/usr/share/libalpm/hooks/60-mkinitcpio-remove.hook', '/usr/share/libalpm/hooks/80-limine-efi-deploy.hook', '/usr/share/libalpm/hooks/90-limine-mkinitcpio-remove-post.hook', '/usr/share/libalpm/hooks/90-mkinitcpio-apple-install.hook', '/usr/share/libalpm/hooks/90-mkinitcpio-install.hook', '/usr/share/libalpm/hooks/91-omarchy-mac-boot-initramfs.hook', '/usr/share/libalpm/hooks/95-m1n1-install.hook', '/usr/share/libalpm/hooks/95-omarchy-mac-dtb-overlays.hook', '/usr/share/libalpm/scripts/depmod', '/usr/share/libalpm/scripts/limine-apple-gate', '/usr/share/libalpm/scripts/limine-mkinitcpio-install', '/usr/share/libalpm/scripts/limine-mkinitcpio-remove', '/usr/share/libalpm/scripts/limine-snapper-lock', '/usr/share/libalpm/scripts/mkinitcpio', '/usr/share/libalpm/scripts/omarchy-mac-retire-saved-modules']
PROTECTED_PATHS=['/boot/efi/m1n1/boot.bin', '/boot/efi/m1n1/boot.bin.old', '/boot/efi/EFI/Linux/omarchy_linux-aurora.efi']
REFERENCE_PATHS=['/var/lib/maclab/known-good.json', '/var/lib/maclab/known-good.json.prev']
OLD_BOOT_CACHE='/var/cache/pacman/pkg/omarchy-mac-boot-20261010-1-aarch64.pkg.tar.zst'
COLLECTOR_SHA_AT_REVIEW_PLACEHOLDER=None
# Constants below are an explicit read scope, never substituted for observations.

def observed_file(path, limit=128*1024, content=False):
    path=Path(path)
    if not os.path.lexists(path):return {'absent':True}
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode):
        STOP.append('nonregular/symlink: '+str(path))
        return {'type':'symlink' if stat.S_ISLNK(st.st_mode) else 'nonregular',
                'mode':stat.S_IMODE(st.st_mode),'target':os.readlink(path) if stat.S_ISLNK(st.st_mode) else None}
    st,h,raw=read_regular(path,limit,content)
    row={'sha256':h,'bytes':st.st_size,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,
         'gid':st.st_gid,'dev':st.st_dev,'ino':st.st_ino,'mtime_ns':st.st_mtime_ns}
    if content:row['base64']=base64.b64encode(raw).decode()
    return row


def installed_packages(names):
    # Retained mtree_inventory's finite package-desc/decompressed-mtree algorithm;
    # byte reads use the owner's unchanged held-inode reader instead of read_text.
    packages={}
    for name in names:
        found=[]
        directories=sorted(Path('/var/lib/pacman/local').glob(name+'-[0-9]*'))
        if len(directories)>16:raise RuntimeError('package metadata directory bound')
        for root in directories:
            if not stat.S_ISDIR(root.lstat().st_mode):raise RuntimeError('package metadata symlink/non-directory')
            _,_,raw=read_regular(root/'desc',128*1024,True);text=raw.decode()
            def field(key):
                match=re.search('%'+key+'%\n([^\n]+)',text)
                return match.group(1) if match else None
            if field('NAME')!=name:continue
            _,_,blob=read_regular(root/'mtree',16*1024*1024,True)
            plain=gzip.decompress(blob) if blob.startswith(b'\x1f\x8b') else blob
            if len(plain)>32*1024*1024:raise RuntimeError('decompressed mtree bound')
            found.append({'version':field('VERSION'),'arch':field('ARCH'),
                          'mtree_sha256':hashlib.sha256(plain).hexdigest(),
                          'metadata_path':str(root),'desc_sha256':hashlib.sha256(raw).hexdigest()})
        if len(found)!=1:raise RuntimeError('missing/ambiguous installed package: '+name)
        packages[name]=found[0]
    return packages


def hook_and_config_closure():
    # Same bounded regular-hook/literal-Exec capture as reviewed M1 ALPM source.
    # Union adds local-only hooks; every raw hook is retained for root's complete
    # ALPM review. The historical relevance regex is not a new semantic parser.
    all_hooks={};selected={};scripts=set();total=0
    match=re.compile(r'linux-modules|mkinitcpio|limine|m1n1|asahi-boot|usr/lib/modules|omarchy-mac-boot',re.I)
    dirs=[Path('/usr/share/libalpm/hooks'),Path('/etc/pacman.d/hooks')]
    names=set()
    for directory in dirs:
        if not os.path.lexists(directory):continue
        if not stat.S_ISDIR(directory.lstat().st_mode):raise RuntimeError('hook directory symlink/non-directory')
        paths=sorted(directory.glob('*.hook'))
        if len(paths)>256:raise RuntimeError('hook namespace bound')
        names.update(path.name for path in paths)
    for name in sorted(names):
        pair=[]
        for directory in dirs:
            path=directory/name;row=observed_file(path,16*1024,True);all_hooks[str(path)]=row
            text=base64.b64decode(row['base64']).decode() if 'base64' in row else ''
            total+=row.get('bytes',0)
            if total>512*1024:raise RuntimeError('complete hook/source byte cap')
            pair.append((path,row,text))
        relevant=any(match.search(path.name) or match.search(text) or str(path) in CLOSURE_PATHS
                     for path,row,text in pair)
        if relevant:
            for path,row,text in pair:
                selected[str(path)]=row
                for line in text.splitlines():
                    literal=re.match(r'\s*Exec\s*=\s*(.+)',line)
                    if literal:
                        words=shlex.split(literal.group(1))
                        if words:
                            script=Path(words[0])
                            if script.is_absolute() and script.parent==Path('/usr/share/libalpm/scripts'):
                                scripts.add(str(script))
    if len(scripts)>16:raise RuntimeError('literal Exec source bound')
    for name in sorted(set(CLOSURE_PATHS)|scripts):
        if name not in selected:
            if name in ['/usr/lib/asahi-boot/m1n1.bin','/usr/lib/asahi-boot/u-boot-nodtb.bin']:
                # Exact known binaries: hash-only held-inode read, not text/b64 budget.
                row=observed_file(name,16*1024*1024,False)
            else:
                row=observed_file(name,128*1024,True);total+=row.get('bytes',0)
            selected[name]=row
            if total>512*1024:raise RuntimeError('selected closure total byte cap')
    config_dirs={}
    for name in ['/usr/share/limine-entry-tool.d','/etc/limine-entry-tool.d']:
        directory=Path(name)
        if not os.path.lexists(directory):config_dirs[name]=None;continue
        if not stat.S_ISDIR(directory.lstat().st_mode):raise RuntimeError('config directory symlink/non-directory')
        paths=sorted(directory.glob('*.conf'))
        if len(paths)>64:raise RuntimeError('config file count cap')
        config_dirs[name]=[path.name for path in paths]
        for path in paths:
            if str(path) not in selected:
                row=observed_file(path,16*1024,True);selected[str(path)]=row;total+=row.get('bytes',0)
                if total>512*1024:raise RuntimeError('closure/config total cap')
    return selected,all_hooks,config_dirs,total


def encode_bounded_output(value):
    payload=json.dumps(value)
    # Check the whole encoded result, including duplicate source blobs/metadata,
    # plus JSON escaping when carried as stdout in the ordinary API envelope.
    envelope=json.dumps({'stdout':payload,'stderr':'','exit_code':0})
    if max(len(payload.encode()),len(envelope.encode()))>=900*1024:
        raise RuntimeError('combined encoded capture exceeds 900KiB; INCOMPLETE, no truncation')
    return payload


def main():
    global STOP
    STOP=[]
    def expired(*_):raise RuntimeError('90s read-only capture deadline')
    signal.signal(signal.SIGALRM,expired);signal.alarm(90)
    if os.geteuid()!=0 or os.uname().machine!='aarch64':raise RuntimeError('root AArch64 m1 capture only')
    if os.path.lexists('/var/lib/pacman/db.lck'):raise RuntimeError('package transaction active')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    kernel=os.uname().release
    compatible=Path('/proc/device-tree/compatible').read_bytes()
    board='apple,j293' if b'apple,j293\0' in compatible else 'OTHER_BOARD'
    if board!='apple,j293' or kernel!='7.2.11-6-1-ARCH':raise RuntimeError('wrong board/current kernel; no inspection')
    packages=installed_packages(PACKAGE_NAMES)
    closure,hooks,config_dirs,total=hook_and_config_closure()
    files={name:observed_file(name,64*1024*1024) for name in PROTECTED_PATHS+REFERENCE_PATHS}
    menu=observed_file('/boot/efi/limine.conf',1024*1024,True)
    uboot=observed_file('/usr/lib/asahi-boot/u-boot-nodtb.bin',16*1024*1024)
    cache=observed_file(OLD_BOOT_CACHE,64*1024*1024)
    units=unit_states(['linux-modules-cleanup.service','limine-snapper-sync.service',
                       'snapper-cleanup.timer','snapper-cleanup.service'])
    unit_sources={}
    for props in units.values():
        for name in [props.get('FragmentPath',''),*props.get('DropInPaths','').split()]:
            if not name:continue
            if not name.startswith(('/usr/lib/systemd/system/','/etc/systemd/system/','/run/systemd/system/')):
                raise RuntimeError('unexpected unit fragment namespace')
            unit_sources[name]=observed_file(name,16*1024,True)
    marker=Path('/usr/lib/modules/7.2.11-6-1-ARCH/.keep-local-kernel')
    marker_meta={'path':str(marker),'absent':not os.path.lexists(marker)}
    if not marker_meta['absent']:STOP.append('preexisting old6 marker; no adoption/removal')
    masks={}
    for directory in ['/etc/systemd/system','/run/systemd/system']:
        for name in ['limine-snapper-sync.service','limine-snapper-watcher.service','snapper-cleanup.timer']:
            path=Path(directory)/name
            if not os.path.lexists(path):masks[str(path)]={'absent':True}
            else:
                st=path.lstat();masks[str(path)]={'mode':stat.S_IMODE(st.st_mode),'dev':st.st_dev,'ino':st.st_ino,
                    'type':'symlink' if stat.S_ISLNK(st.st_mode) else 'other',
                    'target':os.readlink(path) if stat.S_ISLNK(st.st_mode) else None}
    supporting_metadata={}
    for name in ['/run/lock/boot-partition.lock','/tmp/limine-global.lock',
                 '/usr/lib/systemd/system/limine-snapper-watcher.service']:
        path=Path(name)
        if not os.path.lexists(path):supporting_metadata[name]={'absent':True}
        else:
            st=path.lstat();supporting_metadata[name]={'mode':stat.S_IMODE(st.st_mode),'dev':st.st_dev,
                'ino':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,
                'type':'symlink' if stat.S_ISLNK(st.st_mode) else 'regular' if stat.S_ISREG(st.st_mode) else 'other',
                'target':os.readlink(path) if stat.S_ISLNK(st.st_mode) else None}
    module_hash=tree_sha(tree(Path('/usr/lib/modules/7.2.11-6-1-ARCH')))
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot:raise RuntimeError('boot changed')
    if os.path.lexists('/var/lib/pacman/db.lck'):raise RuntimeError('package transaction began during capture')
    if digest(Path('/boot/efi/limine.conf'))!=menu.get('sha256'):raise RuntimeError('menu changed during capture')
    check_time();signal.alarm(0)
    print(encode_bounded_output({'status':'CAPTURED' if not STOP else 'STOP','STOP':STOP,
        'scope':'bounded read-only observations; no authorization/readiness/GPU/package/boot claim',
        'captured_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'collector_sha256':COLLECTOR_SHA_AT_REVIEW_PLACEHOLDER,
        'boot_id':boot,'kernel':kernel,'board':board,'packages':packages,'closure_files':closure,
        'all_vendor_and_local_hook_sources':hooks,'fallback_config_directories':config_dirs,
        'closure_bytes':total,'protected_and_reference_files':files,'menu':menu,'uboot':uboot,
        'oldboot_cache':cache,'old6_marker':marker_meta,'units':units,'unit_sources':unit_sources,
        'six_hold_path_metadata':masks,'old_module_tree_sha256':module_hash,
        'lock_and_vendor_alias_metadata':supporting_metadata,
        'future_uki_observed':False,'prepared_menu_observed':False,'readiness_confirmed':False}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'INCOMPLETE','error':str(error),'readiness_confirmed':False,
                          'execution_authorized':False}),file=__import__('sys').stderr)
        raise SystemExit(2)
