"""Fake pacman + systemctl for bt2 I2 tests.

Operates ONLY inside $BT2_TEST_ROOT (must be under /dev/shm/maclab-bt2-tests). Never touches the real system.

pacman:  -Q [names] | -Qqo PATH | -Qlq NAME | [--config C] -U [--print --print-format F | --noconfirm] -- FILES
         | [--config C] -R [--print --print-format F | --noconfirm] [--] NAMES
         Local DB = real-format dirs /var/lib/pacman/local/<name>-<ver>/{desc,files,mtree}. Real tar extraction of
         .pkg.tar.zst archives, 'exists in filesystem' conflicts, backup= .pacnew/.pacsave, db.lck, and simulated
         hooks: kernel-modules-hook (save/restore running tree, ignore-existing), depmod, UKI regeneration +
         limine auto entry rewrite, update-m1n1 (boot.bin changes only with BT2_FAKE_BOOTBIN_CHANGES=1), and the
         omarchy-mac-boot post_install that starts omarchy-mac-efi-vars.service on a first install.
         Faults: BT2_FAKE_FAIL_PKG=<name> (die mid-extraction), BT2_FAKE_HANG=1 (hang holding db.lck),
         BT2_FAKE_NO_KMOD=1 (kernel-modules-hook absent: the running tree is not saved/restored),
         BT2_FAKE_HOOK_ERROR=1 (hook error line, exit 0), BT2_FAKE_PRINT_EXTRA=<name> (extra repo target in --print),
         BT2_FAKE_NO_HOOKS=1 (fixture setup).
systemctl: show/stop/start/is-active/daemon-reload/mask/unmask over /.fake/systemd.json; masks/aliases are read
         from real symlinks in <root>/etc/systemd/system at daemon-reload time.
"""
import hashlib
import json
import os
import shutil
import sys
import tarfile
import time

UKI_CMDLINE = 'root=UUID=4f4d5801-524f-4f54-8000-000000000001 rw rootflags=subvol=@ quiet splash'
LOCAL = '/var/lib/pacman/local'
LOCK = '/var/lib/pacman/db.lck'
SD = '/.fake/systemd.json'
SAFE_PREFIX = '/dev/shm/maclab-bt2-tests/'


def root():
    r = os.environ.get('BT2_TEST_ROOT', '')
    if not r.startswith(SAFE_PREFIX) or '..' in r or not os.path.isdir(r + '/.fake'):
        sys.stderr.write('fake: refusing: BT2_TEST_ROOT must be a prepared fake root under %s\n' % SAFE_PREFIX)
        sys.exit(97)
    return r


def R(p):
    assert p.startswith('/'), p
    return root() + p


def sha(b):
    return hashlib.sha256(b).hexdigest()


def b2(b):
    return hashlib.blake2b(b, digest_size=64).hexdigest()


def flog(kind, obj):
    with open(R('/.fake/%s.log' % kind), 'a') as f:
        f.write(json.dumps(obj, sort_keys=True) + '\n')


def atomic_write(path, data, mode=0o644):
    tmp = path + '.fake-tmp'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def out(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def err(msg):
    sys.stderr.write(msg + '\n')
    sys.stderr.flush()


# -- version compare (rpmvercmp-lite) --------------------------------------------------------------
def _rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    while True:
        while i < len(a) and not a[i].isalnum():
            i += 1
        while j < len(b) and not b[j].isalnum():
            j += 1
        if i >= len(a) or j >= len(b):
            break
        si, sj = i, j
        num = a[i].isdigit()
        if num:
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
        else:
            while i < len(a) and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isalpha():
                j += 1
        x, y = a[si:i], b[sj:j]
        if not y:
            return 1 if num else -1
        if num:
            x, y = x.lstrip('0') or '0', y.lstrip('0') or '0'
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def vercmp(a, b):
    def split(v):
        e, _, rest = v.rpartition(':') if ':' in v else ('0', '', v)
        ver, _, rel = rest.rpartition('-') if '-' in rest else (rest, '', '')
        return int(e or 0), ver, rel
    ea, va, ra = split(a)
    eb, vb, rb = split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    r = _rpmvercmp(va, vb)
    if r or not ra or not rb:
        return r
    return _rpmvercmp(ra, rb)


# -- local DB --------------------------------------------------------------------------------------
def parse_sections(text):
    res, cur = {}, None
    for line in text.split('\n'):
        if len(line) > 2 and line.startswith('%') and line.endswith('%'):
            cur = line[1:-1]
            res[cur] = []
        elif line == '':
            cur = None
        elif cur:
            res[cur].append(line)
    return res


def read_db():
    d = R(LOCAL)
    db = {}
    for e in sorted(os.listdir(d)):
        p = os.path.join(d, e)
        if not os.path.isdir(p):
            continue
        with open(p + '/desc') as f:
            desc = parse_sections(f.read())
        with open(p + '/files') as f:
            files = parse_sections(f.read())
        name, ver = desc['NAME'][0], desc['VERSION'][0]
        backup = {}
        for line in files.get('BACKUP', []):
            k, h = line.split('\t')
            backup[k] = h
        db[name] = {'name': name, 'version': ver, 'dir': p, 'files': files.get('FILES', []), 'backup': backup,
                    'depends': desc.get('DEPENDS', [])}
    return db


def write_db(a, backup_hashes):
    d = R(LOCAL) + '/%s-%s' % (a.name, a.version)
    os.makedirs(d)
    desc = '%%NAME%%\n%s\n\n%%VERSION%%\n%s\n\n' % (a.name, a.version)
    if a.depends:
        desc += '%DEPENDS%\n' + '\n'.join(a.depends) + '\n\n'
    files = '%FILES%\n' + '\n'.join(a.filelist()) + '\n\n'
    if backup_hashes:
        files += '%BACKUP%\n' + '\n'.join('%s\t%s' % kv for kv in sorted(backup_hashes.items())) + '\n\n'
    with open(d + '/desc', 'w') as f:
        f.write(desc)
    with open(d + '/files', 'w') as f:
        f.write(files)
    with open(d + '/mtree', 'wb') as f:
        f.write(a.mtree)


def owners(db, rel):
    rel = rel.strip('/')
    return [n for n, p in db.items() if rel in p['files'] or rel + '/' in p['files']]


# -- archives --------------------------------------------------------------------------------------
class Archive:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self.mtree = b''
        info = ''
        with tarfile.open(path, 'r:*') as tf:
            for m in tf.getmembers():
                n = m.name[2:] if m.name.startswith('./') else m.name
                n = n.rstrip('/')
                if n == '.PKGINFO':
                    info = tf.extractfile(m).read().decode()
                elif n == '.MTREE':
                    self.mtree = tf.extractfile(m).read()
                elif n.startswith('.'):
                    continue
                elif m.isdir():
                    self.entries.append((n, 'd', m.mode, None, m.mtime))
                elif m.issym():
                    self.entries.append((n, 'l', m.mode, m.linkname, m.mtime))
                elif m.isreg():
                    self.entries.append((n, 'f', m.mode, tf.extractfile(m).read(), m.mtime))
        kv = {}
        for line in info.splitlines():
            if ' = ' in line:
                k, v = line.split(' = ', 1)
                kv.setdefault(k, []).append(v)
        self.name = kv['pkgname'][0]
        self.version = kv['pkgver'][0]
        self.depends = kv.get('depend', [])
        self.backup = kv.get('backup', [])

    def filelist(self):
        return sorted(n + '/' if t == 'd' else n for n, t, _, _, _ in self.entries)

    def has_prefix(self, pre):
        return any(n.startswith(pre) for n, _, _, _, _ in self.entries)

    def kernels(self):
        out = []
        for n, t, _, _, _ in self.entries:
            parts = n.split('/')
            if t == 'f' and len(parts) == 5 and parts[:3] == ['usr', 'lib', 'modules'] and parts[4] == 'vmlinuz':
                out.append(parts[3])
        return out


# -- hooks -----------------------------------------------------------------------------------------
def build_uki(krel, vmlinuz, cmdline=UKI_CMDLINE):
    return b'FAKE-UKI\0' + krel.encode() + b'\0' + cmdline.encode() + b'\0' + vmlinuz


def copy_ignore_existing(src, dst):
    if not os.path.lexists(dst):
        os.mkdir(dst)
        shutil.copystat(src, dst, follow_symlinks=False)
    for e in sorted(os.listdir(src)):
        s, d = os.path.join(src, e), os.path.join(dst, e)
        if os.path.islink(s):
            if not os.path.lexists(d):
                os.symlink(os.readlink(s), d)
        elif os.path.isdir(s):
            copy_ignore_existing(s, d)
        elif not os.path.lexists(d):
            shutil.copy2(s, d)


def hook_kmod_pre():
    if os.environ.get('BT2_FAKE_NO_KMOD') == '1':      # kernel-modules-hook absent: running tree not protected
        return
    krel = os.environ.get('BT2_TEST_UNAME_R', '')
    src = R('/usr/lib/modules/' + krel)
    if krel and os.path.isdir(src) and not os.path.islink(src):
        os.makedirs(R('/usr/lib/modules/backup'), exist_ok=True)
        dst = R('/usr/lib/modules/backup/' + krel)
        if not os.path.lexists(dst):
            shutil.copytree(src, dst, symlinks=True)
        out('(kmod) Saving Linux kernel modules of %s ...' % krel)


def hook_kmod_post():
    krel = os.environ.get('BT2_TEST_UNAME_R', '')
    b = R('/usr/lib/modules/backup/' + krel)
    if krel and os.path.isdir(b):
        copy_ignore_existing(b, R('/usr/lib/modules/' + krel))
        shutil.rmtree(R('/usr/lib/modules/backup'))
        out('(kmod) Restoring Linux kernel modules of %s ...' % krel)


def depmod(krel):
    d = R('/usr/lib/modules/' + krel)
    if not os.path.isdir(d + '/kernel'):
        return
    kos = []
    for base, _, files in os.walk(d + '/kernel'):
        for f in files:
            if f.endswith('.ko'):
                kos.append(os.path.relpath(os.path.join(base, f), d))
    atomic_write(d + '/modules.dep', ('\n'.join('%s:' % k for k in sorted(kos)) + '\n').encode(), 0o644)


def update_menu(pkg, krel, rel, uki):
    p = R('/boot/efi/limine.conf')
    with open(p) as f:
        lines = f.read().split('\n')
    pin = b2(uki)
    hit = None
    for i, line in enumerate(lines):
        if line.strip() == 'comment: kernel-id=' + pkg:
            # entry block: header above i, options below until the next header
            j = i + 1
            path_i = None
            while j < len(lines) and not lines[j].strip().startswith('/') and '# maclab: begin' not in lines[j]:
                if lines[j].strip().startswith('path: boot():/EFI/Linux/'):
                    path_i = j
                j += 1
            if path_i is not None:
                hit = (i, path_i)
                break
    if hit:
        i, path_i = hit
        k = i - 1
        while k >= 0 and not lines[k].strip().startswith('/'):
            if lines[k].strip().startswith('comment: Kernel version:'):
                ind = lines[k][:len(lines[k]) - len(lines[k].lstrip())]
                lines[k] = ind + 'comment: Kernel version: ' + krel
            k -= 1
        ind = lines[path_i][:len(lines[path_i]) - len(lines[path_i].lstrip())]
        lines[path_i] = ind + 'path: boot():/%s#%s' % (rel, pin)
    else:
        # append a new kernel entry at the end of the auto-generated OS block (first '/+' block)
        start = next(i for i, l in enumerate(lines) if l.startswith('/+'))
        end = next((i for i in range(start + 1, len(lines))
                    if (lines[i].startswith('/') and not lines[i].startswith('//')) or '# maclab: begin' in lines[i]),
                   len(lines))
        while end > start + 1 and lines[end - 1].strip() == '':
            end -= 1
        block = ['  //' + pkg, '  ### This kernel entry is auto-generated by limine-entry-tool',
                 '  comment: Kernel version: ' + krel, '  comment: kernel-id=' + pkg + ' ', '  protocol: efi',
                 '  path: boot():/%s#%s' % (rel, pin), '  cmdline: ' + UKI_CMDLINE]
        lines[end:end] = block
    atomic_write(p, '\n'.join(lines).encode(), os.stat(p).st_mode & 0o777)


def hook_uki(pkgs):
    db = read_db()
    for pkg in pkgs:
        if pkg not in db:
            continue
        for f in db[pkg]['files']:
            parts = f.split('/')
            if len(parts) == 5 and parts[:3] == ['usr', 'lib', 'modules'] and parts[4] == 'vmlinuz':
                krel = parts[3]
                with open(R('/' + f), 'rb') as fh:
                    vml = fh.read()
                uki = build_uki(krel, vml)
                rel = 'EFI/Linux/omarchy_%s.efi' % pkg
                atomic_write(R('/boot/efi/' + rel), uki, 0o755)
                update_menu(pkg, krel, rel, uki)
                out('(uki) ==> Building UKI for %s (%s) -> %s' % (pkg, krel, rel))


def hook_m1n1():
    out('(m1n1) update-m1n1: rebuilding m1n1 stage 2')
    if os.environ.get('BT2_FAKE_BOOTBIN_CHANGES') == '1':
        bb = R('/boot/efi/m1n1/boot.bin')
        with open(bb, 'rb') as f:
            old = f.read()
        # update-m1n1 keeps the previous boot.bin as .old; BT2_FAKE_BOOTBIN_OLD makes it keep something else
        atomic_write(bb + '.old', os.environ.get('BT2_FAKE_BOOTBIN_OLD', '').encode() or old)
        atomic_write(bb, old + b'\n+candidate-dtbs\n')


def post_install_boot():
    sd = sd_load()
    sd['units']['omarchy-mac-efi-vars.service'] = {
        'ActiveState': 'active', 'SubState': 'exited', 'UnitFileState': 'static',
        'FragmentPath': '/usr/lib/systemd/system/omarchy-mac-efi-vars.service', 'DropInPaths': ''}
    sd_save(sd)
    out('(post_install) starting omarchy-mac-efi-vars.service')


# -- pacman ----------------------------------------------------------------------------------------
def _fmt(fmt, name, ver, loc):
    return fmt.replace('%n', name).replace('%v', ver).replace('%l', loc)


def _deps_ok(db, targets, removing=()):
    have = {n for n in db if n not in removing} | {a.name for a in targets}
    for a in targets:
        for d in a.depends:
            dn = d.split('>')[0].split('<')[0].split('=')[0]
            if dn not in have:
                return "unable to satisfy dependency '%s' required by %s" % (d, a.name)
    return None


def take_lock():
    try:
        fd = os.open(R(LOCK), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(fd)
        return True
    except FileExistsError:
        err('error: failed to init transaction (unable to lock database)')
        err('error: could not lock database: File exists')
        return False


def release_lock():
    try:
        os.unlink(R(LOCK))
    except FileNotFoundError:
        pass


def do_upgrade(files, fmt, printing):
    db = read_db()
    out('loading packages...')
    targets = [Archive(R(f)) for f in files]
    for a, f in zip(targets, files):
        a.loc = f
    out('resolving dependencies...')
    bad = _deps_ok(db, targets)
    if bad:
        err('error: failed to prepare transaction (could not satisfy dependencies)')
        err(':: ' + bad)
        return 1
    if printing:
        for a in targets:
            old = db.get(a.name)
            if old and vercmp(a.version, old['version']) < 0:
                err('warning: downgrading package %s (%s => %s)' % (a.name, old['version'], a.version))
            elif old and vercmp(a.version, old['version']) == 0:
                err('warning: %s-%s is up to date -- reinstalling' % (a.name, a.version))
        for a in targets:
            out(_fmt(fmt, a.name, a.version, a.loc))
        extra = os.environ.get('BT2_FAKE_PRINT_EXTRA')
        if extra:
            out(_fmt(fmt, extra, '2.4.999-1', 'https://mirror.example/extra/%s-2.4.999-1-aarch64.pkg.tar.zst' % extra))
        return 0
    if not take_lock():
        return 1
    try:
        return _commit_upgrade(db, targets)
    finally:
        if os.environ.get('BT2_FAKE_HANG') != '1':
            release_lock()


def _commit_upgrade(db, targets):
    if os.environ.get('BT2_FAKE_HANG') == '1':
        if os.fork() == 0:
            time.sleep(300)
            os._exit(0)
        time.sleep(300)
    out('looking for conflicting packages...')
    conflicts = []
    for a in targets:
        old = db.get(a.name)
        oldfiles = set(old['files']) if old else set()
        for n, t, _, _, _ in a.entries:
            if t == 'd':
                continue
            p = R('/' + n)
            if not os.path.lexists(p) or n in oldfiles:
                continue
            others = [o for o in owners(db, n) if o != a.name]
            if others:
                conflicts.append('%s: /%s exists in both \'%s\' and \'%s\'' % (a.name, n, a.name, others[0]))
            else:
                conflicts.append('%s: /%s exists in filesystem' % (a.name, n))
    if conflicts:
        err('error: failed to commit transaction (conflicting files)')
        for x in conflicts:
            err(x)
        err('Errors occurred, no packages were upgraded.')
        return 1
    hooks = os.environ.get('BT2_FAKE_NO_HOOKS') != '1'
    touches_modules = any(a.has_prefix('usr/lib/modules/') for a in targets) or any(
        any(f.startswith('usr/lib/modules/') for f in db[a.name]['files']) for a in targets if a.name in db)
    out(':: Running pre-transaction hooks...')
    if hooks and touches_modules:
        hook_kmod_pre()
    out(':: Processing package changes...')
    fresh_boot = False
    for idx, a in enumerate(targets, 1):
        old = db.get(a.name)
        verb = 'installing' if not old else ('downgrading' if vercmp(a.version, old['version']) < 0 else 'upgrading')
        out('(%d/%d) %s %s' % (idx, len(targets), verb, a.name))
        if a.name == 'omarchy-mac-boot' and not old:
            fresh_boot = True
        new_set = set(a.filelist())
        others_files = set()
        for n, p in db.items():
            if n != a.name:
                others_files.update(p['files'])
        if old:
            for f in sorted(old['files'], reverse=True):
                if f in new_set or f in others_files:
                    continue
                p = R('/' + f.rstrip('/'))
                if f.endswith('/'):
                    try:
                        os.rmdir(p)
                    except OSError:
                        pass
                elif os.path.lexists(p):
                    os.unlink(p)
        fail = os.environ.get('BT2_FAKE_FAIL_PKG') == a.name
        files_written = 0
        nfiles = sum(1 for e in a.entries if e[1] != 'd')
        backup_hashes = {}
        for n, t, mode, data, mtime in a.entries:
            p = R('/' + n)
            if t == 'd':
                os.makedirs(p, exist_ok=True)
                os.chmod(p, mode & 0o7777)
                continue
            if fail and files_written >= max(1, nfiles // 2):
                err('error: could not extract /%s (Write error)' % n)
                err('error: failed to commit transaction (unexpected error)')
                err('Errors occurred, no packages were upgraded.')
                return 1
            if t == 'l':
                if os.path.lexists(p):
                    os.unlink(p)
                os.symlink(data, p)
            else:
                if n in a.backup:
                    backup_hashes[n] = sha(data)
                    if old and os.path.lexists(p) and n in old['backup']:
                        with open(p, 'rb') as f:
                            live = sha(f.read())
                        if live != old['backup'][n] and live != sha(data):
                            atomic_write(p + '.pacnew', data, mode & 0o7777)
                            err('warning: /%s installed as /%s.pacnew' % (n, n))
                            files_written += 1
                            continue
                atomic_write(p, data, mode & 0o7777)
                os.utime(p, (mtime, mtime))
            files_written += 1
        if old:
            shutil.rmtree(old['dir'])
        write_db(a, backup_hashes)
        db = read_db()
    out(':: Running post-transaction hooks...')
    if hooks:
        if touches_modules:
            hook_kmod_post()
        for a in targets:
            for k in a.kernels():
                depmod(k)
                out('(depmod) Updating module dependencies for %s' % k)
        uki_pkgs = [a.name for a in targets if a.kernels()]
        if any(a.name == 'omarchy-mac-boot' for a in targets):   # boot package install => rebuild_all
            uki_pkgs = sorted(set(uki_pkgs) | {n for n, p in db.items()
                                               if any(f.endswith('/vmlinuz') and f.startswith('usr/lib/modules/')
                                                      for f in p['files'])})
        hook_uki(uki_pkgs)
        if any(a.has_prefix('usr/lib/modules/') and any('/dtbs/' in e[0] for e in a.entries) for a in targets):
            hook_m1n1()
        if fresh_boot:
            post_install_boot()
        if os.environ.get('BT2_FAKE_HOOK_ERROR') == '1':
            out('(hook) ==> ERROR: fake hook failure')
            err('error: command failed to execute correctly')
    return 0


def do_remove(names, fmt, printing):
    db = read_db()
    out('checking dependencies...')
    for n in names:
        if n not in db:
            err('error: target not found: %s' % n)
            return 1
    for n, p in db.items():
        if n in names:
            continue
        for d in p['depends']:
            if d.split('>')[0].split('<')[0].split('=')[0] in names:
                err('error: failed to prepare transaction (could not satisfy dependencies)')
                err(":: removing %s breaks dependency '%s' required by %s" % (d, d, n))
                return 1
    if printing:
        for n in names:
            out(_fmt(fmt, n, db[n]['version'], '%s-%s' % (n, db[n]['version'])))
        return 0
    if not take_lock():
        return 1
    try:
        hooks = os.environ.get('BT2_FAKE_NO_HOOKS') != '1'
        mods = any(any(f.startswith('usr/lib/modules/') for f in db[n]['files']) for n in names)
        if hooks and mods:
            hook_kmod_pre()
        out(':: Processing package changes...')
        for idx, n in enumerate(names, 1):
            out('(%d/%d) removing %s' % (idx, len(names), n))
            others = set()
            for m, p in db.items():
                if m not in names:
                    others.update(p['files'])
            for f in sorted(db[n]['files'], reverse=True):
                if f in others:
                    continue
                p = R('/' + f.rstrip('/'))
                if f.endswith('/'):
                    try:
                        os.rmdir(p)
                    except OSError:
                        pass
                elif os.path.lexists(p):
                    if f in db[n]['backup'] and not os.path.islink(p):
                        with open(p, 'rb') as fh:
                            live = sha(fh.read())
                        if live != db[n]['backup'][f]:
                            os.rename(p, p + '.pacsave')
                            err('warning: /%s saved as /%s.pacsave' % (f, f))
                            continue
                    os.unlink(p)
            shutil.rmtree(db[n]['dir'])
        if hooks and mods:
            hook_kmod_post()
        return 0
    finally:
        release_lock()


def pacman(argv):
    flog('pacman', {'argv': argv, 'env': {k: v for k, v in os.environ.items() if k.startswith('BT2_FAKE')}})
    config, fmt, ops, flags, targets, dd = None, None, [], set(), [], False
    i = 0
    while i < len(argv):
        a = argv[i]
        if dd:
            targets.append(a)
        elif a == '--':
            dd = True
        elif a == '--config':
            config = argv[i + 1]
            i += 1
        elif a == '--print-format':
            fmt = argv[i + 1]
            i += 1
        elif a in ('--print', '--noconfirm'):
            flags.add(a)
        elif a.startswith('--'):
            err('error: unknown option %s' % a)
            return 1
        elif a.startswith('-'):
            ops.append(a[1:])
        else:
            targets.append(a)
        i += 1
    if config is not None:
        with open(R(config), 'rb') as f:
            raw = f.read()
        sections = [l.split(b'#', 1)[0].strip().decode() for l in raw.splitlines()
                    if l.split(b'#', 1)[0].strip().startswith(b'[')]
        flog('pacman-config', {'path': config, 'sha256': sha(raw), 'sections': sections})
    op = ''.join(ops)
    if op == 'Q':
        db = read_db()
        rc = 0
        for n in (targets or sorted(db)):
            if n in db:
                out('%s %s' % (n, db[n]['version']))
            else:
                err("error: package '%s' was not found" % n)
                rc = 1
        return rc
    if sorted(op) == sorted('Qqo'):
        # Like real pacman: every target is answered (owners on stdout, one error line per unowned/missing
        # path on stderr); exit 1 if any target was unowned or missing. capture.py batches paths after '--'.
        db = read_db()
        rc = 0
        for p in targets:
            if not os.path.lexists(R(p)):
                err("error: failed to find '%s' in PATH: No such file or directory" % p)
                rc = 1
                continue
            own = owners(db, p)
            if not own:
                err('error: No package owns %s' % p)
                rc = 1
                continue
            for n in own:
                out(n)
        return rc
    if sorted(op) == sorted('Qlq'):
        db = read_db()
        if targets[0] not in db:
            err("error: package '%s' was not found" % targets[0])
            return 1
        for f in db[targets[0]]['files']:
            out('/' + f)
        return 0
    if op == 'U':
        return do_upgrade(targets, fmt or '%l', '--print' in flags)
    if op == 'R':
        return do_remove(targets, fmt or '%n-%v', '--print' in flags)
    err('error: unsupported fake operation %r' % op)
    return 1


# -- systemctl -------------------------------------------------------------------------------------
def sd_load():
    with open(R(SD)) as f:
        return json.load(f)


def sd_save(sd):
    atomic_write(R(SD), json.dumps(sd, indent=1, sort_keys=True).encode())


def compute_view(sd, name):
    etc = R('/etc/systemd/system/' + name)
    if os.path.islink(etc) and os.readlink(etc) == '/dev/null':
        return 'mask'
    if name in sd['aliases']:
        return 'alias' if os.path.islink(etc) else 'none'
    frag = (sd['units'].get(name) or {}).get('FragmentPath') or '/usr/lib/systemd/system/' + name
    if os.path.lexists(R(frag)) or os.path.lexists(etc):
        return 'unit'
    return 'none'


def view(sd, name):
    v = sd['views'].get(name)
    return v if v is not None else compute_view(sd, name)


def props(sd, name):
    v = view(sd, name)
    base = sd['units'].get(name) or {}
    if v == 'mask':
        return {'Id': name, 'LoadState': 'masked', 'ActiveState': base.get('ActiveState', 'inactive'),
                'SubState': base.get('SubState', 'dead'), 'UnitFileState': 'masked',
                'FragmentPath': '/etc/systemd/system/' + name, 'DropInPaths': ''}
    if v == 'alias':
        return props(sd, sd['aliases'][name])
    if v == 'unit':
        d = {'ActiveState': 'inactive', 'SubState': 'dead', 'UnitFileState': 'disabled',
             'FragmentPath': '/usr/lib/systemd/system/' + name, 'DropInPaths': ''}
        etc = R('/etc/systemd/system/' + name)
        if os.path.isfile(etc) and not os.path.islink(etc) and 'FragmentPath' not in base:
            # a unit file of its own in /etc/systemd/system: enabled when some *.wants/ links to it
            wants = [w for w in os.listdir(R('/etc/systemd/system')) if w.endswith('.wants')
                     and os.path.islink(R('/etc/systemd/system/%s/%s' % (w, name)))]
            d.update(FragmentPath='/etc/systemd/system/' + name, UnitFileState='enabled' if wants else 'disabled')
        d.update(base)
        if not os.path.lexists(R(d['FragmentPath'])):
            return {'Id': name, 'LoadState': 'not-found', 'ActiveState': d['ActiveState'], 'SubState': d['SubState'],
                    'UnitFileState': '', 'FragmentPath': '', 'DropInPaths': ''}
        return {'Id': name, 'LoadState': 'loaded', **d}
    return {'Id': name, 'LoadState': 'not-found', 'ActiveState': base.get('ActiveState', 'inactive'),
            'SubState': base.get('SubState', 'dead'), 'UnitFileState': '', 'FragmentPath': '', 'DropInPaths': ''}


def resolve(sd, name):
    return sd['aliases'][name] if view(sd, name) == 'alias' else name


def systemctl(argv):
    sd = sd_load()
    flog('systemctl', {'argv': argv})
    want, rest = None, []
    for a in argv:
        if a.startswith('--property='):
            want = a.split('=', 1)[1].split(',')
        elif a in ('--no-pager', '--quiet', '--no-block'):
            continue
        else:
            rest.append(a)
    verb, names = rest[0], rest[1:]
    if verb == 'show':
        for n in names:
            p = props(sd, n)
            for k in (want or sorted(p)):
                out('%s=%s' % (k, p.get(k, '')))
        return 0
    if verb == 'is-active':
        p = props(sd, names[0])
        out(p['ActiveState'])
        return 0 if p['ActiveState'] == 'active' else 3
    if verb == 'daemon-reload':
        known = set(sd['units']) | set(sd['aliases']) | set(sd['views'])
        etc = R('/etc/systemd/system')
        known |= {e for e in os.listdir(etc) if '.' in e and not os.path.isdir(os.path.join(etc, e))}
        sd['views'] = {n: compute_view(sd, n) for n in sorted(known)}
        sd['reloads'] = sd.get('reloads', 0) + 1
        sd_save(sd)
        return 0
    if verb in ('stop', 'start'):
        for n in names:
            v = view(sd, n)
            if verb == 'start' and v == 'mask':
                err('Failed to start %s: Unit %s is masked.' % (n, n))
                return 1
            if v == 'none' and n not in sd['units']:
                err('Failed to %s %s: Unit %s not loaded.' % (verb, n, n))
                return 5
            t = resolve(sd, n)
            u = sd['units'].setdefault(t, {})
            if verb == 'stop':
                u['ActiveState'], u['SubState'] = 'inactive', 'dead'
            else:
                u['ActiveState'], u['SubState'] = 'active', ('waiting' if t.endswith('.timer') else 'running')
        sd_save(sd)
        return 0
    if verb in ('mask', 'unmask'):
        for n in names:
            p = R('/etc/systemd/system/' + n)
            if verb == 'mask':
                if os.path.lexists(p):
                    if os.path.islink(p) and os.readlink(p) == '/dev/null':
                        continue
                    err('Failed to mask unit: File %s already exists.' % p)
                    return 1
                os.symlink('/dev/null', p)
            elif os.path.islink(p) and os.readlink(p) == '/dev/null':
                os.unlink(p)
        return 0
    err('fake systemctl: unsupported verb %s' % verb)
    return 1
