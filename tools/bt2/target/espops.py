"""bt2 esp-prep, esp-restore, etc-restore (SPEC sections 'esp-prep' and 'esp-restore + etc-restore').

All limine.conf / ESP mutations run under flock(/run/lock/boot-partition.lock) and CAS the menu against the
bytes we expect. Every write: temp + fsync + rename (+ dir fsync) + readback. Nothing is ever deleted that
bt2 did not create: extras are moved to <run>/hold/ (cleanup removes hold/ only after a final audit).
"""
import contextlib
import errno
import fcntl
import json
import os
import shutil
import stat
import time

import common as c
import limine
import capture as cap

LOCK = '/run/lock/boot-partition.lock'
RESERVE_DEFAULT = 120 << 20
MiB = 1 << 20
UKI_HEADROOM = 4 * MiB   # room for a candidate UKI larger than the one it replaces (M1 R5: 60219392 + 4 MiB)
PROTECTED_PREFIXES = ('efi/boot/', 'efi/limine/')
PROTECTED_FILES = ('limine.conf', 'm1n1/boot.bin', 'm1n1/boot.bin.old')


# ---------------------------------------------------------------- lock

@contextlib.contextmanager
def boot_lock(timeout=120.0):
    """flock the shared boot-partition mutex; create it (root 0644, O_EXCL|O_NOFOLLOW) only if missing."""
    p = c.P(LOCK)
    created = False
    try:
        try:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            try:
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
                os.fchmod(fd, 0o644)
                created = True
            except FileExistsError:
                fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise c.Refused('boot lock %s is a symlink' % LOCK)
        raise
    try:
        st = os.fstat(fd)
        c.need(stat.S_ISREG(st.st_mode), 'boot lock is not a regular file')
        if not c.TEST_ROOT:
            # /run/lock is sticky: a root-owned file cannot be replaced by others; mode bits do not matter to flock.
            c.need(st.st_uid == 0, 'boot lock %s is not root-owned' % LOCK)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                c.need(time.monotonic() < deadline, 'timed out waiting for %s' % LOCK)
                time.sleep(0.2)
        try:
            yield {'path': LOCK, 'created': created}
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- file helpers

def _tmp_for(path):
    path = str(path)
    return os.path.join(os.path.dirname(path), '.' + os.path.basename(path) + '.bt2tmp')


def install_copy(src, dst, want_sha, mtime_ns=None, mode=0o644, b2=False):
    """Stream src to dst via same-dir temp + fsync + rename + dir fsync; verify sha before and after."""
    tmp = _tmp_for(dst)
    if os.path.lexists(tmp):
        os.unlink(tmp)
    sha, hb, n = cap.copy_file(src, tmp, mode=mode, b2=b2)
    if sha != want_sha:
        os.unlink(tmp)
        raise c.Failed('copy source sha mismatch for %s (got %s want %s)' % (dst, sha, want_sha))
    os.replace(tmp, dst)
    c.fsync_dir(os.path.dirname(str(dst)))
    if mtime_ns is not None:
        st = os.lstat(dst)
        os.utime(dst, ns=(st.st_atime_ns, mtime_ns))
    c.need(c.sha_file(dst)[0] == want_sha, 'readback mismatch after write: %s' % dst, after_change=True)
    return {'sha256': sha, 'b2': hb, 'bytes': n}


def unique_dest(path):
    path = str(path)
    if not os.path.lexists(path):
        return path
    i = 1
    while os.path.lexists('%s.bt2-%d' % (path, i)):
        i += 1
    return '%s.bt2-%d' % (path, i)


def move_esp_file_to_hold(ctx, src, hold_rel, want_sha=None):
    """ESP and root are different filesystems: copy (verified) to hold/, fsync, then unlink the ESP file."""
    dst = unique_dest(ctx.run_dir / 'hold' / hold_rel)
    cap.makedirs(os.path.dirname(dst))
    sha, _, n = cap.copy_file(src, dst)
    c.need(want_sha is None or sha == want_sha, 'ESP file changed under us: %s' % src, after_change=True)
    c.need(c.sha_file(dst)[0] == sha, 'hold copy readback mismatch: %s' % dst, after_change=True)
    os.unlink(src)
    c.fsync_dir(os.path.dirname(str(src)))
    return {'from': str(src), 'hold': os.path.relpath(dst, ctx.run_dir), 'sha256': sha, 'bytes': n}


def move_aside(ctx, src_sys, hold_rel):
    """Move a system path (any type) into hold/ keeping it intact. rename, or verified copy on EXDEV."""
    src = c.P(src_sys)
    dst = unique_dest(ctx.run_dir / 'hold' / hold_rel)
    cap.makedirs(os.path.dirname(dst))
    st = os.lstat(src)
    try:
        os.rename(src, dst)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise
        if stat.S_ISDIR(st.st_mode):
            shutil.copytree(src, dst, symlinks=True)
            c.need(cap.tree_map(src)[0]['tree_sha256'] == cap.tree_map(dst)[0]['tree_sha256'],
                   'cross-fs move verify failed: %s' % src_sys, after_change=True)
            shutil.rmtree(src)
        elif stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(src), dst)
            os.unlink(src)
        else:
            sha, _, _ = cap.copy_file(src, dst, mode=stat.S_IMODE(st.st_mode))
            c.need(c.sha_file(src)[0] == sha, 'cross-fs move verify failed: %s' % src_sys, after_change=True)
            os.unlink(src)
    c.fsync_dir(os.path.dirname(dst))
    c.fsync_dir(os.path.dirname(str(src)))
    return {'path': src_sys, 'type': cap.ftype(st), 'hold': os.path.relpath(dst, ctx.run_dir)}


def save_json(path, obj, exists):
    data = c.dump(obj)
    if exists:
        c.replace_file(path, data, 0o600)
    else:
        c.write_new(path, data)


# ---------------------------------------------------------------- esp-prep

def _norm_rel(rel):
    rel = str(rel).strip().lstrip('/')
    c.need(rel and '..' not in rel.split('/') and '//' not in rel, 'bad ESP-relative path: %r' % rel)
    return rel


def _menu_refs(raw_text, rel):
    """Lines (index, text) referencing boot():/<rel> (case-insensitive: FAT)."""
    needle = ('boot():/' + rel).lower()
    out = []
    for i, line in enumerate(raw_text.split('\n')):
        low = line.lower()
        k = low.find(needle)
        if k >= 0 and (len(low) == k + len(needle) or low[k + len(needle)] in '#\n \t'):
            out.append(i)
    return out


def _park_candidate(ctx, state, menu, default_rel, rel, machine_id):
    """-> (ok, reason, stanza fullnames to remove)"""
    low = rel.lower()
    man = state['esp']['files']
    if rel not in man:
        return False, 'not in capture manifest', []
    if cap.esp_excluded(rel) or low in PROTECTED_FILES or low.startswith(PROTECTED_PREFIXES):
        return False, 'protected ESP path', []
    if machine_id and low.startswith((machine_id + '/limine_history/').lower()):
        return False, 'limine_history is never parked', []
    if low == default_rel.lower():
        return False, 'is the default entry UKI', []
    lab = cap.lab_block(menu.raw())
    if lab is not None and ('boot():/' + rel).lower() in lab.lower():
        return False, 'referenced by the maclab block', []
    refs = set(_menu_refs('\n'.join(menu.lines), rel))
    stanzas = []
    for e in menu.walk():
        p = e.path()
        if not p:
            continue
        try:
            prel, _ = limine.split_path(p)
        except limine.MenuError:
            continue
        if prel.lower() != low:
            continue
        if e.depth != 1 or e.children:
            return False, 'referenced by a nested entry %r' % e.fullname, []
        if menu.default() is e:
            return False, 'referenced by the default entry', []
        stanzas.append(e.fullname)
        refs.discard(e.opts['path'][0])
    if refs:
        return False, 'referenced outside a removable top-level stanza (lines %s)' % sorted(refs), []
    cp = ctx.run_dir / 'capture' / 'esp' / rel
    if not os.path.lexists(cp) or c.sha_file(cp)[0] != man[rel]['sha256']:
        return False, 'capture copy missing or not verified', []
    return True, 'ok', stanzas


def plan_peak(cfg, state, default_rel, sd, auto, cand_names, cl):
    """Largest single file the transaction may write (also pacman's RLIMIT_FSIZE, read back by pkg.py).

    Measured per Mac: the biggest package UKI on this ESP (the file mkinitcpio rewrites), or the default UKI
    when there is none, plus UKI_HEADROOM for kernel growth; never below the largest packaged file + 1 MiB.
    A config 'peak_bytes' overrides. A UKI bigger than this makes pacman fail (EFBIG), which rolls back."""
    if cfg.get('peak_bytes'):
        return int(cfg['peak_bytes']), {'source': 'config'}
    files = state['esp']['files']
    sizes = {r: int(files[r]['size']) for r in sorted(files) if cap.package_uki(r, cand_names)}
    if auto or not sizes:
        sizes.setdefault(default_rel, int(sd['uki_bytes']))
    floor = int(cfg.get('largest_member_bytes') or 0)
    peak = max(cap.alloc(max(sizes.values()), cl) + UKI_HEADROOM, cap.alloc(floor, cl) + MiB)
    return peak, {'source': 'measured', 'uki_sizes': sizes, 'uki_headroom': UKI_HEADROOM,
                  'largest_member_bytes': floor, 'cluster': cl}


def prep(ctx):
    cfg = ctx.config
    state = cap.load_state(ctx)
    esp = ctx.esp
    rpath = ctx.run_dir / 'espops-prep.json'
    if os.path.lexists(rpath):
        r = json.loads(c.read_small(rpath, 4 << 20))
        live = c.H(c.read_small(esp / 'limine.conf', 1 << 20))
        c.need(r.get('status') == 'done' and live == r.get('menu_after_sha256'),
               'espops-prep.json exists (status %s) but the live menu does not match it: run esp-restore'
               % r.get('status'))
        return {'already_done': True, 'menu_sha256': live, 'receipt': 'espops-prep.json'}

    reserve = int(cfg.get('esp_reserve_bytes', RESERVE_DEFAULT))
    r8 = cap.run8(ctx)
    copy_rel = 'EFI/Linux/bt2-%s-original.efi' % r8
    entry_name = 'bt2 original %s' % r8
    cand_names = {p['name'] for p in cfg['candidates']}

    with boot_lock() as lk:
        raw = c.read_small(esp / 'limine.conf', 1 << 20)
        c.need(c.H(raw) == state['menu']['sha256'], 'limine.conf differs from capture (CAS): re-capture')
        drift = cap.esp_drift(esp, state)
        c.need(not drift, 'ESP differs from capture: %s' % '; '.join(drift[:10]))
        menu = limine.Menu(raw)
        d = menu.default()
        sd = state['menu']['default']
        c.need(d is not None and d.fullname == sd['name'], 'default entry differs from capture')
        rel, pin = limine.split_path(d.path())
        c.need(rel == sd['path'], 'default UKI path differs from capture')
        auto = bool(cap.is_auto_entry(menu, d) or cap.package_uki(rel, cand_names))
        c.need(auto == sd['auto_entry'], 'auto_entry re-verification (%s) differs from capture (%s)'
               % (auto, sd['auto_entry']))
        c.need(not os.path.lexists(esp / copy_rel), 'fallback copy path already exists: ' + copy_rel)
        c.need(menu.find(entry_name) is None, 'menu already has an entry named %r' % entry_name)

        cl = cap.esp_cluster(esp)
        peak, peak_basis = plan_peak(cfg, state, rel, sd, auto, cand_names, cl)
        copy_alloc = cap.alloc(sd['uki_bytes'], cl) if auto else 0
        need_bytes = reserve + peak + copy_alloc + MiB
        free0 = cap.esp_free(ctx, state)

        # -- plan parking (pure)
        plan, skipped, free_planned = [], [], free0
        work = limine.Menu(raw)
        if free_planned < need_bytes:
            for prel in cfg.get('parkable', []):
                if free_planned >= need_bytes:
                    break
                prel = _norm_rel(prel)
                ok, why, stanzas = _park_candidate(ctx, state, work, rel, prel, state.get('machine_id'))
                if not ok:
                    skipped.append({'path': prel, 'reason': why})
                    continue
                for name in stanzas:
                    work.remove_entry(work.find(name))
                size = state['esp']['files'][prel]['size']
                plan.append({'path': prel, 'size': size, 'sha256': state['esp']['files'][prel]['sha256'],
                             'stanzas': stanzas})
                free_planned += cap.alloc(size, cl)
        c.need(free_planned >= need_bytes, 'ESP short: free %d (after parking %d) < need %d (reserve %d + peak %d '
               '+ copy %d + 1 MiB); skipped parkable: %s' % (free0, free_planned, need_bytes, reserve, peak,
                                                            copy_alloc, skipped))

        # -- menu edits (pure)
        if auto:
            opts = [('comment', 'bt2 fallback: copy of %s (run %s)' % (sd['name'], cfg['run_id'])),
                    ('protocol', 'efi'), ('path', 'boot():/%s#%s' % (copy_rel, sd['uki_b2']))]
            if sd.get('cmdline') is not None:
                opts.append(('cmdline', sd['cmdline']))
            work.insert_entry_before_lab(entry_name, opts)
            work.set_global('default_entry', entry_name)
        new_raw = work.raw()
        c.need(cap.lab_block(new_raw) == cap.lab_block(raw), 'edit would touch the maclab block')
        chk = limine.Menu(new_raw)
        nd = chk.default()
        if auto:
            c.need(nd is not None and nd.fullname == entry_name and limine.split_path(nd.path())[0] == copy_rel,
                   'edited menu does not resolve default to the fallback stanza')
        else:
            c.need(nd is not None and nd.fullname == sd['name'] and nd.path() == d.path(),
                   'edited menu changed the custom default')

        receipt = {'status': 'started', 'run_id': cfg['run_id'], 'run8': r8, 'auto_entry': auto,
                   'lock': lk, 'menu_before_sha256': c.H(raw), 'menu_planned_sha256': c.H(new_raw),
                   'esp_free_before': free0, 'need_bytes': need_bytes, 'reserve': reserve, 'peak': peak,
                   'peak_basis': peak_basis, 'park_plan': plan, 'park_skipped': skipped, 'parked': [], 'fallback': None,
                   'default_before': {'name': sd['name'], 'path': sd['path'], 'uki_sha256': sd['uki_sha256']},
                   'hold_created': []}
        save_json(rpath, receipt, exists=False)
        try:
            for p in plan:
                ctx.changed = True
                rec = move_esp_file_to_hold(ctx, esp / p['path'], 'esp/' + p['path'], p['sha256'])
                receipt['parked'].append({**p, 'hold': rec['hold']})
                receipt['hold_created'].append(rec['hold'])
                save_json(rpath, receipt, exists=True)
            if auto:
                ctx.changed = True
                info = install_copy(esp / rel, esp / copy_rel, sd['uki_sha256'], mode=0o644, b2=True)
                c.need(info['b2'] == sd['uki_b2'] and info['bytes'] == sd['uki_bytes'],
                       'fallback copy blake2b/size mismatch', after_change=True)
                receipt['fallback'] = {'path': copy_rel, 'entry': entry_name, 'sha256': info['sha256'],
                                       'b2': info['b2'], 'bytes': info['bytes'], 'source': rel}
                save_json(rpath, receipt, exists=True)
            cur = c.read_small(esp / 'limine.conf', 1 << 20)
            c.need(c.H(cur) == c.H(raw), 'limine.conf changed during esp-prep (CAS)', after_change=ctx.changed)
            if new_raw != raw:
                ctx.changed = True
                c.replace_file(esp / 'limine.conf', new_raw)
            back = c.read_small(esp / 'limine.conf', 1 << 20)
            c.need(back == new_raw, 'limine.conf readback mismatch', after_change=ctx.changed)
            free1 = cap.esp_free(ctx, state)
            c.need(free1 >= reserve + peak, 'ESP free %d after prep < reserve + peak %d' % (free1, reserve + peak),
                   after_change=ctx.changed)
            c.need(c.sha_file(esp / rel)[0] == sd['uki_sha256'], 'default UKI changed', after_change=ctx.changed)
            receipt.update(status='done', menu_after_sha256=c.H(new_raw), esp_free_after=free1,
                           default_after={'name': nd.fullname, 'path': limine.split_path(nd.path())[0]})
            save_json(rpath, receipt, exists=True)
        except BaseException as e:
            receipt.update(status='failed', error='%s: %s' % (type(e).__name__, e))
            try:
                save_json(rpath, receipt, exists=True)
            except Exception:  # noqa: BLE001 - the original error matters more
                pass
            if ctx.changed and isinstance(e, c.Refused):
                raise c.Failed(str(e))
            raise
    return {'auto_entry': auto, 'fallback': receipt['fallback'], 'parked': receipt['parked'],
            'park_skipped': skipped, 'menu_before_sha256': receipt['menu_before_sha256'],
            'menu_after_sha256': receipt['menu_after_sha256'], 'default_after': receipt['default_after'],
            'esp_free_before': free0, 'esp_free_after': receipt['esp_free_after'], 'need_bytes': need_bytes,
            'peak': peak, 'peak_basis': peak_basis,
            'lock_created': lk['created'], 'receipt': 'espops-prep.json'}


# ---------------------------------------------------------------- esp-restore

def esp_verify(esp, state):
    """Full manifest equality (size, sha256, mtime_ns; directory set). -> list of differences."""
    files, dirs, _ = cap.walk_esp(esp)
    man = state['esp']['files']
    out = []
    for rel in sorted(set(files) | set(man)):
        if rel not in files:
            out.append({'path': rel, 'issue': 'missing'})
        elif rel not in man:
            out.append({'path': rel, 'issue': 'extra', 'size': files[rel].st_size})
        else:
            st, m = files[rel], man[rel]
            if cap.boot_refreshed(rel, state, st, m):
                continue
            if st.st_size != m['size'] or c.sha_file(esp / rel)[0] != m['sha256']:
                out.append({'path': rel, 'issue': 'bytes'})
            elif st.st_mtime_ns != m['mtime_ns']:
                out.append({'path': rel, 'issue': 'mtime', 'live': st.st_mtime_ns, 'capture': m['mtime_ns']})
    for dd in sorted(set(dirs) ^ set(state['esp']['dirs'])):
        out.append({'path': dd + '/', 'issue': 'extra dir' if dd in dirs else 'missing dir'})
    return out


def restore(ctx):
    state = cap.load_state(ctx)
    esp = ctx.esp
    man = state['esp']['files']
    mdirs = set(state['esp']['dirs'])
    capdir = ctx.run_dir / 'capture' / 'esp'
    done = {'moved_extras': [], 'removed_dirs': [], 'created_dirs': [], 'rewritten': [], 'mtime_only': [],
            'menu_restored': False, 'hold_created': []}

    def mutate():
        ctx.changed = True

    with boot_lock() as lk:
        menu_path = esp / 'limine.conf'
        start_menu = c.read_small(menu_path, 1 << 20) if os.path.lexists(menu_path) else None
        start_sha = c.H(start_menu) if start_menu is not None else None
        diffs = esp_verify(esp, state)
        menu_diff = [x for x in diffs if x['path'] == 'limine.conf']
        diffs = [x for x in diffs if x['path'] != 'limine.conf']
        for x in diffs:
            if x['issue'] in ('missing', 'bytes'):
                live = cap.lst(esp / x['path'])
                c.need(live is None or stat.S_ISREG(live.st_mode), 'live %s is not a file' % x['path'],
                       after_change=ctx.changed)
                cp = capdir / x['path']
                c.need(os.path.lexists(cp) and c.sha_file(cp)[0] == man[x['path']]['sha256'],
                       'capture copy missing/corrupt: %s' % x['path'], after_change=ctx.changed)
        # 1. extras out first (frees space): verified move to hold/esp-extra/
        for x in [x for x in diffs if x['issue'] == 'extra']:
            mutate()
            rec = move_esp_file_to_hold(ctx, esp / x['path'], 'esp-extra/' + x['path'])
            done['moved_extras'].append(rec)
            done['hold_created'].append(rec['hold'])
        for x in sorted([x for x in diffs if x['issue'] == 'extra dir'], key=lambda x: -x['path'].count('/')):
            p = esp / x['path'].rstrip('/')
            c.need(not os.listdir(p), 'extra ESP dir not empty after moving extras: %s' % x['path'],
                   after_change=ctx.changed)
            mutate()
            os.rmdir(p)
            c.fsync_dir(os.path.dirname(str(p)))
            done['removed_dirs'].append(x['path'])
        for x in sorted([x for x in diffs if x['issue'] == 'missing dir'], key=lambda x: x['path'].count('/')):
            mutate()
            p = esp / x['path'].rstrip('/')
            os.mkdir(p)
            c.fsync_dir(os.path.dirname(str(p)))
            done['created_dirs'].append(x['path'])
        # 2. differing / missing files (incl. parked ones) from the capture copies
        cl = cap.esp_cluster(esp)
        for x in [x for x in diffs if x['issue'] in ('missing', 'bytes')]:
            m = man[x['path']]
            free = cap.esp_free(ctx, state)
            c.need(free >= cap.alloc(m['size'], cl) + MiB, 'ESP free %d too low to restore %s' % (free, x['path']),
                   after_change=ctx.changed)
            mutate()
            install_copy(capdir / x['path'], esp / x['path'], m['sha256'], mtime_ns=m['mtime_ns'])
            done['rewritten'].append(x['path'])
        for x in [x for x in diffs if x['issue'] == 'mtime']:
            mutate()
            st = os.lstat(esp / x['path'])
            os.utime(esp / x['path'], ns=(st.st_atime_ns, man[x['path']]['mtime_ns']))
            done['mtime_only'].append(x['path'])
        # 3. limine.conf last, CAS against the bytes read at start
        if menu_diff:
            want = c.read_small(capdir / 'limine.conf', 1 << 20)
            c.need(c.H(want) == man['limine.conf']['sha256'], 'capture limine.conf copy corrupt',
                   after_change=ctx.changed)
            cur = c.read_small(menu_path, 1 << 20) if os.path.lexists(menu_path) else None
            c.need((c.H(cur) if cur is not None else None) == start_sha,
                   'limine.conf changed during esp-restore (CAS)', after_change=ctx.changed)
            mutate()
            if cur != want:
                c.replace_file(menu_path, want)
                done['menu_restored'] = True
            st = os.lstat(menu_path)
            os.utime(menu_path, ns=(st.st_atime_ns, man['limine.conf']['mtime_ns']))
            c.need(c.read_small(menu_path, 1 << 20) == want, 'limine.conf readback mismatch', after_change=True)
        # 4. full verification
        left = esp_verify(esp, state)
        c.need(not left, 'ESP does not match capture after restore: %s' % left[:10], after_change=ctx.changed)
    return {**done, 'noop': not ctx.changed, 'verified': True, 'menu_sha_at_start': start_sha,
            'menu_sha256': man['limine.conf']['sha256'], 'files': len(man),
            'manifest_sha256': c.H(cap.json_bytes(man)), 'esp_free': cap.esp_free(ctx, state),
            'lock_created': lk['created']}


# ---------------------------------------------------------------- etc-restore

def writer_held_paths(ctx):
    """System paths currently held by writers (mask symlinks -> /dev/null, unlinked aliases kept in hold/).
    etc-restore must not touch them; release-writers owns their inverse."""
    w = cap.load_writers(ctx)
    held = set()
    if not w:
        return held
    for m in w.get('masks', []):
        p = m.get('path') or '/etc/systemd/system/' + m['unit']
        st = cap.lst(c.P(p))
        if st is not None and stat.S_ISLNK(st.st_mode) and os.readlink(c.P(p)) == '/dev/null':
            held.add(p)
    for a in w.get('aliases', []):
        p = a.get('path') or '/etc/systemd/system/' + a['unit']
        st = cap.lst(c.P(p))
        if os.path.lexists(cap.held_path(ctx, a['held'])) and (
                st is None or (stat.S_ISLNK(st.st_mode) and os.readlink(c.P(p)) == '/dev/null')):
            held.add(p)
    return held


def _etc_compare(want, live):
    keys = ('type', 'mode', 'uid', 'gid', 'size', 'sha256', 'mtime_ns', 'target')
    return [k for k in keys if want.get(k) != live.get(k)]


def _restore_file(ctx, path, want):
    src = ctx.run_dir / 'capture' / 'etc' / path.lstrip('/')
    c.need(os.path.lexists(src) and c.sha_file(src)[0] == want['sha256'], 'capture copy missing/corrupt: ' + path,
           after_change=ctx.changed)
    dst = c.P(path)
    tmp = _tmp_for(dst)
    if os.path.lexists(tmp):
        os.unlink(tmp)
    sha, _, _ = cap.copy_file(src, tmp, mode=0o600)
    c.need(sha == want['sha256'], 'copy mismatch: ' + path, after_change=True)
    st = os.lstat(tmp)
    if (st.st_uid, st.st_gid) != (want['uid'], want['gid']):
        os.chown(tmp, want['uid'], want['gid'], follow_symlinks=False)
    os.chmod(tmp, want['mode'])
    os.replace(tmp, dst)
    os.utime(dst, ns=(want['mtime_ns'], want['mtime_ns']), follow_symlinks=False)
    c.fsync_dir(os.path.dirname(str(dst)))


def _restore_link(path, want):
    dst = c.P(path)
    tmp = _tmp_for(dst)
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.symlink(want['target'], tmp)
    st = os.lstat(tmp)
    if (st.st_uid, st.st_gid) != (want['uid'], want['gid']):
        os.chown(tmp, want['uid'], want['gid'], follow_symlinks=False)
    os.replace(tmp, dst)
    os.utime(dst, ns=(want['mtime_ns'], want['mtime_ns']), follow_symlinks=False)
    c.fsync_dir(os.path.dirname(str(dst)))


def _fix_meta(path, want, live):
    p = c.P(path)
    if (live['uid'], live['gid']) != (want['uid'], want['gid']):
        os.chown(p, want['uid'], want['gid'], follow_symlinks=False)
    if want['type'] != 'l' and live['mode'] != want['mode']:
        os.chmod(p, want['mode'])
    if os.lstat(p).st_mtime_ns != want['mtime_ns']:
        os.utime(p, ns=(want['mtime_ns'], want['mtime_ns']), follow_symlinks=False)


def etc_live(state):
    """Re-scan the capture set: captured paths + every live member of the recursive roots."""
    explicit = set(state['etc'])
    return cap.etc_scan(explicit, set(state.get('etc_roots', [])))


def etc_restore(ctx):
    state = cap.load_state(ctx)
    want_all = state['etc']
    skip = writer_held_paths(ctx)
    done = {'moved_extras': [], 'restored_bytes': [], 'restored_links': [], 'created_dirs': [], 'metadata': [],
            'mtime_only': [], 'skipped_writer_held': sorted(skip), 'hold_created': []}
    live = etc_live(state)
    under_skip = lambda p: p in skip  # noqa: E731

    # 1. move aside: live entries absent at capture (incl. .pacnew/.pacsave, new files in captured dirs) and
    #    type changes. Topmost first; descendants of a moved dir go with it.
    moved = []
    for p in sorted(live):
        if under_skip(p) or any(p.startswith(m + '/') for m in moved):
            continue
        lv, w = live[p], want_all.get(p, {'type': 'absent'})
        if lv['type'] == 'absent':
            continue
        if w['type'] == 'absent' or w['type'] != lv['type']:
            ctx.changed = True
            rec = move_aside(ctx, p, 'etc-extra/' + p.lstrip('/'))
            done['moved_extras'].append(rec)
            done['hold_created'].append(rec['hold'])
            moved.append(p)
    live = etc_live(state)
    # 2. create / rewrite, parents first
    for p in sorted(want_all, key=lambda x: (x.count('/'), x)):
        w = want_all[p]
        if under_skip(p) or w['type'] in ('absent',):
            continue
        lv = live.get(p) or cap.fs_entry(p)
        if w['type'] == 'd':
            if lv['type'] == 'absent':
                ctx.changed = True
                os.mkdir(c.P(p), w['mode'])
                c.fsync_dir(os.path.dirname(str(c.P(p))))
                done['created_dirs'].append(p)
        elif w['type'] == 'f':
            if lv['type'] == 'absent' or lv['sha256'] != w['sha256'] or lv['size'] != w['size']:
                ctx.changed = True
                _restore_file(ctx, p, w)
                done['restored_bytes'].append(p)
            else:
                diff = _etc_compare(w, lv)
                if diff:
                    ctx.changed = True
                    _fix_meta(p, w, lv)
                    (done['mtime_only'] if diff == ['mtime_ns'] else done['metadata']).append(p)
        elif w['type'] == 'l':
            if lv['type'] == 'absent' or lv['target'] != w['target']:
                ctx.changed = True
                _restore_link(p, w)
                done['restored_links'].append(p)
            else:
                diff = _etc_compare(w, lv)
                if diff:
                    ctx.changed = True
                    _fix_meta(p, w, lv)
                    (done['mtime_only'] if diff == ['mtime_ns'] else done['metadata']).append(p)
        else:
            c.need(_etc_compare(w, lv) == [], 'cannot restore special file %s' % p, after_change=ctx.changed)
    # 3. directory metadata last, deepest first (member changes above touched their mtimes)
    for p in sorted([p for p, w in want_all.items() if w['type'] == 'd' and not under_skip(p)],
                    key=lambda x: (-x.count('/'), x)):
        lv = cap.fs_entry(p)
        diff = _etc_compare(want_all[p], lv)
        if diff:
            ctx.changed = True
            _fix_meta(p, want_all[p], lv)
            (done['mtime_only'] if diff == ['mtime_ns'] else done['metadata']).append(p)
    # 4. verify
    live = etc_live(state)
    bad = []
    for p in sorted(set(live) | set(want_all)):
        if under_skip(p):
            continue
        d = _etc_compare(want_all.get(p, {'type': 'absent', 'mode': None, 'uid': None, 'gid': None, 'size': None,
                                          'sha256': None, 'mtime_ns': None, 'target': None}),
                         live.get(p) or cap.fs_entry(p))
        if d:
            bad.append({'path': p, 'fields': d})
    c.need(not bad, '/etc does not match capture after etc-restore: %s' % bad[:10], after_change=ctx.changed)
    return {**done, 'noop': not ctx.changed, 'verified': True, 'entries': len(want_all)}
