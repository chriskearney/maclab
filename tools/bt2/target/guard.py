"""bt2 boot.bin guard, only for runs whose candidate set changes m1n1/boot.bin (config 'bootbin_guard').

A run that installs a candidate m1n1 stage 2 (or DTBs) leaves the ESP's boot.bin as the candidate until rollback.
labd's identity check reads boot.bin in every phase of the candidate job, the last one after all tests, so it
cannot be put back during that boot. This unit puts the ORIGINAL bytes back afterwards instead:

  ExecStop  (orderly shutdown of a boot while the unit is active; lab-agent ends a job with `systemctl reboot`):
            the ESP holds the candidate -> write the original.
  ExecStart (every boot after install): unless the running kernel is the candidate kernel, the same restore.

Normal path: only the candidate job boot runs the candidate stage 2; the known-good return boot runs the original.
This is NOT a hard one-boot limit. A panic, hang, power loss or forced reset of the candidate boot skips the stop
hook, and the next boot runs the candidate stage 2 again before the start hook restores. A stage 2 that never
reaches Linux is never restored by this unit: that needs a person at macOS Recovery and the original that
update-m1n1 itself keeps as m1n1/boot.bin.old (install verifies it is exactly the captured original).

Lifecycle: bootbin-guard-install right after install (boot.bin = candidate, boot.bin.old = original), enabled for
the next boot only; bootbin-guard-remove back on known-good before rollback (stop hook, then one more
compare-and-swap restore, then the unit files go).

Every restore is a compare-and-swap under the boot-partition lock: only the exact candidate hash is replaced, only
by the captured original (hash-checked), temp + fsync + rename + readback. Any other boot.bin is left alone.
"""
import json
import os
import re
import stat

import common as c
import capture as cap
import espops

SYSTEMD = '/etc/systemd/system'
WANTS = SYSTEMD + '/multi-user.target.wants'
HEX64 = re.compile(r'[0-9a-f]{64}$')
RECEIPT = 'bootbin-guard.json'


def gcfg(ctx):
    g = ctx.config.get('bootbin_guard')
    c.need(isinstance(g, dict), 'config has no bootbin_guard (only runs with allow_bootbin_change use it)')
    c.need(ctx.config.get('allow_bootbin_change') is True, 'bootbin_guard without allow_bootbin_change')
    r8 = cap.run8(ctx)
    c.need(g.get('unit') == 'bt2-%s-bootbin-guard.service' % r8, 'guard unit name must be bt2-<run8>-bootbin-guard.service')
    c.need(g.get('recovery_copy') == 'm1n1/boot.bin.old', 'Recovery copy must be update-m1n1\'s m1n1/boot.bin.old')
    for k in ('candidate_sha256', 'original_sha256'):
        c.need(HEX64.match(str(g.get(k) or '')), 'bootbin_guard.%s' % k)
    c.need(g['candidate_sha256'] != g['original_sha256'], 'candidate and original boot.bin are the same')
    c.need(g['candidate_sha256'] == ctx.config.get('expected_bootbin_sha256'), 'guard candidate != expected boot.bin')
    c.need(isinstance(g.get('candidate_krel'), str) and g['candidate_krel'] == ctx.config.get('expected_kernel'),
           'guard candidate kernel != expected kernel')
    return g


def original_bytes(ctx, g):
    """The captured original boot.bin, hash-checked against the guard config and the capture state."""
    st = cap.load_state(ctx)
    c.need(st['bootbin_sha256'] == g['original_sha256'], 'capture boot.bin differs from the guard original')
    for rel in ('capture/esp/m1n1/boot.bin', 'capture/boot.bin'):
        p = ctx.run_dir / rel
        if os.path.lexists(p):
            data = c.read_small(p, 64 << 20)
            if c.H(data) == g['original_sha256']:
                return data
    raise c.Refused('no captured copy of the original boot.bin with hash %s' % g['original_sha256'])


def unit_text(ctx, g):
    run = '/var/lib/maclab/bt2/' + ctx.config['run_id']
    pin = c.H(ctx.config_raw)
    cmd = '/usr/bin/python3 -I -B %s/t bootbin-guard --run-dir %s --config-sha256 %s --phase' % (run, run, pin)
    return ('# bt2 run %s: puts the original m1n1 boot.bin back after the candidate boot (target/guard.py).\n'
            '# Created and removed by bt2 only.\n'
            '[Unit]\n'
            'Description=bt2 %s boot.bin guard\n'
            'RequiresMountsFor=%s %s\n'
            '\n'
            '[Service]\n'
            'Type=oneshot\n'
            'RemainAfterExit=yes\n'
            'WorkingDirectory=%s\n'
            'ExecStart=%s start\n'
            'ExecStop=%s stop\n'
            'TimeoutStartSec=120\n'
            'TimeoutStopSec=120\n'
            '\n'
            '[Install]\n'
            'WantedBy=multi-user.target\n') % (ctx.config['run_id'], cap.run8(ctx), ctx.config.get('esp', c.ESP_DEFAULT),
                                               run, run, cmd, cmd)


def unit_state(unit):
    r = c.run([c.BIN('systemctl'), 'show', '--property=LoadState,ActiveState,UnitFileState', unit], check=False,
              timeout=60)
    out = {}
    for line in r.stdout.decode(errors='replace').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            out[k] = v
    return out


def _receipt_path(ctx):
    return ctx.run_dir / RECEIPT


def install(ctx):
    g = gcfg(ctx)
    unit = g['unit']
    upath, wpath = c.P(SYSTEMD + '/' + unit), c.P(WANTS + '/' + unit)
    text = unit_text(ctx, g).encode()
    rp = _receipt_path(ctx)
    if os.path.lexists(rp):
        r = json.loads(c.read_small(rp))
        c.need(r.get('status') == 'installed' and os.path.lexists(upath) and c.sha_file(upath)[0] == c.H(text)
               and os.path.islink(wpath) and os.readlink(wpath) == SYSTEMD + '/' + unit,
               'bootbin-guard.json exists but the unit is not as recorded: run bootbin-guard-remove')
        return {'already_done': True, 'unit': unit}
    live = c.sha_file(ctx.esp / 'm1n1' / 'boot.bin')[0]
    c.need(live == g['candidate_sha256'], 'boot.bin %s is not the installed candidate %s' % (live, g['candidate_sha256']))
    original_bytes(ctx, g)
    rec = ctx.esp / g['recovery_copy']
    c.need(os.path.lexists(rec) and c.sha_file(rec)[0] == g['original_sha256'],
           'Recovery copy %s missing or not the original' % g['recovery_copy'])
    ident = esp_identity(ctx)
    c.need(not os.path.lexists(upath) and not os.path.lexists(wpath), 'guard unit path already exists')
    c.need(os.path.isdir(c.P(WANTS)), '%s missing' % WANTS)
    r = {'status': 'started', 'unit': unit, 'unit_sha256': c.H(text)}
    c.write_new(rp, c.dump(r))
    ctx.changed = True
    c.write_new(upath, text, 0o644)
    os.chmod(upath, 0o644)
    os.symlink(SYSTEMD + '/' + unit, wpath)
    c.fsync_dir(wpath.parent)
    su, sw = os.lstat(upath), os.lstat(wpath)
    r.update(status='written', unit_ino=su.st_ino, unit_dev=su.st_dev, wants_ino=sw.st_ino, wants_dev=sw.st_dev)
    c.replace_file(rp, c.dump(r), 0o600)
    c.run([c.BIN('systemctl'), 'daemon-reload'], timeout=120)
    s = unit_state(unit)
    # enabled for the NEXT boot only: started now, its stop hook would restore at the reboot INTO the candidate
    c.need(s.get('LoadState') == 'loaded' and s.get('ActiveState') == 'inactive' and s.get('UnitFileState') == 'enabled',
           'guard unit state after install: %r' % s, after_change=True)
    r.update(status='installed', state=s, esp_identity=ident)
    c.replace_file(rp, c.dump(r), 0o600)
    return {'unit': unit, 'unit_sha256': c.H(text), 'state': s, 'recovery_copy': g['recovery_copy'],
            'recovery_copy_sha256': g['original_sha256'], 'esp_identity': ident}


def remove(ctx):
    g = gcfg(ctx)
    unit = g['unit']
    upath, wpath = c.P(SYSTEMD + '/' + unit), c.P(WANTS + '/' + unit)
    rp = _receipt_path(ctx)
    r = json.loads(c.read_small(rp)) if os.path.lexists(rp) else None
    text = unit_text(ctx, g).encode()
    if r is None:
        c.need(not os.path.lexists(upath) and not os.path.lexists(wpath),
               'guard unit present without bt2 receipt; not removing what bt2 did not record')
        return {'noop': True, 'unit': unit}
    stopped = None
    s0 = unit_state(unit)
    if s0.get('ActiveState') not in ('inactive', 'failed', None, ''):
        # its stop hook runs here: a compare-and-swap that only replaces the exact candidate bytes
        ctx.changed = True
        rs = c.run([c.BIN('systemctl'), 'stop', unit], check=False, timeout=180)
        stopped = {'exit': rs.returncode, 'stderr': rs.stderr.decode(errors='replace')[-300:]}
    cas = restore_if_candidate(ctx, g)
    live = c.sha_file(ctx.esp / 'm1n1' / 'boot.bin')[0]
    c.need(live == g['original_sha256'], 'boot.bin %s is neither restored nor the original; leaving the guard in '
           'place for a person' % live, after_change=ctx.changed)
    removed = []
    if os.path.lexists(wpath):
        st = os.lstat(wpath)
        c.need(stat.S_ISLNK(st.st_mode) and os.readlink(wpath) == SYSTEMD + '/' + unit
               and st.st_ino == r.get('wants_ino'), 'wants link is not the one bt2 made', after_change=ctx.changed)
        ctx.changed = True
        os.unlink(wpath)
        c.fsync_dir(wpath.parent)
        removed.append(WANTS + '/' + unit)
    if os.path.lexists(upath):
        st = os.lstat(upath)
        c.need(stat.S_ISREG(st.st_mode) and c.sha_file(upath)[0] == c.H(text) and st.st_ino == r.get('unit_ino'),
               'guard unit file is not the one bt2 wrote', after_change=ctx.changed)
        ctx.changed = True
        os.unlink(upath)
        c.fsync_dir(upath.parent)
        removed.append(SYSTEMD + '/' + unit)
    c.run([c.BIN('systemctl'), 'daemon-reload'], timeout=120)
    s = unit_state(unit)
    c.need(s.get('LoadState') == 'not-found' and s.get('ActiveState') in ('inactive', ''),
           'guard unit still loaded/active after removal: %r' % s, after_change=ctx.changed)
    r.update(status='removed', removed=removed, stopped=stopped, cas=cas, state_after=s)
    c.replace_file(rp, c.dump(r), 0o600)
    return {'unit': unit, 'removed': removed, 'stopped': stopped, 'cas': cas, 'state': s, 'bootbin_sha256': live}


def run(ctx):
    """ExecStart/ExecStop body. Exit 0 unless a restore it started failed (the unit then shows failed)."""
    g = gcfg(ctx)
    argv = list(getattr(ctx, 'argv', []))
    c.need('--phase' in argv and argv.index('--phase') + 1 < len(argv), 'bootbin-guard needs --phase start|stop')
    phase = argv[argv.index('--phase') + 1]
    c.need(phase in ('start', 'stop'), 'phase must be start or stop')
    bb = ctx.esp / 'm1n1' / 'boot.bin'
    krel = c.kernel_release()
    out = {'phase': phase, 'running_kernel': krel, 'candidate_krel': g['candidate_krel']}
    if phase == 'start' and krel == g['candidate_krel']:
        out.update(action='keep-candidate-boot', bootbin_sha256=c.sha_file(bb)[0])
        return out
    out.update(restore_if_candidate(ctx, g))
    return out


def restore_if_candidate(ctx, g):
    """Compare-and-swap: only the exact candidate is replaced, only by the hash-checked captured original."""
    bb = ctx.esp / 'm1n1' / 'boot.bin'
    data = original_bytes(ctx, g)
    out = {}
    with espops.boot_lock() as lk:
        live = c.sha_file(bb)[0]
        out['bootbin_before'] = live
        if live == g['candidate_sha256']:
            ctx.changed = True
            c.replace_file(bb, data)
            after = c.sha_file(bb)[0]
            c.need(after == g['original_sha256'], 'restore readback %s' % after, after_change=True)
            out.update(action='restored', bootbin_after=after)
        elif live == g['original_sha256']:
            out.update(action='original-already')
        else:
            out.update(action='unexpected-left-alone')
        out['lock_created'] = lk['created']
    return out


def esp_identity(ctx):
    """What a person in macOS Recovery can match: GPT partition UUID (as stage 1 has it), FAT serial, size."""
    try:
        part = c.P('/proc/device-tree/chosen/asahi,efi-system-partition').read_bytes().replace(b'\0', b'').decode().strip()
    except OSError:
        part = None
    src = None
    try:
        mounts = c.P('/proc/self/mounts').read_text().splitlines()
    except OSError:
        mounts = []
    for line in mounts:
        f = line.split()
        if len(f) > 2 and f[1] == ctx.config.get('esp', c.ESP_DEFAULT):
            src = f[0]
    out = {'partition_uuid': part, 'linux_device': src, 'esp_bytes': None, 'fat_serial': None, 'label': None}
    if src:
        for k, tag in (('fat_serial', 'UUID'), ('label', 'LABEL'), ('partuuid', 'PARTUUID')):
            try:
                r = c.run([c.BIN('blkid'), '-s', tag, '-o', 'value', src], check=False, timeout=30)
            except OSError:
                continue
            out[k] = (r.stdout.decode(errors='replace').strip() or None) if r.returncode == 0 else None
        st = os.statvfs(ctx.esp)
        out['esp_bytes'] = st.f_blocks * st.f_frsize
    return out


def status(ctx):
    """Read-only: live boot.bin, live stage 2, unit state and every guard receipt."""
    g = gcfg(ctx)
    try:
        v = c.P('/proc/device-tree/chosen/asahi,m1n1-stage2-version').read_bytes()
        stage2 = v.replace(b'\0', b'').decode(errors='replace').strip()
    except OSError:
        stage2 = None
    recs = []
    rd = ctx.run_dir / 'receipts'
    for p in sorted(rd.glob('bootbin-guard.*.json'), key=lambda p: int(p.name.split('.')[1])):
        x = json.loads(c.read_small(p))
        recs.append({k: x.get(k) for k in ('phase', 'action', 'boot_id', 'running_kernel', 'kernel', 'bootbin_before',
                                           'bootbin_after', 'ok', 'error', 'refused_reason')} | {'receipt': p.name})
    live = c.sha_file(ctx.esp / 'm1n1' / 'boot.bin')[0]
    rec = ctx.esp / g['recovery_copy']
    return {'bootbin_sha256': live, 'is_original': live == g['original_sha256'],
            'is_candidate': live == g['candidate_sha256'], 'stage2_version': stage2,
            'recovery_copy_sha256': c.sha_file(rec)[0] if os.path.lexists(rec) else None,
            'unit_state': unit_state(g['unit']), 'receipts': recs}
