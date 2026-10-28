"""preflight (read-only) and fetch (download artifacts through the agent's own labd credentials)."""
import hashlib
import json
import os
import re
import urllib.request
from pathlib import Path

import common as c
import limine

CLEANUP_DROPIN_DIR = '/etc/systemd/system/linux-modules-cleanup.service.d'


def unit_state(unit):
    r = c.run([c.BIN('systemctl'), 'show', unit, '--property=LoadState,ActiveState,UnitFileState,FragmentPath'],
              check=False, timeout=30)
    props = dict(line.split('=', 1) for line in r.stdout.decode().splitlines() if '=' in line)
    link = c.P('/etc/systemd/system') / unit
    etc = None
    if os.path.lexists(link):
        etc = {'symlink': os.readlink(link)} if link.is_symlink() else {'file': True}
    return {'load': props.get('LoadState'), 'active': props.get('ActiveState'),
            'enabled': props.get('UnitFileState'), 'fragment': props.get('FragmentPath'), 'etc': etc}


def module_trees():
    out = {}
    root = c.P('/usr/lib/modules')
    for d in sorted(root.iterdir()):
        if d.name.startswith('.') or not d.is_dir():
            continue
        owned = c.run([c.BIN('pacman'), '-Qqo', '/usr/lib/modules/' + d.name], check=False, timeout=60)
        out[d.name] = {'owned_by': owned.stdout.decode().split() if owned.returncode == 0 else [],
                       'keep_marker': os.path.lexists(d / '.keep-local-kernel')}
    return out


def cleanup_dropin_honours_marker():
    d = c.P(CLEANUP_DROPIN_DIR)
    if not d.is_dir():
        return False
    for f in d.iterdir():
        if f.suffix == '.conf' and b'.keep-local-kernel' in c.read_small(f, 65536):
            return True
    return False


def default_entry(esp):
    raw = c.read_small(esp / 'limine.conf', 1 << 20)
    m = limine.Menu(raw)
    d = m.default()
    c.need(d is not None and d.path(), 'cannot resolve default_entry in limine.conf')
    rel, pin = limine.split_path(d.path())
    sha, n = c.sha_file(esp / rel)
    return raw, {'name': d.fullname, 'path': rel, 'pin_b2': pin, 'uki_sha256': sha, 'uki_bytes': n,
                 'uki_b2': c.b2_file(esp / rel),
                 'cmdline': d.opts.get('cmdline', (None, None))[1]}


def preflight(ctx):
    cfg = ctx.config
    facts = {'board': c.board(), 'kernel': c.kernel_release(), 'cmdline_job_tag': 'maclab.job=' in c.cmdline(),
             'db_lock': os.path.lexists(c.P('/var/lib/pacman/db.lck'))}
    st = os.statvfs(c.P('/'))
    facts['root_free'] = st.f_bavail * st.f_frsize
    se = os.statvfs(ctx.esp)
    facts['esp_free'] = se.f_bavail * se.f_frsize
    names = sorted({p['name'] for p in cfg['candidates']} | {p['name'] for p in cfg['originals']})
    facts['packages'] = c.pacman_versions(names)
    menu_raw, facts['default_entry'] = default_entry(ctx.esp)
    facts['menu_sha256'] = c.H(menu_raw)
    facts['bootbin_sha256'] = c.sha_file(ctx.esp / 'm1n1/boot.bin')[0]
    facts['writer_units'] = {u: unit_state(u) for u in cfg.get('writer_units', [])}
    facts['module_trees'] = module_trees()
    facts['cleanup_dropin_keep_marker'] = cleanup_dropin_honours_marker()
    problems = []
    if facts['board'] != cfg['board']:
        problems.append('board %s != %s' % (facts['board'], cfg['board']))
    if facts['kernel'] != cfg['known_good_kernel']:
        problems.append('kernel %s != known-good %s' % (facts['kernel'], cfg['known_good_kernel']))
    if facts['cmdline_job_tag']:
        problems.append('running a lab job boot')
    if facts['db_lock']:
        problems.append('pacman lock present')
    if facts['root_free'] < cfg.get('root_reserve_bytes', 2 << 30):
        problems.append('root free space too low')
    for p in cfg['originals']:
        if facts['packages'].get(p['name']) != p.get('version'):
            problems.append('package %s is %s, config original %s' % (p['name'], facts['packages'].get(p['name']), p.get('version')))
    if not facts['cleanup_dropin_keep_marker']:
        problems.append('linux-modules-cleanup drop-in honouring .keep-local-kernel not found')
    if cfg.get('expected_bootbin_sha256') and facts['bootbin_sha256'] != cfg['expected_bootbin_sha256'] \
            and not cfg.get('allow_bootbin_change'):
        problems.append('boot.bin %s differs from manifest expectation %s' % (facts['bootbin_sha256'], cfg['expected_bootbin_sha256']))
    facts['problems'] = problems
    c.need(not problems, 'preflight: ' + '; '.join(problems))
    return {'facts': facts}


def _agent_creds():
    a = json.loads(c.read_small(c.P('/etc/maclab/agent.json'), 65536))
    return a['server'].rstrip('/'), a['secret']


def fetch(ctx):
    cfg = ctx.config
    server, secret = _agent_creds()
    cand = {p['file'] for p in cfg['candidates']}
    got = {}
    for f, sha in sorted(cfg['artifact_shas'].items()):
        c.need(re.fullmatch(r'[A-Za-z0-9@_.+:-]{1,200}', f) and '/' not in f, 'bad artifact file name')
        dest_dir = ctx.sub('pkgs' if f in cand else 'originals')
        dest = dest_dir / f
        if os.path.lexists(dest):
            h, n = c.sha_file(dest)
            c.need(h == sha, 'existing artifact mismatch: ' + f)
            got[f] = {'sha256': h, 'bytes': n, 'reused': True}
            continue
        part = dest_dir / ('.' + f + '.part')
        if os.path.lexists(part):
            os.unlink(part)
        req = urllib.request.Request(server + '/api/agent/artifacts/' + sha,
                                     headers={'Authorization': 'Bearer ' + secret})
        h = hashlib.sha256()
        n = 0
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                while True:
                    b = r.read(1 << 20)
                    if not b:
                        break
                    os.write(fd, b)
                    h.update(b)
                    n += len(b)
            os.fsync(fd)
        finally:
            os.close(fd)
        c.need(h.hexdigest() == sha, 'downloaded artifact hash mismatch: ' + f)
        os.rename(part, dest)
        c.fsync_dir(dest_dir)
        got[f] = {'sha256': sha, 'bytes': n, 'reused': False}
    return {'artifacts': got}
