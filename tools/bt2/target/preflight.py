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

# >>> maclab-labhttp v1 (canonical: tools/bt2/bt2/labhttp.py) >>>
import ipaddress as _lh_ip
import ssl as _lh_ssl
import urllib.parse as _lh_parse
import urllib.request as _lh_req


class TransportRefused(RuntimeError):
    """The request broke the labd client transport policy: it was not sent, or a redirect was not followed."""


def _lh_loopback(host):
    if host == 'localhost':
        return True
    try:
        return _lh_ip.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url, allow_plain_http=False):
    """Refuse a URL a bearer token must not be sent to. Returns its scheme."""
    u = _lh_parse.urlsplit(url)
    if u.scheme not in ('https', 'http') or not u.hostname or u.username is not None or u.password is not None:
        raise TransportRefused('labd URL %r: give https://host[:port] (no credentials in the URL)' % (url,))
    if u.scheme == 'http' and not _lh_loopback(u.hostname) and not allow_plain_http:
        raise TransportRefused('labd URL %s is plain http to %s, which is not loopback: use https, or opt in to plain http '
                               'explicitly (MACLAB_ALLOW_PLAIN_HTTP=1, or "allow_plain_http": true in the config)'
                               % (url, u.hostname))
    return u.scheme


class _LhGuard(_lh_req.BaseHandler):
    handler_order = 100  # before anything is sent

    def __init__(self, allow_plain_http):
        self.allow_plain_http = allow_plain_http

    def http_request(self, req):
        check_url(req.full_url, self.allow_plain_http)
        return req

    https_request = http_request


class _LhNoRedirect(_lh_req.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise TransportRefused('labd answered %d with a redirect to %s; redirects are never followed' % (code, newurl))


def tls_context(ca_file=None, ca_pem=None):
    """System roots plus an optional private CA (a PEM file, or PEM text). Verification always on."""
    ctx = _lh_ssl.create_default_context()
    ctx.minimum_version = _lh_ssl.TLSVersion.TLSv1_2
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    if ca_pem:
        if not isinstance(ca_pem, str) or '-----BEGIN CERTIFICATE-----' not in ca_pem:
            raise TransportRefused('server_ca is not PEM certificate text')
        ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def opener(url, allow_plain_http=False, ca_file=None, ca_pem=None):
    """An opener for labd at url: refuses the URL now if it breaks the policy, and checks every request it sends."""
    check_url(url, allow_plain_http)
    o = _lh_req.OpenerDirector()
    for h in (_LhGuard(allow_plain_http), _lh_req.HTTPHandler(), _lh_req.HTTPSHandler(context=tls_context(ca_file, ca_pem)),
              _LhNoRedirect(), _lh_req.HTTPDefaultErrorHandler(), _lh_req.HTTPErrorProcessor(), _lh_req.UnknownHandler()):
        o.add_handler(h)
    return o


def maintainer_policy(config, environ):
    """A Maintainer tool's choices, from MACLAB_CA_FILE / MACLAB_ALLOW_PLAIN_HTTP=1, else client.json's
    "ca_file" / "allow_plain_http": true. Plain http to a non-loopback host needs one of the two opt-ins."""
    ca_file = environ.get('MACLAB_CA_FILE') or config.get('ca_file') or None
    allow = environ.get('MACLAB_ALLOW_PLAIN_HTTP') == '1' or config.get('allow_plain_http') is True
    return {'allow_plain_http': allow, 'ca_file': ca_file}


def agent_policy(agent):
    """A Mac's choices, from /etc/maclab/agent.json, the same rule as lab-agent: "server_ca" is PEM text;
    "allow_plain_http": true opts in, false refuses, and an agent.json without the key (written by an older lab-agent)
    keeps plain http with a warning. Returns (policy, warning or None)."""
    warning = None
    if 'allow_plain_http' in agent:
        if not isinstance(agent['allow_plain_http'], bool):
            raise TransportRefused('agent.json allow_plain_http must be true or false')
        allow = agent['allow_plain_http']
    else:
        allow = True
        u = _lh_parse.urlsplit(agent.get('server') or '')
        if u.scheme == 'http' and not _lh_loopback(u.hostname or ''):
            warning = ('agent.json has no allow_plain_http (an older lab-agent wrote it), so plain http to %s is allowed '
                       'as before; run lab-agent setup again with --ca-file or --allow-plain-http to decide' % u.hostname)
    return {'allow_plain_http': allow, 'ca_pem': agent.get('server_ca') or None}, warning
# <<< maclab-labhttp v1 <<<



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
    """The agent's labd URL, secret and transport, by lab-agent's own rule (agent_policy above)."""
    a = json.loads(c.read_small(c.P('/etc/maclab/agent.json'), 65536))
    server = a['server'].rstrip('/')
    policy, warning = agent_policy(a)
    return server, a['secret'], opener(server, **policy), warning


def fetch(ctx):
    cfg = ctx.config
    server, secret, op, warning = _agent_creds()
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
            with op.open(req, timeout=120) as r:
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
    out = {'artifacts': got}
    if warning:
        out['transport_warning'] = warning
    return out
