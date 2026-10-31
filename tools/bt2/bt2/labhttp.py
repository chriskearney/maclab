"""The client transport policy for Python callers of labd (docs/https.md).

The block between the markers is the canonical copy. scripts/boot-test/runtime.py, scripts/workflow/m1/controller.py and
tools/bt2/target/preflight.py carry it byte for byte, because each runs from its own bundle or directory with no shared import
path; tests/test_labhttp.py fails if any copy drifts.

- TLS 1.2+ against the system roots, plus an optional private CA. Certificate and hostname checks can't be turned off.
- Redirects are never followed: a 3xx is an error, so a bearer token never follows one to another place.
- Plain http:// goes only to a literal loopback address (127.0.0.0/8, ::1) or localhost, unless the caller opted in.
  Every request is checked before it is sent, not just the configured URL.
- No proxies from the environment, and no file:, ftp: or data: handlers.
"""

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
    "allow_plain_http": true opts in, false refuses. An agent.json without the key (written by an older lab-agent)
    keeps plain http, with a warning, only when its own server URL is plain http to a host other than loopback;
    any other agent.json without the key gets no plain http. Returns (policy, warning or None)."""
    warning = None
    if 'allow_plain_http' in agent:
        if not isinstance(agent['allow_plain_http'], bool):
            raise TransportRefused('agent.json allow_plain_http must be true or false')
        allow = agent['allow_plain_http']
    else:
        u = _lh_parse.urlsplit(agent.get('server') or '')
        allow = u.scheme == 'http' and not _lh_loopback(u.hostname or '')
        if allow:
            warning = ('agent.json has no allow_plain_http (an older lab-agent wrote it), so plain http to %s is allowed '
                       'as before; run lab-agent setup again with --ca-file or --allow-plain-http to decide' % u.hostname)
    return {'allow_plain_http': allow, 'ca_pem': agent.get('server_ca') or None}, warning
# <<< maclab-labhttp v1 <<<
