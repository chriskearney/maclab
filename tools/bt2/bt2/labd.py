#!/usr/bin/env python3
"""Minimal labd API client for bt2. Token is read from ~/.config/maclab/client.json and never logged.

Transport follows bt2.labhttp (docs/https.md): https with the system roots plus MACLAB_CA_FILE / client.json "ca_file";
plain http only to loopback unless MACLAB_ALLOW_PLAIN_HTTP=1 or client.json "allow_plain_http": true; redirects refused.
The URL may carry a path prefix (https://example.net/maclab): every API path is appended to it."""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from bt2 import labhttp

SECRET_KEYS = ('token', 'secret', 'password', 'authkey')
TransportRefused = labhttp.TransportRefused
WAIT_CHUNK = 50   # each GET /wait asks labd to answer within this, under a reverse proxy's 60 s idle timeout


class APIError(RuntimeError):
    def __init__(self, code, body, path):
        super().__init__('labd %s %s: %s' % (code, path, body[:500]))
        self.code = code
        self.body = body
        self.path = path


def redact(o):
    if isinstance(o, dict):
        return {k: ('<redacted>' if any(s in k.lower() for s in SECRET_KEYS) else redact(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [redact(x) for x in o]
    return o


class Labd:
    def __init__(self, url=None, token=None, *, config=None, environ=None):
        c = config
        if c is None and (url is None or token is None):
            c = json.loads((Path.home() / '.config/maclab/client.json').read_bytes())
        c = c or {}
        url = url or c['url']
        token = token or c['token']
        self.url = url.rstrip('/')
        self._token = token
        policy = labhttp.maintainer_policy(c, os.environ if environ is None else environ)
        self._opener = labhttp.opener(self.url, **policy)   # refuses a disallowed URL before any request

    # -- transport -------------------------------------------------------
    def _req(self, method, path, body=None, raw=None, timeout=60, ctype='application/json', want_bytes=False,
             limit=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={'Authorization': 'Bearer ' + self._token,
                                              **({'Content-Type': ctype} if data is not None else {})})
        try:
            with self._opener.open(req, timeout=timeout) as r:
                b = r.read() if limit is None else r.read(limit + 1)
        except urllib.error.HTTPError as e:
            raise APIError(e.code, e.read().decode(errors='replace'), path) from None
        if limit is not None and len(b) > limit:
            raise APIError(413, 'response larger than %d bytes' % limit, path)
        if want_bytes:
            return b
        if not b:
            return None
        try:
            return json.loads(b)
        except ValueError:
            return b.decode(errors='replace')

    def get(self, path, timeout=30):
        return self._req('GET', path, timeout=timeout)

    def post(self, path, body=None, timeout=60):
        return self._req('POST', path, body=body if body is not None else {}, timeout=timeout)

    # -- devices / lease / recovery mode ----------------------------------
    def device(self, name):
        return self.get('/api/devices/' + urllib.parse.quote(name, safe=''))

    def capabilities(self):
        return self.get('/api/recovery', timeout=10)

    def lease(self, name, holder, ttl_sec):
        return self.post('/api/devices/%s/lease' % urllib.parse.quote(name, safe=''),
                         {'holder': holder, 'ttl_sec': int(ttl_sec)}, timeout=15)

    def release(self, name, holder):
        path = '/api/devices/%s/lease?holder=%s' % (urllib.parse.quote(name, safe=''),
                                                    urllib.parse.quote(holder, safe=''))
        return self._req('DELETE', path, timeout=15)

    def recovery_mode(self, name, mode, holder, transaction):
        return self.post('/api/devices/%s/recovery-mode' % urllib.parse.quote(name, safe=''),
                         {'mode': mode, 'holder': holder, 'transaction': transaction}, timeout=25)

    def oob(self, name):
        return self.get('/api/devices/%s/oob' % urllib.parse.quote(name, safe=''), timeout=15)

    # -- exec / artifacts ---------------------------------------------------
    def exec(self, name, command, timeout_sec=120):
        return self.post('/api/devices/%s/exec' % urllib.parse.quote(name, safe=''),
                         {'command': command, 'timeout_sec': int(timeout_sec)}, timeout=int(timeout_sec) + 90)

    def put_artifact(self, data, timeout=600):
        return self._req('POST', '/api/artifacts', raw=data, timeout=timeout, ctype='application/octet-stream')

    def artifact_grants(self, name, shas, ttl_sec):
        """Let the Mac's current enrollment fetch exactly these shas from /api/agent/artifacts until ttl_sec runs out
        (POST /api/devices/<name>/artifact-grants). An empty list revokes. The answer must name exactly what was asked;
        a grant carries its expiry, and a revocation, which has none, carries no "expires" (labd omits the zero time)."""
        shas = sorted(shas)
        res = self.post('/api/devices/%s/artifact-grants' % urllib.parse.quote(name, safe=''),
                        {'artifacts': shas, 'ttl_sec': int(ttl_sec)}, timeout=15)
        expiry_ok = (isinstance(res, dict) and isinstance(res.get('expires'), str)) if shas else \
            (isinstance(res, dict) and res.get('expires') in (None, '0001-01-01T00:00:00Z'))
        if not (isinstance(res, dict) and res.get('device') == name and sorted(res.get('artifacts') or []) == shas
                and expiry_ok):
            raise APIError(200, 'artifact grant answer differs from the request: %r' % (res,), '/api/devices/%s/artifact-grants' % name)
        return res

    # -- jobs -----------------------------------------------------------------
    def submit(self, spec):
        return self.post('/api/jobs', spec, timeout=60)

    def job(self, job_id):
        return self.get('/api/jobs/' + urllib.parse.quote(job_id, safe=''))

    def wait(self, job_id, timeout=3000):
        """The job once it is done, or as it is when timeout runs out. Asks labd in calls of at most WAIT_CHUNK
        seconds, so a reverse proxy's idle timeout never cuts one."""
        end = time.monotonic() + timeout
        while True:
            chunk = max(1, min(WAIT_CHUNK, int(end - time.monotonic())))
            j = self.get('/api/jobs/%s/wait?timeout=%d' % (urllib.parse.quote(job_id, safe=''), chunk), timeout=chunk + 30)
            if not isinstance(j, dict) or j.get('state') == 'done' or time.monotonic() >= end:
                return j

    def job_file(self, job_id, name, limit=16 << 20, timeout=60):
        """Raw bytes of one job file (GET /api/jobs/<id>/files/<name>, server.go hJobFile)."""
        if not name or name.startswith('/') or '..' in name.split('/'):
            raise ValueError('bad job file name %r' % name)
        return self._req('GET', '/api/jobs/%s/files/%s' % (urllib.parse.quote(job_id, safe=''),
                                                           urllib.parse.quote(name, safe='/')),
                         timeout=timeout, want_bytes=True, limit=limit)
