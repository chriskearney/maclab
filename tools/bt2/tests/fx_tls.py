"""Loopback fixtures for the labd client transport tests: a throwaway CA made with openssl, and HTTP(S) servers on
127.0.0.1 that record every request that reaches them. Nothing leaves loopback. scripts/ tests load this file by path."""
import http.server
import json
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

OPENSSL = shutil.which('openssl') or '/usr/bin/openssl'


def make_pki(d):
    """CA + a server certificate for 127.0.0.1, ::1 and localhost ('good') + one for another name ('wrong')."""
    d = Path(d)

    def run(*a):
        subprocess.run([OPENSSL, *map(str, a)], check=True, capture_output=True)

    run('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', d / 'ca.key',
        '-out', d / 'ca.pem', '-days', '2', '-subj', '/CN=maclab transport test CA',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    for name, san in (('good', 'IP:127.0.0.1,IP:::1,DNS:localhost'), ('wrong', 'DNS:other.invalid')):
        (d / (name + '.ext')).write_text('subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' % san)
        run('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', d / (name + '.key'),
            '-out', d / (name + '.csr'), '-subj', '/CN=' + name)
        run('x509', '-req', '-in', d / (name + '.csr'), '-CA', d / 'ca.pem', '-CAkey', d / 'ca.key', '-CAcreateserial',
            '-days', '2', '-extfile', d / (name + '.ext'), '-out', d / (name + '.pem'))
    return {'ca': d / 'ca.pem', 'good': (d / 'good.pem', d / 'good.key'), 'wrong': (d / 'wrong.pem', d / 'wrong.key')}


class Server:
    """A loopback server. route(method, path, body, headers) -> (code, headers, body). Every request that arrives is
    recorded with its method, path and whether it carried an Authorization header (never the value)."""

    def __init__(self, route, cert=None, host='127.0.0.1'):
        self.records = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                outer.records.append({'method': self.command, 'path': self.path,
                                      'auth': self.headers.get('Authorization') is not None, 'body': body})
                code, hdrs, out = route(self.command, self.path, body, self.headers)
                self.send_response(code)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = do_DELETE = do_PUT = _any

        cls = http.server.ThreadingHTTPServer
        if ':' in host:
            class cls(http.server.ThreadingHTTPServer):  # noqa: N801
                address_family = __import__('socket').AF_INET6
        self.httpd = cls((host, 0), H)
        self.httpd.handle_error = lambda *a: None   # a refused handshake is expected in negative tests
        self.scheme = 'http'
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*map(str, cert))
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = 'https'
        self.port = self.httpd.server_address[1]
        self.host = host
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def url(self, host=None, prefix=''):
        h = host or self.host
        return '%s://%s:%d%s' % (self.scheme, '[%s]' % h if ':' in h else h, self.port, prefix)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def json_route(table):
    """route from {(method, path): (code, obj)}; anything else 404."""
    def route(method, path, body, headers):
        code, obj = table.get((method, path), (404, {'error': 'no route'}))
        if callable(obj):
            obj = obj(body)
        if isinstance(obj, (bytes, str)):
            raw = obj if isinstance(obj, bytes) else obj.encode()
            return code, {'Content-Type': 'text/plain'}, raw
        return code, {'Content-Type': 'application/json'}, json.dumps(obj).encode()
    return route


def redirect_route(location, code=302):
    def route(method, path, body, headers):
        return code, {'Location': location}, b''
    return route
