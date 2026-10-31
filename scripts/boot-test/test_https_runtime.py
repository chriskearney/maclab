"""runtime.API's labd transport (docs/https.md), through the frozen SDK's own request() and runtime's release(),
against loopback servers with a throwaway CA. The frozen SDK's bytes stay as pinned; these tests show that its calls
now go through the policy opener, not that its earlier qualification covers it."""
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
spec = importlib.util.spec_from_file_location('fx_tls', REPO / 'tools/bt2/tests/fx_tls.py')
fx_tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx_tls)
import runtime  # noqa: E402

CAP = {'schema': 1, 'per_job_oob_isolation': True, 'transaction_isolation': True, 'modes': ['network-only']}


@unittest.skipUnless(Path(fx_tls.OPENSSL).exists(), 'openssl needed for the test CA')
class RuntimeTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pki = fx_tls.make_pki(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.env = {k: os.environ.get(k) for k in ('XDG_CONFIG_HOME', 'MACLAB_URL', 'MACLAB_TOKEN', 'MACLAB_CA_FILE',
                                                    'MACLAB_ALLOW_PLAIN_HTTP')}
        for k in self.env:
            os.environ.pop(k, None)
        self.addCleanup(self.restore)

    def restore(self):
        urllib.request.install_opener(None)
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def client(self, url, **extra):
        d = Path(tempfile.mkdtemp(dir=self.tmp.name))
        (d / 'maclab').mkdir()
        (d / 'maclab/client.json').write_text(json.dumps({'url': url, 'token': 'tok-secret', **extra}))
        os.environ['XDG_CONFIG_HOME'] = str(d)

    def serve(self, route, cert='good'):
        s = fx_tls.Server(route, self.pki[cert] if cert else None)
        self.addCleanup(s.close)
        return s

    def test_frozen_sdk_bytes_are_unchanged(self):
        self.assertEqual(hashlib.sha256((HERE / 'frozen-controller-ea3.py').read_bytes()).hexdigest(), runtime.SDK_SHA)

    def test_frozen_sdk_request_goes_through_tls_with_the_private_ca_and_prefix(self):
        s = self.serve(fx_tls.json_route({('GET', '/maclab/api/recovery'): (200, CAP)}))
        self.client(s.url(prefix='/maclab'), ca_file=str(self.pki['ca']))
        self.assertEqual(runtime.API().request('/api/recovery', timeout=10), CAP)
        self.assertEqual([(r['path'], r['auth']) for r in s.records], [('/maclab/api/recovery', True)])

    def test_frozen_sdk_request_without_the_ca_is_refused_before_any_request(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/recovery'): (200, CAP)}))
        self.client(s.url())
        with self.assertRaises(urllib.error.URLError):
            runtime.API().request('/api/recovery', timeout=10)
        self.assertEqual(s.records, [])

    def test_frozen_sdk_request_does_not_follow_a_redirect(self):
        sink = self.serve(fx_tls.json_route({}), cert=None)
        s = self.serve(fx_tls.redirect_route(sink.url() + '/steal'))
        self.client(s.url())
        os.environ['MACLAB_CA_FILE'] = str(self.pki['ca'])
        with self.assertRaises(runtime.TransportRefused):
            runtime.API().request('/api/recovery', timeout=10)
        self.assertEqual(sink.records, [])

    def test_plain_http_to_a_non_loopback_host_is_refused_before_any_request(self):
        self.client('http://192.0.2.10:7770')
        with self.assertRaises(runtime.TransportRefused):
            runtime.API()
        self.client('http://192.0.2.10:7770', allow_plain_http=True)
        runtime.API()   # explicit opt-in: accepted (no request made here)

    def test_release_goes_through_the_policy(self):
        s = self.serve(fx_tls.json_route({('DELETE', '/api/devices/m1/lease?holder=h'): (200, 'ok')}))
        self.client(s.url(), ca_file=str(self.pki['ca']))
        runtime.API().release('m1', 'h')
        self.assertEqual([(r['method'], r['auth']) for r in s.records], [('DELETE', True)])


if __name__ == '__main__':
    unittest.main()
