"""controller.API's labd transport (docs/https.md) against loopback servers with a throwaway CA."""
import importlib.util
import tempfile
import unittest
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent


def load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


fx_tls = load('fx_tls', REPO / 'tools/bt2/tests/fx_tls.py')
ctl = load('m1_controller_https', HERE / 'controller.py')
DEV = {'name': 'm1', 'state': 'ready'}


@unittest.skipUnless(Path(fx_tls.OPENSSL).exists(), 'openssl needed for the test CA')
class ControllerTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pki = fx_tls.make_pki(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def serve(self, route, cert='good'):
        s = fx_tls.Server(route, self.pki[cert] if cert else None)
        self.addCleanup(s.close)
        return s

    def test_request_over_tls_with_the_private_ca(self):
        s = self.serve(fx_tls.json_route({('GET', '/maclab/api/devices/m1'): (200, DEV)}))
        api = ctl.API({'url': s.url(prefix='/maclab'), 'token': 't', 'ca_file': str(self.pki['ca'])})
        self.assertEqual(api.request('/api/devices/m1', timeout=10), DEV)
        self.assertTrue(s.records[0]['auth'])

    def test_unknown_ca_refused_before_any_request(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEV)}))
        with self.assertRaises(urllib.error.URLError):
            ctl.API({'url': s.url(), 'token': 't'}).request('/api/devices/m1', timeout=10)
        self.assertEqual(s.records, [])

    def test_redirect_not_followed(self):
        sink = self.serve(fx_tls.json_route({}), cert=None)
        s = self.serve(fx_tls.redirect_route(sink.url() + '/steal'))
        with self.assertRaises(ctl.TransportRefused):
            ctl.API({'url': s.url(), 'token': 't', 'ca_file': str(self.pki['ca'])}).request('/api/devices/m1', timeout=10)
        self.assertEqual(sink.records, [])

    def test_plain_http_rule(self):
        with self.assertRaises(ctl.TransportRefused):
            ctl.API({'url': 'http://192.0.2.10:7770', 'token': 't'})
        ctl.API({'url': 'http://192.0.2.10:7770', 'token': 't', 'allow_plain_http': True})
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEV)}), cert=None)
        self.assertEqual(ctl.API({'url': s.url(), 'token': 't'}).request('/api/devices/m1', timeout=10), DEV)


if __name__ == '__main__':
    unittest.main()
