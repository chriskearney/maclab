"""The labd client transport policy (bt2.labhttp, docs/https.md) through bt2's real Labd client and the target's real
fetch, against loopback servers with a throwaway CA. Run network-denied; nothing leaves 127.0.0.1/::1."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
BT2 = HERE.parent
REPO = BT2.parent.parent
sys.path.insert(0, str(BT2))
sys.path.insert(0, str(HERE))

import fx_tls  # noqa: E402
from bt2 import labd, labhttp  # noqa: E402

BLOCK_FILES = ['tools/bt2/bt2/labhttp.py', 'tools/bt2/target/preflight.py', 'scripts/boot-test/runtime.py',
               'scripts/workflow/m1/controller.py']
DEVICE = {'name': 'm1', 'state': 'ready'}


def block(path):
    t = (REPO / path).read_text()
    b = t.index('# >>> maclab-labhttp v1')
    e = t.index('# <<< maclab-labhttp v1 <<<')
    return t[b:e]


def have_ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(('::1', 0))
        return True
    except OSError:
        return False


@unittest.skipUnless(Path(fx_tls.OPENSSL).exists(), 'openssl needed for the test CA')
class Transport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pki = fx_tls.make_pki(cls.tmp.name)
        cls.ca = str(cls.pki['ca'])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def serve(self, route, cert='good', host='127.0.0.1'):
        s = fx_tls.Server(route, self.pki[cert] if cert else None, host=host)
        self.addCleanup(s.close)
        return s

    def labd(self, url, env=None, config=None):
        return labd.Labd(url, 'tok-secret', config=config or {}, environ=env or {})

    # ---- TLS trust ------------------------------------------------------------------------------------------
    def test_private_ca_via_env_reaches_labd_with_the_bearer(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEVICE)}))
        self.assertEqual(self.labd(s.url(), env={'MACLAB_CA_FILE': self.ca}).device('m1'), DEVICE)
        self.assertEqual([(r['method'], r['path'], r['auth']) for r in s.records], [('GET', '/api/devices/m1', True)])

    def test_private_ca_via_client_json(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEVICE)}))
        self.assertEqual(self.labd(s.url(), config={'ca_file': self.ca}).device('m1'), DEVICE)

    def test_path_prefix_is_kept(self):
        s = self.serve(fx_tls.json_route({('GET', '/maclab/api/devices/m1'): (200, DEVICE)}))
        api = self.labd(s.url(prefix='/maclab/'), env={'MACLAB_CA_FILE': self.ca})
        self.assertEqual(api.device('m1'), DEVICE)
        self.assertEqual(s.records[0]['path'], '/maclab/api/devices/m1')

    def test_unknown_ca_is_refused_before_any_request(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEVICE)}))
        with self.assertRaises(urllib.error.URLError) as e:
            self.labd(s.url()).device('m1')
        self.assertIn('CERTIFICATE_VERIFY_FAILED', str(e.exception))
        self.assertEqual(s.records, [])

    def test_wrong_name_is_refused_before_any_request(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEVICE)}), cert='wrong')
        with self.assertRaises(urllib.error.URLError):
            self.labd(s.url(), env={'MACLAB_CA_FILE': self.ca}).device('m1')
        self.assertEqual(s.records, [])

    # ---- redirects ------------------------------------------------------------------------------------------
    def test_redirect_to_plain_http_is_not_followed(self):
        sink = self.serve(fx_tls.json_route({}), cert=None)
        s = self.serve(fx_tls.redirect_route(sink.url() + '/steal'))
        with self.assertRaises(labhttp.TransportRefused) as e:
            self.labd(s.url(), env={'MACLAB_CA_FILE': self.ca}).device('m1')
        self.assertIn('redirects are never followed', str(e.exception))
        self.assertEqual(sink.records, [])

    def test_same_origin_307_is_not_followed_either(self):
        s = self.serve(fx_tls.redirect_route('/api/elsewhere', code=307))
        with self.assertRaises(labhttp.TransportRefused):
            self.labd(s.url(), env={'MACLAB_CA_FILE': self.ca}).post('/api/jobs', {})
        self.assertEqual([r['path'] for r in s.records], ['/api/jobs'])

    # ---- plain http -----------------------------------------------------------------------------------------
    def test_plain_http_to_a_non_loopback_host_is_refused_before_sending(self):
        for url in ('http://192.0.2.10:7770', 'http://labd.local:7770', 'http://labd:7770', 'http://100.64.0.1:7770',
                    'http://10.1.1.5:7770', 'http://127.1:7770', 'http://labd.tail1234.ts.net:7770'):
            with self.subTest(url=url), self.assertRaises(labhttp.TransportRefused):
                self.labd(url)

    def test_plain_http_opt_in_by_env_or_config(self):
        for env, config in (({'MACLAB_ALLOW_PLAIN_HTTP': '1'}, {}), ({}, {'allow_plain_http': True})):
            api = self.labd('http://192.0.2.10:7770', env=env, config=config)
            # the policy lets it through; the denied network then refuses the connection itself
            with self.assertRaises(urllib.error.URLError) as e:
                api.get('/api/devices', timeout=3)
            self.assertNotIsInstance(e.exception, labhttp.TransportRefused)

    def test_opt_in_must_be_exact(self):
        for env, config in (({'MACLAB_ALLOW_PLAIN_HTTP': 'true'}, {}), ({}, {'allow_plain_http': 'true'}),
                            ({'MACLAB_ALLOW_PLAIN_HTTP': '0'}, {})):
            with self.subTest(env=env, config=config), self.assertRaises(labhttp.TransportRefused):
                self.labd('http://192.0.2.10:7770', env=env, config=config)

    def test_plain_http_to_loopback_needs_no_opt_in(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEVICE)}), cert=None)
        for host in ('127.0.0.1', 'localhost'):
            with self.subTest(host=host):
                self.assertEqual(self.labd(s.url(host=host)).device('m1'), DEVICE)

    @unittest.skipUnless(have_ipv6_loopback(), 'no ::1')
    def test_plain_http_to_ipv6_loopback(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEVICE)}), cert=None, host='::1')
        self.assertEqual(self.labd(s.url()).device('m1'), DEVICE)

    def test_credentials_in_the_url_and_other_schemes_are_refused(self):
        for url in ('https://u:p@labd.example', 'file:///etc/passwd', 'ftp://labd.example', 'https://'):
            with self.subTest(url=url), self.assertRaises(labhttp.TransportRefused):
                self.labd(url)

    def test_every_request_is_checked_not_just_the_configured_url(self):
        op = labhttp.opener('https://labd.example', ca_file=self.ca)
        with self.assertRaises(labhttp.TransportRefused):
            op.open('http://192.0.2.10:7770/api/devices', timeout=3)
        with self.assertRaises(urllib.error.URLError):   # no file: handler at all
            op.open('file:///etc/hostname', timeout=3)

    def test_environment_proxies_are_ignored(self):
        s = self.serve(fx_tls.json_route({('GET', '/api/devices/m1'): (200, DEVICE)}))
        old = {k: os.environ.get(k) for k in ('https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy')}
        try:
            for k in ('https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'):
                os.environ[k] = 'http://127.0.0.1:9'          # nothing listens there
            os.environ.pop('no_proxy', None)
            self.assertEqual(self.labd(s.url(), env={'MACLAB_CA_FILE': self.ca}).device('m1'), DEVICE)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    # ---- bt2's own calls --------------------------------------------------------------------------------------
    def test_artifact_grants_asks_for_exactly_the_shas_and_checks_the_answer(self):
        a, b = 'a' * 64, 'b' * 64

        def answer(body):
            q = json.loads(body)
            return {'device': 'm1', 'artifacts': q['artifacts'], 'expires': '2026-10-31T12:45:00Z'}
        s = self.serve(fx_tls.json_route({('POST', '/maclab/api/devices/m1/artifact-grants'): (200, answer)}))
        api = self.labd(s.url(prefix='/maclab'), env={'MACLAB_CA_FILE': self.ca})
        api.artifact_grants('m1', [b, a], 2700)
        self.assertEqual(json.loads(s.records[0]['body']), {'artifacts': [a, b], 'ttl_sec': 2700})
        api.artifact_grants('m1', [], 2700)  # revoke
        self.assertEqual(json.loads(s.records[1]['body']), {'artifacts': [], 'ttl_sec': 2700})

    def test_artifact_grants_refuses_an_answer_that_differs(self):
        s = self.serve(fx_tls.json_route({('POST', '/api/devices/m1/artifact-grants'):
                                          (200, {'device': 'm1', 'artifacts': ['c' * 64], 'expires': 'x'})}))
        with self.assertRaises(labd.APIError):
            self.labd(s.url(), env={'MACLAB_CA_FILE': self.ca}).artifact_grants('m1', ['a' * 64], 2700)

    def test_wait_asks_in_calls_of_at_most_50_seconds(self):
        calls = []

        def route(method, path, body, headers):
            calls.append(path)
            state = 'done' if len(calls) == 3 else 'running'
            return 200, {'Content-Type': 'application/json'}, json.dumps({'id': 'j1', 'state': state}).encode()
        s = self.serve(route)
        j = self.labd(s.url(), env={'MACLAB_CA_FILE': self.ca}).wait('j1', timeout=3000)
        self.assertEqual(j['state'], 'done')
        self.assertEqual(calls, ['/api/jobs/j1/wait?timeout=50'] * 3)

    # ---- the target's fetch (agent.json rule) ----------------------------------------------------------------
    def run_fetch(self, agent, routes, cert='good'):
        """The real target preflight.fetch in a fresh interpreter (BT2_TEST_ROOT is read at import)."""
        s = self.serve(fx_tls.json_route(routes), cert=cert)
        root = Path(tempfile.mkdtemp(dir=self.tmp.name))
        (root / 'etc/maclab').mkdir(parents=True)
        agent = {k: (v.replace('SERVER', s.url()) if isinstance(v, str) else v) for k, v in agent.items()}
        (root / 'etc/maclab/agent.json').write_text(json.dumps(agent))
        run = root / 'run'
        run.mkdir()
        code = '''
import json, sys
sys.path.insert(0, sys.argv[1])
import preflight
class Ctx:
    config = json.loads(sys.argv[3])
    def sub(self, name):
        p = __import__("pathlib").Path(sys.argv[2]) / name; p.mkdir(exist_ok=True); return p
try:
    print(json.dumps({"ok": preflight.fetch(Ctx())}))
except Exception as e:
    print(json.dumps({"error": type(e).__name__, "msg": str(e)}))
'''
        payload = b'kernel package bytes'
        sha = __import__('hashlib').sha256(payload).hexdigest()
        routes[('GET', '/api/agent/artifacts/' + sha)] = (200, payload)
        cfg = {'candidates': [{'file': 'k.pkg.tar.zst'}], 'artifact_shas': {'k.pkg.tar.zst': sha}}
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'BT2_TEST_ROOT': str(root)}
        r = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(BT2 / 'target'), str(run), json.dumps(cfg)],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout), s

    def test_target_fetch_with_server_ca(self):
        out, s = self.run_fetch({'server': 'SERVER', 'secret': 's', 'server_ca': self.pki['ca'].read_text(),
                                 'allow_plain_http': False}, {})
        self.assertIn('ok', out, out)
        self.assertNotIn('transport_warning', out['ok'])
        self.assertTrue(s.records[0]['auth'])

    def test_target_fetch_without_server_ca_refuses_the_private_ca(self):
        out, s = self.run_fetch({'server': 'SERVER', 'secret': 's', 'allow_plain_http': False}, {})
        self.assertEqual(out.get('error'), 'URLError', out)
        self.assertEqual(s.records, [])

    def test_target_fetch_legacy_agent_json_keeps_plain_http_with_a_warning(self):
        # the legacy server is a non-loopback http URL; checked by the policy alone (the fetch itself is not reached)
        policy, warning = labhttp.agent_policy({'server': 'http://100.64.0.1:7770', 'secret': 's'})
        self.assertTrue(policy['allow_plain_http'])
        self.assertIn('older lab-agent', warning)
        labhttp.opener('http://100.64.0.1:7770', **policy)
        # and through the real fetch, a legacy agent.json over plain loopback http still works and reports no warning
        out, s = self.run_fetch({'server': 'SERVER', 'secret': 's'}, {}, cert=None)
        self.assertIn('ok', out, out)

    def test_target_agent_rule(self):
        with self.assertRaises(labhttp.TransportRefused):
            labhttp.opener('http://100.64.0.1:7770', **labhttp.agent_policy(
                {'server': 'http://100.64.0.1:7770', 'allow_plain_http': False})[0])
        p, w = labhttp.agent_policy({'server': 'http://100.64.0.1:7770', 'allow_plain_http': True})
        self.assertIsNone(w)
        labhttp.opener('http://100.64.0.1:7770', **p)
        # same as lab-agent: without the key, plain http only for an agent.json whose own server is plain non-loopback
        p, w = labhttp.agent_policy({'server': 'https://chonkbase.net/maclab'})
        self.assertEqual((p['allow_plain_http'], w), (False, None))
        with self.assertRaises(labhttp.TransportRefused):
            labhttp.opener('https://chonkbase.net/maclab', **p).open('http://100.64.0.1:7770/api/agent/artifacts/x', timeout=3)
        p, w = labhttp.agent_policy({'server': 'http://127.0.0.1:7770'})
        self.assertEqual((p['allow_plain_http'], w), (False, None))
        labhttp.opener('http://127.0.0.1:7770', **p)   # loopback needs no opt-in
        for bad in ({'server': 'https://x', 'allow_plain_http': 'yes'}, {'server': 'https://x', 'server_ca': 'not pem'}):
            with self.subTest(bad=bad), self.assertRaises(labhttp.TransportRefused):
                labhttp.opener('https://x', **labhttp.agent_policy(bad)[0])

    def test_target_fetch_redirect_is_not_followed(self):
        sink = self.serve(fx_tls.json_route({}), cert=None)
        root_route = fx_tls.redirect_route(sink.url() + '/steal')
        s = self.serve(root_route)
        agent = {'server': s.url(), 'secret': 's', 'server_ca': self.pki['ca'].read_text(), 'allow_plain_http': False}
        policy, _ = labhttp.agent_policy(agent)
        with self.assertRaises(labhttp.TransportRefused):
            labhttp.opener(s.url(), **policy).open(s.url() + '/api/agent/artifacts/' + 'a' * 64, timeout=5)
        self.assertEqual(sink.records, [])


class Copies(unittest.TestCase):
    def test_every_embedded_policy_block_is_the_canonical_one(self):
        canon = block(BLOCK_FILES[0])
        for f in BLOCK_FILES[1:]:
            with self.subTest(file=f):
                self.assertEqual(block(f), canon)

    def test_no_python_labd_caller_uses_bare_urlopen(self):
        """Every urllib caller of labd under tools/ and scripts/ goes through the policy, except the pinned frozen
        sources (unchanged bytes; docs/https.md lists them) whose live entry point installs the policy opener."""
        frozen = {'scripts/boot-test/frozen-controller-ea3.py', 'scripts/workflow/m1/frozen-controller-ea3.py',
                  'scripts/workflow/m1/retention-core/mirror_reuse.py',
                  'scripts/workflow/m1/retention-core/retain-controller.py'}
        found = set()
        for top in ('tools', 'scripts'):
            for p in (REPO / top).rglob('*.py'):
                rel = str(p.relative_to(REPO))
                if '/tests/' in rel or p.name.startswith('test_'):
                    continue
                t = p.read_text(errors='replace')
                if 'urlopen(' in t:
                    found.add(rel)
        self.assertEqual(found - frozen, set(), 'bare urlopen outside the pinned frozen sources')
        self.assertEqual(found & frozen, frozen)


if __name__ == '__main__':
    unittest.main()
