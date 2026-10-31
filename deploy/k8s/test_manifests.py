"""Offline checks of the rendered deploy/k8s manifests (kubectl kustomize only; never a cluster).
Run: KUBECONFIG=/dev/null python3 -I deploy/k8s/test_manifests.py   (network-denied is fine)."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

K = Path(__file__).resolve().parent
KUBECTL = shutil.which('kubectl') or '/usr/local/bin/kubectl'


def render(path):
    env = {'PATH': '/usr/bin:/bin:/usr/local/bin', 'KUBECONFIG': '/dev/null', 'HOME': os.environ.get('TMPDIR', '/tmp')}
    out = subprocess.run([KUBECTL, 'kustomize', str(path)], check=True, capture_output=True, text=True, env=env).stdout
    docs = [d for d in yaml.safe_load_all(out) if d]
    return {(d['kind'], d['metadata']['name']): d for d in docs}


def container(objs):
    return objs[('Deployment', 'maclab')]['spec']['template']['spec']['containers'][0]


@unittest.skipUnless(Path(KUBECTL).exists(), 'kubectl (kustomize) needed')
class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.o = render(K / 'base')

    def test_objects(self):
        self.assertEqual(sorted(self.o), sorted([('Namespace', 'maclab'), ('PersistentVolumeClaim', 'maclab-data'),
                                                 ('Certificate', 'maclab-tls'), ('Service', 'maclab'),
                                                 ('NetworkPolicy', 'maclab'), ('Ingress', 'maclab'),
                                                 ('Deployment', 'maclab')]))
        self.assertFalse([k for k in self.o if k[0] == 'Secret'], 'no Secret in the manifests')

    def test_one_writer_never_two(self):
        d = self.o[('Deployment', 'maclab')]['spec']
        self.assertEqual(d['replicas'], 1)
        self.assertEqual(d['strategy'], {'type': 'Recreate'})
        self.assertEqual(self.o[('PersistentVolumeClaim', 'maclab-data')]['spec']['accessModes'], ['ReadWriteOnce'])

    def test_non_root_and_no_host_paths(self):
        p = self.o[('Deployment', 'maclab')]['spec']['template']['spec']
        sc = p['securityContext']
        self.assertEqual((sc['runAsNonRoot'], sc['runAsUser'], sc['runAsGroup'], sc['fsGroup']), (True, 10001, 10001, 10001))
        self.assertFalse(p['automountServiceAccountToken'])
        c = container(self.o)['securityContext']
        self.assertEqual((c['allowPrivilegeEscalation'], c['readOnlyRootFilesystem'], c['capabilities']), (False, True, {'drop': ['ALL']}))
        self.assertFalse([v for v in p['volumes'] if 'hostPath' in v], 'no hostPath (no i9beef paths)')
        self.assertEqual({m['mountPath'] for m in container(self.o)['volumeMounts']}, {'/data', '/tmp'})

    def test_args_match_the_prefix_contract(self):
        a = container(self.o)['args']
        self.assertIn('--public-url=https://maclab.chonkbase.net', a)
        self.assertIn('--data=/data', a)
        self.assertIn('--listen=0.0.0.0:7770', a)
        self.assertIn('--allow-plain-http', a)
        self.assertNotIn('--tailscale', ' '.join(a))
        tp = [x for x in a if x.startswith('--trusted-proxy=')]
        self.assertEqual(len(tp), 1)
        self.assertEqual(tp[0], '--trusted-proxy=SET-INGRESS-NGINX-POD-CIDR', 'unset placeholder must stay a non-CIDR')
        self.assertEqual(container(self.o)['readinessProbe']['httpGet']['path'], '/healthz')
        self.assertEqual(container(self.o)['livenessProbe']['httpGet']['path'], '/healthz')
        for p in ('readinessProbe', 'livenessProbe'):
            self.assertEqual(container(self.o)[p]['httpGet']['httpHeaders'], [{'name': 'X-Forwarded-Proto', 'value': 'https'},
                             {'name': 'X-Forwarded-Host', 'value': 'maclab.chonkbase.net'}], 'probe names the public origin')
        self.assertEqual(container(self.o)['image'], 'ghcr.io/iconidentify/maclab:SET-IMAGE-TAG')

    def test_ingress_passes_the_prefix_through_and_holds_long_requests(self):
        i = self.o[('Ingress', 'maclab')]
        ann = i['metadata']['annotations']
        self.assertFalse([k for k in ann if 'rewrite' in k or 'x-forwarded-prefix' in k or 'configuration-snippet' in k])
        self.assertGreaterEqual(int(ann['nginx.ingress.kubernetes.io/proxy-read-timeout']), 3700)
        self.assertGreaterEqual(int(ann['nginx.ingress.kubernetes.io/proxy-send-timeout']), 3700)
        self.assertEqual(ann['nginx.ingress.kubernetes.io/proxy-buffering'], 'off')
        self.assertEqual(ann['nginx.ingress.kubernetes.io/proxy-request-buffering'], 'off')
        r = i['spec']['rules'][0]
        self.assertEqual((r['host'], r['http']['paths'][0]['path'], r['http']['paths'][0]['pathType']), ('maclab.chonkbase.net', '/', 'Prefix'))
        self.assertEqual(self.o[('Certificate', 'maclab-tls')]['spec']['dnsNames'], ['maclab.chonkbase.net'])
        self.assertEqual(i['spec']['tls'][0]['hosts'], ['maclab.chonkbase.net'])
        self.assertEqual(i['spec']['tls'][0]['secretName'], self.o[('Certificate', 'maclab-tls')]['spec']['secretName'])

    def test_network_policy_matches_the_pod(self):
        n = self.o[('NetworkPolicy', 'maclab')]['spec']
        pod = self.o[('Deployment', 'maclab')]['spec']['template']['metadata']['labels']
        self.assertEqual(n['podSelector']['matchLabels'], pod)
        self.assertEqual(n['ingress'][0]['from'], [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'ingress-nginx'}}}])
        self.assertEqual(n['ingress'][0]['ports'][0]['port'], container(self.o)['ports'][0]['containerPort'])
        public = n['egress'][1]['to'][0]['ipBlock']
        self.assertIn('10.0.0.0/8', public['except'])
        self.assertEqual([p['port'] for p in n['egress'][1]['ports']], [443])

    def test_service_reaches_the_container(self):
        s = self.o[('Service', 'maclab')]['spec']
        self.assertEqual(s['ports'][0]['targetPort'], container(self.o)['ports'][0]['name'])
        self.assertEqual(s['selector'], self.o[('Deployment', 'maclab')]['spec']['selector']['matchLabels'])


@unittest.skipUnless(Path(KUBECTL).exists(), 'kubectl (kustomize) needed')
class Overlays(unittest.TestCase):
    def test_path_prefix_compatibility_layout(self):
        o = render(K / 'path-prefix')
        r = o[('Ingress', 'maclab')]['spec']['rules'][0]
        self.assertEqual((r['host'], r['http']['paths'][0]['path'], r['http']['paths'][0]['pathType']), ('chonkbase.net', '/maclab', 'Prefix'))
        self.assertEqual(o[('Certificate', 'maclab-tls')]['spec']['dnsNames'], ['chonkbase.net'])
        self.assertEqual(o[('Ingress', 'maclab')]['spec']['tls'][0]['hosts'], ['chonkbase.net'])
        a = container(o)['args']
        self.assertIn('--public-url=https://chonkbase.net/maclab', a)
        self.assertNotIn('--public-url=https://maclab.chonkbase.net', a)
        for p in ('readinessProbe', 'livenessProbe'):
            self.assertEqual(container(o)[p]['httpGet']['path'], '/maclab/healthz')
            self.assertEqual(container(o)[p]['httpGet']['httpHeaders'][1], {'name': 'X-Forwarded-Host', 'value': 'chonkbase.net'})
        ann = o[('Ingress', 'maclab')]['metadata']['annotations']
        self.assertFalse([k for k in ann if 'rewrite' in k or 'x-forwarded-prefix' in k])

    def test_terms_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'k8s'
            shutil.copytree(K, root, ignore=shutil.ignore_patterns('*.py', '__pycache__'))
            (root / 'terms/terms.txt').write_text('Example terms for the render test only.\n')
            o = render(root / 'terms')
        c = container(o)
        self.assertIn('--terms-file=/etc/maclab/terms.txt', c['args'])
        self.assertIn({'name': 'terms', 'mountPath': '/etc/maclab', 'readOnly': True}, c['volumeMounts'])
        cm = [k for k in o if k[0] == 'ConfigMap']
        self.assertEqual(len(cm), 1)
        self.assertTrue(cm[0][1].startswith('maclab-terms-'), 'content-hashed name: a new text rolls the pod')


if __name__ == '__main__':
    unittest.main()
