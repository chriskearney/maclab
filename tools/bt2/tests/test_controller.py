#!/usr/bin/env python3
"""bt2 controller + native tests (fakes only: no labd, SSH, M5 or device access).

Run: cd /dev/shm/claude-229/bt2 && python3.14 -m unittest tests.test_controller -v
Temp dirs live under /dev/shm/maclab-bt2-tests (the /tmp quota is full).
"""
import datetime
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import tarfile
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from bt2 import artifacts, controller, installed, native  # noqa: E402
from bt2 import labd as labd_mod  # noqa: E402
from bt2 import manifest as mgen  # noqa: E402
from fx_ctl import fakes, pkgs  # noqa: E402

SCRATCH = Path('/dev/shm/maclab-bt2-tests')
SCRATCH.mkdir(parents=True, exist_ok=True)
FROZEN_ORIG = installed.FROZEN
NATIVE_OK = all((native.DEFAULT_SRC / n).is_file() for n, _ in native.SOURCE_FILES.values())
REAL_STORE = Path.home() / '.local/share/maclab/boot-test/artifacts'
REAL_MESA = REAL_STORE / '7dc3e016b4edf218eefd19ff4cd358ee9a4f78b2b9282815637c687e185ce8bb' / \
    'mesa-aurora-1:26.3.0_devel.20261025.231095.7c86130d26c-1-aarch64.pkg.tar.zst'
REAL_VK = REAL_STORE / '38750b65df6db38e3f7b83b0236424cfe9d1573929ca0442865cc55564f3c252' / \
    'vulkan-aurora-1:26.3.0_devel.20261025.231095.7c86130d26c-1-aarch64.pkg.tar.zst'
HOLDER = 'bt2-claude'
WIFI = [{'interface': 'lo', 'mac': '00:00:00:00:00:00', 'operstate': 'unknown', 'wireless': False},
        {'interface': 'wlan0', 'mac': 'aa:bb:cc:dd:ee:01', 'operstate': 'up', 'wireless': True}]
HAPPY_STEPS_STALE = ['gate-profile', 'gate-device', 'gate-capabilities', 'gate-open-runs', 'inspect-candidates',
                     'native-sources', 'gate-frozen', 'lease', 'recovery-mode', 'probe', 'resolve-packages',
                     'baseline-mode', 'pull-bootbin', 'manifest', 'gate-native', 'config', 'push', 'upload', 'grant-artifacts', 'fetch',
                     'revoke-artifacts', 'preflight',
                     'capture', 'hold-writers', 'pull-capture', 'm5-capture', 'preinstall', 'freeze-manifest',
                     'esp-prep', 'install', 'freeze-entry', 'native', 'submit', 'job-wait', 'verify-return',
                     'locks-after-job', 'rollback', 'esp-restore', 'etc-restore', 'reboot', 'locks-after-reboot',
                     'audit-held', 'release-writers', 'settle', 'audit', 'cleanup', 'm5-result', 'release-lease']
BASE_STEPS = ['base-preinstall', 'base-freeze-manifest', 'base-freeze-entry', 'base-submit', 'base-job-wait',
              'base-verify-return', 'base-locks', 'fresh-preinstall']
# default (fresh baseline): base-manifest before any change; the base job after capture + hold-writers, before esp-prep
HAPPY_STEPS = (HAPPY_STEPS_STALE[:HAPPY_STEPS_STALE.index('gate-native')] + ['base-manifest']
               + HAPPY_STEPS_STALE[HAPPY_STEPS_STALE.index('gate-native'):HAPPY_STEPS_STALE.index('preinstall')]
               + BASE_STEPS + HAPPY_STEPS_STALE[HAPPY_STEPS_STALE.index('freeze-manifest'):])
HAPPY_TARGETS = ['fetch', 'preflight', 'capture', 'hold-writers', 'esp-prep', 'install', 'rollback', 'esp-restore',
                 'etc-restore', 'audit --held', 'release-writers', 'audit', 'cleanup']


def H(b):
    return hashlib.sha256(b).hexdigest()


def last_json(text):
    """The last JSON object emitted on a StringIO (emit() prints indented objects)."""
    i = text.rstrip().rfind('\n{')
    return json.loads(text[i + 1:] if i >= 0 else text)


class Env:
    def __init__(self, device='m1', kept_in_store=True, trailer=b'', m1n1_candidate=False):
        self.device = device
        self.tmp = Path(tempfile.mkdtemp(prefix='bt2-ctl-', dir=SCRATCH))
        self.prof = json.loads((ROOT / 'tests/devices' / (device + '.json')).read_text())
        self.co = pkgs.build_cohort(self.tmp, kept_in_store, m1n1_candidate)
        self.frozen = self.tmp / 'frozen'
        self.frozen.mkdir()
        self.bootbin = pkgs.bootbin(trailer, m1n1=pkgs.M1N1_V20 if m1n1_candidate else pkgs.M1N1)
        self.cand_bootbin = pkgs.bootbin(trailer, m1n1=pkgs.M1N1_V22)
        cands = [i for i in (artifacts.inspect(p) for p in self.co['candidates'])
                 if i['pkginfo']['pkgname'] != 'm1n1-aurora']      # the baseline release keeps the installed m1n1
        kept = [artifacts.inspect(p) for p in self.co['extra']]
        macs = {device: {'board': self.prof['board'], 'board_dtb': self.prof['board_dtb'], 'bootbin': self.bootbin}}
        _, raw, payload, _ = mgen.generate(self.prof['baseline_release'], cands + kept, macs, 'f5a82fdb-dirty')
        pkgs.make_frozen_release(self.frozen, self.prof['baseline_release'], device, raw, payload)
        kg = self.prof['known_good_kernel']
        self.lab = fakes.FakeLabd({device: {
            'name': device, 'state': 'ready', 'alive': True, 'boot_id': '00000000-0000-4000-8000-000000000000',
            'kernel': kg, 'cmdline': 'root=UUID=x rw quiet', 'known_good': kg, 'queued': 0, 'active_job': '',
            'facts': {'machine': 'aarch64', 'compatible': [self.prof['board'], 'apple,arm-platform']}, 'lease': None}})
        src = native.load_sources()
        tools = native.template_tools(src['template'])
        self.mac = fakes.FakeMac(self.lab, device, known_good=kg, candidate_kernel=pkgs.KREL7, board=self.prof['board'],
                                 packages=self.co['packages'], mtree=self.co['mtree'], bootbin=self.bootbin,
                                 tools={t['path']: t['sha256'] for t in tools.values()},
                                 gui={'user': self.prof['gui_user'], 'uid': self.prof['gui_uid']}, wifi=WIFI)
        self.mac.candidate_bootbin = self.cand_bootbin
        self.mac.versions = {H(self.bootbin): 'f5a82fdb-dirty', H(self.cand_bootbin): '5d17a034-dirty'}
        self.m5 = fakes.FakeM5()
        self.clock = fakes.FakeClock()
        # checker r3: no pins override; the fake (non-7c) archives' own pins are the cohort
        self.out = io.StringIO()
        self.err = io.StringIO()

    def ctl(self):
        self.out, self.err = io.StringIO(), io.StringIO()
        return controller.Controller(self.lab, devices_dir=ROOT / 'tests/devices', state_root=self.tmp / 'runs', ops_factory=self.mac.factory,
                                     m5_runner=self.m5, stores=[self.co['store']], frozen_root=self.frozen,
                                     sleep=self.clock.sleep, clock=self.clock,
                                     out=self.out, err=self.err)

    @property
    def rid(self):
        return 'bt2-%s-test1' % self.device

    def run(self, **kw):
        a = dict(device=self.device, artifact_paths=self.co['candidates'], mode='network-only', run_id=self.rid)
        a.update(kw)
        return self.ctl().run(**a)

    def records(self):
        return controller.Journal(self.tmp / 'runs' / self.rid).records

    def rd(self):
        return self.tmp / 'runs' / self.rid

    def diag(self):
        return 'OUT:\n%s\nERR:\n%s' % (self.out.getvalue()[-4000:], self.err.getvalue()[-2000:])

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


@unittest.skipUnless(NATIVE_OK, 'reference native components not present')
class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.envs = []

    def tearDown(self):
        installed.FROZEN = FROZEN_ORIG
        for e in self.envs:
            e.close()

    def env(self, *a, **k):
        e = Env(*a, **k)
        self.envs.append(e)
        return e

    def test_happy_path_step_order_and_journal(self):
        e = self.env()
        rc = e.run()
        self.assertEqual(rc, 0, e.diag())
        recs = e.records()
        intents = [r['step'] for r in recs if r['event'] == 'intent']
        self.assertEqual(intents, HAPPY_STEPS)
        # every intent is closed by a done for the same step before the next intent
        steps = [r for r in recs if r['event'] in ('intent', 'done', 'failed')]
        for a, b in zip(steps[::2], steps[1::2]):
            self.assertEqual((a['event'], b['event'], a['step']), ('intent', 'done', b['step']))
        inv = {r['step']: (r['inverse'], r['inverse_followups']) for r in recs if r['event'] == 'intent'}
        self.assertEqual(inv['install'], ('rollback', ['esp-restore', 'etc-restore']))
        self.assertEqual(inv['esp-prep'], ('esp-restore', []))
        self.assertEqual(inv['hold-writers'], ('release-writers', []))
        self.assertTrue(all(v[0] is None for k, v in inv.items() if k not in ('install', 'esp-prep', 'hold-writers')))
        self.assertEqual(e.mac.targets(), HAPPY_TARGETS)
        end = controller.last_end(recs)
        self.assertEqual((end['status'], end['lease_released']), ('PASSED_RESTORED_LEASE_RELEASED', True))
        # lease: own holder, ttl >= 7200, released at the end; transaction = run id
        leases = [c for c in e.lab.calls if c[:2] == ('POST', '/api/devices/m1/lease')]
        self.assertEqual(len(leases), 1)
        self.assertGreaterEqual(leases[0][3], 7200)
        self.assertIsNone(e.lab.devices['m1']['lease'])
        self.assertEqual(e.lab.devices['m1']['recovery_transaction'], e.rid)
        self.assertIn(('DELETE', '/api/devices/m1/lease', HOLDER), e.lab.calls)
        # manifest generated, config bound to it, labd frozen + job spec bound to it
        rd = e.rd()
        man_raw = (rd / 'manifest.json').read_bytes()
        man = json.loads(man_raw)
        cfg = json.loads((rd / 'config.json').read_bytes())
        self.assertEqual(cfg['expected_bootbin_sha256'], man['macs']['m1']['boot_bin_sha256'])
        self.assertEqual(cfg['expected_bootbin_sha256'], H(e.bootbin))
        self.assertEqual({o['name']: o['version'] for o in cfg['originals']},
                         {'linux-aurora': '7.2.11.aurora6-1', 'mesa-aurora': '1:26.3.0_devel.147a-1',
                          'vulkan-aurora': '1:26.3.0_devel.147a-1', 'omarchy-mac-boot': '20261010-1'})
        self.assertEqual(sorted(a['name'] for a in man['artifacts']),
                         ['linux-aurora', 'm1n1-aurora', 'mesa-aurora', 'omarchy-mac-boot', 'uboot-asahi', 'vulkan-aurora'])
        self.assertEqual(man['release'], 'bt2-m1-test1')
        self.assertEqual(e.lab.frozen['bt2-m1-test1']['manifest_sha256'], H(man_raw))
        self.assertTrue((e.frozen / 'bt2-m1-test1' / 'PINS.preinstall').is_file())
        diff = [r for r in recs if r.get('step') == 'manifest' and r['event'] == 'done'][0]['summary']['diff_vs_source']
        self.assertEqual(diff, [])
        jobs = list(e.lab.jobs.values())
        self.assertEqual(len(jobs), 2)                                   # base + candidate
        spec = jobs[1]['spec']
        script = (rd / 'native/script.sh').read_bytes()
        self.assertEqual(spec['installed_manifest'], H(man_raw))
        self.assertEqual([t for t in spec['tests'] if t['name'] == 'native-gl-vk'][0]['script'], H(script))
        self.assertEqual((spec['recovery_mode'], spec['recovery_transaction'], spec['holder']),
                         ('network-only', e.rid, HOLDER))
        remote = '/var/lib/maclab/bt2/' + e.rid
        inp = json.loads(e.mac.files[remote + '/native-input.json'])
        cohort = {'expected_kernel': inp['expected_kernel'],
                  'providers': {r: {k: p[k] for k in ('path', 'sha256', 'bytes')} for r, p in inp['providers'].items()}}
        self.assertEqual(script, native.build_script(remote, native.load_sources(), cohort))   # cohort compiled in
        self.assertEqual(inp['cohort_sha256'], H(native.encode(cohort)))
        gate = [r for r in recs if r.get('step') == 'gate-native' and r['event'] == 'done'][0]['summary']
        self.assertEqual((gate['cohort_kernel'], gate['cohort_sha256']), (pkgs.KREL7, H(native.encode(cohort))))
        self.assertEqual(inp['providers']['gallium']['sha256'], H(b'gallium-7c'))
        self.assertEqual(inp['providers']['vulkan']['sha256'], H(b'vk-7c'))
        self.assertEqual(inp['expected_kernel'], pkgs.KREL7)
        self.assertEqual(inp['wifi'], {'interface': 'wlan0', 'mac': 'aa:bb:cc:dd:ee:01'})
        self.assertEqual(H(e.mac.files[remote + '/native/checker.py']), native.CHECKER_SHA)
        # target package + config pushed under t/, artifacts uploaded before fetch
        self.assertIn(remote + '/t/__main__.py', e.mac.files)
        self.assertEqual(H(e.mac.files[remote + '/config.json']), H((rd / 'config.json').read_bytes()))
        # evidence on the controller and the M5
        self.assertEqual(len(list((rd / 'target').glob('*.json'))), len(HAPPY_TARGETS))
        calls = [json.loads(x) for x in (rd / 'labd-calls.jsonl').read_text().splitlines()]
        self.assertIn('submit', [c['call'] for c in calls])
        m5 = e.m5.roots['bt2-' + e.rid]
        self.assertTrue({'capture.tar.gz', 'capture-state.json', 'capture-result.json'} <= set(m5))
        self.assertTrue(any(n.startswith('run-result-') for n in m5))
        self.assertEqual(json.loads((rd / 'RESULT.json').read_bytes())['job']['outcome'], 'pass')

    # -- boot.bin-changing path (--allow-bootbin-change) -----------------------------------------------------------
    BB_STEPS = None

    def bb_steps(self):
        s = list(HAPPY_STEPS)
        s.insert(s.index('install') + 1, 'bootbin-guard-install')
        s.insert(s.index('verify-return') + 1, 'bootbin-guard-check')
        s.insert(s.index('rollback'), 'bootbin-guard-remove')
        s.insert(s.index('reboot') + 1, 'stage2-final')
        return s

    def test_bootbin_change_refused_without_the_flag(self):
        e = self.env(m1n1_candidate=True)
        self.assertEqual(e.run(), 3, e.diag())
        out = last_json(e.out.getvalue())
        self.assertEqual(out['status'], 'REFUSED_NO_CHANGE')
        self.assertIn('needs --allow-bootbin-change', out['reason'])
        self.assertEqual(e.mac.targets(), [])

    def test_flag_refused_when_boot_bin_does_not_change(self):
        e = self.env()
        self.assertEqual(e.run(allow_bootbin_change=True), 3, e.diag())
        self.assertIn('leaves boot.bin unchanged', last_json(e.out.getvalue())['reason'])
        self.assertEqual(e.mac.targets(), [])

    def test_version_rule_must_reproduce_the_live_stage2(self):
        e = self.env(m1n1_candidate=True)
        e.mac.m1n1_version = 'something-else'
        self.assertEqual(e.run(allow_bootbin_change=True), 3, e.diag())
        self.assertIn('is not the live stage 2 version', last_json(e.out.getvalue())['reason'])

    def test_bootbin_change_happy_path(self):
        e = self.env(m1n1_candidate=True)
        rc = e.run(allow_bootbin_change=True)
        self.assertEqual(rc, 0, e.diag())
        recs = e.records()
        self.assertEqual([r['step'] for r in recs if r['event'] == 'intent'], self.bb_steps())
        inv = {r['step']: r['inverse'] for r in recs if r['event'] == 'intent'}
        self.assertEqual(inv['bootbin-guard-install'], 'bootbin-guard-remove')
        rd = e.rd()
        man = json.loads((rd / 'manifest.json').read_bytes())
        cfg = json.loads((rd / 'config.json').read_bytes())
        self.assertEqual(man['m1n1']['version'], '5d17a034-dirty')
        self.assertEqual(man['m1n1']['bin_sha256'], H(pkgs.M1N1_V22))
        self.assertEqual(cfg['expected_bootbin_sha256'], H(e.cand_bootbin))
        self.assertIs(cfg['allow_bootbin_change'], True)
        g = cfg['bootbin_guard']
        self.assertEqual((g['candidate_sha256'], g['original_sha256'], g['recovery_copy']),
                         (H(e.cand_bootbin), H(e.bootbin), 'm1n1/boot.bin.old'))
        self.assertEqual((g['candidate_stage2_version'], g['original_stage2_version'], g['candidate_krel']),
                         ('5d17a034-dirty', 'f5a82fdb-dirty', pkgs.KREL7))
        card = (rd / 'RECOVERY.txt').read_text()
        self.assertIn('159ecdaa-1ad2-4307-a721-44d69c3cb159', card)
        self.assertIn('cp boot.bin.old boot.bin', card)
        self.assertIn(H(e.bootbin), card)
        chk = [r for r in recs if r.get('step') == 'bootbin-guard-check' and r['event'] == 'done'][0]['summary']
        self.assertEqual(chk['candidate_stage2_boots'], 1)
        self.assertEqual(chk['return_boot_stage2'], 'f5a82fdb-dirty')
        fin = [r for r in recs if r.get('step') == 'stage2-final' and r['event'] == 'done'][0]['summary']
        self.assertEqual(fin, {'stage2_version': 'f5a82fdb-dirty', 'bootbin_sha256': H(e.bootbin)})
        self.assertEqual(controller.last_end(recs)['status'], 'PASSED_RESTORED_LEASE_RELEASED')
        self.assertEqual(e.mac.bootbin, e.bootbin)
        self.assertEqual(e.mac.guard, 'removed')

    def test_late_restore_is_never_a_clean_pass(self):
        e = self.env(m1n1_candidate=True)
        e.mac.guard_mode = 'late'          # the candidate boot's stop hook never ran: the next boot ran it again
        self.assertEqual(e.run(allow_bootbin_change=True), 1, e.diag())
        recs = e.records()
        chk = [r for r in recs if r.get('step') == 'bootbin-guard-check' and r['event'] == 'done'][0]['summary']
        self.assertEqual((chk['candidate_stage2_boots'], chk['return_boot_stage2']), (2, '5d17a034-dirty'))
        self.assertEqual(controller.last_end(recs)['status'], 'GUARD_LATE_RESTORE_RESTORED_LEASE_RELEASED')
        self.assertIsNone(e.lab.devices['m1']['lease'])

    def test_no_restore_stops_and_restore_puts_the_original_back_first(self):
        e = self.env(m1n1_candidate=True)
        e.mac.guard_mode = 'none'
        self.assertEqual(e.run(allow_bootbin_change=True), 4, e.diag())
        out = last_json(e.out.getvalue())
        self.assertEqual(out['status'], 'STOPPED_RESTORE_REQUIRED')
        self.assertIn('not the original', out['reason'])
        self.assertEqual(out['restore_plan']['todo'][:2], ['bootbin-guard-remove', 'rollback'])
        self.assertEqual(e.mac.bootbin, e.cand_bootbin)
        n = len(e.mac.calls)
        self.assertEqual(e.ctl().restore(e.rid), 0, e.diag())
        seq = [x[1] if x[0] == 'target' else x[0] for x in e.mac.calls[n:] if x[0] in ('target', 'reboot')]
        self.assertEqual(seq, ['bootbin-guard-remove', 'rollback', 'esp-restore', 'etc-restore', 'reboot',
                               'audit --held', 'release-writers', 'audit', 'cleanup'])
        recs = e.records()
        fin = [r for r in recs if r.get('step') == 'restore-stage2-final' and r['event'] == 'done'][0]['summary']
        self.assertEqual(fin, {'stage2_version': 'f5a82fdb-dirty', 'bootbin_sha256': H(e.bootbin)})
        self.assertEqual(controller.last_end(recs)['status'], 'restored')
        self.assertIsNone(e.lab.devices['m1']['lease'])

    def test_restore_rehydrates_the_flag_and_checks_stage2_before_audit(self):
        e = self.env(m1n1_candidate=True)
        e.lab.fail['entry'] = labd_mod.APIError(409, 'entry boom', '/api/installed/x/entry/m1')
        self.assertEqual(e.run(allow_bootbin_change=True), 4, e.diag())     # stopped after install + guard install
        self.assertEqual(e.mac.bootbin, e.cand_bootbin)
        c = e.ctl()
        self.assertEqual(c.status(e.rid), 0)
        self.assertEqual(last_json(e.out.getvalue())['restore_plan']['todo'],
                         ['bootbin-guard-remove', 'rollback', 'esp-restore', 'etc-restore', 'release-writers'])
        c = e.ctl()
        self.assertEqual(c.restore(e.rid), 0, e.diag())
        self.assertTrue(c.allow_bootbin)
        recs = e.records()
        order = [r['step'] for r in recs if r['event'] == 'intent']
        self.assertLess(order.index('restore-stage2-final'), order.index('audit-held'))
        self.assertEqual(e.mac.bootbin, e.bootbin)
        self.assertEqual(e.mac.m1n1_version, 'f5a82fdb-dirty')

    def test_restore_plan_order_with_the_guard(self):
        recs = [{'seq': 1, 'step': 'install', 'event': 'intent', 'inverse': 'rollback',
                 'inverse_followups': ['esp-restore', 'etc-restore']},
                {'seq': 2, 'step': 'install', 'event': 'done'},
                {'seq': 3, 'step': 'bootbin-guard-install', 'event': 'intent', 'inverse': 'bootbin-guard-remove'},
                {'seq': 4, 'step': 'bootbin-guard-install', 'event': 'done'},
                {'seq': 5, 'step': 'bootbin-guard-remove', 'event': 'intent'},
                {'seq': 6, 'step': 'bootbin-guard-remove', 'event': 'done'}]
        p = controller.restore_plan(recs)
        self.assertEqual(p['todo'], ['rollback', 'esp-restore', 'etc-restore'])
        self.assertTrue(p['reboot_pending'], 'a guard removal that restored boot.bin needs a reboot to prove stage 2')

    def test_stage2_version_marker(self):
        self.assertEqual(controller.stage2_version(pkgs.M1N1_V22), '5d17a034-dirty')
        self.assertEqual(controller.stage2_version(pkgs.M1N1_V20 + pkgs.M1N1_V20), 'f5a82fdb-dirty')
        for bad in (b'no marker', pkgs.M1N1_V20 + pkgs.M1N1_V22, b'##m1n1_ver##' + b'x' * 100,
                    b'##m1n1_ver##bad version\0'):
            with self.assertRaises(controller.Refused):
                controller.stage2_version(bad)

    def test_failure_after_install_then_restore_order(self):
        e = self.env()
        e.lab.fail['entry'] = labd_mod.APIError(409, 'entry boom', '/api/installed/x/entry/m1')
        self.assertEqual(e.run(), 4, e.diag())
        self.assertEqual(last_json(e.out.getvalue())['status'], 'STOPPED_RESTORE_REQUIRED')
        self.assertEqual(e.lab.devices['m1']['lease']['holder'], HOLDER)      # kept for restore
        self.assertEqual(e.mac.targets(), ['fetch', 'preflight', 'capture', 'hold-writers', 'esp-prep', 'install'])
        c = e.ctl()
        self.assertEqual(c.status(e.rid), 0)
        st = last_json(e.out.getvalue())
        self.assertEqual(st['restore_plan']['todo'], ['rollback', 'esp-restore', 'etc-restore', 'release-writers'])
        self.assertTrue(st['open'])
        n = len(e.mac.calls)
        self.assertEqual(e.ctl().restore(e.rid), 0, e.diag())
        seq = [x[1] if x[0] == 'target' else x[0] for x in e.mac.calls[n:] if x[0] in ('target', 'reboot')]
        self.assertEqual(seq, ['rollback', 'esp-restore', 'etc-restore', 'reboot', 'audit --held', 'release-writers',
                               'audit', 'cleanup'])
        snippets = [x[1] for x in e.mac.calls[n:] if x[0] == 'snippet']
        self.assertEqual(snippets[0], 'locks')                                  # locks before rollback
        self.assertIsNone(e.lab.devices['m1']['lease'])
        self.assertEqual(controller.last_end(e.records())['status'], 'restored')
        # idempotent: nothing left to do, no device calls
        n = len(e.mac.calls)
        self.assertEqual(e.ctl().restore(e.rid), 0)
        self.assertEqual(last_json(e.out.getvalue())['status'], 'NOTHING_TO_RESTORE')
        self.assertEqual(e.mac.calls[n:], [])

    def test_restore_refresh_target_repushes_before_inverses(self):
        e = self.env()
        e.lab.fail['entry'] = labd_mod.APIError(409, 'entry boom', '/api/installed/x/entry/m1')
        self.assertEqual(e.run(), 4, e.diag())
        n = len(e.mac.calls)
        self.assertEqual(e.ctl().restore(e.rid, refresh_target=True), 0, e.diag())
        calls = e.mac.calls[n:]
        first_target = next(i for i, x in enumerate(calls) if x[0] == 'target')
        swap = calls.index(('snippet', 'tdir-swap'))
        self.assertLess(calls.index(('snippet', 'tdir-new')), swap)
        self.assertLess(swap, first_target)                                     # new code runs every inverse
        self.assertTrue(all('/t.r1/' in x[1] for x in calls[:swap] if x[0] == 'push'))
        done = [r for r in e.records() if r.get('step') == 'restore-refresh-target' and r.get('event') == 'done']
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]['summary']['k'], 1)
        self.assertEqual(done[0]['summary']['changed_files'], [])                # same source here
        self.assertTrue(any('/t.prev-1/' in p for p in e.mac.files))   # old package kept
        self.assertEqual(controller.last_end(e.records())['status'], 'restored')

    def test_restore_after_job_returns_on_candidate_reboots_first(self):
        e = self.env()
        e.lab.job_outcome = 'tests_failed'
        orig = e.lab._run_job

        def stuck(jid):                     # job ends but the Mac stays on the tagged candidate boot
            j = orig(jid)
            if not e.lab.release_of(j['spec']['installed_manifest']).endswith('-base'):
                e.lab.new_boot('m1', pkgs.KREL7, 'root=UUID=x rw quiet maclab.job=%s panic=10' % jid)
            return j
        e.lab._run_job = stuck
        self.assertEqual(e.run(), 4, e.diag())
        self.assertEqual([r['step'] for r in e.records() if r['event'] == 'failed'], ['verify-return'])
        n = len(e.mac.calls)
        self.assertEqual(e.ctl().restore(e.rid), 0, e.diag())
        seq = [x[1] if x[0] == 'target' else x[0] for x in e.mac.calls[n:] if x[0] in ('target', 'reboot')]
        self.assertEqual(seq, ['reboot', 'rollback', 'esp-restore', 'etc-restore', 'reboot', 'audit --held',
                               'release-writers', 'audit', 'cleanup'])

    def test_restore_blocked_inverse_requires_explicit_retry(self):
        e = self.env()
        e.lab.fail['entry'] = labd_mod.APIError(409, 'entry boom', '/x')
        self.assertEqual(e.run(), 4)
        e.mac.fail['rollback'] = (4, {'error': 'pacman exited 1'})
        self.assertEqual(e.ctl().restore(e.rid), 4)
        n = len(e.mac.calls)
        self.assertEqual(e.ctl().restore(e.rid), 4)                           # refused: no silent re-run
        self.assertIn('--retry rollback', last_json(e.out.getvalue())['reason'])
        self.assertEqual([x for x in e.mac.calls[n:] if x[0] in ('target', 'reboot')], [])
        self.assertEqual(e.ctl().restore(e.rid, retry=['rollback']), 0, e.diag())
        self.assertEqual(e.mac.targets()[-7:], ['rollback', 'esp-restore', 'etc-restore', 'audit --held',
                                                'release-writers', 'audit', 'cleanup'])

    # -- fresh baseline ------------------------------------------------------------------------------------
    def test_fresh_baseline_preinstall_comes_from_the_base_job(self):
        e = self.env()
        self.assertEqual(e.run(), 0, e.diag())
        recs = e.records()
        seq = {r['step']: r['seq'] for r in recs if r['event'] == 'intent'}
        self.assertLess(seq['base-manifest'], seq['push'])                      # proven before any change
        self.assertLess(seq['hold-writers'], seq['base-submit'])                # same conditions as the candidate
        self.assertLess(seq['base-locks'], seq['esp-prep'])                     # nothing installed yet
        base_rel, rel = 'bt2-m1-test1-base', 'bt2-m1-test1'
        base_man = json.loads((e.rd() / 'base/manifest.json').read_bytes())
        self.assertEqual(base_man['release'], base_rel)
        self.assertEqual(sorted('%s %s' % (a['name'], a['version']) for a in base_man['artifacts']),
                         ['linux-aurora 7.2.11.aurora6-1', 'm1n1-aurora 1.6.1.aurora20-4',
                          'mesa-aurora 1:26.3.0_devel.147a-1', 'omarchy-mac-boot 20261010-1',
                          'uboot-asahi 2026.07.asahi2-4', 'vulkan-aurora 1:26.3.0_devel.147a-1'])
        self.assertEqual(base_man['kernel']['release'], pkgs.KREL6)
        self.assertEqual(base_man['macs']['m1']['boot_bin_sha256'], H(e.bootbin))
        self.assertEqual(e.lab.frozen[base_rel]['manifest_sha256'], H((e.rd() / 'base/manifest.json').read_bytes()))
        base_job, cand_job = list(e.lab.jobs.values())
        self.assertEqual(base_job['spec']['installed_manifest'], e.lab.frozen[base_rel]['manifest_sha256'])
        self.assertEqual([t['name'] for t in base_job['spec']['tests']], ['boot-health', 'gui-smoke', 'omarchy-m-test'])
        self.assertEqual((base_job['spec']['recovery_transaction'], base_job['spec']['holder']), (e.rid, HOLDER))
        self.assertEqual(cand_job['spec']['installed_manifest'], e.lab.frozen[rel]['manifest_sha256'])
        # the candidate's frozen preinstall IS the base job's output, byte for byte
        pre = e.frozen / rel / 'preinstall' / 'm1'
        files = e.lab.job_files[base_job['id']]
        self.assertEqual((pre / 'omt-report.json').read_bytes(), files['test-omarchy-m-test/omt-report.json'])
        self.assertEqual((pre / 'dmesg-errors.txt').read_bytes(), files['installed/dmesg-errors.txt'])
        self.assertEqual((pre / 'baseline-job.json').read_bytes(), files['installed/job.json'])
        self.assertEqual((pre / 'omt-status.json').read_bytes(), installed.status_json(
            {c['id']: c['status'] for c in e.lab.base_checks}))
        pins = (e.frozen / rel / 'PINS.preinstall').read_text().splitlines()
        self.assertTrue(pins[0].startswith('# PINS.preinstall %s by bt2: fresh baseline from base job %s'
                                           % (rel, base_job['id'])))
        self.assertEqual(pins[1:], ['%s  preinstall/m1/%s' % (H((pre / n).read_bytes()), n) for n in sorted(
            installed.PRE_FILES)])
        prov = json.loads((e.frozen / rel / 'PREINSTALL-FRESH.json').read_bytes())
        self.assertEqual((prov['base_job'], prov['base_release'], prov['promoted'], prov['baseline_job_source']),
                         (base_job['id'], base_rel, False, 'installed/job.json'))
        self.assertFalse((e.frozen / rel / 'PREINSTALL-REUSE.json').exists())
        # the base release itself got the stale byte copy (labd needs one; its verdict is ignored)
        self.assertTrue((e.frozen / base_rel / 'PREINSTALL-REUSE.json').is_file())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual((res['baseline'], res['base_job']['id'], res['base_job']['outcome']),
                         ('fresh', base_job['id'], 'pass'))
        self.assertEqual(e.mac.targets(), HAPPY_TARGETS)                       # no extra target commands

    def test_extra_test_runs_last_in_both_jobs_with_per_arm_pins(self):
        e = self.env()
        runner = e.tmp / 'runner.py'
        runner.write_bytes(b'print("fake runner")\n')
        assets = e.tmp / 'assets.json'
        assets.write_text(json.dumps({'vk_work': {'path': '/var/lib/sf-eryk-bench/vk-work', 'sha256': 'a' * 64}}))
        # no benchmark files from the fake job: restored, but reported incomplete (rc 1), never a plain pass
        self.assertEqual(e.run(extra_test=str(runner), extra_assets=str(assets)), 1, e.diag())
        self.assertEqual(json.loads((e.rd() / 'RESULT.json').read_bytes())['status'],
                         'PASSED_EXTRA_INCOMPLETE_RESTORED_LEASE_RELEASED')
        intents = [r['step'] for r in e.records() if r['event'] == 'intent']
        for step in ('gate-extra', 'extra-stage', 'base-extra-results', 'extra-results'):
            self.assertIn(step, intents)
        self.assertLess(intents.index('m5-capture'), intents.index('extra-stage'))
        self.assertLess(intents.index('extra-stage'), intents.index('base-submit'))
        base_job, cand_job = list(e.lab.jobs.values())
        script_sha = H((e.rd() / 'extra/script.sh').read_bytes())
        for job in (base_job, cand_job):
            self.assertEqual(job['spec']['tests'][-1], {'name': 'eryk-bench', 'script': script_sha,
                                                        'timeout_sec': 2400})

        # lab-agent dispatch contract (maclab internal/agent/tests.go runTest): gui -> runuser -u <gui_user> -- env
        # ... bash script; otherwise bash script as the agent (root). Both failed M1 baselines of 2026-10-26 ran the
        # runner as the desktop user (gui True) and it stopped at its root guard.
        def agent_runs_as(t):
            return 'chrisk' if t.get('gui') else 'root'

        for job in (base_job, cand_job):
            users = {t['name']: agent_runs_as(t) for t in job['spec']['tests']}
            self.assertEqual(users['eryk-bench'], 'root')
            self.assertEqual((users['gui-smoke'], users['omarchy-m-test']), ('chrisk', 'chrisk'))
            self.assertNotIn('gui', job['spec']['tests'][-1])
        self.assertEqual([t['name'] for t in base_job['spec']['tests']],
                         ['boot-health', 'gui-smoke', 'omarchy-m-test', 'eryk-bench'])
        self.assertEqual([t['name'] for t in cand_job['spec']['tests']][-2:], ['native-gl-vk', 'eryk-bench'])
        base_in = json.loads((e.rd() / 'extra/input-baseline.json').read_bytes())
        cand_in = json.loads((e.rd() / 'extra/input-candidate.json').read_bytes())
        self.assertEqual((base_in['arm'], base_in['expected_kernel']), ('baseline', pkgs.KREL6))
        self.assertEqual((cand_in['arm'], cand_in['expected_kernel']), ('candidate', pkgs.KREL7))
        self.assertEqual(set(base_in['providers']), set(cand_in['providers']))
        self.assertNotEqual(base_in['providers'], cand_in['providers'])     # originals vs candidate Mesa
        self.assertEqual(base_in['assets'], json.loads(assets.read_text()))
        self.assertEqual((base_in['device'], base_in['board']), ('m1', e.prof['board']))
        script = (e.rd() / 'extra/script.sh').read_text()
        self.assertIn('ERYK_BENCH_EXPECT=', script)
        self.assertIn(H((e.rd() / 'extra/input-baseline.json').read_bytes()), script)
        self.assertIn(H((e.rd() / 'extra/input-candidate.json').read_bytes()), script)
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['extra']['script_sha256'], script_sha)
        self.assertEqual(set(res['extra']['inputs']), {'baseline', 'candidate'})
        hdr = json.loads((e.rd() / 'journal.jsonl').read_text().splitlines()[0])
        self.assertEqual(hdr['extra_test_sha256'], H(runner.read_bytes()))
        # a stale baseline has no base job, so the extra test is refused before anything starts
        with self.assertRaises(controller.UsageError):
            e.run(run_id='bt2-m1-test2', baseline='stale', extra_test=str(runner), extra_assets=str(assets))

    def _extra_env(self, base_ok=True, cand_ok=True, bad_binding=False, cand_test_ok=None):
        e = self.env()
        runner = e.tmp / 'runner.py'
        runner.write_bytes(b'print("fake runner")\n')
        assets = e.tmp / 'assets.json'
        assets.write_text(json.dumps({'vk_work': {'path': '/var/lib/sf-eryk-bench/vk-work', 'sha256': 'a' * 64}}))

        def behavior(jid, is_base, krel):
            arm = 'baseline' if is_base else 'candidate'
            raw = (e.rd() / ('extra/input-%s.json' % arm)).read_bytes()
            ok = base_ok if is_base else cand_ok
            gate = {'job': jid, 'arm': arm, 'release': krel, 'input_sha256': '0' * 64 if bad_binding else H(raw)}
            summary = {'arm': arm, 'status': 'complete' if ok else 'stopped'}
            test_ok = ok if is_base or cand_test_ok is None else cand_test_ok
            return test_ok, {'test-eryk-bench/eryk-bench/gate.json': json.dumps(gate).encode(),
                        'test-eryk-bench/eryk-bench/summary.json': json.dumps(summary).encode()}
        e.lab.extra_behavior = behavior
        return e, runner, assets

    def test_extra_complete_both_arms_passes(self):
        e, runner, assets = self._extra_env()
        self.assertEqual(e.run(extra_test=str(runner), extra_assets=str(assets)), 0, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['status'], 'PASSED_RESTORED_LEASE_RELEASED')
        for arm in ('baseline', 'candidate'):
            self.assertIs(res['extra']['outcome'][arm]['test_passed'], True)
            self.assertEqual(res['extra']['outcome'][arm]['status'], 'complete')
            self.assertIs(res['extra']['outcome'][arm]['binding_ok'], True)

    def test_extra_failed_baseline_is_never_a_silent_pass(self):
        e, runner, assets = self._extra_env(base_ok=False)
        self.assertEqual(e.run(extra_test=str(runner), extra_assets=str(assets)), 1, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['status'], 'PASSED_EXTRA_INCOMPLETE_RESTORED_LEASE_RELEASED')
        self.assertEqual(res['extra']['outcome']['baseline']['status'], 'stopped')

    def test_extra_failed_candidate_is_labelled_not_a_bt2_failure(self):
        e, runner, assets = self._extra_env(cand_ok=False)
        self.assertEqual(e.run(extra_test=str(runner), extra_assets=str(assets)), 1, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['status'], 'PASSED_EXTRA_INCOMPLETE_RESTORED_LEASE_RELEASED')

    def test_extra_script_failure_after_complete_summary_is_not_laundered(self):
        # Codex9 r3 control: the candidate's script fails (labd test failed) after writing a complete, bound summary
        e, runner, assets = self._extra_env(cand_test_ok=False)
        self.assertEqual(e.run(extra_test=str(runner), extra_assets=str(assets)), 1, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['status'], 'PASSED_EXTRA_INCOMPLETE_RESTORED_LEASE_RELEASED')
        self.assertIs(res['extra']['outcome']['candidate']['test_passed'], False)
        self.assertEqual(res['extra']['outcome']['candidate']['status'], 'complete')

    def test_extra_wrong_input_binding_is_incomplete(self):
        e, runner, assets = self._extra_env(bad_binding=True)
        self.assertEqual(e.run(extra_test=str(runner), extra_assets=str(assets)), 1, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertIs(res['extra']['outcome']['baseline']['binding_ok'], False)

    # -- campaign CTS test (candidate job only, its own TestSpec and result) ------------------------------------------
    def _cts_env(self, cts_ok=True, failures=0, status='complete', bad_binding=False, **bench):
        e, runner, assets = self._extra_env(**bench)
        cts_runner = e.tmp / 'eryk_cts.py'
        cts_runner.write_bytes(b'print("fake cts")\n')
        archive = e.tmp / 'cts.pkg.tar.zst'
        archive.write_bytes(b'FAKE-CTS-ARCHIVE' * 64)
        lists = []
        for name, n, dl in (('uaddcarry-geometry', 2, 180), ('conditional-rendering-draw', 3, 600)):
            p = e.tmp / (name + '.txt')
            p.write_text(''.join('dEQP-VK.fake.%s.case_%d\n' % (name.replace('-', '_'), i) for i in range(n)))
            lists.append({'name': name, 'path': str(p), 'sha256': H(p.read_bytes()), 'cases': n, 'deadline_s': dl})
        doc = {'archive': {'path': str(archive), 'sha256': H(archive.read_bytes())}, 'deqp_vk_sha256': 'd' * 64,
               'data_manifest_sha256': 'e' * 64, 'lists': lists}
        cts_assets = e.tmp / 'cts-assets.json'
        cts_assets.write_text(json.dumps(doc))

        def behavior(jid, is_base, krel):
            self.assertFalse(is_base, 'eryk-cts must never be in the baseline job')
            raw = (e.rd() / 'cts/input-candidate.json').read_bytes()
            gate = {'job': jid, 'arm': 'candidate', 'release': krel,
                    'input_sha256': '0' * 64 if bad_binding else H(raw)}
            summary = {'arm': 'candidate', 'status': status, 'failures': failures, 'counts': {}}
            return cts_ok, {'test-eryk-cts/eryk-cts/gate.json': json.dumps(gate).encode(),
                            'test-eryk-cts/eryk-cts/summary.json': json.dumps(summary).encode()}
        e.lab.cts_behavior = behavior
        return e, doc, dict(extra_test=str(runner), extra_assets=str(assets), cts_test=str(cts_runner),
                            cts_assets=str(cts_assets))

    def test_cts_runs_only_in_the_candidate_job_after_the_benchmark(self):
        e, doc, kw = self._cts_env()
        self.assertEqual(e.run(**kw), 0, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['status'], 'PASSED_RESTORED_LEASE_RELEASED')
        self.assertEqual(res['cts']['status'], 'CTS_NO_FAILURES')
        base_job, cand_job = list(e.lab.jobs.values())
        self.assertNotIn('eryk-cts', [t['name'] for t in base_job['spec']['tests']])
        self.assertEqual([t['name'] for t in cand_job['spec']['tests']][-2:], ['eryk-bench', 'eryk-cts'])
        self.assertEqual(cand_job['spec']['tests'][-1], {'name': 'eryk-cts', 'timeout_sec': 1500,
                                                         'script': H((e.rd() / 'cts/script.sh').read_bytes())})
        intents = [r['step'] for r in e.records() if r['event'] == 'intent']
        self.assertLess(intents.index('extra-stage'), intents.index('cts-stage'))
        self.assertLess(intents.index('cts-stage'), intents.index('base-submit'))
        self.assertLess(intents.index('extra-results'), intents.index('cts-results'))
        rrun = '/var/lib/maclab/bt2/' + e.rid + '/cts/'
        staged = {p[len(rrun):]: d for p, d in e.mac.files.items() if p.startswith(rrun)}
        self.assertEqual(staged['cts.pkg.tar.zst'], Path(doc['archive']['path']).read_bytes())
        for item in doc['lists']:
            self.assertEqual(staged[item['name'] + '.txt'], Path(item['path']).read_bytes())
        inp = json.loads((e.rd() / 'cts/input-candidate.json').read_bytes())
        self.assertEqual(staged['cts-input-%s.json' % inp['expected_kernel']], (e.rd() / 'cts/input-candidate.json').read_bytes())
        self.assertEqual((inp['arm'], inp['expected_kernel']), ('candidate', pkgs.KREL7))
        self.assertEqual([(l['name'], l['cases'], l['deadline_s']) for l in inp['lists']],
                         [('uaddcarry-geometry', 2, 180), ('conditional-rendering-draw', 3, 600)])
        self.assertEqual(inp['providers'], json.loads((e.rd() / 'extra/input-candidate.json').read_bytes())['providers'])
        cand_bench = (e.rd() / 'extra/input-candidate.json').read_bytes()
        self.assertEqual(inp['bench'], {'input_sha256': H(cand_bench), 'executables': ['/var/lib/sf-eryk-bench/vk-work']})
        self.assertIs(json.loads(cand_bench)['settle_receipt'], True)              # the runner writes its receipt
        self.assertNotIn('settle_receipt', json.loads((e.rd() / 'extra/input-baseline.json').read_bytes()))

    def test_without_cts_the_benchmark_inputs_are_unchanged(self):
        e, runner, assets = self._extra_env()
        self.assertEqual(e.run(extra_test=str(runner), extra_assets=str(assets)), 0, e.diag())
        for arm in ('baseline', 'candidate'):
            self.assertNotIn('settle_receipt', json.loads((e.rd() / ('extra/input-%s.json' % arm)).read_bytes()))

    def test_cts_functional_failure_is_never_an_overall_pass(self):
        e, _, kw = self._cts_env(cts_ok=False, failures=2)
        self.assertEqual(e.run(**kw), 1, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['status'], 'CTS_FAILED_RESTORED_LEASE_RELEASED')
        self.assertEqual(res['cts']['status'], 'CTS_FAILED')
        for arm in ('baseline', 'candidate'):                     # the benchmark's own bound outcome is untouched
            o = res['extra']['outcome'][arm]
            self.assertEqual((o['test_passed'], o['status'], o['binding_ok']), (True, 'complete', True))

    def test_cts_stopped_unbound_or_inconsistent_is_not_a_pass(self):
        for kwargs, want in (({'cts_ok': False, 'status': 'stopped'}, 'CTS_STOPPED'),
                             ({'bad_binding': True}, 'CTS_INCOMPLETE'),
                             ({'cts_ok': True, 'failures': 1}, 'CTS_INCOMPLETE'),
                             ({'cts_ok': False, 'failures': 0, 'status': 'complete'}, 'CTS_INCOMPLETE')):
            with self.subTest(want=want, **kwargs):
                e, _, kw = self._cts_env(**kwargs)
                self.assertEqual(e.run(**kw), 1, e.diag())
                res = json.loads((e.rd() / 'RESULT.json').read_bytes())
                self.assertEqual((res['status'], res['cts']['status']), (want + '_RESTORED_LEASE_RELEASED', want))
                e.close()

    def test_cts_pass_cannot_launder_an_incomplete_benchmark(self):
        e, _, kw = self._cts_env(cand_ok=False)
        self.assertEqual(e.run(**kw), 1, e.diag())
        res = json.loads((e.rd() / 'RESULT.json').read_bytes())
        self.assertEqual(res['status'], 'PASSED_EXTRA_INCOMPLETE_RESTORED_LEASE_RELEASED')
        self.assertEqual(res['cts']['status'], 'CTS_NO_FAILURES')

    def test_cts_inputs_are_checked_before_anything_runs(self):
        e, doc, kw = self._cts_env()
        bad = {'no benchmark': dict(kw, extra_test=None, extra_assets=None)}
        for name, mutate in (('archive hash', lambda d: d['archive'].update(sha256='0' * 64)),
                             ('case count', lambda d: d['lists'][0].update(cases=3)),
                             ('deadline budget', lambda d: d['lists'][1].update(deadline_s=900)
                              or d['lists'][0].update(deadline_s=900)),
                             ('bad case name', lambda d: Path(d['lists'][0]['path']).write_text('rm -rf /\n')
                              or d['lists'][0].update(sha256=H(b'rm -rf /\n'), cases=1)),
                             ('extra key', lambda d: d.update(waivers='x'))):
            d = json.loads(json.dumps(doc))
            mutate(d)
            p = e.tmp / ('cts-assets-%s.json' % name.replace(' ', '-'))
            p.write_text(json.dumps(d))
            bad[name] = dict(kw, cts_assets=str(p))
        for name, args in bad.items():
            with self.subTest(name):
                with self.assertRaises(controller.UsageError):
                    e.run(run_id='bt2-m1-u%d' % (len(name) % 10), **args)
        self.assertEqual(e.lab.jobs, {})

    def test_cts_verdict_table(self):
        v = controller.cts_verdict
        ok = {'binding_ok': True, 'failures': 0, 'status': 'complete', 'test_passed': True}
        self.assertEqual(v(ok), 'CTS_NO_FAILURES')
        self.assertEqual(v(dict(ok, failures=3, test_passed=False)), 'CTS_FAILED')
        self.assertEqual(v(dict(ok, failures=1, status='stopped', test_passed=False)), 'CTS_FAILED')
        self.assertEqual(v(dict(ok, status='stopped', test_passed=False)), 'CTS_STOPPED')
        for broken in (None, {}, dict(ok, binding_ok=False), dict(ok, failures='0'), dict(ok, status='odd'),
                       dict(ok, test_passed=False), dict(ok, failures=1)):
            self.assertEqual(v(broken), 'CTS_INCOMPLETE', broken)

    def test_cts_wrapper_checks_both_files_then_execs(self):
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as d:
            d = Path(d)
            lib = b'# helper library\n'
            runner = (b'import os,sys,pathlib\np=pathlib.Path(sys.argv[1])\n'
                      b'p.joinpath("ran").write_text(os.environ["ERYK_CTS_EXPECT"]+"|"+os.environ["ERYK_CTS_LIB_SHA256"])\n')
            script = controller.cts_script(lib, runner, str(d), {'7.2.11-7-238.1-ARCH': 'b' * 64})
            (d / 'w.sh').write_bytes(script)
            out = d / 'out'
            out.mkdir()
            r = subprocess.run(['bash', str(d / 'w.sh')], env={'PATH': '/usr/bin:/bin', 'MACLAB_OUT': str(out)},
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((d / 'ran').read_text(), json.dumps({'7.2.11-7-238.1-ARCH': 'b' * 64}) + '|' + H(lib))
            self.assertEqual(((out / 'eryk_bench.py').read_bytes(), (out / 'eryk_cts.py').read_bytes()), (lib, runner))
            for victim in (H(lib), H(runner)):
                (d / 'ran').unlink(missing_ok=True)
                for f in ('eryk_bench.py', 'eryk_cts.py'):
                    (out / f).unlink(missing_ok=True)
                (d / 't.sh').write_bytes(script.replace(victim.encode(), b'0' * 64))
                r = subprocess.run(['bash', str(d / 't.sh')], env={'PATH': '/usr/bin:/bin', 'MACLAB_OUT': str(out)},
                                   capture_output=True, text=True)
                self.assertNotEqual(r.returncode, 0)
                self.assertFalse((d / 'ran').exists())

    def test_fresh_baseline_boot_failure_stops_with_only_release_writers(self):
        e = self.env()
        e.lab.fail['base-boot'] = True
        self.assertEqual(e.run(), 4, e.diag())
        self.assertEqual([r['step'] for r in e.records() if r['event'] == 'failed'], ['fresh-preinstall'])
        self.assertEqual(e.mac.targets(), ['fetch', 'preflight', 'capture', 'hold-writers'])   # nothing installed
        self.assertFalse((e.frozen / 'bt2-m1-test1').exists())                   # no candidate preinstall
        self.assertEqual(len(e.lab.jobs), 1)
        out = last_json(e.out.getvalue())
        self.assertEqual(out['restore_plan']['todo'], ['release-writers'])
        self.assertTrue(out['restore_plan']['boot_risk'])
        self.assertIn('boot_failed', out['reason'])
        n = len(e.mac.calls)
        self.assertEqual(e.ctl().restore(e.rid), 0, e.diag())
        seq = [x[1] if x[0] == 'target' else x[0] for x in e.mac.calls[n:] if x[0] in ('target', 'reboot')]
        self.assertEqual(seq, ['audit --held', 'release-writers', 'audit', 'cleanup'])
        self.assertIsNone(e.lab.devices['m1']['lease'])

    def test_fresh_baseline_missing_evidence_stops_before_install(self):
        e = self.env()
        e.lab.fail['drop-files'] = ['installed/dmesg-errors.txt']
        self.assertEqual(e.run(), 4, e.diag())
        self.assertIn('installed/dmesg-errors.txt', last_json(e.out.getvalue())['reason'])
        self.assertNotIn('esp-prep', e.mac.targets())
        self.assertEqual(last_json(e.out.getvalue())['restore_plan']['todo'], ['release-writers'])

    def test_fresh_baseline_regression_vs_stale_pins_is_ignored(self):
        e = self.env()
        e.lab.base_outcome, e.lab.base_omt = 'tests_failed', 'REGRESSION'
        self.assertEqual(e.run(), 0, e.diag())
        done = [r for r in e.records() if r.get('step') == 'fresh-preinstall' and r['event'] == 'done'][0]['summary']
        self.assertEqual((done['base_outcome'], done['base_omt_vs_stale'], done['base_failed_tests']),
                         ('tests_failed', 'REGRESSION', ['omarchy-m-test']))
        prov = json.loads((e.frozen / 'bt2-m1-test1' / 'PREINSTALL-FRESH.json').read_bytes())
        self.assertEqual(prov['base_outcome'], 'tests_failed')

    def test_fresh_baseline_without_a_sealed_record_uses_the_api_job(self):
        e = self.env()
        e.lab.fail['drop-files'] = ['installed/job.json']
        self.assertEqual(e.run(), 0, e.diag())
        base_job = list(e.lab.jobs.values())[0]
        pre = e.frozen / 'bt2-m1-test1' / 'preinstall' / 'm1'
        self.assertEqual(json.loads((pre / 'baseline-job.json').read_bytes())['id'], base_job['id'])
        prov = json.loads((e.frozen / 'bt2-m1-test1' / 'PREINSTALL-FRESH.json').read_bytes())
        self.assertEqual(prov['baseline_job_source'], 'api')

    def test_fresh_baseline_refuses_before_any_change_when_an_original_differs(self):
        e = self.env()
        e.mac.mtree['mesa-aurora'] = '0' * 64                 # installed mesa is not the archive we would pin
        self.assertEqual(e.run(), 3, e.diag())
        failed = [r for r in e.records() if r['event'] == 'failed']
        self.assertEqual((failed[0]['step'], failed[0]['refused']), ('base-manifest', True))
        self.assertIn('--baseline stale', last_json(e.out.getvalue())['reason'])
        self.assertFalse([c for c in e.mac.calls if c[0] in ('push', 'target')])
        self.assertIsNone(e.lab.devices['m1']['lease'])
        # the escape hatch still works on the same Mac
        self.assertEqual(e.run(run_id='bt2-m1-test2', baseline='stale'), 0)

    def test_kernel_only_run_pins_the_installed_mesa(self):
        e = self.env()
        kernel = [p for p in e.co['candidates'] if '/linux-aurora-' in p]
        self.assertEqual(len(kernel), 1)
        self.assertEqual(e.run(artifact_paths=kernel), 0, e.diag())
        inp = json.loads((e.rd() / 'native' / 'native-input.json').read_bytes())
        vers = {r: p.get('package_version') for r, p in inp['providers'].items()}
        self.assertEqual(vers['gallium'], '1:26.3.0_devel.147a-1')                 # the Mac's own Mesa, kept
        self.assertEqual(vers['vulkan'], '1:26.3.0_devel.147a-1')
        res = [r for r in e.records() if r.get('step') == 'resolve-packages' and r['event'] == 'done'][0]['summary']
        self.assertEqual(sorted(x['name'] for x in res['staying_providers']), ['mesa-aurora', 'vulkan-aurora'])

    def test_kernel_only_run_refuses_without_the_installed_mesa_archive(self):
        e = self.env()
        for d in list(Path(e.co['store']).iterdir()):
            for f in d.iterdir():
                if f.name.startswith('mesa-aurora-'):
                    f.unlink()
        kernel = [p for p in e.co['candidates'] if '/linux-aurora-' in p]
        self.assertEqual(e.run(artifact_paths=kernel), 3)
        self.assertIn('native GL/VK test needs its archive', last_json(e.out.getvalue())['reason'])
        self.assertEqual(e.mac.calls[-1:] and [c for c in e.mac.calls if c[0] == 'target'], [])   # nothing on the Mac

    def test_stale_baseline_escape_hatch(self):
        e = self.env()
        self.assertEqual(e.run(baseline='stale'), 0, e.diag())
        self.assertEqual([r['step'] for r in e.records() if r['event'] == 'intent'], HAPPY_STEPS_STALE)
        self.assertEqual(len(e.lab.jobs), 1)
        self.assertTrue((e.frozen / 'bt2-m1-test1' / 'PREINSTALL-REUSE.json').is_file())
        self.assertFalse((e.frozen / 'bt2-m1-test1-base').exists())
        self.assertEqual(json.loads((e.rd() / 'RESULT.json').read_bytes())['baseline'], 'stale')

    def test_fresh_baseline_m3pro_absent_boot_package(self):
        e = self.env('m3pro', trailer=b'chosen.asahi,t6030-gpu=1\n')
        e.mac.packages.pop('omarchy-mac-boot')          # m3pro: the boot package is not installed at all
        self.assertEqual(e.run(baseline='fresh'), 0, e.diag())   # forced: auto picks stale on the m3pro
        done = [r for r in e.records() if r.get('step') == 'base-manifest' and r['event'] == 'done'][0]['summary']
        self.assertEqual(done['absent_originals'], ['omarchy-mac-boot'])
        self.assertNotIn('omarchy-mac-boot', ' '.join(done['artifacts']))
        self.assertEqual(done['krel'], pkgs.KREL6)
        self.assertFalse(done['kernel_is_known_good'])             # the packaged original, not the custom default
        cfg = json.loads((e.rd() / 'config.json').read_bytes())
        self.assertIn({'name': 'omarchy-mac-boot', 'version': None}, cfg['originals'])
        self.assertNotIn('omarchy-mac-boot', e.mac.packages)       # rolled back to absent

    def test_gate_foreign_lease_refuses_before_mutation(self):
        e = self.env()
        exp = fakes.iso(fakes.now() + datetime.timedelta(hours=1))
        e.lab.devices['m1']['lease'] = {'holder': 'someone-else', 'expires': exp}
        self.assertEqual(e.run(), 3)
        self.assertEqual(e.mac.calls, [])
        self.assertFalse([c for c in e.lab.calls if c[0] in ('POST', 'DELETE') and 'lease' in c[1]])
        self.assertEqual(e.lab.devices['m1']['lease']['holder'], 'someone-else')
        failed = [r for r in e.records() if r['event'] == 'failed']
        self.assertEqual((failed[0]['step'], failed[0]['refused']), ('gate-device', True))
        end = controller.last_end(e.records())
        self.assertEqual((end['status'], end['mutated'], end['lease_released']), ('refused', False, False))
        self.assertIn('foreign lease', last_json(e.out.getvalue())['reason'])

    def test_gate_wrong_kernel_refuses_before_lease(self):
        e = self.env()
        e.lab.devices['m1']['kernel'] = pkgs.KREL7
        self.assertEqual(e.run(), 3)
        self.assertEqual(e.mac.calls, [])
        self.assertFalse([c for c in e.lab.calls if 'lease' in c[1]])
        self.assertIn('known-good', last_json(e.out.getvalue())['reason'])

    def test_serial_assisted_refused_when_oob_not_connected(self):
        e = self.env('m3pro', trailer=b'chosen.asahi,t6030-gpu=1\n')
        e.lab.give_oob('m3pro')
        e.lab.oob_state = {'controller': 'oobd m5', 'serial_connected': False, 'status': 'ok'}
        self.assertEqual(e.run(mode='serial-assisted'), 3)
        failed = [r for r in e.records() if r['event'] == 'failed']
        self.assertEqual(failed[0]['step'], 'recovery-mode')                     # live check after selection
        self.assertEqual(e.mac.calls, [])
        self.assertIn(('DELETE', '/api/devices/m3pro/lease', HOLDER), e.lab.calls)  # own lease released

    def test_serial_assisted_refused_without_oob_route(self):
        e = self.env('m3pro', trailer=b'chosen.asahi,t6030-gpu=1\n')
        self.assertEqual(e.run(mode='serial-assisted'), 3)
        failed = [r for r in e.records() if r['event'] == 'failed']
        self.assertEqual(failed[0]['step'], 'gate-oob')
        self.assertEqual(e.mac.calls, [])
        self.assertFalse([c for c in e.lab.calls if 'lease' in c[1]])

    def test_serial_assisted_not_offered_for_m1(self):
        e = self.env()
        self.assertEqual(e.run(mode='serial-assisted'), 3)
        self.assertEqual([r['step'] for r in e.records() if r['event'] == 'failed'], ['gate-profile'])

    def test_m3pro_serial_assisted_happy_path_with_trailer(self):
        e = self.env('m3pro', trailer=b'chosen.asahi,t6030-gpu=1\n')
        e.lab.give_oob('m3pro')
        self.assertEqual(e.run(mode='serial-assisted'), 0, e.diag())
        man = json.loads((e.rd() / 'manifest.json').read_bytes())
        self.assertEqual(man['macs']['m3pro']['trailer'], 'chosen.asahi,t6030-gpu=1\n')
        self.assertEqual(man['macs']['m3pro']['boot_bin_sha256'], H(e.bootbin))
        self.assertIn('gate-oob', [r['step'] for r in e.records() if r['event'] == 'intent'])
        self.assertEqual([j['spec']['recovery_mode'] for j in e.lab.jobs.values()], ['serial-assisted'])
        dec = [r for r in e.records() if r.get('step') == 'baseline-mode' and r['event'] == 'done'][0]['summary']
        self.assertEqual((dec['requested'], dec['baseline']), ('auto', 'stale'))   # custom known-good kernel
        self.assertIn('not in any original package', dec['reason'])

    def test_auto_baseline_is_fresh_when_known_good_kernel_is_packaged(self):
        e = self.env()
        self.assertEqual(e.run(), 0, e.diag())
        dec = [r for r in e.records() if r.get('step') == 'baseline-mode' and r['event'] == 'done'][0]['summary']
        self.assertEqual((dec['requested'], dec['baseline']), ('auto', 'fresh'))
        self.assertEqual(len(e.lab.jobs), 2)                                      # base job + candidate job

    def test_missing_kept_archive_refuses_and_releases_own_lease(self):
        e = self.env(kept_in_store=False)
        self.assertEqual(e.run(), 3)
        self.assertIn('kept boot-chain archive', last_json(e.out.getvalue())['reason'])
        self.assertIn(('DELETE', '/api/devices/m1/lease', HOLDER), e.lab.calls)   # we acquired it: released
        self.assertIsNone(e.lab.devices['m1']['lease'])
        self.assertFalse([c for c in e.mac.calls if c[0] in ('push', 'target')])

    def test_extra_package_resolves_kept_archive(self):
        e = self.env(kept_in_store=False)
        self.assertEqual(e.run(extra_packages=e.co['extra']), 0, e.diag())

    def test_reuse_manifest_fallback(self):
        e = self.env()
        self.assertEqual(e.run(manifest_mode='reuse'), 0, e.diag())
        man = json.loads((e.rd() / 'manifest.json').read_bytes())
        self.assertEqual((man['release'], list(man['macs'])), ('bt2-m1-test1', ['m1']))

    def test_reboot_exec_error_is_ambiguous_then_polled(self):
        e = self.env()
        e.mac.reboot_raises = True
        self.assertEqual(e.run(), 0, e.diag())
        notes = [r for r in e.records() if r['event'] == 'note' and r['step'] == 'reboot']
        self.assertIn('exec_ambiguous', notes[0])

    def test_open_run_blocks_new_run(self):
        e = self.env()
        e.lab.fail['entry'] = labd_mod.APIError(409, 'entry boom', '/x')
        self.assertEqual(e.run(), 4)
        e.lab.fail.clear()
        self.assertEqual(e.run(run_id='bt2-m1-test2'), 3)
        self.assertIn('still need `restore`', last_json(e.out.getvalue())['reason'])


@unittest.skipUnless(NATIVE_OK, 'reference native components not present')
class NativeTests(unittest.TestCase):
    RUN = '/var/lib/maclab/bt2/bt2-m1-test1'

    def setUp(self):
        self.src = native.load_sources()
        self.tmp = Path(tempfile.mkdtemp(prefix='bt2-native-', dir=SCRATCH))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cohort(self, providers=None, kernel=pkgs.KREL7):
        if providers is None:
            providers = native.providers_from([artifacts.inspect(p) for p in self.fake_mesa()])
        return native.cohort_pins(kernel, providers, self.src['checker'])

    def worker(self, run=RUN, cohort=None):
        ns = {'__name__': 'bt2_worker_under_test'}
        exec(compile(native.worker_source(run, self.src, cohort or self.cohort()), 'worker', 'exec'), ns)
        return ns

    def sample_input(self, providers=None):
        tools = native.template_tools(self.src['template'])
        man = {'release': 'bt2-m1-test1', 'kernel': {'release': pkgs.KREL7, 'vmlinuz_sha256': 'a' * 64}}
        entry = {'found': True, 'path': 'boot():/EFI/Linux/omarchy_linux-aurora.efi#' + 'c' * 128,
                 'cmdline_tokens': ['root=UUID=x', 'rw', 'quiet'], 'uki_file': '/boot/efi/EFI/Linux/omarchy_linux-aurora.efi',
                 'uki_sha256': 'e' * 64, 'entry_sha256': 'd' * 64, 'uki_sections': {'.uname': {'text': pkgs.KREL7}}}
        prof = json.loads((ROOT / 'tests/devices/m1.json').read_text())
        facts = {'wifi': WIFI, 'gui': {'user': 'chrisk', 'uid': 1000}}
        inp = native.compute_input(run_id='bt2-m1-test1', run_dir=self.RUN, profile=prof, facts=facts,
                                   inspections=[artifacts.inspect(p) for p in self.fake_mesa()], manifest=man,
                                   entry=entry, script_sha256='5' * 64, mode='network-only', tools=tools,
                                   cohort=self.cohort())
        if providers is not None:
            inp['providers'] = providers
        return inp

    def fake_mesa(self):
        d = self.tmp / 'mesa'
        if not d.exists():
            pkgs.make_pkg(d, 'mesa-aurora', '1:26.3.0_devel.7c-1', pkgs.mesa_files('7c'), pkgs.MESA_LINKS)
            pkgs.make_pkg(d, 'vulkan-aurora', '1:26.3.0_devel.7c-1', {'usr/lib/libvulkan_asahi.so': b'vk-7c'})
        return sorted(str(p) for p in d.glob('*.pkg.tar.zst'))

    def test_script_is_deterministic_and_passes_bash_n(self):
        c = self.cohort()
        a = native.build_script(self.RUN, self.src, c)
        self.assertEqual(a, native.build_script(self.RUN, native.load_sources(), self.cohort()))
        self.assertNotEqual(a, native.build_script('/var/lib/maclab/bt2/bt2-m1-test2', self.src, c))
        other = json.loads(json.dumps(c))
        other['providers']['vulkan']['sha256'] = 'b' * 64
        self.assertNotEqual(a, native.build_script(self.RUN, self.src, other))   # the cohort is part of the Script
        with self.assertRaises(native.NativeError):                             # non-canonical cohort
            native.build_script(self.RUN, self.src, {**c, 'note': 'x'})
        with self.assertRaisesRegex(native.NativeError, 'not canonical'):    # extra keys inside a provider pin
            extra = json.loads(json.dumps(c))
            extra['providers']['gallium']['package'] = 'mesa-aurora'
            native.build_script(self.RUN, self.src, extra)
        with self.assertRaises(native.NativeError):
            bad = json.loads(json.dumps(c))
            bad['providers']['gallium']['path'] = '/opt/libgallium-1.so'
            native.build_script(self.RUN, self.src, bad)
        p = self.tmp / 'test-native-gl-vk.sh'
        p.write_bytes(a)
        r = subprocess.run(['bash', '-n', str(p)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(a.startswith(b'#!/usr/bin/env bash\nset -euo pipefail\n'))
        self.assertIn("PACKET='%s'" % self.RUN, native.worker_source(self.RUN, self.src, c))
        with self.assertRaises(native.NativeError):
            native.build_script('/var/lib/maclab/rc7-m1-x', self.src, c)

    def test_native_input_providers_from_fake_mesa(self):
        inp = self.sample_input()
        files = pkgs.mesa_files('7c')
        for role, member in (('gallium', 'usr/lib/libgallium-26.3.0-devel.so'), ('egl', 'usr/lib/libEGL_mesa.so.0.0.0'),
                             ('dril', 'usr/lib/dri/libdril_dri.so'), ('glx', 'usr/lib/libGLX_mesa.so.0.0.0'),
                             ('gbm', 'usr/lib/libgbm.so.1.0.0')):
            self.assertEqual(inp['providers'][role]['path'], '/' + member)
            self.assertEqual(inp['providers'][role]['sha256'], H(files[member]))
            self.assertEqual(inp['providers'][role]['bytes'], len(files[member]))
        self.assertEqual(inp['providers']['vulkan']['sha256'], H(b'vk-7c'))
        self.assertEqual(inp['providers']['egl']['note'], native.EGL_NOTE)
        self.assertEqual(inp['tools'], native.template_tools(self.src['template']))
        self.assertEqual(inp['candidate_uki'], {'path': '/boot/efi/EFI/Linux/omarchy_linux-aurora.efi', 'sha256': 'e' * 64})
        self.assertEqual(inp['checker_sha256'], native.CHECKER_SHA)
        self.assertEqual(inp['cohort_sha256'], H(native.encode(self.cohort())))
        with self.assertRaises(native.NativeError):           # input recomputed from other archives than the cohort
            other = json.loads(json.dumps(self.cohort()))
            other['providers']['gbm']['sha256'] = 'c' * 64
            prof = json.loads((ROOT / 'tests/devices/m1.json').read_text())
            native.compute_input(run_id='bt2-m1-test1', run_dir=self.RUN, profile=prof,
                                 facts={'wifi': WIFI, 'gui': {'user': 'chrisk', 'uid': 1000}},
                                 inspections=[artifacts.inspect(p) for p in self.fake_mesa()],
                                 manifest={'release': 'r', 'kernel': {'release': pkgs.KREL7, 'vmlinuz_sha256': 'a' * 64}},
                                 entry={'found': True, 'cmdline_tokens': ['rw'], 'uki_file': '/boot/efi/x.efi'},
                                 script_sha256='5' * 64, mode='network-only',
                                 tools=native.template_tools(self.src['template']), cohort=other)
        with self.assertRaises(native.NativeError):           # no Vulkan provider anywhere
            native.providers_from([artifacts.inspect(p) for p in self.fake_mesa() if 'mesa-aurora' in p])

    def test_worker_validation_and_identity(self):
        w = self.worker()
        inp = self.sample_input()
        w['validate_input'](inp)
        with self.assertRaises(RuntimeError):
            w['validate_input']({**inp, 'run_dir': '/var/lib/maclab/bt2/other-run'})
        # the input must carry exactly the cohort compiled into this Script
        tampered = json.loads(json.dumps(inp))
        tampered['providers']['gallium']['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'cohort'):
            w['validate_input'](tampered)
        with self.assertRaisesRegex(RuntimeError, 'cohort'):
            w['validate_input']({**inp, 'expected_kernel': pkgs.KREL6})
        with self.assertRaisesRegex(RuntimeError, 'cohort'):
            w['validate_input']({**inp, 'cohort_sha256': '1' * 64})
        with self.assertRaisesRegex(RuntimeError, 'cohort'):        # same input, Script compiled for another cohort
            other = json.loads(json.dumps(self.cohort()))
            other['providers']['dril']['sha256'] = 'd' * 64
            self.worker(cohort=other)['validate_input'](inp)
        boot = '12345678-1234-4123-8123-123456789abc'
        env = {'MACLAB_JOB': 'j1026-170000-ab00', 'MACLAB_TEST': 'native-gl-vk'}
        cmd = 'root=UUID=x rw quiet maclab.job=j1026-170000-ab00 panic=10'
        self.assertEqual(w['job_identity'](env, cmd, boot, pkgs.KREL7, 'aarch64', 'apple,j293', inp), env['MACLAB_JOB'])
        with self.assertRaises(RuntimeError):
            w['job_identity'](env, cmd, boot, pkgs.KREL6, 'aarch64', 'apple,j293', inp)
        base = ['root=UUID=x', 'rw', 'quiet']
        self.assertFalse(w['installed_cmdline'](cmd.split(), base, env['MACLAB_JOB']))
        self.assertTrue(w['installed_cmdline'](cmd.split() + ['console=ttySAC0,115200', 'console=tty0', 'loglevel=7'],
                                               base, env['MACLAB_JOB']))
        with self.assertRaises(RuntimeError):
            w['installed_cmdline'](cmd.split() + ['extra'], base, env['MACLAB_JOB'])
        m = w['checker_manifest'](self.src['template'], inp, 'apple,j293', boot, 'f' * 64)
        self.assertEqual((m['expected_kernel'], m['expected_boot_id'], m['output_dir']),
                         (pkgs.KREL7, boot, '/var/tmp/sf-rc-normal-session-' + 'f' * 16))
        self.assertEqual(m['providers'], inp['providers'])

    def test_worker_cmdline_accepts_only_agent_generated_additions(self):
        check = self.worker()['installed_cmdline']
        job = 'j1028-082251-7b2c'
        base = ['root=UUID=x', 'rw', 'quiet']
        added = ['maclab.job=' + job, 'panic=10']
        consoles = ['console=ttySAC0,115200', 'console=tty0', 'loglevel=7']
        for serial in (False, True):
            prefix = base + added + (consoles if serial else [])
            for timeout in ('120', '240'):
                modern = prefix + ['watchdog.open_timeout=' + timeout, 'maclab.lab_boot=1']
                self.assertEqual(check(modern, base, job), serial)
            bad_tails = [
                ['watchdog.open_timeout=120'], ['maclab.lab_boot=1'],
                ['watchdog.open_timeout=120', 'maclab.lab_boot=0'],
                ['watchdog.open_timeout=-1', 'maclab.lab_boot=1'],
                ['watchdog.open_timeout=1.5', 'maclab.lab_boot=1'],
                ['watchdog.open_timeout=', 'maclab.lab_boot=1'],
                ['maclab.lab_boot=1', 'watchdog.open_timeout=120'],
                ['watchdog.open_timeout=120', 'maclab.lab_boot=1', 'maclab.lab_boot=1'],
                ['watchdog.open_timeout=120', 'watchdog.open_timeout=120', 'maclab.lab_boot=1'],
                ['watchdog.open_timeout=120', 'maclab.lab_boot=1', 'extra'],
            ]
            for tail in bad_tails:
                with self.subTest(serial=serial, tail=tail), self.assertRaises(RuntimeError):
                    check(prefix + tail, base, job)
        inherited = base + ['watchdog.open_timeout=77']
        actual = inherited + added + ['maclab.lab_boot=1']
        self.assertFalse(check(actual, inherited, job))
        with self.assertRaises(RuntimeError):
            check(base + ['watchdog.open_timeout=78'] + added + ['maclab.lab_boot=1'], inherited, job)
        for changed in (['root=UUID=other'] + actual[1:], actual + ['maclab.job=other']):
            with self.assertRaises(RuntimeError):
                check(changed, inherited, job)

    def test_checker_pins_and_cohort_gate(self):
        ck = self.src['checker']
        pins = native.checker_pins(ck)                  # since r3 only the reference cohort (template/tests)
        self.assertEqual(pins['kernel'], '7.2.11-7-1-ARCH')
        self.assertEqual(pins['providers']['gallium']['sha256'][:8], 'f1c4a87b')
        tools = native.template_tools(self.src['template'])
        self.assertEqual(pins['tools'], tools)
        fake = native.providers_from([artifacts.inspect(p) for p in self.fake_mesa()])
        # r3: a cohort that is not the reference 7c one now passes (r2 refused all 6 providers here)
        self.assertEqual(native.cohort_problems(pkgs.KREL7, fake, tools, ck), [])
        self.assertEqual(native.cohort_problems(pkgs.KREL6, fake, tools, ck), [])
        # still refused before any mutation: bad pins and different lab tools
        bad = json.loads(json.dumps(fake))
        bad['gallium']['path'] = '/usr/local/lib/libgallium-26.4.0-devel.so'
        self.assertIn('cohort provider path: gallium', ' '.join(native.cohort_problems(pkgs.KREL7, bad, tools, ck)))
        bad = json.loads(json.dumps(fake))
        bad['vulkan']['sha256'] = bad['egl']['sha256']
        self.assertIn('not distinct', ' '.join(native.cohort_problems(pkgs.KREL7, bad, tools, ck)))
        bad = {r: p for r, p in fake.items() if r != 'vulkan'}
        self.assertIn('cohort provider roles', ' '.join(native.cohort_problems(pkgs.KREL7, bad, tools, ck)))
        self.assertIn('not explicit', ' '.join(native.cohort_problems('7.3 bad', fake, tools, ck)))
        other_tools = json.loads(json.dumps(tools))
        other_tools['vk_pixels']['sha256'] = '0' * 64
        self.assertEqual(native.cohort_problems(pkgs.KREL7, fake, other_tools, ck), ['tool pins differ from the checker'])
        # a cohort-locked (pre-r3) checker is refused outright
        with self.assertRaises(native.NativeError):
            native.cohort_pins(pkgs.KREL7, fake, (ROOT / 'native-src/checker-r2.py').read_bytes()
                               if (ROOT / 'native-src/checker-r2.py').is_file() else b'TOOLS = {}\n')

    def test_non_7c_mesa_cohort_runs_end_to_end_through_worker_and_checker(self):
        # Mesa 26.4.0 (new gallium soname, new hashes) + another kernel release: gate, Script, input, worker, checker
        d = self.tmp / 'mesa264'
        files = {k.replace('libgallium-26.3.0-devel.so', 'libgallium-26.4.0-devel.so'): v.replace(b'7c', b'8d')
                 for k, v in pkgs.mesa_files('7c').items()}
        pkgs.make_pkg(d, 'mesa-aurora', '1:26.4.0_devel.8d-1', files, pkgs.MESA_LINKS)
        pkgs.make_pkg(d, 'vulkan-aurora', '1:26.4.0_devel.8d-1', {'usr/lib/libvulkan_asahi.so': b'vk-8d'})
        insp = [artifacts.inspect(str(p)) for p in sorted(d.glob('*.pkg.tar.zst'))]
        prov = native.providers_from(insp)
        self.assertEqual(prov['gallium']['path'], '/usr/lib/libgallium-26.4.0-devel.so')
        kernel = '7.3.1-2-1-ARCH'
        tools = native.template_tools(self.src['template'])
        self.assertEqual(native.cohort_problems(kernel, prov, tools, self.src['checker']), [])
        c = native.cohort_pins(kernel, prov, self.src['checker'])
        prof = json.loads((ROOT / 'tests/devices/m1.json').read_text())
        inp = native.compute_input(
            run_id='bt2-m1-test1', run_dir=self.RUN, profile=prof, facts={'wifi': WIFI, 'gui': {'user': 'chrisk', 'uid': 1000}},
            inspections=insp, manifest={'release': 'r', 'kernel': {'release': kernel, 'vmlinuz_sha256': 'a' * 64}},
            entry={'found': True, 'cmdline_tokens': ['rw'], 'uki_file': '/boot/efi/x.efi', 'uki_sha256': 'e' * 64,
                   'uki_sections': {'.uname': {'text': kernel}}},
            script_sha256='5' * 64, mode='network-only', tools=tools, cohort=c)
        w = self.worker(cohort=c)
        w['validate_input'](inp)
        boot = '12345678-1234-4123-8123-123456789abc'
        m = w['checker_manifest'](self.src['template'], inp, 'apple,j293', boot, 'a' * 64)
        checker = types.ModuleType('checker_r3_under_test')
        exec(compile(self.src['checker'], 'checker', 'exec'), checker.__dict__)
        self.assertIs(checker.frozen_manifest(m), m)
        self.assertEqual((checker.KERNEL, checker.GALLIUM), (kernel, '/usr/lib/libgallium-26.4.0-devel.so'))
        self.assertEqual(checker.PROVIDERS, c['providers'])
        env = {'MACLAB_JOB': 'j1026-170000-ab00', 'MACLAB_TEST': 'native-gl-vk'}
        cmd = 'rw maclab.job=j1026-170000-ab00 panic=10'
        self.assertEqual(w['job_identity'](env, cmd, boot, kernel, 'aarch64', 'apple,j293', inp), env['MACLAB_JOB'])
        with self.assertRaises(RuntimeError):                       # booted kernel is not the cohort's
            w['job_identity'](env, cmd, boot, pkgs.KREL7, 'aarch64', 'apple,j293', inp)

    @unittest.skipUnless(REAL_MESA.is_file() and REAL_VK.is_file(), 'real 7c archives not in the durable store')
    def test_real_7c_cohort_satisfies_unchanged_checker(self):
        insp = [artifacts.inspect(REAL_MESA), artifacts.inspect(REAL_VK)]
        providers = native.providers_from(insp)
        pins = native.checker_pins(self.src['checker'])
        self.assertEqual(native.cohort_problems(pkgs.KREL7, providers, pins['tools'], self.src['checker']), [])
        c = native.cohort_pins(pkgs.KREL7, providers, self.src['checker'])
        self.assertEqual(c['providers'], pins['providers'])   # the real 7c archives give exactly the reference pins
        inp = self.sample_input(providers=providers)
        m = self.worker()['checker_manifest'](self.src['template'], inp, 'apple,j293',
                                              '12345678-1234-4123-8123-123456789abc', 'a' * 64)
        checker = types.ModuleType('checker_under_test')
        exec(compile(self.src['checker'], 'checker', 'exec'), checker.__dict__)
        self.assertIs(checker.frozen_manifest(m), m)            # r3 accepts the generic manifest and binds 7c
        self.assertEqual(checker.PROVIDERS, pins['providers'])


class CaptureArchiveTests(unittest.TestCase):
    def test_gzip_capture_preserves_data_metadata_and_receipts(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            root = Path(root)
            (root / 'capture/nested').mkdir(parents=True)
            (root / 'receipts').mkdir()
            data = b'full recovery bytes\0' * 50000
            p = root / 'capture/nested/boot.bin'
            p.write_bytes(data)
            p.chmod(0o640)
            (root / 'capture/link').symlink_to('nested/boot.bin')
            receipt = b'{"changed":false}\n'
            (root / 'receipts/capture.1.json').write_bytes(receipt)
            args = {'run_dir': str(root), 'name': 'bt2-capture.tar.gz'}
            out = subprocess.check_output([sys.executable, '-I', '-B', '-c',
                                           controller.SNIPPETS['tar'], json.dumps(args)])
            result = json.loads(out)
            archive = root / args['name']
            self.assertEqual(result['sha256'], H(archive.read_bytes()))
            self.assertEqual(result['bytes'], archive.stat().st_size)
            self.assertEqual(result['receipts'], {'capture.1.json': H(receipt)})
            self.assertLess(result['bytes'], len(data) // 4)
            with tarfile.open(archive, 'r:gz') as tar:
                self.assertEqual(tar.extractfile('capture/nested/boot.bin').read(), data)
                self.assertEqual(tar.getmember('capture/nested/boot.bin').mode, 0o640)
                self.assertEqual(tar.getmember('capture/link').linkname, 'nested/boot.bin')
                self.assertEqual(tar.extractfile('receipts/capture.1.json').read(), receipt)
            self.assertEqual(p.read_bytes(), data)


class PlanTests(unittest.TestCase):
    def rec(self, seq, step, event, **kw):
        return {'seq': seq, 'step': step, 'event': event, **kw}

    def test_refused_install_needs_no_rollback(self):
        recs = [self.rec(0, None, 'header'),
                self.rec(1, 'hold-writers', 'intent', inverse='release-writers'), self.rec(2, 'hold-writers', 'done'),
                self.rec(3, 'install', 'intent', inverse='rollback', inverse_followups=['esp-restore', 'etc-restore']),
                self.rec(4, 'install', 'failed', refused=True)]
        p = controller.restore_plan(recs)
        self.assertEqual(p['todo'], ['release-writers'])
        recs[-1] = self.rec(4, 'install', 'failed', refused=False, exit_code=4)
        self.assertEqual(controller.restore_plan(recs)['todo'],
                         ['rollback', 'esp-restore', 'etc-restore', 'release-writers'])
        recs.pop()                                                       # intent without outcome = ambiguous
        self.assertEqual(controller.restore_plan(recs)['todo'][0], 'rollback')

    def test_base_job_is_a_boot_risk(self):
        recs = [self.rec(0, None, 'header'),
                self.rec(1, 'hold-writers', 'intent', inverse='release-writers'), self.rec(2, 'hold-writers', 'done'),
                self.rec(3, 'base-submit', 'intent', mutating=True)]          # submitted, outcome unknown
        p = controller.restore_plan(recs)
        self.assertEqual((p['todo'], p['boot_risk'], p['mutated']), (['release-writers'], True, True))
        recs.append(self.rec(4, 'base-submit', 'failed', refused=True))
        self.assertFalse(controller.restore_plan(recs)['boot_risk'])

    def test_release_name(self):
        self.assertEqual(controller.release_name('bt2-m1-20261026170000'), 'bt2-m1-20261026170000')
        self.assertEqual(controller.release_name('m1-run'), 'bt2-m1-run')


if __name__ == '__main__':
    unittest.main()
