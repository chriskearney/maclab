"""Fakes for the controller tests: labd API subset, a simulated Mac behind the Ops seam, the M5 runner.

Nothing here talks to a network, SSH or a device.
"""
import copy
import datetime
import hashlib
import json
import re

from bt2 import labd as labd_mod
from bt2 import transport


def H(b):
    return hashlib.sha256(b).hexdigest()


def iso(dt):
    return dt.isoformat().replace('+00:00', 'Z')


def now():
    return datetime.datetime.now(datetime.timezone.utc)


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.slept = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s
        self.slept += s


class FakeLabd:
    def __init__(self, devices, *, oob=None, modes=('network-only', 'serial-assisted')):
        self.devices = devices
        self.cap = {'schema': 1, 'per_job_oob_isolation': True, 'transaction_isolation': True, 'modes': list(modes)}
        self.oob_state = oob if oob is not None else {'controller': 'oobd m5', 'serial_connected': True,
                                                       'status': 'ok'}
        self.artifacts = {}
        self.frozen = {}
        self.jobs = {}
        self.calls = []
        self.fail = {}
        self.job_outcome = 'pass'
        self.base_outcome = 'pass'          # the fresh-baseline job (release ...-base)
        self.base_omt = 'NO_REGRESSION'     # its own verdict vs the stale pins (bt2 must not care)
        self.base_checks = [{'id': 'audio.default-sink', 'status': 'pass'}, {'id': 'gpu.driver', 'status': 'pass'},
                            {'id': 'setup.first-boot-hardware', 'status': 'skip'}]
        self.job_files = {}
        self.extra_behavior = None   # (jid, is_base, krel) -> (passed, {file: bytes}) for an eryk-bench test
        self.cts_behavior = None     # same, for an eryk-cts test (candidate job only)
        self.mac = None
        self.boots = 0
        self.grants = {}             # device -> {'artifacts': [...], 'ttl_sec': n} (POST .../artifact-grants)

    def _dev(self, name):
        if name not in self.devices:
            raise labd_mod.APIError(404, 'no device ' + name, '/api/devices/' + name)
        return self.devices[name]

    def give_oob(self, name):
        self.devices[name]['oob'] = {'driver': 'oobd', 'url': 'http://m5.test:7780', 'token': 'fake-token'}

    def new_boot(self, name, kernel, cmdline):
        self.boots += 1
        d = self.devices[name]
        d.update(boot_id='%08x-0000-4000-8000-%012x' % (self.boots, self.boots), kernel=kernel, cmdline=cmdline)

    # devices / lease / mode
    def device(self, name):
        self.calls.append(('GET', '/api/devices/' + name))
        return copy.deepcopy(self._dev(name))

    def capabilities(self):
        self.calls.append(('GET', '/api/recovery'))
        return copy.deepcopy(self.cap)

    def oob(self, name):
        self.calls.append(('GET', '/api/devices/%s/oob' % name))
        d = self._dev(name)
        # deployed labd: no route, or the sticky mode is not serial-assisted -> 404 (OOB hidden)
        if not d.get('oob') or d.get('effective_recovery_mode') != 'serial-assisted':
            raise labd_mod.APIError(404, '%s has no out-of-band controller' % name, '/api/devices/%s/oob' % name)
        return copy.deepcopy(self.oob_state)

    def lease(self, name, holder, ttl_sec):
        self.calls.append(('POST', '/api/devices/%s/lease' % name, holder, ttl_sec))
        d = self._dev(name)
        cur = d.get('lease')
        if cur and cur['holder'] != holder:
            raise labd_mod.APIError(409, 'leased by ' + cur['holder'], '/api/devices/%s/lease' % name)
        d['lease'] = {'holder': holder, 'expires': iso(now() + datetime.timedelta(seconds=ttl_sec))}
        return copy.deepcopy(d['lease'])

    def release(self, name, holder):
        self.calls.append(('DELETE', '/api/devices/%s/lease' % name, holder))
        d = self._dev(name)
        if d.get('lease') and d['lease']['holder'] == holder:
            d['lease'] = None
        return 'ok'

    def recovery_mode(self, name, mode, holder, transaction):
        self.calls.append(('POST', '/api/devices/%s/recovery-mode' % name, mode, transaction))
        d = self._dev(name)
        assert d.get('lease') and d['lease']['holder'] == holder, 'own lease required'
        d.update(effective_recovery_mode=mode, recovery_transaction=transaction, recovery_holder=holder)
        return {'schema': 1, 'device': name, 'mode': mode, 'holder': holder, 'transaction': transaction,
                'quiescent': True}

    # artifacts / installed / jobs
    def put_artifact(self, data):
        self.calls.append(('POST', '/api/artifacts', len(data)))
        sha = H(data)
        self.artifacts[sha] = bytes(data)
        return {'sha256': sha, 'size': len(data)}

    def artifact_grants(self, name, shas, ttl_sec):
        self.calls.append(('POST', '/api/devices/%s/artifact-grants' % name, tuple(shas), ttl_sec))
        self._dev(name)
        assert all(s in self.artifacts for s in shas), 'grant for a sha labd does not hold'
        self.grants[name] = {'artifacts': sorted(shas), 'ttl_sec': ttl_sec}
        if not shas:   # as labd answers a revocation: no expires (json omitzero)
            return {'device': name, 'artifacts': []}
        return {'device': name, 'artifacts': sorted(shas), 'expires': iso(now() + datetime.timedelta(seconds=ttl_sec))}

    def exec(self, *a, **k):
        raise AssertionError('controller tests never exec through labd directly (Ops seam is faked)')

    def post(self, path, body=None, timeout=60):
        self.calls.append(('POST', path))
        m = re.fullmatch(r'/api/installed/([^/]+)/manifest', path)
        if m:
            rel = m.group(1)
            assert body['manifest'] in self.artifacts and body['payload'] in self.artifacts
            man = json.loads(self.artifacts[body['manifest']])
            assert man['release'] == rel
            if rel in self.frozen:
                raise labd_mod.APIError(409, 'already frozen', path)
            self.frozen[rel] = {'manifest': man, 'manifest_sha256': body['manifest'], 'approved_by': body['approved_by']}
            return {'release': rel, 'manifest_sha256': body['manifest'], 'pins': 'PINS.expected', 'pins_sha256': 'b' * 64}
        m = re.fullmatch(r'/api/installed/([^/]+)/entry/([^/]+)', path)
        if m:
            rel, dev = m.groups()
            if 'entry' in self.fail and not rel.endswith('-base'):       # the candidate's entry
                raise self.fail['entry']
            if 'base-entry' in self.fail and rel.endswith('-base'):
                raise self.fail['base-entry']
            krel = self.frozen[rel]['manifest']['kernel']['release']
            entry = {'schema': 'maclab.installer-entry/1', 'device': dev, 'release': rel, 'found': True,
                     'name': 'Omarchy / linux-aurora', 'protocol': 'efi',
                     'path': 'boot():/EFI/Linux/omarchy_linux-aurora.efi#' + 'c' * 128,
                     'cmdline': 'root=UUID=x rw quiet', 'cmdline_tokens': ['root=UUID=x', 'rw', 'quiet'],
                     'entry_lines': ['  //linux-aurora'], 'entry_sha256': 'd' * 64,
                     'uki_file': '/boot/efi/EFI/Linux/omarchy_linux-aurora.efi', 'uki_sha256': 'e' * 64,
                     'uki_blake2b': 'c' * 128, 'uki_sections': {'.uname': {'text': krel}}}
            return {'device': dev, 'release': rel, 'entry': entry, 'entry_sha256': 'f' * 64,
                    'pins': 'PINS.installer-entry.' + dev}
        raise labd_mod.APIError(404, 'no route', path)

    def submit(self, spec):
        self.calls.append(('POST', '/api/jobs'))
        if 'submit' in self.fail:
            raise self.fail['submit']
        d = self._dev(spec['device'])
        assert d['lease']['holder'] == spec['holder']
        assert d['recovery_transaction'] == spec['recovery_transaction']
        assert d['effective_recovery_mode'] == spec['recovery_mode']
        assert any(f['manifest_sha256'] == spec['installed_manifest'] for f in self.frozen.values())
        assert [t['name'] for t in spec['tests']].count('omarchy-m-test') == 1
        for t in spec['tests']:
            if 'script' in t:
                assert t['script'] in self.artifacts
        jid = 'j1026-170000-ab%02x' % len(self.jobs)
        self.jobs[jid] = {'id': jid, 'state': 'queued', 'spec': copy.deepcopy(spec)}
        return copy.deepcopy(self.jobs[jid])

    def release_of(self, manifest_sha):
        return [r for r, f in self.frozen.items() if f['manifest_sha256'] == manifest_sha][0]

    def _run_job(self, jid):
        j = self.jobs[jid]
        if j['state'] != 'done':
            dev = j['spec']['device']
            rel = self.release_of(j['spec']['installed_manifest'])
            krel = self.frozen[rel]['manifest']['kernel']['release']
            is_base = rel.endswith('-base')
            outcome = self.base_outcome if is_base else self.job_outcome
            if is_base and 'base-boot' in self.fail:
                # the one-shot never came up: the Mac fell back to its default (labd outcome boot_failed)
                self.new_boot(dev, self.mac.known_good, self.mac.base_cmdline)
                j.update(state='done', outcome='boot_failed', summary='fake: test kernel did not come up',
                         result={'booted': False})
                return copy.deepcopy(j)
            # one-shot boot of the installed kernel, then labd restore = plain reboot to the default (the original)
            m = self.mac
            m.boot_stage2()
            self.new_boot(dev, krel, m.base_cmdline + ' maclab.job=' + jid + ' panic=10')
            m.guard_hook('start', krel)
            m.guard_hook('stop', krel)
            m.boot_stage2()
            self.new_boot(dev, m.known_good, m.base_cmdline)
            m.guard_hook('start', m.known_good)
            omt = self.base_omt if is_base else 'NO_REGRESSION'
            report = json.dumps({'tool': {'version': '0.1.13'}, 'machine': {'kernel': krel},
                                 'checks': self.base_checks}).encode()
            res = {'booted': True, 'boot_kernel': krel,
                   'installed': {'release': rel, 'verdicts': {'before': 'MATCH', 'booted': 'MATCH', 'after': 'MATCH'},
                                 'omt': omt, 'dmesg': 'NONE_NEW'},
                   'tests': [{'name': 'boot-health', 'passed': True},
                             {'name': 'omarchy-m-test', 'passed': omt == 'NO_REGRESSION',
                              'files': ['test-omarchy-m-test/omt-report.json']}]}
            extra = {}
            if any(t['name'] == 'eryk-bench' for t in j['spec']['tests']) and self.extra_behavior:
                ok, extra = self.extra_behavior(jid, is_base, krel)
                res['tests'].append({'name': 'eryk-bench', 'passed': ok})
                if not ok and outcome == 'pass':
                    outcome = 'tests_failed'
            if any(t['name'] == 'eryk-cts' for t in j['spec']['tests']) and self.cts_behavior:
                ok, files = self.cts_behavior(jid, is_base, krel)
                res['tests'].append({'name': 'eryk-cts', 'passed': ok})
                extra = {**extra, **files}
                if not ok and outcome == 'pass':
                    outcome = 'tests_failed'
            j.update(state='done', outcome=outcome, summary='fake job ' + outcome, result=res)
            sealed = (json.dumps(j, indent=2) + '\n').encode()
            self.job_files[jid] = {'test-omarchy-m-test/omt-report.json': report,
                                   'installed/dmesg-errors.txt': ('dmesg of %s\n' % jid).encode(),
                                   'installed/job.json': sealed, **extra}
            for name in self.fail.get('drop-files', []):
                self.job_files[jid].pop(name, None)
        return copy.deepcopy(j)

    def job_file(self, jid, name, limit=16 << 20, timeout=60):
        self.calls.append(('GET', '/api/jobs/%s/files/%s' % (jid, name)))
        f = self.job_files.get(jid, {})
        if name not in f:
            raise labd_mod.APIError(404, 'no file', '/api/jobs/%s/files/%s' % (jid, name))
        return f[name]

    def get(self, path, timeout=30):
        self.calls.append(('GET', path))
        m = re.fullmatch(r'/api/jobs/([^/?]+)/wait\?timeout=(\d+)', path)
        if m:
            assert int(m.group(2)) <= 2400
            return self._run_job(m.group(1))
        m = re.fullmatch(r'/api/jobs/([^/?]+)', path)
        if m:
            return copy.deepcopy(self.jobs[m.group(1)])
        raise labd_mod.APIError(404, 'no route', path)

    def job(self, jid):
        return self.get('/api/jobs/' + jid)


class FakeMac:
    """State of one simulated Mac + the bt2 target package semantics, reached only through FakeOps."""

    def __init__(self, lab, device, *, known_good, candidate_kernel, board, packages, mtree, bootbin, tools,
                 gui, wifi, m1n1_version='f5a82fdb-dirty'):
        self.lab, self.device = lab, device
        lab.mac = self
        self.known_good, self.candidate_kernel, self.board = known_good, candidate_kernel, board
        self.packages, self.mtree, self.bootbin = dict(packages), dict(mtree), bootbin
        self.tools, self.gui, self.wifi, self.m1n1_version = tools, gui, wifi, m1n1_version
        self.base_cmdline = 'root=UUID=x rw quiet'
        self.files = {}
        self.dirs = set()
        self.calls = []
        self.fail = {}
        self.held = self.esp_dirty = self.etc_dirty = self.installed = False
        # boot.bin-changing path: candidate bytes the install leaves, the guard unit and what it does per boot
        self.candidate_bootbin = None
        self.versions = {}                  # boot.bin sha -> stage 2 version that boot.bin runs
        self.guard = None                   # None | 'installed' | 'removed'
        self.guard_mode = 'stop'            # 'stop': restores at the candidate shutdown; 'late': at the next boot;
                                            # 'none': never restores
        self.guard_receipts = []

    def boot_stage2(self):
        """A boot runs the stage 2 of whatever boot.bin is on the ESP."""
        self.m1n1_version = self.versions.get(H(self.bootbin), self.m1n1_version)

    def guard_hook(self, phase, krel):
        if self.guard != 'installed':
            return
        boot = self.lab.devices[self.device]['boot_id']
        cand = H(self.candidate_bootbin)
        rec = {'phase': phase, 'running_kernel': krel, 'boot_id': boot, 'ok': True, 'bootbin_before': H(self.bootbin)}
        if phase == 'start' and krel == self.candidate_kernel_release:
            rec['action'] = 'keep-candidate-boot'
        elif H(self.bootbin) == cand and (self.guard_mode == 'stop' or (self.guard_mode == 'late' and phase == 'start')):
            self.bootbin = self.original_bootbin
            rec.update(action='restored', bootbin_after=H(self.bootbin))
        elif H(self.bootbin) == cand:
            return                          # the hook did not run (panic, power loss) or did nothing
        else:
            rec['action'] = 'original-already'
        rec['receipt'] = 'bootbin-guard.%d.json' % len(self.guard_receipts)
        self.guard_receipts.append(rec)

    def factory(self, api, device):
        assert device == self.device
        return FakeOps(self, api)

    def targets(self):
        return [c[1] for c in self.calls if c[0] == 'target']


class FakeOps:
    def __init__(self, mac, api):
        self.mac, self.api = mac, api

    @property
    def dev(self):
        return self.mac.lab.devices[self.mac.device]

    def push(self, path, data, mode=0o600):
        self.mac.calls.append(('push', path))
        if path in self.mac.files:
            raise transport.TransportError('push finalize failed: final exists')
        assert any(path.startswith(d + '/') for d in self.mac.dirs), 'push outside a created run dir: ' + path
        self.mac.files[path] = bytes(data)
        return {'path': path, 'sha256': H(data), 'bytes': len(data)}

    def pull(self, path, limit=1 << 31):
        self.mac.calls.append(('pull', path))
        if path == '/boot/efi/m1n1/boot.bin':
            return self.mac.bootbin
        return self.mac.files[path]

    def reboot(self):
        self.mac.calls.append(('reboot',))
        self.mac.boot_stage2()
        self.mac.lab.new_boot(self.mac.device, self.mac.known_good, self.mac.base_cmdline)
        if getattr(self.mac, 'reboot_raises', False):      # the agent died before answering the exec
            raise labd_mod.APIError(502, 'agent disconnected', '/api/devices/%s/exec' % self.mac.device)
        return {'exit_code': 0, 'stdout': '', 'stderr': ''}

    def snippet(self, name, arg, timeout=120):
        m, d = self.mac, self.dev
        m.calls.append(('snippet', name))
        if name == 'probe':
            return 0, {'schema': 'bt2.probe/1', 'kernel': d['kernel'], 'machine': 'aarch64', 'boot_id': d['boot_id'],
                       'cmdline': d['cmdline'], 'board': m.board, 'm1n1_stage2_version': m.m1n1_version,
                       'packages': {n: m.packages.get(n) for n in arg.get('packages', [])},
                       'mtree': {n: m.mtree.get(n) for n in arg.get('packages', [])},
                       'wifi': m.wifi, 'gui': m.gui if arg.get('gui_user') else None,
                       'tools': {p: m.tools.get(p) for p in arg.get('tools', [])},
                       'bootbin_sha256': H(m.bootbin), 'db_lock': False,
                       'run_dir_exists': (arg['run_dir'] in m.dirs) if arg.get('run_dir') else None}, {}
        if name == 'mkrun':
            if arg['run_dir'] in m.dirs:
                return 1, None, {'stderr': 'AssertionError: run dir already exists'}
            m.dirs.add(arg['run_dir'])
            for s in arg['subdirs']:
                m.dirs.add(arg['run_dir'] + '/' + s)
            return 0, {'created': True, 'run_dir': arg['run_dir']}, {}
        if name == 'locks':
            return 0, {'ok': True, 'locks': {}}, {}
        if name == 'tdir-new':
            new = arg['run_dir'] + '/t.r%d' % arg['k']
            assert arg['run_dir'] + '/t' in m.dirs and new not in m.dirs
            m.dirs.add(new)
            return 0, {'created': new}, {}
        if name == 'tdir-swap':
            run, k = arg['run_dir'], arg['k']
            def tree(d):
                return {p.rsplit('/', 1)[1]: H(v) for p, v in m.files.items() if p.rsplit('/', 1)[0] == d}
            new, cur, prev = run + '/t.r%d' % k, run + '/t', run + '/t.prev-%d' % k
            assert tree(new) == arg['files'], 'refreshed package differs'
            old = tree(cur)
            for p in [p for p in m.files if p.rsplit('/', 1)[0] == cur]:
                m.files[prev + '/' + p.rsplit('/', 1)[1]] = m.files.pop(p)
            for p in [p for p in m.files if p.rsplit('/', 1)[0] == new]:
                m.files[cur + '/' + p.rsplit('/', 1)[1]] = m.files.pop(p)
            m.dirs.discard(new); m.dirs.add(prev)
            return 0, {'previous': prev, 'previous_files': old, 'files': tree(cur)}, {}
        if name == 'settle':
            return 0, {'settled': True, 'menu_sha256': None, 'samples': 5, 'seen_busy': []}, {}
        if name == 'tar':
            run = arg['run_dir']
            data = b'FAKETAR\0' + m.files[run + '/capture/state.json']
            path = run + '/' + arg['name']
            m.files[path] = data
            rec = {k.rsplit('/', 1)[1]: H(v) for k, v in sorted(m.files.items()) if k.startswith(run + '/receipts/')}
            return 0, {'path': path, 'sha256': H(data), 'bytes': len(data), 'receipts': rec}, {}
        raise AssertionError('unknown snippet ' + name)

    def target(self, run_dir, cmd, timeout, extra=()):
        m, d = self.mac, self.dev
        held_flag = '--held' in extra
        m.calls.append(('target', cmd + (' --held' if held_flag else '')))
        assert list(extra[:1]) == ['--config-sha256']
        cfg_raw = m.files[run_dir + '/config.json']
        assert H(cfg_raw) == extra[1]
        cfg = json.loads(cfg_raw)
        base = {'schema': 'bt2.target-result/1', 'cmd': cmd, 'run_id': cfg['run_id'], 'device': cfg['device'],
                'boot_id': d['boot_id'], 'kernel': d['kernel'], 'config_sha256': H(cfg_raw)}
        if cmd in m.fail:
            code, fields = m.fail.pop(cmd)
            return code, {**base, 'ok': False, 'changed': code != 3, **fields}, {'stderr': 'injected'}
        code, res = getattr(self, '_' + cmd.replace('-', '_'))(run_dir, cfg, held_flag)
        out = {**base, 'ok': code == 0, **res}
        n = sum(1 for k in m.files if k.startswith('%s/receipts/%s.' % (run_dir, cmd)))
        m.files['%s/receipts/%s.%d.json' % (run_dir, cmd, n)] = json.dumps(out).encode()
        return code, out, {'stderr': ''}

    # target command semantics (state machine only)
    def _fetch(self, run, cfg, held):
        assert all(s in self.mac.lab.artifacts for s in cfg['artifact_shas'].values()), 'fetch before upload'
        g = self.mac.lab.grants.get(cfg['device']) or {}
        assert g.get('artifacts') == sorted(set(cfg['artifact_shas'].values())), 'fetch without a grant for exactly its shas'
        return 0, {'changed': True, 'artifacts': {f: {'sha256': s} for f, s in cfg['artifact_shas'].items()}}

    def _preflight(self, run, cfg, held):
        names = sorted({p['name'] for p in cfg['candidates']} | {p['name'] for p in cfg['originals']})
        return 0, {'changed': False, 'facts': {'board': self.mac.board, 'kernel': self.dev['kernel'],
                                               'packages': {n: self.mac.packages.get(n) for n in names},
                                               'bootbin_sha256': H(self.mac.bootbin), 'problems': []}}

    def _capture(self, run, cfg, held):
        st = {'schema': 'bt2.capture/1', 'run_id': cfg['run_id'], 'device': cfg['device'], 'kernel': self.dev['kernel'],
              'packages': {p['name']: {'version': self.mac.packages.get(p['name'])} for p in cfg['originals']}}
        raw = json.dumps(st, sort_keys=True).encode()
        self.mac.files[run + '/capture/state.json'] = raw
        return 0, {'changed': False, 'capture_sha256': H(raw)}

    def _hold_writers(self, run, cfg, held):
        self.mac.held = True
        return 0, {'changed': True, 'masked': cfg['writer_units']}

    def _esp_prep(self, run, cfg, held):
        assert self.mac.held
        self.mac.esp_dirty = True
        return 0, {'changed': True}

    def _install(self, run, cfg, held):
        assert self.mac.held and self.dev['kernel'] == cfg['known_good_kernel']
        for p in cfg['candidates']:
            self.mac.packages[p['name']] = p['version']
        self.mac.installed = self.mac.esp_dirty = self.mac.etc_dirty = True
        res = {'changed': True, 'candidate': {'krel': cfg['expected_kernel'], 'uki_path': 'EFI/Linux/omarchy_linux-aurora.efi',
                                              'uki_sha256': 'e' * 64, 'entry_name': 'Omarchy/linux-aurora'},
               'bootbin_unchanged': True}
        if cfg.get('allow_bootbin_change'):
            m = self.mac
            m.original_bootbin, m.bootbin = m.bootbin, m.candidate_bootbin
            m.candidate_kernel_release = cfg['expected_kernel']
            assert H(m.bootbin) == cfg['expected_bootbin_sha256'], 'fake candidate boot.bin differs from the manifest'
            res.update(bootbin_unchanged=False, bootbin_is_expected=True, bootbin_sha256=H(m.bootbin),
                       recovery_copy={'path': 'm1n1/boot.bin.old', 'sha256': H(m.original_bootbin)})
        return 0, res

    def _rollback(self, run, cfg, held):
        d = self.dev
        if d['kernel'] != cfg['known_good_kernel'] or 'maclab.job=' in d['cmdline'] or not self.mac.held:
            return 3, {'changed': False, 'refused_reason': 'not on known-good untagged boot with writers held'}
        for o in cfg['originals']:
            if o['version'] is None:
                self.mac.packages.pop(o['name'], None)
            else:
                self.mac.packages[o['name']] = o['version']
        self.mac.installed = False
        return 0, {'changed': True}

    def _esp_restore(self, run, cfg, held):
        self.mac.esp_dirty = False
        return 0, {'changed': True}

    def _etc_restore(self, run, cfg, held):
        self.mac.etc_dirty = False
        return 0, {'changed': True}

    def _audit(self, run, cfg, held):
        diffs = [k for k, v in (('packages', self.mac.installed), ('esp', self.mac.esp_dirty),
                                ('etc', self.mac.etc_dirty), ('writers', self.mac.held != held)) if v]
        return (0 if not diffs else 4), {'changed': False, 'differences': diffs, 'held_mode': held}

    def _release_writers(self, run, cfg, held):
        self.mac.held = False
        return 0, {'changed': True}

    def _cleanup(self, run, cfg, held):
        return 0, {'changed': True}

    def _bootbin_guard_install(self, run, cfg, held):
        m = self.mac
        assert cfg['bootbin_guard']['recovery_copy'] == 'm1n1/boot.bin.old' and H(m.bootbin) == cfg['bootbin_guard']['candidate_sha256']
        m.guard, m.etc_dirty = 'installed', True
        return 0, {'changed': True, 'unit': cfg['bootbin_guard']['unit'],
                   'state': {'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'enabled'},
                   'recovery_copy': 'm1n1/boot.bin.old', 'recovery_copy_sha256': H(m.original_bootbin),
                   'esp_identity': {'partition_uuid': '159ecdaa-1ad2-4307-a721-44d69c3cb159', 'fat_serial': '4F4D-5801',
                                    'esp_bytes': 524288000, 'linux_device': '/dev/nvme0n1p4'}}

    def _bootbin_guard_status(self, run, cfg, held):
        m, g = self.mac, cfg['bootbin_guard']
        return 0, {'changed': False, 'bootbin_sha256': H(m.bootbin), 'is_original': H(m.bootbin) == g['original_sha256'],
                   'is_candidate': H(m.bootbin) == g['candidate_sha256'], 'stage2_version': m.m1n1_version,
                   'recovery_copy_sha256': g['original_sha256'], 'unit_state': {}, 'receipts': list(m.guard_receipts)}

    def _bootbin_guard_remove(self, run, cfg, held):
        m, g = self.mac, cfg['bootbin_guard']
        cas = {'action': 'original-already'}
        if H(m.bootbin) == g['candidate_sha256']:
            m.bootbin, cas = m.original_bootbin, {'action': 'restored'}
        m.guard = 'removed'
        return 0, {'changed': True, 'cas': cas, 'removed': ['unit'], 'bootbin_sha256': H(m.bootbin)}


class FakeM5:
    def __init__(self):
        self.roots = {}
        self.calls = []

    def __call__(self, args, data=None, timeout=600):
        self.calls.append(tuple(args[:3]))
        action, root = args[0], args[1]
        if action == 'init':
            assert root not in self.roots, 'never adopt an existing run root'
            self.roots[root] = {}
            return {'root': '/m5/' + root, 'dev': 1, 'uid': 501, 'gid': 20, 'mode': 0o700, 'free_bytes': 1 << 40,
                    'hostname': 'm5'}
        name, size, sha = args[2], int(args[3]), args[4]
        files = self.roots[root]
        if action == 'write':
            assert name not in files and H(data) == sha and len(data) == size
            files[name] = data
        assert name in files
        return {'path': '/m5/%s/%s' % (root, name), 'sha256': sha, 'bytes': size, 'identity': [1, len(files)],
                'fsync_reopen_match': True}
