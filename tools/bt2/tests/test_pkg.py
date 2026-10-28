"""bt2 I2 tests: target pkg.py (install/rollback) and writers.py (hold/release) against fake roots.

Run: python3.14 -B -m unittest -v /dev/shm/claude-229/bt2/tests/test_pkg.py
Fake roots live under /dev/shm/maclab-bt2-tests/i2-* (BT2_KEEP=1 keeps them). The real target is run as a
subprocess exactly as on the Mac: python3 -I -B <target dir> <cmd> --run-dir /var/lib/maclab/bt2/<run>.
"""
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fx_pkg'))
import fixture as fx  # noqa: E402

ETC = '/etc/systemd/system'
ALIAS = 'limine-snapper-watcher.service'


def lst(lab, p):
    return os.lstat(lab.R(p))


class Base(unittest.TestCase):
    def tearDown(self):
        lab = getattr(self, 'lab', None)
        if lab is not None:
            lab.cleanup()

    def ok(self, cmd, **env):
        code, res, r = self.lab.target(cmd, **env)
        self.assertEqual(code, 0, '%s failed: %s\nstderr: %s' % (cmd, res, r.stderr.decode()[-3000:]))
        self.assertTrue(res['ok'])
        self.assertTrue(os.path.exists(self.lab.run + '/receipts/%s.0.json' % cmd))
        return res

    def bad(self, cmd, want_code, **env):
        code, res, r = self.lab.target(cmd, **env)
        self.assertEqual(code, want_code, '%s: expected exit %d, got %d: %s\n%s'
                         % (cmd, want_code, code, res, r.stderr.decode()[-3000:]))
        self.assertFalse(res['ok'])
        return res

    def journal(self, name):
        p = os.path.join(self.lab.run, name)
        return sorted(os.listdir(p)) if os.path.isdir(p) else []

    def jread(self, name):
        with open(os.path.join(self.lab.run, name)) as f:
            return json.load(f)


class WritersTests(Base):
    def setUp(self):
        self.lab = fx.m1_lab('wr')
        self.lab.capture()

    def test_hold_release_round_trip(self):
        lab = self.lab
        alias_ino = lst(lab, ETC + '/' + ALIAS).st_ino
        os.utime(lab.R(ETC), ns=(fx.MTIME * 10**9, fx.MTIME * 10**9))
        dir_mtime = lst(lab, ETC).st_mtime_ns
        res = self.ok('hold-writers')
        self.assertTrue(res['changed'])
        w = self.jread('writers.json')
        self.assertEqual(w['etc_systemd_dir_mtime_ns'], dir_mtime, 'recorded before the first change')
        self.assertNotEqual(lst(lab, ETC).st_mtime_ns, dir_mtime)
        self.assertEqual(sorted(m['unit'] for m in w['masks']), sorted(fx.WRITERS))
        self.assertEqual([a['unit'] for a in w['aliases']], [ALIAS])
        self.assertEqual(w['aliases'][0]['ino'], alias_ino)
        self.assertEqual(sorted(w['was_active']), ['limine-snapper-sync.service', 'snapper-cleanup.timer'])
        self.assertEqual(w['stopped'][0], 'snapper-cleanup.timer', 'timers are stopped before services')
        held = lab.run + '/hold/alias.' + ALIAS
        self.assertEqual(os.lstat(held).st_ino, alias_ino, 'alias kept by hard link (same inode)')
        for u in fx.WRITERS:
            self.assertEqual(os.readlink(lab.R(ETC + '/' + u)), '/dev/null')
            s = lab.show(u)
            self.assertEqual((s['LoadState'], s['ActiveState']), ('masked', 'inactive'), u)
        # idempotent second hold: no change, with proof
        res2 = self.ok('hold-writers')
        self.assertFalse(res2['changed'])
        self.assertTrue(res2['already_held'])
        self.assertEqual(len(res2['proof']['masks']), 4)
        n_start_before = len([a for a in lab.systemctl_log() if a[0] == 'start'])
        self.assertEqual(n_start_before, 0)
        rel = self.ok('release-writers')
        self.assertTrue(rel['changed'])
        self.assertEqual(lst(lab, ETC + '/' + ALIAS).st_ino, alias_ino, 'alias re-linked with the original inode')
        self.assertEqual(lst(lab, ETC).st_mtime_ns, dir_mtime, '/etc/systemd/system mtime restored')
        self.assertFalse(os.path.lexists(held))
        for u in ('limine-snapper-sync.service', 'snapper-timeline.timer', 'snapper-cleanup.timer'):
            self.assertFalse(os.path.lexists(lab.R(ETC + '/' + u)), u)
        starts = [a[1] for a in lab.systemctl_log() if a[0] == 'start']
        self.assertEqual(sorted(starts), ['limine-snapper-sync.service', 'snapper-cleanup.timer'],
                         'only originally active units are started')
        for u in fx.WRITERS:
            s = lab.show(u)
            cap = lab.state['units'][u]
            self.assertEqual({k: s[k] for k in cap}, cap, u)
        rel2 = self.ok('release-writers')
        self.assertFalse(rel2['changed'])
        self.assertTrue(rel2['already_released'])

    def test_hold_and_release_resume_after_crash(self):
        lab = self.lab
        alias_ino = lst(lab, ETC + '/' + ALIAS).st_ino
        self.ok('hold-writers')
        # Simulate a crash right after the last mask symlink was created but before writers.json recorded it.
        w = self.jread('writers.json')
        last = w['masks'].pop()
        w['complete'] = False
        fx.wr(lab.run + '/writers.json', json.dumps(w).encode(), 0o600)
        res = self.ok('hold-writers')
        w2 = self.jread('writers.json')
        self.assertTrue(w2['complete'])
        self.assertEqual(w2['masks'][-1]['ino'], last['ino'], 'own mask adopted via its intent file')
        self.assertEqual(w2['preexisting_masks'], [])
        self.assertTrue(res['proof']['units'])
        # Simulate a crashed release: alias already re-linked (same inode) and one mask removed.
        os.unlink(lab.R(ETC + '/limine-snapper-sync.service'))
        os.unlink(lab.R(ETC + '/' + ALIAS))
        os.link(lab.run + '/hold/alias.' + ALIAS, lab.R(ETC + '/' + ALIAS), follow_symlinks=False)
        self.ok('release-writers')
        self.assertEqual(lst(lab, ETC + '/' + ALIAS).st_ino, alias_ino)
        self.assertFalse(os.path.lexists(lab.run + '/hold/alias.' + ALIAS))
        for u in fx.WRITERS:
            cap = lab.state['units'][u]
            s = lab.show(u)
            self.assertEqual({k: s[k] for k in cap}, cap, u)

    def test_refuse_when_cleanup_running(self):
        lab = self.lab
        lab.sd_set('snapper-cleanup.service', ActiveState='active', SubState='running')
        res = self.bad('hold-writers', 3)
        self.assertIn('snapper-cleanup.service', res['refused_reason'])
        self.assertFalse(res['changed'])
        self.assertFalse(os.path.exists(lab.run + '/writers.json'))
        self.assertEqual(os.readlink(lab.R(ETC + '/' + ALIAS)), '/usr/lib/systemd/system/limine-snapper-sync.service')
        self.assertFalse(os.path.lexists(lab.R(ETC + '/limine-snapper-sync.service')))
        self.assertEqual([a for a in lab.systemctl_log() if a[0] in ('stop', 'start')], [])

    def test_install_refuses_without_hold(self):
        res = self.bad('install', 3)
        self.assertIn('writers', res['refused_reason'])
        self.assertEqual(self.lab.versions()['linux-aurora'], '7.2.11.aurora6-1')


class M1RoundTrip(Base):
    def setUp(self):
        self.lab = fx.m1_lab('m1')
        self.lab.capture()
        self.before = self.lab.snapshot(skip=(ETC,))
        self.before_etc = self.lab.snapshot(subs=(ETC,))
        self.ok('hold-writers')
        self.prep = self.lab.esp_prep_fallback()

    def test_upgrade_rollback_exact(self):
        lab = self.lab
        st = lab.state
        orig_uki = fx.rd(lab.R('/boot/efi/EFI/Linux/omarchy_linux-aurora.efi'))
        res = self.ok('install')
        v = lab.versions()
        for p in lab.cfg['candidates']:
            self.assertEqual(v[p['name']], p['version'])
        self.assertEqual([p['tag'] for p in res['phases']], ['main', 'boot'])
        self.assertEqual(res['candidate']['krel'], fx.K7)
        self.assertEqual(res['candidate']['entry_name'], 'Omarchy/linux-aurora')
        self.assertTrue(res['candidate']['pin_ok'])
        self.assertTrue(res['bootbin_unchanged'])
        self.assertEqual(res['default_entry']['name'], self.prep['fallback']['entry'])
        self.assertEqual(res['default_entry']['mode'], 'fallback')
        self.assertEqual(res['running_tree']['status'], 'exact')
        self.assertEqual(res['esp_new_files'], [])
        self.assertEqual(res['units_started'], [])
        # local-only config: byte-exact options block, no repository sections
        conf = fx.rd(lab.run + '/pkgs/pacman-local-only.conf')
        self.assertTrue(fx.PACMAN_CONF.startswith(conf))
        self.assertIn(b'SigLevel    = Required DatabaseOptional', conf)
        self.assertNotIn(b'[core]', conf)
        cfgs = [json.loads(x) for x in fx.rd(lab.R('/.fake/pacman-config.log')).decode().splitlines()]
        self.assertTrue(cfgs and all(c['sections'] == ['[options]'] for c in cfgs))
        # marker lifecycle: owned marker created (absent at capture), receipt with dev/ino
        mk = lab.R('/usr/lib/modules/%s/.keep-local-kernel' % fx.K6)
        self.assertTrue(os.path.isfile(mk))
        rec = self.jread('install/marker.json')
        self.assertEqual(rec['ino'], os.lstat(mk).st_ino)
        self.assertTrue(res['marker']['created'])
        # rerun install is an idempotent no-op on a completed install
        res_again = self.ok('install')
        self.assertFalse(res_again['changed'])
        # rollback refuses off the known-good kernel / on a tagged boot
        self.bad('rollback', 3, BT2_TEST_UNAME_R=fx.K7)
        rb = self.ok('rollback')
        self.assertEqual([p['tag'] for p in rb['phases']], ['boot', 'rest-u'])
        self.assertTrue(rb['tree']['held'] and rb['tree']['hold_deleted'] and rb['tree']['exact'])
        self.assertEqual(self.jread('rollback/tree.hold-intent.json')['hold'],
                         '/usr/lib/modules/.bt2-hold-%s-%s' % (fx.sha(lab.run_id.encode())[:8], fx.K6))
        self.assertTrue(rb['marker']['removed'])
        self.assertFalse(os.path.lexists(mk))
        self.assertEqual(rb['leftover_candidate_module_dirs'], [fx.K7])
        v = lab.versions()
        for n, p in st['packages'].items():
            self.assertEqual(v.get(n), p['version'], n)
        mods = os.listdir(lab.R('/usr/lib/modules'))
        self.assertFalse([m for m in mods if m.startswith('.bt2')], mods)
        after = lab.snapshot(skip=(ETC, '/usr/lib/modules/' + fx.K7))
        self.assertEqual(after, self.before)
        self.assertEqual(fx.rd(lab.R('/boot/efi/EFI/Linux/omarchy_linux-aurora.efi')), orig_uki)
        # rerun rollback: nothing left to do, still exact
        rb2 = self.ok('rollback')
        self.assertEqual(rb2['phases'], [])
        self.assertFalse(rb2['changed'])
        self.ok('release-writers')
        self.assertEqual(lab.snapshot(subs=(ETC,)), self.before_etc)

    def test_marker_tamper_blocks_removal(self):
        lab = self.lab
        self.ok('install')
        mk = lab.R('/usr/lib/modules/%s/.keep-local-kernel' % fx.K6)
        fx.wr(mk, b'someone else\n')
        res = self.bad('rollback', 3)
        self.assertIn('marker', res['refused_reason'])
        self.assertTrue(os.path.exists(mk))
        self.assertEqual(lab.versions()['linux-aurora'], '7.2.11.aurora7-1')
        self.assertFalse(os.path.lexists(lab.R('/usr/lib/modules/.bt2-hold-%s-%s' % (lab.run8(), fx.K6))))


class M3FirstInstall(Base):
    def setUp(self):
        self.lab = fx.m3_lab('m3')
        self.lab.capture()
        self.before = self.lab.snapshot(skip=(ETC + '/limine-snapper-sync.service', ETC + '/' + ALIAS,
                                              ETC + '/snapper-timeline.timer', ETC + '/snapper-cleanup.timer'))
        self.ok('hold-writers')
        self.lab.esp_prep_custom()

    def test_conflicts_held_absent_boot_removed(self):
        lab = self.lab
        st = lab.state
        self.assertEqual(sorted(cf['path'] for cf in st['conflicts']),
                         ['/etc/default/update-m1n1', '/etc/systemd/system/omarchy-vendor-firmware.service'])
        inos = {cf['path']: os.lstat(lab.R(cf['path'])).st_ino for cf in st['conflicts']}
        res = self.ok('install')
        self.assertEqual([p['tag'] for p in res['phases']], ['main', 'boot'])
        self.assertEqual(sorted(res['conflicts_held']), sorted(inos))
        self.assertEqual(lab.versions()['omarchy-mac-boot'], '20261026-1')
        self.assertEqual(fx.rd(lab.R('/etc/default/update-m1n1')), b'M1N1_UPDATE=1 # package default\n')
        self.assertEqual(res['default_entry']['mode'], 'custom')
        self.assertEqual(res['default_entry']['name'], 'Omacom Edge - aurora6 M3 GPU')
        self.assertEqual(res['candidate']['entry_name'], 'SiliconForest Linux/linux-aurora')
        self.assertEqual(res['candidate']['krel'], fx.K7)
        self.assertIn('EFI/Linux/omarchy_linux-m3-eryk.efi', [f['path'] for f in res['esp_new_files']])
        self.assertIn('SiliconForest Linux/linux-m3-eryk', res['menu_entries_new'])
        self.assertEqual(res['units_started'], ['omarchy-mac-efi-vars.service'])
        self.assertTrue(res['marker'].get('preexisting'))
        self.assertEqual(res['running_tree']['status'], 'exact')
        rb = self.ok('rollback')
        self.assertEqual(rb['units_stopped'], ['omarchy-mac-efi-vars.service'])
        self.assertEqual([(p['tag'], p['op']) for p in rb['phases']], [('boot', 'R'), ('rest-u', 'U')])
        self.assertFalse(rb['tree']['held'])
        self.assertIsNone(lab.versions().get('omarchy-mac-boot'))
        for cf in st['conflicts']:
            s = os.lstat(lab.R(cf['path']))
            self.assertEqual((fx.sha(fx.rd(lab.R(cf['path']))), s.st_mode & 0o7777, s.st_mtime_ns),
                             (cf['sha256'], cf['mode'], cf['mtime_ns']), cf['path'])
            self.assertEqual(s.st_ino, inos[cf['path']], 'reinstated by rename (same inode)')
        self.assertEqual(sorted(rb['conflicts_reinstated']), sorted(inos))
        self.assertTrue(os.path.isfile(lab.R('/usr/lib/modules/%s/.keep-local-kernel' % fx.KM3)))
        after = lab.snapshot(skip=(ETC + '/limine-snapper-sync.service', ETC + '/' + ALIAS,
                                   ETC + '/snapper-timeline.timer', ETC + '/snapper-cleanup.timer',
                                   '/usr/lib/modules/' + fx.K7))
        self.assertEqual(after, self.before)
        self.assertEqual(lab.show('omarchy-mac-efi-vars.service')['ActiveState'], 'inactive')


class Failures(Base):
    def setUp(self):
        self.lab = fx.m1_lab('fail')
        self.lab.capture()
        self.before = self.lab.snapshot(skip=(ETC,))
        self.ok('hold-writers')
        self.lab.esp_prep_fallback()

    def test_print_plan_extra_target_refused(self):
        lab = self.lab
        res = self.bad('install', 3, BT2_FAKE_PRINT_EXTRA='libdrm-aurora')
        self.assertIn('print plan', res['refused_reason'])
        self.assertIn('libdrm-aurora', res['refused_reason'])
        self.assertFalse(res['changed'])
        self.assertEqual(lab.versions()['linux-aurora'], '7.2.11.aurora6-1')
        self.assertFalse([f for f in self.journal('install') if f.endswith('.intent.json')])
        self.assertEqual(lab.snapshot(skip=(ETC,)), self.before)

    def test_unfinished_esp_prep_refused(self):
        lab = self.lab
        p = json.loads(fx.rd(lab.run + '/espops-prep.json'))
        p['status'] = 'started'
        fx.wr(lab.run + '/espops-prep.json', json.dumps(p).encode(), 0o600)
        res = self.bad('install', 3)
        self.assertIn('esp-prep did not complete', res['refused_reason'])
        self.assertEqual(lab.versions()['linux-aurora'], '7.2.11.aurora6-1')

    def test_pacman_failure_midway_then_rollback(self):
        lab = self.lab
        res = self.bad('install', 4, BT2_FAKE_FAIL_PKG='mesa-aurora')
        self.assertIn('FAILED', res['error'])
        out = self.jread('install/main.0.outcome.json')
        self.assertEqual((out['outcome'], out['exit_code']), ('FAILED', 1))
        self.assertTrue(out['group_drained'])
        self.assertTrue(os.path.exists(lab.run + '/install/main.0.intent.json'))
        self.assertEqual(lab.versions()['linux-aurora'], '7.2.11.aurora7-1')   # partial: kernel went first
        again = self.bad('install', 3)                                         # no automatic retry
        self.assertIn('no automatic retry', again['refused_reason'])
        rb = self.ok('rollback')
        self.assertEqual(rb['phases'][0]['tag'], 'rest-u')
        self.assertEqual(sorted(rb['phases'][0]['packages']),
                         ['linux-aurora', 'linux-aurora-headers', 'mesa-aurora', 'vulkan-aurora'])
        self.assertTrue(rb['tree']['hold_deleted'])
        self.assertEqual(lab.snapshot(skip=(ETC, '/usr/lib/modules/' + fx.K7)), self.before)

    def test_bootbin_change_restored_and_failed(self):
        lab = self.lab
        bb = fx.rd(lab.R('/boot/efi/m1n1/boot.bin'))
        bbo = fx.rd(lab.R('/boot/efi/m1n1/boot.bin.old'))
        res = self.bad('install', 4, BT2_FAKE_BOOTBIN_CHANGES=1)
        self.assertIn('boot.bin changed', res['error'])
        self.assertEqual(fx.rd(lab.R('/boot/efi/m1n1/boot.bin')), bb)
        self.assertEqual(fx.rd(lab.R('/boot/efi/m1n1/boot.bin.old')), bbo)
        self.assertIn('bootbin-restore.m1n1_boot.bin.intent.json', self.journal('install'))
        self.ok('rollback')
        self.assertEqual(lab.snapshot(skip=(ETC, '/usr/lib/modules/' + fx.K7)), self.before)

    def test_hook_error_line_fails_even_on_exit_0(self):
        res = self.bad('install', 4, BT2_FAKE_HOOK_ERROR=1)
        self.assertIn('hook-failure', res['error'])
        out = self.jread('install/main.0.outcome.json')
        self.assertEqual((out['outcome'], out['exit_code']), ('COMPLETED', 0))
        self.assertTrue(out['hook_errors'])

    def test_timeout_is_unknown(self):
        lab = self.lab
        res = self.bad('install', 4, BT2_FAKE_HANG=1, BT2_TEST_PACMAN_TIMEOUT=2, BT2_TEST_PACMAN_GRACE=3)
        self.assertTrue(res['error'].startswith('UNKNOWN'), res['error'])
        out = self.jread('install/main.0.outcome.json')
        self.assertEqual(out['outcome'], 'UNKNOWN')
        self.assertTrue(out['timed_out'] and out['group_drained'])
        self.assertTrue(os.path.exists(lab.R('/var/lib/pacman/db.lck')))
        self.assertIn('db.lck', self.bad('rollback', 3)['refused_reason'])

    def test_rollback_resumes_after_failed_attempt(self):
        lab = self.lab
        self.ok('install')
        r1 = self.bad('rollback', 4, BT2_FAKE_FAIL_PKG='mesa-aurora')
        self.assertIn('rest-u', r1['error'])
        self.assertEqual(lab.versions()['omarchy-mac-boot'], '20261010-1')   # boot phase done in attempt 1
        rb = self.ok('rollback')
        self.assertEqual([p['tag'] for p in rb['phases']], ['rest-u'])
        self.assertTrue(rb['tree']['hold_deleted'])
        self.assertEqual(lab.snapshot(skip=(ETC, '/usr/lib/modules/' + fx.K7)), self.before)


if __name__ == '__main__':
    unittest.main()
