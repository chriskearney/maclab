"""bt2 boot.bin-changing path: target pkg.py check_bootbin (allow_bootbin_change) and target/guard.py.

Every command runs through the real target dispatcher exactly as on the Mac
(python -I -B <target> <cmd> --run-dir /var/lib/maclab/bt2/<run>, fixture.TARGET = this checkout's target/ unless
BT2_TARGET says otherwise) against a fake M1 root, with a frozen config.json written before each command.
"""
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fx_pkg'))
import fixture as fx  # noqa: E402
import capture as tcap  # noqa: E402  (the target's own module, from fixture.TARGET)

ETC = '/etc/systemd/system'
ORIG_BB = b'm1n1 stage2 aurora20 + dtbs + u-boot ' + b'o' * 4963      # 5000 B: two 4 KiB clusters
CAND_BB = ORIG_BB + b'\n+candidate-dtbs\n'                            # what the fake update-m1n1 writes
OLD_BB = b'm1n1 older (fc1d)'                                         # boot.bin.old before the run
PART = '159ecdaa-1ad2-4307-a721-44d69c3cb159'


class GuardBase(unittest.TestCase):
    def setUp(self):
        lab = self.lab = fx.m1_lab('gd')
        fx.wr(lab.R('/boot/efi/m1n1/boot.bin'), ORIG_BB, mtime=fx.MTIME)
        fx.wr(lab.R('/boot/efi/m1n1/boot.bin.old'), OLD_BB, mtime=fx.MTIME)
        os.makedirs(lab.R('/proc/device-tree/chosen'), exist_ok=True)
        fx.wr(lab.R('/proc/device-tree/chosen/asahi,efi-system-partition'), PART.encode() + b'\0')
        os.makedirs(lab.R('/proc/self'), exist_ok=True)
        fx.wr(lab.R('/proc/self/mounts'), b'/dev/nvme0n1p5 / btrfs rw 0 0\n/dev/nvme0n1p4 /boot/efi vfat rw 0 0\n')
        keep = ('linux-aurora', 'linux-aurora-headers')
        self.cands = [p for p in lab.cfg['candidates'] if p['name'] in keep]
        self.origs = [p for p in lab.cfg['originals'] if p['name'] in keep]
        self.run8 = fx.sha(lab.run_id.encode())[:8]
        self.unit = 'bt2-%s-bootbin-guard.service' % self.run8
        self.write_config()
        lab.capture()
        lab.state['esp']['usage'] = tcap.esp_usage(lab.R('/boot/efi'))
        fx.wr(lab.run + '/capture/state.json', (json.dumps(lab.state, indent=1, sort_keys=True) + '\n').encode(), 0o600)
        self.ok('hold-writers')
        lab.esp_prep_fallback()

    def tearDown(self):
        self.lab.cleanup()

    def write_config(self, expected=None, **kw):
        g = {'unit': self.unit, 'recovery_copy': 'm1n1/boot.bin.old', 'candidate_sha256': expected or fx.sha(CAND_BB),
             'original_sha256': fx.sha(ORIG_BB), 'candidate_krel': fx.K7, 'candidate_stage2_version': 'cand-5d17',
             'original_stage2_version': 'orig-f5a8'}
        return self.lab.config(self.cands, self.origs, allow_bootbin_change=True,
                               expected_bootbin_sha256=expected or fx.sha(CAND_BB), expected_kernel=fx.K7,
                               bootbin_guard=g, **kw)

    def call(self, cmd, *args, **env):
        lab = self.lab
        import subprocess
        r = subprocess.run([sys.executable, '-I', '-B', fx.TARGET, cmd, '--run-dir', lab.run_sys, *args],
                           capture_output=True, env=lab.env(**env), timeout=900)
        lines = r.stdout.decode(errors='replace').strip().splitlines()
        res = json.loads(lines[-1]) if lines else None
        return r.returncode, res, r

    def ok(self, cmd, *args, **env):
        code, res, r = self.call(cmd, *args, **env)
        self.assertEqual(code, 0, '%s failed: %s\n%s' % (cmd, res, r.stderr.decode()[-3000:]))
        self.assertTrue(res['ok'])
        return res

    def bad(self, cmd, want, *args, **env):
        code, res, r = self.call(cmd, *args, **env)
        self.assertEqual(code, want, '%s: want exit %d, got %d: %s\n%s' % (cmd, want, code, res, r.stderr.decode()[-3000:]))
        self.assertFalse(res['ok'])
        return res

    def bb(self, rel='m1n1/boot.bin'):
        return fx.rd(self.lab.R('/boot/efi/' + rel))

    def install(self):
        res = self.ok('install', BT2_FAKE_BOOTBIN_CHANGES=1)
        self.assertEqual(self.bb(), CAND_BB)
        return res


class InstallCheck(GuardBase):
    def test_exact_candidate_with_original_old_and_budget_passes(self):
        res = self.install()
        self.assertIs(res['bootbin_is_expected'], True)
        self.assertIs(res['bootbin_unchanged'], False)
        self.assertEqual(res['recovery_copy'], {'path': 'm1n1/boot.bin.old', 'sha256': fx.sha(ORIG_BB)})
        self.assertTrue(res['esp_budget']['ok'])
        self.assertEqual(res['esp_budget']['rule'], 'reserve+peak after install')
        self.assertEqual(self.bb('m1n1/boot.bin.old'), ORIG_BB)

    def test_other_candidate_bytes_are_restored_and_fail(self):
        self.write_config(expected=fx.sha(b'some other boot.bin'))
        res = self.bad('install', 4, BT2_FAKE_BOOTBIN_CHANGES=1)
        self.assertIn('boot.bin changed', res['error'])
        self.assertEqual(self.bb(), ORIG_BB)
        self.assertEqual(self.bb('m1n1/boot.bin.old'), OLD_BB)

    def test_old_that_is_not_the_original_is_restored_and_fails(self):
        res = self.bad('install', 4, BT2_FAKE_BOOTBIN_CHANGES=1, BT2_FAKE_BOOTBIN_OLD='not the original')
        self.assertIn('boot.bin changed', res['error'])
        self.assertEqual(self.bb(), ORIG_BB)
        self.assertEqual(self.bb('m1n1/boot.bin.old'), OLD_BB)

    def test_esp_budget_short_after_install_is_restored_and_fails(self):
        lab = self.lab
        peak = 8192
        grown = tcap.esp_usage(lab.R('/boot/efi')) - lab.state['esp']['usage']      # esp-prep's fallback copy
        # the install gate sees exactly reserve + peak; boot.bin.old then grows 1 -> 2 clusters during the install
        self.write_config(test_esp_free=125829120 + peak + grown, peak_bytes=peak)
        res = self.bad('install', 4, BT2_FAKE_BOOTBIN_CHANGES=1)
        # a failed install reports only its error (common.main); the budget is in it
        self.assertIn("ESP budget {'esp_free': %d, 'need': %d, 'rule': 'reserve+peak after install', 'ok': False}"
                      % (125829120 + peak - 4096, 125829120 + peak), res['error'])
        self.assertEqual(self.bb(), ORIG_BB)
        self.assertEqual(self.bb('m1n1/boot.bin.old'), OLD_BB)

    def test_without_allow_any_change_still_fails(self):
        self.lab.config(self.cands, self.origs, expected_kernel=fx.K7)        # the default path, unchanged
        res = self.bad('install', 4, BT2_FAKE_BOOTBIN_CHANGES=1)
        self.assertIn('boot.bin changed', res['error'])
        self.assertEqual(self.bb(), ORIG_BB)


class GuardCycle(GuardBase):
    def unit_text(self):
        return fx.rd(self.lab.R(ETC + '/' + self.unit)).decode()

    def receipts(self):
        d = self.lab.run + '/receipts'
        out = [json.loads(fx.rd(d + '/' + n)) for n in os.listdir(d) if n.startswith('bootbin-guard.')]
        return sorted(out, key=lambda r: r['_seq'] if '_seq' in r else 0)

    def test_full_cycle(self):
        lab = self.lab
        # before the install the guard refuses: boot.bin is still the original
        res = self.bad('bootbin-guard-install', 3)
        self.assertIn('not the installed candidate', res['refused_reason'])
        self.assertFalse(os.path.lexists(lab.R(ETC + '/' + self.unit)))
        self.install()
        res = self.ok('bootbin-guard-install')
        self.assertEqual(res['state'], {'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'enabled'})
        self.assertEqual(res['recovery_copy_sha256'], fx.sha(ORIG_BB))
        self.assertEqual(res['esp_identity']['partition_uuid'], PART)
        self.assertEqual(res['esp_identity']['fat_serial'], '4F4D-5801')
        self.assertEqual(os.readlink(lab.R(ETC + '/multi-user.target.wants/' + self.unit)), ETC + '/' + self.unit)
        pin = fx.sha(fx.rd(lab.run + '/config.json'))
        text = self.unit_text()
        self.assertIn('ExecStart=/usr/bin/python3 -I -B %s/t bootbin-guard --run-dir %s --config-sha256 %s --phase start'
                      % (lab.run_sys, lab.run_sys, pin), text)
        self.assertIn('--phase stop\n', text)
        self.assertIn('RequiresMountsFor=/boot/efi ' + lab.run_sys, text)
        self.assertTrue(self.ok('bootbin-guard-install')['already_done'])
        # candidate boot: the start hook keeps the candidate (labd's identity reads it in every phase)
        res = self.ok('bootbin-guard', '--phase', 'start', BT2_TEST_UNAME_R=fx.K7)
        self.assertEqual(res['action'], 'keep-candidate-boot')
        self.assertEqual(self.bb(), CAND_BB)
        # its orderly shutdown: the stop hook puts the original back
        res = self.ok('bootbin-guard', '--phase', 'stop', BT2_TEST_UNAME_R=fx.K7)
        self.assertEqual((res['action'], res['bootbin_before'], res['bootbin_after']),
                         ('restored', fx.sha(CAND_BB), fx.sha(ORIG_BB)))
        self.assertEqual(self.bb(), ORIG_BB)
        # known-good return boot: nothing left to do
        self.assertEqual(self.ok('bootbin-guard', '--phase', 'start')['action'], 'original-already')
        st = self.ok('bootbin-guard-status')
        self.assertTrue(st['is_original'])
        self.assertEqual([r['action'] for r in st['receipts']], ['keep-candidate-boot', 'restored', 'original-already'])
        self.assertEqual(st['recovery_copy_sha256'], fx.sha(ORIG_BB))
        # remove: back to no unit at all
        res = self.ok('bootbin-guard-remove')
        self.assertEqual(res['state']['LoadState'], 'not-found')
        self.assertFalse(os.path.lexists(lab.R(ETC + '/' + self.unit)))
        self.assertFalse(os.path.lexists(lab.R(ETC + '/multi-user.target.wants/' + self.unit)))
        self.assertEqual(self.ok('bootbin-guard-remove')['removed'], [])
        # the rest of the way back is unchanged: rollback + esp-restore leave boot.bin and .old exactly as captured
        self.ok('rollback')
        self.ok('esp-restore')
        self.assertEqual((self.bb(), self.bb('m1n1/boot.bin.old')), (ORIG_BB, OLD_BB))

    def test_a_later_non_candidate_boot_restores_when_the_stop_hook_never_ran(self):
        self.install()
        self.ok('bootbin-guard-install')
        res = self.ok('bootbin-guard', '--phase', 'start')          # known-good kernel, candidate still on the ESP
        self.assertEqual(res['action'], 'restored')
        self.assertEqual(self.bb(), ORIG_BB)

    def test_unexpected_bytes_are_left_alone_and_block_removal(self):
        lab = self.lab
        self.install()
        self.ok('bootbin-guard-install')
        fx.wr(lab.R('/boot/efi/m1n1/boot.bin'), b'someone else wrote this')
        res = self.ok('bootbin-guard', '--phase', 'stop', BT2_TEST_UNAME_R=fx.K7)
        self.assertEqual(res['action'], 'unexpected-left-alone')
        self.assertEqual(self.bb(), b'someone else wrote this')
        st = self.ok('bootbin-guard-status')
        self.assertFalse(st['is_original'])
        res = self.bad('bootbin-guard-remove', 3)
        self.assertIn('neither restored nor the original', res['refused_reason'])
        self.assertTrue(os.path.lexists(lab.R(ETC + '/' + self.unit)), 'unit kept for a person')

    def test_remove_restores_a_candidate_left_on_the_esp(self):
        self.install()
        self.ok('bootbin-guard-install')
        res = self.ok('bootbin-guard-remove')
        self.assertEqual(res['cas']['action'], 'restored')
        self.assertEqual(self.bb(), ORIG_BB)

    def test_remove_refuses_a_unit_file_bt2_did_not_write(self):
        lab = self.lab
        self.install()
        self.ok('bootbin-guard-install')
        fx.wr(lab.R(ETC + '/' + self.unit), b'[Service]\nExecStart=/bin/true\n')
        res = self.bad('bootbin-guard-remove', 4)                   # the CAS restore already changed boot.bin
        self.assertIn('not the one bt2 wrote', res['error'])
        self.assertTrue(os.path.lexists(lab.R(ETC + '/' + self.unit)))

    def test_guard_config_must_match_the_run(self):
        g = dict(self.lab.cfg['bootbin_guard'], recovery_copy='m1n1/boot.bin.elsewhere')
        self.lab.config(self.cands, self.origs, allow_bootbin_change=True, expected_bootbin_sha256=fx.sha(CAND_BB),
                        expected_kernel=fx.K7, bootbin_guard=g)
        self.install()
        res = self.bad('bootbin-guard-install', 3)
        self.assertIn('Recovery copy must be', res['refused_reason'])


if __name__ == '__main__':
    unittest.main()
