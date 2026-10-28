"""bt2 end-to-end integration test: capture/espops/audit (I1) + pkg/writers (I2) + the controller's order (I3) on ONE
fake Mac per scenario.

Run: cd /dev/shm/claude-229/bt2 && python3.14 -B -m unittest -v tests.test_e2e
Fake roots: /dev/shm/maclab-bt2-tests/e2e-*/root (BT2_KEEP=1 keeps them). Every target command runs as the
controller runs it: python3 -I -B <target> <cmd> --run-dir /var/lib/maclab/bt2/<run> --config-sha256 <sha> [...].

Sequence (bt2/controller.py run): preflight -> [snapshot] -> capture -> hold-writers -> esp-prep -> install -> job
(reboot into the candidate and back) -> locks-after-job -> rollback -> esp-restore -> etc-restore -> ordinary reboot
(nothing recreated in /run/lock) -> audit --held -> release-writers -> audit -> cleanup -> [snapshot, compare].
The failure path (C) follows `bt2 restore` after a failed install: rollback -> esp-restore -> etc-restore -> reboot
-> audit --held -> release-writers -> audit -> cleanup.
Every scenario ends with an ok final audit and a byte-level comparison of the whole fake root against the snapshot
taken right before capture (bytes, modes, owners, symlink targets; mtimes where the SPEC promises restoration: every
ESP manifest file, the /etc capture set incl. its dirs, the conflict files). Excluded: /proc, /run, the run dir,
/usr/lib/modules/.old, ESP ubootefi.var* and maclab/, /.fake (fake systemd/pacman state: unit states are compared
through `systemctl show` instead). ESP entries are compared without mode/uid/gid (FAT: mount options, not state).
Scenarios: A M1-like full run; A2 M1-like without kernel-modules-hook (install restores the running tree from
capture's tar); B M3-like full run; C M1-like boot-phase pacman failure + restore; C2 M3-like failure of the ABSENT
boot package (rollback must stop on unowned partial payload, then an operator-reviewed retry restores exactly).
"""
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fx_e2e'))
import mac as fm  # noqa: E402

ETC = '/etc/systemd/system'
ALIAS = 'limine-snapper-watcher.service'
UNITS = ['limine-snapper-sync.service', ALIAS, 'snapper-timeline.timer', 'snapper-cleanup.timer',
         'snapper-cleanup.service', 'snapper-timeline.service', 'linux-modules-cleanup.service',
         'omarchy-mac-efi-vars.service', 'omarchy-vendor-firmware.service']


class E2E(unittest.TestCase):
    mac = None

    def tearDown(self):
        if self.mac is not None:
            self.mac.cleanup()

    # -- helpers ----------------------------------------------------------------------------------------
    def step(self, cmd, *extra, want=0, **env):
        code, res, r = self.mac.target(cmd, *extra, **env)
        self.assertEqual(code, want, '%s %s: exit %d (want %d): %s\nstderr: %s'
                         % (cmd, ' '.join(extra), code, want, json.dumps(res, sort_keys=True)[:6000],
                            r.stderr.decode(errors='replace')[-3000:]))
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get('schema'), 'bt2.target-result/1')
        self.assertEqual(res.get('cmd'), cmd)
        self.assertEqual(res.get('ok'), want == 0, res)
        if want == 0:
            self.assertEqual(res['run_id'], self.mac.run_id)
            self.assertEqual(res['config_sha256'], self.mac.cfg_sha)
        rd = self.mac.run + '/receipts'
        self.assertTrue(any(f.startswith(cmd + '.') for f in os.listdir(rd)), 'no receipt for ' + cmd)
        return res

    def installer_path(self, inst):
        """The installer entry's own path: line (what labd freezes and the agent stages verbatim)."""
        raw = fm.rd(self.mac.R('/boot/efi/limine.conf'))
        e = fm.fxp.limine.Menu(raw).find(inst['candidate']['entry_name'])
        self.assertIsNotNone(e, inst['candidate'])
        return e.path()

    def units_now(self):
        return {u: {k: v for k, v in self.mac.show(u).items() if k != 'SubState'} for u in UNITS}

    def begin(self):
        """Controller: fetch is simulated by Mac.configure(); preflight; snapshot right before capture; capture."""
        mac = self.mac
        pf = self.step('preflight')
        self.assertEqual(pf['facts']['problems'], [])
        self.assertFalse(pf['changed'])
        self.before = mac.snapshot()
        self.before_units = self.units_now()
        self.before_versions = mac.versions()
        cap = self.step('capture')
        self.assertFalse(cap['changed'])
        self.st = mac.state()
        self.assertEqual(cap['capture_sha256'], fm.sha(fm.rd(mac.run + '/capture/state.json')))
        self.assertEqual(mac.snapshot(), self.before, 'capture must not change the system')
        hold = self.step('hold-writers')
        w = hold['writers']
        self.assertEqual(sorted(m['unit'] for m in w['masks']), sorted(mac.cfg['writer_units']))
        self.assertEqual([a['unit'] for a in w['aliases']], [ALIAS])
        self.assertEqual(sorted(w['was_active']), ['limine-snapper-sync.service', 'snapper-cleanup.timer'])
        return cap

    def finish(self, expect_old):
        """Ordinary reboot (tmpfs locks gone, nothing recreated) -> audit --held -> release -> audit -> cleanup."""
        mac = self.mac
        boot_before = mac.boot_id
        mac.reboot(mac.krel)
        self.assertNotEqual(mac.boot_id, boot_before)
        self.assertEqual(os.listdir(mac.R('/run/lock')), [], 'tmpfs /run/lock wiped by the reboot')
        self.assertEqual(sorted(e[1] for e in mac.events if e[0] == 'modules-cleanup'), sorted(expect_old))
        held = self.step('audit', '--held')
        self.assertEqual(held['mode'], 'held')
        self.assertEqual(held['differences'], [])
        rel = self.step('release-writers')
        self.assertEqual(sorted(rel['started']), ['limine-snapper-sync.service', 'snapper-cleanup.timer'])
        self.assertTrue(rel['proof']['equal_to_capture'])
        final = self.step('audit')
        self.assertEqual(final['mode'], 'final')
        self.assertEqual(final['differences'], [])
        info = {i['item'] for i in final['informational']}
        self.assertIn('modules_old_dir', info)
        cl = self.step('cleanup')
        self.assertEqual(sorted(cl['removed']), ['hold', 'originals', 'pkgs'], cl)
        self.assertEqual(cl['hold_unknown'], [])
        for d in ('pkgs', 'originals', 'hold'):
            self.assertFalse(os.path.lexists(mac.run + '/' + d), d)
        self.assertTrue(os.path.isfile(mac.run + '/capture/state.json'))
        # -- whole-root comparison against the snapshot taken right before capture
        after = mac.snapshot()
        diffs = mac.compare(self.before, after, mac.promised_mtimes(self.st, self.before))
        # the per-boot seed (systemd-boot-random-seed.service) is the one ESP file a reboot itself rewrites:
        # content/mtime only, and only when the fixture actually refreshed it on a reboot
        seed = [x for x in diffs if x['path'] == '/boot/efi/loader/random-seed']
        if seed:
            self.assertTrue([e for e in mac.events if e[0] == 'random-seed-refreshed'])
            self.assertTrue(set(seed[0]['fields']) <= {'sha256', 'mtime_ns'}, seed)
            diffs = [x for x in diffs if x not in seed]
        self.assertEqual(diffs, [], 'fake root differs from the pre-capture snapshot:\n' +
                         json.dumps(diffs, indent=1, sort_keys=True)[:8000])
        self.assertEqual(mac.versions(), self.before_versions)
        self.assertEqual(self.units_now(), self.before_units)
        # systemd's view of /etc/systemd/system: alias re-linked with its original inode
        se = self.st['systemd_etc']
        self.assertEqual(os.lstat(mac.R(ETC + '/' + ALIAS)).st_ino, se[ALIAS]['ino'])
        # bt2 left nothing behind outside its run dir
        mods = os.listdir(mac.R('/usr/lib/modules'))
        self.assertFalse([m for m in mods if m.startswith('.bt2')], mods)
        self.assertFalse(os.path.lexists(mac.R('/var/lib/pacman/db.lck')))
        return final

    # -- A: M1-like -------------------------------------------------------------------------------------
    def test_a_m1_full_run(self):
        mac = self.mac = fm.m1_mac('m1')
        cap = self.begin()
        st = self.st
        run8 = st['run8']
        d = st['menu']['default']
        self.assertEqual((d['name'], d['path']), ('Omarchy/linux-aurora', 'EFI/Linux/omarchy_linux-aurora.efi'))
        self.assertTrue(d['auto_entry'])
        self.assertEqual(st['running_kernel']['copy'], 'capture/modules/%s.tar' % fm.K6)
        self.assertEqual(st['running_kernel']['owned_by'], ['linux-aurora', 'linux-aurora-headers'])
        self.assertEqual(cap['conflicts'], [])
        self.assertIn('/etc/default/update-m1n1.pacnew', st['etc'])
        # limine-snapper-sync rewrote limine.conf with identical bytes after the capture (seen on the M1):
        # not drift; esp-restore later puts the captured mtime back
        mp = mac.R('/boot/efi/limine.conf')
        mb = fm.rd(mp)
        os.unlink(mp)
        mac.wr('/boot/efi/limine.conf', mb)
        self.assertNotEqual(os.lstat(mp).st_mtime_ns, st['esp']['files']['limine.conf']['mtime_ns'])
        prep = self.step('esp-prep')
        self.assertTrue(prep['changed'])
        self.assertEqual([p['path'] for p in prep['parked']], ['EFI/Linux/siliconforest-normal-205f5e8b20fc.efi'])
        self.assertEqual(prep['fallback']['path'], 'EFI/Linux/bt2-%s-original.efi' % run8)
        self.assertEqual(prep['default_after']['name'], 'bt2 original %s' % run8)
        menu = fm.rd(mac.R('/boot/efi/limine.conf')).decode()
        self.assertNotIn('/SiliconForest - kernel 177+182', menu)
        self.assertIn('default_entry: bt2 original %s' % run8, menu)
        inst = self.step('install')
        self.assertEqual([p['tag'] for p in inst['phases']], ['main', 'boot'])
        self.assertEqual(inst['candidate']['krel'], fm.K7)
        self.assertEqual(inst['candidate']['entry_name'], 'Omarchy/linux-aurora')
        self.assertTrue(inst['candidate']['pin_ok'])
        self.assertEqual(inst['default_entry']['mode'], 'fallback')
        self.assertEqual(inst['running_tree']['status'], 'exact')
        self.assertTrue(inst['marker']['created'])
        self.assertTrue(inst['bootbin_unchanged'])
        self.assertTrue(os.path.lexists(mac.R('/etc/default/update-m1n1.pacnew')))
        # both phase gates measured the tight ESP that esp-prep planned for (reserve + PEAK after parking)
        self.assertEqual(prep['peak'], -(-len(mac.uki) // 4096) * 4096 + (4 << 20))
        self.assertEqual(prep['peak_basis']['source'], 'measured')
        floor = mac.cfg['esp_reserve_bytes'] + prep['peak']
        self.assertLess(prep['esp_free_before'], prep['need_bytes'])
        for tag in ('main', 'boot'):
            with open(mac.run + '/install/%s.0.intent.json' % tag) as f:
                g = json.load(f)['gates']['esp_free']
            self.assertGreaterEqual(g, floor, tag)
            self.assertLessEqual(abs(g - prep['esp_free_after']), 2 * 4096, (tag, g, prep['esp_free_after']))
        # the labd job: candidate boot and back; K6 survives the candidate boot thanks to the owned marker
        mac.job(fm.K7, installer_path=self.installer_path(inst))
        self.assertEqual([e for e in mac.events if e[0] == 'modules-cleanup'], [])
        mac.controller_locks()
        rb = self.step('rollback')
        self.assertEqual([(p['tag'], p['op']) for p in rb['phases']], [('boot', 'U'), ('rest-u', 'U')])
        self.assertTrue(rb['tree']['held'] and rb['tree']['hold_deleted'] and rb['tree']['exact'])
        self.assertTrue(rb['marker']['removed'])
        self.assertEqual(rb['leftover_candidate_module_dirs'], [fm.K7])
        er = self.step('esp-restore')
        self.assertIn('EFI/Linux/bt2-%s-original.efi' % run8,
                      [os.path.relpath(x['from'], mac.R('/boot/efi')) for x in er['moved_extras']])
        self.assertIn('EFI/Linux/siliconforest-normal-205f5e8b20fc.efi', er['rewritten'])
        self.assertTrue(er['menu_restored'])
        # the job's reboots refreshed loader/random-seed; esp-restore must not copy the old seed back
        self.assertTrue([e for e in mac.events if e[0] == 'random-seed-refreshed'])
        self.assertNotIn('loader/random-seed', er['rewritten'])
        xr = self.step('etc-restore')
        self.assertIn('/etc/default/update-m1n1.pacnew', [x['path'] for x in xr['moved_extras']])
        final = self.finish(expect_old=[fm.K7])
        info = {i['item'] for i in final['informational']}
        self.assertIn('esp_excluded_changed', info, 'ubootefi.var/maclab changes are reported, not compared')
        self.assertIn('esp_boot_refreshed', info, 'per-boot random seed is reported, not compared')
        # the package-owned unit file was rewritten by pacman twice: same bytes/meta, new inode (reported)
        self.assertIn(('systemd_etc_inode_replaced', ETC + '/omarchy-vendor-firmware.service'),
                      {(i['item'], i['path']) for i in final['informational']})
        # negative controls (audit is read-only and may run again after cleanup):
        # 1. an entry nothing in bt2 rewrote keeps its inode requirement
        wl = mac.R(ETC + '/multi-user.target.wants/limine-snapper-sync.service')
        st_l, st_d = os.lstat(wl), os.lstat(os.path.dirname(wl))
        tgt = os.readlink(wl)
        os.rename(wl, mac.base + '/orig-wants-link')
        os.symlink(tgt, wl)
        os.utime(wl, ns=(st_l.st_atime_ns, st_l.st_mtime_ns), follow_symlinks=False)
        bad = self.step('audit', want=3)
        self.assertIn('systemd_etc', bad['refused_reason'])
        self.assertIn('multi-user.target.wants/limine-snapper-sync.service', bad['refused_reason'])
        os.unlink(wl)
        os.rename(mac.base + '/orig-wants-link', wl)
        os.utime(os.path.dirname(wl), ns=(st_d.st_atime_ns, st_d.st_mtime_ns))
        # 2. a package-owned unit file with a flipped byte (same size and mtime) is still a difference
        vf = mac.R(ETC + '/omarchy-vendor-firmware.service')
        st_v, data = os.lstat(vf), fm.rd(vf)
        with open(vf, 'r+b') as f:
            f.write(bytes([data[0] ^ 1]))
        os.utime(vf, ns=(st_v.st_atime_ns, st_v.st_mtime_ns))
        bad = self.step('audit', want=3)
        self.assertIn('omarchy-vendor-firmware.service', bad['refused_reason'])
        with open(vf, 'r+b') as f:
            f.write(data[:1])
        os.utime(vf, ns=(st_v.st_atime_ns, st_v.st_mtime_ns))
        self.step('audit')
        # 3. the per-boot seed exemption covers content only: a different size is still a difference
        sp = mac.R('/boot/efi/loader/random-seed')
        seed = fm.rd(sp)
        with open(sp, 'wb') as f:
            f.write(seed[:16])
        bad = self.step('audit', want=3)
        self.assertIn('loader/random-seed', bad['refused_reason'])
        with open(sp, 'wb') as f:
            f.write(seed)
        self.step('audit')

    # -- B: M3-like -------------------------------------------------------------------------------------
    def test_b_m3_full_run(self):
        mac = self.mac = fm.m3_mac('m3')
        cap = self.begin()
        st = self.st
        d = st['menu']['default']
        self.assertEqual(d['name'], 'Omacom Edge - aurora6 M3 GPU')
        self.assertFalse(d['auto_entry'])
        self.assertIsNone(st['running_kernel']['copy'])
        self.assertTrue(st['modules'][fm.KM3]['keep_marker'])
        self.assertIsNone(st['packages']['omarchy-mac-boot']['version'])
        conflicts = sorted(cf['path'] for cf in cap['conflicts'])
        self.assertEqual(conflicts, ['/etc/default/update-m1n1', '/etc/initcpio/install/omarchy-vendorfw',
                                     '/etc/systemd/system/omarchy-vendor-firmware.service'])
        inos = {p: os.lstat(mac.R(p)).st_ino for p in conflicts}
        prep = self.step('esp-prep')
        self.assertFalse(prep['changed'])
        self.assertIsNone(prep['fallback'])
        self.assertEqual(prep['parked'], [])
        inst = self.step('install')
        self.assertEqual([p['tag'] for p in inst['phases']], ['main', 'boot'])
        self.assertEqual(sorted(inst['conflicts_held']), conflicts)
        self.assertEqual(inst['default_entry']['mode'], 'custom')
        self.assertEqual(inst['candidate']['entry_name'], 'SiliconForest Linux/linux-aurora')
        self.assertTrue(inst['marker'].get('preexisting'))
        self.assertEqual(inst['units_started'], ['omarchy-mac-efi-vars.service'])
        self.assertIn('EFI/Linux/omarchy_linux-m3-eryk.efi', [f['path'] for f in inst['esp_new_files']])
        self.assertIn('SiliconForest Linux/linux-m3-eryk', inst['menu_entries_new'])
        mac.job(fm.K7, installer_path=self.installer_path(inst))
        # aurora6's depmod residue is unowned once 7-1 replaced it: cleanup moved it during the candidate boot
        self.assertEqual([e[1] for e in mac.events if e[0] == 'modules-cleanup'], [fm.K6])
        mac.controller_locks()
        rb = self.step('rollback')
        self.assertEqual([(p['tag'], p['op']) for p in rb['phases']], [('boot', 'R'), ('rest-u', 'U')])
        self.assertFalse(rb['tree']['held'])
        self.assertEqual(sorted(rb['conflicts_reinstated']), conflicts)
        for p in conflicts:
            self.assertEqual(os.lstat(mac.R(p)).st_ino, inos[p], 'conflict reinstated by rename: ' + p)
        self.assertIsNone(mac.versions().get('omarchy-mac-boot'))
        er = self.step('esp-restore')
        self.assertIn('EFI/Linux/omarchy_linux-m3-eryk.efi',
                      [os.path.relpath(x['from'], mac.R('/boot/efi')) for x in er['moved_extras']])
        self.step('etc-restore')
        self.finish(expect_old=[fm.K6, fm.K7])
        self.assertTrue(os.path.isfile(mac.R('/usr/lib/modules/%s/.keep-local-kernel' % fm.KM3)))

    # -- A2: M1-like without kernel-modules-hook: install restores the running tree from capture's tar --------
    def test_a2_m1_tree_restored_from_capture_copy(self):
        mac = self.mac = fm.m1_mac('nokmod')
        self.begin()
        self.step('esp-prep')
        inst = self.step('install', BT2_FAKE_NO_KMOD=1)
        self.assertEqual(inst['running_tree']['status'], 'restored', inst['running_tree'])
        self.assertTrue(inst['marker']['created'])
        mac.job(fm.K7, installer_path=self.installer_path(inst))
        self.assertEqual([e for e in mac.events if e[0] == 'modules-cleanup'], [])
        mac.controller_locks()
        rb = self.step('rollback', BT2_FAKE_NO_KMOD=1)
        self.assertTrue(rb['tree']['held'] and rb['tree']['hold_deleted'] and rb['tree']['exact'])
        self.step('esp-restore')
        self.step('etc-restore')
        self.finish(expect_old=[fm.K7])

    # -- A3: fresh baseline: the base job (installed original) reboots the Mac between capture and esp-prep ------
    def test_a3_m1_base_job_reboots_before_esp_prep(self):
        mac = self.mac = fm.m1_mac('base')
        self.begin()
        st = self.st
        seed0 = fm.rd(mac.R('/boot/efi/loader/random-seed'))
        menu0 = fm.rd(mac.R('/boot/efi/limine.conf'))
        boot0 = mac.boot_id
        # labd installed-mode job of the ORIGINAL cohort: the installer entry is the K6 package UKI; it boots and
        # returns to the default; the agent's block cleanup rewrites limine.conf (same bytes, new mtime)
        mac.job(fm.K6, job_id='4710', installer_path=self.installer_path({'candidate': {'entry_name':
                                                                                         'Omarchy/linux-aurora'}}))
        self.assertNotEqual(mac.boot_id, boot0)
        self.assertNotEqual(fm.rd(mac.R('/boot/efi/loader/random-seed')), seed0)
        self.assertEqual(fm.rd(mac.R('/boot/efi/limine.conf')), menu0)
        self.assertNotEqual(os.lstat(mac.R('/boot/efi/limine.conf')).st_mtime_ns,
                            st['esp']['files']['limine.conf']['mtime_ns'])
        self.assertEqual([e for e in mac.events if e[0] == 'modules-cleanup'], [], 'K6 is owned before the install')
        mac.controller_locks()                       # base-locks: the reboot wiped /run/lock
        prep = self.step('esp-prep')                 # neither the new seed nor the rewritten menu is drift
        self.assertTrue(prep['changed'])
        inst = self.step('install')
        mac.job(fm.K7, installer_path=self.installer_path(inst))
        mac.controller_locks()
        self.step('rollback')
        self.step('esp-restore')
        self.step('etc-restore')
        final = self.finish(expect_old=[fm.K7])
        self.assertIn('esp_boot_refreshed', {i['item'] for i in final['informational']})

    # -- C: failure in the install's boot phase, then `bt2 restore` --------------------------------------
    def test_c_boot_phase_failure_restore(self):
        mac = self.mac = fm.m1_mac('fail')
        self.begin()
        self.step('esp-prep')
        res = self.step('install', want=4, BT2_FAKE_FAIL_PKG='omarchy-mac-boot')
        self.assertIn('boot: pacman FAILED', res['error'])
        with open(mac.run + '/install/boot.0.outcome.json') as f:
            out = json.load(f)
        self.assertEqual((out['outcome'], out['exit_code'], out['group_drained']), ('FAILED', 1, True))
        v = mac.versions()
        self.assertEqual(v['linux-aurora'], '7.2.11.aurora7-1', 'main phase completed before the failure')
        self.assertEqual(v['omarchy-mac-boot'], '20261010-1', 'DB untouched by the failed transaction')
        self.assertNotEqual(fm.rd(mac.R('/usr/bin/update-m1n1')), b'#!/bin/sh\n# update-m1n1 old\n',
                            'the failed transaction left partial payload')
        self.step('install', want=3)        # never retried automatically
        # bt2 restore: the Mac is still on the known-good untagged boot -> locks, inverses, reboot, audits
        mac.controller_locks()
        rb = self.step('rollback')
        self.assertEqual([(p['tag'], p['op']) for p in rb['phases']], [('boot', 'U'), ('rest-u', 'U')])
        self.assertEqual(fm.rd(mac.R('/usr/bin/update-m1n1')), b'#!/bin/sh\n# update-m1n1 old\n')
        self.assertTrue(rb['tree']['hold_deleted'])
        self.step('esp-restore')
        self.step('etc-restore')
        self.finish(expect_old=[fm.K7])

    # -- C2: M3-like, the ABSENT boot package dies mid-extraction: no DB entry, unowned partial payload --------
    def test_c2_m3_absent_boot_package_dies_mid_install(self):
        mac = self.mac = fm.m3_mac('m3fail')
        cap = self.begin()
        conflicts = sorted(cf['path'] for cf in cap['conflicts'])
        self.step('esp-prep')
        res = self.step('install', want=4, BT2_FAKE_FAIL_PKG='omarchy-mac-boot')
        self.assertIn('boot: pacman FAILED', res['error'])
        self.assertIsNone(mac.versions().get('omarchy-mac-boot'), 'not registered: -R cannot remove its files')
        residue = '/usr/bin/omarchy-vendorfw.sh'
        self.assertTrue(os.path.lexists(mac.R(residue)), 'the dead transaction wrote payload')
        mac.controller_locks()
        # bt2 restore: rollback does all it can, then refuses to call the rollback exact (stop, record, report)
        rb = self.step('rollback', want=4)
        self.assertIn(residue, rb['error'])
        self.assertTrue(os.path.lexists(mac.R(residue)), 'nothing is deleted by bt2')
        self.assertEqual(mac.versions(), self.before_versions)
        for p in conflicts:
            want = [c for c in self.st['conflicts'] if c['path'] == p][0]
            self.assertEqual(fm.sha(fm.rd(mac.R(p))), want['sha256'], 'conflict reinstated: ' + p)
        # operator review moves the residue off the system, then `bt2 restore --retry rollback`
        os.rename(mac.R(residue), mac.base + '/reviewed-' + os.path.basename(residue))
        rb2 = self.step('rollback')
        self.assertEqual(rb2['partial_residue'], [])
        self.assertEqual(rb2['unrecoverable_partial'], ['omarchy-mac-boot'])
        # the dead transaction's files at the three conflict paths were displaced (by attempt 1) and are named in
        # this receipt, so cleanup can remove hold/ after the final audit
        self.assertEqual(len(rb2['conflicts_displaced']), len(conflicts))
        self.step('esp-restore')
        self.step('etc-restore')
        self.finish(expect_old=[fm.K7])


if __name__ == '__main__':
    unittest.main()
