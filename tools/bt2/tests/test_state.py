"""bt2 target tests: capture, esp-prep, esp-restore, etc-restore, audit (--held/final), cleanup.

Run:  cd /dev/shm/claude-229/bt2 && python3.14 -m unittest tests.test_state -v
Each test builds a fake root under /dev/shm/maclab-bt2-tests (never /tmp) and drives the real target
package through subprocess exactly like the controller does:
  python -I -B target <cmd> --run-dir /var/lib/maclab/bt2/<run>   (BT2_TEST_ROOT/BIN/UNAME_R set)
Set BT2_KEEP=1 to keep fixtures for inspection.
"""
import json
import os
import re
import sys
import tarfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'fx_state'))
sys.path.insert(0, os.environ.get('BT2_TARGET') or os.path.join(os.path.dirname(HERE), 'target'))
import builder as B  # noqa: E402
import limine  # noqa: E402  (target's own menu model, stdlib only; used to inspect results)

RUN8 = B.sha(B.RUN_ID.encode())[:8]
KREL6 = '7.2.11-6-1-ARCH'
HEX64 = re.compile(r'[0-9a-f]{64}$')


def check_schema(t, st):
    """CONTRACT.md capture/state.json (bt2.capture/1) shape."""
    for k, typ in [('schema', str), ('run_id', str), ('device', str), ('boot_id', str), ('kernel', str),
                   ('board', str), ('captured_at', float), ('packages_all', dict), ('packages', dict),
                   ('backup_files', list), ('modules', dict), ('running_kernel', dict), ('esp', dict),
                   ('menu', dict), ('bootbin_sha256', str), ('etc', dict), ('units', dict), ('systemd_etc', dict),
                   ('efivars', dict), ('snapshots', list), ('limine_history', dict), ('conflicts', list),
                   ('known_good_refs', dict), ('originals_verified', dict), ('copies', dict)]:
        t.assertIsInstance(st.get(k), typ, k)
    t.assertEqual(st['schema'], 'bt2.capture/1')
    for n, p in st['packages'].items():
        t.assertEqual(set(p), {'version', 'mtree_sha256', 'files'}, n)
        if p['version'] is not None:
            t.assertRegex(p['mtree_sha256'], HEX64)
            t.assertTrue(all(f.startswith('/') for f in p['files']))
    for k, m in st['modules'].items():
        t.assertTrue({'owned_by', 'keep_marker', 'tree_sha256', 'entries'} <= set(m), k)
    t.assertEqual(set(st['running_kernel']) >= {'krel', 'owned_by', 'copy'}, True)
    e = st['esp']
    t.assertEqual(e['excluded'], ['ubootefi.var*', 'maclab/'])
    for k in ('root', 'free', 'files', 'dirs', 'info'):
        t.assertIn(k, e)
    for rel, f in e['files'].items():
        t.assertEqual(set(f), {'size', 'sha256', 'mtime_ns'}, rel)
    t.assertIn('ubootefi.var', e['info'])
    d = st['menu']['default']
    for k in ('name', 'path', 'uki_sha256', 'uki_b2', 'cmdline', 'auto_entry'):
        t.assertIn(k, d)
    t.assertRegex(st['menu']['sha256'], HEX64)
    for p, x in st['etc'].items():
        t.assertTrue(p.startswith('/'))
        t.assertEqual(set(x), {'type', 'mode', 'uid', 'gid', 'size', 'sha256', 'mtime_ns', 'target'}, p)
        t.assertIn(x['type'], ('f', 'd', 'l', 'absent'))
    for u, x in st['units'].items():
        t.assertEqual(set(x), {'LoadState', 'ActiveState', 'UnitFileState', 'FragmentPath', 'DropInPaths'}, u)
    for rel, x in st['systemd_etc'].items():
        t.assertEqual(set(x), {'type', 'target', 'ino'}, rel)
    t.assertEqual(set(st['efivars']), {'LoaderEntryOneShot', 'LoaderEntryDefault'})
    for x in st['conflicts']:
        t.assertTrue({'path', 'package', 'sha256', 'mode', 'uid', 'gid', 'mtime_ns'} <= set(x))
    t.assertEqual(st['copies'], {'esp': 'capture/esp', 'etc': 'capture/etc'})


class Base(unittest.TestCase):
    profile = 'm1'

    def setUp(self):
        self.fx = B.Fixture(self.profile)

    def tearDown(self):
        if not os.environ.get('BT2_KEEP'):
            self.fx.close()

    def call(self, cmd, *extra, rc=0):
        got, out = self.fx.run(cmd, *extra)
        self.assertEqual(got, rc, '%s rc=%d want %d: %s' % (cmd, got, rc, json.dumps(out)[:6000]))
        self.assertEqual(out.get('ok'), rc == 0, out)
        if rc == 3:
            self.assertFalse(out['changed'])
        return out

    def esp(self, rel):
        return self.fx.read('/boot/efi/' + rel)

    def menu(self):
        return self.esp('limine.conf')


class TestCaptureM1(Base):
    def test_capture_schema_copies_and_no_system_change(self):
        before = self.fx.snapshot_tree()
        out = self.call('capture')
        self.assertFalse(out['changed'])
        self.assertEqual(before, self.fx.snapshot_tree(), 'capture changed the system')
        st = self.fx.state()
        check_schema(self, st)
        raw = B.rd(self.fx.run_dir + '/capture/state.json')
        self.assertEqual(out['capture_sha256'], B.sha(raw))
        self.assertTrue(os.path.exists(self.fx.run_dir + '/receipts/capture.0.json'))
        # ESP: every manifest file byte-copied; exclusions honoured
        files = st['esp']['files']
        self.assertIn('limine.conf', files)
        self.assertNotIn('ubootefi.var', files)
        self.assertFalse(any(r.startswith('maclab/') for r in files))
        self.assertEqual(st['esp']['info']['ubootefi.var'], B.sha(self.esp('ubootefi.var')))
        for rel, f in files.items():
            live, copy = self.esp(rel), B.rd(self.fx.run_dir + '/capture/esp/' + rel)
            self.assertEqual(B.sha(live), f['sha256'], rel)
            self.assertEqual(copy, live, rel)
            self.assertEqual(os.lstat(self.fx.P('/boot/efi/' + rel)).st_mtime_ns, f['mtime_ns'])
        self.assertEqual(st['bootbin_sha256'], B.sha(self.esp('m1n1/boot.bin')))
        # menu/default
        d = st['menu']['default']
        self.assertEqual(d['name'], 'Omarchy/linux-aurora')
        self.assertEqual(d['path'], 'EFI/Linux/omarchy_linux-aurora.efi')
        self.assertTrue(d['auto_entry'])
        self.assertTrue(d['owned_by_package_uki'])
        self.assertEqual(d['uki_b2'], B.b2(self.fx.uki))
        # /etc capture set (explicit, dirs recursive, backup= + siblings, absent entries)
        etc = st['etc']
        self.assertEqual(etc['/etc/pacman.conf']['type'], 'f')
        self.assertEqual(etc['/etc/limine-entry-tool.d']['type'], 'absent')
        self.assertEqual(etc['/etc/m1n1.conf']['type'], 'absent')
        self.assertEqual(etc['/etc/default/update-m1n1.pacnew']['type'], 'absent')
        self.assertEqual(etc['/etc/default/update-m1n1.pacsave']['type'], 'absent')
        self.assertEqual(etc['/etc/mkinitcpio.conf.d/90-omarchy-mac.conf']['type'], 'f')
        self.assertEqual(etc['/etc/systemd/system/limine-snapper-watcher.service'],
                         {**etc['/etc/systemd/system/limine-snapper-watcher.service'], 'type': 'l',
                          'target': '/usr/lib/systemd/system/limine-snapper-sync.service'})
        self.assertEqual(etc['/etc/default']['type'], 'd')
        self.assertIn('/etc/default/update-m1n1', st['backup_files'])
        for p, x in etc.items():
            if x['type'] == 'f':
                self.assertEqual(B.rd(self.fx.run_dir + '/capture/etc' + p), self.fx.read(p), p)
        # module trees: running (package-owned -> tar copy), candidate krel absent
        rk = st['running_kernel']
        self.assertEqual(rk['krel'], KREL6)
        self.assertEqual(rk['owned_by'], ['linux-aurora'])
        self.assertEqual(rk['copy'], 'capture/modules/%s.tar' % KREL6)
        self.assertFalse(st['modules']['7.2.11-7-1-ARCH']['present'])
        self.assertTrue(st['modules'][KREL6]['present'])
        with tarfile.open(self.fx.run_dir + '/' + rk['copy']) as t:
            names = set()
            for m in t:
                names.add(m.name)
                self.assertEqual((m.uname, m.gname), ('', ''))
                live = self.fx.P('/usr/lib/modules/' + m.name)
                if m.isreg():
                    self.assertEqual(t.extractfile(m).read(), B.rd(live), m.name)
                elif m.issym():
                    self.assertEqual(m.linkname, os.readlink(live))
        self.assertIn(KREL6 + '/modules.alias', names)
        self.assertIn(KREL6 + '/build', names)
        # original-archive proof
        ov = st['originals_verified']
        self.assertEqual(set(ov), {'linux-aurora', 'omarchy-mac-boot'})
        self.assertGreater(ov['linux-aurora']['files_checked'], 4)
        self.assertEqual(ov['linux-aurora']['regenerated'], ['/usr/lib/modules/%s/modules.dep' % KREL6])
        self.assertEqual(ov['omarchy-mac-boot']['backup_skipped'], 1)
        # the rest
        self.assertEqual(st['conflicts'], [])
        for u in ('limine-snapper-sync.service', 'snapper-cleanup.timer', 'linux-modules-cleanup.service',
                  'omarchy-mac-efi-vars.service'):
            self.assertIn(u, st['units'])
        self.assertEqual(st['units']['limine-snapper-sync.service']['ActiveState'], 'active')
        self.assertEqual(st['efivars'], {'LoaderEntryOneShot': False, 'LoaderEntryDefault': False})
        self.assertEqual(st['snapshots'], [1, 2])
        self.assertEqual(len(st['known_good_refs']), 2)
        self.assertEqual(len(st['limine_history']), 1)
        self.assertEqual(st['packages']['linux-aurora']['version'], '7.2.11.aurora6-1')
        self.assertEqual(st['packages_all']['bash'], '5.3.3-1')
        self.assertIn('limine-snapper-watcher.service', st['systemd_etc'])

    def test_tree_sha_matches_pkg_definition(self):
        """capture's tree_sha256 must equal pkg.py's tsha_of() (install/rollback compare against it)."""
        try:
            import pkg  # sibling target module (owned by another workstream)
        except Exception as e:  # noqa: BLE001
            self.skipTest('pkg.py not importable: %s' % e)
        self.call('capture')
        st = self.fx.state()
        self.assertEqual(pkg.tsha_of(self.fx.P('/usr/lib/modules/' + KREL6)), st['modules'][KREL6]['tree_sha256'])

    def test_capture_refuses_when_capture_exists(self):
        self.call('capture')
        out = self.call('capture', rc=3)
        self.assertIn('already exists', out['refused_reason'])

    def test_capture_refuses_original_archive_mismatch(self):
        self.fx.flip_byte('/usr/lib/modules/%s/kernel/drivers/gpu/asahi.ko' % KREL6, 100)
        out = self.call('capture', rc=3)
        self.assertIn('does not reproduce', out['refused_reason'])
        self.assertIn('asahi.ko', out['refused_reason'])
        self.assertFalse(os.path.exists(self.fx.run_dir + '/capture'))
        self.assertFalse(os.path.exists(self.fx.run_dir + '/.capture.partial'))

    def test_capture_refuses_missing_original_and_low_root(self):
        f = self.fx.config()['originals'][1]['file']
        os.rename(self.fx.run_dir + '/originals/' + f, self.fx.run_dir + '/' + f + '.aside')
        out = self.call('capture', rc=3)
        self.assertIn('missing original archive', out['refused_reason'])
        os.rename(self.fx.run_dir + '/' + f + '.aside', self.fx.run_dir + '/originals/' + f)
        self.fx.set_config(test_root_free=1 << 30)
        out = self.call('capture', rc=3)
        self.assertIn('root free', out['refused_reason'])
        self.fx.set_config(test_root_free=10 << 30)
        self.call('capture')


class TestM3(Base):
    profile = 'm3'

    def test_capture_custom_default_and_prep_keeps_default(self):
        self.call('capture')
        st = self.fx.state()
        check_schema(self, st)
        d = st['menu']['default']
        self.assertEqual(d['name'], 'Omacom Edge - aurora6 M3 GPU')
        self.assertFalse(d['auto_entry'])
        rk = st['running_kernel']
        self.assertEqual((rk['owned_by'], rk['copy']), ([], None))
        self.assertTrue(st['modules']['7.2.11-lab7876c8e8-cc71']['keep_marker'])
        self.assertEqual(st['modules'][KREL6]['owned_by'], ['linux-aurora'])
        self.assertIsNone(st['packages']['omarchy-mac-boot']['version'])
        self.assertEqual(sorted(x['path'] for x in st['conflicts']),
                         ['/etc/default/update-m1n1', '/etc/initcpio/install/omarchy-vendorfw'])
        self.assertTrue(all(x['package'] == 'omarchy-mac-boot' and x['type'] == 'f' for x in st['conflicts']))
        self.assertEqual([(x['path'], x['type']) for x in st['conflicts_other']],
                         [('/usr/lib/systemd/system/omarchy-vendorfw.service', 'l')])
        self.assertIn('omarchy-mac-efi-vars.service', st['units'])
        self.assertEqual(st['units']['omarchy-mac-efi-vars.service']['LoadState'], 'not-found')
        menu0 = self.menu()
        out = self.call('esp-prep')
        self.assertFalse(out['changed'])
        self.assertFalse(out['auto_entry'])
        self.assertIsNone(out['fallback'])
        self.assertEqual(self.menu(), menu0)
        self.assertFalse(os.path.exists(self.fx.P('/boot/efi/EFI/Linux/bt2-%s-original.efi' % RUN8)))
        self.assertEqual(out['default_after']['name'], 'Omacom Edge - aurora6 M3 GPU')
        self.assertTrue(self.call('esp-prep')['already_done'])


class TestEspPrepM1(Base):
    def need_bytes(self):
        return 125829120 + 67108864 + -(-len(self.fx.uki) // 4096) * 4096 + B.MiB

    def test_fallback_copy_stanza_and_default_repoint(self):
        self.call('capture')
        menu0 = self.menu()
        out = self.call('esp-prep')
        self.assertTrue(out['changed'])
        self.assertTrue(out['auto_entry'])
        copy_rel = 'EFI/Linux/bt2-%s-original.efi' % RUN8
        self.assertEqual(self.esp(copy_rel), self.fx.uki)
        self.assertEqual(out['fallback']['b2'], B.b2(self.fx.uki))
        m = limine.Menu(self.menu())
        d = m.default()
        self.assertEqual(d.fullname, 'bt2 original %s' % RUN8)
        self.assertEqual(d.path(), 'boot():/%s#%s' % (copy_rel, B.b2(self.fx.uki)))
        self.assertEqual(d.opts['cmdline'][1], self.fx.state()['menu']['default']['cmdline'])
        self.assertEqual(d.depth, 1)
        # stanza sits right before the maclab block, which is byte-identical
        lines = self.menu().decode().split('\n')
        lab = lines.index(B.LAB_BEGIN)
        self.assertEqual(lines[lab - 1], '')
        self.assertTrue(any(ln == '/bt2 original %s' % RUN8 for ln in lines[lab - 7:lab]))
        old = menu0.decode().split('\n')
        self.assertEqual(lines[lab:], old[old.index(B.LAB_BEGIN):])
        # everything else identical: undo our two edits textually
        txt = self.menu().decode().replace('default_entry: bt2 original %s' % RUN8, 'default_entry: Omarchy/linux-aurora')
        start = txt.index('\n/bt2 original')
        txt = txt[:start - 1] + txt[txt.index('\n' + B.LAB_BEGIN):]
        self.assertEqual(txt.encode(), menu0)
        self.assertTrue(os.path.exists(self.fx.P('/run/lock/boot-partition.lock')))
        rec = json.loads(B.rd(self.fx.run_dir + '/espops-prep.json'))
        self.assertEqual(rec['status'], 'done')
        self.assertEqual(rec['menu_after_sha256'], B.sha(self.menu()))
        self.assertTrue(self.call('esp-prep')['already_done'])

    def test_prep_refuses_when_menu_changed_since_capture(self):
        self.call('capture')
        self.fx.write('/boot/efi/limine.conf', self.menu().replace(b'timeout: 3', b'timeout: 4'))
        out = self.call('esp-prep', rc=3)
        self.assertIn('CAS', out['refused_reason'])

    def test_parking_when_short_then_restore(self):
        self.fx.set_config(test_esp_free=self.need_bytes() - 100 * 1024)
        self.call('capture')
        menu0, sf_rel = self.menu(), 'EFI/Linux/siliconforest-normal-205f5e8b20fc.efi'
        out = self.call('esp-prep')
        self.assertEqual([p['path'] for p in out['parked']], [sf_rel])
        self.assertEqual(out['parked'][0]['stanzas'], ['SiliconForest - kernel 177+182'])
        self.assertFalse(os.path.exists(self.fx.P('/boot/efi/' + sf_rel)))
        self.assertEqual(B.rd(self.fx.run_dir + '/hold/esp/' + sf_rel), self.fx.sf)
        self.assertNotIn(b'SiliconForest - kernel 177+182', self.menu())
        self.assertGreaterEqual(out['esp_free_after'], 125829120 + 67108864)
        out = self.call('esp-restore')
        self.assertIn(sf_rel, out['rewritten'])
        self.assertEqual(self.esp(sf_rel), self.fx.sf)
        self.assertEqual(self.menu(), menu0)
        self.assertFalse(os.path.exists(self.fx.P('/boot/efi/EFI/Linux/bt2-%s-original.efi' % RUN8)))

    def test_parking_insufficient_refuses_without_change(self):
        self.fx.set_config(test_esp_free=self.need_bytes() - 10 * B.MiB)
        self.call('capture')
        before = self.fx.snapshot_tree(exclude=(B.RUN_SYS, '/run/lock'))
        out = self.call('esp-prep', rc=3)
        self.assertIn('ESP short', out['refused_reason'])
        self.assertEqual(before, self.fx.snapshot_tree(exclude=(B.RUN_SYS, '/run/lock')))
        self.assertFalse(os.path.exists(self.fx.run_dir + '/espops-prep.json'))


class TestEspRestoreM1(Base):
    def test_exact_restore_after_simulated_install_and_idempotent(self):
        self.call('capture')
        st = self.fx.state()
        self.call('esp-prep')
        # simulated transaction / job side effects
        new_uki = B.blob('uki-7-1', 310 * 1024)
        self.fx.write('/boot/efi/EFI/Linux/omarchy_linux-aurora.efi', new_uki)
        self.fx.write('/boot/efi/EFI/Linux/omarchy_linux-m3-eryk.efi', B.blob('eryk', 64 * 1024))
        m = self.menu().replace(b'Kernel version: 7.2.11-6-1-ARCH', b'Kernel version: 7.2.11-7-1-ARCH')
        m = m.replace(B.b2(self.fx.uki).encode(), B.b2(new_uki).encode(), 1)
        self.fx.write('/boot/efi/limine.conf', m + b'\n/linux-m3-eryk\n    protocol: efi\n'
                      b'    path: boot():/EFI/Linux/omarchy_linux-m3-eryk.efi\n')
        bb = self.fx.P('/boot/efi/m1n1/boot.bin')
        os.utime(bb, ns=(0, os.lstat(bb).st_mtime_ns + 10 ** 10))
        os.unlink(self.fx.P('/boot/efi/limine.conf.old'))
        self.fx.write('/boot/efi/EFI/extra/new.bin', b'extra')
        self.fx.write('/boot/efi/ubootefi.var', B.blob('ubootvar-new', 8192))
        self.fx.write('/boot/efi/maclab/j1/entry.limine', b'/maclab j1\n')
        out = self.call('esp-restore')
        self.assertTrue(out['changed'])
        self.assertTrue(out['menu_restored'])
        self.assertIn('m1n1/boot.bin', out['mtime_only'])
        self.assertEqual(sorted(out['rewritten']), ['EFI/Linux/omarchy_linux-aurora.efi', 'limine.conf.old'])
        for rel, f in st['esp']['files'].items():
            self.assertEqual(B.sha(self.esp(rel)), f['sha256'], rel)
            self.assertEqual(os.lstat(self.fx.P('/boot/efi/' + rel)).st_mtime_ns, f['mtime_ns'], rel)
        for gone in ('EFI/Linux/omarchy_linux-m3-eryk.efi', 'EFI/Linux/bt2-%s-original.efi' % RUN8,
                     'EFI/extra/new.bin', 'EFI/extra'):
            self.assertFalse(os.path.lexists(self.fx.P('/boot/efi/' + gone)), gone)
            if gone != 'EFI/extra':
                self.assertTrue(os.path.exists(self.fx.run_dir + '/hold/esp-extra/' + gone), gone)
        self.assertEqual(self.esp('ubootefi.var'), B.blob('ubootvar-new', 8192))   # lab-agent owned: untouched
        self.assertEqual(self.esp('maclab/j1/entry.limine'), b'/maclab j1\n')
        again = self.call('esp-restore')
        self.assertFalse(again['changed'])
        self.assertTrue(again['noop'])
        self.assertEqual((again['rewritten'], again['moved_extras'], again['mtime_only']), ([], [], []))
        self.assertEqual(again['manifest_sha256'], out['manifest_sha256'])
        aud = self.call('audit')
        items = {x['item'] for x in aud['informational']}
        self.assertIn('esp_excluded_changed', items)


class TestEtcRestoreM1(Base):
    def test_pacnew_extra_mtime_only_and_bytes(self):
        self.call('capture')
        st = self.fx.state()
        self.fx.write('/etc/default/update-m1n1.pacnew', b'packaged defaults\n')
        mk = self.fx.P('/etc/mkinitcpio.conf')
        ino = os.lstat(mk).st_ino
        os.utime(mk, ns=(0, os.lstat(mk).st_mtime_ns - 5 * 10 ** 9))
        self.fx.write('/etc/default/limine', b'TARGET_OS_NAME="Changed"\n', mode=0o600)
        self.fx.write('/etc/mkinitcpio.conf.d/zz-new.conf', b'new\n')
        os.unlink(self.fx.P('/etc/mkinitcpio.d/linux-aurora.preset'))
        self.fx.write('/etc/limine-entry-tool.d/10-new.conf', b'x\n')
        out = self.call('etc-restore')
        self.assertTrue(out['changed'])
        self.assertIn('/etc/mkinitcpio.conf', out['mtime_only'])
        self.assertEqual(os.lstat(mk).st_ino, ino, 'mtime-only difference must be fixed by utime, not rewrite')
        self.assertEqual(sorted(x['path'] for x in out['moved_extras']),
                         ['/etc/default/update-m1n1.pacnew', '/etc/limine-entry-tool.d',
                          '/etc/mkinitcpio.conf.d/zz-new.conf'])
        hold = self.fx.run_dir + '/hold/etc-extra'
        self.assertEqual(B.rd(hold + '/etc/default/update-m1n1.pacnew'), b'packaged defaults\n')
        self.assertEqual(B.rd(hold + '/etc/limine-entry-tool.d/10-new.conf'), b'x\n')
        self.assertIn('/etc/default/limine', out['restored_bytes'])
        self.assertIn('/etc/mkinitcpio.d/linux-aurora.preset', out['restored_bytes'])
        for p, want in st['etc'].items():
            full = self.fx.P(p)
            if want['type'] == 'absent':
                self.assertFalse(os.path.lexists(full), p)
                continue
            s = os.lstat(full)
            self.assertEqual((s.st_mode & 0o7777, s.st_mtime_ns), (want['mode'], want['mtime_ns']), p)
            if want['type'] == 'f':
                self.assertEqual(B.sha(self.fx.read(p)), want['sha256'], p)
        again = self.call('etc-restore')
        self.assertTrue(again['noop'])
        self.assertFalse(again['changed'])
        self.call('audit')


class TestAuditM1(Base):
    def test_single_byte_difference_then_restore_then_cleanup(self):
        self.call('capture')
        self.assertEqual(self.call('audit')['differences'], [])
        self.fx.flip_byte('/boot/efi/m1n1/boot.bin.old', 7)
        self.fx.flip_byte('/etc/mkinitcpio.conf', 2)
        out = self.call('audit', rc=3)
        self.assertIn('2 difference', out['refused_reason'])
        self.assertIn('m1n1/boot.bin.old', out['refused_reason'])
        self.assertIn('/etc/mkinitcpio.conf', out['refused_reason'])
        rep = sorted(os.listdir(self.fx.run_dir + '/audit-reports'))
        self.assertEqual(rep, ['final.0.json', 'final.1.json'])
        diffs = json.loads(B.rd(self.fx.run_dir + '/audit-reports/final.1.json'))['differences']
        self.assertEqual(sorted((d['item'], d['path'], tuple(d['fields'])) for d in diffs),
                         [('esp_file', 'm1n1/boot.bin.old', ('sha256',)), ('etc', '/etc/mkinitcpio.conf', ('sha256',))])
        self.assertIn('not an ok final-mode audit', self.call('cleanup', rc=3)['refused_reason'])
        self.call('esp-restore')
        self.call('etc-restore')
        self.call('audit', '--held')
        self.assertIn('not an ok final-mode audit', self.call('cleanup', rc=3)['refused_reason'])
        self.assertEqual(self.call('audit')['differences'], [])
        out = self.call('cleanup')
        self.assertEqual(sorted(out['removed']), ['originals', 'pkgs'])   # nothing was ever held in this run
        for gone in ('pkgs', 'originals', 'hold'):
            self.assertFalse(os.path.exists(self.fx.run_dir + '/' + gone))
        for kept in ('capture/state.json', 'receipts/capture.0.json'):
            self.assertTrue(os.path.exists(self.fx.run_dir + '/' + kept))

    def test_cleanup_removes_the_staged_campaign_cts_dir(self):
        self.call('capture')
        self.fx.write(B.RUN_SYS + '/cts/cts.pkg.tar.zst', b'archive')
        self.fx.write(B.RUN_SYS + '/cts/uaddcarry-geometry.txt', b'dEQP-VK.x\n')
        self.assertEqual(self.call('audit')['differences'], [])         # bt2's own run dir is never audited
        out = self.call('cleanup')
        self.assertIn('cts', out['removed'])
        self.assertFalse(os.path.exists(self.fx.run_dir + '/cts'))

    def test_cleanup_removes_both_carriers_only_after_final_audit(self):
        self.call('capture')
        names = ('bt2-capture.tar', 'bt2-capture.tar.gz')
        for name in names:
            self.fx.write(B.RUN_SYS + '/' + name, b'redundant retained carrier')
        self.call('cleanup', rc=3)
        for name in names:
            self.assertTrue(os.path.isfile(self.fx.run_dir + '/' + name))
        self.assertEqual(self.call('audit')['differences'], [])
        out = self.call('cleanup')
        for name in names:
            self.assertIn(name, out['removed'])
            self.assertFalse(os.path.lexists(self.fx.run_dir + '/' + name))
        for name in ('capture/state.json', 'receipts/capture.0.json'):
            self.assertTrue(os.path.isfile(self.fx.run_dir + '/' + name))

    def test_cleanup_keeps_symlink_carrier_and_its_target(self):
        self.call('capture')
        carrier = self.fx.run_dir + '/bt2-capture.tar.gz'
        target = self.fx.run_dir + '/capture/state.json'
        before = B.rd(target)
        os.symlink('capture/state.json', carrier)
        self.assertEqual(self.call('audit')['differences'], [])
        out = self.call('cleanup')
        self.assertNotIn('bt2-capture.tar.gz', out['removed'])
        self.assertTrue(os.path.islink(carrier))
        self.assertEqual(B.rd(target), before)

    def test_cleanup_keeps_unknown_hold_content(self):
        self.call('capture')
        self.call('audit')
        self.fx.write(B.RUN_SYS + '/hold/mystery/file', b'not from a bt2 receipt')
        out = self.call('cleanup')
        self.assertEqual(out['hold_unknown'], ['mystery/file'])
        self.assertIn('hold', out['kept'])
        self.assertTrue(os.path.exists(self.fx.run_dir + '/hold/mystery/file'))

    def test_held_mode_with_writer_masks(self):
        self.call('capture')
        ss = '/etc/systemd/system/'
        alias = self.fx.P(ss + 'limine-snapper-watcher.service')
        target = os.readlink(alias)
        ino = os.lstat(alias).st_ino
        os.makedirs(self.fx.run_dir + '/hold')
        os.link(alias, self.fx.run_dir + '/hold/alias.limine-snapper-watcher.service', follow_symlinks=False)
        os.unlink(alias)
        masked = ['limine-snapper-sync.service', 'limine-snapper-watcher.service', 'snapper-cleanup.timer']
        for u in masked:
            os.symlink('/dev/null', self.fx.P(ss + u))
        self.fx.units(**{u: {'LoadState': 'masked', 'ActiveState': 'inactive', 'UnitFileState': 'masked'}
                         for u in masked})
        with open(self.fx.run_dir + '/writers.json', 'w') as f:
            json.dump({'masks': [{'unit': u, 'path': ss + u} for u in masked],
                       'aliases': [{'unit': 'limine-snapper-watcher.service',
                                    'held': 'hold/alias.limine-snapper-watcher.service', 'ino': ino,
                                    'target': target}],
                       'stopped': ['snapper-cleanup.timer', 'limine-snapper-sync.service'],
                       'was_active': ['snapper-cleanup.timer', 'limine-snapper-sync.service']}, f)
        out = self.call('etc-restore')            # must leave the writer hold alone
        self.assertTrue(out['noop'] or set(out['mtime_only']) <= {'/etc/systemd/system'}, out)
        self.assertEqual(sorted(out['skipped_writer_held']), sorted(ss + u for u in masked))
        for u in masked:
            self.assertEqual(os.readlink(self.fx.P(ss + u)), '/dev/null')
        held = self.call('audit', '--held')
        self.assertEqual(held['mode'], 'held')
        self.call('audit', rc=3)                  # final mode: masks/units are differences
        # simulated release-writers: remove our masks, re-link the same alias inode, restore unit states
        for u in masked:
            os.unlink(self.fx.P(ss + u))
        os.link(self.fx.run_dir + '/hold/alias.limine-snapper-watcher.service', alias, follow_symlinks=False)
        self.assertEqual(os.lstat(alias).st_ino, ino)
        base = self.fx.units_base
        self.fx.units(**{u: dict(base[u]) for u in masked})
        fin = self.call('audit')
        self.assertIn('dir_mtime_changed_by_writer_hold', {x['item'] for x in fin['informational']})
        out = self.call('cleanup')
        self.assertIn('hold', out['removed'])


class TestAuditSnapshotsAir(Base):
    profile = 'air'

    def write_menu(self, raw):
        self.fx.write('/boot/efi/limine.conf', raw)

    def test_final_mode_allows_only_snapshot_additions(self):
        self.call('capture')
        st = self.fx.state()
        self.assertTrue(st['menu']['default']['auto_entry'])
        cur = self.fx.air_menu('ACTUAL-READONLY-CURRENT.conf')
        self.write_menu(cur)
        for i in range(516, 529):
            os.makedirs(self.fx.P('/.snapshots/%d/snapshot' % i))
        out = self.call('audit')
        info = {x['item']: x for x in out['informational']}
        self.assertEqual(info['menu_snapshot_additions']['added_ids'], list(range(528, 515, -1)))
        self.assertEqual(info['snapshots_added']['ids'], list(range(516, 529)))
        self.assertIn('menu', self.call('audit', '--held', rc=3)['refused_reason'])
        # one static byte changed
        self.write_menu(cur.replace(b'timeout: 3', b'timeout: 4'))
        self.assertIn('non-snapshot bytes changed', self.call('audit', rc=3)['refused_reason'])
        # a retained record changed
        self.write_menu(cur.replace('///515 │ 2026-10-26 08:00:00'.encode(), '///515 │ 2026-10-26 08:00:01'.encode()))
        self.assertIn('retained snapshot 515', self.call('audit', rc=3)['refused_reason'])
        # an added record with a foreign kernel template
        self.write_menu(cur.replace(b'rootflags=subvol=/@/.snapshots/528/snapshot loglevel=3',
                                    b'rootflags=subvol=/@/.snapshots/528/snapshot loglevel=7'))
        self.assertIn('does not match a captured', self.call('audit', rc=3)['refused_reason'])
        # a captured record removed (only additions are allowed)
        ref = self.fx.air_menu('reference.conf').decode().split('\n')
        k = next(i for i, ln in enumerate(ref) if ln.endswith('///496 │ 2026-10-25 14:00:04'))
        ref = ref[:k] + ref[k + 8:]
        txt = '\n'.join(ref).replace('comment: 20 snapshots', 'comment: 19 snapshots')
        self.write_menu(txt.encode())
        self.assertIn('removed', self.call('audit', rc=3)['refused_reason'])
        # back to the captured bytes (mtime differs -> esp-restore fixes it) -> clean
        self.write_menu(self.fx.air_menu('reference.conf'))
        self.call('esp-restore')
        self.assertEqual(self.call('audit')['differences'], [])


if __name__ == '__main__':
    unittest.main()
