"""r3 cohort binding: the kernel release and provider pins come from the explicit manifest, strictly validated.

Each test loads a FRESH checker module (a bound cohort is module state and never changes)."""
import copy, importlib.util, json, os, unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).parent
CHECKER = HERE / os.environ.get('R3_CHECKER', 'checker-r3.py')
_n = [0]


def fresh():
    _n[0] += 1
    spec = importlib.util.spec_from_file_location('r3_%d' % _n[0], CHECKER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def filled(c):
    m = json.loads((HERE / 'smoke-manifest.template.json').read_text())
    token = 'ab' * 32
    m.update(source_review='accepted-by-root', approved=True, device='m1air', board='apple,j313',
             expected_boot_id='11111111-2222-3333-4444-555555555555', token=token, gui_user='somebody',
             gui_uid=1000, wifi_interface='wlan0', wifi_mac='02:00:00:00:00:01',
             output_dir='/var/tmp/sf-rc-normal-session-' + token[:16])
    return m


def other_cohort(c):
    """A different Mesa (26.4.0) and kernel release: new hashes and sizes for every role."""
    prov = {}
    for i, role in enumerate(c.PROVIDER_ROLES):
        path = '/usr/lib/libgallium-26.4.0-devel.so' if role == 'gallium' else c.ROLE_PATHS[role]
        prov[role] = {'path': path, 'sha256': ('%x' % (i + 1)) * 64, 'bytes': 1000 + i}
    prov['egl']['note'] = 'unchanged wrapper; insufficient alone'
    prov['gallium']['package'] = 'mesa-aurora'           # extra keys from the controller are ignored
    return '7.3.1-2-1-ARCH', prov


def manifest_with(c, kernel, prov):
    m = filled(c)
    m['expected_kernel'] = kernel
    m['providers'] = copy.deepcopy(prov)
    return m


class CohortBinding(unittest.TestCase):
    def test_reference_cohort_still_validates(self):
        c = fresh()
        ref = copy.deepcopy(c.PROVIDERS)
        c.frozen_manifest(filled(c))
        self.assertEqual(c.KERNEL, '7.2.11-7-1-ARCH')
        self.assertEqual(c.PROVIDERS, ref)

    def test_other_kernel_and_mesa_are_bound_from_the_manifest(self):
        c = fresh()
        kernel, prov = other_cohort(c)
        c.frozen_manifest(manifest_with(c, kernel, prov))
        self.assertEqual(c.KERNEL, kernel)
        self.assertEqual(c.GALLIUM, '/usr/lib/libgallium-26.4.0-devel.so')
        self.assertEqual(c.PROVIDERS['vulkan'], {k: prov['vulkan'][k] for k in ('path', 'sha256', 'bytes')})
        self.assertEqual(c.REQUIRED['GL'], (c.GALLIUM, c.EGL))
        self.assertEqual(c.REQUIRED['compositor'], (c.GALLIUM,))
        self.assertIn(c.GALLIUM, c.ALLOWED['GL'])
        # the reference (7c) Gallium is no longer an allowed provider: a stale Mesa map is refused
        self.assertIsNone(c.provider_for('/usr/lib/libgallium-26.3.0-devel.so'))
        with self.assertRaisesRegex(ValueError, 'unknown map'):
            c.guarded([{'path': '/usr/lib/libgallium-26.3.0-devel.so', 'deleted': False}], 'GL')
        rows = c.assess([{'path': c.GALLIUM, 'deleted': False}, {'path': c.EGL, 'deleted': False}], 'GL')
        self.assertEqual({r['provider'] for r in rows}, {c.GALLIUM, c.EGL})
        # same manifest again (the run re-reads it from disk): identical rebinding is fine
        c.frozen_manifest(manifest_with(c, kernel, prov))

    def test_installed_provider_hashes_are_checked_against_the_bound_pins(self):
        c = fresh()
        kernel, prov = other_cohort(c)
        c.frozen_manifest(manifest_with(c, kernel, prov))
        good = {p['path']: {'sha256': p['sha256']} for p in c.PROVIDERS.values()}
        with mock.patch.object(c, 'regular_sha256', side_effect=lambda path, n: good[path]):
            self.assertEqual(set(c.provider_cache()), {p['path'] for p in c.PROVIDERS.values()})
        bad = dict(good)
        bad[c.VULKAN] = {'sha256': '0' * 64}                # the file on disk is not the candidate's
        with mock.patch.object(c, 'regular_sha256', side_effect=lambda path, n: bad[path]):
            with self.assertRaisesRegex(ValueError, 'installed provider hash mismatch'):
                c.provider_cache()

    def test_booted_kernel_must_be_the_bound_kernel(self):
        c = fresh()
        kernel, prov = other_cohort(c)
        m = c.frozen_manifest(manifest_with(c, kernel, prov))
        uname = os.uname()
        fake = type(uname)((uname.sysname, uname.nodename, '7.2.11-7-1-ARCH', uname.version, 'aarch64'))
        real_read_bytes = Path.read_bytes

        def read_bytes(p):
            if str(p) == '/proc/device-tree/compatible':
                return b'apple,j313\0apple,t8103\0'
            return real_read_bytes(p)
        with mock.patch.object(c.os, 'uname', return_value=fake), mock.patch.object(Path, 'read_bytes', read_bytes):
            with self.assertRaisesRegex(ValueError, 'wrong current kernel'):
                c.snapshot(m, Path('/proc/1'), {})

    def test_rebinding_to_different_pins_is_refused(self):
        c = fresh()
        kernel, prov = other_cohort(c)
        c.frozen_manifest(manifest_with(c, kernel, prov))
        tampered = copy.deepcopy(prov)
        tampered['gallium']['sha256'] = 'f' * 64            # manifest file changed after the in-process check
        with self.assertRaisesRegex(ValueError, 'already bound to different pins'):
            c.frozen_manifest(manifest_with(c, kernel, tampered))
        with self.assertRaisesRegex(ValueError, 'already bound to different pins'):
            c.frozen_manifest(manifest_with(c, '7.3.1-9-1-ARCH', prov))
        self.assertEqual(c.PROVIDERS['gallium']['sha256'], prov['gallium']['sha256'])

    def refused(self, mutate, pattern):
        c = fresh()
        kernel, prov = other_cohort(c)
        kernel, prov = mutate(c, kernel, copy.deepcopy(prov)) or (kernel, prov)
        with self.assertRaisesRegex(ValueError, pattern):
            c.frozen_manifest(manifest_with(c, kernel, prov))
        self.assertIsNone(c._BOUND)                          # nothing was bound
        self.assertEqual(c.KERNEL, '7.2.11-7-1-ARCH')

    def test_missing_provider_role(self):
        self.refused(lambda c, k, p: (k, {r: v for r, v in p.items() if r != 'vulkan'}), 'cohort provider roles')

    def test_extra_provider_role(self):
        def m(c, k, p):
            p['swrast'] = dict(p['dril'], sha256='9' * 64)
            return k, p
        self.refused(m, 'cohort provider roles')

    def test_provider_outside_usr_lib(self):
        def m(c, k, p):
            p['gallium']['path'] = '/tmp/libgallium-26.4.0-devel.so'
            return k, p
        self.refused(m, 'cohort provider path: gallium')

    def test_gallium_path_traversal(self):
        def m(c, k, p):
            p['gallium']['path'] = '/usr/lib/libgallium-../../tmp/x.so'
            return k, p
        self.refused(m, 'cohort provider path: gallium')

    def test_fixed_soname_role_cannot_move(self):
        def m(c, k, p):
            p['vulkan']['path'] = '/usr/lib/libvulkan_lvp.so'
            return k, p
        self.refused(m, 'cohort provider path: vulkan')

    def test_bad_sha_and_size(self):
        for field, value, pat in (('sha256', 'F' * 64, 'sha256'), ('sha256', 'a' * 63, 'sha256'),
                                  ('sha256', None, 'sha256'), ('bytes', 0, 'size'), ('bytes', -1, 'size'),
                                  ('bytes', True, 'size'), ('bytes', '1000', 'size'), ('bytes', 1 << 40, 'size')):
            def m(c, k, p, field=field, value=value):
                p['egl'][field] = value
                return k, p
            with self.subTest(field=field, value=value):
                self.refused(m, 'cohort provider ' + pat + ': egl')

    def test_duplicate_hashes(self):
        def m(c, k, p):
            p['glx']['sha256'] = p['gbm']['sha256']
            return k, p
        self.refused(m, 'hashes are not distinct')

    def test_kernel_release_not_explicit(self):
        for bad in (None, '', ' 7.3', '7.3/../x', 'x' * 80, 7):
            with self.subTest(kernel=bad):
                self.refused(lambda c, k, p, bad=bad: (bad, p), 'cohort kernel release is not explicit')

    def test_providers_not_a_dict(self):
        self.refused(lambda c, k, p: (k, [p]), 'cohort provider roles')

    def test_unapproved_manifest_binds_nothing(self):
        c = fresh()
        kernel, prov = other_cohort(c)
        m = manifest_with(c, kernel, prov)
        m['approved'] = False
        with self.assertRaisesRegex(ValueError, 'not approved'):
            c.frozen_manifest(m)
        self.assertIsNone(c._BOUND)


if __name__ == '__main__':
    unittest.main()
