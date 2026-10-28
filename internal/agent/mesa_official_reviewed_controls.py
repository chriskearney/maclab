"""Host controls for the staged official 65 adapter. No GPU, systemd, or package action."""
from pathlib import Path
import inspect, json, os, shutil, stat, sys, tarfile, tempfile, unittest
import mesa_official as m

ARCHIVE = m.Q / 'release-native-arm' / 'omarchy-m-test.tar.gz'
GL = '/var/lib/sf-mesa-trueup-20261024/probes/gl-render-check-aarch64'
VK = '/var/lib/sf-mesa-trueup-20261024/probes/vk-render-check-aarch64'

def load_gpu(tmp):
    dest = Path(tmp) / 'pkg'
    with tarfile.open(ARCHIVE) as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('.py'):
                tar.extract(member, dest, filter='data')
    sys.path.insert(0, str(dest / 'omarchy-m-test'))
    from omarchy_m_test import gpu_benchmark
    return gpu_benchmark

def identity_of(path):
    st = os.lstat(path)
    return {'sha256': m.regular_identity(path)['sha256'], 'size': st.st_size, 'dev': st.st_dev, 'inode': st.st_ino}

def fixture(tmp, official=True):
    uid, gid = os.getuid(), os.getgid()
    prefix = Path(tmp) / 'job'
    root = prefix / 'packages'
    out = prefix / 'out'
    lib = root / 'lib'
    lib.mkdir(parents=True)
    out.mkdir(mode=0o700)
    os.chmod(out, 0o700)
    vulkan = lib / 'libvulkan_asahi.so'
    vulkan.write_bytes(b'\x7fELF' + b'staged-vulkan')
    egl = lib / 'libEGL_mesa.so.0.0.0'
    egl.write_bytes(b'egl')
    gallium = lib / 'libgallium.so'
    gallium.write_bytes(b'gallium')
    icd = prefix / 'asahi_icd.json'
    icd.write_text(json.dumps({'library_path': str(vulkan)}))
    egl_json = prefix / 'egl.json'
    egl_json.write_text(json.dumps({'library_path': str(egl)}))
    official_dir = prefix / 'official'
    official_dir.mkdir()
    os.link(ARCHIVE, official_dir / 'archive.tar.gz')
    gui = Path(tmp) / 'gui'
    nested = gui / '.local'
    state = nested / 'state'
    keydir = state / 'omarchy-m-test'
    keydir.mkdir(parents=True)
    for directory in (gui, nested, state, keydir):
        os.chmod(directory, 0o700)
    key = keydir / 'machine-key'
    key.write_text('private')
    os.chmod(key, 0o600)
    pub = keydir / 'machine-key.pub'
    pub.write_text('ssh-ed25519 ' + ('A' * 68) + ' machine\n')
    os.chmod(pub, 0o644)
    loader = Path(tmp) / 'libvulkan.so.1'
    loader.write_bytes(b'loader-pin')
    pin = identity_of(loader)
    render = os.lstat('/dev/null')
    session = {'XDG_RUNTIME_DIR': '/run/user/' + str(uid), 'WAYLAND_DISPLAY': 'wayland-1', 'HYPRLAND_INSTANCE_SIGNATURE': 'actual'}
    files = {}
    for rel, path in (('lib/libvulkan_asahi.so', vulkan), ('lib/libEGL_mesa.so.0.0.0', egl), ('lib/libgallium.so', gallium)):
        ident = m.regular_identity(path)
        files[rel] = {'sha256': ident['sha256'], 'size': ident['size'], 'package': 'mesa-aurora'}
    manifest = {
        'schema': 1, 'job': 'job1', 'prefix': str(prefix), 'root': str(root),
        'packages': [{'pkgbase': 'mesa-aurora', 'version': '1', 'arch': 'aarch64', 'pkginfo_sha256': 'ab' * 32}],
        'files': files,
        'probes': {'gl': {'path': GL, 'sha256': m.GL_PROBE_SHA}, 'vulkan': {'path': VK, 'sha256': m.VK_PROBE_SHA}},
        'providers': {'egl': 'lib/libEGL_mesa.so.0.0.0', 'gallium': 'lib/libgallium.so', 'vulkan': 'lib/libvulkan_asahi.so'},
        'vulkan_json': str(icd), 'egl_json': str(egl_json),
    }
    plan = {
        'schema': 1, 'job': 'job1', 'boot_id': '11111111-2222-3333-4444-555555555555', 'kernel': '7.2.11-7-1-ARCH',
        'cmdline_sha256': 'cd' * 32, 'manifest_path': str(prefix / 'manifest.json'), 'manifest_sha256': 'ef' * 32,
        'gui_user': 'somebody', 'gui_uid': uid, 'gui_gid': gid, 'gui_home': str(gui), 'gui_env': dict(session),
        'official_gpu': official, 'signing_public_sha256': m.regular_identity(pub)['sha256'],
        'signing_state_home': str(state),
    }
    plan['official_identity'] = {
        'signing': {
            'state_home': str(state),
            'public_sha256': plan['signing_public_sha256'],
            'files': [m.file_metadata(keydir, 'directory'), m.file_metadata(key, 'regular'), m.file_metadata(pub, 'regular')],
        },
        'device': {
            'board': 'j313', 'soc': 't8103',
            'compatible': ['apple,j313', 'apple,t8103', 'apple,arm-platform'],
            'render_node': {
                'path': '/dev/null', 'major': os.major(render.st_rdev), 'minor': os.minor(render.st_rdev),
                'mode': stat.S_IMODE(render.st_mode), 'uid': render.st_uid, 'gid': render.st_gid,
                'dev': render.st_dev, 'inode': render.st_ino,
            },
        },
    }
    env = {
        'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'USER': 'somebody', 'LOGNAME': 'somebody',
        'LD_LIBRARY_PATH': str(lib), 'VK_DRIVER_FILES': str(icd), '__EGL_VENDOR_LIBRARY_FILENAMES': str(egl_json),
        'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'), 'XDG_CACHE_HOME': str(out / 'cache'),
        'XDG_CONFIG_HOME': str(out / 'config'), 'XDG_DATA_HOME': str(out / 'data'),
        'XDG_STATE_HOME': str(out / 'private-state'), **session,
    }
    return plan, manifest, str(out), env, {str(loader): pin}, vulkan, loader

def run_record(gpu, work, phase, index, sequence, negative, impl, loader):
    measurements = {
        'mismatches': 1 if negative else 0,
        'operations': gpu.OPERATIONS[work] // gpu.QUERIES[work] if negative else gpu.OPERATIONS[work],
        'owned_bytes_peak': 4096,
        'width': 1920 if work in ('raster', 'texture') else 0,
        'height': 1080 if work in ('raster', 'texture') else 0,
        'record_ns': 10, 'submit_wait_ns': 11, 'thread_cpu_ns': 12, 'bo_lifetime_ns': 0,
        'gpu_timestamp_queries': 0, 'gpu_timestamp_status': 'unsupported',
    }
    return {
        'phase': phase, 'index': index, 'sequence': sequence, 'negative': negative, 'status': 'pass',
        'reason': 'negative-control-detected' if negative else 'completed', 'helper_sha256': m.HELPER_SHA,
        'identity': {'vendor_id': 0x10005, 'driver_id': 26, 'device_type': 1, 'api_version': 4202496,
                     'device_name': 'Apple M2 (G14G C1)', 'source_sha256': m.SOURCE_SHA, 'timestamp_bits': 0},
        'measurements': measurements,
        'driver_libraries': [{'role': 'implementation', 'sha256': impl}, {'role': 'loader', 'sha256': loader}],
    }

def document(gpu, plan, impl, loader):
    schedule = m.document_schedule(gpu)
    controls = [run_record(gpu, 'compute', 'control', 0, 0, flag, impl, loader) for flag in (False, True)]
    cases = []
    for work in gpu.WORKLOADS:
        rows = []
        for item in schedule:
            if item['workload'] != work:
                continue
            rows.append(run_record(gpu, work, item['phase'], item['index'], schedule.index(item), False, impl, loader))
        cases.append({'workload': gpu.workload_definition(work), 'status': 'pass', 'runs': rows, 'metrics': gpu.metrics_for(rows)})
    return {'status': 'pass', 'machine': {'kernel': plan['kernel'], 'arch': 'aarch64', 'board': 'j313', 'soc': 't8103'},
            'protocol': dict(m.PROTOCOL), 'controls': controls, 'schedule': schedule, 'cases': cases}

class Adapter(unittest.TestCase):
    def test_pins_and_archive_helper_are_the_qualified_bytes(self):
        supervisor = m.load_pinned()
        self.assertEqual(supervisor.COMMIT, m.COMMIT)
        self.assertEqual(supervisor.WALL, 1800)
        self.assertIn('dart', supervisor.s.FAULTS)
        self.assertIn('gpu', supervisor.s.FAULTS)
        supervisor_text = Path(m.SUPERVISOR_PATH).read_text()
        stop = supervisor_text.split('def stop_unit', 1)[1].split('\ndef ', 1)[0]
        unit_state = supervisor_text.split('def unit_state', 1)[1].split('\ndef ', 1)[0]
        self.assertEqual(stop.count('timeout=12'), 2)
        self.assertIn('timeout=5', stop)
        self.assertIn('timeout=5', unit_state)
        self.assertIn('reset-failed', stop)
        self.assertIn("timeout=10);s.private_write(logs/'journal-final.jsonl',raw)", supervisor_text)
        kill = Path(m.GUARD_PATH).read_text().split('def kill_group', 1)[1].split('\ndef ', 1)[0]
        self.assertIn('proc.wait(timeout=2)', kill)
        self.assertIn('proc.wait(timeout=3)', kill)
        self.assertIn('time.monotonic()+2', kill)
        self.assertEqual(m.KILL_GROUP_S, 2 + 3 + 2)
        self.assertEqual(m.DECLARED_CLEANUP_ALLOWANCE_S, 3 * 5 + 12 + 5 + 12 + 5 + 10)
        self.assertEqual(m.MONITOR_CLOSE_S, 2)
        self.assertGreater(m.DECLARED_CLEANUP_ALLOWANCE_S + m.MONITOR_CLOSE_S, m.CALLER_CLEANUP_RESERVE_S)
        self.assertEqual(m.CALLER_CLEANUP_RESERVE_S, 60)
        self.assertNotIn('PINNED_STOP_JOURNAL_S', Path(m.__file__).read_text())
        self.assertNotIn('WatchdogSec', inspect.getsource(m.launch_argv))
        self.assertNotIn('WatchdogSec', Path(m.__file__).read_text())
        self.assertNotIn('sleep', m.release_execution.__code__.co_names)
        data = supervisor.s.inspect_archive(ARCHIVE)
        self.assertEqual(len(data), m.ARCHIVE_BYTES)
        self.assertEqual(m.sha_bytes(data), m.ARCHIVE_SHA)

    def test_schedule_is_two_controls_plus_seven_by_nine(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            gpu = load_gpu(tmp)
            supervisor = m.load_pinned()
            order = m.official_order(supervisor, gpu)
            self.assertEqual(len(order), 2 + 7 * (2 + 7))
            self.assertEqual(order[:2], [('compute', False), ('compute', True)])
            self.assertEqual([(item['workload'], False) for item in m.document_schedule(gpu)], order[2:])
            self.assertEqual(tuple(gpu.WORKLOADS), m.WORKLOADS)
            self.assertEqual(gpu.OPERATIONS['submit-batched'], 128)
            self.assertEqual(gpu.QUERIES['submit-batched'], 4)
        finally:
            shutil.rmtree(tmp)

    def test_request_refuses_installed_software_and_missing_identity(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            plan, manifest, out, env, pins, vulkan, loader = fixture(tmp)
            bound = m.bind(plan, manifest, out, env, pins)
            self.assertEqual(bound['staged']['vulkan'], str(vulkan))
            plan['official_gpu'] = False
            with self.assertRaises(m.Refuse):
                m.bind(plan, manifest, out, env, pins)
            plan['official_gpu'] = True
            plan['signing_public_sha256'] = ''
            with self.assertRaises(m.Refuse):
                m.bind(plan, manifest, out, env, pins)
            plan['signing_public_sha256'] = 'ab' * 32
            manifest['root'] = '/usr'
            with self.assertRaises(m.Refuse) as caught:
                m.bind(plan, manifest, out, env, pins)
            self.assertIn('installed', str(caught.exception))
            manifest['root'] = str(Path(tmp) / 'job' / 'packages')
            env['LIBGL_ALWAYS_SOFTWARE'] = '1'
            with self.assertRaises(m.Refuse):
                m.bind(plan, manifest, out, env, pins)
            del env['LIBGL_ALWAYS_SOFTWARE']
            env['LD_LIBRARY_PATH'] = '/usr/lib'
            with self.assertRaises(m.Refuse):
                m.bind(plan, manifest, out, env, pins)
            env['LD_LIBRARY_PATH'] = str(vulkan.parent)
            pins[str(loader)] = {**pins[str(loader)], 'inode': pins[str(loader)]['inode']}
            bad = {str(Path(tmp) / 'libGLX.so'): pins[str(loader)]}
            with self.assertRaises(m.Refuse):
                m.bind(plan, manifest, out, env, bad)
            plan['signing_public_sha256'] = plan['official_identity']['signing']['public_sha256']
            plan['gui_env'] = {**plan['gui_env'], 'HOME': plan['gui_home']}
            with self.assertRaises(m.Refuse):
                m.bind(plan, manifest, out, env, pins)
            plan['gui_env'] = {key: value for key, value in plan['gui_env'].items() if key != 'HOME'}
            plan['signing_state_home'] = str(Path(manifest['prefix']) / 'state')
            plan['official_identity']['signing']['state_home'] = plan['signing_state_home']
            plan['gui_home'] = str(Path(tmp))
            with self.assertRaises(m.Refuse) as caught:
                m.bind(plan, manifest, out, env, pins)
            self.assertIn('prefix', str(caught.exception))
        finally:
            shutil.rmtree(tmp)

    def test_bindings_match_archive_probes_elf_and_existing_pubkey(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            plan, manifest, out, env, pins, vulkan, loader = fixture(tmp)
            real_open = os.open
            seen = []
            def opened(path, flags, *args, **kwargs):
                seen.append((os.fspath(path), flags))
                return real_open(path, flags, *args, **kwargs)
            os.open = opened
            try:
                bound = m.prove_bindings(m.bind(plan, manifest, out, env, pins))
            finally:
                os.open = real_open
            private = str(Path(plan['signing_state_home']) / 'omarchy-m-test' / 'machine-key')
            self.assertTrue(seen)
            self.assertFalse(any(path == private or path == '/dev/null' or flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY) for path, flags in seen))
            self.assertEqual(bound['staged_identity']['vulkan']['magic'], b'\x7fELF')
            os.chmod(private, 0o644)
            with self.assertRaises(m.Refuse):
                m.prove_bindings(m.bind(plan, manifest, out, env, pins))
            os.chmod(private, 0o600)
            self.assertNotEqual(bound['staged_identity']['vulkan']['inode'], pins[str(loader)]['inode'])
            self.assertTrue(m.PUBKEY.fullmatch(bound['public_identity']))
            os.chmod(vulkan, 0o644)
            vulkan.write_bytes(b'\x7fELF' + b'replaced')
            with self.assertRaises(m.Refuse):
                m.prove_bindings(m.bind(plan, manifest, out, env, pins))
        finally:
            shutil.rmtree(tmp)

    def test_system_pin_drift_and_nonregular_files_fail(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            path = Path(tmp) / 'libvulkan.so.1'
            path.write_bytes(b'one')
            before = identity_of(path)
            path.write_bytes(b'two')
            after = identity_of(path)
            self.assertNotEqual(before['sha256'], after['sha256'])
            bound = {'system_graphics_pins': {str(path): before}, 'staged_identity': {'vulkan': {'inode': -1}}}
            with self.assertRaises(m.Refuse):
                m.snapshot_graphics(bound)
            fresh = Path(tmp) / 'libvulkan.so.1.new'
            fresh.write_bytes(b'three')
            os.replace(fresh, path)
            replaced = identity_of(path)
            self.assertNotEqual(before['inode'], replaced['inode'])
            self.assertNotEqual(before['sha256'], replaced['sha256'])
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(m.Refuse):
                m.regular_identity(link)
            fifo = Path(tmp) / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(m.Refuse):
                m.regular_identity(fifo)
        finally:
            shutil.rmtree(tmp)

    def test_btrfs_text_device_is_not_identity_and_same_inode_other_dev_is_refused(self):
        pid = os.getpid()
        found = None
        for line in (Path('/proc') / str(pid) / 'maps').read_text().splitlines():
            fields = line.split(None, 5)
            if len(fields) != 6 or not fields[5].startswith('/') or fields[5].endswith(' (deleted)'):
                continue
            try:
                st = os.stat(fields[5], follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_ino != int(fields[4]):
                continue
            major, minor = fields[3].split(':')
            maps_dev = (int(major, 16), int(minor, 16))
            stat_dev = (os.major(st.st_dev), os.minor(st.st_dev))
            if maps_dev != stat_dev:
                found = (fields[0], maps_dev, stat_dev, st.st_ino, fields[5])
                break
        self.assertIsNotNone(found)
        span, maps_dev, stat_dev, inode, path = found
        self.assertNotEqual(maps_dev, stat_dev)
        start, end = span.split('-', 1)
        try:
            held = m.kernel_held_map(pid, start, end)
        except m.Refuse as refused:
            self.assertIn('denied', str(refused))
        else:
            self.assertEqual((os.major(held['dev']), os.minor(held['dev'])), stat_dev)
            self.assertNotEqual((os.major(held['dev']), os.minor(held['dev'])), maps_dev)
            self.assertEqual(held['inode'], inode)
            self.assertEqual(held['sha256'], m.regular_identity(path)['sha256'])
        body = inspect.getsource(m.open_held_descriptor)
        self.assertIn('O_PATH', body)
        self.assertNotIn('O_NOFOLLOW', body)
        self.assertIn('open_held_descriptor', m.kernel_held_map.__code__.co_names)
        self.assertNotIn('regular_identity', m.kernel_held_map.__code__.co_names)
        self.assertIn('provider_maps', m.classify_process.__code__.co_names)
        self.assertIn('kernel_held_map', m.provider_maps.__code__.co_names)
        self.assertNotIn('regular_identity', m.classify_process.__code__.co_names)
        self.assertIn('held_matches', m.finish_observations.__code__.co_names)
        self.assertIn('retain_sample', m.observe_until_exit.__code__.co_names)
        self.assertIn('open_fault_monitor', m.observe_until_exit.__code__.co_names)
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        fd = None
        try:
            path = Path(tmp) / 'held-elf'
            path.write_bytes(b'\x7fELF' + b'old-mapping')
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            held = m.descriptor_identity(fd, 'mapped reference')
            fresh = Path(tmp) / 'replaced-elf'
            fresh.write_bytes(b'\x7fELF' + b'replaced-path')
            os.replace(fresh, path)
            still = m.descriptor_identity(fd, 'mapped reference')
            self.assertEqual(still['dev'], held['dev'])
            self.assertEqual(still['inode'], held['inode'])
            self.assertEqual(still['sha256'], held['sha256'])
            live = m.regular_identity(path)
            self.assertNotEqual(live['inode'], held['inode'])
            self.assertFalse(m.held_matches(held, live))
            other_dev = {'dev': os.makedev(0, 24), 'inode': held['inode'], 'sha256': held['sha256']}
            typed = {'dev': os.makedev(0, 39), 'inode': held['inode'], 'sha256': held['sha256']}
            self.assertFalse(m.held_matches(other_dev, typed))
            self.assertTrue(m.held_matches(held, dict(held)))
        finally:
            if fd is not None:
                os.close(fd)
            shutil.rmtree(tmp)

    def test_frozen_call_keeps_root_payload_and_accumulates_partial_maps(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            plan, manifest, out, env, pins, vulkan, loader = fixture(tmp)
            agent_out = Path(tmp) / 'agent-out'
            agent_out.mkdir(mode=0o700)
            run = Path(manifest['prefix']) / 'run'
            for name in ('home', 'tmp', 'cache', 'config', 'data', 'state', 'reports'):
                (run / name).mkdir(parents=True)
            env['LD_LIBRARY_PATH'] = str(vulkan.parent) + ':/usr/lib'
            env['LIBGL_DRIVERS_PATH'] = str(vulkan.parent) + '/dri'
            env['GBM_BACKENDS_PATH'] = str(vulkan.parent) + '/gbm'
            env['HOME'] = str(run / 'home')
            env['TMPDIR'] = str(run / 'tmp')
            env['XDG_CACHE_HOME'] = str(run / 'cache')
            env['XDG_CONFIG_HOME'] = str(run / 'config')
            env['XDG_DATA_HOME'] = str(run / 'data')
            env['XDG_STATE_HOME'] = str(run / 'state')
            manifest['packages'][0]['name'] = 'vulkan-asahi'
            manifest['packages'][0]['pkgbase'] = 'mesa'
            for meta in manifest['files'].values():
                meta['package'] = 'vulkan-asahi'
            egl_pin = Path(tmp) / 'libEGL.so.1'
            egl_pin.write_bytes(b'egl-pin')
            asahi_pin = Path(tmp) / 'libvulkan_asahi.so'
            asahi_pin.write_bytes(b'asahi-pin')
            pins[str(egl_pin)] = identity_of(egl_pin)
            pins[str(asahi_pin)] = identity_of(asahi_pin)
            plan['gui_uid'] = os.getuid() + 1
            bound = m.bind(plan, manifest, agent_out, env, pins)
            self.assertEqual(bound['state_home'], plan['signing_state_home'])
            self.assertEqual(bound['unit_env']['XDG_STATE_HOME'], plan['signing_state_home'])
            self.assertNotEqual(bound['state_home'], env['XDG_STATE_HOME'])
            self.assertEqual(bound['unit_env']['HYPRLAND_INSTANCE_SIGNATURE'], 'actual')
            self.assertNotIn('HOME', plan['gui_env'])
            self.assertNotIn('existing_state_home', Path(m.__file__).read_text())
            self.assertNotIn('.local', Path(m.__file__).read_text())
            self.assertEqual(bound['unit_env']['LD_LIBRARY_PATH'], str(vulkan.parent))
            self.assertNotIn('LIBGL_DRIVERS_PATH', bound['unit_env'])
            self.assertNotIn('GBM_BACKENDS_PATH', bound['unit_env'])
            paths = m.layout_paths(bound)
            self.assertTrue(str(paths['payload_root']).endswith('/official/payload'))
            self.assertTrue(str(paths['logs']).endswith('/official/root'))
            self.assertTrue(str(paths['report']).endswith('/run/reports/gpu-block1.json'))
            self.assertFalse(str(paths['payload_root']).startswith(str(agent_out)))
            self.assertFalse(str(paths['logs']).startswith(str(run)))
            argv = m.launch_argv(m.load_pinned(), bound, Path(tmp) / 'payload' / 'omarchy-m-test', paths['report'], paths['stdout'], paths['stderr'])
            self.assertIn('User=' + str(plan['gui_uid']), '\n'.join(argv))
            self.assertNotIn('User=0', '\n'.join(argv))
            seen = {}
            sha = 'ab' * 32
            loader_held = {'dev': 1, 'inode': 2, 'sha256': sha}
            impl = {'dev': 3, 'inode': 4, 'sha256': sha}
            partial = {'pid': 7, 'birth': 1, 'workload': 'compute', 'negative': False, 'implementation': None, 'loader': None, 'renders': []}
            m.retain_sample(seen, partial)
            self.assertIsNone(seen[(7, 1)]['implementation'])
            m.retain_sample(seen, {**partial, 'implementation': impl, 'loader': loader_held, 'renders': [(226, 128)]})
            m.retain_sample(seen, partial)
            self.assertTrue(m.held_matches(seen[(7, 1)]['implementation'], impl))
            self.assertEqual(seen[(7, 1)]['renders'], [(226, 128)])
            other = {'dev': os.makedev(0, 24), 'inode': impl['inode'], 'sha256': sha}
            with self.assertRaises(m.Refuse):
                m.retain_sample(seen, {**partial, 'implementation': other})
            self.assertIsNone(m.classify_process(1 << 30, 1, Path('/no/such/helper'), {'plan': {'gui_uid': 1}}))
            report = Path(tmp) / 'report.json'
            report.write_bytes(b'{"status":"pass"}\n')
            ident, blob = m.read_regular(report, m.REPORT_CAP)
            self.assertEqual(m.sha_bytes(blob), ident['sha256'])
            self.assertEqual(blob, b'{"status":"pass"}\n')
            link = Path(tmp) / 'report-link'
            link.symlink_to(report)
            with self.assertRaises(m.Refuse):
                m.read_regular(link, m.REPORT_CAP)
            module = m.exec_verified('pinned_bytes', b'PIN = 1\n')
            self.assertEqual(module.PIN, 1)
            self.assertIn('exec_verified', m.load_pinned.__code__.co_names)
            self.assertNotIn('spec_from_file_location', m.load_pinned.__code__.co_names)
            supervisor = m.load_pinned()
            boot = '11111111-2222-3333-4444-555555555555'
            raw = (json.dumps({'_BOOT_ID': boot.replace('-', ''), 'MESSAGE': 'asahi: gpu fault'}) + '\n').encode()
            supervisor.s.capture = lambda *args, **kwargs: raw
            fault_logs = Path(tmp) / 'fault-logs'
            fault_logs.mkdir(mode=0o700)
            caught = m.journal_final(supervisor, {'plan': {'boot_id': boot}}, 'cursor', fault_logs, {'stopped': True}, None)
            self.assertIn('new-kernel-fault', caught)
            self.assertEqual((fault_logs / 'journal-final.jsonl').read_bytes(), raw)
            observer = json.loads((fault_logs / 'observer-final.json').read_text())
            self.assertIn('new-kernel-fault', observer['journal_error'])
        finally:
            shutil.rmtree(tmp)

    def test_oracle_keeps_65_raw_stats_and_rejects_a_short_or_wrong_run(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            gpu = load_gpu(tmp)
            plan, manifest, out, env, pins, vulkan, loader = fixture(tmp)
            impl = m.regular_identity(vulkan)['sha256']
            loader_sha = pins[str(loader)]['sha256']
            doc = document(gpu, plan, impl, loader_sha)
            runs = m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            supervisor = m.load_pinned()
            m.require_order(supervisor, gpu, runs)
            self.assertEqual(len(runs), 65)
            doc['machine']['kernel'] = 'other'
            with self.assertRaises(m.Refuse):
                m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            doc = document(gpu, plan, impl, loader_sha)
            doc['machine']['board'] = 'j293'
            with self.assertRaises(m.Refuse):
                m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            doc = document(gpu, plan, impl, loader_sha)
            doc['machine']['soc'] = 't6030'
            with self.assertRaises(m.Refuse):
                m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            self.assertNotIn('device_id', inspect.getsource(m.accept_run))
            self.assertNotIn('G13G', inspect.getsource(m.oracle_body))
            self.assertNotIn('j293', inspect.getsource(m.oracle_body))
            doc = document(gpu, plan, impl, loader_sha)
            doc['cases'][0]['runs'][0]['measurements']['mismatches'] = 4
            doc['cases'][0]['metrics'] = gpu.metrics_for(doc['cases'][0]['runs'])
            with self.assertRaises(m.Refuse):
                m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            doc = document(gpu, plan, impl, loader_sha)
            doc['cases'][0]['metrics'][2]['statistics']['raw'] = [1]
            with self.assertRaises(m.Refuse):
                m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            doc = document(gpu, plan, impl, loader_sha)
            doc['protocol']['repetitions'] = 8
            with self.assertRaises(m.Refuse):
                m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            doc = document(gpu, plan, impl, loader_sha)
            doc['cases'][2]['runs'][0]['identity']['device_name'] = 'llvmpipe'
            with self.assertRaises(m.Refuse):
                m.oracle_body(doc, plan, impl, {loader_sha}, gpu)
            self.assertNotIn('j293', json.dumps(m.PROTOCOL))
        finally:
            shutil.rmtree(tmp)

    def test_fresh_journal_rejects_gpu_and_dart_on_the_same_boot(self):
        supervisor = m.load_pinned()
        boot = '11111111-2222-3333-4444-555555555555'
        boot_hex = boot.replace('-', '')
        clean = (json.dumps({'_BOOT_ID': boot_hex, 'MESSAGE': 'asahi: allocated'}) + '\n').encode()
        self.assertEqual(m.screen_journal(supervisor.s, boot, clean).categories, set())
        for message in ('asahi: gpu fault', 'apple-dart: fault'):
            raw = (json.dumps({'_BOOT_ID': boot_hex, 'MESSAGE': message}) + '\n').encode()
            with self.assertRaises(supervisor.s.Stop):
                m.screen_journal(supervisor.s, boot, raw)
        other = (json.dumps({'_BOOT_ID': 'ab' * 16, 'MESSAGE': 'ok'}) + '\n').encode()
        with self.assertRaises(supervisor.s.Stop):
            m.screen_journal(supervisor.s, boot, other)

    def test_terminal_success_and_seal_require_real_cleanup(self):
        supervisor = m.load_pinned()
        good = {'ActiveState': 'active', 'SubState': 'exited', 'MainPID': '0', 'ExecMainCode': '1', 'ExecMainStatus': '0', 'Result': 'success'}
        self.assertTrue(supervisor.terminal_success(dict(good)))
        for key, value in (('Result', 'failed'), ('MainPID', '9'), ('SubState', 'running')):
            self.assertFalse(supervisor.terminal_success({**good, key: value}))
        cleanup = {'stopped': True, 'control_group_empty': True}
        signature = {'cryptographic_verification': True, 'existing_public_key_matches': True}
        artifacts = {'journal_final': '/job/journal-final.jsonl', 'observer': '/job/observer-final.json'}
        sealed = m.seal('/job/gpu-block1.json', 'ab' * 32, cleanup, 65, signature, artifacts)
        self.assertEqual(sealed['status'], 'PASS')
        self.assertEqual(sealed['native_invocations'], 65)
        self.assertEqual(sealed['source_commit'], m.COMMIT)
        self.assertEqual(sealed['archive_sha256'], m.ARCHIVE_SHA)
        for bad in (
            dict(cleanup, stopped=False), dict(cleanup, not_created=True),
        ):
            with self.assertRaises(m.Refuse):
                m.seal('/job/gpu-block1.json', 'ab' * 32, bad, 65, signature, artifacts)
        with self.assertRaises(m.Refuse):
            m.seal('/job/gpu-block1.json', 'ab' * 32, cleanup, 64, signature, artifacts)
        self.assertIn('owned_members', m.observe_until_exit.__code__.co_names)
        self.assertIn('release_execution', m.execute.__code__.co_names)
        self.assertIn('record_and_stop', m.release_execution.__code__.co_names)
        self.assertIn('journal_final', m.release_execution.__code__.co_names)
        self.assertIn('terminal_success', m.observe_until_exit.__code__.co_names)

    def test_release_attempts_stop_and_final_journal_and_keeps_the_first_failure(self):
        import inspect
        supervisor = m.load_pinned()
        real_stop = supervisor.record_and_stop
        real_capture = supervisor.s.capture
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            calls = []
            def stop_ok(plan, logs, invocation):
                calls.append('stop')
                return {'stopped': True, 'control_group_empty': True}
            def stop_bad(plan, logs, invocation):
                calls.append('stop')
                raise RuntimeError('stop failed')
            def capture_ok(command, limit=None, timeout=10):
                calls.append(('capture', command[0], timeout, tuple(command)))
                return b''
            def capture_bad(command, limit=None, timeout=10):
                calls.append(('capture', command[0], timeout, tuple(command)))
                raise RuntimeError('final journal failed')
            bound = {'plan': {'boot_id': '11111111-2222-3333-4444-555555555555'}}
            plan = {'prefix': 'unused'}
            invocation = {'id': 'owned'}
            def run(label, stop, capture, failed):
                calls.clear()
                supervisor.record_and_stop = stop
                supervisor.s.capture = capture
                logs = Path(tmp) / label
                logs.mkdir()
                cleanup, error = m.release_execution(supervisor, bound, plan, logs, True, invocation, 'cursor', None, failed)
                self.assertEqual(calls[0], 'stop')
                self.assertEqual(calls[1][0], 'capture')
                self.assertEqual(calls[1][1], 'journalctl')
                self.assertEqual(calls[1][2], 10)
                self.assertIn('--after-cursor=cursor', calls[1][3])
                self.assertTrue((logs / 'journal-final.jsonl').is_file())
                self.assertTrue((logs / 'observer-final.json').is_file())
                observer = json.loads((logs / 'observer-final.json').read_text())
                return cleanup, error, observer, logs
            cleanup, error, observer, logs = run('stop-fails', stop_bad, capture_ok, None)
            self.assertIsNone(cleanup)
            self.assertIsInstance(error, RuntimeError)
            self.assertNotIsInstance(error, m.Refuse)
            self.assertEqual(str(error), 'stop failed')
            self.assertEqual(observer['error'], 'stop failed')
            cleanup, error, observer, logs = run('journal-fails', stop_ok, capture_bad, None)
            self.assertEqual(cleanup, {'stopped': True, 'control_group_empty': True})
            self.assertIsInstance(error, m.Refuse)
            self.assertIn('final journal failed', str(error))
            self.assertNotEqual(getattr(error, 'status', None), 'PASS')
            self.assertEqual((logs / 'journal-final.jsonl').read_bytes(), b'')
            body = m.Refuse('report rejected')
            cleanup, error, observer, logs = run('body-and-stop', stop_bad, capture_ok, body)
            self.assertIs(error, body)
            self.assertEqual(observer['error'], 'report rejected')
            self.assertIn('report rejected', observer['journal_error'])
            cleanup, error, observer, logs = run('both-fail', stop_bad, capture_bad, None)
            self.assertIsInstance(error, RuntimeError)
            self.assertNotIsInstance(error, m.Refuse)
            self.assertEqual(str(error), 'stop failed')
            self.assertNotIn('final journal failed', str(error))
            self.assertEqual((logs / 'journal-final.jsonl').read_bytes(), b'')
            source = inspect.getsource(m.execute)
            except_slice = source.split('except BaseException', 1)[1].split('finally:', 1)[0]
            self.assertNotIn('raise', except_slice)
            tail = source.split('cleanup, failed = release_execution', 1)[1]
            self.assertLess(tail.index('raise failed'), tail.index('return seal'))
            self.assertNotIn('sleep', m.release_execution.__code__.co_names)
        finally:
            supervisor.record_and_stop = real_stop
            supervisor.s.capture = real_capture
            shutil.rmtree(tmp)

    def test_launch_keeps_the_qualified_cgroup_and_binds_only_the_staged_elf(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            plan, manifest, out, env, pins, vulkan, loader = fixture(tmp)
            bound = m.bind(plan, manifest, out, env, pins)
            supervisor = m.load_pinned()
            argv = m.launch_argv(supervisor, bound, Path(tmp) / 'payload' / 'omarchy-m-test', Path(out) / 'gpu-block1.json', Path(out) / 'out', Path(out) / 'err')
            text = '\n'.join(argv)
            for required in ('KillMode=control-group', 'SendSIGKILL=yes', 'RuntimeMaxSec=1800s', 'PrivateMounts=yes',
                             'RemainAfterExit=yes', 'Type=exec', '--benchmark-seed', '42', '--benchmark-repetitions', '7',
                             '--benchmark-block', '1'):
                self.assertIn(required, text)
            self.assertIn(f'BindReadOnlyPaths={vulkan}:{m.SYSTEM_VULKAN}', text)
            self.assertNotIn('--benchmark-repetitions\n8', text)
            self.assertNotIn('RENDER_CHECK_RUNS', text)
            self.assertTrue(m.shared_render([(226, 128)] * 65, {(226, 128)}))
            with self.assertRaises(m.Refuse):
                m.shared_render([(226, 128)] * 64, {(226, 128)})
            with self.assertRaises(m.Refuse):
                m.shared_render([(226, 128)] * 64 + [(226, 129)], {(226, 128), (226, 129)})
        finally:
            shutil.rmtree(tmp)

    def test_run_official_refuses_this_host_before_creating_output(self):
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            plan, manifest, out, env, pins, vulkan, loader = fixture(tmp)
            marker = Path(tmp) / 'not-created'
            self.assertFalse(marker.exists())
            with self.assertRaises(m.Refuse) as caught:
                m.run_official(plan, manifest, out, env, pins)
            self.assertIn('boot', str(caught.exception))
            self.assertFalse(marker.exists())
            self.assertEqual(list(Path(out).iterdir()), [])
            text = Path(m.__file__).read_text()
            for banned in ('pacman', 'reboot', 'ssh-keygen', 'systemctl enable'):
                self.assertNotIn(banned, text)
        finally:
            shutil.rmtree(tmp)

    def test_identity_binds_all_65_and_a_same_process_late_map(self):
        import ctypes, subprocess
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        held_fds = []
        handles = []
        libdl = None
        previous = m.open_held_descriptor
        try:
            plan, manifest, out, env, pins, vulkan, loader = fixture(tmp)
            node = plan['official_identity']['device']['render_node']
            render = (node['major'], node['minor'])
            impl = {'dev': 3, 'inode': 4, 'sha256': 'ab' * 32}
            held_loader = {'dev': 1, 'inode': 2, 'sha256': 'cd' * 32}
            def fill(count, minor):
                seen = {}
                for index in range(count):
                    m.retain_sample(seen, {'pid': index + 1, 'birth': 1, 'workload': 'compute', 'negative': False,
                                           'implementation': impl, 'loader': held_loader, 'renders': [(render[0], minor)]})
                return seen
            finished = m.finish_observations(fill(65, render[1]), {render}, impl, [held_loader], node)
            self.assertEqual(len(finished), 65)
            self.assertTrue(all(item['render'] == render for item in finished))
            with self.assertRaises(m.Refuse):
                m.finish_observations(fill(64, render[1]), {render}, impl, [held_loader], node)
            with self.assertRaises(m.Refuse):
                m.finish_observations(fill(65, render[1] + 1), {render, (render[0], render[1] + 1)}, impl, [held_loader], node)
            pid = os.getpid()
            birth = int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
            late_dir = Path(tmp) / 'late-dlopen'
            late_dir.mkdir()
            source = late_dir / 'late_marker.c'
            source.write_text('void late_marker(void) {}\n')
            built = late_dir / 'late_marker.so'
            compile_env = os.environ.copy()
            compile_env['TMPDIR'] = str(late_dir)
            compiled = subprocess.run(
                ['cc', '-shared', '-fPIC', '-o', str(built), str(source)],
                cwd=late_dir, env=compile_env, capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            blob = built.read_bytes()
            self.assertTrue(blob.startswith(b'\x7fELF') and len(blob) > 64)
            impl_path = (late_dir / 'libvulkan_asahi.so').resolve()
            loader_path = (late_dir / 'libvulkan.so.1').resolve()
            self.assertNotEqual(impl_path, Path(loader).resolve())
            impl_path.write_bytes(blob)
            loader_path.write_bytes(blob)
            self.assertEqual(Path(loader).read_bytes(), b'loader-pin')
            def maps_text():
                return Path(f'/proc/{pid}/maps').read_text()
            self.assertNotIn(str(impl_path), maps_text())
            self.assertNotIn(str(loader_path), maps_text())
            absent = m.provider_maps(pid)
            self.assertIsNone(absent['implementation'])
            self.assertIsNone(absent['loader'])
            libdl = ctypes.CDLL('libdl.so.2', use_errno=True)
            libdl.dlclose.argtypes = [ctypes.c_void_p]
            libdl.dlclose.restype = ctypes.c_int
            impl_lib = ctypes.CDLL(str(impl_path))
            loader_lib = ctypes.CDLL(str(loader_path))
            handles.extend((impl_lib, loader_lib))
            mapped = maps_text()
            self.assertIn(str(impl_path), mapped)
            self.assertIn(str(loader_path), mapped)
            impl_fd = os.open(impl_path, os.O_PATH | os.O_CLOEXEC)
            loader_fd = os.open(loader_path, os.O_PATH | os.O_CLOEXEC)
            held_fds.extend((impl_fd, loader_fd))
            ranges = {}
            for line in mapped.splitlines():
                fields = line.split(None, 5)
                if len(fields) != 6:
                    continue
                text = fields[5][:-len(' (deleted)')] if fields[5].endswith(' (deleted)') else fields[5]
                if text == str(impl_path):
                    ranges[tuple(fields[0].split('-', 1))] = impl_fd
                elif text == str(loader_path):
                    ranges[tuple(fields[0].split('-', 1))] = loader_fd
            self.assertGreaterEqual(len(ranges), 2)
            with self.assertRaises(m.Refuse) as refused:
                m.provider_maps(pid)
            self.assertIn('denied', str(refused.exception))
            opened = []
            def injected(mapped_pid, start, end):
                fd = ranges.get((start, end))
                opened.append(fd is not None)
                if fd is None:
                    return previous(mapped_pid, start, end)
                return os.dup(fd)
            m.open_held_descriptor = injected
            calls = []
            real_identity = m.regular_identity
            def wrapped(path):
                calls.append(str(path))
                return real_identity(path)
            m.regular_identity = wrapped
            try:
                present = m.provider_maps(pid)
            finally:
                m.regular_identity = real_identity
                m.open_held_descriptor = previous
            self.assertTrue(opened and all(opened))
            self.assertFalse(any(path in (str(impl_path), str(loader_path)) for path in calls))
            direct = m.descriptor_identity(impl_fd, 'mapped reference')
            self.assertTrue(m.held_matches(present['implementation'], direct))
            self.assertTrue(m.held_matches(present['loader'], m.descriptor_identity(loader_fd, 'mapped reference')))
            null = os.open('/dev/null', os.O_PATH | os.O_CLOEXEC)
            held_fds.append(null)
            middle_renders = m.char_renders(pid)
            os.close(null)
            held_fds.remove(null)
            for lib in handles:
                self.assertEqual(libdl.dlclose(lib._handle), 0)
                lib._handle = None
            handles.clear()
            self.assertNotIn(str(impl_path), maps_text())
            self.assertNotIn(str(loader_path), maps_text())
            after = m.provider_maps(pid)
            self.assertIsNone(after['implementation'])
            self.assertIsNone(after['loader'])
            seen = {}
            sample = {'pid': pid, 'birth': birth, 'workload': 'compute', 'negative': False}
            m.retain_sample(seen, {**sample, 'implementation': absent['implementation'], 'loader': absent['loader'], 'renders': []})
            m.retain_sample(seen, {**sample, 'implementation': present['implementation'], 'loader': present['loader'], 'renders': middle_renders})
            m.retain_sample(seen, {**sample, 'implementation': after['implementation'], 'loader': after['loader'], 'renders': []})
            self.assertEqual(len(seen), 1)
            self.assertEqual(next(iter(seen)), (pid, birth))
            self.assertTrue(m.held_matches(seen[(pid, birth)]['implementation'], direct))
            item = m.require_held_sample(seen[(pid, birth)], {render}, present['implementation'], [present['loader']], node)
            self.assertEqual(item['render'], render)
            with self.assertRaises(m.Refuse) as caught:
                m.finish_observations(seen, {render}, present['implementation'], [present['loader']], node)
            self.assertIn('observations', str(caught.exception))
        finally:
            m.open_held_descriptor = previous
            if libdl is not None:
                for lib in handles:
                    handle = getattr(lib, '_handle', None)
                    if handle:
                        libdl.dlclose(handle)
                        lib._handle = None
            for fd in held_fds:
                os.close(fd)
            shutil.rmtree(tmp)

    def test_gui_directory_rejects_symlink_replacement_and_keeps_the_destination(self):
        from unittest import mock
        walk = inspect.getsource(m._walk)
        body = inspect.getsource(m.own_gui)
        flags = inspect.getsource(m._dir_open_flags)
        self.assertIn('O_NOFOLLOW', flags)
        self.assertIn('O_DIRECTORY', flags)
        self.assertIn('_dir_open_flags', walk)
        self.assertIn('dir_fd', walk)
        self.assertIn('dir_fd', body)
        self.assertNotIn('os.chmod(', body)
        self.assertNotIn('os.chown(', body)
        self.assertNotIn('exist_ok', body)
        self.assertNotIn('.resolve(', walk + body)
        self.assertIn('os.fchmod(', body)
        self.assertIn('os.fchown(', body)
        uid, gid = os.geteuid(), os.getegid()
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        try:
            def snap(path):
                st = os.lstat(path)
                children = ()
                if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    children = tuple(sorted(os.listdir(path)))
                return (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_dev, st.st_ino, children)

            def directory(path):
                path.mkdir()
                os.chmod(path, 0o700)
                return path

            def privileged(parent):
                target = parent / 'outside'
                target.mkdir()
                os.chmod(target, 0o755)
                marker = target / 'keep'
                marker.write_bytes(b'untouched')
                os.chmod(marker, 0o644)
                return target, marker

            def unchanged(before, paths):
                for path in paths:
                    self.assertEqual(snap(path), before[path])

            def refuse_without_metadata(path):
                def boom(*args, **kwargs):
                    raise AssertionError('pathname metadata')
                with mock.patch.object(os, 'chown', side_effect=boom), \
                     mock.patch.object(os, 'chmod', side_effect=boom), \
                     mock.patch.object(os, 'fchown', side_effect=boom), \
                     mock.patch.object(os, 'fchmod', side_effect=boom):
                    with self.assertRaises(m.Refuse):
                        m.own_gui(path, uid, gid)

            base = directory(Path(tmp) / 'links')
            target, marker = privileged(base)
            parent = directory(base / 'parent')
            run = parent / 'run'
            run.symlink_to(target, target_is_directory=True)
            before = {path: snap(path) for path in (base, target, marker, parent)}
            refuse_without_metadata(run)
            refuse_without_metadata(run / 'home')
            unchanged(before, before)
            run.unlink()
            run = directory(parent / 'run')
            for name in ('home', 'cache', 'reports'):
                link = run / name
                link.symlink_to(target, target_is_directory=True)
                before = {path: snap(path) for path in (base, target, marker, parent, run)}
                refuse_without_metadata(link)
                self.assertTrue(link.is_symlink())
                unchanged(before, before)
                link.unlink()
            home = directory(run / 'home')
            note = home / 'marker'
            note.write_text('private-home')
            home_ino = os.lstat(home).st_ino
            refuse_calls = []
            real_fchown = os.fchown
            def record_fchown(fd, owner, group):
                refuse_calls.append((owner, group))
                return real_fchown(fd, owner, group)
            with mock.patch.object(os, 'chown', side_effect=AssertionError('pathname chown')), \
                 mock.patch.object(os, 'chmod', side_effect=AssertionError('pathname chmod')), \
                 mock.patch.object(os, 'fchown', side_effect=record_fchown), \
                 mock.patch.object(os, 'fchmod', side_effect=AssertionError('fchmod')):
                m.own_gui(home, uid, gid)
            self.assertEqual(refuse_calls, [])
            self.assertEqual(os.lstat(home).st_ino, home_ino)
            self.assertEqual(stat.S_IMODE(os.lstat(home).st_mode), 0o700)
            self.assertEqual((os.lstat(home).st_uid, os.lstat(home).st_gid), (uid, gid))
            self.assertFalse(stat.S_ISLNK(os.lstat(home).st_mode))
            self.assertEqual(note.read_text(), 'private-home')
            loose = directory(run / 'loose')
            os.chmod(loose, 0o755)
            loose_mode = os.lstat(loose).st_mode
            refuse_without_metadata(loose)
            self.assertEqual(os.lstat(loose).st_mode, loose_mode)
            payload = run / 'file'
            payload.write_bytes(b'kept-bytes')
            os.chmod(payload, 0o644)
            refuse_without_metadata(payload)
            self.assertEqual(payload.read_bytes(), b'kept-bytes')
            self.assertEqual(stat.S_IMODE(os.lstat(payload).st_mode), 0o644)
            fresh_parent = directory(Path(tmp) / 'fresh')
            parent_ino = os.lstat(fresh_parent).st_ino
            created = fresh_parent / 'cache'
            self.assertFalse(created.exists())
            m.own_gui(created, uid, gid)
            st = os.lstat(created)
            self.assertTrue(stat.S_ISDIR(st.st_mode))
            self.assertFalse(stat.S_ISLNK(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
            self.assertEqual((st.st_uid, st.st_gid), (uid, gid))
            self.assertEqual(os.lstat(fresh_parent).st_ino, parent_ino)
            again = os.lstat(created).st_ino
            m.own_gui(created, uid, gid)
            self.assertEqual(os.lstat(created).st_ino, again)
            self.assertEqual(snap(target), (0o755, uid, gid, target.lstat().st_dev, target.lstat().st_ino, ('keep',)))
            self.assertEqual(marker.read_bytes(), b'untouched')
        finally:
            shutil.rmtree(tmp)

    def test_retired_map_is_admitted_only_after_complete_evidence(self):
        from unittest import mock
        pid = os.getpid()
        try:
            os.close(m.open_held_descriptor(pid, '1', '2'))
            self.fail('missing range opened')
        except m.RangeUnavailable as unavailable:
            self.assertEqual(unavailable.pid, pid)
            self.assertNotIsInstance(unavailable, FileNotFoundError)
            self.assertIn('absent', str(unavailable))
        except m.Refuse as refused:
            self.assertIn('denied', str(refused))
            self.assertNotIsInstance(refused, m.RangeUnavailable)
        real_open = os.open
        def missing(path, flags, *args, **kwargs):
            if isinstance(path, str) and '/map_files/' in path:
                raise FileNotFoundError(2, 'normal VMA retirement')
            return real_open(path, flags, *args, **kwargs)
        def denied(path, flags, *args, **kwargs):
            if isinstance(path, str) and '/map_files/' in path:
                raise PermissionError(1, 'denied')
            return real_open(path, flags, *args, **kwargs)
        def vanished(path, flags, *args, **kwargs):
            if isinstance(path, str) and '/map_files/' in path:
                raise ProcessLookupError(3, 'gone')
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(os, 'open', side_effect=missing):
            with self.assertRaises(m.RangeUnavailable) as caught:
                m.open_held_descriptor(pid, '1000', '2000')
            self.assertNotIsInstance(caught.exception, FileNotFoundError)
        with mock.patch.object(os, 'open', side_effect=denied):
            with self.assertRaises(m.Refuse) as caught:
                m.open_held_descriptor(pid, '1000', '2000')
            self.assertIn('denied', str(caught.exception))
            self.assertNotIsInstance(caught.exception, m.RangeUnavailable)
            self.assertNotIsInstance(caught.exception, m.ProcessUnavailable)
        with mock.patch.object(os, 'open', side_effect=vanished):
            unavailable = None
            with self.assertRaises(m.ProcessUnavailable) as caught:
                m.open_held_descriptor(pid, '1000', '2000')
            unavailable = caught.exception
            self.assertEqual(unavailable.pid, pid)
            self.assertNotIsInstance(unavailable, m.RangeUnavailable)
        classify_body = inspect.getsource(m.classify_process)
        self.assertNotIn('RangeUnavailable', classify_body)
        self.assertNotIn('ProcessUnavailable', classify_body)
        self.assertIn('except FileNotFoundError', classify_body)
        expected = Path(f'/proc/{pid}/exe').resolve()
        real_read = Path.read_bytes
        def read_bytes(self, *args, **kwargs):
            if str(self) == f'/proc/{pid}/cmdline':
                return str(expected).encode() + b'\0--workload\0compute\0'
            return real_read(self, *args, **kwargs)
        bound = {'plan': {'gui_uid': os.getuid()}}
        with mock.patch.object(Path, 'read_bytes', autospec=True, side_effect=read_bytes), \
             mock.patch.object(m, 'char_renders', return_value=[(226, 128)]), \
             mock.patch.object(m, 'provider_maps', side_effect=m.RangeUnavailable(pid, '1000', '2000')):
            with self.assertRaises(m.RangeUnavailable):
                m.classify_process(pid, 1, expected, bound, check_exe=False)
        impl = {'dev': 3, 'inode': 4, 'sha256': 'ab' * 32}
        loader = {'dev': 1, 'inode': 2, 'sha256': 'cd' * 32}
        birth = 7
        complete = {'implementation': impl, 'loader': loader, 'renders': [(226, 128)]}
        seen = {(pid, birth): dict(complete)}
        completions = []
        with self.assertRaises(m.RangeUnavailable):
            m.note_unavailable({}, completions, pid, birth, m.RangeUnavailable(pid, '1000', '2000'))
        partial = {'implementation': impl, 'loader': None, 'renders': [(226, 128)]}
        with self.assertRaises(m.RangeUnavailable):
            m.note_unavailable({(pid, birth): partial}, completions, pid, birth, m.RangeUnavailable(pid, '1000', '2000'))
        self.assertIsNone(partial['loader'])
        with self.assertRaises(m.RangeUnavailable):
            m.note_unavailable(seen, completions, pid, birth + 1, m.RangeUnavailable(pid, '1000', '2000'))
        with self.assertRaises(m.RangeUnavailable) as foreign:
            m.note_unavailable(seen, completions, pid, birth, m.RangeUnavailable(pid + 1, '1000', '2000'))
        self.assertEqual(foreign.exception.pid, pid + 1)
        self.assertEqual(completions, [])
        m.note_unavailable(seen, completions, pid, birth, m.RangeUnavailable(pid, '1000', '2000'))
        m.note_unavailable(seen, completions, pid, birth, m.RangeUnavailable(pid, '1000', '2000'))
        m.note_unavailable(seen, completions, pid, birth, m.ProcessUnavailable(pid))
        self.assertEqual([(event.pid, event.birth, event.phase) for event in completions],
                         [(pid, birth, 'range'), (pid, birth, 'process')])
        self.assertTrue(m.held_matches(seen[(pid, birth)]['implementation'], impl))
        many = []
        for index in range(m.RETIREMENT_CAP):
            m.note_unavailable({(index + 1, birth): dict(complete)}, many, index + 1, birth, m.RangeUnavailable(index + 1, '1', '2'))
        with self.assertRaises(m.Refuse) as capped:
            m.note_unavailable({(99999, birth): dict(complete)}, many, 99999, birth, m.RangeUnavailable(99999, '1', '2'))
        self.assertIn('budget', str(capped.exception))
        self.assertEqual(len(many), m.RETIREMENT_CAP)
        real_text = Path.read_text
        def deleted_text(self, *args, **kwargs):
            if self.name == 'maps':
                return '1000-2000 r-xp 00000000 00:00 1 /usr/lib/libvulkan_asahi.so (deleted)\n'
            return real_text(self, *args, **kwargs)
        with mock.patch.object(Path, 'read_text', autospec=True, side_effect=deleted_text):
            with self.assertRaises(m.Refuse) as deleted:
                m.provider_maps(pid)
            self.assertIn('deleted provider', str(deleted.exception))
            self.assertNotIsInstance(deleted.exception, m.RangeUnavailable)
        def unknown_deleted(self, *args, **kwargs):
            if self.name == 'maps':
                return '1000-2000 r-xp 00000000 00:00 1 /usr/lib/libc.so.6 (deleted)\n'
            return real_text(self, *args, **kwargs)
        with mock.patch.object(Path, 'read_text', autospec=True, side_effect=unknown_deleted):
            found = m.provider_maps(pid)
        self.assertIsNone(found['implementation'])
        self.assertIsNone(found['loader'])
        other = {'dev': os.makedev(0, 24), 'inode': impl['inode'], 'sha256': impl['sha256']}
        self.assertFalse(m.held_matches(other, impl))
        node = {'major': 226, 'minor': 128}
        item = {'pid': pid, 'birth': birth, 'workload': 'compute', 'negative': False, **complete}
        event = completions[0]
        with self.assertRaises(m.Refuse) as early:
            m.check_completions([dict(item)], [event], False, {(226, 128)}, impl, [loader], node)
        self.assertIn('retirement exit', str(early.exception))
        with self.assertRaises(m.Refuse):
            m.check_completions([dict(item)], [m.RetiredEvent(pid + 5, birth, 'range')], True, {(226, 128)}, impl, [loader], node)
        with self.assertRaises(m.Refuse):
            m.check_completions([dict(item)], [{'pid': pid, 'birth': birth, 'phase': 'range'}], True, {(226, 128)}, impl, [loader], node)
        m.check_completions([dict(item)], [], True, {(226, 128)}, impl, [loader], node)
        m.check_completions([dict(item)], [m.RetiredEvent(pid, birth, 'range')], True, {(226, 128)}, impl, [loader], node)
        source = inspect.getsource(m.execute)
        self.assertLess(source.index('oracle_body'), source.index('check_completions'))
        self.assertLess(source.index('require_order'), source.index('check_completions'))
        held = os.open(Path(m.__file__), os.O_PATH | os.O_CLOEXEC)
        cache = {}
        calls = []
        real_identity = m.descriptor_identity
        def identity(fd, label):
            calls.append(label)
            return real_identity(fd, label)
        try:
            with mock.patch.object(m, 'open_held_descriptor', side_effect=lambda *args: os.dup(held)), \
                 mock.patch.object(m, 'descriptor_identity', side_effect=identity):
                first = m.kernel_held_map(pid, '1000', '2000', cache)
                second = m.kernel_held_map(pid, '3000', '4000', cache)
            self.assertEqual(calls, ['mapped reference'])
            self.assertIs(first, second)
            self.assertEqual(len(cache), 1)
            cache.clear()
            calls.clear()
            def fail_once(fd, label):
                if not calls:
                    calls.append(label)
                    raise m.Refuse('mapped reference denied')
                return {'dev': 9, 'inode': 9, 'size': 1, 'sha256': 'ab' * 32}
            class Stat:
                def __init__(self, inode):
                    self.st_dev = 9
                    self.st_ino = inode
                    self.st_size = 1
                    self.st_mtime_ns = 1
                    self.st_ctime_ns = 1
            inodes = {'n': 0}
            def next_stat(fd):
                inodes['n'] += 1
                return Stat(inodes['n'])
            with mock.patch.object(m, 'open_held_descriptor', side_effect=lambda *args: os.dup(held)), \
                 mock.patch.object(m, 'descriptor_identity', side_effect=fail_once), \
                 mock.patch.object(os, 'fstat', side_effect=next_stat):
                with self.assertRaises(m.Refuse):
                    m.kernel_held_map(pid, '1000', '2000', cache)
                self.assertEqual(cache, {})
                m.kernel_held_map(pid, '1000', '2000', cache)
                self.assertEqual(len(cache), 1)
                for index in range(m.IDENTITY_CACHE_CAP - 1):
                    m.kernel_held_map(pid, '1000', '2000', cache)
                with self.assertRaises(m.Refuse) as budget:
                    m.kernel_held_map(pid, '1000', '2000', cache)
            self.assertIn('descriptor cache budget', str(budget.exception))
            self.assertEqual(len(cache), m.IDENTITY_CACHE_CAP)
        finally:
            os.close(held)

    def test_observer_samples_inside_the_helper_grace(self):
        bench = m.Q / 'worktree' / 'cli' / 'omarchy_m_test' / 'gpu_native' / 'benchmark.c'
        text = bench.read_text()
        self.assertIn('struct timespec grace = {.tv_nsec = 400000000};', text)
        self.assertEqual(m.SAMPLE_S, 0.02)
        self.assertLessEqual(m.SAMPLE_S, 0.4)
        self.assertEqual(m.MANAGER_S, 0.5)
        self.assertIn('selector.select(0.02)', Path(m.SUPERVISOR_PATH).read_text())
        self.assertNotIn('sleep(0.5)', inspect.getsource(m.observe_until_exit))
        self.assertIn('identity_cache = {}', inspect.getsource(m.observe_until_exit))
        clock = {'ms': 0}
        state_calls = []
        classify_at = []
        health_at = []
        def monotonic():
            return clock['ms'] / 1000
        def sleep(seconds):
            self.assertEqual(seconds, m.SAMPLE_S)
            clock['ms'] += round(seconds * 1000)
        supervisor = m.load_pinned()
        real_state = supervisor.unit_state
        real_members = supervisor.owned_members
        real_journal = supervisor.s.Journal
        real_verify = supervisor.s.verify_staged
        real_health = supervisor.s.health_snapshot
        real_open = m.open_fault_monitor
        real_poll = m.poll_fault_monitor
        real_classify = m.classify_process
        impl = {'dev': 3, 'inode': 4, 'sha256': 'ab' * 32}
        loader = {'dev': 1, 'inode': 2, 'sha256': 'cd' * 32}
        def unit_state(unit):
            state_calls.append(clock['ms'])
            if clock['ms'] >= 500:
                return {'ActiveState': 'active', 'SubState': 'exited', 'MainPID': '0',
                        'ExecMainCode': '1', 'ExecMainStatus': '0', 'Result': 'success'}
            return {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '42'}
        def owned_members(plan, state, invocation):
            if 100 <= clock['ms'] <= 300:
                return [(4242, 'birth')]
            return []
        def classify(pid, birth, expected, bound, check_exe=True, cache=None):
            classify_at.append(clock['ms'])
            self.assertIsInstance(cache, dict)
            return {'pid': pid, 'birth': birth, 'workload': 'compute', 'negative': False,
                    'renders': [(226, 128)], 'implementation': impl, 'loader': loader}
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        original_monotonic = m.time.monotonic
        original_sleep = m.time.sleep
        try:
            m.time.monotonic = monotonic
            m.time.sleep = sleep
            supervisor.unit_state = unit_state
            supervisor.owned_members = owned_members
            supervisor.s.Journal = lambda boot: object()
            supervisor.s.verify_staged = lambda *args: health_at.append(clock['ms'])
            supervisor.s.health_snapshot = lambda *args: health_at.append(clock['ms'])
            m.open_fault_monitor = lambda cursor: type('Watch', (), {'poll': lambda self: 0, 'pid': 1})()
            m.poll_fault_monitor = lambda watch, journal: None
            m.classify_process = classify
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            bound = {'plan': {'boot_id': boot, 'official_identity': {'device': {'render_node': {'major': 226, 'minor': 128}}}},
                     'staged_identity': {'vulkan': impl},
                     'graphics_before': {'/usr/lib/libvulkan.so.1': loader}}
            plan = {'prefix': '/var/tmp/sf-official-gpu-full-1234567890abcdef'}
            with self.assertRaises(m.Refuse) as caught:
                m.observe_until_exit(supervisor, bound, Path(tmp), plan, {}, 'invocation', 'cursor', Path(tmp), b'')
            self.assertIn('observations', str(caught.exception))
            self.assertTrue(classify_at)
            self.assertTrue(all(100 <= stamp <= 300 for stamp in classify_at))
            self.assertEqual(state_calls, [0, 500])
            self.assertEqual(health_at, [0, 0])
            self.assertLess(clock['ms'], 1800 * 1000)
            self.assertNotIn(0.5, [m.SAMPLE_S])
        finally:
            m.time.monotonic = original_monotonic
            m.time.sleep = original_sleep
            supervisor.unit_state = real_state
            supervisor.owned_members = real_members
            supervisor.s.Journal = real_journal
            supervisor.s.verify_staged = real_verify
            supervisor.s.health_snapshot = real_health
            m.open_fault_monitor = real_open
            m.poll_fault_monitor = real_poll
            m.classify_process = real_classify
            shutil.rmtree(tmp)

    def test_cleanup_deadline_includes_kill_group_and_stays_inside_the_reserve(self):
        supervisor = m.load_pinned()
        real_capture = supervisor.s.capture
        properties = (
            'Description', 'LimitFSIZE', 'LoadState', 'ActiveState', 'SubState', 'Transient', 'User', 'Group',
            'Type', 'RemainAfterExit', 'KillMode', 'SendSIGKILL', 'TimeoutStopUSec', 'RuntimeMaxUSec', 'UMask',
            'MainPID', 'ControlGroup', 'InvocationID', 'Result', 'ExecMainCode', 'ExecMainStatus')
        unit = 'sf-official-gpu-full-1234567890abcdef.service'
        plan = {'prefix': '/var/tmp/sf-official-gpu-full-1234567890abcdef', 'gui_uid': os.getuid(), 'gui_gid': os.getgid()}
        invocation = 'a' * 32
        def show(active, sub, pid):
            values = {
                'Description': 'official-gpu:' + m.COMMIT + ':1234567890abcdef',
                'LimitFSIZE': '4194304', 'LoadState': 'loaded', 'ActiveState': active, 'SubState': sub,
                'Transient': 'yes', 'User': str(os.getuid()), 'Group': str(os.getgid()), 'Type': 'exec',
                'RemainAfterExit': 'yes', 'KillMode': 'control-group', 'SendSIGKILL': 'yes',
                'TimeoutStopUSec': '5s', 'RuntimeMaxUSec': '30min', 'UMask': '0077', 'MainPID': pid,
                'ControlGroup': '/system.slice/' + unit, 'InvocationID': invocation,
                'Result': 'success', 'ExecMainCode': '1', 'ExecMainStatus': '0'}
            self.assertEqual(set(values), set(properties))
            return ''.join(key + '=' + value + '\n' for key, value in values.items()).encode()
        tmp = tempfile.mkdtemp(dir=Path(m.__file__).parent)
        original_monotonic = m.time.monotonic
        original_sleep = m.time.sleep
        clock = {'ms': 0}
        def monotonic():
            return clock['ms'] / 1000
        def forbid_sleep(seconds):
            raise AssertionError('cleanup slept')
        try:
            m.time.monotonic = monotonic
            m.time.sleep = forbid_sleep
            class Watch:
                def __init__(self):
                    self.pid = os.getpid()
                    self.done = None
                def poll(self):
                    return self.done
                def wait(self, timeout):
                    self.waited = timeout
                    clock['ms'] += round(timeout * 1000)
                    self.done = 0
            watch = Watch()
            bound = {'plan': {'boot_id': '11111111-2222-3333-4444-555555555555'}}
            real_killpg = os.killpg
            os.killpg = lambda pid, sig: None
            try:
                m.close_fault_monitor(watch, bound)
            finally:
                os.killpg = real_killpg
            self.assertEqual(watch.waited, m.MONITOR_CLOSE_S)
            self.assertEqual(clock['ms'], m.MONITOR_CLOSE_S * 1000)
            self.assertEqual(bound['cleanup_deadline'], m.CALLER_CLEANUP_RESERVE_S)
            recorded = []
            shows = {'n': 0}
            stops = {'n': 0}
            def slow(command, limit=None, timeout=10):
                recorded.append((tuple(command[:2]), timeout))
                clock['ms'] += round((timeout + m.KILL_GROUP_S) * 1000)
                if command[:2] == ['systemctl', 'show']:
                    shows['n'] += 1
                    if shows['n'] >= 3:
                        return show('failed', 'failed', '0')
                    return show('active', 'running', '42')
                if command[:2] == ['systemctl', 'stop']:
                    stops['n'] += 1
                    if stops['n'] == 1:
                        raise supervisor.s.Stop('first stop timeout')
                    return b''
                if command[:2] in (['systemctl', 'kill'], ['systemctl', 'reset-failed'], ['journalctl', '-k']):
                    return b''
                raise AssertionError(command)
            supervisor.s.capture = slow
            logs = Path(tmp) / 'slow'
            logs.mkdir()
            cleanup, error = m.release_execution(supervisor, bound, plan, logs, True, invocation, 'cursor', None, None)
            self.assertIsInstance(error, m.Refuse)
            self.assertIn('cleanup deadline', str(error))
            self.assertNotEqual(getattr(error, 'status', None), 'PASS')
            self.assertLessEqual(clock['ms'], m.CALLER_CLEANUP_RESERVE_S * 1000)
            self.assertTrue((logs / 'journal-final.jsonl').is_file())
            self.assertTrue((logs / 'observer-final.json').is_file())
            self.assertIn((('systemctl', 'stop'), 12), recorded)
            self.assertIn((('systemctl', 'kill'), 5), recorded)
            self.assertNotIn((('journalctl', '-k'), 10), recorded)
            self.assertGreater(m.DECLARED_CLEANUP_ALLOWANCE_S + m.MONITOR_CLOSE_S + 8 * m.KILL_GROUP_S, m.CALLER_CLEANUP_RESERVE_S)
            clock['ms'] = 0
            recorded.clear()
            shows['n'] = 0
            stops['n'] = 0
            bound.pop('cleanup_deadline', None)
            def fast(command, limit=None, timeout=10):
                recorded.append((tuple(command[:2]), timeout))
                if command[:2] == ['systemctl', 'show']:
                    shows['n'] += 1
                    if shows['n'] >= 3:
                        return show('inactive', 'dead', '0')
                    return show('active', 'running', '42')
                if command[0] == 'journalctl':
                    return b''
                return b''
            supervisor.s.capture = fast
            logs = Path(tmp) / 'fast'
            logs.mkdir()
            started = clock['ms']
            cleanup, error = m.release_execution(supervisor, bound, plan, logs, True, invocation, 'cursor', None, None)
            self.assertIsNone(error)
            self.assertEqual(cleanup['control_group_empty'], True)
            self.assertEqual(cleanup['stopped'], True)
            self.assertIn((('journalctl', '-k'), 10), recorded)
            self.assertIn((('systemctl', 'stop'), 12), recorded)
            self.assertEqual(clock['ms'], started)
            self.assertLess(clock['ms'], m.CALLER_CLEANUP_RESERVE_S * 1000)
            self.assertNotIn('sleep', m.release_execution.__code__.co_names)
            self.assertNotIn('WatchdogSec', Path(m.__file__).read_text())
        finally:
            m.time.monotonic = original_monotonic
            m.time.sleep = original_sleep
            supervisor.s.capture = real_capture
            shutil.rmtree(tmp)

if __name__ == '__main__':
    unittest.main(verbosity=2)
