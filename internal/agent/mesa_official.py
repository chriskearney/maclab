#!/usr/bin/env python3
"""Optional official 65 adapter for a staged Mesa job. Source until root review.

Imports pinned full-supervisor 10e5805c and guard f65d169c. It does not rewrite
the workload, schema, raw statistics, signature check, cgroup terminal race, or
journal fault vocabulary. Installed-desktop mode is refused. This module does
not install packages, restart the machine, deploy, or create a key.

The qualified helper replaces its environment and accepts a provider only when
the mapped path is under /usr/lib. Staged LD_LIBRARY_PATH therefore never
reaches it. The transient unit bind-mounts the staged Vulkan ELF read-only onto
/usr/lib/libvulkan_asahi.so in that unit's mount namespace. The host file and
system_graphics_pins must stay unchanged. A maps text device is not identity.
The kernel-held map_files reference must match the staged file's device, inode,
and bytes. Signing state comes only from plan.signing_state_home and
official_identity. A private HOME or a prefix-local state directory is not a
signing path. The caller reserves 60s for cleanup. Pinned unit-state, stop,
kill, reset-failed, and final-journal allowances are 59s, the monitor close is
2s, and each capture can then spend 7s in kill_group. That worst path does not
fit in 60s. A shared deadline at the caller reserve refuses another wait that
would pass it. Both cleanup phases are still attempted while time remains.
The first failure is kept. Cleanup does not salvage a pass. This module adds
no watchdog and does not enable official execution.
"""
from pathlib import Path
import hashlib, importlib.util, json, os, re, stat, time

Q = Path('/home/chrisk/.cache/sf-coordination-20261025/official-gpu-admission')
SUPERVISOR_PATH = Q / 'full-guard-r2' / 'full-supervisor.py'
GUARD_PATH = Q / 'rerun-guard' / 'admission-supervisor.py'
SUPERVISOR_SHA = '10e5805c5f8c6eaf3149f0d846813191a536c02b69d3cd6a609065f38339db0a'
GUARD_SHA = 'f65d169c599f08213632849090c75a8e6f4499ed85691baff2e21890821c0efe'
COMMIT = 'e81d80938876c906b64c4e3f31f76c6c33ba95b1'
ARCHIVE_SHA = 'f209493b34e13e2985b1752c147a33a9a45e3e2eac99eb9606ae5a664c252f99'
ARCHIVE_BYTES = 372821
HELPER_SHA = '059ccbce35f2154bc4c62984bddcbb1c4dabd6ad8e4d580482233412f52a8af0'
SOURCE_SHA = 'bc615d52a927d0b26e20e31bf699176c19e127c5cfcfb5e5b52f2d648a13677b'
GL_PROBE_SHA = '24007754c92e05220edc4645702853ac86c0ff5d98c084da126955ccdd4d6e82'
VK_PROBE_SHA = 'e4a7b8d50c10d1cc3bf40c1dcaf9e74cd566ebb1901857e84b06256bbdf0d40d'
SCHEMA = 1
WALL = 1800
HASH_LIMIT = 512 * 1024 ** 2
SYSTEM_VULKAN = '/usr/lib/libvulkan_asahi.so'
KEY_RELATIVE = 'omarchy-m-test/machine-key.pub'
WORKLOADS = ('raster', 'texture', 'compute', 'copy', 'submit-single', 'submit-batched', 'bo-lifetime')
PROTOCOL = {'warmups': 2, 'repetitions': 7, 'order_seed': 42, 'declared_boot_block': 1,
            'api_scope': 'native-vulkan-1.2-offscreen', 'upload': 'never'}
HEX64 = re.compile(r'^[0-9a-f]{64}$')
HEX_ADDR = re.compile(r'^[0-9a-f]+$')
BOOT = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
JOB = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
PUBKEY = re.compile(r'^ssh-ed25519 [A-Za-z0-9+/]{40,100}={0,2}$')
SESSION_KEYS = {'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'WAYLAND_DISPLAY', 'DISPLAY',
                 'XDG_SESSION_TYPE', 'XDG_CURRENT_DESKTOP', 'HYPRLAND_INSTANCE_SIGNATURE'}
PRIVATE_KEYS = ('HOME', 'TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME')
DROPPED = {'LIBGL_DRIVERS_PATH', 'GBM_BACKENDS_PATH'}
FORBIDDEN = {
    'LD_PRELOAD', 'LD_AUDIT', 'VK_ADD_DRIVER_FILES', 'VK_LAYER_PATH', 'VK_LOADER_LAYERS_ENABLE',
    'VK_LOADER_DRIVERS_SELECT', '__GLX_VENDOR_LIBRARY_NAME',
    'LIBGL_ALWAYS_SOFTWARE', 'GBM_ALWAYS_SOFTWARE', 'GALLIUM_DRIVER',
    'MESA_LOADER_DRIVER_OVERRIDE', 'MESA_GL_VERSION_OVERRIDE', 'MESA_VK_DEVICE_SELECT', 'MESA_M3_FALLBACK',
}
REPORT_CAP = 4 * 1024 ** 2
PUB_LIMIT = 16384
SAMPLE_S = 0.02
MANAGER_S = 0.5
MONITOR_CLOSE_S = 2
KILL_GROUP_S = 2 + 3 + 2
UNIT_STATE_S = 5
STOP_COMMAND_S = 12
KILL_COMMAND_S = 5
RESET_FAILED_S = 5
JOURNAL_S = 10
DECLARED_CLEANUP_ALLOWANCE_S = (3 * UNIT_STATE_S + STOP_COMMAND_S + KILL_COMMAND_S
                                 + STOP_COMMAND_S + RESET_FAILED_S + JOURNAL_S)
CALLER_CLEANUP_RESERVE_S = 60
RETIREMENT_CAP = 128
IDENTITY_CACHE_CAP = 64
FILE_FIELDS = ('path', 'type', 'dev', 'inode', 'mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns')
RENDER_FIELDS = ('path', 'major', 'minor', 'mode', 'uid', 'gid', 'dev', 'inode')
SOC_TOKEN = re.compile(r'^apple,t[0-9a-f]+$')
SESSION_REJECT = {'HOME', 'USER', 'LOGNAME', 'XDG_SESSION_ID'}
BAD_TEXT = re.compile(r'llvmpipe|lavapipe|softpipe|software raster|mesa-m3|/opt/mesa-m3', re.I)
UNIT_PROPERTIES = (
    'Type=exec', 'RemainAfterExit=yes', 'KillMode=control-group', 'SendSIGKILL=yes',
    'TimeoutStopSec=5s', 'RuntimeMaxSec=1800s', 'LimitFSIZE=4194304', 'UMask=0077',
)

class Refuse(RuntimeError):
    pass

class RangeUnavailable(Refuse):
    """One mapped range disappeared. This is not a missing process."""
    def __init__(self, pid, start, end):
        super().__init__('mapped reference absent')
        self.pid = pid
        self.start = start
        self.end = end

class ProcessUnavailable(Refuse):
    """The sampled process is gone. This is not a permission denial."""
    def __init__(self, pid):
        super().__init__('mapped process absent')
        self.pid = pid

class RetiredEvent:
    """Admitted retirement of one already-complete pid and birth."""
    def __init__(self, pid, birth, phase):
        self.pid = pid
        self.birth = birth
        self.phase = phase

def need(value, reason):
    if not value:
        raise Refuse(reason)

def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()

def descriptor_identity(fd, label):
    """Bounded hash of an already-open kernel reference. The caller owns fd."""
    st = os.fstat(fd)
    need(stat.S_ISREG(st.st_mode), label + ' is not a regular file')
    need(0 < st.st_size <= HASH_LIMIT, label + ' size')
    key = (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    read = os.open(f'/proc/self/fd/{fd}', os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        blob = bytearray()
        deadline = time.monotonic() + 5
        while len(blob) < st.st_size:
            need(time.monotonic() < deadline, label + ' read exceeded 5s')
            try:
                chunk = os.read(read, min(1024 ** 2, st.st_size - len(blob) + 1))
            except BlockingIOError:
                raise Refuse(label + ' read would block') from None
            need(chunk, label + ' read short')
            blob.extend(chunk)
            need(len(blob) <= st.st_size, label + ' read grew')
        after = os.fstat(read)
        after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        need(after_key == key and len(blob) == st.st_size, label + ' identity changed during read')
    finally:
        os.close(read)
    return {'dev': st.st_dev, 'inode': st.st_ino, 'size': st.st_size, 'uid': st.st_uid, 'gid': st.st_gid,
            'mode': stat.S_IMODE(st.st_mode), 'sha256': sha_bytes(blob), 'magic': bytes(blob[:4])}

def regular_identity(path):
    """O_PATH on a path, then a bounded nonblocking read. Refuse a link, device, or FIFO."""
    raw = os.fspath(path)
    fd = os.open(raw, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        ident = descriptor_identity(fd, 'regular')
        st = os.fstat(fd)
    finally:
        os.close(fd)
    again = os.lstat(raw)
    need((again.st_dev, again.st_ino, again.st_mode, again.st_uid, again.st_gid, again.st_size, again.st_mtime_ns, again.st_ctime_ns) ==
         (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns, st.st_ctime_ns), 'path identity changed')
    need(ident['dev'] == st.st_dev and ident['inode'] == st.st_ino and ident['size'] == st.st_size, 'regular identity changed')
    return {'path': str(Path(raw).resolve()), **ident}

def held_matches(held, pinned):
    """Same file means descriptor device, inode, and bytes. Inode number alone does not."""
    return (isinstance(held, dict) and isinstance(pinned, dict)
            and isinstance(held.get('dev'), int) and isinstance(held.get('inode'), int)
            and HEX64.fullmatch(str(held.get('sha256', ''))) is not None
            and held.get('dev') == pinned.get('dev') and held.get('inode') == pinned.get('inode')
            and held.get('sha256') == pinned.get('sha256'))

def open_held_descriptor(pid, start, end):
    """Open /proc/pid/map_files/<range>. O_PATH follows the kernel reference."""
    need(isinstance(pid, int) and pid > 0, 'mapped pid')
    need(HEX_ADDR.fullmatch(start) and HEX_ADDR.fullmatch(end) and int(start, 16) < int(end, 16), 'mapped range')
    raw = f'/proc/{pid}/map_files/{start}-{end}'
    try:
        return os.open(raw, os.O_PATH | os.O_CLOEXEC)
    except PermissionError:
        raise Refuse('mapped reference denied') from None
    except FileNotFoundError:
        raise RangeUnavailable(pid, start, end) from None
    except ProcessLookupError:
        raise ProcessUnavailable(pid) from None

def kernel_held_map(pid, start, end, cache=None):
    """Identity of one kernel-held mapping. The descriptor is not the live path.

    cache is owned by one observe call. A miss stores a successful identity.
    A failure is not stored. The cache is not evicted and is not global.
    """
    fd = open_held_descriptor(pid, start, end)
    try:
        st = os.fstat(fd)
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if cache is not None and key in cache:
            return cache[key]
        ident = descriptor_identity(fd, 'mapped reference')
        if cache is not None:
            need(len(cache) < IDENTITY_CACHE_CAP, 'descriptor cache budget')
            cache[key] = ident
        return ident
    finally:
        os.close(fd)

def under(path, root):
    return Path(path).is_absolute() and Path(root).is_absolute() and Path(path).resolve().is_relative_to(Path(root).resolve())

def read_regular(path, limit):
    """One O_NOFOLLOW read. The returned bytes are the bytes that were hashed."""
    raw = os.fspath(path)
    fd = os.open(raw, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode), 'bounded is not a regular file')
        need(0 < st.st_size <= limit, 'bounded size')
        key = (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        read = os.open(f'/proc/self/fd/{fd}', os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    finally:
        os.close(fd)
    try:
        blob = bytearray()
        deadline = time.monotonic() + 5
        while len(blob) < st.st_size:
            need(time.monotonic() < deadline, 'bounded read exceeded 5s')
            try:
                chunk = os.read(read, min(1024 ** 2, st.st_size - len(blob) + 1))
            except BlockingIOError:
                raise Refuse('bounded read would block') from None
            need(chunk, 'bounded read short')
            blob.extend(chunk)
            need(len(blob) <= st.st_size, 'bounded read grew')
        after = os.fstat(read)
        after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        need(after_key == key and len(blob) == st.st_size, 'bounded identity changed during read')
    finally:
        os.close(read)
    again = os.lstat(raw)
    need((again.st_dev, again.st_ino, again.st_mode, again.st_uid, again.st_gid, again.st_size, again.st_mtime_ns, again.st_ctime_ns) == key, 'path identity changed')
    body = bytes(blob)
    return {'dev': st.st_dev, 'inode': st.st_ino, 'size': st.st_size, 'sha256': sha_bytes(body), 'magic': body[:4]}, body

def exec_verified(name, raw):
    """Execute the pinned bytes. Do not read a path again."""
    import types
    module = types.ModuleType(name)
    module.__dict__['__file__'] = '<verified:' + name + '>'
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module

def layout_paths(bound):
    prefix = Path(bound['manifest']['prefix'])
    official = prefix / 'official'
    return {'payload_root': official / 'payload', 'logs': official / 'root',
            'report': prefix / 'run' / 'reports' / 'gpu-block1.json',
            'stdout': official / 'root' / 'child.stdout', 'stderr': official / 'root' / 'child.stderr'}

def clean_absolute(value, label):
    path = Path(value) if isinstance(value, str) else None
    need(path is not None and value and path.is_absolute() and str(path) == value, label)
    need('..' not in path.parts and not any(c in value for c in ('\0', '\n', '\r', ':')), label)
    return path

def integer_field(value, label):
    need(type(value) is int and value >= 0, label)
    return value

def signing_state_path(plan, prefix):
    """Explicit existing state directory. Private HOME is not consulted."""
    home = clean_absolute(plan.get('gui_home'), 'gui home')
    state = clean_absolute(plan.get('signing_state_home'), 'explicit signing state')
    need(state != home and state.is_relative_to(home), 'signing state outside gui home')
    need(not state.is_relative_to(Path(prefix)) and state != Path(prefix), 'signing state inside prefix')
    parent = Path(plan['manifest_path']).parent
    need(not state.is_relative_to(parent) and state != parent, 'signing state inside prefix')
    return state

def signing_ancestors(state, home, uid):
    for directory in (state, *state.parents):
        if not directory.is_relative_to(home):
            break
        st = directory.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == uid, 'signing ancestry')
        need(stat.S_IMODE(st.st_mode) & 0o022 == 0, 'signing ancestry writable')

def file_metadata(path, kind):
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) if kind == 'directory' else stat.S_ISREG(st.st_mode), 'signing type')
    return {'path': str(path), 'type': kind, 'dev': st.st_dev, 'inode': st.st_ino, 'mode': stat.S_IMODE(st.st_mode),
            'uid': st.st_uid, 'gid': st.st_gid, 'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns}

def typed_record(value, fields, label):
    need(isinstance(value, dict) and set(value) == set(fields), label)
    if 'path' in fields:
        clean_absolute(value.get('path'), label)
    if 'type' in fields:
        need(value.get('type') in ('directory', 'regular'), label)
    for key in fields:
        if key in ('path', 'type'):
            continue
        integer_field(value.get(key), label)
    return value

def official_shape(plan):
    identity = plan.get('official_identity')
    need(isinstance(identity, dict) and set(identity) == {'signing', 'device'}, 'official identity')
    signing = identity['signing']
    device = identity['device']
    need(isinstance(signing, dict) and set(signing) == {'state_home', 'public_sha256', 'files'}, 'signing identity')
    need(signing.get('state_home') == plan.get('signing_state_home'), 'signing state home drift')
    need(HEX64.fullmatch(str(signing.get('public_sha256', ''))) and signing.get('public_sha256') == plan.get('signing_public_sha256'), 'existing public key sha')
    files = signing.get('files')
    need(isinstance(files, list) and len(files) == 3, 'signing files')
    for item in files:
        typed_record(item, FILE_FIELDS, 'signing file')
    need(isinstance(device, dict) and set(device) == {'board', 'soc', 'compatible', 'render_node'}, 'device identity')
    board, soc, compatible = device.get('board'), device.get('soc'), device.get('compatible')
    need(isinstance(board, str) and board and isinstance(soc, str) and soc, 'device identity')
    need(isinstance(compatible, list) and compatible and all(isinstance(item, str) and item for item in compatible), 'compatible')
    need(compatible[0].removeprefix('apple,') == board, 'board identity')
    socs = [item for item in compatible if SOC_TOKEN.fullmatch(item)]
    need(len(socs) == 1 and socs[0].removeprefix('apple,') == soc, 'soc identity')
    typed_record(device.get('render_node'), RENDER_FIELDS, 'render node')
    return identity

def recheck_official_identity(plan, prefix):
    """Compare live signing files and the render node to official_identity. Do not read the private key or the device."""
    identity = official_shape(plan)
    state = signing_state_path(plan, prefix)
    signing_ancestors(state, Path(plan['gui_home']), plan['gui_uid'])
    directory = state / 'omarchy-m-test'
    private = directory / 'machine-key'
    public = directory / 'machine-key.pub'
    live = [file_metadata(directory, 'directory'), file_metadata(private, 'regular'), file_metadata(public, 'regular')]
    need(live == identity['signing']['files'], 'signing identity drift')
    need(live[0]['mode'] == 0o700 and live[1]['mode'] == 0o600 and live[2]['mode'] in (0o600, 0o644), 'signing mode')
    need(all(row['uid'] == plan['gui_uid'] and row['gid'] == plan['gui_gid'] for row in live), 'signing owner')
    need(0 < live[2]['size'] <= PUB_LIMIT, 'existing public key')
    _ident, blob = read_regular(public, PUB_LIMIT)
    digest = sha_bytes(blob)
    need(digest == identity['signing']['public_sha256'], 'existing public key')
    text = blob.decode().split()
    need(PUBKEY.fullmatch(' '.join(text[:2])), 'existing public key')
    need([file_metadata(directory, 'directory'), file_metadata(private, 'regular'), file_metadata(public, 'regular')] == live, 'signing identity changed during public read')
    node = identity['device']['render_node']
    st = Path(node['path']).lstat()
    need(stat.S_ISCHR(st.st_mode), 'render node type')
    need(os.major(st.st_rdev) == node['major'] and os.minor(st.st_rdev) == node['minor'], 'render node identity')
    need(stat.S_IMODE(st.st_mode) == node['mode'] and st.st_uid == node['uid'] and st.st_gid == node['gid'] and st.st_dev == node['dev'] and st.st_ino == node['inode'], 'render node metadata')
    return {'files': live, 'sha256': digest, 'public_identity': ' '.join(text[:2])}

def unit_env(plan, manifest, command_env, staged, state_home):
    prefix = manifest['prefix']
    env = {key: value for key, value in command_env.items() if key not in DROPPED}
    entries = [entry for entry in env.get('LD_LIBRARY_PATH', '').split(':') if entry]
    vulkan_dir = str(Path(staged['vulkan']).parent)
    kept = [entry for entry in entries if under(entry, prefix) and not entry.startswith('/usr') and not entry.startswith('/lib')]
    need(vulkan_dir in kept, 'staged library path')
    env['LD_LIBRARY_PATH'] = ':'.join(kept)
    env['XDG_STATE_HOME'] = state_home
    for key, value in plan['gui_env'].items():
        env[key] = value
    return env

def signing_fingerprint(state_home):
    public = Path(state_home) / KEY_RELATIVE
    private = public.with_name('machine-key')
    rows = []
    for path in (public.parent, private, public):
        st = path.lstat()
        rows.append((str(path), st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
    _ident, blob = read_regular(public, PUB_LIMIT)
    return tuple(rows), sha_bytes(blob)

def retain_sample(seen, item):
    """Keep provider and render evidence across load and teardown samples."""
    key = (item['pid'], item['birth'])
    entry = seen.get(key)
    if entry is None:
        need(len(seen) < 65, 'extra native invocation')
        entry = {'pid': item['pid'], 'birth': item['birth'], 'workload': item['workload'], 'negative': item['negative'],
                 'implementation': None, 'loader': None, 'renders': []}
        seen[key] = entry
    else:
        need(entry['workload'] == item['workload'] and entry['negative'] == item['negative'], 'helper identity drift')
    for role in ('implementation', 'loader'):
        held = item.get(role)
        if held is None:
            continue
        if entry[role] is None:
            entry[role] = held
        else:
            need(held_matches(entry[role], held), 'mapped ' + role + ' drifted')
    for node in item.get('renders') or []:
        if node not in entry['renders']:
            entry['renders'].append(node)
    return entry

def require_held_sample(item, allowed, staged, loader_pins, render_node):
    """One invocation must hold both provider roles and the typed render node."""
    need(item['implementation'] is not None and item['loader'] is not None, 'provider maps')
    render = (render_node['major'], render_node['minor'])
    chosen = [node for node in item['renders'] if node in allowed]
    need(len(set(chosen)) == 1 and set(chosen) == {render}, 'render fd absent')
    item['render'] = render
    need(held_matches(item['implementation'], staged), 'mapped provider is not staged')
    need(loader_pins and any(held_matches(item['loader'], candidate) for candidate in loader_pins), 'mapped loader left the frozen pin')
    return item

def finish_observations(seen, allowed, staged, loader_pins, render_node):
    items = list(seen.values())
    need(len(items) == 65, 'observations')
    for item in items:
        require_held_sample(item, allowed, staged, loader_pins, render_node)
        need(held_matches(item['loader'], items[0]['loader']), 'mapped loader drift')
    shared_render([item['render'] for item in items], allowed)
    return items

def prior_complete(entry):
    """Both provider roles and at least one render, already stored for this birth."""
    return (isinstance(entry, dict) and held_matches(entry.get('implementation'), entry.get('implementation'))
            and held_matches(entry.get('loader'), entry.get('loader'))
            and isinstance(entry.get('renders'), list) and len(entry['renders']) > 0)

def note_unavailable(seen, completions, pid, birth, unavailable):
    """Admit one retirement only for the same pid and birth with complete evidence."""
    need(isinstance(unavailable, (RangeUnavailable, ProcessUnavailable)), 'retirement record')
    if unavailable.pid != pid:
        raise unavailable
    if not prior_complete(seen.get((pid, birth))):
        raise unavailable
    phase = 'range' if isinstance(unavailable, RangeUnavailable) else 'process'
    if any(event.pid == pid and event.birth == birth and event.phase == phase for event in completions):
        return
    need(len(completions) < RETIREMENT_CAP, 'retirement budget')
    completions.append(RetiredEvent(pid, birth, phase))

def check_completions(items, completions, clean_exit, allowed, staged, loader_pins, render_node):
    """Retirements count only after the oracle and a real clean exit."""
    need(clean_exit is True, 'retirement exit')
    need(isinstance(items, list) and isinstance(completions, list) and len(completions) <= RETIREMENT_CAP, 'retirement record')
    keys = set()
    for item in items:
        require_held_sample(item, allowed, staged, loader_pins, render_node)
        keys.add((item['pid'], item['birth']))
    for event in completions:
        need(type(event) is RetiredEvent and event.phase in ('range', 'process'), 'retirement record')
        need((event.pid, event.birth) in keys, 'retirement witness')

def relative_clean(value):
    path = Path(value)
    return isinstance(value, str) and value and not path.is_absolute() and '..' not in path.parts and not any(part in ('', '.') for part in path.parts)

def bind(plan, manifest, output_dir, command_env, system_graphics_pins):
    need(isinstance(plan, dict) and isinstance(manifest, dict), 'plan or manifest type')
    need(plan.get('schema') == SCHEMA and manifest.get('schema') == SCHEMA, 'schema')
    need(plan.get('official_gpu') is True, 'official gpu not requested')
    need(HEX64.fullmatch(str(plan.get('signing_public_sha256', ''))), 'existing public key sha absent')
    need(JOB.fullmatch(str(plan.get('job', ''))) and plan.get('job') == manifest.get('job'), 'job')
    need(BOOT.fullmatch(str(plan.get('boot_id', ''))), 'boot id')
    need(isinstance(plan.get('kernel'), str) and plan['kernel'] and len(plan['kernel']) <= 128, 'kernel')
    need(HEX64.fullmatch(str(plan.get('cmdline_sha256', ''))), 'cmdline sha')
    need(HEX64.fullmatch(str(plan.get('manifest_sha256', ''))), 'manifest sha')
    need(isinstance(plan.get('manifest_path'), str) and Path(plan['manifest_path']).is_absolute(), 'manifest path')
    need(isinstance(plan.get('gui_uid'), int) and isinstance(plan.get('gui_gid'), int) and plan['gui_uid'] > 0 and plan['gui_gid'] > 0, 'gui id')
    need(plan['gui_uid'] != 0 and isinstance(plan.get('gui_user'), str) and plan['gui_user'] not in ('', 'root'), 'gui user')
    clean_absolute(plan.get('gui_home'), 'gui home')
    need(Path(plan['gui_home']) not in (Path('/'), Path('/usr'), Path('/usr/lib'), Path('/root')), 'gui home')
    prefix, root = manifest.get('prefix'), manifest.get('root')
    need(isinstance(prefix, str) and isinstance(root, str) and Path(prefix).is_absolute() and Path(root).is_absolute(), 'prefix')
    need(Path(prefix) not in (Path('/'), Path('/usr'), Path('/usr/lib')) and Path(root) not in (Path('/'), Path('/usr'), Path('/usr/lib')), 'installed root refused')
    need(under(root, prefix) or Path(root).resolve() == Path(prefix).resolve(), 'root outside prefix')
    if isinstance(output_dir, Path):
        output_dir = str(output_dir)
    need(isinstance(output_dir, str) and Path(output_dir).is_absolute() and Path(output_dir) not in (Path('/'), Path('/usr'), Path('/usr/lib')), 'output directory')
    need(Path(output_dir).resolve() != Path(root).resolve() and Path(output_dir).resolve() != Path(prefix).resolve(), 'output directory')
    providers = manifest.get('providers')
    need(isinstance(providers, dict) and set(providers) == {'egl', 'gallium', 'vulkan'}, 'provider roles')
    files = manifest.get('files')
    need(isinstance(files, dict) and files, 'files')
    packages = manifest.get('packages')
    need(isinstance(packages, list) and packages, 'packages')
    names = set()
    for package in packages:
        need(isinstance(package, dict), 'package type')
        for key in ('version', 'arch', 'pkginfo_sha256'):
            need(isinstance(package.get(key), str) and package[key], 'package field ' + key)
        identity = package.get('name') if isinstance(package.get('name'), str) and package.get('name') else package.get('pkgbase')
        need(isinstance(identity, str) and identity, 'package field name')
        need(HEX64.fullmatch(package['pkginfo_sha256']), 'package pkginfo sha')
        names.add(identity)
    staged = {}
    for role, rel in providers.items():
        need(relative_clean(rel) and rel in files, 'provider path ' + role)
        meta = files[rel]
        need(isinstance(meta, dict) and HEX64.fullmatch(str(meta.get('sha256', ''))) and isinstance(meta.get('size'), int) and meta['size'] > 0, 'provider file ' + role)
        need('link' not in meta and meta.get('package') in names, 'provider alias or package ' + role)
        staged[role] = str(Path(root) / rel)
        need(not staged[role].startswith('/usr/') and not staged[role].startswith('/lib'), 'installed provider refused')
        need(':' not in staged[role] and not any(ch.isspace() for ch in staged[role]), 'staged path unsafe for bind mount')
    probes = manifest.get('probes')
    need(isinstance(probes, dict) and set(probes) == {'gl', 'vulkan'}, 'probes')
    for name, pin in (('gl', GL_PROBE_SHA), ('vulkan', VK_PROBE_SHA)):
        tool = probes[name]
        need(isinstance(tool, dict) and isinstance(tool.get('path'), str) and Path(tool['path']).is_absolute() and tool.get('sha256') == pin, 'probe ' + name)
    for key in ('vulkan_json', 'egl_json'):
        value = manifest.get(key)
        need(isinstance(value, str) and Path(value).is_absolute() and under(value, prefix) and ':' not in value and '\n' not in value, key)
    need(isinstance(command_env, dict) and command_env and all(isinstance(k, str) and isinstance(v, str) for k, v in command_env.items()), 'command env')
    need(not (set(command_env) & FORBIDDEN), 'forbidden graphics env')
    need(all(not BAD_TEXT.search(v) for v in command_env.values()), 'software renderer env')
    vulkan_env = [command_env.get('VK_DRIVER_FILES'), command_env.get('VK_ICD_FILENAMES')]
    present = [item for item in vulkan_env if item]
    need(present and all(item == manifest['vulkan_json'] for item in present) and (command_env.get('VK_DRIVER_FILES') or command_env.get('VK_ICD_FILENAMES')), 'staged vulkan json')
    need(command_env.get('__EGL_VENDOR_LIBRARY_FILENAMES') == manifest['egl_json'], 'staged egl json')
    run_root = Path(prefix) / 'run'
    for key in PRIVATE_KEYS:
        value = command_env.get(key)
        need(isinstance(value, str) and under(value, prefix) and not under(value, root), 'private ' + key)
        need(Path(value).resolve() != Path(plan['gui_home']).resolve() and Path(value).resolve() != Path(output_dir).resolve(), 'private path is the gui home')
        need(under(value, run_root) or under(value, output_dir), 'private ' + key)
    state = signing_state_path(plan, prefix)
    for key in ('HOME', 'XDG_STATE_HOME'):
        private = command_env.get(key)
        if isinstance(private, str) and private:
            private_path = clean_absolute(private, 'private ' + key)
            need(state != private_path and not state.is_relative_to(private_path), 'signing state is private home')
    official_shape(plan)
    state_home = str(state)
    gui_env = plan.get('gui_env')
    need(isinstance(gui_env, dict) and set(gui_env) <= SESSION_KEYS and not (set(gui_env) & SESSION_REJECT), 'gui env')
    need(all(isinstance(k, str) and isinstance(v, str) and v and command_env.get(k) == v for k, v in gui_env.items()), 'gui env drift')
    need(isinstance(system_graphics_pins, dict) and system_graphics_pins, 'system graphics pins')
    loaders = []
    for path, pin in system_graphics_pins.items():
        need(isinstance(path, str) and Path(path).is_absolute() and ':' not in path, 'system pin path')
        need(isinstance(pin, dict) and HEX64.fullmatch(str(pin.get('sha256', ''))) and isinstance(pin.get('size'), int) and pin['size'] > 0, 'system pin fields')
        need(isinstance(pin.get('dev'), int) and isinstance(pin.get('inode'), int), 'system pin identity')
        if Path(path).name.startswith('libvulkan.so'):
            loaders.append(path)
    need(loaders, 'loader pin absent')
    built = unit_env(plan, manifest, command_env, staged, state_home)
    return {'plan': plan, 'manifest': manifest, 'output_dir': output_dir, 'command_env': command_env,
            'unit_env': built, 'system_graphics_pins': system_graphics_pins, 'staged': staged, 'state_home': state_home}

def execution_gate(plan):
    live = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if live != plan['boot_id']:
        return 'staged job boot is not this boot'
    if os.geteuid() != 0 or os.uname().machine != 'aarch64':
        return 'official suite runs only as root on the staged aarch64 job'
    return None

def stage_verified(path, raw):
    if path.exists():
        current, _body = None, path.read_bytes()
        need(_body == raw, 'staged supervisor drift')
        return
    path.parent.mkdir(mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        view = memoryview(raw)
        while view:
            wrote = os.write(fd, view)
            need(wrote > 0, 'staged supervisor short write')
            view = view[wrote:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o644)

def load_pinned(prefix=None):
    staged_supervisor = Path(prefix) / 'official' / 'full-supervisor.py' if prefix is not None else None
    staged_guard = Path(prefix) / 'official' / 'admission-supervisor.py' if prefix is not None else None
    if staged_supervisor is not None and staged_supervisor.is_file() and staged_guard.is_file():
        supervisor_bytes = staged_supervisor.read_bytes()
        guard_bytes = staged_guard.read_bytes()
    else:
        supervisor_bytes = SUPERVISOR_PATH.read_bytes()
        guard_bytes = GUARD_PATH.read_bytes()
        if staged_supervisor is not None:
            stage_verified(staged_supervisor, supervisor_bytes)
            stage_verified(staged_guard, guard_bytes)
    need(sha_bytes(supervisor_bytes) == SUPERVISOR_SHA, 'supervisor pin')
    need(sha_bytes(guard_bytes) == GUARD_SHA, 'guard pin')
    module = exec_verified('mesa_official_full_supervisor', supervisor_bytes)
    guard = exec_verified('reviewed_guard', guard_bytes)
    module.s = guard
    need(module.COMMIT == COMMIT and module.GUARD_SHA == GUARD_SHA and module.WALL == WALL, 'supervisor contract drift')
    need(guard.ARCHIVE_SHA == ARCHIVE_SHA and guard.ARCHIVE_BYTES == ARCHIVE_BYTES and guard.HELPER_SHA == HELPER_SHA, 'guard archive pin')
    need(guard.COMMIT == COMMIT and guard.SOURCE_SHA == SOURCE_SHA, 'guard source pin')
    need({'gpu', 'dart'} <= set(guard.FAULTS), 'fault vocabulary drift')
    return module

def unit_plan(bound):
    token = sha_bytes(bound['plan']['job'].encode())[:16]
    return {'prefix': '/var/tmp/sf-official-gpu-full-' + token, 'gui_uid': bound['plan']['gui_uid'], 'gui_gid': bound['plan']['gui_gid']}

def benchmark_argv(payload, report):
    return ['/usr/bin/python3', '-B', str(Path(payload) / 'bin' / 'omarchy-m-test'), '--gpu-benchmark', '--accept-gpu-risk',
            '--benchmark-seed', '42', '--benchmark-block', '1', '--benchmark-repetitions', '7', '--output', str(report)]

def launch_argv(supervisor, bound, payload, report, stdout_path, stderr_path):
    plan = unit_plan(bound)
    qualified = supervisor.command(plan, Path(payload))
    qualified_properties = [item.split('=', 1)[1] for item in qualified if item.startswith('--property=') and item.split('=', 1)[1].split('=', 1)[0] != 'Description']
    description = supervisor.owner_description(plan)
    staged = bound['staged']['vulkan']
    bind_mount = f'BindReadOnlyPaths={staged}:{SYSTEM_VULKAN}'
    properties = [f'--property={item}' for item in (
        'Type=exec', 'Description=' + description, 'RemainAfterExit=yes', 'User=' + str(plan['gui_uid']),
        'Group=' + str(plan['gui_gid']), 'KillMode=control-group', 'SendSIGKILL=yes', 'TimeoutStopSec=5s',
        'RuntimeMaxSec=1800s', 'LimitFSIZE=4194304', 'UMask=0077', 'PrivateMounts=yes', bind_mount,
        'StandardOutput=append:' + str(stdout_path), 'StandardError=append:' + str(stderr_path),
    )]
    for item in qualified_properties:
        name = item.split('=', 1)[0]
        if name in ('StandardOutput', 'StandardError', 'User', 'Group', 'Description'):
            continue
        need('--property=' + item in properties, 'dropped unit property ' + item)
    env = ['/usr/bin/env', '-i', *[key + '=' + value for key, value in bound['unit_env'].items()]]
    return ['systemd-run', '--quiet', '--unit=' + supervisor.unit_name(plan), *properties, *env, *benchmark_argv(payload, report)]

def screen_journal(guard, boot, data):
    journal = guard.Journal(boot)
    journal.consume(data if data.endswith(b'\n') or data == b'' else data + b'\n')
    need(not journal.categories, 'new kernel fault')
    return journal

def accept_run(gpu, work, negative, run, implementation_sha, loader_shas):
    identity = run.get('identity', {})
    measurements = run.get('measurements', {})
    need(run.get('status') == 'pass' and run.get('reason') == ('negative-control-detected' if negative else 'completed'), 'run status')
    need(run.get('helper_sha256') == HELPER_SHA and identity.get('source_sha256') == SOURCE_SHA, 'run source')
    need(identity.get('vendor_id') == 0x10005 and identity.get('driver_id') == 26 and identity.get('device_type') == 1 and identity.get('api_version', 0) >= 4202496, 'native identity')
    need(gpu.GPU_NAME.fullmatch(str(identity.get('device_name', ''))), 'device name')
    operations = gpu.OPERATIONS[work] // gpu.QUERIES[work] if negative else gpu.OPERATIONS[work]
    need(measurements.get('mismatches') == (1 if negative else 0) and measurements.get('operations') == operations, 'run oracle')
    need(0 < measurements.get('owned_bytes_peak', 0) <= 64 * 1024 ** 2, 'owned bytes')
    need((measurements.get('width'), measurements.get('height')) == ((1920, 1080) if work in ('raster', 'texture') else (0, 0)), 'extent')
    libraries = run.get('driver_libraries')
    need(isinstance(libraries, list) and len(libraries) == 2, 'provider elf')
    found = {item.get('role'): item.get('sha256') for item in libraries}
    need(found.get('implementation') == implementation_sha and found.get('loader') in loader_shas, 'provider elf')
    if measurements.get('gpu_timestamp_status') == 'supported':
        need(36 <= identity.get('timestamp_bits', 0) <= 64 and measurements.get('gpu_timestamp_queries') == (1 if negative else gpu.QUERIES[work]) and gpu.integer(measurements.get('gpu_timestamp_ns')), 'gpu timestamp')
    else:
        need(measurements.get('gpu_timestamp_status') == 'unsupported' and identity.get('timestamp_bits') == 0 and measurements.get('gpu_timestamp_queries') == 0 and 'gpu_timestamp_ns' not in measurements, 'gpu timestamp unsupported')
    for key in ('record_ns', 'submit_wait_ns', 'thread_cpu_ns'):
        need(gpu.integer(measurements.get(key)), 'cpu scope ' + key)

def document_schedule(gpu):
    import random
    schedule = []
    rng = random.Random(42)
    for phase, count in (('warmup', 2), ('measured', 7)):
        for index in range(count):
            order = list(gpu.WORKLOADS)
            rng.shuffle(order)
            schedule.extend({'workload': work, 'phase': phase, 'index': index} for work in order)
    return schedule

def oracle_body(doc, plan, implementation_sha, loader_shas, gpu):
    need(isinstance(doc, dict) and doc.get('status') == 'pass', 'report status')
    machine = doc.get('machine', {})
    device = plan['official_identity']['device']
    need(machine.get('kernel') == plan['kernel'] and machine.get('arch') == 'aarch64', 'report machine')
    need(machine.get('board') == device['board'] and machine.get('soc') == device['soc'], 'report machine')
    protocol = doc.get('protocol', {})
    need(all(protocol.get(key) == value for key, value in PROTOCOL.items()), 'protocol')
    controls = doc.get('controls')
    need(isinstance(controls, list) and len(controls) == 2 and [item.get('negative') for item in controls] == [False, True], 'controls')
    schedule = document_schedule(gpu)
    need(doc.get('schedule') == schedule and len(doc.get('cases', [])) == 7, 'schedule')
    runs = []
    sequenced = []
    loaders = set()
    for negative, run in zip((False, True), controls):
        accept_run(gpu, 'compute', negative, run, implementation_sha, loader_shas)
        loaders.add(next(item['sha256'] for item in run['driver_libraries'] if item['role'] == 'loader'))
        runs.append(('compute', negative))
    for case, work in zip(doc['cases'], gpu.WORKLOADS):
        need(case.get('workload') == gpu.workload_definition(work) and case.get('status') == 'pass' and len(case.get('runs', [])) == 9, 'case definition')
        need(case.get('metrics') == gpu.metrics_for(case['runs']), 'raw statistics')
        metric_ids = [item.get('id') for item in case['metrics']]
        need(metric_ids[:4] == ['record_ns', 'submit_wait_ns', 'thread_cpu_ns', 'bo_lifetime_ns'] and 'gpu_timestamp_ns' in metric_ids, 'cpu gpu scopes')
        expected_runs = [{**item, 'sequence': index} for index, item in enumerate(schedule) if item['workload'] == work]
        for run, expected_run in zip(case['runs'], expected_runs):
            need(all(run.get(key) == expected_run[key] for key in ('phase', 'index', 'sequence')), 'case order')
            accept_run(gpu, work, False, run, implementation_sha, loader_shas)
            loaders.add(next(item['sha256'] for item in run['driver_libraries'] if item['role'] == 'loader'))
            sequenced.append((run['sequence'], work))
    need(sorted(sequence for sequence, _work in sequenced) == list(range(len(schedule))), 'sequence coverage')
    runs.extend((work, False) for _sequence, work in sorted(sequenced, key=lambda item: item[0]))
    need(len(loaders) == 1 and len(runs) == 65, 'report invocations')
    return runs

def official_order(supervisor, gpu):
    return supervisor.expected_schedule(tuple(gpu.WORKLOADS))

def require_order(supervisor, gpu, runs):
    need(runs == official_order(supervisor, gpu) and len(runs) == 65, 'native invocations')
    need(runs[:2] == [('compute', False), ('compute', True)], 'controls')
    need(all(negative is False for _, negative in runs[2:]), 'measured negative')

def prove_bindings(bound):
    manifest = bound['manifest']
    archive = Path(manifest['prefix']) / 'official' / 'archive.tar.gz'
    archived = regular_identity(archive)
    need(archived['size'] == ARCHIVE_BYTES and archived['sha256'] == ARCHIVE_SHA, 'staged archive pin')
    for role, path in bound['staged'].items():
        ident = regular_identity(path)
        rel = manifest['providers'][role]
        meta = manifest['files'][rel]
        need(ident['sha256'] == meta['sha256'] and ident['size'] == meta['size'], 'staged provider drift ' + role)
        system_ids = {(pin['dev'], pin['inode']) for pin in bound['system_graphics_pins'].values()}
        need((ident['dev'], ident['inode']) not in system_ids, 'staged provider is the system file')
        if role == 'vulkan':
            need(ident['magic'] == b'\x7fELF', 'vulkan provider is not an ELF')
        bound['staged_identity'] = bound.get('staged_identity', {})
        bound['staged_identity'][role] = ident
    for name, pin in (('gl', GL_PROBE_SHA), ('vulkan', VK_PROBE_SHA)):
        ident = regular_identity(manifest['probes'][name]['path'])
        need(ident['sha256'] == pin, 'probe drift ' + name)
    observed = recheck_official_identity(bound['plan'], manifest['prefix'])
    bound['public_identity'] = observed['public_identity']
    bound['identity_observed'] = {'files': observed['files'], 'sha256': observed['sha256']}
    bound['graphics_before'] = snapshot_graphics(bound)
    return bound

def snapshot_graphics(bound):
    found = {}
    for path, pin in bound['system_graphics_pins'].items():
        ident = regular_identity(path)
        need(ident['sha256'] == pin['sha256'] and ident['size'] == pin['size'] and ident['dev'] == pin['dev'] and ident['inode'] == pin['inode'], 'system graphics pin drift')
        found[path] = {'sha256': ident['sha256'], 'size': ident['size'], 'dev': ident['dev'], 'inode': ident['inode']}
    host = Path(SYSTEM_VULKAN)
    if host.exists():
        ident = regular_identity(host)
        found[SYSTEM_VULKAN] = {'sha256': ident['sha256'], 'size': ident['size'], 'dev': ident['dev'], 'inode': ident['inode']}
        staged = bound['staged_identity']['vulkan']
        need((ident['dev'], ident['inode']) != (staged['dev'], staged['inode']), 'host vulkan is the staged file')
    return found

def shared_render(nodes, allowed):
    need(len(nodes) == 65 and len(set(nodes)) == 1, 'render node drift')
    need(nodes[0] in allowed, 'render node is not a drm render node')
    return nodes[0]

def seal(report_path, report_sha, cleanup, observations, signature, artifacts):
    need(isinstance(cleanup, dict) and cleanup.get('stopped') is True and cleanup.get('control_group_empty') is True and not cleanup.get('not_created'), 'cleanup')
    need(observations == 65, 'observations')
    need(isinstance(signature, dict) and signature.get('cryptographic_verification') is True and signature.get('existing_public_key_matches') is True, 'signature')
    need(isinstance(artifacts, dict) and artifacts.get('journal_final') and artifacts.get('observer'), 'fault receipt')
    return {'status': 'PASS', 'native_invocations': 65, 'signature_verified': True, 'source_commit': COMMIT,
            'archive_sha256': ARCHIVE_SHA, 'report_path': str(report_path), 'report_sha256': report_sha,
            'cleanup': cleanup, 'artifacts': artifacts}

def run_official(plan, manifest, output_dir, command_env, system_graphics_pins):
    bound = bind(plan, manifest, output_dir, command_env, system_graphics_pins)
    reason = execution_gate(bound['plan'])
    if reason:
        raise Refuse(reason)
    return execute(bound)

def own_root(path, mode):
    path.mkdir(mode=mode, exist_ok=True)
    os.chmod(path, mode)
    os.chown(path, 0, 0)
    st = path.lstat()
    need(not path.is_symlink() and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == mode, 'root ownership')

def _dir_open_flags():
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def _ancestry_ok(st, leaf_parent, uid, gid):
    """Root or the caller may own an ancestor. The GUI may own only the leaf parent."""
    if not stat.S_ISDIR(st.st_mode):
        return False
    mode = stat.S_IMODE(st.st_mode)
    group_write = mode & 0o022
    sticky_root = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
    if group_write and not sticky_root:
        return False
    if st.st_uid == 0 or st.st_uid == os.geteuid():
        return True
    return bool(leaf_parent and st.st_uid == uid and st.st_gid == gid)

def _walk(path, uid, gid):
    """Hold nofollow directory fds from /. Do not resolve or follow a link."""
    need(isinstance(path, Path) and path.is_absolute(), 'directory ancestry')
    raw = os.fspath(path)
    need('\0' not in raw and '\n' not in raw and '\r' not in raw, 'directory ancestry')
    parts = path.parts[1:]
    need(parts and '..' not in path.parts and all(part not in ('', '.', '..') for part in parts), 'directory ancestry')
    fds = []
    try:
        flags = _dir_open_flags()
        fd = os.open('/', flags)
        fds.append(fd)
        st = os.fstat(fd)
        need(_ancestry_ok(st, False, uid, gid), 'directory ancestry')
        parent_parts = parts[:-1]
        for index, name in enumerate(parent_parts):
            fd = os.open(name, flags, dir_fd=fd)
            fds.append(fd)
            st = os.fstat(fd)
            need(_ancestry_ok(st, index == len(parent_parts) - 1, uid, gid), 'directory ancestry')
        return fds, fd, parts[-1], (st.st_dev, st.st_ino)
    except Refuse:
        for held in reversed(fds):
            os.close(held)
        raise
    except OSError:
        for held in reversed(fds):
            os.close(held)
        raise Refuse('directory ancestry') from None

def own_gui(path, uid, gid):
    """Validate an existing 0700 GUI directory, or exclusively create one.

    Metadata writes use the new directory fd only. An existing directory is not
    chmodded or chowned. A symlink or other replacement is refused. The parent
    inode is checked again after the operation.
    """
    need(type(uid) is int and type(gid) is int and uid > 0 and gid >= 0, 'gui id')
    flags = _dir_open_flags()
    fds, parent_fd, name, ident = _walk(path, uid, gid)
    try:
        again = os.fstat(parent_fd)
        need((again.st_dev, again.st_ino) == ident, 'directory ancestry')
        try:
            listed = os.lstat(name, dir_fd=parent_fd)
        except FileNotFoundError:
            listed = None
        except OSError:
            raise Refuse('directory replacement') from None
        if listed is not None and (stat.S_ISLNK(listed.st_mode) or not stat.S_ISDIR(listed.st_mode)):
            raise Refuse('directory replacement')
        if listed is None:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                raise Refuse('directory replacement') from None
            try:
                child = os.open(name, flags, dir_fd=parent_fd)
            except OSError:
                raise Refuse('directory replacement') from None
            fds.append(child)
            st = os.fstat(child)
            need(stat.S_ISDIR(st.st_mode), 'directory replacement')
            try:
                os.fchmod(child, 0o700)
                os.fchown(child, uid, gid)
            except PermissionError:
                raise Refuse('directory owner') from None
            after = os.fstat(child)
            need((after.st_dev, after.st_ino) == (st.st_dev, st.st_ino), 'directory replacement')
            need(stat.S_IMODE(after.st_mode) == 0o700 and after.st_uid == uid and after.st_gid == gid, 'directory owner')
        else:
            try:
                child = os.open(name, flags, dir_fd=parent_fd)
            except OSError:
                raise Refuse('directory replacement') from None
            fds.append(child)
            st = os.fstat(child)
            need(stat.S_ISDIR(st.st_mode) and (st.st_dev, st.st_ino) == (listed.st_dev, listed.st_ino), 'directory replacement')
            need(stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == uid and st.st_gid == gid, 'directory replacement')
        end = os.fstat(parent_fd)
        need((end.st_dev, end.st_ino) == ident, 'directory ancestry')
        fds2, parent2, name2, ident2 = _walk(path, uid, gid)
        fds.extend(fds2)
        need(ident2 == ident and name2 == name, 'directory ancestry')
        end2 = os.fstat(parent2)
        need((end2.st_dev, end2.st_ino) == ident, 'directory ancestry')
    finally:
        for held in reversed(fds):
            os.close(held)

def open_fault_monitor(cursor):
    import subprocess
    return subprocess.Popen(
        ['timeout', '--signal=TERM', '--kill-after=5s', '1805s', 'journalctl', '-k', '-b', '--after-cursor=' + cursor,
         '-f', '-o', 'json', '--no-pager', '--all'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

def poll_fault_monitor(watch, journal):
    need(watch.poll() is None, 'journal monitor exited')
    os.set_blocking(watch.stdout.fileno(), False)
    os.set_blocking(watch.stderr.fileno(), False)
    try:
        err = os.read(watch.stderr.fileno(), 16384)
    except BlockingIOError:
        err = b''
    need(not err, 'journal monitor stderr')
    try:
        data = os.read(watch.stdout.fileno(), 16384)
    except BlockingIOError:
        data = b''
    if data:
        journal.consume(data)

def begin_cleanup_deadline(bound):
    """One absolute deadline for monitor close, stop, and the final journal."""
    if bound.get('cleanup_deadline') is None:
        bound['cleanup_deadline'] = time.monotonic() + CALLER_CLEANUP_RESERVE_S
    return bound['cleanup_deadline']

def close_fault_monitor(watch, bound=None):
    if bound is not None:
        begin_cleanup_deadline(bound)
    if watch is None or watch.poll() is not None:
        return
    try:
        os.killpg(watch.pid, 15)
        timeout = MONITOR_CLOSE_S
        if bound is not None:
            left = bound['cleanup_deadline'] - time.monotonic()
            timeout = min(MONITOR_CLOSE_S, left) if left > 0 else 0
        watch.wait(timeout=timeout)
    except Exception:
        try:
            os.killpg(watch.pid, 9)
        except ProcessLookupError:
            return

def release_execution(supervisor, bound, plan, logs, launch, invocation, cursor, cleanup, failed):
    """Attempt the owned stop and the final journal. Keep the first failure.

    Each pinned capture keeps its timeout only when that timeout plus the
    pinned kill_group waits still fit the shared caller deadline. A capture
    that would pass the deadline is not started. The journal is still attempted
    after a stop failure. Neither failure becomes a pass.
    """
    begin_cleanup_deadline(bound)
    real_capture = supervisor.s.capture

    def capture(command, limit=supervisor.s.LOG_CAP, timeout=10):
        left = bound['cleanup_deadline'] - time.monotonic()
        if left < timeout + KILL_GROUP_S:
            raise Refuse('cleanup deadline')
        return real_capture(command, limit=limit, timeout=timeout)

    supervisor.s.capture = capture
    try:
        stop_error = None
        if launch:
            try:
                cleanup = supervisor.record_and_stop(plan, logs, invocation)
            except BaseException as error:
                stop_error = error
        journal_error = None
        try:
            journal_error = journal_final(supervisor, bound, cursor, logs, cleanup, failed if failed is not None else stop_error)
        except BaseException as error:
            journal_error = error
        if failed is not None:
            return cleanup, failed
        if stop_error is not None:
            return cleanup, stop_error
        if not journal_error:
            return cleanup, None
        if isinstance(journal_error, BaseException):
            return cleanup, journal_error
        return cleanup, Refuse(str(journal_error))
    finally:
        supervisor.s.capture = real_capture

def execute(bound):
    """Target path. execution_gate refuses this host before this function runs."""
    prefix = Path(bound['manifest']['prefix'])
    supervisor = load_pinned(prefix)
    prove_bindings(bound)
    bound['signing_before'] = signing_fingerprint(bound['state_home'])
    paths = layout_paths(bound)
    plan = unit_plan(bound)
    logs = paths['logs']
    report = paths['report']
    failed = None
    launch = False
    invocation = None
    cleanup = None
    cursor = None
    try:
        own_root(logs, 0o700)
        for name in ('stdout', 'stderr'):
            handle = paths[name].open('xb')
            handle.close()
            os.chmod(paths[name], 0o600)
            os.chown(paths[name], 0, 0)
        for key in PRIVATE_KEYS:
            own_gui(Path(bound['unit_env'][key]), bound['plan']['gui_uid'], bound['plan']['gui_gid'])
        own_gui(report.parent, bound['plan']['gui_uid'], bound['plan']['gui_gid'])
        data = supervisor.s.inspect_archive(prefix / 'official' / 'archive.tar.gz')
        payload = unpack_payload(data, paths['payload_root'])
        supervisor.s.verify_staged(data, payload)
        supervisor.s.start_gate(payload)
        cursor = supervisor.s.cursor()
        state = supervisor.unit_state(supervisor.unit_name(plan))
        need(state.get('LoadState') == 'not-found', 'unit preexists')
        argv = launch_argv(supervisor, bound, payload, report, paths['stdout'], paths['stderr'])
        launch = True
        supervisor.s.capture(argv, timeout=10)
        state = supervisor.unit_state(supervisor.unit_name(plan))
        invocation = supervisor.owner_check(plan, state)
        supervisor.s.private_write(logs / 'unit-start.json', state)
        seen, completions, clean_exit = observe_until_exit(supervisor, bound, payload, plan, state, invocation, cursor, logs, data)
        supervisor.s.verify_staged(data, payload)
        gpu, schema, bundled = load_report_modules(payload)
        _ident, blob = read_regular(report, REPORT_CAP)
        report_sha = sha_bytes(blob)
        kept = logs / 'gpu-block1.json'
        supervisor.s.private_write(kept, blob)
        document = json.loads(blob.decode())
        need(not schema.errors(json.loads(bundled.gpu_document_schema()), document), 'schema')
        loader_shas = {info['sha256'] for path, info in bound['graphics_before'].items() if Path(path).name.startswith('libvulkan.so')}
        runs = oracle_body(document, bound['plan'], bound['staged_identity']['vulkan']['sha256'], loader_shas, gpu)
        require_order(supervisor, gpu, runs)
        require_order(supervisor, gpu, official_order_from_seen(seen))
        allowed = drm_render_nodes()
        loader_pins = [pin for path, pin in bound['graphics_before'].items() if Path(path).name.startswith('libvulkan.so')]
        check_completions(seen, completions, clean_exit, allowed, bound['staged_identity']['vulkan'], loader_pins, bound['plan']['official_identity']['device']['render_node'])
        signature = supervisor.verify_signature(document, bound['public_identity'], logs)
        need(snapshot_graphics(bound) == bound['graphics_before'], 'graphics pin changed')
        need(signing_fingerprint(bound['state_home']) == bound['signing_before'], 'signing state changed')
        again = recheck_official_identity(bound['plan'], prefix)
        need(again['files'] == bound['identity_observed']['files'] and again['sha256'] == bound['identity_observed']['sha256'], 'official identity changed')
        body = (kept, report_sha, signature, seen)
    except BaseException as error:
        failed = error
        body = None
    finally:
        cleanup, failed = release_execution(supervisor, bound, plan, logs, launch, invocation, cursor, cleanup, failed)
    if failed is not None:
        raise failed
    report, report_sha, signature, seen = body
    return seal(report, report_sha, cleanup, len(seen), signature,
                {'journal_final': str(logs / 'journal-final.jsonl'), 'observer': str(logs / 'observer-final.json'),
                 'report': str(report), 'unit': supervisor.unit_name(plan)})

def unpack_payload(data, root):
    import io, tarfile
    need(not root.exists(), 'payload preexists')
    root.mkdir(mode=0o755)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        for member in tar.getmembers():
            target = root / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o755)
                os.chown(target, 0, 0)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(target.parent, 0o755)
                with tar.extractfile(member) as src, target.open('xb') as dst:
                    dst.write(src.read())
                    dst.flush()
                    os.fsync(dst.fileno())
                os.chmod(target, member.mode)
                os.chown(target, 0, 0)
    for current, dirs, files in os.walk(root):
        os.chmod(current, 0o755)
        os.chown(current, 0, 0)
    return root / 'omarchy-m-test'

def load_report_modules(payload):
    import sys
    sys.path.insert(0, str(payload))
    from omarchy_m_test import bundled, gpu_benchmark, gpu_schema
    return gpu_benchmark, gpu_schema, bundled

def official_order_from_seen(seen):
    return [(item['workload'], item['negative']) for item in seen]

def observe_until_exit(supervisor, bound, payload, plan, state, invocation, cursor, logs, archive_bytes):
    """Sample helpers at the qualified 20ms cadence. Manager calls stay slower."""
    expected = (payload / 'omarchy_m_test' / 'gpu_native' / 'bin' / 'gpu-benchmark-vulkan').resolve()
    seen = {}
    completions = []
    identity_cache = {}
    started = time.monotonic()
    next_health = 0
    next_manager = 0
    state_now = state
    watch = open_fault_monitor(cursor)
    journal = supervisor.s.Journal(bound['plan']['boot_id'])
    try:
        while True:
            now = time.monotonic()
            need(now - started < WALL, 'official wall')
            if now >= next_manager:
                poll_fault_monitor(watch, journal)
                need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == bound['plan']['boot_id'], 'boot id changed')
                if now >= next_health:
                    supervisor.s.verify_staged(archive_bytes, payload)
                    supervisor.s.health_snapshot(payload)
                    next_health = now + 1
                state_now = supervisor.unit_state(supervisor.unit_name(plan))
                next_manager = now + MANAGER_S
            members = supervisor.owned_members(plan, state_now, invocation) or []
            for pid, birth in members:
                try:
                    item = classify_process(pid, birth, expected, bound, check_exe=(pid, birth) not in seen, cache=identity_cache)
                except (RangeUnavailable, ProcessUnavailable) as unavailable:
                    note_unavailable(seen, completions, pid, birth, unavailable)
                    continue
                if item is None:
                    continue
                retain_sample(seen, item)
            if state_now.get('SubState') == 'exited':
                need(supervisor.terminal_success(state_now), 'unit failed')
                need(not members, 'descendants remain')
                break
            need(state_now.get('ActiveState') == 'active' and state_now.get('SubState') == 'running', 'unit not running')
            time.sleep(SAMPLE_S)
    finally:
        close_fault_monitor(watch, bound)
    allowed = drm_render_nodes()
    staged = bound['staged_identity']['vulkan']
    loader_pins = [pin for path, pin in bound['graphics_before'].items() if Path(path).name.startswith('libvulkan.so')]
    items = finish_observations(seen, allowed, staged, loader_pins, bound['plan']['official_identity']['device']['render_node'])
    return items, completions, True

def char_renders(pid):
    renders = []
    for fd in list((Path('/proc') / str(pid) / 'fd').iterdir())[:256]:
        try:
            st = fd.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISCHR(st.st_mode):
            renders.append((os.major(st.st_rdev), os.minor(st.st_rdev)))
    return renders

def provider_role(text):
    name = Path(text).name
    if name.startswith('libvulkan_asahi'):
        return 'implementation'
    if name.startswith('libvulkan.so'):
        return 'loader'
    return None

def provider_maps(pid, cache=None):
    try:
        text = (Path('/proc') / str(pid) / 'maps').read_text()
    except FileNotFoundError:
        raise ProcessUnavailable(pid) from None
    except ProcessLookupError:
        raise ProcessUnavailable(pid) from None
    found = {'implementation': None, 'loader': None}
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            continue
        deleted = fields[5].endswith(' (deleted)')
        path_text = fields[5][:-len(' (deleted)')] if deleted else fields[5]
        if not path_text.startswith('/'):
            continue
        role = provider_role(path_text)
        if role is None:
            continue
        if deleted:
            raise Refuse('deleted provider')
        start, end = fields[0].split('-', 1)
        held = kernel_held_map(pid, start, end, cache)
        need(int(fields[4]) == held['inode'], 'maps inode disagrees with held reference')
        previous = found[role]
        if previous is None:
            found[role] = held
        else:
            need(held_matches(previous, held), 'mapped ' + role + ' drifted')
    return found

def classify_process(pid, birth, expected, bound, check_exe=True, cache=None):
    proc = Path('/proc') / str(pid)
    try:
        if proc.joinpath('exe').resolve() != expected:
            return None
        args = proc.joinpath('cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        decoded = [item.decode() for item in args]
        negative = decoded == [str(expected), '--workload', 'compute', '--negative-control']
        plain = len(decoded) == 3 and decoded[:2] == [str(expected), '--workload'] and decoded[2] in WORKLOADS
        need(plain or negative, 'helper arguments')
        need(proc.stat().st_uid == bound['plan']['gui_uid'], 'helper uid')
        renders = char_renders(pid)
        found = provider_maps(pid, cache)
        if check_exe:
            ident_exe = proc_exe(pid)
            need(ident_exe['sha256'] == HELPER_SHA and ident_exe['magic'] == b'\x7fELF', 'helper elf')
        return {'pid': pid, 'birth': birth, 'workload': 'compute' if negative else decoded[2], 'negative': negative,
                'renders': renders, 'implementation': found['implementation'], 'loader': found['loader']}
    except FileNotFoundError:
        return None

def proc_exe(pid):
    fd = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= HASH_LIMIT, 'helper exe')
        blob = bytearray()
        deadline = time.monotonic() + 5
        while len(blob) < st.st_size:
            need(time.monotonic() < deadline, 'helper exe exceeded 5s')
            chunk = os.read(fd, min(1024 ** 2, st.st_size - len(blob)))
            need(chunk, 'helper exe short')
            blob.extend(chunk)
        return {'sha256': sha_bytes(blob), 'magic': bytes(blob[:4]), 'inode': st.st_ino}
    finally:
        os.close(fd)

def drm_render_nodes():
    found = set()
    root = Path('/sys/class/drm')
    need(root.is_dir(), 'drm class absent')
    for node in root.glob('renderD*'):
        major, minor = node.joinpath('dev').read_text().split(':')
        found.add((int(major), int(minor)))
    need(found, 'no drm render node')
    return found

def write_exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        view = memoryview(raw)
        while view:
            wrote = handle.write(view)
            need(wrote > 0, 'receipt short write')
            view = view[wrote:]
        handle.flush()
        os.fsync(handle.fileno())

def journal_final(supervisor, bound, cursor, logs, cleanup, failed):
    if cursor is None:
        return None
    raw = b''
    error = None if failed is None else failed
    try:
        raw = supervisor.s.capture(['journalctl', '-k', '-b', '--after-cursor=' + cursor, '-o', 'json', '--no-pager', '--all'], limit=supervisor.s.LOG_CAP, timeout=10)
    except Exception as exc:
        error = error or exc
    logs.mkdir(mode=0o700, exist_ok=True)
    final = None
    try:
        write_exclusive(logs / 'journal-final.jsonl', raw)
        if error is None:
            final = screen_journal(supervisor.s, bound['plan']['boot_id'], raw)
    except Exception as exc:
        error = error or exc
    observer = {'cleanup': cleanup, 'journal_records': 0 if final is None else final.records,
                'fault_categories': [] if final is None else sorted(final.categories),
                'journal_error': None if error is None else str(error),
                'error': None if failed is None else str(failed)}
    try:
        write_exclusive(logs / 'observer-final.json', (json.dumps(observer, sort_keys=True) + '\n').encode())
    except Exception as exc:
        error = error or exc
    return None if error is None else str(error)
