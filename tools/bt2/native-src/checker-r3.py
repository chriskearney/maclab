#!/usr/bin/env python3
import errno
"""Normal installed-session GL/VK pixel smoke. Source only until root review.

Reads an explicit manifest and, only after that review gate, checks the
already-running session. It does not install packages, edit configuration,
stage, lease, or boot. The shipped template is not approval.

r3: the kernel release and the six regular provider pins (path, sha256,
bytes) are the COHORT under test and come from the explicit manifest
(bind_cohort, called by frozen_manifest before anything is checked). The
literals below are only the reference cohort (Mesa 7c, kernel 7.2.11-7-1)
of the shipped template and the host tests. Gallium, Vulkan and EGL stay
mandatory; the non-Gallium paths are fixed sonames and Gallium must be
/usr/lib/libgallium-<version>.so. A bound cohort never changes. EGL is
the unchanged wrapper and is not sufficient alone. GL and the compositor
may also map the pinned support files libdril, libGLX_mesa, and libgbm.
A dri soname counts only when its mapped inode is that libdril file.
The two readback tools are the probes-r2 binaries. Each call passes
argv 3, a three-second ceiling, and does not set RENDER_CHECK_RUNS.
The printed run count must be at least 3. The receipt stores that
count and the printed duration. Native maps stay mandatory.
"""
from pathlib import Path
import argparse, hashlib, json, os, pwd, re, selectors, signal, stat, subprocess, time
MIB = 1024 ** 2
SUITE = 'rc-normal-installed-session-smoke-v1'
KERNEL = '7.2.11-7-1-ARCH'
MIN_RUNS = 3
TOOL_SECONDS = 3
CASE_SECONDS = 30
TOTAL_SECONDS = 90
HASH_LIMIT = 64 * MIB
GALLIUM = '/usr/lib/libgallium-26.3.0-devel.so'
EGL = '/usr/lib/libEGL_mesa.so.0.0.0'
VULKAN = '/usr/lib/libvulkan_asahi.so'
DRIL = '/usr/lib/dri/libdril_dri.so'
GLX = '/usr/lib/libGLX_mesa.so.0.0.0'
GBM = '/usr/lib/libgbm.so.1.0.0'
GL_TOOL = '/var/lib/sf-mesa-trueup-20261024/probes-r2/gl-render-check-aarch64'
VK_TOOL = '/var/lib/sf-mesa-trueup-20261024/probes-r2/vk-render-check-aarch64'
PROVIDERS = {
    'gallium': {'path': GALLIUM, 'sha256': 'f1c4a87bf69c0468d40295fab2183ec219e2e3d91f1df700db9ea9e3b8588676', 'bytes': 32409208},
    'egl': {'path': EGL, 'sha256': '19f5a8d8249b894c0fd4fe97c557d67a10f604aa099a25a765492fbc963c6b9e', 'bytes': 396392},
    'vulkan': {'path': VULKAN, 'sha256': '86cef05867f62be3f6aa967b69ff18f81bd107cbafd27a74aff2031892ceee75', 'bytes': 28083280},
    'dril': {'path': DRIL, 'sha256': 'a6ae89538c276a053bd88c985b8b3f966ed163822b86bc639629dc525ba20455', 'bytes': 133272},
    'glx': {'path': GLX, 'sha256': 'ef6e93257fb7b79dd750dfd10f232f11d2d6c1661624d6c7e10cc0b70d25594e', 'bytes': 395984},
    'gbm': {'path': GBM, 'sha256': '01acc4059e9d8d326a0deec1548c08d009acfeb11710adc56592adf85a42b4be', 'bytes': 67632},
}
# Archive symlinks. A map using the soname is the target regular file only when the inode matches.
ALIASES = {
    '/usr/lib/libEGL_mesa.so.0': EGL,
    '/usr/lib/libGLX_mesa.so.0': GLX,
    '/usr/lib/libgbm.so.1': GBM,
    '/usr/lib/dri/asahi_dri.so': DRIL,
    '/usr/lib/dri/kms_swrast_dri.so': DRIL,
    '/usr/lib/dri/swrast_dri.so': DRIL,
}
TOOLS = {
    'gl_pixels': {'path': GL_TOOL, 'sha256': '24007754c92e05220edc4645702853ac86c0ff5d98c084da126955ccdd4d6e82'},
    'vk_pixels': {'path': VK_TOOL, 'sha256': 'e4a7b8d50c10d1cc3bf40c1dcaf9e74cd566ebb1901857e84b06256bbdf0d40d'},
}
REQUIRED = {'GL': (GALLIUM, EGL), 'VK': (VULKAN,), 'compositor': (GALLIUM,)}
SUPPORT = {DRIL, GLX, GBM}
ALLOWED = {
    'GL': {GALLIUM, EGL} | SUPPORT,
    'VK': {VULKAN},
    'compositor': {GALLIUM, EGL} | SUPPORT,
}
# r3 cohort binding. Fixed sonames per role; only Gallium's file name carries the Mesa version.
PROVIDER_ROLES = ('gallium', 'egl', 'vulkan', 'dril', 'glx', 'gbm')
ROLE_PATHS = {'egl': EGL, 'vulkan': VULKAN, 'dril': DRIL, 'glx': GLX, 'gbm': GBM}
GALLIUM_PATH = re.compile(r'^/usr/lib/libgallium-[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\.so$')
KERNEL_RELEASE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$')
_BOUND = None
FAULT = re.compile(r'BUG:|Oops:|Kernel panic|soft lockup|RCU.*stall|(?:asahi|agx).*(?:fault|timed? ?out|reset|hang)|(?:DART|apple-dart).*fault|oom-kill:|I/O error|BTRFS.*(?:error|corrupt)', re.I)
BAD = re.compile(r'llvmpipe|lavapipe|softpipe|software raster', re.I)
GRAPHICS = re.compile(r'libEGL_mesa|libgallium-|libvulkan_|/dri/.*\.so|libGLX_mesa|libgbm|mesa-m3|llvmpipe|swrast')
FORBIDDEN = {
    'LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT', 'VK_DRIVER_FILES', 'VK_ICD_FILENAMES',
    'VK_ADD_DRIVER_FILES', 'VK_LAYER_PATH', 'VK_LOADER_LAYERS_ENABLE', 'VK_LOADER_DRIVERS_SELECT',
    '__EGL_VENDOR_LIBRARY_FILENAMES', '__GLX_VENDOR_LIBRARY_NAME', 'LIBGL_DRIVERS_PATH',
    'LIBGL_ALWAYS_SOFTWARE', 'GBM_ALWAYS_SOFTWARE', 'GBM_BACKENDS_PATH', 'GALLIUM_DRIVER',
    'MESA_LOADER_DRIVER_OVERRIDE', 'MESA_GL_VERSION_OVERRIDE', 'MESA_VK_DEVICE_SELECT', 'MESA_M3_FALLBACK',
}
CHILD_KEYS = (
    'PATH', 'HOME', 'USER', 'LOGNAME', 'LC_ALL', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
    'XDG_SESSION_TYPE', 'HYPRLAND_INSTANCE_SIGNATURE', 'WAYLAND_DISPLAY',
    'RENDER_CHECK_RENDERER', 'RENDER_CHECK_DEVICE',
)
HEX64 = re.compile(r'^[0-9a-f]{64}$')
BOOT = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
MAC = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')

def need(v, msg):
    if not v:
        raise ValueError(msg)

def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, doc):
    raw = (json.dumps(doc, sort_keys=True, indent=2) + '\n').encode()
    need(len(raw) < 4 * MIB, 'receipt above 4MiB')
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        off = 0
        while off < len(view):
            n = os.write(fd, view[off:])
            if n <= 0:
                raise OSError('short write')
            off += n
        os.fsync(fd)
    finally:
        os.close(fd)
    need(regular_sha256(path, len(raw))['sha256'] == sha_bytes(raw), 'receipt readback mismatch')
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)

def command(args, timeout=5):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    need(r.returncode == 0, 'read-only command failed: ' + args[0])
    need(len(r.stdout) < MIB, 'command output too large')
    return r.stdout

def file_identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def regular_sha256(path, expect_size=None):
    # O_PATH refuses a FIFO, device, or symlink. Reopen that held regular inode NONBLOCK.
    meta = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(meta)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('not a regular file')
        if before.st_size <= 0 or before.st_size > HASH_LIMIT:
            raise ValueError('regular file size out of bounds')
        if expect_size is not None and before.st_size != expect_size:
            raise ValueError('provider size mismatch')
        ident_key = file_identity(before)
        fd = os.open('/proc/self/fd/' + str(meta), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            need(stat.S_ISREG(opened.st_mode) and file_identity(opened) == ident_key, 'reopened inode drift')
            h = hashlib.sha256()
            n = 0
            deadline = time.monotonic() + 5
            while n <= before.st_size:
                if time.monotonic() > deadline:
                    raise TimeoutError('regular read exceeded 5s')
                try:
                    chunk = os.read(fd, min(1048576, before.st_size + 1 - n))
                except BlockingIOError:
                    raise ValueError('regular read would block')
                if not chunk:
                    break
                n += len(chunk)
                h.update(chunk)
            need(n == before.st_size and file_identity(os.fstat(fd)) == ident_key, 'file changed during read')
        finally:
            os.close(fd)
        need(file_identity(os.lstat(path)) == ident_key, 'path identity drift')
    finally:
        os.close(meta)
    return {'path': str(path), 'major': os.major(before.st_dev), 'minor': os.minor(before.st_dev), 'inode': before.st_ino, 'size': before.st_size, 'sha256': h.hexdigest()}

def parse_maps(text):
    if len(text) > 8 * MIB:
        raise ValueError('unknown maps: too large')
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 5)
        if len(parts) < 5 or not re.fullmatch(r'[0-9a-fA-F]+:[0-9a-fA-F]+', parts[3]) or not parts[4].isdigit():
            raise ValueError('unknown map line')
        major, minor = (int(x, 16) for x in parts[3].split(':'))
        path = parts[5] if len(parts) == 6 else ''
        deleted = path.endswith(' (deleted)')
        if deleted:
            path = path[:-len(' (deleted)')]
        if path.startswith('[') or (not path and int(parts[4]) == 0):
            continue
        if not path.startswith('/'):
            raise ValueError('unknown map path')
        need(re.fullmatch(r'[0-9a-fA-F]+-[0-9a-fA-F]+', parts[0]) is not None, 'unknown map range')
        lo, hi = (int(x, 16) for x in parts[0].split('-'))
        need(0 <= lo < hi and re.fullmatch(r'[r-][w-][x-][ps]', parts[1]) is not None and re.fullmatch(r'[0-9a-fA-F]+', parts[2]) is not None, 'invalid map range/perms/offset')
        out.append({'range': parts[0].lower(), 'perms': parts[1], 'offset': int(parts[2], 16), 'path': path, 'major': major, 'minor': minor, 'inode': int(parts[4]), 'deleted': deleted})
    return out

def graphics_maps(parsed):
    return [m for m in parsed if GRAPHICS.search(m['path'])]

def provider_for(path):
    if path in ALLOWED['GL'] or path in ALLOWED['VK'] or path in ALLOWED['compositor']:
        return path
    return ALIASES.get(path)

def guarded(parsed, role):
    rows = []
    for m in graphics_maps(parsed):
        if m['deleted']:
            raise ValueError('deleted map ' + m['path'])
        provider = provider_for(m['path'])
        if provider not in ALLOWED[role]:
            raise ValueError('unknown map ' + m['path'])
        rows.append({**m, 'provider': provider})
    return rows

def assess(parsed, role):
    rows = guarded(parsed, role)
    seen = {m['provider'] for m in rows}
    if role == 'GL' and EGL in seen and GALLIUM not in seen:
        raise ValueError('EGL wrapper without Gallium')
    for path in REQUIRED[role]:
        if path not in seen:
            raise ValueError('missing mapped provider ' + path)
    return rows

class OwnedProcUnavailable(OSError):
    def __init__(self, pid, birth, phase, number, mapping=None):
        self.pid, self.birth, self.phase, self.mapping = pid, birth, phase, mapping
        super().__init__(number, 'owned /proc read unavailable: ' + phase)

def proc_read(pid, leaf, birth=None):
    need(isinstance(pid, int) and pid > 0 and leaf in ('stat', 'maps', 'environ', 'cmdline', 'status'), 'unknown owned proc read')
    try:
        return Path(f'/proc/{pid}/{leaf}').read_bytes()
    except OSError as e:
        if e.errno in (errno.ENOENT, errno.ESRCH):
            raise OwnedProcUnavailable(pid, birth, leaf, e.errno) from e
        raise

def proc_birth(pid):
    raw = proc_read(pid, 'stat')
    need(len(raw) < 16384, 'process stat too large')
    return int(raw.rsplit(b') ', 1)[1].split()[19])

def require_owned_proc(pid, leader, birth):
    raw = proc_read(pid, 'stat', birth)
    need(len(raw) < 16384, 'process stat too large')
    fields = raw.rsplit(b') ', 1)[1].split()
    need(int(fields[19]) == birth, 'owned PID birth drift')
    need(int(fields[2]) == leader, 'process no longer belongs to owned group')

def map_signature(mapping):
    return tuple(mapping[k] for k in ('range', 'perms', 'offset', 'path', 'major', 'minor', 'inode', 'deleted'))

class MapRangeRetired(ValueError):
    def __init__(self, mapping):
        self.mapping = dict(mapping)
        super().__init__("previously sampled map range retired/changed")

def current_mapping(mapping):
    need(isinstance(mapping.get('pid'), int) and mapping['pid'] > 0 and isinstance(mapping.get('birth'), int), 'missing mapped PID birth')
    try:
        need(proc_birth(mapping['pid']) == mapping['birth'], 'mapped PID replaced')
        rows = parse_maps(proc_read(mapping['pid'], 'maps', mapping['birth']).decode())
        matches = [r for r in rows if r['range'] == mapping['range']]
        need(proc_birth(mapping['pid']) == mapping['birth'], 'mapped PID replaced during range check')
        if len(matches) != 1 or map_signature(matches[0]) != map_signature(mapping):
            raise MapRangeRetired(mapping)
    except OwnedProcUnavailable as e:
        raise OwnedProcUnavailable(e.pid, mapping['birth'], e.phase, e.errno, dict(mapping)) from e

def held_regular_sha256(meta, expect_size):
    before = os.fstat(meta)
    need(stat.S_ISREG(before.st_mode) and before.st_size == expect_size and 0 < before.st_size <= HASH_LIMIT, 'mapped descriptor is not bounded regular provider')
    key = file_identity(before)
    fd = os.open('/proc/self/fd/' + str(meta), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        need(file_identity(os.fstat(fd)) == key, 'mapped descriptor reopen drift')
        h = hashlib.sha256(); n = 0; deadline = time.monotonic() + 5
        while n <= before.st_size:
            need(time.monotonic() <= deadline, 'mapped hash deadline')
            data = os.read(fd, min(1048576, before.st_size + 1 - n))
            if not data: break
            h.update(data); n += len(data)
        need(n == before.st_size and file_identity(os.fstat(fd)) == key and file_identity(os.fstat(meta)) == key, 'mapped descriptor changed')
    finally:
        os.close(fd)
    return {'major': os.major(before.st_dev), 'minor': os.minor(before.st_dev), 'inode': before.st_ino, 'size': before.st_size, 'sha256': h.hexdigest()}

def same_provider_descriptor(mapped, live):
    # Device is mandatory: equal Btrfs inode numbers from different subvolumes are not the same file.
    keys = ('major', 'minor', 'inode', 'size', 'sha256')
    need(all(mapped[k] == live[k] for k in keys), 'replaced/different-subvolume mapped descriptor')

class MapWitnesses:
    """One case only; retained O_PATH fds prevent cached inode recycling."""
    def __init__(self):
        self.hashes = {}
        self.bindings = {}
        self.live_keys = {}

    @staticmethod
    def key(mapping):
        return (mapping['pid'], mapping['birth'], map_signature(mapping))

    def digest(self, meta, mapping, size):
        identity = file_identity(os.fstat(meta))
        key = (mapping['pid'], mapping['birth'], identity)
        cached = self.hashes.get(key)
        if cached is not None:
            fd, value = cached
            need(file_identity(os.fstat(fd)) == identity, 'cached mapped descriptor changed')
            return dict(value)
        need(len(self.hashes) < 64, 'too many provider descriptor witnesses')
        value = held_regular_sha256(meta, size)
        self.hashes[key] = (os.dup(meta), dict(value))
        return value

    def commit(self, mapping, mapped_key, live_key):
        key = self.key(mapping)
        pair = (mapped_key, live_key)
        need(key not in self.bindings or self.bindings[key] == pair, 'mapped/live full identity changed')
        provider = mapping.get("provider") or provider_for(mapping["path"])
        need(provider not in self.live_keys or self.live_keys[provider] == live_key, "live provider full identity changed")
        self.live_keys[provider] = live_key
        self.bindings[key] = pair

    def witnessed(self, mapping):
        return self.key(mapping) in self.bindings

    def verify_live(self):
        need(self.live_keys, 'no live provider witnesses')
        for path, expected in self.live_keys.items():
            meta = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                st = os.fstat(meta)
                need(stat.S_ISREG(st.st_mode) and file_identity(st) == expected and file_identity(os.lstat(path)) == expected, 'live provider full identity changed')
            finally:
                os.close(meta)
        for (_, _, expected), (fd, _) in self.hashes.items():
            need(file_identity(os.fstat(fd)) == expected, 'retained descriptor changed')

    def close(self):
        for fd, _ in self.hashes.values():
            os.close(fd)
        self.hashes.clear()
        self.bindings.clear()
        self.live_keys.clear()

def mapped_provider(mapping, live, witnesses=None):
    need(not mapping['deleted'], 'deleted map')
    own = witnesses is None
    if own: witnesses = MapWitnesses()
    meta = live_meta = None
    try:
        current_mapping(mapping)
        path = f"/proc/{mapping['pid']}/map_files/{mapping['range']}"
        # Only this validated kernel magic link is followed. Both fstats precede data opens.
        try:
            meta = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ESRCH):
                raise OwnedProcUnavailable(mapping['pid'], mapping['birth'], 'map_files', e.errno, dict(mapping)) from e
            raise
        live_meta = os.open(live['path'], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        mapped_stat, live_stat = os.fstat(meta), os.fstat(live_meta)
        for st in (mapped_stat, live_stat):
            need(stat.S_ISREG(st.st_mode) and st.st_size == live['size'] and 0 < st.st_size <= HASH_LIMIT, 'mapped/live descriptor is not bounded regular provider')
        mapped_key, live_key = file_identity(mapped_stat), file_identity(live_stat)
        key = witnesses.key(mapping)
        if key in witnesses.bindings:
            need(witnesses.bindings[key] == (mapped_key, live_key), 'mapped/live full identity changed')
        mapped = witnesses.digest(meta, mapping, live['size'])
        current = witnesses.digest(live_meta, mapping, live['size'])
        same_provider_descriptor(mapped, current)
        same_provider_descriptor(current, live)
        need(mapped['inode'] == mapping['inode'], 'maps/map_files inode disagreement')
        need(file_identity(os.fstat(meta)) == mapped_key and file_identity(os.fstat(live_meta)) == live_key and file_identity(os.lstat(live['path'])) == live_key, 'mapped/live descriptor drift')
        # The opened kernel descriptor has now proved the live mapped file.
        # Retain that witness even if its VMA retires during the final range check.
        witnesses.commit(mapping, mapped_key, live_key)
        current_mapping(mapping)
        return mapped
    finally:
        if meta is not None: os.close(meta)
        if live_meta is not None: os.close(live_meta)
        if own: witnesses.close()

def confirm_rows(rows, cache, mapped_reader=None, witnesses=None):
    own = witnesses is None
    if own: witnesses = MapWitnesses()
    out = {}
    try:
        for m in rows:
            provider = m.get('provider') or provider_for(m['path'])
            ident = cache.get(provider)
            need(ident is not None and not m['deleted'], 'unknown/deleted mapped provider')
            mapped = mapped_provider(m, ident, witnesses) if mapped_reader is None else mapped_reader(m, ident)
            same_provider_descriptor(mapped, ident)
            out[provider] = ident['sha256']
        return out
    finally:
        if own: witnesses.close()

def complete_provider_set(paths, api):
    return set(REQUIRED[api]).issubset(paths) and (api != 'GL' or GALLIUM in paths)

def validate_owned_exits(exits, complete, returncode, text):
    if exits:
        need(complete and returncode == 0, 'vanished child without complete witness and clean exit')
        parse_pixels(text)  # A genuine oracle pass is mandatory, never inferred from disappearance.

def clean_environ(raw):
    need(len(raw) < MIB, 'environ too large')
    bad = []
    for item in raw.split(b'\0'):
        if not item:
            continue
        if b'=' not in item:
            raise ValueError('unknown environ')
        key, val = item.split(b'=', 1)
        name = key.decode('ascii', 'replace')
        text = val.decode('utf-8', 'replace')
        if name in FORBIDDEN or 'mesa-m3' in text or '/opt/mesa-m3' in text or '/var/tmp/sf-' in text or BAD.search(text):
            bad.append(name)
    need(not bad, 'graphics env override: ' + ','.join(bad))

def child_env(user, home, runtime, signature, wayland):
    env = {
        'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': home, 'USER': user, 'LOGNAME': user, 'LC_ALL': 'C',
        'XDG_RUNTIME_DIR': runtime, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus',
        'XDG_SESSION_TYPE': 'wayland', 'HYPRLAND_INSTANCE_SIGNATURE': signature, 'WAYLAND_DISPLAY': wayland,
        'RENDER_CHECK_RENDERER': 'Apple', 'RENDER_CHECK_DEVICE': 'Apple',
    }
    need(set(env) == set(CHILD_KEYS), 'child env key drift')
    need(not (set(env) & FORBIDDEN), 'child env carries a driver override')
    return env

def prefix(user, env):
    return ['/usr/sbin/runuser', '-u', user, '--', '/usr/bin/env', '-i', *[k + '=' + v for k, v in env.items()]]

def work_banner(api, text):
    # Frozen helpers fflush this checked-work banner before entering the loop.
    name = 'gl' if api == 'GL' else 'vk'
    expected = f'{name}-render-check: 64x64 clear + 48x48 triangle, {TOOL_SECONDS} s'
    return expected in text.splitlines()

def parse_pixels(text):
    need(not BAD.search(text), 'software renderer detected')
    need(re.search(r'(?:Renderer:|Device:)\s*.*Apple', text), 'Apple renderer/device absent')
    found = re.search(r'PASS: (\d+) runs in ([\d.]+) s, 0 with wrong pixels', text)
    need(found, 'pixel pass line absent')
    runs = int(found.group(1))
    need(runs >= MIN_RUNS, 'reported runs below 3')
    need(not re.search(r'FAIL:|error|timed out', text, re.I), 'pixel mismatch/failure')
    return {'wrong_pixels': 0, 'runs': runs, 'duration_s': found.group(2)}

def topology(monitors):
    need(isinstance(monitors, list) and monitors, 'no display')
    out = []
    for row in monitors:
        item = {k: row.get(k) for k in ('name', 'width', 'height', 'refreshRate', 'scale', 'transform', 'disabled')}
        need(item['name'] and item['width'] and item['height'] and item['width'] > 0 and item['height'] > 0 and not item['disabled'], 'inactive display')
        out.append(item)
    return out

def faults_of(text):
    rows = [line for line in text.splitlines() if FAULT.search(line)]
    need(len(rows) <= 500, 'unknown fault volume')
    return rows

def wifi_view(interface, mac, nmcli_text, operstate):
    line = interface + ':wifi:connected'
    need(line in nmcli_text.splitlines(), 'Wi-Fi disconnected')
    need(operstate == 'up', 'Wi-Fi operstate is not up')
    return {'interface': interface, 'mac': mac, 'state': 'connected', 'operstate': operstate}

def stable(before, after):
    for key in ('boot_id', 'kernel', 'board', 'monitors', 'wifi', 'faults', 'compositor_gallium'):
        need(before[key] == after[key], 'state changed: ' + key)

def validate_cohort(kernel, providers):
    """Strict form of a cohort: explicit kernel release, exactly the six roles, fixed sonames (Gallium versioned),
    lowercase sha256, positive size within the hash limit, distinct paths and hashes. Returns the canonical pins."""
    need(isinstance(kernel, str) and KERNEL_RELEASE.fullmatch(kernel), 'cohort kernel release is not explicit')
    need(isinstance(providers, dict) and set(providers) == set(PROVIDER_ROLES), 'cohort provider roles')
    pins = {}
    for role in PROVIDER_ROLES:
        p = providers[role]
        need(isinstance(p, dict), 'cohort provider pin is not explicit: ' + role)
        path, digest, size = p.get('path'), p.get('sha256'), p.get('bytes')
        if role == 'gallium':
            need(isinstance(path, str) and GALLIUM_PATH.fullmatch(path), 'cohort provider path: gallium')
        else:
            need(path == ROLE_PATHS[role], 'cohort provider path: ' + role)
        need(isinstance(digest, str) and HEX64.fullmatch(digest), 'cohort provider sha256: ' + role)
        need(type(size) is int and 0 < size <= HASH_LIMIT, 'cohort provider size: ' + role)
        pins[role] = {'path': path, 'sha256': digest, 'bytes': size}
    need(len({p['path'] for p in pins.values()}) == len(pins), 'cohort provider paths are not distinct')
    need(len({p['sha256'] for p in pins.values()}) == len(pins), 'cohort provider hashes are not distinct')
    return kernel, pins

def bind_cohort(kernel, providers):
    """Bind the cohort under test once; every later check reads these globals. Rebinding must be identical."""
    global KERNEL, GALLIUM, PROVIDERS, REQUIRED, ALLOWED, _BOUND
    kernel, pins = validate_cohort(kernel, providers)
    key = json.dumps([kernel, pins], sort_keys=True)
    need(_BOUND is None or _BOUND == key, 'cohort already bound to different pins')
    gallium = pins['gallium']['path']
    KERNEL, GALLIUM, PROVIDERS = kernel, gallium, pins
    REQUIRED = {'GL': (GALLIUM, EGL), 'VK': (VULKAN,), 'compositor': (GALLIUM,)}
    ALLOWED = {'GL': {GALLIUM, EGL} | SUPPORT, 'VK': {VULKAN}, 'compositor': {GALLIUM, EGL} | SUPPORT}
    _BOUND = key
    return kernel, pins

def frozen_manifest(m):
    need(m.get('suite') == SUITE, 'wrong suite')
    need(m.get('source_review') == 'accepted-by-root', 'root source review is not recorded')
    need(m.get('approved') is True, 'manifest is not approved')
    bind_cohort(m.get('expected_kernel'), m.get('providers'))
    need(m.get('expected_kernel') == KERNEL, 'manifest kernel is not the bound cohort kernel')
    need('frames' not in m, 'exact frame cap is not the schedule')
    need(m.get('minimum_runs') == MIN_RUNS and m.get('tool_seconds') == TOOL_SECONDS, 'readback schedule drift')
    need(m.get('case_seconds') == CASE_SECONDS and m.get('total_seconds') == TOTAL_SECONDS, 'timeout schedule drift')
    need(isinstance(m.get('gui_uid'), int) and m['gui_uid'] > 0, 'GUI uid is not an explicit user')
    need(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}$', str(m.get('gui_user', ''))) and m['gui_user'] != 'root', 'GUI user is not explicit')
    need(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}$', str(m.get('device', ''))), 'device is not explicit')
    need(re.fullmatch(r'apple,[a-z0-9]+$', str(m.get('board', ''))), 'board is not explicit')
    need(BOOT.fullmatch(str(m.get('expected_boot_id', ''))), 'expected boot is not explicit')
    need(HEX64.fullmatch(str(m.get('token', ''))), 'token is not explicit')
    need(re.fullmatch(r'[A-Za-z0-9._-]+', str(m.get('wifi_interface', ''))), 'Wi-Fi interface is not explicit')
    need(MAC.fullmatch(str(m.get('wifi_mac', ''))), 'Wi-Fi MAC is not explicit')
    need(m.get('output_dir') == '/var/tmp/sf-rc-normal-session-' + m['token'][:16], 'private output path is not bound to the token')
    need(m.get('tools') == TOOLS, 'tool path or hash drift')
    for name, pin in PROVIDERS.items():
        got = m.get('providers', {}).get(name, {})
        need({k: got.get(k) for k in ('path', 'sha256', 'bytes')} == pin, 'provider drift: ' + name)
    need(m['providers']['egl'].get('note') == 'unchanged wrapper; insufficient alone', 'EGL note drift')
    return m

def require_mac():
    need(os.geteuid() == 0 and os.uname().machine == 'aarch64', 'run only as root on the installed aarch64 session')

def group(leader):
    out = []
    for p in Path('/proc').glob('[0-9]*'):
        try:
            if os.getpgid(int(p.name)) == leader:
                out.append(int(p.name))
        except (ProcessLookupError, PermissionError, ValueError):
            pass
    return out

def stop_group(proc):
    if proc is None:
        return []
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    for _ in range(20):
        remaining = []
        for pid in group(proc.pid):
            try:
                if Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[0] != 'Z':
                    remaining.append(pid)
            except FileNotFoundError:
                pass
        if not remaining:
            return []
        time.sleep(0.05)
    return remaining

def read_maps(pids):
    rows = []
    for pid in pids:
        birth = proc_birth(pid)
        text = proc_read(pid, 'maps', birth).decode()
        parsed = parse_maps(text)
        need(proc_birth(pid) == birth, 'PID replaced while reading maps')
        rows.extend({**row, 'pid': pid, 'birth': birth} for row in parsed)
    return rows

class LaunchTransition(ValueError):
    """A typed, pre-proof exec/UID-drop boundary; never provider evidence."""
    def __init__(self,pid,birth,phase):
        self.pid,self.birth,self.phase=pid,birth,phase
        super().__init__('pre-witness launch transition: '+phase)

class ExitPending(ValueError):
    """Typed retry: the witnessed unique tool's exe is gone (exit released its mm)
    but it is not yet Z/X/absent; same pid, birth and owned group. Never evidence."""
    def __init__(self,pid,birth):
        self.pid,self.birth=pid,birth
        super().__init__('owned process exit not yet terminal')

class RunningImages:
    """Held ELF identity plus exact argv; only one native tool image per case."""
    def __init__(self, tool, expected_sha, command=None, gui_uid=None):
        self.pins = {}; self.actual = {}; self.admitted = {}; self.unique = None; self.gui_uid = gui_uid
        self.add('tool', tool, [tool, str(TOOL_SECONDS)], expected_sha)
        if command is not None:
            env_index = command.index('/usr/bin/env')
            self.add('launcher', command[0], command)
            self.add('environment', '/usr/bin/env', command[env_index:])

    def add(self, role, path, argv, expected=None):
        canonical = os.path.realpath(path)
        fd = os.open(canonical, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode), 'tool image is not regular')
            digest = held_regular_sha256(fd, st.st_size)['sha256']
            need(expected is None or digest == expected, 'tool image hash drift')
            self.pins[role] = {'fd': fd, 'path': canonical, 'identity': file_identity(st), 'sha256': digest, 'argv': b'\0'.join(os.fsencode(x) for x in argv)+b'\0'}
        except BaseException:
            os.close(fd); raise

    def live(self):
        for pin in self.pins.values():
            need(file_identity(os.fstat(pin['fd'])) == pin['identity'] and file_identity(os.lstat(pin['path'])) == pin['identity'], 'live tool/launcher image changed')

    def admitted_non_tool(self,pid,birth):
        return self.admitted.get((pid,birth)) in ("launcher","environment") and self.unique != (pid,birth)

    def argv_race(self, pid, birth, role, ident, argv, leader):
        # Only after a cmdline read that differs from the pin. A fresh exe link
        # types two proven kernel races; anything else returns to the unchanged
        # argv failure. Neither raise is evidence.
        try: fd = os.open(f'/proc/{pid}/exe', os.O_PATH | os.O_CLOEXEC)
        except OSError as e:
            # Exit: exe and cmdline both read task->mm; exit_mm() cleared it.
            if argv or e.errno not in (errno.ENOENT, errno.ESRCH) or proc_birth(pid) != birth: return
            raise OwnedProcUnavailable(pid, birth, 'exe', e.errno) from e
        try: now = file_identity(os.fstat(fd))
        finally: os.close(fd)
        # Exec: a non-leader launcher/env image was replaced between exe and cmdline.
        if argv and now != ident and role in ('launcher', 'environment') and self.unique != (pid,birth) and leader is not None and pid != leader and proc_birth(pid) == birth:
            raise LaunchTransition(pid, birth, 'exec-during-argv-read')

    def check(self, pid, birth, leader=None):
        self.live(); need(proc_birth(pid) == birth, 'tool PID birth changed')
        fd = after = None
        try:
            try: fd = os.open(f'/proc/{pid}/exe', os.O_PATH | os.O_CLOEXEC)
            except OSError as e:
                if e.errno in (errno.ENOENT, errno.ESRCH): raise OwnedProcUnavailable(pid, birth, 'exe', e.errno) from e
                raise
            st = os.fstat(fd); ident = file_identity(st)
            need(stat.S_ISREG(st.st_mode), 'running tool image not regular')
            roles = [role for role,pin in self.pins.items() if pin['identity'] == ident]
            need(len(roles) == 1, 'unadmitted running process image or exec transition')
            role = roles[0]; pin = self.pins[role]
            need(self.unique is None or (pid,birth) != self.unique or role == 'tool', 'admitted tool executed another image')
            argv=proc_read(pid,'cmdline',birth)
            if argv != pin['argv']:self.argv_race(pid,birth,role,ident,argv,leader)
            if not argv and self.unique != (pid,birth):raise LaunchTransition(pid,birth,'empty-exec-argv')
            need(argv == pin['argv'], 'running tool/launcher argv mismatch')
            if self.gui_uid is not None:
                match = re.search(rb'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$', proc_read(pid,'status',birth), re.M)
                want = 0 if role == 'launcher' else self.gui_uid
                if match and role=='launcher' and leader is not None and pid!=leader and self.unique!=(pid,birth) and all(int(x)==self.gui_uid for x in match.groups()):
                    raise LaunchTransition(pid,birth,'launcher-child-uid-drop')
                need(match and all(int(x) == want for x in match.groups()), 'running tool UID mismatch')
            key = (pid,birth,role,ident)
            if key not in self.actual:
                need(len(self.actual) < 16, 'actual image witness budget')
                need(held_regular_sha256(fd,st.st_size)['sha256'] == pin['sha256'], 'actual running image SHA mismatch')
                self.actual[key] = os.dup(fd)
            need(file_identity(os.fstat(self.actual[key])) == ident, 'held actual image drift')
            try: after = os.open(f'/proc/{pid}/exe', os.O_PATH | os.O_CLOEXEC)
            except OSError as e:
                if e.errno in (errno.ENOENT,errno.ESRCH):raise OwnedProcUnavailable(pid,birth,'exe',e.errno) from e
                raise
            need(file_identity(os.fstat(after)) == ident and proc_birth(pid) == birth,'image/birth changed during observation')
            argv_after=proc_read(pid,'cmdline',birth)
            if argv_after != pin['argv']:self.argv_race(pid,birth,role,ident,argv_after,leader)
            if not argv_after and self.unique!=(pid,birth):raise LaunchTransition(pid,birth,'empty-exec-argv')
            need(argv_after==pin['argv'],'image/argv changed during observation')
            if role == 'tool':
                need(self.unique is None or self.unique == (pid,birth), 'multiple admitted native tool processes')
                self.unique = (pid,birth)
            self.admitted[(pid,birth)]=role
            return role
        finally:
            if fd is not None:os.close(fd)
            if after is not None:os.close(after)

    def require_tool(self, pid, birth, leader, terminal_ok=False):
        try:need(self.check(pid,birth,leader) == 'tool', 'non-tool image cannot supply provider witness')
        except OwnedProcUnavailable as e:
            # Ordinary sampling must preserve the typed disappearance so its
            # existing complete-provider/environment retirement gate handles it.
            if not terminal_ok:
                raise
            need(self.unique == (pid,birth), 'tool image unavailable before a verified terminal/absent process')
            if not terminal_or_absent(pid,birth,leader):
                # Exit in progress (exe gone, same birth and group, not yet Z/X): typed retry only.
                need(e.phase == 'exe' and (e.pid,e.birth) == (pid,birth), 'tool image unavailable before a verified terminal/absent process')
                raise ExitPending(pid,birth)
            self.live()

    def close(self):
        for pin in self.pins.values():os.close(pin['fd'])
        for fd in self.actual.values():os.close(fd)
        self.pins.clear();self.actual.clear();self.admitted.clear()

COMPLETION_GRACE = 5.0

class CompletionState:
    def __init__(self, images=None, leader=None):
        self.deadline = None
        self.events = []
        self.retired = {}
        self.images, self.leader = images, leader

    def check(self):
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise TimeoutError('provider retirement completion grace exceeded')

    def remember(self, rows):
        # Capture only fresh, fully bound sample rows; stale loader bindings are
        # not a first-work baseline. A later provider cannot overwrite history.
        check_retired_addresses(rows, self)
        for row in rows:
            key = (row['pid'], row['birth'], row['range'])
            self.retired.setdefault(key, row.get('provider') or provider_for(row['path']))

    def begin(self, pid, birth, phase, complete, env_witnesses, witnesses, mapping=None):
        need((pid, birth) in complete and (pid, birth) in env_witnesses, 'retirement without prior complete provider/environment witness')
        if mapping is not None:
            need(witnesses.witnessed(mapping), 'retirement of unverified new mapping')
        if self.images is not None:
            try:self.images.require_tool(pid,birth,self.leader,terminal_ok=True)
            except ExitPending:
                # The existing grace bounds the wait; providers stay verified; no event yet.
                witnesses.verify_live()
                if self.deadline is None: self.deadline = time.monotonic() + COMPLETION_GRACE
                self.check(); raise
        witnesses.verify_live()
        if mapping is not None:self.remember([mapping])
        if self.deadline is None:
            self.deadline = time.monotonic() + COMPLETION_GRACE
        self.check()
        event = {'pid': pid, 'birth': birth, 'phase': phase, 'range': mapping.get('range') if mapping else None}
        if event not in self.events:
            need(len(self.events) < 128, 'too many retirement events')
            self.events.append(event)
        return event

def unavailable_identity(error, complete, env_witnesses):
    prior = [identity for identity in complete if identity[0] == error.pid]
    need(len(prior) == 1, 'vanished child without prior complete provider witness')
    identity = prior[0]
    need(identity in env_witnesses and error.birth in (None, identity[1]), 'vanished child without same-birth environment witness')
    return identity

def retirement_scan(pid, birth, leader, api):
    # Every currently mapped graphics row still goes through ordinary admission.
    actual = proc_birth(pid)
    need(actual == birth, 'owned PID was reused')
    require_owned_proc(pid, leader, birth)
    rows = guarded(read_maps([pid]), api)
    need(all(row['birth'] == birth for row in rows), 'owned PID birth drift')
    return rows

def check_retired_addresses(rows, completion):
    for row in rows:
        lo, hi = (int(x, 16) for x in row['range'].split('-'))
        provider = row.get('provider') or provider_for(row['path'])
        for (pid, birth, old_range), previous in completion.retired.items():
            if (pid, birth) != (row['pid'], row['birth']): continue
            old_lo, old_hi = (int(x, 16) for x in old_range.split('-'))
            need(hi <= old_lo or old_hi <= lo or provider == previous, 'retired address reused by different graphics provider')

def terminal_or_absent(pid, birth, leader):
    try:
        raw = proc_read(pid, 'stat', birth)
    except OwnedProcUnavailable:
        return True
    need(len(raw) < 16384, 'process stat too large')
    fields = raw.rsplit(b') ', 1)[1].split()
    need(int(fields[19]) == birth, 'owned PID was reused')
    need(int(fields[2]) == leader, 'process no longer belongs to owned group')
    return fields[0] in (b'Z', b'X', b'x')

def exit_pending(error, pid, birth):
    need(error.pid == pid and error.birth == birth, 'unrelated owned exit wait')
    time.sleep(0.01)  # Retry only; the loop's case deadline and completion grace bound it.

def sample_owned_process(pid, leader, api, cache, witnesses, known, complete, env_witnesses, completion=None, work_started=True, case_deadline=None):
    if completion is None: completion = CompletionState()
    prior_event = None
    if case_deadline is None:case_deadline = time.monotonic()+CASE_SECONDS
    # All sampling races return here. No nested path can bypass fresh maps or
    # promote a teardown event to pass without exit/oracle/owned-group cleanup.
    for attempt in range(512):
        completion.check()
        need(time.monotonic() < case_deadline, 'loader/provider sampling deadline')
        try:
            birth = proc_birth(pid)
            need(pid not in known or known[pid] == birth, 'owned PID was reused')
            require_owned_proc(pid, leader, birth)
            known[pid] = birth
            if completion.images is not None and completion.images.check(pid,birth,leader) != 'tool':return {}, None
            clean_environ(proc_read(pid, 'environ', birth))
            rows = retirement_scan(pid, birth, leader, api)
            check_retired_addresses(rows, completion)
            # Newly observed VMAs bind first; a disappearing old VMA cannot hide
            # a new wrong mapped file later in the current graphics list.
            rows.sort(key=lambda row: witnesses.witnessed(row))
            bound = confirm_rows(rows, cache, witnesses=witnesses)
            if completion.images is not None:completion.images.require_tool(pid,birth,leader)
            env_witnesses.add((pid, birth))
            if work_started and complete_provider_set(set(bound), api):
                completion.remember(rows)
                complete.add((pid, birth))
            elif (pid, birth) in complete:
                completion.remember(rows)
                prior_event = completion.begin(pid, birth, 'provider-set-retired', complete, env_witnesses, witnesses)
            if completion.deadline is not None: witnesses.verify_live()
            completion.check()
            return bound, prior_event
        except ExitPending as x:
            exit_pending(x, pid, known.get(pid)); continue
        except LaunchTransition as e:
            need(not complete and e.pid==pid and e.birth==known.get(pid),'launch transition after proof or unknown PID')
            need(proc_birth(pid)==e.birth,'launch transition PID reused')
            require_owned_proc(pid,leader,e.birth)
            if completion.images is not None:completion.images.live()
            if witnesses.live_keys:witnesses.verify_live()
            time.sleep(0.01);continue  # Bounded rescan only; no provider/env proof or grace.
        except MapRangeRetired as e:
            mapping = e.mapping
            need(mapping['pid'] == pid, 'unrelated map retirement')
            if (pid,mapping['birth']) not in complete:
                if completion.images is not None:completion.images.require_tool(pid,mapping['birth'],leader)
                if witnesses.live_keys:witnesses.verify_live()
                time.sleep(0.01);continue  # Fresh loader/RELRO rescan; no proof or completion grace.
            try:prior_event = completion.begin(pid, mapping['birth'], 'map-range-retired', complete, env_witnesses, witnesses, mapping)
            except ExitPending as x:exit_pending(x, pid, mapping['birth']); continue
            # The next loop MUST rescan/admit/bind every current graphics row.
            time.sleep(0.01)
        except OwnedProcUnavailable as e:
            if e.phase=='exe' and e.birth is not None and completion.images is not None and completion.images.admitted_non_tool(pid,e.birth):
                need(e.pid==pid and known.get(pid)==e.birth,'unrelated launcher disappearance')
                if terminal_or_absent(pid,e.birth,leader):
                    completion.images.live()
                    return {},None  # An already admitted TERMINAL launcher supplies no proof.
                time.sleep(0.01);continue  # Same exit window, birth and group just verified: retry, no proof.
            if e.phase == 'map_files' and e.birth is not None and (pid,e.birth) not in complete:
                need(proc_birth(pid) == e.birth, 'pre-witness tool PID changed')
                require_owned_proc(pid,leader,e.birth)
                if completion.images is not None:completion.images.require_tool(pid,e.birth,leader)
                if witnesses.live_keys:witnesses.verify_live()
                time.sleep(0.01);continue  # Only a transient map_files range; no evidence accepted.
            identity = unavailable_identity(e, complete, env_witnesses)
            try:prior_event = completion.begin(pid, identity[1], e.phase, complete, env_witnesses, witnesses, e.mapping)
            except ExitPending as x:exit_pending(x, pid, identity[1]); continue
            if terminal_or_absent(pid, identity[1], leader):
                return {}, prior_event
            # Still alive: retry the complete boundary, including environment,
            # current graphics admission and authoritative descriptors.
            time.sleep(0.01)
    raise ValueError('could not obtain complete fresh graphics rescan during retirement')

def session(m):
    user = pwd.getpwnam(m['gui_user'])
    need(user.pw_uid == m['gui_uid'], 'GUI uid mismatch')
    runtime = Path('/run/user') / str(user.pw_uid)
    socks = list((runtime / 'hypr').glob('*/.socket.sock'))
    wayland = [p for p in runtime.glob('wayland-*') if stat.S_ISSOCK(p.stat().st_mode)]
    need(len(socks) == len(wayland) == 1, 'ambiguous desktop')
    comp = []
    for p in Path('/proc').glob('[0-9]*'):
        try:
            if p.stat().st_uid == user.pw_uid and (p / 'comm').read_text().strip().lower().startswith(('hyprland', 'chonkstep')):
                comp.append(p)
        except FileNotFoundError:
            pass
    need(len(comp) == 1, 'ambiguous installed compositor')
    return user, runtime, socks[0].parent.name, wayland[0].name, comp[0]

def live_wifi(m):
    iface = m['wifi_interface']
    base = Path('/sys/class/net') / iface
    need(base.exists() and (base / 'address').is_file(), 'Wi-Fi interface missing')
    mac = (base / 'address').read_text().strip()
    need(mac == m['wifi_mac'], 'Wi-Fi MAC mismatch')
    oper = (base / 'operstate').read_text().strip()
    text = command(['/usr/bin/nmcli', '-t', '-f', 'DEVICE,TYPE,STATE', 'device'])
    return wifi_view(iface, mac, text, oper)

def live_faults():
    return faults_of(command(['/usr/bin/journalctl', '-k', '-b', '-n', '2500', '--no-pager', '-o', 'cat'], timeout=8))

def provider_cache():
    cache = {}
    for pin in PROVIDERS.values():
        ident = regular_sha256(pin['path'], pin['bytes'])
        need(ident['sha256'] == pin['sha256'], 'installed provider hash mismatch: ' + pin['path'])
        cache[pin['path']] = ident
    return cache

def snapshot(m, comp, cache):
    board = Path('/proc/device-tree/compatible').read_bytes().split(b'\0')[0].decode()
    need(os.uname().release == m['expected_kernel'] == KERNEL, 'wrong current kernel')
    need(board == m['board'], 'wrong board')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(boot == m['expected_boot_id'], 'wrong current boot')
    clean_environ((comp / 'environ').read_bytes())
    rows = assess(read_maps([int(comp.name)]), 'compositor')
    bound = confirm_rows(rows, cache)
    user, runtime, signature, wayland, _ = session(m)
    env = child_env(user.pw_name, user.pw_dir, str(runtime), signature, wayland)
    mons = topology(json.loads(command(prefix(user.pw_name, env) + ['/usr/bin/hyprctl', '-j', 'monitors'])))
    return {
        'boot_id': boot, 'kernel': os.uname().release, 'board': board, 'monitors': mons,
        'wifi': live_wifi(m), 'faults': live_faults(), 'compositor_gallium': bound[GALLIUM],
        'compositor_pid': int(comp.name),
    }

def watch(proc, data, case_deadline, total_deadline, sample):
    sel = selectors.DefaultSelector()
    try:
        os.set_blocking(proc.stdout.fileno(), False)
        sel.register(proc.stdout, selectors.EVENT_READ)
        while sel.get_map() or proc.poll() is None:
            now = time.monotonic()
            if now >= case_deadline or now >= total_deadline:
                raise TimeoutError('tool/overall timeout')
            if proc.poll() is None:
                sample()
            for key, _ in sel.select(0.05):
                chunk = os.read(key.fd, 16384)
                if not chunk:
                    sel.unregister(key.fileobj)
                else:
                    data.extend(chunk)
                    need(len(data) <= 65536, 'tool output above 64KiB')
        need(proc.wait(timeout=1) == 0, 'tool failed')
    finally:
        sel.close()
        if proc.stdout is not None:
            proc.stdout.close()

def run_case(m, user, env, api, tool, out, cache, total_deadline):
    rec = {'api': api, 'tool': tool, 'status': 'stopped', 'metrics': None, 'output': ''}
    data = bytearray()
    proc = None
    observed = []
    witnesses = MapWitnesses()
    complete = set()
    images = None
    completion = CompletionState()
    known = {}
    env_witnesses = set()
    started = time.monotonic()
    try:
        need(started < total_deadline, 'overall deadline')
        ident = regular_sha256(tool)
        need(ident['sha256'] == TOOLS['gl_pixels' if api == 'GL' else 'vk_pixels']['sha256'], 'tool hash mismatch')
        command_line = prefix(user.pw_name, env) + [tool,str(TOOL_SECONDS)]
        images = RunningImages(tool,ident['sha256'],command_line,user.pw_uid)
        proc = subprocess.Popen(command_line, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        rec['owned_pgid'] = proc.pid
        completion = CompletionState(images,proc.pid)
        seen = {}

        def sample():
            completion.check()
            for pid in group(proc.pid):
                bound, provisional = sample_owned_process(pid, proc.pid, api, cache, witnesses, known, complete, env_witnesses, completion, work_banner(api, data.decode(errors="replace")), min(started+CASE_SECONDS,total_deadline))
                seen.update(bound)
                if bound: observed.append(dict(seen))

        watch(proc, data, started + CASE_SECONDS, total_deadline, sample)
        need(observed and complete, 'unknown maps or no complete single-process provider witness')
        completion.check()
        need(images.unique is not None and complete == {images.unique}, 'oracle/provider witness not bound to unique admitted tool image')
        rec['admitted_tool_image'] = {'pid':images.unique[0],'birth':images.unique[1],'sha256':images.pins['tool']['sha256'],'identity':list(images.pins['tool']['identity']),'argv':[tool,str(TOOL_SECONDS)]}
        validate_owned_exits(completion.events, complete, proc.returncode, data.decode(errors='replace'))
        assess_seen = set(seen)
        for path in REQUIRED[api]:
            need(path in assess_seen, 'missing mapped provider ' + path)
        if api == 'GL':
            need(GALLIUM in assess_seen, 'EGL wrapper without Gallium')
        rec.update(status='pass', metrics=parse_pixels(data.decode(errors='replace')), validated_completion_events=completion.events, completion_grace_seconds=COMPLETION_GRACE)
    except BaseException as e:
        status = 'timeout' if isinstance(e, TimeoutError) else 'cancelled' if 'termination requested' in str(e) else 'stopped'
        rec.update(status=status, reason=str(e), metrics=None)
        raise
    finally:
        remaining = stop_group(proc)
        witnesses.close()
        if images is not None:images.close()
        if remaining:
            rec.update(status='stopped', metrics=None, reason='owned process group remains')
        rec['owned_processes_remaining'] = remaining
        rec['output'] = data.decode(errors='replace')
        rec['elapsed_seconds'] = time.monotonic() - started
        rec['mapped_provider_hashes'] = observed[-1] if observed else {}
        save(out / f'{api}.json', rec)
        need(not remaining, 'owned workload remains')
    return rec

def run(manifest_path):
    m = frozen_manifest(json.loads(Path(manifest_path).read_text()))
    require_mac()
    need(not Path('/var/lib/pacman/db.lck').exists(), 'package transaction active')
    out = Path(m['output_dir'])
    need(out.parent == Path('/var/tmp') and not out.exists() and not out.is_symlink(), 'private output is not a new owned directory')
    user, runtime, signature, wayland, comp = session(m)
    cache = provider_cache()
    os.mkdir(out, 0o700)
    os.chmod(out, 0o700)
    records = []
    try:
        before = snapshot(m, comp, cache)
        save(out / 'before.json', before)
        env = child_env(user.pw_name, user.pw_dir, str(runtime), signature, wayland)
        deadline = time.monotonic() + TOTAL_SECONDS
        for api, key in (('GL', 'gl_pixels'), ('VK', 'vk_pixels')):
            records.append(run_case(m, user, env, api, m['tools'][key]['path'], out, cache, deadline))
        after = snapshot(m, comp, cache)
        stable(before, after)
        save(out / 'after.json', after)
        save(out / 'complete.json', {'status': 'pass', 'records': records, 'qualification': False, 'source_review': 'accepted-by-root'})
    except BaseException as e:
        save(out / 'stopped.json', {'status': 'stopped', 'reason': str(e), 'records': records})
        raise
    print(json.dumps({'private_output': str(out), 'status': 'pass'}))

def main(argv=None):
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='operation', required=True)
    a = sub.add_parser('validate')
    a.add_argument('manifest', type=Path)
    a = sub.add_parser('run')
    a.add_argument('manifest', type=Path)
    args = p.parse_args(argv)
    if args.operation == 'validate':
        frozen_manifest(json.loads(args.manifest.read_text()))
        print(json.dumps({'manifest': 'explicit', 'gpu': False}))
        return
    run(args.manifest)

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *a: (_ for _ in ()).throw(RuntimeError('termination requested')))
    signal.signal(signal.SIGINT, lambda *a: (_ for _ in ()).throw(RuntimeError('termination requested')))
    try:
        main()
    except (ValueError, OSError, KeyError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as e:
        raise SystemExit('STOP: ' + str(e))
