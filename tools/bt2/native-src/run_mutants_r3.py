#!/usr/bin/env python3
"""Mutation check for the r3 cohort guards (checker) and the cohort plumbing (bt2/native.py)."""
import os, shutil, subprocess, sys, tempfile
from pathlib import Path

N = Path(__file__).resolve().parent
G = N.parent
CK = (N / 'checker-r3.py').read_text()
NAT = (G / 'bt2/native.py').read_text()

CHECKER_MUTANTS = [
    ('roles check', "need(isinstance(providers, dict) and set(providers) == set(PROVIDER_ROLES), 'cohort provider roles')",
     "need(isinstance(providers, dict), 'cohort provider roles')"),
    ('gallium path regex', "need(isinstance(path, str) and GALLIUM_PATH.fullmatch(path), 'cohort provider path: gallium')",
     "need(isinstance(path, str), 'cohort provider path: gallium')"),
    ('fixed sonames', "need(path == ROLE_PATHS[role], 'cohort provider path: ' + role)", "pass"),
    ('sha regex', "need(isinstance(digest, str) and HEX64.fullmatch(digest), 'cohort provider sha256: ' + role)",
     "need(isinstance(digest, str), 'cohort provider sha256: ' + role)"),
    ('size bounds', "need(type(size) is int and 0 < size <= HASH_LIMIT, 'cohort provider size: ' + role)",
     "need(isinstance(size, int), 'cohort provider size: ' + role)"),
    ('distinct hashes', "need(len({p['sha256'] for p in pins.values()}) == len(pins), 'cohort provider hashes are not distinct')",
     "pass"),
    ('kernel regex', "need(isinstance(kernel, str) and KERNEL_RELEASE.fullmatch(kernel), 'cohort kernel release is not explicit')",
     "pass"),
    ('rebind identical', "need(_BOUND is None or _BOUND == key, 'cohort already bound to different pins')", "pass"),
    ('bind in frozen_manifest', "    bind_cohort(m.get('expected_kernel'), m.get('providers'))\n", "\n"),
    ('REQUIRED rebuilt', "    REQUIRED = {'GL': (GALLIUM, EGL), 'VK': (VULKAN,), 'compositor': (GALLIUM,)}\n    ALLOWED = {'GL'",
     "    ALLOWED = {'GL'"),
    ('ALLOWED rebuilt', "    ALLOWED = {'GL': {GALLIUM, EGL} | SUPPORT, 'VK': {VULKAN}, 'compositor': {GALLIUM, EGL} | SUPPORT}\n    _BOUND = key",
     "    _BOUND = key"),
    ('bound before approval', "    need(m.get('approved') is True, 'manifest is not approved')\n    bind_cohort(",
     "    bind_cohort(m.get('expected_kernel'), m.get('providers'))\n    need(m.get('approved') is True, 'manifest is not approved')\n    bind_cohort("),
]
NATIVE_MUTANTS = [
    ('worker input cohort check',
     "    need(inp['expected_kernel']==COHORT['expected_kernel'] and {r:{k:p.get(k) for k in ('path','sha256','bytes')} for r,p in prov.items()}==COHORT['providers'] and inp.get('cohort_sha256')==H(encoded(COHORT)),'native input cohort differs from the cohort compiled into this Script')\n",
     ""),
    ('worker cohort sha only', " and inp.get('cohort_sha256')==H(encoded(COHORT)),'native input cohort", ",'native input cohort"),
    ('compute_input equality',
     "    if krel != cohort['expected_kernel'] or {r: {k: p[k] for k in ('path', 'sha256', 'bytes')}\n                                             for r, p in providers.items()} != cohort['providers']:\n        raise NativeError('candidate kernel/providers differ from the cohort compiled into the Script')",
     "    pass"),
    ('canonical cohort', "    if canon != cohort:\n        raise NativeError('cohort is not canonical (extra provider keys?)')", "    pass"),
    ('gate validation', "    try:\n        cohort_pins(expected_kernel, providers, checker_raw)\n    except NativeError as e:\n        out.append(str(e))\n", ""),
    ('gate tools', "    if tools != checker_module(checker_raw).TOOLS:\n        out.append('tool pins differ from the checker')\n", ""),
    ('cohort in script', "                 .replace(\"COHORT='REQUIRED_COHORT'\", 'COHORT=json.loads(' + repr(json.dumps(canon, sort_keys=True)) + ')'))",
     "                 .replace(\"COHORT='REQUIRED_COHORT'\", 'COHORT=json.loads(' + repr(json.dumps({'expected_kernel': canon['expected_kernel'], 'providers': {}})) + ')'))"),
]


def run(cmd, cwd, env):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    return r.returncode, (r.stdout + r.stderr)[-400:]


out = []
base_env = dict(os.environ)
# control: unmodified passes
code, tail = run([sys.executable, '-B', 'test_cohort_r3.py'], N, base_env)
out.append(('control checker', code == 0, tail.strip().splitlines()[-1] if tail.strip() else ''))
for name, old, new in CHECKER_MUTANTS:
    assert CK.count(old) == 1, name
    mp = N / ('_mut_r3_%s.py' % name.replace(' ', '_'))
    mp.write_text(CK.replace(old, new))
    code, tail = run([sys.executable, '-B', 'test_cohort_r3.py'], N, {**base_env, 'R3_CHECKER': mp.name})
    out.append(('checker: ' + name, code != 0, 'caught' if code != 0 else 'SURVIVED'))
    mp.unlink()
tmp = Path(tempfile.mkdtemp(prefix='bt2-gn-mut-', dir='/dev/shm/claude-229'))
try:
    env = {**base_env, 'BT2_NATIVE_SRC': str(N / 'dist-r3')}
    shutil.copytree(G, tmp / 'g', ignore=shutil.ignore_patterns('__pycache__', 'native-src', 'notes'))
    code, tail = run([sys.executable, '-B', 'tests/test_controller.py', 'NativeTests', 'ControllerTests'], tmp / 'g', env)
    out.append(('control native', code == 0, tail.strip().splitlines()[-1] if tail.strip() else ''))
    for name, old, new in NATIVE_MUTANTS:
        assert NAT.count(old) == 1, name
        (tmp / 'g/bt2/native.py').write_text(NAT.replace(old, new))
        code, tail = run([sys.executable, '-B', 'tests/test_controller.py', 'NativeTests', 'ControllerTests'], tmp / 'g', env)
        out.append(('native: ' + name, code != 0, 'caught' if code != 0 else 'SURVIVED'))
    (tmp / 'g/bt2/native.py').write_text(NAT)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
for row in out:
    print('%-40s %s  %s' % row)
print('mutants caught: %d/%d' % (sum(1 for r in out if not r[0].startswith('control') and r[1]),
                                 sum(1 for r in out if not r[0].startswith('control'))))
