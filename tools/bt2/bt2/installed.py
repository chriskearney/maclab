#!/usr/bin/env python3
"""labd installed-mode plumbing for bt2 (controller side).

A bt2 run uses NEW frozen release names (freezes are write-once): <run> for the candidate and, with the default
fresh baseline, <run>-base for the installed-mode job of the Mac's original packages whose outputs become the
candidate's preinstall (write_preinstall_files). The stale path byte-copies the device's old preinstall baseline.
"""
import hashlib
import json
import os
import re
from pathlib import Path

FROZEN = Path.home() / '.local/share/maclab/frozen'
REL_RE = re.compile(r'^[0-9A-Za-z][0-9A-Za-z._-]*$')
PRE_FILES = ('baseline-job.json', 'dmesg-errors.txt', 'omt-report.json', 'omt-status.json')


class InstalledError(RuntimeError):
    pass


def H(b):
    return hashlib.sha256(b).hexdigest()


def _write_once(path, data, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view[:1 << 20])
            view = view[n:]
            os.fsync(fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    if path.read_bytes() != data:
        raise InstalledError('write-once readback mismatch: %s' % path)


def source_cohort(source_release, device):
    """Load a frozen source release that already covers `device` for the same package cohort."""
    src = FROZEN / source_release
    man_raw = (src / 'expected/manifest.json').read_bytes()
    man = json.loads(man_raw)
    pins = {}
    for line in (src / 'PINS.expected').read_text().splitlines():
        if line and not line.startswith('#'):
            sha, rel = line.split('  ', 1)
            pins[rel] = sha
    if pins.get('expected/manifest.json') != H(man_raw):
        raise InstalledError('source manifest pin mismatch')
    pay_rel = 'expected/' + man['kernel']['payload_manifest']
    pay_raw = (src / pay_rel).read_bytes()
    if pins.get(pay_rel) != H(pay_raw):
        raise InstalledError('source payload pin mismatch')
    if device not in man.get('macs', {}):
        raise InstalledError('source manifest has no macs entry for ' + device)
    pre = {}
    prepins = {}
    for line in (src / 'PINS.preinstall').read_text().splitlines():
        if line and not line.startswith('#'):
            sha, rel = line.split('  ', 1)
            prepins[rel] = sha
    for name in PRE_FILES:
        rel = 'preinstall/%s/%s' % (device, name)
        p = src / rel
        if not p.exists():
            if name == 'baseline-job.json':
                continue
            raise InstalledError('source preinstall missing ' + rel)
        raw = p.read_bytes()
        if rel in prepins and prepins[rel] != H(raw):
            raise InstalledError('source preinstall pin mismatch ' + rel)
        pre[name] = raw
    return {'source_release': source_release, 'manifest': man, 'manifest_raw_sha256': H(man_raw),
            'payload_raw': pay_raw, 'payload_rel': man['kernel']['payload_manifest'], 'preinstall': pre}


def new_manifest(cohort, release, device):
    if not REL_RE.match(release):
        raise InstalledError('bad release name')
    m = json.loads(json.dumps(cohort['manifest']))
    m['release'] = release
    m['macs'] = {device: m['macs'][device]}
    raw = (json.dumps(m, indent=2, sort_keys=True) + '\n').encode()
    return m, raw


def report_status(report):
    """Mirror of labd internal/installed ReportStatus (installed.go:604): checks[].id -> checks[].status, plus
    tool.version and machine.kernel. Returns (status, tool, kernel)."""
    r = json.loads(report)
    if not isinstance(r, dict):
        raise InstalledError('omarchy-m-test report is not a JSON object')
    status = {}
    for c in r.get('checks') or []:
        if isinstance(c, dict):
            status[str(c.get('id', ''))] = str(c.get('status', ''))
    return status, str((r.get('tool') or {}).get('version') or ''), str((r.get('machine') or {}).get('kernel') or '')


def status_json(status):
    """omt-status.json bytes exactly as the existing preinstall stores write them (byte-checked against the
    m1/m1air/m3pro stores on 2026-10-26): 2-space indent, sorted keys, final newline."""
    return (json.dumps(status, indent=2, sort_keys=True) + '\n').encode()


def write_preinstall_files(release, device, files, note, provenance_name, provenance):
    """Hand-written preinstall (no labd API exists for it): write-once files + PINS.preinstall (same format for
    the stale byte copy and the fresh baseline) + a provenance record."""
    required = set(PRE_FILES) - {'baseline-job.json'}          # labd reads baseline-job.json only if present
    if not (required <= set(files) <= set(PRE_FILES)):
        raise InstalledError('preinstall needs %s (+ optional baseline-job.json), got %s' % (
            sorted(required), sorted(files)))
    root = FROZEN / release
    if root.exists():
        raise InstalledError('release dir already exists: ' + str(root))
    root.mkdir(mode=0o700)
    (root / 'preinstall').mkdir(mode=0o700)
    (root / 'preinstall' / device).mkdir(mode=0o700)
    lines = ['# PINS.preinstall %s by bt2: %s' % (release, note)]
    for name in sorted(files):
        raw = files[name]
        _write_once(root / 'preinstall' / device / name, raw)
        lines.append('%s  preinstall/%s/%s' % (H(raw), device, name))
    _write_once(root / provenance_name, (json.dumps(
        {**provenance, 'release': release, 'device': device, 'files': {n: H(r) for n, r in files.items()}},
        indent=2, sort_keys=True) + '\n').encode())
    _write_once(root / 'PINS.preinstall', ('\n'.join(lines) + '\n').encode())
    return {n: H(r) for n, r in files.items()}


def write_preinstall(release, device, cohort, note):
    """Byte copy of the device's frozen preinstall baseline (stale; `--baseline stale` and the base job)."""
    files = dict(cohort['preinstall'])
    return write_preinstall_files(release, device, files, note, 'PREINSTALL-REUSE.json',
                                  {'schema': 'bt2.preinstall-reuse/1', 'source_release': cohort['source_release'],
                                   'new_baseline_claim': False})


def freeze_manifest(api, release, manifest_raw, payload_raw, approved_by):
    up1 = api.put_artifact(manifest_raw)
    up2 = api.put_artifact(payload_raw)
    if up1['sha256'] != H(manifest_raw) or up2['sha256'] != H(payload_raw):
        raise InstalledError('artifact upload hash mismatch')
    return api.post('/api/installed/%s/manifest' % release,
                    {'manifest': up1['sha256'], 'payload': up2['sha256'], 'approved_by': list(approved_by)},
                    timeout=60)


def freeze_entry(api, release, device):
    return api.post('/api/installed/%s/entry/%s' % (release, device), {}, timeout=420)


def job_spec(device, holder, manifest_sha256, mode, transaction, native_script_sha=None, extra_tests=()):
    tests = [{'name': 'boot-health', 'builtin': 'boot-health'},
             {'name': 'gui-smoke', 'builtin': 'gui-smoke', 'gui': True},
             {'name': 'omarchy-m-test', 'builtin': 'omarchy-m-test', 'timeout_sec': 900, 'gui': True}]
    if native_script_sha:
        tests.append({'name': 'native-gl-vk', 'script': native_script_sha, 'timeout_sec': 180})
    tests.extend(extra_tests)    # campaign-local script tests run last, after every bt2 test
    return {'device': device, 'holder': holder, 'installed_manifest': manifest_sha256, 'recovery_mode': mode,
            'recovery_transaction': transaction, 'tests': tests}
