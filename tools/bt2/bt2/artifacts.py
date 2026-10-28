#!/usr/bin/env python3
"""Inspect pacman package archives without extracting or executing anything.

inspect(path) -> {
  'path','sha256','bytes','file' (basename),
  'pkginfo': {pkgname,pkgver,arch,pkgbase?,...},
  'kernel_releases': [..]   # dirs usr/lib/modules/<rel>/ that contain vmlinuz
  'members': {relpath: {'type': 'f'|'d'|'l'|'h', 'mode', 'size', 'sha256'?, 'link'?}},
  'ledger_sha256': sha256 over canonical member lines,
}
Requires Python >= 3.14 (tarfile zstd support).
"""
import hashlib
import json
import re
import tarfile
from pathlib import Path

MAX_MEMBERS = 60000
MAX_TOTAL = 6 * 1024 ** 3
SINGULAR = ('pkgname', 'pkgver', 'pkgbase', 'arch', 'size', 'builddate', 'packager')


class ArtifactError(RuntimeError):
    pass


def _normal(name):
    while name.startswith('./'):
        name = name[2:]
    name = name.rstrip('/')
    if name in ('', '.'):
        return ''
    if name.startswith('/') or '\x00' in name or any(p in ('', '.', '..') for p in name.split('/')):
        raise ArtifactError('unsafe member path: %r' % name)
    return name


def parse_pkginfo(raw):
    vals = {}
    multi = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        if ' = ' not in line:
            raise ArtifactError('bad PKGINFO line')
        k, v = line.split(' = ', 1)
        if k in SINGULAR:
            if k in vals:
                raise ArtifactError('duplicate PKGINFO ' + k)
            vals[k] = v
        else:
            multi.setdefault(k, []).append(v)
    for k in ('pkgname', 'pkgver', 'arch'):
        if k not in vals:
            raise ArtifactError('PKGINFO missing ' + k)
    if not re.fullmatch(r'[a-zA-Z0-9@_.+-]{1,128}', vals['pkgname']) or vals['arch'] not in ('aarch64', 'any'):
        raise ArtifactError('unsupported package identity')
    vals.update({k: v for k, v in multi.items() if k in ('depend', 'provides', 'conflict', 'replaces', 'backup')})
    return vals


def inspect(path):
    p = Path(path)
    raw_hash = hashlib.sha256()
    size = 0
    with p.open('rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            raw_hash.update(b)
            size += len(b)
    members = {}
    info = None
    total = 0
    ledger = hashlib.sha256()
    with tarfile.open(p, mode='r:*') as t:
        for m in t:
            name = _normal(m.name)
            if not name:
                continue
            if name in members:
                raise ArtifactError('duplicate member ' + name)
            if len(members) >= MAX_MEMBERS:
                raise ArtifactError('too many members')
            total += m.size
            if total > MAX_TOTAL:
                raise ArtifactError('declared size too large')
            row = {'mode': m.mode}
            if m.isfile():
                row['type'] = 'f'
                row['size'] = m.size
                f = t.extractfile(m)
                h = hashlib.sha256()
                got = 0
                keep = name in ('.PKGINFO',)
                parts = []
                while True:
                    b = f.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
                    got += len(b)
                    if keep:
                        parts.append(b)
                if got != m.size:
                    raise ArtifactError('truncated member ' + name)
                row['sha256'] = h.hexdigest()
                if name == '.PKGINFO':
                    info = parse_pkginfo(b''.join(parts))
            elif m.isdir():
                row['type'] = 'd'
            elif m.issym():
                row['type'] = 'l'
                row['link'] = m.linkname
            elif m.islnk():
                row['type'] = 'h'
                row['link'] = _normal(m.linkname)
            else:
                raise ArtifactError('special member ' + name)
            members[name] = row
            ledger.update((json.dumps({'path': name, **row}, sort_keys=True, separators=(',', ':')) + '\n').encode())
    if info is None:
        raise ArtifactError('no .PKGINFO')
    rels = sorted({n.split('/')[3] for n in members
                   if n.startswith('usr/lib/modules/') and n.count('/') == 4 and n.endswith('/vmlinuz')})
    return {'path': str(p), 'file': p.name, 'sha256': raw_hash.hexdigest(), 'bytes': size, 'pkginfo': info,
            'kernel_releases': rels, 'members': members, 'ledger_sha256': ledger.hexdigest()}


def payload_files(insp):
    """Installed paths (absolute) of regular files with sha256, excluding pacman metadata members."""
    out = {}
    for n, r in insp['members'].items():
        if n.startswith('.') and '/' not in n:
            continue
        if r['type'] == 'f':
            out['/' + n] = {'sha256': r['sha256'], 'size': r['size']}
    return out


if __name__ == '__main__':
    import sys
    for a in sys.argv[1:]:
        r = inspect(a)
        print(json.dumps({k: v for k, v in r.items() if k != 'members'} | {'member_count': len(r['members'])}, indent=1))
