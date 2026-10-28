#!/usr/bin/env python3
"""Bounded regular-file reuse on the existing private M5 retention filesystem."""
if not __debug__:
    raise RuntimeError('optimized Python forbidden')
import hashlib
import json
import os
import re
import stat
from pathlib import Path

BASE = Path('/Users/chriskearney/.local/share/maclab/recovery-retained')
NAMES = {'boot.bin.original', 'kernel6.uki.original', 'limine.conf.original',
         'kernel6-tree.tar.zst', 'boot-inputs.original.tar', 'state.original.json',
         'kernel6-tree.original.jsonl'}
SUPPLEMENT_NAMES = {'boot.bin.old.original', 'boot-metadata.original.json'}

def need(value, message):
    if not value:
        raise RuntimeError(message)

def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def safe_directory(path):
    for q in [path, *path.parents]:
        s = q.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.getuid())
             and not s.st_mode & 0o022, 'unsafe retention ancestry')

def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def checked(path, size, sha, allow_mismatch=False):
    safe_directory(path.parent)
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600
         and s.st_uid == os.getuid() and s.st_nlink == 1
         and 0 < s.st_size <= 2 * 1024**3,
         'reuse object is not an owned private unlinked regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(identity(os.fstat(fd)) == identity(s), 'preopen identity drift')
        h = hashlib.sha256()
        count = 0
        while count <= s.st_size:
            b = os.read(fd, min(1048576, s.st_size + 1 - count))
            if not b:
                break
            count += len(b)
            h.update(b)
        need(count == s.st_size and identity(os.fstat(fd)) == identity(s),
             'reuse object changed during hash')
    finally:
        os.close(fd)
    need(identity(path.lstat()) == identity(s), 'reuse path changed')
    match = count == size and h.hexdigest() == sha
    need(match or allow_mismatch, 'retained object hash/size mismatch')
    return {'identity': identity(s), 'sha256': h.hexdigest(), 'bytes': count,
            'match': match}

def reuse(source, destination, size, sha):
    """Return None on missing/different bytes; unsafe objects and races STOP.

    Always copy into an exclusive independent inode. Hardlinks are deliberately
    avoided: modifying the fresh namespace must never change an old backup.
    """
    need(0 < size <= 2 * 1024**3 and re.fullmatch('[0-9a-f]{64}', sha),
         'invalid bounded object pin')
    safe_directory(source.parent)
    if not os.path.lexists(source):
        return None
    before = checked(source, size, sha, allow_mismatch=True)
    if not before['match']:
        return None
    safe_directory(destination.parent)
    need(source != destination and not os.path.lexists(destination),
         'fresh exclusive destination required')
    src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    out = None
    try:
        need(identity(os.fstat(src)) == before['identity'], 'reuse source drift')
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                      | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        created = os.fstat(out)
        count = 0
        h = hashlib.sha256()
        while count < size:
            b = os.read(src, min(1048576, size - count))
            need(b, 'truncated reuse source')
            view = memoryview(b)
            while view:
                n = os.write(out, view)
                need(n > 0, 'short local write')
                view = view[n:]
            count += len(b)
            h.update(b)
        need(not os.read(src, 1) and h.hexdigest() == sha,
             'reuse source changed bytes')
        os.fsync(out)
        need((created.st_dev, created.st_ino) ==
             (os.fstat(out).st_dev, os.fstat(out).st_ino), 'output inode drift')
        need(identity(os.fstat(src)) == before['identity'], 'reuse source drift')
    finally:
        os.close(src)
        if out is not None:
            os.close(out)
    source_final = checked(source, size, sha)
    need(source_final['identity'] == before['identity'], 'source metadata drift')
    result = checked(destination, size, sha)
    need(result['identity'][:2] != before['identity'][:2], 'shared old inode')
    fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    syncdir(destination.parent)
    return {**result, 'reused_from': str(source),
            'reused_source_identity': before['identity'],
            'remote_fsync_reopen_match': True, 'transferred_bytes': 0,
            'reuse_method': 'bounded-independent-regular-copy'}

def paths(root, name, candidates):
    need(root.parent == BASE and re.fullmatch('rc7-m1-[a-z0-9-]{8,96}', root.name),
         'unreviewed new namespace')
    need(name in NAMES | SUPPLEMENT_NAMES and isinstance(candidates, list) and len(candidates) <= 16,
         'unreviewed object/candidate list')
    for candidate in candidates:
        p = Path(candidate['path'])
        need(str(p)==candidate['path'] and str(p).startswith(str(BASE) + '/') and p.name == name
             and p.parent.name in ('main', 'supplement') and p.parent.parent.parent == BASE
             and re.fullmatch('rc7-m1-[a-z0-9-]{8,96}', p.parent.parent.name)
             and p.parent.parent != root, 'unreviewed retained source path')
    return root / ('main' if name in NAMES else 'supplement') / name
