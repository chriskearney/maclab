#!/usr/bin/env python3
"""File transfer and command execution on a Mac through labd exec (root, via lab-agent).

push(): base64 chunks appended to <path>.bt2part, then sha-verified atomic rename (O_EXCL semantics: the final
path must not exist). pull(): bounded base64 reads with an identity check across chunks.
run_target(): runs the bt2 target package and returns its single JSON result + exit code.
"""
import base64
import hashlib
import json
import shlex

CHUNK = 48 * 1024           # raw bytes per push exec (base64 ~64 KiB command)
PULL = 256 * 1024           # raw bytes per pull exec


class TransportError(RuntimeError):
    pass


def _py(code):
    return '/usr/bin/python3 -I -B -c ' + shlex.quote(code)


def push(api, device, path, data, mode=0o600):
    sha = hashlib.sha256(data).hexdigest()
    part = path + '.bt2part'
    init = _py('import os,sys\np=sys.argv[1]\nassert not os.path.lexists(sys.argv[2]),"final exists"\n'
               'fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600);os.close(fd)') + ' ' + \
        shlex.quote(part) + ' ' + shlex.quote(path)
    r = api.exec(device, init, 60)
    if r.get('exit_code') != 0:
        raise TransportError('push init failed: %s' % (r.get('stderr') or r.get('stdout'))[:400])
    for off in range(0, len(data), CHUNK):
        b64 = base64.b64encode(data[off:off + CHUNK]).decode()
        cmd = _py('import base64,os,sys\nfd=os.open(sys.argv[1],os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)\n'
                  'n=int(sys.argv[2]);assert os.fstat(fd).st_size==n,"offset"\n'
                  'os.write(fd,base64.b64decode(sys.argv[3],validate=True));os.close(fd)') + ' ' + \
            shlex.quote(part) + ' %d ' % off + b64
        r = api.exec(device, cmd, 60)
        if r.get('exit_code') != 0:
            raise TransportError('push chunk %d failed: %s' % (off, (r.get('stderr') or r.get('stdout'))[:400]))
    fin = _py('import hashlib,os,sys\np,f,s,m=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4],8)\n'
              'b=open(p,"rb").read();assert hashlib.sha256(b).hexdigest()==s,"sha"\n'
              'fd=os.open(p,os.O_RDONLY);os.fsync(fd);os.close(fd);os.chmod(p,m)\n'
              'assert not os.path.lexists(f);os.rename(p,f)\n'
              'd=os.open(os.path.dirname(f),os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);print(s)') + \
        ' %s %s %s %o' % (shlex.quote(part), shlex.quote(path), sha, mode)
    r = api.exec(device, fin, 120)
    if r.get('exit_code') != 0 or r.get('stdout', '').strip() != sha:
        raise TransportError('push finalize failed: %s' % (r.get('stderr') or r.get('stdout'))[:400])
    return {'path': path, 'sha256': sha, 'bytes': len(data)}


def pull(api, device, path, limit=1 << 31):
    head = _py('import os,sys,json\ns=os.lstat(sys.argv[1]);import stat\nassert stat.S_ISREG(s.st_mode)\n'
               'print(json.dumps([s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns]))') + ' ' + shlex.quote(path)
    r = api.exec(device, head, 60)
    if r.get('exit_code') != 0:
        raise TransportError('pull stat failed: %s' % (r.get('stderr') or r.get('stdout'))[:400])
    ident = json.loads(r['stdout'].strip().splitlines()[-1])
    size = ident[2]
    if size > limit:
        raise TransportError('pull too large')
    out = bytearray()
    while len(out) < size:
        n = min(PULL, size - len(out))
        cmd = _py('import base64,os,sys,json\nfd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)\n'
                  's=os.fstat(fd)\nassert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns]==json.loads(sys.argv[4])\n'
                  'b=os.pread(fd,int(sys.argv[3]),int(sys.argv[2]));os.close(fd)\n'
                  'print(base64.b64encode(b).decode())') + ' %s %d %d %s' % (
            shlex.quote(path), len(out), n, shlex.quote(json.dumps(ident)))
        r = api.exec(device, cmd, 60)
        if r.get('exit_code') != 0:
            raise TransportError('pull chunk failed: %s' % (r.get('stderr') or r.get('stdout'))[:400])
        b = base64.b64decode(r['stdout'].strip(), validate=True)
        if len(b) != n:
            raise TransportError('short pull chunk')
        out += b
    return bytes(out)


def run_target(api, device, run_dir, cmd, timeout=900, extra=()):
    command = 'cd %s && /usr/bin/python3 -I -B t %s --run-dir %s %s' % (
        shlex.quote(run_dir), shlex.quote(cmd), shlex.quote(run_dir), ' '.join(shlex.quote(x) for x in extra))
    r = api.exec(device, command, timeout)
    lines = [l for l in (r.get('stdout') or '').splitlines() if l.strip()]
    result = None
    if lines:
        try:
            result = json.loads(lines[-1])
        except ValueError:
            result = None
    return r.get('exit_code'), result, r
