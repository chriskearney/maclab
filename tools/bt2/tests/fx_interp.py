"""Bind the fixtures' fake tools (fx_pkg/bin, fx_state/bin) to the Python running the tests.

The target under test runs a fake tool by its path (common.BIN), so the kernel follows the script's own
"#!/usr/bin/python3" to whatever Python the host has: on GitHub's ubuntu runner that is the system 3.12, which can't read
the zstd packages the fixtures build, while the tests run under 3.14 (CI run 41229895120). bound(src) is a directory
of sh wrappers, one per fake tool, each running that very script with sys.executable and the flags its own shebang
names (-B, -IB). The fake tools themselves are unchanged."""
import atexit
import os
import shlex
import shutil
import sys
import tempfile

_made = {}


def shebang_flags(script):
    """The interpreter flags on script's first line, e.g. ['-IB'] for "#!/usr/bin/python3 -IB"."""
    with open(script, 'rb') as f:
        first = f.readline().decode('utf-8', 'replace').strip()
    if not first.startswith('#!'):
        raise RuntimeError('fake tool %s has no shebang' % script)
    return [p for p in first[2:].split()[1:] if p.startswith('-')]


def bound(src):
    """A directory of wrappers that run each executable file in src with this interpreter (made once per src)."""
    src = os.path.abspath(src)
    if src not in _made:
        d = tempfile.mkdtemp(prefix='bt2-fakebin-')
        atexit.register(shutil.rmtree, d, True)
        for name in sorted(os.listdir(src)):
            p = os.path.join(src, name)
            if not (os.path.isfile(p) and os.access(p, os.X_OK)):
                continue
            argv = [sys.executable, *shebang_flags(p), p]
            w = os.path.join(d, name)
            with open(w, 'x') as f:
                f.write('#!/bin/sh\nexec %s "$@"\n' % ' '.join(shlex.quote(a) for a in argv))
            os.chmod(w, 0o755)
        _made[src] = d
    return _made[src]


def load():
    """This module, for a fixture loading it by path (fixtures are imported from their own directories)."""
    return sys.modules[__name__]
