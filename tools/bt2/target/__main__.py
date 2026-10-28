"""bt2 target entry point: python3 -I -B t <cmd> --run-dir /var/lib/maclab/bt2/<run>"""
import importlib

import common

# command -> (module, function)
COMMANDS = {
    'preflight': ('preflight', 'preflight'),
    'fetch': ('preflight', 'fetch'),
    'capture': ('capture', 'capture'),
    'hold-writers': ('writers', 'hold'),
    'release-writers': ('writers', 'release'),
    'esp-prep': ('espops', 'prep'),
    'install': ('pkg', 'install'),
    'rollback': ('pkg', 'rollback'),
    'esp-restore': ('espops', 'restore'),
    'etc-restore': ('espops', 'etc_restore'),
    'audit': ('audit', 'audit'),
    'cleanup': ('audit', 'cleanup'),
    # only for runs with allow_bootbin_change (guard.py)
    'bootbin-guard-install': ('guard', 'install'),
    'bootbin-guard-remove': ('guard', 'remove'),
    'bootbin-guard': ('guard', 'run'),
    'bootbin-guard-status': ('guard', 'status'),
}


def _lazy(mod, fn):
    def call(ctx):
        return getattr(importlib.import_module(mod), fn)(ctx)
    return call


common.main({k: _lazy(m, f) for k, (m, f) in COMMANDS.items()})
