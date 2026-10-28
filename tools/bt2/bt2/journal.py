#!/usr/bin/env python3
"""Durable append-only run journal (JSON lines, fsync per record, full reread check).

Records: {"seq", "at", "step", "event": "intent"|"done"|"failed"|"note", ...}
An 'intent' is written BEFORE a mutating step runs; 'done'/'failed' after. The restore
driver uses the set of steps with an intent (done or not) to decide which inverses to run.
"""
import json
import os
import time
from pathlib import Path


class JournalError(RuntimeError):
    pass


class Journal:
    def __init__(self, run_dir):
        self.dir = Path(run_dir)
        self.path = self.dir / 'journal.jsonl'
        self.records = []
        if self.path.exists():
            for line in self.path.read_bytes().splitlines():
                if line.strip():
                    self.records.append(json.loads(line))

    @classmethod
    def create(cls, run_dir, header):
        d = Path(run_dir)
        d.mkdir(mode=0o700, parents=False, exist_ok=False)
        j = cls(d)
        j.append({'event': 'header', **header})
        return j

    def append(self, rec):
        rec = {'seq': len(self.records), 'at': time.time(), **rec}
        line = (json.dumps(rec, sort_keys=True, separators=(',', ':')) + '\n').encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            n = os.write(fd, line)
            if n != len(line):
                raise JournalError('short journal write')
            os.fsync(fd)
        finally:
            os.close(fd)
        if rec['seq'] == 0:
            dfd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        if not self.path.read_bytes().endswith(line):
            raise JournalError('journal readback mismatch')
        self.records.append(rec)
        return rec

    def intent(self, step, **kw):
        return self.append({'event': 'intent', 'step': step, **kw})

    def done(self, step, **kw):
        return self.append({'event': 'done', 'step': step, **kw})

    def failed(self, step, error, **kw):
        return self.append({'event': 'failed', 'step': step, 'error': str(error)[:4000], **kw})

    def note(self, step, **kw):
        return self.append({'event': 'note', 'step': step, **kw})

    def header(self):
        return self.records[0] if self.records else None

    def started(self, step):
        return any(r.get('step') == step and r['event'] == 'intent' for r in self.records)

    def completed(self, step):
        return any(r.get('step') == step and r['event'] == 'done' for r in self.records)

    def last_done(self, step):
        for r in reversed(self.records):
            if r.get('step') == step and r['event'] == 'done':
                return r
        return None
