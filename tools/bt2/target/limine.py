#!/usr/bin/env python3
"""Minimal, exact Limine menu model for bt2 (stdlib only; also shipped to the Mac).

The menu is kept as a list of raw lines so that untouched bytes round-trip exactly.
Entries are lines whose first non-blank char is '/': depth = number of leading '/' (a '+' after the
slashes marks an expanded directory). Options are 'key: value' lines.
Paths look like  boot():/EFI/Linux/x.efi#<blake2b-512 hex>  (Limine verifies with BLAKE2b).
"""
import hashlib
import re

ENTRY_RE = re.compile(r'^(\s*)(/+)(\+?)(.*)$')
OPT_RE = re.compile(r'^(\s*)([A-Za-z_][A-Za-z0-9_]*):\s?(.*)$')
LAB_BEGIN = '# maclab: begin.'
LAB_END = '# maclab: end'


class MenuError(ValueError):
    pass


def b2(data):
    return hashlib.blake2b(data, digest_size=64).hexdigest()


class Entry:
    def __init__(self, idx, depth, name, expanded, parent):
        self.idx = idx            # line index of the entry header
        self.depth = depth
        self.name = name.strip()
        self.expanded = expanded
        self.parent = parent
        self.children = []
        self.opts = {}            # key -> (line index, value)

    @property
    def fullname(self):
        parts = []
        e = self
        while e is not None:
            parts.append(e.name)
            e = e.parent
        return '/'.join(reversed(parts))

    def path(self):
        v = self.opts.get('path')
        return v[1] if v else None


class Menu:
    def __init__(self, raw):
        if b'\x00' in raw or b'\r' in raw:
            raise MenuError('NUL/CR in menu')
        self.lines = raw.decode('utf-8').split('\n')   # keeps trailing '' if raw ends with \n
        self.parse()

    def raw(self):
        return '\n'.join(self.lines).encode('utf-8')

    def parse(self):
        self.globals = {}
        self.entries = []
        self.lab = None
        stack = []
        begin = end = None
        for i, line in enumerate(self.lines):
            s = line.strip()
            if s.startswith(LAB_BEGIN):
                if begin is not None:
                    raise MenuError('duplicate maclab begin')
                begin = i
                continue
            if s == LAB_END:
                if end is not None:
                    raise MenuError('duplicate maclab end')
                end = i
                continue
            if begin is not None and end is None:
                continue  # inside the lab block: never parsed or edited here
            if s.startswith('#') or not s:
                continue
            m = ENTRY_RE.match(line) if s.startswith('/') else None
            if m:
                depth = len(m.group(2))
                while stack and stack[-1].depth >= depth:
                    stack.pop()
                parent = stack[-1] if stack else None
                if parent is None and depth != 1:
                    raise MenuError('entry without parent at line %d' % (i + 1))
                e = Entry(i, depth, m.group(4), bool(m.group(3)), parent)
                (parent.children if parent else self.entries).append(e)
                stack.append(e)
                continue
            o = OPT_RE.match(line)
            if not o:
                raise MenuError('unparsed line %d: %r' % (i + 1, line[:80]))
            key, val = o.group(2), o.group(3)
            if stack:
                if key != 'comment':
                    stack[-1].opts[key] = (i, val)
            else:
                if key in self.globals and key != 'comment':
                    raise MenuError('duplicate global ' + key)
                self.globals[key] = (i, val)
        if (begin is None) != (end is None) or (begin is not None and end < begin):
            raise MenuError('bad maclab block')
        self.lab = (begin, end) if begin is not None else None

    def walk(self):
        out = []

        def rec(es):
            for e in es:
                out.append(e)
                rec(e.children)
        rec(self.entries)
        return out

    def find(self, fullname):
        hits = [e for e in self.walk() if e.fullname == fullname]
        return hits[0] if len(hits) == 1 else None

    def default(self):
        """Resolve default_entry (name path like 'Omarchy/linux-aurora' or 1-based index)."""
        v = self.globals.get('default_entry')
        if v is None:
            bootable = [e for e in self.walk() if e.path()]
            return bootable[0] if bootable else None
        val = v[1].strip()
        if val.isdigit():
            bootable = [e for e in self.walk() if e.path()]
            n = int(val)
            return bootable[n - 1] if 0 < n <= len(bootable) else None
        e = self.find(val)
        if e is None:
            # Limine also matches the leaf name for a single kernel entry
            leaf = [x for x in self.walk() if x.fullname.endswith('/' + val) or x.name == val]
            e = leaf[0] if len(leaf) == 1 else None
        return e

    # -- edits (each returns new bytes; callers re-parse) -------------------
    def set_global(self, key, value):
        if key in self.globals:
            i, _ = self.globals[key]
            indent = re.match(r'^(\s*)', self.lines[i]).group(1)
            self.lines[i] = '%s%s: %s' % (indent, key, value)
        else:
            self.lines.insert(0, '%s: %s' % (key, value))
        self.parse()

    def set_entry_opt(self, entry, key, value):
        i, _ = entry.opts[key]
        indent = re.match(r'^(\s*)', self.lines[i]).group(1)
        self.lines[i] = '%s%s: %s' % (indent, key, value)
        self.parse()

    def insert_entry_before_lab(self, name, opts):
        """Insert a top-level entry just before the maclab block (or at the end)."""
        if '/' in name:
            raise MenuError('entry name must not contain /')
        block = ['', '/' + name] + ['    %s: %s' % (k, v) for k, v in opts]
        at = self.lab[0] if self.lab else len(self.lines) - (1 if self.lines and self.lines[-1] == '' else 0)
        self.lines[at:at] = block + ['']
        self.parse()

    def remove_entry(self, entry):
        if entry.depth != 1 or entry.children:
            raise MenuError('only leaf top-level entries may be removed')
        start = entry.idx
        end = start + 1
        while end < len(self.lines):
            s = self.lines[end].strip()
            if s.startswith('/') or s.startswith(LAB_BEGIN):
                break
            if s and not OPT_RE.match(self.lines[end]):
                break
            end += 1
        # drop one preceding blank line to keep spacing stable
        if start > 0 and self.lines[start - 1].strip() == '':
            start -= 1
        del self.lines[start:end]
        self.parse()


def split_path(value):
    """'boot():/EFI/Linux/x.efi#hash' -> ('EFI/Linux/x.efi', hash or None)."""
    v = value.strip()
    if not v.startswith('boot():/'):
        raise MenuError('unsupported resource: ' + v[:60])
    rest = v[len('boot():/'):]
    if '#' in rest:
        p, h = rest.split('#', 1)
        if not re.fullmatch(r'[0-9a-f]{128}', h):
            raise MenuError('bad blake2b in path')
        return p, h
    return rest, None


def join_path(rel, data):
    return 'boot():/%s#%s' % (rel, b2(data))
