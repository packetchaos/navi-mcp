#!/usr/bin/env python3
"""
validate_audit.py - Structural validation for Tenable .audit files.

Catches the failures that make Nessus refuse to load a file or silently skip a
check: unknown wrapper tags, unbalanced structure, check types that do not exist
on the target platform, keywords that do not belong to the check type, undeclared
variables, and bad value_types.

It does NOT verify that a check is semantically correct. A file that passes here
can still be wrong about the thing it is checking.

Usage:
    python3 validate_audit.py myfile.audit
    python3 validate_audit.py myfile.audit --strict   # warnings become errors
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'platform_data.json')

VALUE_TYPES = {
    'POLICY_DWORD', 'POLICY_TEXT', 'POLICY_MULTI_TEXT', 'POLICY_SET',
    'POLICY_BINARY', 'POLICY_HEXADECIMAL', 'POLICY_DAY', 'POLICY_FILE_VERSION',
    'USER_RIGHT', 'AUDIT_SET', 'SERVICE_SET', 'FILE_ACL', 'REG_ACL',
    'TIME_MINUTE', 'TIME_DAY',
}
OPERATORS = {
    'CHECK_EQUAL', 'CHECK_NOT_EQUAL', 'CHECK_REGEX', 'CHECK_NOT_REGEX',
    'CHECK_GREATER_THAN_OR_EQUAL', 'CHECK_LESS_THAN_OR_EQUAL',
    'CHECK_SUBSET', 'CHECK_SUPERSET', 'CHECK_SUBSET_USER',
}
REPORT_TYPES = {'PASSED', 'FAILED', 'WARNING', 'INFO'}

RE_WRAPPER = re.compile(r'^<check_type:[^>]*>', re.M)
RE_ITEM = re.compile(r'<(custom_item|item)>(.*?)</\1>', re.S)
RE_KEYLINE = re.compile(r'^\s*([a-z][a-z_0-9]*)\s*:\s*(.*)$')
RE_VAR_USE = re.compile(r'@([A-Z][A-Z_0-9]*)@')
RE_VAR_DECL = re.compile(r'#\s*<n>\s*([A-Z][A-Z_0-9]*)\s*</n>')


class Result:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.notes = []

    def err(self, msg):
        self.errors.append(msg)

    def warn(self, msg):
        self.warnings.append(msg)

    def note(self, msg):
        self.notes.append(msg)


def keys_of(block):
    """Keyword names in an item block, skipping lines inside quoted values."""
    out, in_q = [], False
    for line in block.split('\n'):
        if in_q:
            if line.count('"') % 2 == 1:
                in_q = False
            continue
        m = RE_KEYLINE.match(line)
        if m:
            out.append((m.group(1), m.group(2)))
            v = m.group(2)
            if v.startswith('"') and v.count('"') % 2 == 1:
                in_q = True
    return out


def match_platform(wrapper, data):
    """Find which platform(s) a wrapper tag belongs to."""
    norm = re.sub(r'version:"[0-9.]+"', 'version:"N"', wrapper)
    hits = []
    for plat, d in data.items():
        for t in d['tags']:
            if re.sub(r'version:"[0-9.]+"', 'version:"N"', t) == norm:
                hits.append(plat)
                break
    if hits:
        return hits
    # try matching just the primary token, e.g. Database with any db_type
    m = re.match(r'<check_type:"([^"]+)"', wrapper)
    if m:
        tok = m.group(1)
        for plat, d in data.items():
            if any(re.match(r'<check_type:"%s"' % re.escape(tok), t) for t in d['tags']):
                hits.append(plat)
    return hits


def validate(path, data, r):
    text = open(path, encoding='utf-8', errors='replace').read()

    if not path.endswith('.audit'):
        r.warn('file does not have a .audit extension')

    # --- wrapper -------------------------------------------------------
    wrappers = RE_WRAPPER.findall(text)
    if not wrappers:
        r.err('no opening check_type tag found - Nessus will not load this file')
        return
    if len(wrappers) > 1:
        r.err('%d opening check_type tags found; exactly one is allowed' % len(wrappers))
    wrapper = wrappers[0]
    n_close = len(re.findall(r'</check_type>', text))
    if n_close != len(wrappers):
        r.err('%d opening tag(s) but %d closing </check_type>' % (len(wrappers), n_close))

    platforms = match_platform(wrapper, data)
    known_types = {}
    if not platforms:
        r.err('unrecognised wrapper tag %s - not used by any shipped audit; '
              'check navi-audit-platforms for the exact tag' % wrapper)
        r.note('platform-specific checks skipped')
    else:
        if len(platforms) > 1:
            r.note('wrapper matches multiple platforms: %s' % ', '.join(platforms))
        r.note('platform: %s' % ' / '.join(platforms))
        for p in platforms:
            for t, kws in data[p]['types'].items():
                known_types.setdefault(t, set()).update(kws)

    # --- structure -----------------------------------------------------
    for open_t, close_t in [('<if>', '</if>'), ('<then>', '</then>'),
                            ('<else>', '</else>'), ('<condition', '</condition>')]:
        a, b = text.count(open_t), text.count(close_t)
        if a != b:
            r.err('unbalanced %s / %s (%d vs %d)' % (open_t, close_t, a, b))

    for m in re.finditer(r'<report\s+type\s*:\s*"?([A-Za-z]+)"?', text):
        if m.group(1).upper() not in REPORT_TYPES:
            r.err('invalid report type "%s" - expected one of %s'
                  % (m.group(1), ', '.join(sorted(REPORT_TYPES))))

    for m in re.finditer(r'<condition([^>]*)>', text):
        if not re.search(r'type\s*:\s*"(AND|OR)"', m.group(1)):
            r.err('condition block missing type:"AND" or type:"OR"')

    # --- items ---------------------------------------------------------
    items = list(RE_ITEM.finditer(text))
    if not items:
        r.warn('no custom_item or item blocks found')
    r.note('%d item block(s)' % len(items))

    for idx, m in enumerate(items, 1):
        block = m.group(2)
        pairs = keys_of(block)
        keys = [k for k, _ in pairs]
        label = 'item %d' % idx
        desc = dict(pairs).get('description', '').strip('"')[:50]
        if desc:
            label += ' ("%s")' % desc

        if 'description' not in keys:
            r.err('%s: missing required keyword "description"' % label)

        ctype = None
        for k, v in pairs:
            if k == 'type':
                ctype = v.strip().strip('"')
                break

        if ctype is None:
            if m.group(1) == 'custom_item':
                r.warn('%s: no "type" keyword' % label)
        elif not known_types:
            pass
        elif ctype not in known_types:
            close = [t for t in known_types if t.startswith(ctype[:5])]
            hint = ' (similar: %s)' % ', '.join(sorted(close)[:3]) if close else ''
            r.err('%s: check type "%s" is not used on %s%s'
                  % (label, ctype, ' / '.join(platforms), hint))
        else:
            allowed = known_types[ctype]
            for k in keys:
                if k not in allowed:
                    on_other = sorted(t for t, kw in known_types.items() if k in kw)
                    hint = (' - valid on %s' % ', '.join(on_other[:3])) if on_other else ''
                    r.warn('%s: keyword "%s" not seen with %s%s'
                           % (label, k, ctype, hint))

        for k, v in pairs:
            v = v.strip().strip('"')
            if k == 'value_type' and v and v not in VALUE_TYPES:
                r.err('%s: invalid value_type "%s"' % (label, v))
            if k == 'check_type' and v and v not in OPERATORS:
                r.err('%s: invalid operator "%s"' % (label, v))

        if block.count('"') % 2 == 1:
            r.err('%s: unbalanced double quotes' % label)

    # --- variables -----------------------------------------------------
    header = text.split('</ui_metadata>')[0] if '</ui_metadata>' in text else ''
    declared = set(RE_VAR_DECL.findall(header))
    body = text.split('</ui_metadata>')[-1]
    used = set(RE_VAR_USE.findall(body))
    for v in sorted(used - declared):
        r.err('variable @%s@ used but not declared in the metadata header' % v)
    for v in sorted(declared - used):
        r.warn('variable @%s@ declared but never used' % v)

    # --- regex escaping ------------------------------------------------
    for m in re.finditer(r'^\s*value_data\s*:\s*"(.*)"\s*$', text, re.M):
        val = m.group(1)
        if re.search(r'(?<!\\)\\[dwsSDW(){}\[\]]', val) and 'CHECK_REGEX' in text:
            r.warn('value_data "%s" contains single-escaped regex metacharacters; '
                   'backslashes usually need doubling' % val[:40])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='+')
    ap.add_argument('--strict', action='store_true',
                    help='treat warnings as errors')
    args = ap.parse_args()

    if not os.path.exists(DATA):
        sys.exit('error: platform_data.json not found next to this script')
    data = json.load(open(DATA))

    failed = False
    for path in args.file:
        r = Result()
        print('== %s' % path)
        if not os.path.exists(path):
            print('   ERROR  file not found')
            failed = True
            continue
        validate(path, data, r)
        for n in r.notes:
            print('   info   %s' % n)
        for w in r.warnings:
            print('   WARN   %s' % w)
        for e in r.errors:
            print('   ERROR  %s' % e)
        bad = r.errors or (args.strict and r.warnings)
        print('   -> %s (%d error(s), %d warning(s))\n'
              % ('FAIL' if bad else 'OK', len(r.errors), len(r.warnings)))
        failed = failed or bool(bad)

    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
