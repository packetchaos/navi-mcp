#!/usr/bin/env python3
"""
build_catalog.py - Build a queryable control catalog from Tenable's shipped
audit warehouse.

The warehouse (audit_warehouse.audit) is a signed SQLite database that ships
with the Tenable platform. It holds every compliance audit Tenable publishes.
This script distills it into audit_catalog.db: one row per unique control,
searchable by platform, check type, framework reference, and free text.

Usage:
    python3 build_catalog.py /path/to/audit_warehouse.audit
    python3 build_catalog.py /path/to/audit_warehouse.audit -o ~/.navi/audit_catalog.db

The warehouse is read-only; this script never modifies it.
"""

import argparse
import hashlib
import os
import re
import sqlite3
import sys

SCHEMA = """
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE audits (
    id            INTEGER PRIMARY KEY,
    display_name  TEXT,
    filename      TEXT,
    platform      TEXT,      -- warehouse category, e.g. 'Windows', 'Cisco IOS'
    platform_group TEXT,     -- e.g. 'Operating Systems and Applications'
    check_type    TEXT,      -- verbatim opening wrapper tag
    spec_type     TEXT,      -- CIS, DISA STIG, TNS, ...
    spec_name     TEXT,
    spec_profile  TEXT,
    spec_version  TEXT,
    spec_link     TEXT,
    labels        TEXT
);

CREATE TABLE controls (
    id          INTEGER PRIMARY KEY,
    platform    TEXT,
    check_type  TEXT,        -- wrapper tag this control lives under
    item_tag    TEXT,        -- 'custom_item' or 'item'
    type        TEXT,        -- check type, e.g. FILE_CHECK, CONFIG_CHECK
    description TEXT,
    solution    TEXT,
    info        TEXT,
    reference   TEXT,        -- raw reference string
    see_also    TEXT,
    body        TEXT         -- full verbatim block, ready to paste
);

-- one control can appear in many shipped audits; this maps them
CREATE TABLE control_audits (
    control_id INTEGER,
    audit_id   INTEGER,
    PRIMARY KEY (control_id, audit_id)
);

-- exploded framework references, e.g. ('800-53','AC-2') for each control
CREATE TABLE control_refs (
    control_id INTEGER,
    framework  TEXT,
    control_ref TEXT
);

CREATE TABLE variables (
    audit_id      INTEGER,
    name          TEXT,
    default_value TEXT,
    description   TEXT,
    info          TEXT
);
"""

INDEXES = """
CREATE INDEX idx_controls_platform ON controls(platform);
CREATE INDEX idx_controls_type ON controls(type);
CREATE INDEX idx_controls_platform_type ON controls(platform, type);
CREATE INDEX idx_refs_ctl ON control_refs(control_id);
CREATE INDEX idx_refs_pair ON control_refs(framework, control_ref);
CREATE INDEX idx_ca_audit ON control_audits(audit_id);
CREATE INDEX idx_audits_platform ON audits(platform);
CREATE INDEX idx_audits_spec ON audits(spec_type, spec_name);
"""

FTS = """
CREATE VIRTUAL TABLE controls_fts USING fts5(
    description, info, body,
    content='controls', content_rowid='id', tokenize='porter unicode61'
);
INSERT INTO controls_fts(rowid, description, info, body)
    SELECT id, description, info, body FROM controls;
"""

RE_CHECK_TYPE = re.compile(r'^<check_type:[^>]*>', re.M)
RE_ITEM = re.compile(r'<(custom_item|item)>(.*?)</\1>', re.S)
RE_TYPE = re.compile(r'^\s*type\s*:\s*([A-Za-z0-9_]+)', re.M)
RE_VARBLOCK = re.compile(r'#<variable>(.*?)#</variable>', re.S)
RE_LABELS = re.compile(r'#<labels>(.*?)</labels>', re.S)


def field(block, key):
    """Pull a `key : value` field from an item block, handling quotes."""
    m = re.search(r'^\s*%s\s*:\s*(.+?)\s*$' % key, block, re.M)
    if not m:
        return None
    v = m.group(1).strip()
    if v.startswith('"'):
        m2 = re.search(r'^\s*%s\s*:\s*"(.*?)"' % key, block, re.M | re.S)
        if m2:
            return m2.group(1).strip()
        v = v.lstrip('"')
    return v


def var_field(block, key):
    m = re.search(r'#\s*<%s>(.*?)</%s>' % (key, key), block, re.S)
    if not m:
        return None
    return re.sub(r'^\s*#\s?', '', m.group(1), flags=re.M).strip()


def explode_refs(raw):
    """
    Turn a reference string into (framework, control) pairs.

    Shipped form is comma-separated `FRAMEWORK|CONTROL` tokens, e.g.
    "800-53|AC-2,CSCv8|5.1,PCI-DSSv4.0|8.2.1"
    """
    out = []
    if not raw:
        return out
    for tok in raw.split(','):
        tok = tok.strip()
        if not tok:
            continue
        if '|' in tok:
            fw, ctl = tok.split('|', 1)
            out.append((fw.strip(), ctl.strip()))
        else:
            out.append((tok, ''))
    return out


def norm(text):
    return re.sub(r'\s+', ' ', text).strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('warehouse', help='path to audit_warehouse.audit')
    ap.add_argument('-o', '--output', default='audit_catalog.db',
                    help='output catalog path (default: ./audit_catalog.db)')
    ap.add_argument('--include-deprecated', action='store_true',
                    help='include deprecated audits (they normally ship without content)')
    ap.add_argument('--no-fts', action='store_true',
                    help='skip the full-text index (smaller, but no keyword search)')
    args = ap.parse_args()

    if not os.path.exists(args.warehouse):
        sys.exit('error: warehouse not found: %s' % args.warehouse)

    src = sqlite3.connect('file:%s?mode=ro' % os.path.abspath(args.warehouse), uri=True)
    src.text_factory = str

    try:
        wh_meta = dict(src.execute('SELECT key, value FROM database_metadata'))
    except sqlite3.DatabaseError as e:
        sys.exit('error: %s does not look like an audit warehouse (%s)' % (args.warehouse, e))

    if os.path.exists(args.output):
        os.remove(args.output)
    dst = sqlite3.connect(args.output)
    dst.executescript(SCHEMA)

    where = '' if args.include_deprecated else 'WHERE a.deprecated = 0'
    rows = src.execute("""
        SELECT a.id, a.display_name, a.filename, cat.name, cg.name,
               a.spec_type, a.spec_name, a.spec_profile, a.spec_version, a.spec_link,
               co.data
        FROM audit a
        JOIN content co ON co.id = a.content
        JOIN category cat ON cat.id = a.category
        JOIN category_group cg ON cg.id = cat.category_group
        %s
    """ % where)

    control_ids = {}          # hash -> control id
    next_control_id = 1
    n_audits = 0
    audit_rows, control_rows, link_rows, ref_rows, var_rows = [], [], [], [], []

    for (aid, dname, fname, platform, pgroup, stype, sname,
         sprofile, sversion, slink, data) in rows:
        n_audits += 1

        tags = RE_CHECK_TYPE.findall(data)
        wrapper = tags[0] if tags else ''

        lm = RE_LABELS.search(data)
        labels = re.sub(r'\s*#\s*', '', lm.group(1)).strip() if lm else ''

        audit_rows.append((aid, dname, fname, platform, pgroup, wrapper,
                           stype, sname, sprofile, sversion, slink, labels))

        for vb in RE_VARBLOCK.findall(data):
            name = var_field(vb, 'n') or var_field(vb, 'name')
            if name:
                var_rows.append((aid, name, var_field(vb, 'default'),
                                 var_field(vb, 'description'), var_field(vb, 'info')))

        for m in RE_ITEM.finditer(data):
            item_tag, block = m.group(1), m.group(2)
            body = block.strip()
            key = hashlib.md5(('%s\x00%s' % (platform, norm(body))).encode('utf-8',
                                                                          'replace')).hexdigest()
            cid = control_ids.get(key)
            if cid is None:
                cid = next_control_id
                next_control_id += 1
                control_ids[key] = cid

                tm = RE_TYPE.search(block)
                ctype = tm.group(1) if tm else None
                raw_ref = field(block, 'reference')

                control_rows.append((
                    cid, platform, wrapper, item_tag, ctype,
                    field(block, 'description'), field(block, 'solution'),
                    field(block, 'info'), raw_ref, field(block, 'see_also'), body,
                ))
                for fw, ctl in explode_refs(raw_ref):
                    ref_rows.append((cid, fw, ctl))

            link_rows.append((cid, aid))

        if len(control_rows) > 20000:
            flush(dst, audit_rows, control_rows, link_rows, ref_rows, var_rows)
            audit_rows, control_rows, link_rows, ref_rows, var_rows = [], [], [], [], []
            print('  ... %d audits, %d unique controls' % (n_audits, next_control_id - 1),
                  file=sys.stderr)

    flush(dst, audit_rows, control_rows, link_rows, ref_rows, var_rows)

    dst.executescript(INDEXES)
    if not args.no_fts:
        print('building full-text index ...', file=sys.stderr)
        dst.executescript(FTS)

    meta = [
        ('catalog_source', os.path.basename(args.warehouse)),
        ('warehouse_build_date', wh_meta.get('build date', '')),
        ('warehouse_commit', wh_meta.get('warehouse commit hash', '')),
        ('compliance_checks_commit', wh_meta.get('compliance_checks commit hash', '')),
        ('audits', str(n_audits)),
        ('unique_controls', str(next_control_id - 1)),
    ]
    dst.executemany('INSERT INTO meta VALUES (?,?)', meta)
    dst.commit()

    size_mb = os.path.getsize(args.output) / 1e6
    print('\nBuilt %s' % args.output)
    print('  audits            %d' % n_audits)
    print('  unique controls   %d' % (next_control_id - 1))
    print('  platforms         %d' % dst.execute(
        'SELECT COUNT(DISTINCT platform) FROM controls').fetchone()[0])
    print('  frameworks        %d' % dst.execute(
        'SELECT COUNT(DISTINCT framework) FROM control_refs').fetchone()[0])
    print('  warehouse built   %s' % wh_meta.get('build date', 'unknown'))
    print('  size              %.1f MB' % size_mb)
    dst.close()
    src.close()


def flush(dst, audits, controls, links, refs, variables):
    dst.executemany('INSERT INTO audits VALUES (%s)' % ','.join('?' * 12), audits)
    dst.executemany('INSERT INTO controls VALUES (%s)' % ','.join('?' * 11), controls)
    dst.executemany('INSERT OR IGNORE INTO control_audits VALUES (?,?)', links)
    dst.executemany('INSERT INTO control_refs VALUES (?,?,?)', refs)
    dst.executemany('INSERT INTO variables VALUES (?,?,?,?,?)', variables)
    dst.commit()


if __name__ == '__main__':
    main()
