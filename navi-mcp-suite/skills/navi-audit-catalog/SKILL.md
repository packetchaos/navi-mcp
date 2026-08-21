---
name: navi-audit-catalog
description: >
  Search and reuse the roughly 107,000 compliance controls that ship with the
  Tenable platform, indexed from the signed audit warehouse into a local queryable
  catalog. Use this before authoring any audit check from scratch, and whenever the
  user wants to find, compare, or recombine existing controls. Trigger on: "find an
  existing check for", "does Tenable already have a control for", "which controls
  map to 800-53 AC-2", "pull the CIS password controls", "combine controls from two
  benchmarks", "what does the STIG check for this", "build me an audit from the CIS
  benchmark", "how many controls cover PCI", "search the audit catalog", "build the
  catalog", "rebuild the audit index". Also covers building the catalog from the
  warehouse file and where that warehouse lives. Companion to navi-audit.
---

# The Shipped-Control Catalog

Tenable ships every compliance audit it publishes inside a signed SQLite database
called the **audit warehouse** (`audit_warehouse.audit`). The warehouse holds
5,931 audit records; content ships for the 1,737 current ones, and the remaining
deprecated entries are metadata-only stubs with no body.

`build_catalog.py` distills that into a local catalog: one row per unique control,
searchable by platform, check type, framework reference, and free text.

**Reuse beats authoring.** A shipped control has been tested against real hosts,
carries framework mappings, and uses keywords known to be valid for its platform.
Search here before writing anything by hand.

## Building the catalog

```bash
python3 ../navi-audit/scripts/build_catalog.py \
    /path/to/audit_warehouse.audit \
    -o ~/.navi/audit_catalog.db
```

Roughly two minutes and about 775 MB. Options:

- `--no-fts` skips the full-text index — about 130 MB smaller, but keyword search
  stops working. Only worth it if disk is tight.
- `--include-deprecated` pulls in the deprecated records; they normally carry no
  content, so this rarely adds anything.

The warehouse is read-only throughout — the builder never modifies it.

### Finding the warehouse

It ships with the platform rather than as a separate download:

- Nessus: under the plugins directory in the Nessus install tree.
- Tenable Security Center: in the feed directory alongside the plugin feed.
- If neither is available, the user can export it from a Tenable instance.

Re-run the builder whenever Tenable publishes a new warehouse. The catalog stores
the source warehouse's build date in its `meta` table — check it before trusting
the catalog to be current:

```sql
SELECT * FROM meta;
```

## Schema

| Table | Contents |
|---|---|
| `controls` | One row per unique control: `platform`, `check_type` (wrapper), `type`, `description`, `info`, `solution`, `reference`, `see_also`, `body` |
| `audits` | The shipped audit files: `display_name`, `platform`, `check_type`, `spec_type`, `spec_name`, `spec_version`, `spec_link`, `labels` |
| `control_audits` | Which audits a control appears in — controls are deduped across benchmark versions |
| `control_refs` | Exploded framework mappings: `framework`, `control_ref` |
| `variables` | Variable declarations per audit — useful as authoring templates |
| `controls_fts` | Full-text index over `description`, `info`, and `body` |
| `meta` | Catalog provenance and warehouse build date |

`body` holds the complete verbatim item block, ready to paste into a file.

## Query patterns

### Free-text search, scoped to a platform

```sql
SELECT c.type, c.description, c.body
FROM controls_fts f JOIN controls c ON c.id = f.rowid
WHERE controls_fts MATCH 'password AND length'
  AND c.platform = 'Windows'
LIMIT 10;
```

FTS5 syntax: `AND`, `OR`, `NOT`, `"exact phrase"`, and `term*` prefixes.

### Everything mapped to a framework control

```sql
SELECT c.platform, c.type, c.description
FROM control_refs r JOIN controls c ON c.id = r.control_id
WHERE r.framework = '800-53' AND r.control_ref LIKE 'AC-2%'
ORDER BY c.platform;
```

### Pull a whole benchmark

```sql
SELECT c.body
FROM controls c
JOIN control_audits ca ON ca.control_id = c.id
JOIN audits a ON a.id = ca.audit_id
WHERE a.spec_type = 'CIS'
  AND a.spec_name LIKE '%Windows Server 2022%'
  AND a.spec_profile LIKE '%L1%';
```

### Find controls touching a specific target

```sql
SELECT platform, type, description FROM controls
WHERE platform = 'Unix' AND body LIKE '%/etc/ssh/sshd_config%';
```

### Trace a control back to its source benchmarks

```sql
SELECT a.spec_type, a.spec_name, a.spec_version, a.spec_profile
FROM control_audits ca JOIN audits a ON a.id = ca.audit_id
WHERE ca.control_id = ?;
```

Always do this before presenting a reused control — the user needs to know
whether they are getting a CIS Level 1, a STIG, or a vendor hardening guide.

### What benchmarks exist for a platform

```sql
SELECT spec_type, spec_name, spec_version, spec_profile
FROM audits WHERE platform = 'Cisco IOS'
ORDER BY spec_name, spec_version;
```

## Composing a file from catalog controls

1. Query for the controls the requirement needs, scoped to one platform.
2. Confirm they share a wrapper — `SELECT DISTINCT check_type` over the result
   set must return exactly one row. If it returns two, the file has to be split.
3. Concatenate the `body` values inside `<custom_item>` tags under that wrapper.
4. Dedupe near-identical controls pulled from multiple benchmark versions; they
   often differ only in the `reference` line. Keep the newer one, or merge the
   reference strings.
5. Adjust `value_data` where the user's threshold differs from the benchmark's,
   and consider promoting it to a variable.
6. Run the validation checklist in `navi-audit`.

Tell the user which benchmarks each control came from. Silently mixing a STIG
control into a file the user believes is pure CIS causes real problems at audit
time.

## Limits

- The catalog reflects one warehouse build. It goes stale as Tenable publishes.
- Deprecated audits carry no content, so historical controls are not searchable.
- A control being present says nothing about whether it applies to the user's
  environment — benchmark profiles (L1 vs L2, DC vs member server) matter.
- FTS matches text, not intent. A search for "encryption" will miss a control
  described as "TLS 1.2 required".
