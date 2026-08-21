---
name: navi-audit
description: >
  Entry point for authoring Tenable Nessus compliance audit files (.audit) from a
  natural-language requirement, and for reusing or recombining controls from the
  5,900+ audits Tenable ships. Load this whenever the user wants to create, write,
  edit, extend, or troubleshoot an audit file, or asks what a compliance check for
  something would look like. Trigger on: "write an audit file", "create a .audit",
  "custom audit for", "check that this registry key is set", "audit file to verify
  a file exists", "build a compliance check", "make a CIS-style check for", "combine
  controls from two benchmarks", "which controls cover NIST 800-53 AC-2", "turn this
  policy into a Nessus check", "my audit file will not load", "audit this Cisco
  config setting". Routes to navi-audit-syntax (grammar), navi-audit-platforms
  (per-platform check types and wrapper tags), and navi-audit-catalog (search the
  shipped corpus). Use this even when the user names only a platform or a control
  and does not say the word "audit".
---

# Authoring Tenable .audit Files

An `.audit` file is a plain-text policy file that Nessus loads to run compliance
checks. A malformed one does not error usefully — Nessus simply refuses to load
it, or the checks silently never fire. That failure mode drives everything in
this skill: **prefer a control that Tenable already ships over one you write from
scratch**, and validate before handing anything over.

## The workflow

### 1. Identify the platform

Map the request to a platform family. This decides the opening wrapper tag and
which check types are legal — Windows keywords on a Cisco check produce a file
that will not load.

Read the matching reference in `navi-audit-platforms`. Never guess a wrapper tag;
all 53 are confirmed verbatim there.

### 2. Search the catalog before writing anything

Tenable ships roughly 107,000 unique controls across CIS, DISA STIG, MSCT, TNS,
and vendor benchmarks. Most requirements already exist as a shipped, tested,
framework-mapped control. Search first — see `navi-audit-catalog`.

Three outcomes:

- **Exact match** — lift the control verbatim, adjust `value_data` if the user's
  threshold differs, keep the `reference` line. Cite which benchmark it came from.
- **Near match** — use it as the structural template and change the target
  (a different registry key, a different file path).
- **Nothing** — author from scratch using `navi-audit-syntax` plus the platform's
  keyword table. This is the minority case.

Composing a file from controls that came from *different* benchmarks is fine and
is a common ask ("CIS password policy plus our own file checks"). The only hard
constraint is that every control in one file must belong to the same
`check_type` wrapper — see the mixing rules below.

### 3. Author or assemble

Wrap the items in exactly one opening tag and its closing `</check_type>`.
Structure, keywords, conditionals, and reporting are covered in
`navi-audit-syntax`.

If the user's requirement has a threshold they may want to change later
(password length, timeout, banner text), declare it as a variable rather than
hardcoding it — the shipped audits do this heavily and it is what makes a file
reusable.

### 4. Validate before delivering

Run the checklist below. Do not skip it because the file "looks right" — the
most common failure is a keyword that is valid on another platform.

### 5. Deliver

Write the file with a `.audit` extension. Tell the user which benchmarks the
reused controls came from, and flag anything you authored from scratch as
untested — a scratch-authored check should be run against one host before it
goes into a scan policy.

## Mixing controls across benchmarks

| Situation | Allowed? |
|---|---|
| CIS and STIG controls for the same platform in one file | Yes |
| Controls from two versions of the same benchmark | Yes, but dedupe — they often differ only in the `reference` line |
| Windows config checks plus Windows file-content checks | **No** — different wrappers (`Windows` vs `FileContent`); two files |
| Unix checks plus Windows checks | **No** — two files |
| Two database engines in one file | **No** — `db_type` is set on the wrapper |
| Same platform, different `type:` values | Yes — that is normal |

When a user asks for something that spans wrappers, produce multiple `.audit`
files and say why rather than silently dropping half the request.

## Validation checklist

Before delivering any file:

1. **Wrapper tag is verbatim** from `navi-audit-platforms` — including the
   `version:"2"` on Windows and `db_type:` on Database.
2. **Exactly one wrapper**, opened at the top and closed with `</check_type>`.
3. **Every `type:` is valid for that platform** — check the platform's table.
4. **Every keyword is valid for that `type:`** — same table. A keyword that
   exists on the platform but not on that check type is still a failure.
5. **`value_type` is one of** POLICY_DWORD, POLICY_TEXT, POLICY_MULTI_TEXT,
   POLICY_SET, POLICY_BINARY, POLICY_HEXADECIMAL, POLICY_DAY,
   POLICY_FILE_VERSION, USER_RIGHT, AUDIT_SET, SERVICE_SET, FILE_ACL, REG_ACL,
   TIME_MINUTE, TIME_DAY.
6. **Quotes are balanced** and backslashes in regexes are escaped.
7. **Every `@VARIABLE@` reference has a declaration** in the metadata header.
8. **Conditionals are closed** — every `<if>` has `<condition>`/`</condition>`,
   `<then>`, and `</if>`.
9. **File extension is `.audit`.**

A validation script is available: `scripts/validate_audit.py <file>`. It catches
structural problems and unknown keywords; it cannot tell you whether a check is
semantically correct.

## Setup

The catalog must be built once before search works:

```bash
python3 scripts/build_catalog.py /path/to/audit_warehouse.audit -o ~/.navi/audit_catalog.db
```

The warehouse ships with the Tenable platform. Re-run the builder whenever
Tenable publishes a new one — the catalog is a derived artifact, not a fixture.
See `navi-audit-catalog` for where to find the warehouse and how to query the
result.

## navi integration

When `navi_*` tools are present:

- `navi explore data audits` lists the audit files already running in the
  environment — the fastest way to see which benchmarks are in use before adding
  another.
- After a compliance scan, filter the same command by audit name or asset UUID to
  confirm your checks actually fired. A check that returns nothing usually means
  the keyword was wrong, not that the host is compliant.
- navi is optional. Everything in this skill works without it.

## Related skills

- **navi-audit-syntax** — the grammar: item structure, keywords, operators,
  conditionals, variables, reporting.
- **navi-audit-platforms** — what can be checked on each of 53 platforms.
- **navi-audit-catalog** — build and search the shipped-control corpus.
