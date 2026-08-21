---
name: navi-audit-syntax
description: >
  The universal grammar of Tenable Nessus audit files — the part that is identical
  on every platform. Covers file structure, the custom_item and item blocks,
  required and optional keywords, the value_type vocabulary, comparison operators,
  regex handling, conditional if/then/else logic, report blocks, variable
  declarations, and the metadata header. Load this for any real audit-file
  authoring or editing, alongside navi-audit-platforms for the target system.
  Trigger on: "audit file syntax", "how do I structure a custom_item", "what
  value_type should I use", "CHECK_REGEX vs CHECK_EQUAL", "conditional check in an
  audit file", "how do I add a variable to an audit", "why will my audit not load",
  "escape a regex in an audit file", "add a reference to a control", "make this
  check report a warning instead of a failure".
---

# Audit File Grammar

Everything here is platform-independent. What changes per platform — the opening
tag, which check types exist, which keywords each takes — lives in
`navi-audit-platforms`.

## File structure

```
#<ui_metadata>
#<display_name>My Custom Policy</display_name>
#<spec>
#  <type>TNS</type>
#  <n>My Custom Policy</n>
#  <version>1.0.0</version>
#</spec>
#<labels>custom,internal</labels>
#<variables>
#  <variable>
#    <n>MIN_PASSWORD_LENGTH</n>
#    <default>14</default>
#    <description>Minimum Password Length</description>
#    <info>Minimum characters required for user passwords.</info>
#    <value_type>STRING</value_type>
#  </variable>
#</variables>
#</ui_metadata>

<check_type:"Unix">

<custom_item>
  type        : FILE_CHECK
  description : "Verify /etc/ssh/sshd_config exists"
  info        : "The SSH daemon configuration file must be present."
  file        : "/etc/ssh/sshd_config"
  exists      : YES
</custom_item>

</check_type>
```

Three parts, in order:

1. **Metadata header** (optional but strongly recommended) — commented-out block
   that Tenable's UI reads for the display name, labels, and variable prompts.
   Every line starts with `#`. Without it the file still runs; it just shows up
   unnamed and unconfigurable.
2. **Opening wrapper tag** — exactly one, verbatim from `navi-audit-platforms`.
3. **Items**, then the closing `</check_type>`.

## The item block

`<custom_item>` is what you write. `<item>` is a reference to a predefined check
that ships inside Nessus and is far rarer — in the shipped corpus, custom items
outnumber predefined ones roughly 22 to 1. Author `<custom_item>` unless you are
deliberately invoking a built-in.

Keywords are `name : value` pairs, one per line. Values containing spaces or
special characters must be double-quoted. Order does not matter, but shipped
audits put `type` first and the target last, which is worth matching.

### Universal keywords

| Keyword | Required | Purpose |
|---|---|---|
| `type` | yes | The check type, e.g. `FILE_CHECK`, `REGISTRY_SETTING` |
| `description` | yes | One line shown in scan results — make it specific and greppable |
| `info` | no | Longer explanation shown in the report; why the control matters |
| `solution` | no | Remediation guidance |
| `reference` | no | Framework mappings (see below) |
| `see_also` | no | URL to the benchmark or vendor doc |
| `severity` | no | `MEDIUM` is the only value used in the shipped corpus |

`description` is the field that appears in every results view and in navi's
compliance table. Vague descriptions make results unusable at scale.

### The reference field

Comma-separated `FRAMEWORK|CONTROL` tokens in one quoted string:

```
reference : "800-53|AC-2,CSCv8|5.1,PCI-DSSv4.0|8.2.1,CSF2.0|PR.AA-01"
```

46 framework schemes appear in the shipped corpus, including 800-53, 800-53r5,
800-171, 800-171r3, CSF, CSF2.0, PCI-DSSv3.2.1, PCI-DSSv4.0, ISO-27001-2022,
HIPAA, GDPR, CSCv7, CSCv8, ITSG-33, NESA, SWIFT-CSCv1, and the STIG triplet
STIG-ID / Rule-ID / CCI. Copy the mapping from an equivalent shipped control
rather than inventing one — `navi-audit-catalog` can look it up.

## Comparison: value_type, value_data, check_type

`value_type` declares how `value_data` is interpreted; the optional inner
`check_type` keyword declares the operator.

### value_type vocabulary

| value_type | Use |
|---|---|
| `POLICY_DWORD` | Numeric value — by far the most common |
| `POLICY_TEXT` | String value |
| `POLICY_MULTI_TEXT` | Multi-line string |
| `POLICY_SET` | A set of values |
| `POLICY_BINARY` | Binary data |
| `POLICY_HEXADECIMAL` | Hex value |
| `POLICY_DAY` / `TIME_DAY` / `TIME_MINUTE` | Time-based thresholds |
| `POLICY_FILE_VERSION` | File version string |
| `USER_RIGHT` | Windows user rights assignment |
| `AUDIT_SET` | Windows audit policy setting |
| `SERVICE_SET` | Windows service state |
| `FILE_ACL` / `REG_ACL` | Permission sets |

### Operators

| `check_type` | Meaning |
|---|---|
| `CHECK_EQUAL` | Exact match (the default when omitted) |
| `CHECK_NOT_EQUAL` | Must not match |
| `CHECK_REGEX` | `value_data` is a regular expression |
| `CHECK_NOT_REGEX` | Must not match the expression |
| `CHECK_GREATER_THAN_OR_EQUAL` | Numeric floor — the common form for minimums |
| `CHECK_LESS_THAN_OR_EQUAL` | Numeric ceiling |
| `CHECK_SUBSET` / `CHECK_SUPERSET` | Set containment |

Ranges are expressed as `value_data : [1..14]`.

### Regex escaping

Regexes go in `value_data` with `check_type : CHECK_REGEX`. Backslashes must be
escaped, and Windows registry paths are full of them:

```
value_data : "^[a-zA-Z0-9\\(\\)\\s]*Server 2019[\\s]*$"
```

Unescaped backslashes are the single most common reason a file loads but the
check never matches.

## Conditionals

Conditional logic is heavily used — roughly 29,000 blocks in the shipped corpus.
The pattern gates checks on a prior result, so a control only applies where it is
relevant (a domain controller check that should not run on a member server).

```
<if>
  <condition type:"AND">
    <custom_item>
      type        : REGISTRY_SETTING
      description : "Detect whether the role is installed"
      value_type  : POLICY_DWORD
      value_data  : 1
      reg_key     : "HKLM\Software\Example\RoleInstalled"
      reg_item    : "Enabled"
    </custom_item>
  </condition>
  <then>
    <custom_item>
      type        : REGISTRY_SETTING
      description : "Role-specific hardening setting"
      value_type  : POLICY_DWORD
      value_data  : 1
      reg_key     : "HKLM\Software\Example\Hardening"
      reg_item    : "Strict"
    </custom_item>
  </then>
  <else>
    <report type:"PASSED">
      description : "Role not installed - check not applicable"
    </report>
  </else>
</if>
```

- `<condition type:"AND">` and `type:"OR"` are the two forms.
- `auto:"FAILED"` on the condition suppresses noise from the detection check
  itself; `auto:"WARNING"` is also used.
- `<else>` is optional — about half of shipped conditionals omit it.

## Report blocks

`<report type:"PASSED">` emits a result without running a check. Valid types are
`PASSED`, `WARNING`, `FAILED`, and `INFO`. The dominant use is the `<else>` branch
above: explicitly passing a control that does not apply, so the result set does
not fill with false failures.

```
<report type:"WARNING">
  description : "Manual review required - verify the retention policy"
  info        : "This control cannot be evaluated automatically."
</report>
```

## Variables

Declare in the metadata header, reference as `@NAME@` anywhere in the body:

```
value_data : "[@MIN_PASSWORD_LENGTH@..999]"
```

Declared variables become editable fields in the Tenable UI when the audit is
attached to a policy. Use them for anything an operator might reasonably tune:
thresholds, banner text, allowed account lists, management VRF names. Every
`@NAME@` in the body must have a matching declaration or the file will not load.

## Common load failures

| Symptom | Cause |
|---|---|
| File will not load at all | Wrapper tag wrong, misspelled, or missing `</check_type>` |
| File loads, check never fires | Keyword not valid for that check type, or unescaped regex |
| Check always fails | `value_type` mismatched to the actual data type |
| Variable prompt missing in UI | `@NAME@` used without a declaration block |
| Everything reports as failed on hosts where it should not apply | Missing conditional gate |
