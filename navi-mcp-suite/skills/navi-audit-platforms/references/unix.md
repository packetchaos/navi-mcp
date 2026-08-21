# Unix, Linux, and macOS — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## Unix

- **Opening tag:** `<check_type:"Unix">`
- **Corpus:** 646 shipped audits, 108701 control items
- **Benchmark families:** CIS (493), DISA STIG (113), TNS (37), IBM (2), VMWare (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CMD_EXEC` | 62000 | `cmd`, `expect`, `system`, `severity`, `dont_echo_cmd`, `timeout`, `required`, `check_option` |
| `FILE_CONTENT_CHECK` | 21914 | `regex`, `file`, `expect`, `system`, `string_required`, `min_occurrences`, `required`, `file_required`, `json_transform`, `severity`, `file_supersedence`, `xsl_stmt`, `search_locations`, `ignore` |
| `FILE_CHECK` | 8406 | `file`, `mask`, `owner`, `group`, `system`, `required`, `file_required`, `file_type`, `check_uneveness`, `severity`, `ignore`, `search_locations` |
| `RPM_CHECK` | 6625 | `rpm`, `operator`, `required`, `system`, `severity` |
| `FILE_CONTENT_CHECK_NOT` | 3727 | `regex`, `file`, `expect`, `system`, `file_required`, `required`, `string_required`, `min_occurrences`, `search_locations`, `severity`, `ignore` |
| `(untyped item)` | 1704 | `name`, `system`, `find_option`, `severity`, `mask`, `ignore_shell`, `ignore_user`, `uid_ge`, `file`, `timeout`, `uid_lt`, `basedir`, `ignore`, `value` |
| `MACOSX_OSASCRIPT` | 898 | `payload_type`, `payload_key`, `expect`, `required`, `severity` |
| `FILE_CHECK_NOT` | 630 | `file`, `system`, `owner`, `group`, `required`, `severity` |
| `FIND_CMD` | 508 | `not_expect`, `find_type`, `target`, `exec`, `find_name`, `perm`, `not_group`, `not_user`, `not_gid`, `severity`, `expect`, `not_perm`, `uid`, `verbose` |
| `AUDIT_XML` | 504 | `xsl_stmt`, `file`, `expect`, `not_expect`, `system`, `regex`, `severity` |
| `BANNER_CHECK` | 452 | `content`, `file`, `is_substring`, `system` |
| `MACOSX_DEFAULTS_READ` | 402 | `plist_item`, `plist_name`, `regex`, `plist_option`, `plist_user`, `byhost`, `managed_path`, `not_regex`, `severity` |
| `XINETD_SVC` | 252 | `status`, `service`, `system` |
| `CHKCONFIG` | 241 | `status`, `service`, `levels`, `system` |
| `PROCESS_CHECK` | 206 | `name`, `status`, `system`, `severity`, `owner` |
| `SVC_PROP` | 206 | `property`, `service`, `regex`, `svcprop_option`, `system`, `value`, `severity` |
| `GRAMMAR_CHECK` | 19 | `regex`, `file`, `system` |
| `PKG_CHECK` | 7 | `pkg`, `required`, `system` |

### Example — `CMD_EXEC`

From `CAS Implementation Group 1 Audit File`:

```
<custom_item>
  type          : CMD_EXEC
  description   : "CIS Control 1 (1.4) Maintain Detailed Asset Inventory"
  info          : "Implementation Group 1 - Does the organization have an established policy or procedure detailing how assets/devices are added or removed from inventory?"
  see_also      : "https://controls-assessment-specification.readthedocs.io/en/latest"
  reference     : "800-171|3.4.1,800-53|CM-8,800-53r5|CM-8,CN-L3|8.1.10.2(a),CN-L3|8.1.10.2(b),CSCv7|1.4,CSF|DE.CM-7,CSF|ID.AM-1,CSF|ID.AM-2,CSF|PR.DS-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-8,NESA|T1.2.1,NESA|T1.2.2"
  cmd           : "printf '@1_4_Answer@ - @Attesting_User@\\nPolicy or Policy Statement: @1_4_Support@'"
  expect        : "^[Yy]es - .*"
  dont_echo_cmd : YES
</custom_item>
```

## Unix File Contents

- **Opening tag:** `<check_type:"FileContent">`
- **Corpus:** 22 shipped audits, 793 control items
- **Benchmark families:** TNS (22)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `FILE_CONTENT_CHECK` | 758 | `max_size`, `file_extension`, `regex`, `expect`, `only_show`, `regex_replace`, `file_name` |
| `(untyped item)` | 35 | — |

### Example — `FILE_CONTENT_CHECK`

From `TNS File Analysis - Drivers License`:

```
<custom_item>
  type           : FILE_CONTENT_CHECK
  description    : "PII - The file contains an Arizona Drivers license number"
  file_extension : "txt" |"doc" |"xls" |"pdf"
  regex          : "([^0-9]|^)(([A-Z][0-9]{8}))([^0-9\-]|$)"
  expect         : "License" | "Driver" | "ID" | "Arizona" | "AZ"
  max_size       : "50K"
</custom_item>
```
