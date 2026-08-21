# Windows — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## Windows

- **Opening tag:** `<check_type:"Windows" version:"2">`
- **Corpus:** 430 shipped audits, 49555 control items
- **Benchmark families:** CIS (253), DISA STIG (100), MSCT (76), IBM (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REGISTRY_SETTING` | 36038 | `reg_key`, `value_data`, `value_type`, `reg_item`, `reg_option`, `reg_ignore_hku_users`, `check_type`, `reg_include_hku_users`, `reg_type`, `severity`, `v1607`, `reg_enum` |
| `USER_RIGHTS_POLICY` | 3078 | `right_type`, `value_data`, `value_type`, `check_type`, `use_domain`, `severity` |
| `AUDIT_POLICY_SUBCATEGORY` | 2615 | `value_data`, `audit_policy_subcategory`, `value_type` |
| `AUDIT_POWERSHELL` | 2360 | `value_data`, `powershell_args`, `value_type`, `check_type`, `severity`, `powershell_option`, `only_show_cmd_output`, `powershell_console_file`, `https`, `ps_encoded_args` |
| `FILE_CONTENT_CHECK` | 837 | `expect`, `value_data`, `regex`, `value_type`, `file_option`, `check_type`, `severity`, `net`, `mode`, `ssl`, `tls`, `port`, `roles`, `authorization` |
| `AUDIT_EXCHANGE` | 759 | `value_data`, `powershell_args`, `secure_string`, `value_type`, `check_type`, `severity`, `https` |
| `WMI_POLICY` | 715 | `value_data`, `wmi_namespace`, `wmi_request`, `value_type`, `wmi_attribute`, `wmi_key`, `check_type`, `wmi_option` |
| `REG_CHECK` | 607 | `reg_option`, `value_data`, `value_type`, `key_item`, `severity` |
| `AUDIT_IIS_APPCMD` | 530 | `appcmd_args`, `value_data`, `value_type`, `check_type`, `appcmd_list`, `appcmd_filter`, `appcmd_filter_value`, `severity`, `only_show_cmd_output` |
| `PASSWORD_POLICY` | 528 | `password_policy`, `value_data`, `value_type` |
| `LOCKOUT_POLICY` | 265 | `value_data`, `lockout_policy`, `value_type`, `check_type` |
| `FILE_PERMISSIONS` | 238 | `value_data`, `value_type`, `file`, `severity`, `acl_option`, `check_type` |
| `FILE_CHECK` | 224 | `value_data`, `file_option`, `value_type`, `severity` |
| `CHECK_ACCOUNT` | 185 | `value_data`, `account_type`, `value_type`, `check_type` |
| `FILE_CONTENT_CHECK_NOT` | 122 | `expect`, `value_data`, `regex`, `value_type`, `check_type`, `file_option`, `severity` |
| `BANNER_CHECK` | 120 | `value_data`, `value_type`, `reg_key`, `reg_item`, `is_substring`, `file` |
| `REGISTRY_PERMISSIONS` | 81 | `reg_key`, `value_data`, `value_type`, `acl_option` |
| `GUID_REGISTRY_SETTING` | 75 | `reg_option`, `reg_key`, `value_data`, `value_type`, `reg_item`, `guid_reg_key`, `reg_ignore_hku_users` |
| `ANONYMOUS_SID_SETTING` | 57 | `value_data`, `value_type` |
| `SERVICE_POLICY` | 44 | `service_name`, `value_data`, `value_type`, `svc_option`, `severity` |
| `KERBEROS_POLICY` | 40 | `value_data`, `kerberos_policy`, `value_type` |
| `GROUP_MEMBERS_POLICY` | 17 | `value_data`, `group_name`, `value_type`, `check_type`, `severity` |
| `AUDIT_USER_TIMESTAMPS` | 16 | `severity`, `value_data`, `timestamp`, `ignore_users`, `value_type`, `check_type` |
| `USER_GROUPS_POLICY` | 2 | `value_data`, `user_name`, `value_type` |
| `FILE_VERSION` | 2 | `value_data`, `value_type`, `file`, `check_type` |

### Example — `REGISTRY_SETTING`

From `CIS Azure Compute Microsoft Windows Server 2019 v1.0.0 L1 DC`:

```
<custom_item>
  type        : REGISTRY_SETTING
  description : "Windows Server 2019 is installed"
  value_type  : POLICY_TEXT
  value_data  : "^[a-zA-Z0-9\(\)\s]*@PLATFORM_VERSION@[\s]*[a-zA-Z0-9\(\)\s:]*$"
  reg_key     : "HKLM\Software\Microsoft\Windows Nt\Currentversion"
  reg_item    : "ProductName"
  check_type  : CHECK_REGEX
</custom_item>
```

## Windows File Contents

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
