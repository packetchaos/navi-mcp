# Mobile Device Management — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## Mobile Device Manager

- **Opening tag:** `<check_type:"MDM" mdm_type:AIRWATCH>` or `<check_type:"MDM" mdm_type:MOBILEIRON>`
- **Corpus:** 192 shipped audits, 3116 control items
- **Benchmark families:** CIS (108), DISA STIG (84)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `FULL_PROFILE_INFO` | 2390 | `json_transform`, `regex`, `expect`, `match_all`, `severity`, `not_expect` |
| `CONFIGURATION_INFO` | 532 | `json_transform`, `regex`, `expect`, `match_all`, `severity` |
| `APP_INFO_BY_DEVICE` | 191 | `bw_list`, `json_transform`, `regex`, `expect`, `output_all_lines` |
| `DEVICE_INFO` | 3 | `json_transform`, `regex`, `expect`, `severity` |

### Example — `FULL_PROFILE_INFO`

From `AirWatch - CIS Apple iOS 10 v2.0.0 End User Owned L1`:

```
<custom_item>
  type           : FULL_PROFILE_INFO
  description    : "2.1.2 Ensure 'Controls when the profile can be removed' is set to 'Always'"
  info           : "This recommendation pertains to the removal of a given configuration profile.

  Rationale:

  In this section of the benchmark, recommendations are for devices that are owned by the end-user. They are voluntarily accepting the configuration profile and should be able to remove it at will."
  solution       : "1. Open Apple Configurator.
  2. Open the Configuration Profile.
  3. In the left windowpane, click on the 'General' tab.
  4. In the right windowpane, under the heading 'Security', set the menu 'Controls when the profile can be removed' to 'Always'.
  5. Deploy the Configuration Profile.

  Impact:

  None."
  reference      : "LEVEL|1A"
  see_also       : "https://workbench.cisecurity.org/files/1688"
  json_transform : '.[] | select((.type == "Apple") and (.General.IsActive == "true")) | "Policy: " + .General.Name + " - Allow Removal = \(.General.AllowRemoval // "not defined")"'
  regex          : "Allow Removal ="
  expect         : "Allow Removal = always"
  match_all      : YES
</custom_item>
```
