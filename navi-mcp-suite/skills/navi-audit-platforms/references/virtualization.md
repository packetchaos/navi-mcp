# Virtual Infrastructure — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## VMware vCenter/vSphere

- **Opening tag:** `<check_type:"VMware">`
- **Corpus:** 42 shipped audits, 1346 control items
- **Benchmark families:** CIS (20), DISA STIG (18), VMWare (4)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `AUDIT_ESX` | 656 | `xsl_stmt`, `regex`, `expect`, `not_expect`, `severity` |
| `AUDIT_VM` | 629 | `xsl_stmt`, `regex`, `expect`, `not_expect`, `severity` |
| `AUDIT_VCENTER` | 60 | `xsl_stmt`, `regex`, `expect`, `not_expect` |
| `(untyped item)` | 1 | — |

### Example — `AUDIT_ESX`

From `CIS VMware vSphere 8.0 ESXi STIG v1.0.0 CAT II VMware`:

```
<custom_item>
  type        : AUDIT_ESX
  description : "check if ptpd is running"
  xsl_stmt    : "<xsl:template match=\"/\">"
  xsl_stmt    : "<xsl:for-each select=\"//audit:returnval\">"
  xsl_stmt    : "<xsl:value-of select=\"audit:propSet[audit:name='name']/audit:val\"/><xsl:text> - PTPd running: </xsl:text> <xsl:value-of select=\"audit:propSet/audit:val/audit:service/audit:service[audit:key='ptpd']/audit:running\" />"
  xsl_stmt    : "</xsl:for-each>"
  xsl_stmt    : "</xsl:template>"
  regex       : "PTPd running: "
  expect      : "PTPd running: true$"
</custom_item>
```

## RHEV

- **Opening tag:** `<check_type:"RHEV">`
- **Corpus:** 1 shipped audits, 20 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 20 | `json_transform`, `request`, `expect`, `severity`, `match_all`, `not_expect` |

### Example — `REST_API`

From `Tenable RedHat Enterprise Virtualization`:

```
<custom_item>
  type           : REST_API
  description    : "RHEV: Product Info"
  info           : "Review product information to verify the version in operation is still supported by the vendor.

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  see_also       : "https://access.redhat.com/documentation/en-us/red_hat_virtualization/4.3/html/rest_api_guide/index"
  request        : "getAPI"
  json_transform : "\"Name : \(.product_info.name)\", \"Version: \(.product_info.version.full_version)\""
  expect         : "Manual Review Required"
  severity       : MEDIUM
</custom_item>
```
