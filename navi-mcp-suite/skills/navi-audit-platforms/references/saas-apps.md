# SaaS and Application Platforms — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## Contents

- [Salesforce.com](#salesforcecom) — `<check_type:"Salesforce.com">`
- [Snowflake](#snowflake) — `<check_type:"Snowflake">`
- [Splunk](#splunk) — `<check_type:"Splunk">`
- [Zoom](#zoom) — `<check_type:"Zoom">`
- [IBM iSeries](#ibm-iseries) — `<check_type:"AS/400">`

## Salesforce.com

- **Opening tag:** `<check_type:"Salesforce.com">`
- **Corpus:** 1 shipped audits, 121 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 121 | `xsl_stmt`, `query`, `regex`, `expect`, `settings_name`, `not_expect`, `match_all`, `severity` |

### Example — `(untyped item)`

From `TNS Salesforce Best Practices Audit v1.2.0`:

```
<custom_item>
  description   : "Salesforce.com : Network-Based Security - 'Trusted IP Ranges exist'"
  xsl_stmt      : "<xsl:template match=\"/\" xmlns:sf=\"http://soap.sforce.com/2006/04/metadata\" >
  <xsl:choose>
  <xsl:when test=\"//sf:records/sf:networkAccess/sf:ipRanges\">
  <xsl:for-each select=\"//sf:records/sf:networkAccess/sf:ipRanges\">
  <xsl:text>Trusted IP Ranges = Start: </xsl:text><xsl:value-of select=\"sf:start\"/><xsl:text> End: </xsl:text><xsl:value-of select=\"sf:end\"/><xsl:text>&#10;</xsl:text>
  </xsl:for-each>
  </xsl:when>
  <xsl:otherwise>
  <xsl:text>Trusted IP Ranges = NONE FOUND</xsl:text><xsl:text>&#10;</xsl:text>
  </xsl:otherwise>
  </xsl:choose>
  </xsl:template>"
  regex         : "Trusted IP Ranges ="
  not_expect    : "Trusted IP Ranges = NONE FOUND$"
  settings_name : "SecuritySettings"
</custom_item>
```

## Snowflake

- **Opening tag:** `<check_type:"Snowflake">`
- **Corpus:** 2 shipped audits, 24 control items
- **Benchmark families:** CIS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 24 | `sql_types`, `sql_expect`, `sql_request`, `num_rows`, `severity`, `match_all` |

## Splunk

- **Opening tag:** `<check_type:"Splunk">`
- **Corpus:** 2 shipped audits, 18 control items
- **Benchmark families:** DISA STIG (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 18 | `request`, `json_transform`, `expect`, `not_expect` |

### Example — `REST_API`

From `DISA STIG Splunk Enterprise 7.x for Windows v3r2 REST API`:

```
<custom_item>
  type           : REST_API
  description    : "Splunk is installed and the correct version"
  request        : "SplunkGetServerInfo"
  json_transform : ".generator.version"
  expect         : "^@SPLUNK_VERSION@"
</custom_item>
```

## Zoom

- **Opening tag:** `<check_type:"Zoom">`
- **Corpus:** 2 shipped audits, 142 control items
- **Benchmark families:** CIS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 142 | `json_transform`, `request`, `expect`, `not_expect`, `severity` |

### Example — `REST_API`

From `CIS Zoom L1 v1.0.0`:

```
<custom_item>
  type           : REST_API
  description    : "1.1.1.1.1 Ensure minimum passcode length is set to at least 6 characters"
  info           : "For security purposes, Zoom has a few requirements that your passcode must meet. Minimum passcode length must be at least 6 characters.

  Rationale:

  This ensures the passcode complexity requirements are met and a strong passcode is set for meetings."
  solution       : "Go into the Zoom Admin Dashboard on the zoom website. Account Management -> Account Settings -> Security -> Passcode Requirement -> Have a minimum passcode length, and ensure it is set to enabled.

  Default Value:

  Unchecked"
  reference      : "800-171|3.4.2,800-53|CM-6,800-53r5|CM-6,CSCv7|5.1,CSF|PR.IP-1,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-6,LEVEL|1M,SWIFT-CSCv1|2.3"
  see_also       : "https://workbench.cisecurity.org/files/2986"
  request        : "getAccounts"
  json_transform : ".schedule_meeting | .meeting_password_requirement | .length"
  not_expect     : "0"
</custom_item>
```

## IBM iSeries

- **Opening tag:** `<check_type:"AS/400">`
- **Corpus:** 4 shipped audits, 181 control items
- **Benchmark families:** IBM (4)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `AUDIT_SYSTEMVAL` | 181 | `value_data`, `systemvalue`, `value_type`, `check_type` |

### Example — `AUDIT_SYSTEMVAL`

From `IBM iSeries Security Reference v5r4`:

```
<custom_item>
  type        : AUDIT_SYSTEMVAL
  description : "IBM i : System Security (QSECURITY) System Value - '40'"
  reference   : "800-171|3.4.2,800-53|CM-6b.,800-53r5|CM-6b.,CN-L3|8.1.10.6(d),CSCv6|3.1,CSF|PR.IP-1,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-6b.,NESA|T3.2.1,SWIFT-CSCv1|2.3"
  see_also    : "http://publib.boulder.ibm.com/infocenter/iseries/v5r4/topic/books/sc415302.pdf"
  value_type  : POLICY_DWORD
  value_data  : "40"
  systemvalue : "QSECURITY"
</custom_item>
```
