---
name: navi-audit-platforms
description: >
  Which compliance checks exist on each target system, and the exact wrapper tag
  that opens an audit file for it. Covers all 53 platforms Tenable ships audits
  for — Windows, Unix/Linux/macOS, seven database engines, 27 network and security
  device families, AWS/Azure/GCP/OpenStack/OpenShift, VMware and RHEV, Salesforce,
  Snowflake, Splunk, Zoom, IBM iSeries, and mobile device managers. Every tag,
  check type, and keyword here was extracted from shipped audit files, not from
  prose. Load this whenever authoring or editing an audit file, or when asked what
  can be checked on a specific system. Trigger on: "what check types does Windows
  support", "how do I check a registry value", "audit an Oracle setting", "Cisco
  IOS config check", "check an S3 bucket", "Azure compliance check", "which keyword
  sets file permissions on Unix", "what is the wrapper tag for", "audit a Palo Alto
  firewall", "can Nessus audit Salesforce". Pair with navi-audit-syntax for grammar.
---

# Audit Platforms — Check Types and Keywords by Target

Pick the platform, take its wrapper tag verbatim, then open the reference file
for its check types and keywords.

**Do not carry keywords across platforms.** A keyword valid on Windows will make
a Cisco file fail to load, and the failure is silent.

## Wrapper tags — all 53, confirmed

Every tag below was extracted from the audit files Tenable ships. Copy exactly,
including quoting and attributes.

### Operating systems → `references/windows.md`, `references/unix.md`

| Platform | Opening tag |
|---|---|
| Windows (config) | `<check_type:"Windows" version:"2">` |
| Windows (file contents) | `<check_type:"FileContent">` |
| Unix / Linux / macOS / Solaris / AIX / HP-UX | `<check_type:"Unix">` |
| Unix (file contents) | `<check_type:"FileContent">` |

Windows and Unix file-content audits share the **same** `FileContent` wrapper.
The platform difference is expressed inside the items, not in the tag.

### Databases → `references/database.md`

| Platform | Opening tag |
|---|---|
| Generic (DB2, MySQL, Oracle, PostgreSQL, SQLServer, Sybase) | `<check_type:"Database" db_type:"<engine>" version:"1">` |
| MS SQL | `<check_type:"MS_SQLDB">` |
| MySQL | `<check_type:"MySQLDB">` |
| Oracle | `<check_type:"OracleDB">` |
| PostgreSQL | `<check_type:"PostgreSQLDB">` |
| IBM DB2 | `<check_type:"IBM_DB2DB">` |
| Sybase | `<check_type:"SybaseDB">` |
| MongoDB | `<check_type:"MongoDB">` |

Both the generic `Database` wrapper and the engine-specific wrappers are in
active use. Match whichever the existing audits for that engine use.

### Network and security devices → `references/network-devices.md`

| Platform | Opening tag | Platform | Opening tag |
|---|---|---|---|
| Cisco IOS | `<check_type:"Cisco">` | Cisco ACI | `<check_type:"Cisco_ACI">` |
| Cisco Firepower | `<check_type:"Cisco_Firepower">` | Cisco Viptela | `<check_type:"Cisco_Viptela">` |
| Juniper Junos | `<check_type:"Juniper">` | Arista EOS | `<check_type:"Arista">` |
| ArubaOS | `<check_type:"ArubaOS">` | Adtran NetVanta | `<check_type:"Adtran">` |
| Alcatel TiMOS | `<check_type:"Alcatel">` | Brocade FabricOS | `<check_type:"Brocade">` |
| Check Point GAiA | `<check_type:"CheckPoint">` | Dell OS10 | `<check_type:"Dell_OS10">` |
| Extreme ExtremeXOS | `<check_type:"Extreme_ExtremeXOS">` | F5 | `<check_type:"F5">` |
| FireEye | `<check_type:"FireEye">` | FortiGate FortiOS | `<check_type:"FortiGate">` |
| HP ProCurve | `<check_type:"HPProCurve">` | Huawei VRP | `<check_type:"Huawei">` |
| NetApp Data ONTAP | `<check_type:"NetApp">` | NetApp API | `<check_type:"Netapp_API">` |
| SonicWALL SonicOS | `<check_type:"SonicWALL">` | WatchGuard | `<check_type:"WatchGuard">` |
| ZTE JINOS | `<check_type:"ZTE_JINOS">` | ZTE ROSNG | `<check_type:"ZTE_ROSNG">` |
| BlueCoat ProxySG | `<check_type:"BlueCoat">` | Palo Alto PAN-OS | `<check_type:"Palo_Alto">` |
| Citrix Application Delivery | `<check_type:"Citrix_Application_Delivery">` | | |

### Cloud → `references/cloud.md`

| Platform | Opening tag |
|---|---|
| Amazon AWS | `<check_type:"amazon_aws">` |
| Microsoft Azure | `<check_type:"microsoft_azure">` |
| Google Cloud Platform | `<check_type:"GCP">` |
| OpenStack | `<check_type:"OpenStack">` |
| OpenShift Container Platform | `<check_type:"OpenShift">` |
| Rackspace | `<check_type:"Rackspace">` |

Note the lowercase-with-underscores form on AWS and Azure. It is inconsistent
with the rest of the platform set and is a frequent source of load failures.

### Virtual infrastructure → `references/virtualization.md`

| Platform | Opening tag |
|---|---|
| VMware vCenter / vSphere | `<check_type:"VMware">` |
| RHEV | `<check_type:"RHEV">` |

### SaaS and applications → `references/saas-apps.md`

| Platform | Opening tag |
|---|---|
| Salesforce.com | `<check_type:"Salesforce.com">` |
| Snowflake | `<check_type:"Snowflake">` |
| Splunk | `<check_type:"Splunk">` |
| Zoom | `<check_type:"Zoom">` |
| IBM iSeries | `<check_type:"AS/400">` |

### Mobile device management → `references/mdm.md`

| Platform | Opening tag |
|---|---|
| AirWatch | `<check_type:"MDM" mdm_type:AIRWATCH>` |
| MobileIron | `<check_type:"MDM" mdm_type:MOBILEIRON>` |

`mdm_type` is unquoted. This is the only wrapper in the set with an unquoted
attribute value.

## Coverage at a glance

The corpus behind these references: 1,737 current audits, 187,165 control items.

| Platform | Audits | Items | Dominant check types |
|---|---|---|---|
| Unix | 646 | 108,701 | CMD_EXEC, FILE_CONTENT_CHECK, FILE_CHECK, RPM_CHECK |
| Windows | 430 | 49,555 | REGISTRY_SETTING, USER_RIGHTS_POLICY, AUDIT_POLICY_SUBCATEGORY |
| Mobile Device Manager | 192 | 3,116 | FULL_PROFILE_INFO, CONFIGURATION_INFO |
| Cisco IOS | 65 | 4,719 | CONFIG_CHECK, CONFIG_CHECK_NOT, BANNER_CHECK |
| VMware | 42 | 1,346 | AUDIT_ESX, AUDIT_VCENTER |
| MySQL / MS SQL / Oracle / PostgreSQL / DB2 | 120 | 7,776 | SQL_POLICY |
| Palo Alto PAN-OS | 15 | 1,093 | AUDIT_XML |
| Juniper Junos | 12 | 1,092 | CONFIG_CHECK, SHOW_CONFIG_CHECK |
| Microsoft Azure | 16 | 798 | POLICY, AZURE_REPORT |
| All others | 199 | ~9,000 | see reference files |

Thin coverage is a real signal. A platform with one shipped audit and 20 items
has a narrow supported check surface — say so rather than implying full parity
with Windows or Unix.

## Reference files

| File | Platforms |
|---|---|
| `references/windows.md` | Windows, Windows File Contents |
| `references/unix.md` | Unix, Unix File Contents |
| `references/database.md` | 8 database engines |
| `references/network-devices.md` | 27 network and security platforms |
| `references/cloud.md` | AWS, Azure, GCP, OpenStack, OpenShift, Rackspace |
| `references/virtualization.md` | VMware, RHEV |
| `references/saas-apps.md` | Salesforce, Snowflake, Splunk, Zoom, IBM iSeries |
| `references/mdm.md` | AirWatch, MobileIron |

Each file lists, per platform, every check type with its item count and the
keywords that appear with it, plus a real example lifted from a shipped audit.
