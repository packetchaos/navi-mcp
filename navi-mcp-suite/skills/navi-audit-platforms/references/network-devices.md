# Network and Security Devices — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## Contents

- [Cisco IOS](#cisco-ios) — `<check_type:"Cisco">`
- [Cisco ACI](#cisco-aci) — `<check_type:"Cisco_ACI">`
- [Cisco Firepower](#cisco-firepower) — `<check_type:"Cisco_Firepower">`
- [Cisco Viptela](#cisco-viptela) — `<check_type:"Cisco_Viptela">`
- [Juniper Junos](#juniper-junos) — `<check_type:"Juniper">`
- [Arista EOS](#arista-eos) — `<check_type:"Arista">`
- [ArubaOS](#arubaos) — `<check_type:"ArubaOS">`
- [Adtran NetVanta](#adtran-netvanta) — `<check_type:"Adtran">`
- [Alcatel TiMOS](#alcatel-timos) — `<check_type:"Alcatel">`
- [Brocade FabricOS](#brocade-fabricos) — `<check_type:"Brocade">`
- [Check Point GAiA](#check-point-gaia) — `<check_type:"CheckPoint">`
- [Dell OS10](#dell-os10) — `<check_type:"Dell_OS10">`
- [Extreme ExtremeXOS](#extreme-extremexos) — `<check_type:"Extreme_ExtremeXOS">`
- [F5](#f5) — `<check_type:"F5">`
- [FireEye](#fireeye) — `<check_type:"FireEye">`
- [FortiGate FortiOS](#fortigate-fortios) — `<check_type:"FortiGate">`
- [HP ProCurve](#hp-procurve) — `<check_type:"HPProCurve">`
- [Huawei VRP](#huawei-vrp) — `<check_type:"Huawei">`
- [NetApp Data ONTAP](#netapp-data-ontap) — `<check_type:"NetApp">`
- [Netapp API](#netapp-api) — `<check_type:"Netapp_API">`
- [SonicWALL SonicOS](#sonicwall-sonicos) — `<check_type:"SonicWALL">`
- [WatchGuard](#watchguard) — `<check_type:"WatchGuard">`
- [ZTE JINOS](#zte-jinos) — `<check_type:"ZTE_JINOS">`
- [ZTE ROSNG](#zte-rosng) — `<check_type:"ZTE_ROSNG">`
- [BlueCoat ProxySG](#bluecoat-proxysg) — `<check_type:"BlueCoat">`
- [Citrix Application Delivery](#citrix-application-delivery) — `<check_type:"Citrix_Application_Delivery">`
- [Palo Alto Networks PAN-OS](#palo-alto-networks-pan-os) — `<check_type:"Palo_Alto">`

## Cisco IOS

- **Opening tag:** `<check_type:"Cisco">`
- **Corpus:** 65 shipped audits, 4719 control items
- **Benchmark families:** CIS (46), DISA STIG (18), TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 4257 | `item`, `context`, `severity`, `regex`, `min_occurrences`, `cmd`, `required`, `max_occurrences` |
| `CONFIG_CHECK_NOT` | 425 | `item`, `context`, `severity`, `regex`, `cmd` |
| `BANNER_CHECK` | 37 | `item`, `content` |

### Example — `CONFIG_CHECK`

From `CIS Cisco ASA 9.x Firewall L1 v1.1.0`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "lifetime"
  item        : "password-policy lifetime ([1-9]|[1-8][0-9]|9[0-9]|1[0-7][0-9]|180)"
</custom_item>
```

## Cisco ACI

- **Opening tag:** `<check_type:"Cisco_ACI">`
- **Corpus:** 1 shipped audits, 52 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 34 | `item`, `context`, `severity` |
| `CONFIG_CHECK_NOT` | 18 | `item`, `context`, `regex` |

### Example — `CONFIG_CHECK`

From `Tenable Cisco ACI`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "System Alias and Banners - Controller CLI Banner"
  info        : "The contents of the CLI informational banner to be displayed before user login authentication. The CLI banner is a text based string printed as-is to the console."
  solution    : "Log into the Cisco APIC Web Console:
  Navigate to 'System' -> 'System Settings'.

  Expand 'System Alias and Banners'.

  Set 'Controller CLI Banner' to an appropriate value for your environment."
  reference   : "800-171|3.1.9,800-53|AC-8a.,800-53r5|AC-8a.,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|AC-8a.,NESA|M5.2.5,NESA|T5.5.1,NIAv2|AM10a,NIAv2|AM10b,NIAv2|AM10c,NIAv2|AM10d,NIAv2|AM10e,TBA-FIISB|45.2.4"
  item        : "^[\s]*aaa[\s]+banner[\s]+['\"]@BANNER_TEXT_CONTROLLER@['\"]"
</custom_item>
```

## Cisco Firepower

- **Opening tag:** `<check_type:"Cisco_Firepower">`
- **Corpus:** 1 shipped audits, 59 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 36 | `item`, `regex`, `severity` |
| `CONFIG_CHECK_NOT` | 12 | `item`, `regex`, `severity` |
| `CMD_EXEC` | 11 | `cmd`, `regex`, `expect`, `not_expect`, `severity` |

### Example — `CONFIG_CHECK`

From `Tenable Cisco Firepower Threat Defense Best Practices Audit`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "Ensure 'Password Policy' is enabled - minimum-length"
  info        : "Enforces the Enterprise Password Policy by setting compliant local password requirements for the security appliance

  Rationale:

  The password policy helps to prevent unauthorized accesses by enforcing the password for more complexity and making them difficult to be guessed."
  solution    : "Run the following to set the password minimum length to your organization's security policy

  >configure user minpasswdlen"
  reference   : "800-171|3.5.7,800-53|IA-5(1)(a),800-53r5|IA-5(1)(a),CN-L3|7.1.2.7(e),CN-L3|7.1.3.1(b),CSF|PR.AC-1,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(2)(i),HIPAA|164.312(d),ISO/IEC-27001|A.9.4.3,ITSG-33|IA-5(1)(a),NESA|T5.2.3,NIAv2|AM19a,NIAv2|AM19b,NIAv2|AM19c,NIAv2|AM19d,NIAv2|AM22a,QCSC-v1|5.2.2,QCSC-v1|13.2,SWIFT-CSCv1|4.1,TBA-FIISB|26.2.1,TBA-FIISB|26.2.4"
  see_also    : "https://www.cisco.com/c/en/us/td/docs/security/firepower/640/hardening/ftd/FTD_Hardening_Guide_v64.html"
  regex       : "^\s*password-policy"
  item        : "^\s*password-policy\s+minimum-length\s+@MINIMUM_LENGTH@"
</custom_item>
```

## Cisco Viptela

- **Opening tag:** `<check_type:"Cisco_Viptela">`
- **Corpus:** 4 shipped audits, 106 control items
- **Benchmark families:** TNS (4)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 82 | `context`, `item`, `required`, `severity`, `min_occurrences`, `regex` |
| `CONFIG_CHECK_NOT` | 12 | `context`, `item` |
| `BANNER_CHECK` | 8 | `item`, `content` |
| `CMD_EXEC` | 4 | `severity`, `cmd`, `regex`, `expect` |

### Example — `CONFIG_CHECK`

From `Tenable Cisco Viptela SD-WAN - vBond`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "Account Management - Review disabled user accounts"
  info        : "Information system account types include, for example, individual, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  solution    : "Conditions for disabling or deactivating accounts include, for example: (i) when shared/group, emergency, or temporary accounts are no longer required; or (ii) when individuals are transferred or terminated. Some types of information system accounts may require specialized training."
  reference   : "800-171|3.1.1,800-53|AC-2,800-53r5|AC-2,CN-L3|7.1.3.2(d),CSF|DE.CM-1,CSF|DE.CM-3,CSF|PR.AC-1,CSF|PR.AC-4,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(1),ISO/IEC-27001|A.9.2.1,ITSG-33|AC-2,NIAv2|AM28,NIAv2|NS5j,NIAv2|SS14e,QCSC-v1|5.2.2,QCSC-v1|8.2.1,QCSC-v1|13.2,QCSC-v1|15.2"
  context     : "^\s*system"
  context     : "^\s*aaa"
  context     : "^\s*user\s+"
  item        : "^\s*status\s+disabled"
  severity    : MEDIUM
</custom_item>
```

## Juniper Junos

- **Opening tag:** `<check_type:"Juniper">`
- **Corpus:** 12 shipped audits, 1092 control items
- **Benchmark families:** DISA STIG (9), CIS (2), Juniper (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 1082 | `regex`, `expect`, `severity`, `not_expect`, `number_of_lines`, `match_all`, `check_option`, `min_occurrences`, `cmd`, `required`, `max_occurrences` |
| `BANNER_CHECK` | 5 | `content`, `regex` |
| `SHOW_CONFIG_CHECK` | 5 | `property`, `match`, `hierarchy`, `severity`, `number_of_lines` |

### Example — `CONFIG_CHECK`

From `CIS Juniper OS Benchmark v2.1.0 L1`:

```
<custom_item>
  type            : CONFIG_CHECK
  description     : "Check for dialer interfaces"
  regex           : "set interfaces dl[0-9]"
  number_of_lines : "^([1-9]|[1-9][0-9]+)$"
</custom_item>
```

## Arista EOS

- **Opening tag:** `<check_type:"Arista">`
- **Corpus:** 9 shipped audits, 603 control items
- **Benchmark families:** DISA STIG (9)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 601 | `expect`, `regex`, `context`, `severity`, `min_occurrences`, `cmd`, `not_expect`, `required`, `max_occurrences` |
| `BANNER_CHECK` | 2 | `item`, `content` |

### Example — `(untyped item)`

From `DISA Arista MLS EOS 4.X L2S STIG v2r3`:

```
<custom_item>
  description : "dot1x informational"
  regex       : "^[\s]*logging level"
  expect      : "^[\s]*logging level DOT1X informational"
</custom_item>
```

## ArubaOS

- **Opening tag:** `<check_type:"ArubaOS">`
- **Corpus:** 8 shipped audits, 407 control items
- **Benchmark families:** CIS (3), DISA STIG (3), TNS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 320 | `item`, `regex`, `context`, `severity`, `match_all`, `min_occurrences` |
| `CMD_EXEC` | 61 | `cmd`, `expect`, `regex`, `severity`, `not_expect`, `match_all` |
| `CONFIG_CHECK_NOT` | 16 | `item`, `regex`, `match_case` |
| `BANNER_CHECK` | 10 | `item`, `content`, `is_substring` |

### Example — `CONFIG_CHECK`

From `ArubaOS CX 10.x Hardening Guide v1.0.0`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "Access control lists"
  info        : "IP Access Control Lists (ACLs) can also be used to limit management access, permitting more granular control over IP ranges or protocols permitted to access the switch.

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  solution    : "Note that all ACLs in ArubaOS-Switch have an implicit \"deny any\" rule at the end of the rules list; this requires that allowed traffic be explicitly permitted to pass through an applied ACL."
  see_also    : "https://support.hpe.com/hpesc/public/docDisplay?docId=a00053695en_us"
  context     : "ip access-list"
  regex       : ".*"
  item        : "Manual Review Required"
  severity    : MEDIUM
  reference   : "800-171|3.13.1,800-53|SC-7(11),800-53r5|SC-7(11),CN-L3|8.1.10.6(j),CSF|PR.AC-5,CSF|PR.PT-4,GDPR|32.1.b,HIPAA|164.306(a)(1),ISO/IEC-27001|A.13.1.3,ITSG-33|SC-7(11),NESA|T4.5.4,NIAv2|GS7c,PCI-DSSv3.2.1|1.3.1,PCI-DSSv3.2.1|1.3.2,PCI-DSSv3.2.1|1.3.3,PCI-DSSv3.2.1|1.3.5,PCI-DSSv4.0|1.3.1,PCI-DSSv4.0|1.4.2,PCI-DSSv4.0|1.4.3,QCSC-v1|5.2.1,QCSC-v1|5.2.2,QCSC-v1|6.2,QCSC-v1|8.2.1,TBA-FIISB|31.3"
</custom_item>
```

## Adtran NetVanta

- **Opening tag:** `<check_type:"Adtran">`
- **Corpus:** 1 shipped audits, 42 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 42 | `expect`, `not_expect`, `cmd`, `severity`, `context`, `regex` |

### Example — `(untyped item)`

From `TNS Adtran AOS Best Practice Audit`:

```
<custom_item>
  description : "Adtran : Device Info"
  info        : "Review the output of this check for Asset Inventory purposes

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  reference   : "800-171|3.4.1,800-53|CM-8a.,800-53r5|CM-8a.,CN-L3|8.1.10.2(a),CN-L3|8.1.10.2(b),SANS-CSC|1,CSF|DE.CM-7,CSF|ID.AM-1,CSF|ID.AM-2,CSF|PR.DS-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ISO/IEC-27001|A.8.1.1,ITSG-33|CM-8,NESA|T1.2.1,NESA|T1.2.2,NIAv2|NS35,PCI-DSS|2.4,QCSC-v1|3.2,QCSC-v1|5.2.2,QCSC-v1|5.2.3,QCSC-v1|6.2,QCSC-v1|8.2.1"
  cmd         : "show version"
  expect      : "MANUAL_REVIEW"
  severity    : MEDIUM
</custom_item>
```

## Alcatel TiMOS

- **Opening tag:** `<check_type:"Alcatel">`
- **Corpus:** 1 shipped audits, 77 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 77 | `expect`, `regex`, `cmd`, `severity`, `not_expect` |

### Example — `(untyped item)`

From `TNS Alcatel-Lucent TiMOS/Nokia SR-OS Best Practice Audit`:

```
<custom_item>
  description : "TiMOS/SR-OS : OS Version is up to date"
  info        : "Regular OS and firmware updates are an important tool in mitigating security vulnerabilities.

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  solution    : "Make sure that your device is running the most recent version of TiMOS/SR-OS."
  reference   : "800-171|3.4.1,800-53|CM-8a.,800-53r5|CM-8a.,CN-L3|8.1.10.2(a),CN-L3|8.1.10.2(b),CSF|DE.CM-7,CSF|ID.AM-1,CSF|ID.AM-2,CSF|PR.DS-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ISO/IEC-27001|A.8.1.1,ITSG-33|CM-8,NESA|T1.2.1,NESA|T1.2.2,NIAv2|NS35,QCSC-v1|3.2,QCSC-v1|5.2.2,QCSC-v1|5.2.3,QCSC-v1|6.2,QCSC-v1|8.2.1"
  see_also    : "https://infoproducts.alcatel-lucent.com/aces/cgi-bin/dbaccessfilename.cgi/9305050101_V1_SR-OS Security Best Practices v2.0.pdf"
  cmd         : "show version"
  regex       : ""
  expect      : "Manual review required"
  severity    : MEDIUM
</custom_item>
```

## Brocade FabricOS

- **Opening tag:** `<check_type:"Brocade">`
- **Corpus:** 1 shipped audits, 63 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 61 | `regex`, `expect`, `cmd`, `context`, `required`, `min_occurrences`, `severity`, `not_expect` |
| `BANNER_CHECK` | 2 | `item`, `content` |

### Example — `CONFIG_CHECK`

From `Tenable Best Practices Brocade FabricOS`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "Brocade - Disable Telnet IPv4"
  info        : "Telnet is enabled by default.

  To prevent passing clear text passwords over the network when connecting to the switch, you can block the Telnet protocol using an IP Filter policy"
  solution    : "The command to disable Telnet is as follows

  switch:admin> ipfilter --addrule policy_name -rule rule_number -sip any -dp 23 -proto

  tcp -act deny"
  reference   : "800-171|3.4.6,800-171|3.4.7,800-53|CM-7b.,800-53r5|CM-7b.,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CN-L3|8.1.4.4(b),CSF|PR.IP-1,CSF|PR.PT-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-7a.,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,PCI-DSSv3.2.1|2.2.2,PCI-DSSv4.0|2.2.4,QCSC-v1|3.2,SWIFT-CSCv1|2.3"
  see_also    : "https://docs.broadcom.com/docs/12380061"
  cmd         : "ipfilter --show"
  context     : "ipv4.+active"
  regex       : "tcp[\s]+23"
  expect      : "deny"
</custom_item>
```

## Check Point GAiA

- **Opening tag:** `<check_type:"CheckPoint">`
- **Corpus:** 2 shipped audits, 51 control items
- **Benchmark families:** CIS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 51 | `regex`, `expect`, `severity`, `not_expect` |

### Example — `CONFIG_CHECK`

From `CIS Check Point Firewall L1 v1.1.0`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "2.1.3 Ensure Core Dump is enabled"
  info        : "A Core Dump contains the recorded state of the working memory and CPU's contents of the Gaia system at the time that a Gaia process terminated abnormally. The core file is stored in the /var/log/dump/usermode directory.

  Rationale:

  The Core Dump helps in troubleshooting to identify for which reason the process/system got crashed."
  solution    : "Run the following command to set Core Dump.

  Hostname> set core-dump enable

  GUI:

  Navigate to System Management > Core Dump > select Enable Core Dumps

  Default Value:

  enabled"
  reference   : "800-53|SC-24,800-53r5|SC-24,CSF2.0|PR.DS-10,CSF2.0|PR.IR-03,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|SC-24,ITSG-33|SC-24a.,QCSC-v1|5.2.1"
  see_also    : "https://workbench.cisecurity.org/files/2828"
  regex       : "set core-dump enable"
  expect      : "set core-dump enable"
</custom_item>
```

## Dell OS10

- **Opening tag:** `<check_type:"Dell_OS10">`
- **Corpus:** 3 shipped audits, 209 control items
- **Benchmark families:** DISA STIG (3)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 161 | `item`, `regex`, `context`, `severity`, `min_occurrences`, `max_occurrences`, `match_all` |
| `CONFIG_CHECK_NOT` | 25 | `item`, `context`, `regex`, `severity` |
| `CMD_EXEC` | 22 | `cmd`, `expect`, `regex`, `severity`, `not_expect` |
| `BANNER_CHECK` | 1 | `item`, `content` |

### Example — `CONFIG_CHECK`

From `DISA Dell OS10 Switch Layer 2 Switch STIG v1r1`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "802.1X Global System Authentication Control Enabled"
  item        : "^\s*dot1x\s+system-auth-control"
</custom_item>
```

## Extreme ExtremeXOS

- **Opening tag:** `<check_type:"Extreme_ExtremeXOS">`
- **Corpus:** 1 shipped audits, 21 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 21 | `expect`, `cmd`, `not_expect`, `regex` |

### Example — `(untyped item)`

From `TNS Extreme ExtremeXOS Best Practice Audit`:

```
<custom_item>
  description : "Extreme : Device Info"
  info        : "Review the output of this check for Asset Inventory purposes"
  reference   : "800-171|3.4.1,800-53|CM-8a.,800-53r5|CM-8a.,CN-L3|8.1.10.2(a),CN-L3|8.1.10.2(b),SANS-CSC|1,CSF|DE.CM-7,CSF|ID.AM-1,CSF|ID.AM-2,CSF|PR.DS-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ISO/IEC-27001|A.8.1.1,ITSG-33|CM-8,NESA|T1.2.1,NESA|T1.2.2,NIAv2|NS35,PCI-DSS|2.4,QCSC-v1|3.2,QCSC-v1|5.2.2,QCSC-v1|5.2.3,QCSC-v1|6.2,QCSC-v1|8.2.1"
  cmd         : "show version"
</custom_item>
```

## F5

- **Opening tag:** `<check_type:"F5">`
- **Corpus:** 13 shipped audits, 425 control items
- **Benchmark families:** DISA STIG (10), CIS (2), TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 314 | `json_transform`, `f5_command`, `expect`, `regex`, `severity`, `match_all`, `not_expect` |
| `OFFLINE_CONFIG_CHECK` | 108 | `context`, `regex`, `expect`, `severity`, `match_all`, `not_expect` |
| `OFFLINE_BANNER_CHECK` | 3 | `context`, `item`, `content` |

### Example — `(untyped item)`

From `CIS F5 Networks v1.0.0 L1`:

```
<custom_item>
  description    : "Check REST API for required special"
  f5_command     : "/tm/auth/password-policy"
  json_transform : ".requiredSpecial"
  expect         : "\b@REQUIRED_SPECIAL@\b"
</custom_item>
```

## FireEye

- **Opening tag:** `<check_type:"FireEye">`
- **Corpus:** 1 shipped audits, 75 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 72 | `regex`, `expect`, `cmd`, `severity`, `required`, `not_expect` |
| `RANDOMNESS_CHECK` | 3 | `required`, `regex` |

### Example — `CONFIG_CHECK`

From `TNS FireEye`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "FireEye - Configuration auditing logs the required number of changes"
  info        : "Saving past configurations allows them to be audited for unauthorized changes and reviewed when troubleshooting. Auditing cannot be disabled but can be set to 1, significantly reducing effectiveness. Configuration changes can be exported through the Log Manager."
  solution    : "The default value is 1000. Edit the configuration and add or modify this line:\n

  configuration audit max-changes 1000"
  reference   : "800-171|3.4.3,800-53|CM-3e.,800-53r5|CM-3e.,CN-L3|8.1.10.6(g),SANS-CSC|3,CSF|DE.CM-1,CSF|DE.CM-7,CSF|PR.IP-1,CSF|PR.IP-3,GDPR|32.1.b,GDPR|32.4,HIPAA|164.306(a)(1),ISO/IEC-27001|A.12.1.2,ITSG-33|CM-3e.,NESA|T7.6.1,NIAv2|CM5,PCI-DSS|6.4,QCSC-v1|3.2,QCSC-v1|5.2.1,QCSC-v1|6.2,QCSC-v1|7.2,QCSC-v1|8.2.1"
  regex       : "configuration audit max-changes.+"
  expect      : "configuration audit max-changes @CONFIG_CHANGES_AUDITED@"
</custom_item>
```

## FortiGate FortiOS

- **Opening tag:** `<check_type:"FortiGate">`
- **Corpus:** 8 shipped audits, 396 control items
- **Benchmark families:** CIS (4), DISA STIG (2), TNS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 392 | `context`, `expect`, `regex`, `severity`, `not_expect`, `cmd` |
| `BANNER_CHECK` | 4 | `context`, `item`, `content` |

### Example — `(untyped item)`

From `CIS FortiGate 7.4.x v1.0.1 L1`:

```
<custom_item>
  description : "dns server 1"
  context     : "config system dns$"
  regex       : "set[\s]+primary[\s]+"
  expect      : "set[\s]+primary[\s]+@DNS_SERVER_1@"
</custom_item>
```

## HP ProCurve

- **Opening tag:** `<check_type:"HPProCurve">`
- **Corpus:** 1 shipped audits, 19 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 18 | `item` |
| `CONFIG_CHECK_NOT` | 1 | `item` |

### Example — `CONFIG_CHECK`

From `TNS HP ProCurve`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "HP ProCurve - 'Disable Telnet'"
  info        : "It is recommended that you use Secure Shell (SSH) instead of Telnet.

  Telnet is insecure by nature as it sends all traffic across the wire in clear text."
  solution    : "The command to disable Telnet is as follows\n

  ProCurve Switch(config)# no telnet-server\n"
  reference   : "800-171|3.4.6,800-171|3.4.7,800-53|CM-7b.,800-53r5|CM-7b.,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CN-L3|8.1.4.4(b),CSF|PR.IP-1,CSF|PR.PT-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-7a.,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,PCI-DSSv3.2.1|2.2.2,PCI-DSSv4.0|2.2.4,QCSC-v1|3.2,SWIFT-CSCv1|2.3"
  see_also    : "http://www.hp.com/rnd/pdfs/Hardening_ProCurve_Switches_White_Paper.pdf"
  item        : "no telnet-server"
</custom_item>
```

## Huawei VRP

- **Opening tag:** `<check_type:"Huawei">`
- **Corpus:** 1 shipped audits, 42 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 42 | `expect`, `not_expect`, `regex`, `context`, `severity`, `cmd` |

### Example — `(untyped item)`

From `TNS Huawei VRP Best Practice Audit`:

```
<custom_item>
  description : "Huawei: Review Device Info/Version"
  info        : "Review the output of this check for Asset Inventory purposes

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  reference   : "800-171|3.4.1,800-171r3|03.04.10a.,800-53|CM-8a.,800-53r5|CM-8a.,CN-L3|8.1.10.2(a),CN-L3|8.1.10.2(b),SANS-CSC|1-4,CSF|DE.CM-7,CSF|ID.AM-1,CSF|ID.AM-2,CSF|PR.DS-3,CSF2.0|ID.AM-01,CSF2.0|ID.AM-02,CSF2.0|PR.PS-01,GDPR|32.1.b,HIPAA|164.306(a)(1),ISO-27001-2022|A.5.9,ISO-27001-2022|A.8.9,ISO/IEC-27001|A.8.1.1,ITSG-33|CM-8,NESA|T1.2.1,NESA|T1.2.2,NIAv2|NS35,PCI-DSS|2.4,QCSC-v1|3.2,QCSC-v1|5.2.2,QCSC-v1|5.2.3,QCSC-v1|6.2,QCSC-v1|8.2.1"
  cmd         : "display version"
  not_expect  : ".+"
  severity    : MEDIUM
</custom_item>
```

## NetApp Data ONTAP

- **Opening tag:** `<check_type:"NetApp">`
- **Corpus:** 1 shipped audits, 144 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 144 | `regex`, `expect`, `check_option`, `not_expect` |

### Example — `CONFIG_CHECK`

From `TNS NetApp Data ONTAP 7G`:

```
<custom_item>
  type         : CONFIG_CHECK
  description  : "2.0 Install & Config - 'Disable FTP'"
  info         : "There are several services that should be considered for disabling. Depending on your enterprise security structure, the state of any service depends on where the service is deployed and how deep it is in your infrastructure."
  solution     : "Disable the File Transfer Protocol (FTP) service"
  reference    : "800-171|3.4.6,800-171|3.4.7,800-53|CM-7b.,800-53r5|CM-7b.,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CN-L3|8.1.4.4(b),SANS-CSC|3,CSCv6|9.1,CSF|PR.IP-1,CSF|PR.PT-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-7a.,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,PCI-DSS|1.1.5,PCI-DSS|2.2.2,PCI-DSSv3.2.1|2.2.2,PCI-DSSv4.0|2.2.4,QCSC-v1|3.2,SWIFT-CSCv1|2.3"
  see_also     : "http://media.netapp.com/documents/tr-3649.pdf"
  regex        : "ftpd.enable[\s\t]+"
  expect       : "ftpd.enable[\s\t]+off"
  check_option : CAN_BE_NULL
</custom_item>
```

## Netapp API

- **Opening tag:** `<check_type:"Netapp_API">`
- **Corpus:** 1 shipped audits, 56 control items
- **Benchmark families:** NetApp (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `AUDIT_XML` | 56 | `xsl_stmt`, `request`, `expect`, `not_expect`, `severity`, `regex` |

### Example — `AUDIT_XML`

From `NetApp Security Hardening Guide for ONTAP 9 v1.7.0`:

```
<custom_item>
  type        : AUDIT_XML
  description : "3.1 - Roles, Applications, and Authentication - Use of secure applications"
  info        : "For security reasons, Telnet and Remote Shell (RSH) are disabled by default because NetApp recommends Secure Shell (SSH) for secure remote access. If there is a requirement or a unique need to use Telnet or RSH, they must be enabled."
  solution    : "The security protocol modify command modifies the existing clusterwide configuration of RSH and Telnet. You can disable RSH and Telnet in the cluster by setting the enabled field to false."
  see_also    : "https://www.netapp.com/us/media/tr-4569.pdf"
  request     : '<security-login-get-iter></security-login-get-iter>'
  xsl_stmt    : '<xsl:template match="/">
  <xsl:text>Administrative Application Methods&#xa;</xsl:text>
  <xsl:text>==================================&#xa;</xsl:text>
  <xsl:for-each select="//security-login-account-info">
  <xsl:value-of select="vserver" /><xsl:text> - </xsl:text>
  <xsl:value-of select="user-name" /><xsl:text> - </xsl:text>
  <xsl:value-of select="application" /><xsl:text>&#xa;</xsl:text>
  </xsl:for-each>
  </xsl:template>'
  not_expect  : "(rsh|telnet)"
</custom_item>
```

## SonicWALL SonicOS

- **Opening tag:** `<check_type:"SonicWALL">`
- **Corpus:** 1 shipped audits, 102 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 102 | `context`, `expect`, `regex`, `not_expect`, `cmd`, `severity` |

### Example — `(untyped item)`

From `TNS SonicWALL v5.9`:

```
<custom_item>
  description : "SonicWALL - Review the NTP server configuration"
  info        : "Ensuring that approved NTP servers are used allows for accurate log/audit file correlation."
  solution    : "To add an NTP server to the SonicWALL security appliance configuration:
  Step 1 - Click Add. The Add NTP Server window is displayed.
  Step 2 - Type the IP address of an NTP server in the NTP Server field.
  Step 3 - Click OK.
  Step 4 - Click Accept on the System > Time page to update the SonicWALL security appliance."
  reference   : "800-171|3.3.7,800-53|AU-8(1),800-53r5|SC-45(1),CN-L3|8.1.4.3(b),CSCv6|6.1,SANS-CSC|14,CSF|PR.PT-1,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(b),ISO/IEC-27001|A.12.4.4,ITSG-33|AU-8(1),NESA|T3.6.7,NIAv2|NS44,NIAv2|NS45,NIAv2|NS46,NIAv2|NS47,PCI-DSS|10.4.1,PCI-DSSv3.2.1|10.4,PCI-DSSv3.2.1|10.4.1,PCI-DSSv3.2.1|10.4.3,PCI-DSSv4.0|10.6,PCI-DSSv4.0|10.6.1,PCI-DSSv4.0|10.6.2,PCI-DSSv4.0|10.6.3,QCSC-v1|8.2.1,QCSC-v1|13.2,TBA-FIISB|37.4"
  context     : "time"
  regex       : "^[\s]*ntp-server[\s]*"
  expect      : "^[\s]*ntp-server[\s]+@NTP_SERVER@[\s]*$"
</custom_item>
```

## WatchGuard

- **Opening tag:** `<check_type:"WatchGuard">`
- **Corpus:** 1 shipped audits, 53 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 53 | `xsl_stmt`, `regex`, `expect`, `severity`, `not_expect` |

### Example — `(untyped item)`

From `TNS Best Practice WatchGuard Audit 1.0.0`:

```
<custom_item>
  description : "WatchGuard : LDAP is used check"
  xsl_stmt    : "<xsl:template match=\"profile\">"
  xsl_stmt    : "<xsl:text>LDAP in use: </xsl:text>"
  xsl_stmt    : "<xsl:choose>"
  xsl_stmt    : "<xsl:when test=\"auth-domain-list/auth-domain[contains(name,'LDAP')]\">"
  xsl_stmt    : "<xsl:value-of select=\"auth-domain-list/auth-domain/ldap/enabled\"/>"
  xsl_stmt    : "</xsl:when>"
  xsl_stmt    : "<xsl:otherwise>"
  xsl_stmt    : "<xsl:text>Not Enabled </xsl:text>"
  xsl_stmt    : "</xsl:otherwise>"
  xsl_stmt    : "</xsl:choose>"
  xsl_stmt    : "</xsl:template>"
  regex       : "LDAP in use:"
  expect      : "LDAP in use: 1"
</custom_item>
```

## ZTE JINOS

- **Opening tag:** `<check_type:"ZTE_JINOS">`
- **Corpus:** 1 shipped audits, 82 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CONFIG_CHECK` | 68 | `item`, `section`, `context` |
| `CONFIG_CHECK_NOT` | 14 | `item`, `context`, `section` |

### Example — `CONFIG_CHECK`

From `Tenable ZTE JINOS`:

```
<custom_item>
  type        : CONFIG_CHECK
  description : "1.1 Secure Login and Telnet Disabling - Enable SSH server"
  info        : "From the perspective of security, the management plane should support at least the SSH/SSL login mode. Ordinary plain text Telnet/ftp login is vulnerable to attack, and such secure login modes as SSH and SFTP should be supported. The session validity period must be limited."
  solution    : "It is recommended to enable ssh server

  Enable SSH server by running:
  ZXR10 (config)#ssh server enable"
  reference   : "800-171|3.4.6,800-171|3.4.7,800-171r3|03.04.06a.,800-53|CM-7a.,800-53r5|CM-7a.,CN-L3|7.1.3.5(c),CN-L3|8.1.4.4(a),CSF|PR.IP-1,CSF|PR.PT-3,CSF2.0|PR.PS-01,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-7a.,NIAv2|SS15a,PCI-DSSv3.2.1|2.2.1,PCI-DSSv4.0|2.2.3,QCSC-v1|3.2,SWIFT-CSCv1|2.3"
  see_also    : "https://support.zte.com.cn/support/doccenter/DocumentProductHandBookDetail.aspx?sid=102&id=30768582&type=docfeedback"
  item        : "^ssh server enable"
</custom_item>
```

## ZTE ROSNG

- **Opening tag:** `<check_type:"ZTE_ROSNG">`
- **Corpus:** 1 shipped audits, 78 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `CMD_EXEC` | 64 | `cmd`, `expect`, `not_expect` |
| `CONFIG_CHECK` | 14 | `item`, `section`, `context`, `min_occurrences` |

### Example — `CMD_EXEC`

From `Tenable ZTE ROSNG Best Practices`:

```
<custom_item>
  type        : CMD_EXEC
  description : "1.1 Secure Login and telnet Disabling - Enable SSH server"
  info        : "From the perspective of security, the management plane should support at least the SSH/SSL login mode. Ordinary plain text telnet/ftp login is vulnerable to attack, and such secure login modes as SSH and SFTP should be supported. The session validity period must be limited."
  solution    : "It is recommended to enable ssh server

  Enable SSH server by running:
  ZXR10 (config)#ssh server enable"
  see_also    : "https://support.zte.com.cn/support/doccenter/DocumentProductHandBookDetail.aspx?sid=102&id=30768582&type=docfeedback"
  cmd         : "show running-config ssh all"
  expect      : "ssh server enable"
</custom_item>
```

## BlueCoat ProxySG

- **Opening tag:** `<check_type:"BlueCoat">`
- **Corpus:** 2 shipped audits, 166 control items
- **Benchmark families:** DISA STIG (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 141 | `expect`, `regex`, `context`, `severity`, `cmd`, `not_expect` |
| `AUDIT_XML_VPM` | 25 | `xsl_stmt`, `not_expect`, `regex`, `expect`, `severity` |

### Example — `(untyped item)`

From `DISA Symantec ProxySG Benchmark ALG v1r3`:

```
<custom_item>
  description : "SNMP v1 disabled"
  context     : "snmp ;mode"
  regex       : "protocol snmpv1 disable"
  expect      : "protocol snmpv1 disable"
</custom_item>
```

## Citrix Application Delivery

- **Opening tag:** `<check_type:"Citrix_Application_Delivery">`
- **Corpus:** 2 shipped audits, 35 control items
- **Benchmark families:** TNS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 35 | `json_transform`, `request`, `expect`, `regex`, `not_expect` |

### Example — `REST_API`

From `Tenable Best Practice Citrix ADC v1.0.0`:

```
<custom_item>
  type           : REST_API
  description    : "Check that a specific ADC key exists"
  request        : "ADCgetHardware"
  json_transform : ".nshardware"
  expect         : "hwdescription"
</custom_item>
```

## Palo Alto Networks PAN-OS

- **Opening tag:** `<check_type:"Palo_Alto">`
- **Corpus:** 15 shipped audits, 1093 control items
- **Benchmark families:** CIS (12), DISA STIG (3)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `AUDIT_XML` | 1093 | `api_request_type`, `xsl_stmt`, `request`, `regex`, `expect`, `not_expect`, `severity` |

### Example — `AUDIT_XML`

From `CIS Palo Alto Firewall 10 v1.3.0 L1`:

```
<custom_item>
  type             : AUDIT_XML
  description      : "Check for Palo Alto version 10"
  api_request_type : "op"
  request          : "<show><system><info></info></system></show>"
  xsl_stmt         : "<xsl:template match=\"/\">"
  xsl_stmt         : "<xsl:value-of select=\"/response/result/system/sw-version\"/>"
  regex            : ".*"
  expect           : "^[\s]*@PLATFORM_VERSION@\..*"
</custom_item>
```
