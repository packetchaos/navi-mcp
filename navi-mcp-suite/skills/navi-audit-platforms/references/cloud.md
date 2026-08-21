# Cloud Platforms — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## Contents

- [Amazon AWS](#amazon-aws) — `<check_type:"amazon_aws">`
- [Microsoft Azure](#microsoft-azure) — `<check_type:"microsoft_azure">`
- [Google Cloud Platform](#google-cloud-platform) — `<check_type:"GCP">`
- [OpenStack](#openstack) — `<check_type:"OpenStack">`
- [OpenShift Container Platform](#openshift-container-platform) — `<check_type:"OpenShift">`
- [Rackspace](#rackspace) — `<check_type:"Rackspace">`

## Amazon AWS

- **Opening tag:** `<check_type:"amazon_aws">`
- **Corpus:** 4 shipped audits, 144 control items
- **Benchmark families:** CIS (4)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `EC2` | 41 | `xsl_stmt`, `aws_action`, `severity`, `not_expect`, `regex`, `expect`, `parameters` |
| `IAM` | 25 | `aws_action`, `xsl_stmt`, `regex`, `expect`, `json_transform`, `not_expect`, `severity`, `policy_arn`, `role_name`, `policy_name`, `name`, `days` |
| `ELB` | 14 | `expect`, `xsl_stmt`, `regex`, `aws_action`, `severity` |
| `RDS` | 13 | `xsl_stmt`, `aws_action`, `regex`, `not_expect`, `expect`, `severity` |
| `CONFIG` | 10 | `json_transform`, `regex`, `aws_action`, `expect`, `not_expect`, `any_region` |
| `AUTOSCALING` | 9 | `xsl_stmt`, `aws_action`, `regex`, `not_expect`, `expect`, `severity` |
| `CLOUDFRONT` | 6 | `xsl_stmt`, `aws_action`, `regex`, `not_expect`, `expect`, `distribution_id`, `severity` |
| `S3` | 5 | `regex`, `aws_action`, `xsl_stmt`, `expect`, `not_expect`, `json_transform`, `bucket_name`, `severity` |
| `LOGS` | 5 | `expect`, `json_transform`, `aws_action`, `regex` |
| `KMS` | 4 | `json_transform`, `regex`, `aws_action`, `expect`, `not_expect` |
| `CLOUDTRAIL` | 3 | `json_transform`, `regex`, `aws_action`, `not_expect`, `expect` |
| `CLOUDWATCH` | 2 | `xsl_stmt`, `aws_action`, `severity`, `not_expect`, `expect`, `regex` |
| `SNS` | 2 | `severity`, `not_expect`, `xsl_stmt`, `aws_action` |
| `ROUTE53` | 2 | `expect`, `xsl_stmt`, `regex`, `aws_action`, `hosted_zone_id` |
| `ACCESS_ANALYZER` | 1 | `expect`, `json_transform`, `regex`, `aws_action` |
| `EFS` | 1 | `json_transform`, `not_expect`, `regex`, `aws_action` |
| `SECURITYHUB` | 1 | `expect`, `json_transform`, `regex`, `aws_action` |

### Example — `EC2`

From `CIS Amazon Web Services Foundations v7.0.0 L2`:

```
<custom_item>
  type        : EC2
  description : "'No Outbound Rules exist"
  aws_action  : "DescribeSecurityGroups"
  xsl_stmt    : "<xsl:template match=\"/\">
  <xsl:choose>
  <xsl:when test=\"//ec2:securityGroupInfo/ec2:item[ec2:groupName = 'default']\">
  <xsl:choose>
  <xsl:when test=\"//ec2:securityGroupInfo/ec2:item[ec2:groupName = 'default']/ec2:ipPermissionsEgress/ec2:item\">
  <xsl:for-each select=\"//ec2:securityGroupInfo/ec2:item[ec2:groupName = 'default']/ec2:ipPermissionsEgress/ec2:item\">
  <xsl:text>FAIL - Default Security Group with VPCID </xsl:text><xsl:value-of select=\"../../ec2:vpcId\"/><xsl:text> contains outbound rules.</xsl:text><xsl:text>&#10;</xsl:text>
  </xsl:for-each>
  </xsl:when>
  <xsl:otherwise>
  <xsl:text>PASS - No Default Security Groups in this region contain any outbound rules.</xsl:text><xsl:text>&#10;</xsl:text>
  </xsl:otherwise>
  </xsl:choose>
  </xsl:when>
  <xsl:otherwise>
  <xsl:text>PASS - No VPCs in this region.</xsl:text>
  </xsl:otherwise>
  </xsl:choose>
  </xsl:template>"
  regex       : ".+"
  expect      : "PASS \-.+"
</custom_item>
```

## Microsoft Azure

- **Opening tag:** `<check_type:"microsoft_azure">`
- **Corpus:** 16 shipped audits, 798 control items
- **Benchmark families:** TNS (10), CIS (6)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 661 | `json_transform`, `request`, `expect`, `regex`, `match_all`, `not_expect`, `severity` |
| `POLICY` | 137 | `name`, `severity` |

### Example — `(untyped item)`

From `CIS Microsoft 365 Foundations v7.0.0 L1 E3`:

```
<custom_item>
  description    : "default mailbox policy"
  request        : "getOwaMailboxPolicy"
  json_transform : '.[] | select(.Name == "OwaMailboxPolicy-Default") | "Name: \(.Name), BookingsMailboxCreationEnabled: \(.BookingsMailboxCreationEnabled)"'
  regex          : ".+"
  expect         : "Name: OwaMailboxPolicy-Default, BookingsMailboxCreationEnabled: false"
</custom_item>
```

## Google Cloud Platform

- **Opening tag:** `<check_type:"GCP">`
- **Corpus:** 6 shipped audits, 154 control items
- **Benchmark families:** CIS (6)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 154 | `json_transform`, `request`, `regex`, `expect`, `match_all`, `not_expect`, `severity` |

### Example — `REST_API`

From `CIS Google Cloud Platform Foundation v5.0.0 L1`:

```
<custom_item>
  type           : REST_API
  description    : "exemptedMembers"
  request        : "listProjectIAM"
  json_transform : ".projects[] | .projectNumber as $projectNumber | .projectId as $projectId | .value.auditConfigs[] | \"Project Number: \($projectNumber), Project ID: \($projectId), Service: \(.service), Audit Log Configs: \(.auditLogConfigs[])\""
  regex          : "exemptedMembers"
  not_expect     : "exemptedMembers"
</custom_item>
```

## OpenStack

- **Opening tag:** `<check_type:"OpenStack">`
- **Corpus:** 1 shipped audits, 13 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 13 | `json_transform`, `request` |

### Example — `REST_API`

From `Tenable Best Practices OpenStack v2.0.0`:

```
<custom_item>
  type           : REST_API
  description    : "OpenStack Servers and their details"
  info           : "The Servers and their current state will determine what services are available."
  solution       : "Review the list of Servers. If any are unknown or not in the expected state they should be investigated."
  request        : "getServers"
  json_transform : ".servers[] | \"Name: \(.name), ID: \(.id), Status: \(.status), User_ID: \(.user_id), Created: \(.created), Updated: \(.updated), Host_ID: \(.hostId), Tenant_ID: \(.tenant_id), Addresses: \([.addresses.[].[].addr] | join(\",\"))\""
  reference      : "800-171|3.4.1,800-53|CM-8,800-53r5|CM-8,CN-L3|8.1.10.2(a),CN-L3|8.1.10.2(b),CSF|DE.CM-7,CSF|ID.AM-1,CSF|ID.AM-2,CSF|PR.DS-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-8,NESA|T1.2.1,NESA|T1.2.2"
</custom_item>
```

## OpenShift Container Platform

- **Opening tag:** `<check_type:"OpenShift">`
- **Corpus:** 2 shipped audits, 79 control items
- **Benchmark families:** CIS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 79 | `json_transform`, `request`, `expect`, `not_expect`, `severity`, `regex`, `match_all` |

### Example — `REST_API`

From `CIS Red Hat OpenShift Container Platform v1.9.0 L1`:

```
<custom_item>
  type           : REST_API
  description    : "feature-gates"
  request        : "getKubeApiServers"
  json_transform : ".items[] | .spec.clusterID as $clusterID | .items[] | \"Cluster ID: \($clusterID), Name: \(.metadata.name), UID: \(.metadata.uid), Feature Gates: \(.spec.observedConfig.apiServerArguments.\"feature-gates\")\""
  not_expect     : "Feature Gates:.*\"InsecureBindAddress=true\".*"
</custom_item>
```

## Rackspace

- **Opening tag:** `<check_type:"Rackspace">`
- **Corpus:** 1 shipped audits, 35 control items
- **Benchmark families:** TNS (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `REST_API` | 35 | `json_transform`, `request`, `regex`, `expect`, `not_expect`, `severity`, `match_all` |

### Example — `REST_API`

From `Tenable Best Practices RackSpace v2.0.0`:

```
<custom_item>
  type           : REST_API
  description    : "Review the list of Rackspace Tenants"
  info           : "The Tenants and their current state will determine what services are available."
  solution       : "Review the list of Tenants. If any are unknown they should be investigated."
  reference      : "800-171|3.1.1,800-53|AC-2,800-53r5|AC-2,CCM-3|IVS-07,CN-L3|7.1.3.2(d),CSF|DE.CM-1,CSF|DE.CM-3,CSF|PR.AC-1,CSF|PR.AC-4,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(1),ISO/IEC-27001|A.9.2.1,ITSG-33|AC-2,NIAv2|AM28,NIAv2|NS5j,NIAv2|SS14e,PCI-DSS|2.2,QCSC-v1|5.2.2,QCSC-v1|8.2.1,QCSC-v1|13.2,QCSC-v1|15.2"
  request        : "getTenants"
  json_transform : ".tenants[] | \"Name: \(.name), ID: \(.id), Enabled: \(.enabled)\""
</custom_item>
```
