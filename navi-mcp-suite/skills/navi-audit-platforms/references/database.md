# Databases — check types and keywords

Every fact in this file was extracted from the audit files Tenable
ships, not from prose documentation. Opening tags are verbatim.

Universal keywords (`description`, `info`, `reference`, `see_also`, `solution`, `type`) are valid on nearly every check and are
omitted from the per-type tables below — see `navi-audit-syntax`.

## Contents

- [Database](#database) — `<check_type:"Database" db_type:"SQLServer" version:"1">`
- [MS SQL DB](#ms-sql-db) — `<check_type:"MS_SQLDB">`
- [MySQL DB](#mysql-db) — `<check_type:"MySQLDB">`
- [Oracle DB](#oracle-db) — `<check_type:"OracleDB">`
- [PostgreSQL DB](#postgresql-db) — `<check_type:"PostgreSQLDB">`
- [IBM DB2 DB](#ibm-db2-db) — `<check_type:"IBM_DB2DB">`
- [MongoDB](#mongodb) — `<check_type:"MongoDB">`
- [Sybase DB](#sybase-db) — `<check_type:"SybaseDB">`

## Database

- **Opening tag:** `<check_type:"Database" db_type:"SQLServer" version:"1">` or `<check_type:"Database" db_type:"MySQL" version:"1">` or `<check_type:"Database" db_type:"Oracle" version:"1">` or `<check_type:"Database" db_type:"DB2" version:"1">`
- **Corpus:** 38 shipped audits, 2873 control items
- **Benchmark families:** CIS (32), DISA STIG (6)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 2873 | `sql_types`, `sql_request`, `sql_expect`, `severity`, `check_option` |

### Example — `SQL_POLICY`

From `Sunset - CIS IBM DB2 v10 v1.1.0 Database Level 1`:

```
<custom_item>
  type        : SQL_POLICY
  description : "1.1 Install the latest fix packs"
  info        : "Periodically, IBM releases fix packs to enhance features and resolve defects, including security defects. It is recommended that the DB2 instance remain current with all fix packs.

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  solution    : "Apply the latest fix pack as offered from IBM."
  reference   : "LEVEL|1NS"
  see_also    : "https://workbench.cisecurity.org/files/162"
  sql_request : "SELECT service_level FROM TABLE(SYSPROC.ENV_GET_INST_INFO())"
  sql_types   : POLICY_VARCHAR
  sql_expect  : regex:".+"
  severity    : MEDIUM
</custom_item>
```

## MS SQL DB

- **Opening tag:** `<check_type:"MS_SQLDB">`
- **Corpus:** 34 shipped audits, 2342 control items
- **Benchmark families:** CIS (26), DISA STIG (8)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 2342 | `sql_types`, `sql_expect`, `sql_request`, `severity`, `match_all` |

### Example — `SQL_POLICY`

From `CIS SQL Server 2014 Database L1 AWS RDS v1.5.0`:

```
<custom_item>
  type        : SQL_POLICY
  description : "2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'"
  sql_request : "SELECT SERVERPROPERTY('IsClustered') AS [isClustered]"
  sql_types   : STRING
  sql_expect  : "0"
</custom_item>
```

## MySQL DB

- **Opening tag:** `<check_type:"MySQLDB">`
- **Corpus:** 39 shipped audits, 1861 control items
- **Benchmark families:** CIS (37), DISA STIG (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 1861 | `sql_types`, `sql_expect`, `sql_request`, `severity`, `match_all` |

### Example — `SQL_POLICY`

From `CIS MariaDB 10.11 v1.0.0 L1 MariaDB RDBMS MySQLDB`:

```
<custom_item>
  type        : SQL_POLICY
  description : "MariaDB 10.11 is installed"
  sql_request : "show variables like 'version' ;"
  sql_types   : STRING, REGEX
  sql_expect  : "version", "@PLATFORM_VERSION@"
</custom_item>
```

## Oracle DB

- **Opening tag:** `<check_type:"OracleDB">`
- **Corpus:** 19 shipped audits, 1587 control items
- **Benchmark families:** CIS (14), DISA STIG (5)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 1587 | `sql_types`, `sql_expect`, `sql_request`, `severity`, `num_rows`, `match_all` |

### Example — `SQL_POLICY`

From `CIS Oracle Database 19c STIG v1.1.0 CAT III`:

```
<custom_item>
  type        : SQL_POLICY
  description : "check for traditional auditing"
  sql_request : "SELECT gp.inst_id, gp.con_id, gp.display_value FROM sys.gv_$parameter gp WHERE gp.name = 'audit_trail' AND gp.display_value != 'NONE';"
  sql_types   : REGEX, REGEX, REGEX
  sql_expect  : ".+", ".+", ".+"
</custom_item>
```

## PostgreSQL DB

- **Opening tag:** `<check_type:"PostgreSQLDB">`
- **Corpus:** 19 shipped audits, 1184 control items
- **Benchmark families:** CIS (13), DISA STIG (6)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 1184 | `sql_types`, `sql_expect`, `sql_request`, `severity`, `match_all` |

### Example — `SQL_POLICY`

From `CIS PostgreSQL 10 DB v1.0.0`:

```
<custom_item>
  type        : SQL_POLICY
  description : "PostgreSQL version is 10"
  sql_request : "select version()"
  sql_types   : REGEX
  sql_expect  : "^[\\s]*PostgreSQL 10\..*"
</custom_item>
```

## IBM DB2 DB

- **Opening tag:** `<check_type:"IBM_DB2DB">`
- **Corpus:** 9 shipped audits, 802 control items
- **Benchmark families:** CIS (8), DISA STIG (1)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 802 | `sql_types`, `sql_expect`, `sql_request`, `severity` |

### Example — `SQL_POLICY`

From `CIS IBM DB2 v10 v1.1.0 Database Level 1`:

```
<custom_item>
  type        : SQL_POLICY
  description : "1.1 Install the latest fix packs"
  info        : "Periodically, IBM releases fix packs to enhance features and resolve defects, including security defects. It is recommended that the DB2 instance remain current with all fix packs.

  NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance."
  solution    : "Apply the latest fix pack as offered from IBM."
  reference   : "LEVEL|1NS"
  see_also    : "https://workbench.cisecurity.org/files/162"
  sql_request : "SELECT service_level FROM TABLE(SYSPROC.ENV_GET_INST_INFO())"
  sql_types   : REGEX
  sql_expect  : ".+"
  severity    : MEDIUM
</custom_item>
```

## MongoDB

- **Opening tag:** `<check_type:"MongoDB">`
- **Corpus:** 23 shipped audits, 171 control items
- **Benchmark families:** CIS (18), DISA STIG (5)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `(untyped item)` | 171 | `query`, `collection`, `severity`, `regex`, `expect`, `not_expect` |

### Example — `(untyped item)`

From `CIS MongoDB 3.2 Database Audit L2 v1.0.0`:

```
<custom_item>
  description : "6.5 Ensure The 'test' database is not installed"
  info        : "The default MongoDB installation comes with an unused database called 'test'. It is recommended that the test database be dropped.
  Rationale:
  The test database can be accessed by all users and can be used to consume system resources. Dropping the test database will reduce the attack surface of the MongoDB server."
  solution    : "Execute the following command mongoshell to drop the test database:
  use test

  db.dropDatabase()"
  reference   : "800-171|3.4.6,800-171|3.4.7,800-53|CM-7b.,800-53r5|CM-7b.,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CN-L3|8.1.4.4(b),CSCv6|18.9,CSF|PR.IP-1,CSF|PR.PT-3,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-7a.,LEVEL|2M,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,PCI-DSSv3.2.1|2.2.2,PCI-DSSv4.0|2.2.4,QCSC-v1|3.2,SWIFT-CSCv1|2.3"
  see_also    : "https://workbench.cisecurity.org/files/1705"
  not_expect  : "test"
  collection  : "admin.$cmd"
  query       : '{"listDatabases": true}'
</custom_item>
```

## Sybase DB

- **Opening tag:** `<check_type:"SybaseDB">`
- **Corpus:** 2 shipped audits, 45 control items
- **Benchmark families:** CIS (2)

### Check types

| `type:` | Items | Keywords used with it |
|---|---|---|
| `SQL_POLICY` | 45 | `sql_types`, `sql_expect`, `sql_request`, `severity` |

### Example — `SQL_POLICY`

From `CIS Sybase 15.0 L1 DB v1.1.0`:

```
<custom_item>
  type        : SQL_POLICY
  description : "2.2 Enable message integrity"
  info        : "Sybase ASE supports a means of signaling to the underlying security mechanism that message integrity is required via the msg integrity reqd configuration parameter.
  The setting is disabled by default. It is recommended the message integrity is enabled. Note that enabling the use security services configuration parameter is a prerequisite for enabling message integrity.

  Rationale:
  Enabling message integrity prevents an attacker positioned between the client and the server from intercepting and modifying messages."
  solution    : "1. Connect to the database as a user with the sso_role and execute the following SQL statement to enable message integrity.
  exec sp_configure 'msg integrity reqd', 1"
  reference   : "LEVEL|1S"
  see_also    : "https://workbench.cisecurity.org/files/1612"
  sql_request : "exec sp_configure 'msg integrity reqd'"
  sql_types   : STRING, STRING, STRING, STRING, STRING, STRING, STRING
  sql_expect  : "msg integrity reqd", "0", "0", "1", "1", "switch", "dynamic"
</custom_item>
```
