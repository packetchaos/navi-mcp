---
name: navi-export
description: >
  CSV export skill for Tenable navi CLI. Use for ANY request to export data to
  CSV from navi. Covers all navi export subcommands: assets, bytag (includes
  ACR + AES scores), network, licensed, vulns, failures (SLA breaches), route,
  compliance, agents, group, users, policy, parsed, and query (custom
  SQL). Two critical distinctions: bytag is the ONLY export carrying ACR and
  AES scores, and `vulns` intentionally exposes no filters — the navi pattern
  is tag-then-export-by-tag, or export query for a one-off slice. Trigger on:
  "export to CSV", "give me a spreadsheet", "download asset list", "export
  vulnerabilities", "export only criticals", "filter my export", "give me a
  report", "export compliance", "export by tag", "export users", "export
  agents", "export status", "is my export finished".
---

# Navi Export — CSV Export Reference

All export commands write CSV files from navi.db. Every export subcommand is
exposed through MCP as `navi_export(subcommand=..., ...)` — no write-gating,
no confirmation required. The tool returns the CSV path, file size, row
count, header, and a short preview (first 5 rows). **The preview is a
preview, not the full export** — Claude surfaces the file path to the user
and prefers `navi_explore_query` against navi.db for further analysis.

**Naming the output file.** Every subcommand takes `--file` at the CLI and an
optional `file` param through MCP. The extension is optional — navi appends it —
so `--file report` and `--file report.csv` both produce `report.csv`. Passing
`file` makes the returned path deterministic instead of relying on
newest-file detection, which matters when exports run concurrently.

Two older spellings still work but are deprecated and print a notice:
`export agents --filename` and `export parsed --name`. Use `--file`; the
aliases are scheduled for removal in navi 9.0. Note that `--name` remains a
**filter** on `export vulns` (plugin name) and `export compliance` (audit file
name) — it never names the output on those two.

**Data freshness matters.** CSV exports are only as current as navi.db. For
targeted refreshes between full syncs, use `navi_config_update(kind=...)` —
valid kinds are `assets`, `vulns`, `agents`, `compliance`, `route`, `paths`,
`was`, `fixed`, `plugins`. (The certs table is *not* an update kind; populate it
with `navi_config(kind="certificates")`.) For foundational syncs and first-run
setup, `navi config update full` is the CLI command you run at your terminal —
it's intentionally not exposed as an MCP tool because first-run syncs can pull
hundreds of GB and take hours. See navi-mcp for the full stance.

When running under navi-mcp, use tool-invocation form (shown first in each
example below). The bash forms are standalone CLI equivalents for readers
outside an MCP context.

---

## Asset Exports

Full asset dump — `ip_address, hostname, fqdn, uuid, os, network, first_found,
last_found, etc.`

`navi_export(subcommand="assets")`

```bash
navi export assets
```

Assets matching a tag — **the only export with ACR + AES scores**. Use for
risk reporting by business segment, exec exposure summaries. ACR/AES are
NOT available via `navi_export(subcommand="query", ...)` — bytag only.

`navi_export(subcommand="bytag", category="Environment", value="Production")`

```bash
navi export bytag --c "Environment" --v "Production"
```

Assets in a specific network. Get network names first via
`navi_explore_info(subcommand="networks")`.

`navi_export(subcommand="network", network="<NETWORK_UUID>")`

```bash
navi export network <NETWORK_UUID>
```

The value is the network **UUID**, not its display name — the export matches
on `assets.network`. Get UUIDs from `navi_explore_info(subcommand="networks")`.

Licensed assets only. Use for license management and billing reconciliation.

`navi_export(subcommand="licensed")`

```bash
navi export licensed
```

---

## Vulnerability Exports

Full vulnerability dump — `asset_ip, plugin_id, plugin_name, severity, output,
first_found, last_found, etc.`

`navi_export(subcommand="vulns")`

```bash
navi export vulns
```

### Why `vulns` takes no filters — and what to do instead

`navi export vulns` accepts `--c`/`--v`, `--severity`, `--plugin`, `--name`,
`--output`, `--cve`, `--xrefs`, and `-regexp` on the CLI. **`navi_export`
exposes none of them, deliberately.** This is a closed decision, not a gap
waiting to be filled — don't work around it by shelling out.

The navi pattern is **tag, then export by tag**:

1. `navi_enrich_tag(...)` narrows the population once. It carries the full
   selector surface — `xrefs`, `regexp`, plugin, CVE, CPE, custom SQL — far
   more than the export flags express.
2. `navi_export(subcommand="bytag", category=..., value=...)` pulls the CSV.

That route is strictly better, not merely equivalent: **`bytag` is the only
export carrying ACR and AES**, so the tagged path yields a richer CSV than any
filtered `export vulns` could. The tag is also reusable and auditable, which a
one-off flag combination is not.

**For a one-off slice that doesn't deserve a tag**, use
`navi_export(subcommand="query", sql=...)` — it expresses anything those flags
could, cross-references included:

```
navi_export(subcommand="query",
            sql="SELECT asset_ip, plugin_id, plugin_name, severity "
                "FROM vulns WHERE xrefs LIKE '%CISA%' AND severity='critical';")
```

Reach for `subcommand="vulns"` when you genuinely want everything.

Vulnerabilities that have failed SLA thresholds. Requires SLA thresholds
to be configured first via `navi_config(kind="sla")` — see navi-core.
Use for SLA breach reporting, escalation lists, overdue remediation.

`navi_export(subcommand="failures")`

```bash
navi export failures
```

Vulnerabilities for a specific route ID. Get route IDs first via
`navi_explore_data(subcommand="route")`. Use for handing a remediator their
exact vuln list for their technology stack.

`navi_export(subcommand="route", route_id="<ROUTE_ID>")`

```bash
navi export route <ROUTE_ID>
```

Parsed plugin data (normalized output). Use for feeding structured findings
to ticketing systems or SIEMs.

`navi_export(subcommand="parsed")`

```bash
navi export parsed
```

## Compliance Export

Compliance check results — `asset_uuid, check_name, status
(passed/failed/warning), audit_file, plugin_id`. Requires the compliance
table to be populated first via `navi_config_update(kind="compliance")`.
Use for audit evidence, CIS/STIG compliance reports, failed control lists.

`navi_export(subcommand="compliance")`

```bash
navi export compliance
```

---

## Agent Exports

All agent data — `name, IP, UUID, status, group, platform, last_connect,
version, etc.`

`navi_export(subcommand="agents")`

```bash
navi export agents
```

Agents in a specific group. Get group names first via
`navi_explore_info(subcommand="agent_groups")`.

`navi_export(subcommand="group", group_name="Production Servers")`

```bash
navi export group "Production Servers"
```

---

## User & Policy Exports

All users with roles and permissions — `username, email, permission level,
role, enabled/disabled`. Use for access reviews and offboarding audits.

`navi_export(subcommand="users")`

```bash
navi export users
```

Scan policies. Use for policy migration between Tenable instances and
policy backup.

`navi_export(subcommand="policy", policy_id="<POLICY_ID>")`

```bash
navi export policy --pid <POLICY_ID>
```

Get IDs from `navi_explore_info(subcommand="policies")`. This is the one export
that does **not** produce a CSV — it writes a `.nessus` XML policy file, so the
response carries no `csv_header` / `csv_preview`.

---

## Custom Export (SQL)

Full control over columns, joins, and filters. Does NOT include ACR/AES —
use `navi_export(subcommand="bytag", ...)` for those.

When composing a custom query, check the relevant schema first via the
`navi://schema/{table}` resource rather than guessing column names.

`navi_export(subcommand="query", sql="SELECT ...")`

```bash
navi export query "SELECT ..."
```

**Example queries:**

```sql
-- Critical vulns by asset
SELECT asset_ip, plugin_name, severity FROM vulns
WHERE severity='critical' ORDER BY asset_ip;

-- Asset + vuln join filtered by network
SELECT a.hostname, v.plugin_name FROM vulns v
JOIN assets a ON a.ip_address = v.asset_ip
WHERE a.network = 'DMZ';

-- Certs expiring in a given year
SELECT common_name, not_valid_after FROM certs
WHERE not_valid_after LIKE '%2026%';

-- Workload by route
SELECT app_name, total_vulns FROM vuln_route
ORDER BY total_vulns DESC;

-- Distinct fix locations by path
SELECT path, COUNT(DISTINCT plugin_id) AS vulns FROM vuln_paths
GROUP BY path ORDER BY vulns DESC;

-- WAS findings for dev team
SELECT a.name, a.target, f.plugin_name, f.severity, f.solution
FROM findings f JOIN apps a ON f.config_id = a.config_id
ORDER BY a.name, f.severity;
```

---

## Decision Guide

| Want | Tool call |
|------|---------|
| Full asset dump | `navi_export(subcommand="assets")` |
| **Assets with ACR + AES** | `navi_export(subcommand="bytag", category=<cat>, value=<val>)` |
| Assets in a network | `navi_export(subcommand="network", network=<network_uuid>)` |
| Licensed assets | `navi_export(subcommand="licensed")` |
| Full vuln dump | `navi_export(subcommand="vulns")` |
| **Overdue / SLA breaches** | `navi_export(subcommand="failures")` (needs SLA configured) |
| Vulns for one technology route | `navi_export(subcommand="route", route_id=<id>)` |
| Compliance / audit evidence | `navi_export(subcommand="compliance")` (needs `navi_config_update(kind="compliance")`) |
| Agent inventory | `navi_export(subcommand="agents")` |
| Agents in a group | `navi_export(subcommand="group", group_name=<group>)` |
| User list + roles | `navi_export(subcommand="users")` |
| Policies for migration | `navi_export(subcommand="policy", policy_id=<id>)` (writes `.nessus`) |
| Parsed plugin data | `navi_export(subcommand="parsed")` |
| Custom filter / joins | `navi_export(subcommand="query", sql="SELECT ...")` |

---

## Delivering a CSV to someone — `navi_action_mail`

Email is now a tool (`navi_action_mail`), but double-gated: it needs
`NAVI_MCP_ALLOW_WRITES=1` + `NAVI_EMAIL=1` on the server plus `confirm=True`.
Export first, then mail the returned path. Full harness: **navi-mail**
(`navi://skill/mail`).

**Pattern:**

> I'll export production assets with ACR and AES scores.
>
> `navi_export(subcommand="bytag", category="Environment", value="Production")`
>
> *[tool returns: "Wrote bytag_export.csv — 1,247 rows. Columns: ip_address,
> hostname, uuid, os, network, acr, aes, ..."]*
>
> CSV is at `bytag_export.csv`. I'll email it to your CISO — confirm and I'll
> send:
>
> `navi_action_mail(to="ciso@company.com", subject="Production ACR/AES export", file="bytag_export.csv", confirm=True)`

For sensitive columns, encrypt first (`navi_action_encrypt`) and mail the `.enc`.

---

## In-flight export status

`navi_export(...)` launches an export and blocks until it finishes. Large
exports (vulns/assets) can exceed the ~4-minute call budget. Polling an export
by UUID is useful when:

- An export was launched outside this session (the Tenable UI, another tool, a
  prior MCP call that hit the call budget and returned before finishing).
- You want to confirm an export already completed before kicking off a duplicate.

This is now **tool-driven** via the `navi_explore_api` passthrough (GET, no
confirmation needed):

```
# Vulnerability exports
navi_explore_api(url="/vulns/export/<EXPORT_UUID>/status")
navi_explore_api(url="/vulns/export/<EXPORT_UUID>/chunk/<CHUNK_NUMBER>")

# Asset exports — same shape, 'assets' instead of 'vulns'
navi_explore_api(url="/assets/export/<EXPORT_UUID>/status")
navi_explore_api(url="/assets/export/<EXPORT_UUID>/chunk/<CHUNK_NUMBER>")
```

CLI equivalent (fallback): `navi explore api '/vulns/export/<EXPORT_UUID>/status'`.

**Typical flow**: poll `/status` until state is `FINISHED` (or `PROCESSING`
with chunks already available), read `chunks_available` from the response, then
fetch each chunk number in turn. States are `QUEUED`, `PROCESSING`, `FINISHED`,
`CANCELLED`, `ERROR`. A 401 here means the same thing it means anywhere else in
navi — keys are missing, wrong, or revoked; fix them in navi-mcp / Tenable
before retrying. (To cancel an export still in flight, `navi_action_cancel`
takes the export `uuid`.)

For the surrounding workflow — what to do when an MCP export exceeds the call
budget, and how to avoid the DB-lock chain that can follow — see
navi-troubleshooting's "Long-running operations and MCP timeouts".

---

## Natural Language → Export

| User says | Tool call |
|---|---|
| "export all assets" | `navi_export(subcommand="assets")` |
| "export production assets with risk scores" | `navi_export(subcommand="bytag", category="Environment", value="Production")` |
| "export assets in DMZ" | `navi_export(subcommand="network", network=<DMZ network UUID>)` |
| "export licensed assets" | `navi_export(subcommand="licensed")` |
| "export all vulns" | `navi_export(subcommand="vulns")` |
| "export overdue / failed vulns / SLA" | `navi_export(subcommand="failures")` |
| "export vulns for Jenkins route" | `navi_export(subcommand="route", route_id=<id>)` |
| "export compliance results" | `navi_export(subcommand="compliance")` |
| "export agents" | `navi_export(subcommand="agents")` |
| "export agents in a group" | `navi_export(subcommand="group", group_name=<group>)` |
| "export users / access report" | `navi_export(subcommand="users")` |
| "export policies for migration" | `navi_export(subcommand="policy", policy_id=<id>)` |
| "custom export / specific columns" | `navi_export(subcommand="query", sql="SELECT ...")` |
