---
name: navi-enrich
description: >
  Asset tagging skill for Tenable navi CLI. Use for ANY request involving
  tagging assets in Tenable VM: tag by plugin, CVE, CPE, CISA KEV, port,
  route, file, manual UUID, scan ID, agent group, AD group, cross-references,
  custom SQL query, or tag-on-tag derivation. Also covers adding assets from
  external sources (navi_enrich_add). Critical patterns: ephemeral tagging
  with remove=True for health tags, tag UUID preservation (do NOT delete-and-
  recreate), scale fork at 50K assets, and the 30-minute propagation window.
  Covers `regexp=True` for pattern matching — global across plugin_output,
  plugin_name, cpe, xrefs, by_val and by_cat, raising elsewhere rather than
  silently matching literally — the deprecated `plugin_regexp` alias, and the
  guards for selectors navi would accept while building an empty tag (xid
  without xrefs, histid without scanid). Trigger on: "tag all assets", "create
  a tag", "how do I tag", "enrich", "refresh a tag", "regex tag", "tag by
  pattern", "import assets". For ACR adjustment see navi-acr.
---

# Navi Enrich — Tagging & Asset Enrichment

Two enrichment tools covered here: `navi_enrich_tag` (tagging) and
`navi_enrich_add` (importing assets from external sources). Both are
**write-gated** — each call requires `confirm=True` and requires the
navi-mcp server to be running with `NAVI_MCP_ALLOW_WRITES=1`.

**For ACR adjustment (`navi_enrich_acr`), see navi-acr.** ACR workflows
are conceptually distinct from tagging — tagging establishes which
assets are what; ACR assigns criticality to those tagged groups.

See navi-mcp for the full write-gate convention: Claude describes the
operation in prose, states the exact tool call, and waits for user
confirmation before invoking.

When running under navi-mcp, use tool-invocation form (shown first in each
example below). Bash forms are standalone CLI equivalents for readers
outside an MCP context.

---

## Prereqs

- **Data freshness**: tagging works off the local navi.db. If the data is
  stale, tags apply to a stale picture. Under navi-mcp, the freshness
  check runs automatically at the start of a data-dependent workflow —
  see navi-mcp. If navi.db is empty or very old, the foundational
  `navi config update full` needs to run at the user's terminal before
  tagging is reliable.
- **Propagation window**: after a tagging write, allow **up to 30 minutes**
  for tags to be fully visible in the Tenable UI/API. This is a
  platform-side delay, not a navi delay. `navi_explore_query` against
  navi.db reflects the write immediately; `navi_explore_info` against the
  Tenable API can lag during the propagation window. The same window
  applies to ACR changes — see navi-acr for the ACR-specific timing.
- **Scale fork**: check asset count first —
  `navi_explore_query(sql="SELECT count(uuid) FROM assets;")`. Under 50K
  uses plugin regex; over 50K uses dedicated `certs`/`software` tables
  via `query=...`.
- **Slow tagging?** First try `navi config optimize` at the CLI (navi
  8.5.31+) — it builds curated indexes that fix most slowness in seconds.
  If you're on older navi or need custom indexes, see navi-troubleshooting
  for the manual SQL index fallback. For repeated workloads against a
  specific subset, a purpose-built navi directory (see navi-core's
  multi-workload pattern) is structurally faster.

---

## `navi_enrich_tag` — selectors & use cases

**Required args:** `category`, `value`, and `confirm=True` at call time.
**Optional:** `description` for a human-readable tag description.

Server enforces: pass exactly ONE primary selector per call. `plugin_output`
and `plugin_regexp` are modifiers that require `plugin`. `xid` requires
`xrefs`. `histid` requires `scanid`. `require_both=True` requires both
`parent_category` and `parent_value`.

Two of those guards exist because **navi itself would not stop you.** Given
`xid` without `xrefs`, or `histid` without `scanid`, navi prints a warning and
then keeps going — it builds a tag with no selector and exits 0. A zero exit
reads as success, so without a server-side raise you would get an empty tag
reported as a completed one.

The two are not enforced identically:

- **`xid` without `xrefs` raises on every path**, `remove=True` included.
- **`histid` without `scanid` raises only when `remove=False`.** On a
  `remove=True` call it isn't checked — `histid` is folded into the "you
  combined remove with a selector" warning instead, so the call runs. Supply
  `scanid` yourself there rather than relying on the guard.

Every tag call is write-gated. Examples show the tool form with `confirm=True`;
in actual use, Claude narrates first and then asks for confirmation before
invoking.

### Selector quick map

One primary selector per call. Full per-selector examples (tool + CLI) are in
**`references/selectors.md`** (`navi://skill/enrich/selectors`).

| Selector | Tags assets by | Tool param |
|---|---|---|
| plugin (+ output / regexp) | a plugin firing, optionally matching output text | `plugin=`, `plugin_output=` |
| `plugin_name` | text in the plugin NAME | `plugin_name=` |
| `cve` / `cpe` | a CVE / CPE identifier | `cve=` / `cpe=` |
| `xrefs` (+ `xid`) | a cross-reference type (e.g. CISA) | `xrefs=`, `xid=` |
| `port` | a vuln on a given port | `port=` |
| `route_id` | a route in `vuln_route` | `route_id=` |
| `file` / `manual` | IPs in a CSV / explicit UUIDs | `file=` / `manual=` |
| `group` / `byadgroup` | an agent group / AD groups in a CSV | `group=` / `byadgroup=` |
| `missed` | agents that missed auth in N days | `missed=` |
| `scanid` (+ `histid`) / `scantime` | a scan / assets scanning > N min | `scanid=` / `scantime=` |
| `query` | a custom SELECT returning `asset_uuid` | `query=` |
| `by_tag` / `by_cat` / `by_val` | derivation from existing tags | `by_tag=` etc. |
| hierarchical | child→parent tag relationships | `parent_category=`, `parent_value=`, `require_both=` |
| modes | ephemeral refresh / TONE tag | `remove=True` / `tone=True` / `regexp=True` |

---

## `regexp=True` — pattern matching, and where it actually applies

`regexp=True` maps to navi's `-regexp`, which flips the underlying SQL from
`LIKE` to `REGEXP` for whichever **text** selector you used. It is a global
switch, not a plugin-output feature.

**Regexp-capable selectors — these six and no others:**

`plugin_output` (with `plugin`) · `plugin_name` · `cpe` · `xrefs` · `by_val` · `by_cat`

Passing `regexp=True` without one of them **raises**. That is deliberate:
navi accepts `-regexp` everywhere and silently ignores it on the selectors
that can't use it, which would hand you a literal-match tag wearing a
pattern-match label. A tag that quietly matched nothing — or matched the
wrong population — is worse than an error.

```
# Cross-reference tagging with alternation — one tag for KEV *or* IAVA
navi_enrich_tag(category="Threat", value="KEV-or-IAVA",
                xrefs="CISA|IAVA", regexp=True, confirm=True)
```

That call is the reason this matters: before `regexp` was a global parameter,
regexp cross-reference tagging was unreachable through MCP entirely.

### `plugin_regexp` is deprecated

`plugin_regexp="<pattern>"` was the old spelling and only ever reached plugin
**output**. It still works — it sets `--output` and `-regexp` together — but it
returns a deprecation `_warning`. Write it the new way:

```
# Deprecated
plugin=10863, plugin_regexp="Not After\\s*:\\s*Apr.*2026"

# Preferred — identical behavior, no warning
plugin=10863, plugin_output="Not After\\s*:\\s*Apr.*2026", regexp=True
```

### `xrefs` + `xid` + `regexp` — the pattern is ignored

Supplying `xid` puts navi on a two-term `LIKE` branch that never reaches the
`REGEXP` branch below it. The call succeeds, and the server returns a
`_warning` telling you the pattern was treated literally. **Read that warning
and tell the user** — the tag looks fine and is wrong. If you need a pattern
across cross-references, use `xrefs` alone.

### Tagging use-case playbook

Common real-world tagging goals → the selector to reach for:

- **IoT / device fingerprinting** (correct assets Nessus mislabels as "Linux"):
  SSL-cert appliances via `plugin=10863` + `plugin_output=`; local-network IoT
  (e.g. Chromecast) via `plugin=66717`; MAC OUI via `plugin=35716`.
- **Software inventory** ("where is `<package>`?"): `plugin_name=`, or `plugin=`
  + `plugin_output=` against software plugins (20811 Win / 22869 Linux /
  83991 Mac), or a `query=` on the `software` table. Classic case: find
  tcpdump / wireshark.
- **Plugin family** ("where am I using `<tech>`?", e.g. AI): `query=`
  `"SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_family='Artificial Intelligence';"`
  — no native family selector, so use `query`.
- **User access / offboarding** (which assets a local user can reach): `query=`
  on the local-user enumeration plugins (95928 Linux / 71246 Windows), matching
  the username in plugin output.
- **CISA KEV** (actively-exploited): `xrefs="CISA"`, kept **ephemeral** — on
  each KEV release, refresh accurately via clear (`remove=True`) → wait →
  re-apply. See the ephemeral pattern below.
- **Bulk by CVE from an external CSV** (e.g. MITRE ATT&CK→CVE): the `cve=`
  selector in a download→parse→loop — worked example in
  **`references/tag-by-cve-external-csv.md`** (`navi://skill/enrich/tag-by-cve-external-csv`).
- **Slow-to-scan assets**: `scantime=<minutes>` (e.g. "Long Scan Times").

## The `remove=True` ephemeral tagging pattern (TWO STEPS)

**The problem**: without refreshing, tags accumulate. Fixed assets stay
tagged. A credential-failure tag run twice = 12 tagged on Monday, 8 fixed
Tuesday, still 12 tagged.

**What `remove=True` actually does**: it is a **CLEAR**, not a reassignment.
navi's `-remove` looks up the tag's UUID and strips the tag from **every
asset currently carrying it** — and it **ignores any selector** you pass.
It does not "replace old membership with new" in a single call.

### The most accurate refresh is TWO calls with a wait between them

This two-step is the pattern that keeps the tag as accurate as possible. It's
the recommended default for a true refresh — but it's a **choice**, not a hard
rule: when the difference is moot (first-time creation, or you deliberately just
want to add/update the current set), a single selector call — or even a combined
`remove=True` + selector call — is fine.

1. **Clear** — `remove=True`, no selector:

   `navi_enrich_tag(category="Scan Health", value="Cred Failure", remove=True, confirm=True)`

2. **Wait ~30 minutes** for the removal to propagate.

3. **Re-apply** — same `category`/`value`, the selector, **no `remove`**:

   `navi_enrich_tag(category="Scan Health", value="Cred Failure", plugin=104410, confirm=True)`

> **Avoid combining them in one call.** `navi_enrich_tag(..., plugin=104410,
> remove=True)` is allowed but the tool returns a `_warning`. In navi, the
> selector adds and `-remove` strips as two independent jobs in the same
> command — so it only adds/updates against the tag's *current* membership
> rather than doing a clean refresh, and can strip assets that should have
> stayed tagged. It's not forbidden (sometimes an add-before-remove is what you
> want), just flagged as potentially inaccurate. Splitting into clear → wait →
> re-apply is the accurate refresh; surface the warning to the user if you do
> combine them.

### Tag UUID preservation — why the two-step matters

Both steps target the same `category` + `value`, so the tag's **UUID stays
intact** across the refresh. This matters because **access groups, API
integrations, saved dashboards, and external automation reference tags by
UUID**. Deleting a tag and recreating it — even with the same category and
value — generates a NEW UUID and silently breaks every downstream reference.

Do NOT use `navi_action_delete(kind="tag", ...)` followed by a fresh
`navi_enrich_tag(...)` to "rotate" a tag's contents. That's the UUID-breaking
pattern. Use the clear → wait → re-apply cycle instead.

### Operational health tags — the re-apply selectors

Each of these is the **re-apply (step 3)** call. Precede it with a step-1
clear of the same `category`/`value` (`remove=True`, no selector) and a
~30-minute wait whenever you're refreshing an existing tag.

Cred failure: `navi_enrich_tag(category="Scan Health", value="Cred Failure", plugin=104410, confirm=True)`

Auth issue: `navi_enrich_tag(category="Scan Health", value="Auth Issue", plugin=21745, confirm=True)`

Slow scan: `navi_enrich_tag(category="Scan Health", value="Slow Scan", scantime=30, confirm=True)`

Reboot required: `navi_enrich_tag(category="Remediation", value="Reboot Required", plugin=35453, confirm=True)`

CISA KEV: `navi_enrich_tag(category="CISA", value="KEV", xrefs="CISA", confirm=True)`

Cert expiry (stable value, rotating query): `navi_enrich_tag(category="CertExpiry", value="ExpiringSoon", query="SELECT asset_uuid FROM certs WHERE not_valid_after LIKE 'Apr%2026%';", confirm=True)`

### Monthly cert expiry rotation — the right way

Use a stable tag value and rotate only the query; the UUID never changes so
downstream references to `CertExpiry:ExpiringSoon` keep working. Each month:
clear the tag (step 1), wait ~30 min, then re-apply with the new month's query
(step 3).

Step 1 (clear): `navi_enrich_tag(category="CertExpiry", value="ExpiringSoon", remove=True, confirm=True)`

Step 3 this month: `navi_enrich_tag(category="CertExpiry", value="ExpiringSoon", query="SELECT asset_uuid FROM certs WHERE not_valid_after LIKE 'May%2026%';", confirm=True)`

Step 3 next month — same tag, new query: `navi_enrich_tag(category="CertExpiry", value="ExpiringSoon", query="SELECT asset_uuid FROM certs WHERE not_valid_after LIKE 'Jun%2026%';", confirm=True)`

Month patterns: `Jan%2026%`, `Feb%2026%`, `Mar%2026%`, ..., `Dec%2026%`.

For a "certs expiring in the next N days" rotation that doesn't need month
boundaries (still clear → wait → re-apply):

`navi_enrich_tag(category="CertExpiry", value="Next60Days", query="SELECT asset_uuid FROM certs WHERE date(not_valid_after) <= date('now', '+60 days') AND date(not_valid_after) >= date('now');", confirm=True)`

### When do you actually need the clear step?

Think of it as a spectrum of how fast the tagged fact changes:

- **Fast-changing / point-in-time state** (cred failures, "reboot required",
  "cert expiring this month") — refresh often, and the clear → wait → re-apply
  keeps it accurate. This is where `remove=True` earns its keep.
- **Stable / slow-changing classifications** (Environment, OS, Route, or a
  hardware tag like `Hardware:iDRAC`) — assets that match tend to keep matching
  for months or years. New assets joining just get **added** on the next
  selector run; almost nothing needs removing. You can go a long time — often
  indefinitely — without ever running the clear step. Running it here is
  usually wasted effort (and a needless 30-min propagation wait).

So the clear step is a tool for churn, not a ritual. Match it to how volatile
the underlying condition is. First-time creation of any tag also needs no clear
(there's nothing to clear yet) — just the selector call.

**Trigger for the ephemeral refresh**: user says "assets are still tagged
after we fixed them," "the tag is stale," "I deleted the tag and now my access
group is broken," or "how do I refresh a tag."

---

## Certificate expiry tagging (scale fork)

Check count first:

`navi_explore_query(sql="SELECT count(uuid) FROM assets;")`

These are the **re-apply (selector)** calls. For an accurate refresh of an
existing tag, precede each with a step-1 clear (`remove=True`, no selector) and
a ~30-min wait; on first creation the clear is unnecessary.

**PATH A — under 50K (plugin regex):**

`navi_enrich_tag(category="CertExpiry", value="ExpiringSoon", plugin=10863, plugin_output="Not After\s*:\s*Apr\s+\d{1,2}\s+[\d:]+\s+2026", regexp=True, confirm=True)`

```bash
navi enrich tag --c "CertExpiry" --v "ExpiringSoon" \
  --plugin 10863 --output "Not After\s*:\s*Apr\s+\d{1,2}\s+[\d:]+\s+2026" -regexp
```

> `-regexp` is a **boolean flag** — the pattern belongs to `--output`, not to
> `-regexp` itself. Writing `-regexp "<pattern>"` makes click read the pattern
> as a stray argument and the search text goes missing.

**PATH B — over 50K (certs table — much faster):**

First populate the certs table: `navi_config(kind="certificates")` — note
`navi_config`, **not** `navi_config_update`; there is no `certificates` update
kind (see navi-core).

Then:

`navi_enrich_tag(category="CertExpiry", value="ExpiringSoon", query="SELECT asset_uuid FROM certs WHERE not_valid_after LIKE 'Apr%2026%';", confirm=True)`

```bash
navi enrich tag --c "CertExpiry" --v "ExpiringSoon" \
  --query "SELECT asset_uuid FROM certs WHERE not_valid_after LIKE 'Apr%2026%';"
```

Both PATH A and PATH B use a stable value (`ExpiringSoon`), so the tag UUID is
preserved across monthly rotations. See "Monthly cert expiry rotation" above
for the clear → wait → re-apply cycle.

Month patterns: `Jan%2026%`, `Feb%2026%`, `Mar%2026%`, etc.


---

## Software tagging (scale fork)

**PATH A — under 50K:**

Linux:

`navi_enrich_tag(category="Software", value="Splunk", plugin=22869, plugin_output="splunk", confirm=True)`

Windows:

`navi_enrich_tag(category="Software", value="Splunk", plugin=20811, plugin_output="splunk", confirm=True)`

```bash
navi enrich tag --c "Software" --v "Splunk" --plugin 22869 --output "splunk"  # Linux
navi enrich tag --c "Software" --v "Splunk" --plugin 20811 --output "splunk"  # Windows
```

**PATH B — over 50K:**

First populate the software table: `navi_config(kind="software")`

Then:

`navi_enrich_tag(category="Software", value="Splunk", query="SELECT asset_uuid FROM software WHERE software_string LIKE '%splunk%';", confirm=True)`

```bash
navi enrich tag --c "Software" --v "Splunk" \
  --query "SELECT asset_uuid FROM software WHERE software_string LIKE '%splunk%';"
```

Requires credentialed scans. No data? Check for cred failures via
`navi_explore_data(subcommand="creds")`.

---

## ACR adjustment — see navi-acr

Adjusting Asset Criticality Ratings (`navi_enrich_acr`) has its own skill
file. ACR workflows are conceptually distinct from tagging — tagging
establishes which assets are what; ACR assigns criticality to those
tagged groups.

The typical sequence is:

1. **Tag by business tier** (this skill) — `navi_enrich_tag` with
   categories like `Environment:Production`, `Data Class:PII`, etc.
2. **Set ACR per tag** (navi-acr) — `navi_enrich_acr` with business-
   appropriate scores and required Change Reasons.
3. **Re-sync** — `navi_config_update(kind="assets")` so Tenable One
   recalculates AES across dashboards.

See navi-acr for the full `navi_enrich_acr` tool signature, Change Reason
mapping, mod set/inc/dec semantics, suggested tier mapping (10/9/8/6/3/2),
and temporary ACR adjustments for incident workflows.

**Trigger phrases that should route to navi-acr instead of here**: "adjust
ACR", "risk scores are wrong", "Tenable One isn't showing the right
things", "set production assets as most critical", "calibrate criticality",
"how do I improve my AES scores."

---

## `navi_enrich_add` — add assets from external sources

Each call is write-gated. Pass either `ip` (single) or `list_csv` (bulk),
not both.

Single IP:

`navi_enrich_add(ip="192.168.1.100", confirm=True)`

```bash
navi enrich add --ip 192.168.1.100
```

IP with optional identity fields — `hostname`, `fqdn`, `mac`, `netbios`
(`mac` matters for OT/IoT, where MAC OUI is the reliable fingerprint):

`navi_enrich_add(ip="192.168.1.100", hostname="web-prod-01", fqdn="web-prod-01.corp.com", mac="00:11:22:33:44:55", confirm=True)`

```bash
navi enrich add --ip 192.168.1.100 --hostname "web-prod-01" --fqdn "web-prod-01.corp.com" --mac "00:11:22:33:44:55"
```

CSV import — the tool param is `list_csv`, but the CLI flag is **`--file`** (not
`--list`). CSV column order is IP, MAC, FQDN, Hostname.

`navi_enrich_add(list_csv="assets.csv", source="CMDB", confirm=True)`

```bash
navi enrich add --file assets.csv --source "CMDB"
```

AWS inventory:

`navi_enrich_add(list_csv="aws_inventory.csv", source="AWS", confirm=True)`

```bash
navi enrich add --file aws_inventory.csv --source "AWS"
```

Use for: CMDB imports, OT/IoT devices that can't be actively scanned,
newly provisioned hosts between scan cycles.

---

## Quick reference table

All `navi_enrich_tag` args:

| Arg | Does | Example |
|--------|------|---------|
| `plugin` | Plugin fired (int) | `plugin=104410` |
| `plugin_output` | Text in output (requires `plugin`) | `plugin_output="splunk"` |
| `plugin_regexp` | *Deprecated* — regex in output (requires `plugin`). Use `plugin_output=` + `regexp=True` | `plugin_regexp="jenkins 2\.\d+"` |
| `regexp` | LIKE → REGEXP for text selectors only (`plugin_output`, `plugin_name`, `cpe`, `xrefs`, `by_val`, `by_cat`); raises otherwise | `regexp=True` |
| `plugin_name` | Text in plugin name | `plugin_name="Apache"` |
| `cve` | CVE ID | `cve="CVE-2021-44228"` |
| `cpe` | CPE string | `cpe="cpe:/a:apache"` |
| `xrefs` | Cross-ref type | `xrefs="CISA"` |
| `xid` | Cross-ref ID (requires `xrefs`) | `xid="2024-001"` |
| `port` | Vuln on port (int) | `port=3389` |
| `route_id` | Route ID | `route_id="<id>"` |
| `file` | CSV of IPs | `file="assets.csv"` |
| `manual` | Asset UUID | `manual="<uuid>"` |
| `group` | Agent group | `group="Prod"` |
| `missed` | Missed auth N days (int) | `missed=7` |
| `byadgroup` | AD group CSV | `byadgroup="ad.csv"` |
| `scanid` | Assets in scan | `scanid="<id>"` |
| `histid` | Scan history ID (requires `scanid`) | `histid="<id>"` |
| `scantime` | Scan > N min (int) | `scantime=30` |
| `query` | Custom SQL | `query="SELECT ..."` |
| `by_tag` | Has this tag | `by_tag="Env:Prod"` |
| `by_val` | Match tag value | `by_val="Prod"` |
| `by_cat` | Match tag category | `by_cat="CVE"` |
| `parent_category` | Parent category (hierarchical) | `parent_category="Region"` |
| `parent_value` | Parent value (hierarchical) | `parent_value="Americas"` |
| `require_both` | AND logic with parent | `require_both=True` |
| `remove` | Ephemeral refresh | `remove=True` |
| `tone` | TONE tag instead of TVM | `tone=True` |
| `description` | Tag description | `description="auto-tagged by navi"` |
