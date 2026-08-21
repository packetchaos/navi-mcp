---
name: navi-core
description: >
  Core reference for Tenable navi CLI: installation, API keys, database sync,
  version detection, navi.db schemas, tagging timing, and the 50K asset scale
  fork. Use for setup and core mechanics: "how do I install navi?", "set up
  navi", "update my database", "what tables does navi have?". Covers the full
  `config update` option set and how to bound a sync - `days` vs. the `since`
  (vulns) and `updated_at` (assets) watermark filters; the list-valued
  `state`, `severity` and `plugin_id`, where `state`/`severity` REPLACE navi's
  default rather than narrowing it; and `navi_config_rebuild`, the destructive
  tool that drops and re-creates a table. Trigger on "sync only what changed",
  "incremental update", "nightly sync", "start over", "rebuild my vulns
  table", "sync only criticals", "my sync takes too long". Also covers FedRAMP
  URL config, SLA setup, Docker, threads, SQL indexes, the multi-workload
  pattern, and the 30d/90d `update full` defaults. For fix-it workflows use
  navi-troubleshooting.
---

# Navi Core — Setup, Config & Schema

Navi is a CLI tool by packetchaos that wraps the Tenable VM API. All data is stored
in a local SQLite file (`navi.db`). Five command categories: Configuration, Enrichment,
Exploration, Action, Exportation.

**Companion skills — use these for deeper coverage:**
- `navi-mcp` — conventions for using navi through the navi-mcp server
- `navi-troubleshooting` — fix-it workflows for errors, empty results, slow tagging, post-upgrade issues
- `navi-enrich` — all tagging options, `remove=True` ephemeral pattern, tag UUID preservation
- `navi-acr` — Asset Criticality Rating adjustment, Change Reasons, tier mapping
- `navi-explore` — `explore data` and `explore info` full reference
- `navi-export` — all CSV export commands
- `navi-scan` — scan creation, control, evaluate
- `navi-action` — delete, rotate, cancel, encrypt/decrypt
- `navi-mail` — `navi_action_mail`, email harness (double-gated: `NAVI_EMAIL`)
- `navi-remote-exec` — `navi_action_push`, remote-exec harness (double-gated: `NAVI_REMOTE_CODE_EXECUTION`)
- `navi-was` — WAS integration

This skill has two setup paths. Read whichever matches your situation:

- **Running under navi-mcp** → jump to "Setup under navi-mcp" below. Keys and
  installation are handled by your operator; your job is the initial data sync
  and knowing when to re-sync.
- **Installing navi standalone** → see **`references/installation.md`**
  (`navi://skill/core/installation`) for the full install-from-zero walkthrough.

---

## Setup under navi-mcp

If Claude has `navi_*` tools available, navi is already installed and the
navi-mcp server is already running. Three things still apply:

### 1. API keys are set out-of-band

Your operator sets API keys when starting the navi-mcp server. Claude does
not see or manage them. If a query returns empty or commands fail with no
data, the most likely cause is either (a) keys scoped to a subset of
assets, or (b) keys not set at all. Check `navi://workdir` for write-gate
status; for key scope, verify in the Tenable platform directly. See
navi-mcp for the full stance.

### 2. Run `navi config update full` at least once before using the tools

This is the foundational data sync that populates navi.db from the Tenable
platform. **Without it, navi.db is empty and every query returns nothing.**

**Default windows: 30 days of vulns, 90 days of assets.** `update full` is
not "all of history" unless you widen it — `--days N` moves both windows,
and `--since` / `--updated_at` override them per export. See "Choosing a
sync window" below.

`navi config update full` is NOT exposed as an MCP tool — first-run syncs
can pull hundreds of GB and run for hours, which is not well-handled by a
tool-call lifecycle. Run it at your terminal:

```bash
navi config update full
```

Scope a full sync to a single tag with `--c`/`--v` (handy for a per-tag /
per-business-unit navi instance): `navi config update full --c "<category>" --v "<value>"`.

After the initial sync completes, you can use `navi_config_update(kind=...)`
for targeted incremental refreshes — those finish in minutes and are fine
as tool calls. See "Targeted database sync (MCP-exposed)" below.

#### Recommended: run `navi config optimize` after the first sync

In navi 8.5.31+, run `navi config optimize` once after the first
`navi config update full` completes:

```bash
navi config optimize
```

This builds a curated set of indexes against the `vulns` table and makes
tagging, querying, and exporting noticeably faster — often the difference
between a tag operation taking hours vs. seconds.

`navi config update full` does NOT build these indexes itself, so without
optimize you'll see slow performance until you run it. Note that targeted
`navi_config_update(kind="vulns")` calls through MCP DO build indexes
automatically — so users running incremental refreshes through the tool
get this for free, but users who only ever do `update full` need to run
optimize separately.

Optimize takes seconds against a populated database. If you run it
against an empty navi.db (no syncs have happened yet) it will print
"no such table: main.vulns" errors per index — that's benign, just
re-run after a sync. See navi-troubleshooting for the specific error.

Indexes survive `navi_config_update(kind=...)` calls. They do NOT
survive deleting navi.db. After any post-upgrade recovery (delete +
re-keys + re-sync), re-run optimize.

### 3. After upgrading navi, you need to recover navi.db

Navi version upgrades cause a schema mismatch with any existing navi.db.
Recovery under navi-mcp is a multi-channel operation — neither Claude nor
the MCP server can do all of it:

1. **You (at the CLI):** delete the old database.
   ```bash
   rm navi.db
   ```
   Use `navi://workdir` to confirm where it lives.

2. **Your operator:** re-enter API keys into the navi-mcp server
   configuration and restart it. Keys are stored in navi.db and are lost
   when it's deleted.

3. **You (at the CLI):** re-sync.
   ```bash
   navi config update full
   ```

4. **You (at the CLI, navi 8.5.31+):** rebuild indexes — `navi config update full`
   does not create them, and they were dropped when navi.db was deleted.
   Without this step, tagging and queries will be much slower than they
   were before the upgrade.
   ```bash
   navi config optimize
   ```

5. **Back to Claude:** once navi.db exists again, is populated, and is
   indexed, resume your MCP workflows.

Store API keys securely outside of navi.db (password manager, environment
variables) so the out-of-band step in (2) is quick after an upgrade.

---

## Standalone installation

Installing navi directly — Python 3.12+, Docker build, API key entry,
key-permission scoping, version detection, and standalone post-upgrade
recovery — is operator-only and already done for you under navi-mcp. Full
walkthrough lives in **`references/installation.md`** (via the resource:
`navi://skill/core/installation`).

> Key-scope reminder (the one install fact that bites later): navi only sees
> what the API key can see. A key scoped to a subset of assets silently
> returns partial data — the usual cause of "missing assets" / "zero chunks."
> See navi-troubleshooting for the diagnostic ladder.

---

## Targeted database sync (MCP-exposed)

Once navi.db exists and has had a `navi config update full` run at least
once, targeted refreshes are exposed through MCP as `navi_config_update(kind=...)`.
Each finishes in minutes rather than hours and is safe to call as a tool.

> **⚠️ Long syncs must run on the CLI, not through MCP.** The "minutes
> rather than hours" expectation above holds for most tenants — but on a
> large tenant a `vulns` (or full-size `assets`) refresh can run for tens
> of minutes to **hours**. MCP tool calls are synchronous and the client
> enforces a hard tool-call timeout (currently around 4 minutes in Claude
> Desktop) that **cannot be raised from Claude's side** — it's set by the
> MCP host, not by navi or navi-mcp, and there is no tool parameter to
> extend it. When a sync exceeds that window the tool call fails with a
> timeout even though the export usually keeps running on the Tenable
> side, leaving you with no progress visibility and the local subprocess
> still holding navi.db open.
>
> **Rule of thumb:**
> - **Through MCP** — incremental refreshes you're confident will finish
>   in a few minutes (small/scoped tenants, a watermark, or a short
>   `days=N` window). `navi_config_update(kind="vulns", since=<last sync>)`
>   for a nightly catch-up is the canonical example.
> - **On the CLI** — any first-time pull, full-size refresh, or anything
>   on a large tenant. Run it at a terminal where it can take as long as
>   it needs, throttling threads if the disk is slow:
>
>     ```bash
>     navi config update vulns --threads 1
>     navi config update assets
>     ```
>
> **Narrowing the window is the practical lever that keeps a vulns refresh
> inside the MCP call budget, and `since` narrows harder than `days`.** A
> watermark asks only for what changed since the last sync; `days=7` asks
> for the last week every time, re-downloading the overlap. If a
> `days=N` call is timing out, try `since=<timestamp of the last successful
> sync>` before dropping to the CLI. On vulns you can narrow further still
> without leaving MCP — `severity=["critical","high","medium","low"]` (drops
> `info`, usually most of the rows), `plugin_id=[...]`, `state=`,
> `category=`+`value=` are all tool parameters, and the scope is applied by
> the Tenable export rather than after download. See the option reference
> below. A full-history pull
> should always be CLI. For recovery steps when a sync does time out
> (including what to do about the stuck subprocess and the DB lock that
> often follows), see navi-troubleshooting's "Long-running operations
> and MCP timeouts". This is the same reasoning that keeps
> `navi config update full` off the MCP surface entirely.

`navi_config_update(kind="assets")` — assets only
`navi_config_update(kind="vulns")` — vulns only
`navi_config_update(kind="compliance")` — compliance checks (required before
`navi_export(subcommand="compliance")`)
`navi_config_update(kind="agents")` — agent data (required before agent-based
tagging: `group`, `missed`, `byadgroup` selectors in navi-enrich)
`navi_config_update(kind="route")` — vuln_route table (technology-level routing)
`navi_config_update(kind="paths")` — vuln_paths table (filesystem/URL paths
per vuln)
`navi_config_update(kind="was")` — WAS apps + findings tables
`navi_config_update(kind="fixed")` — fixed-vuln table (required before
`navi_export(subcommand="failures")` / SLA processing)
`navi_config_update(kind="plugins", size=N)` — full Tenable plugin DB.
**`size` (1000–10000) is REQUIRED for `kind="plugins"`** (it's the API page
size). Can be large/slow on the first run — mind the call budget.

### Scoping parameters — the per-kind allow-list

`navi_config_update` exposes navi's full export-scoping surface, not just the
window. Each parameter is accepted only by the kinds that support it:

| Kind | Accepts |
|---|---|
| `assets` | `days`, `exid`, `threads`, `category` + `value`, `updated_at` |
| `vulns` | `days`, `exid`, `threads`, `category` + `value`, `state`, `severity`, `vpr_score` + `operator`, `plugin_id`, `since` |
| *(same set applies to `navi_config_rebuild`)* | `kind` is `assets` or `vulns` only |
| `fixed` | `days` |
| `plugins` | `size` (required) |
| `agents`, `compliance`, `route`, `paths`, `was` | no scoping parameters |

**Passing a parameter to a kind that doesn't accept it raises**, naming what
was rejected and what that kind does accept. This is deliberate: a filter can
never silently evaporate into a full-scope sync. `kind="assets", since=...`
is an error, not an unfiltered asset pull.

Scope is enforced by the **Tenable export itself**, not filtered after
download — so a narrow parameter genuinely shrinks the transfer, which is
what makes these the right lever against the call budget.

**Argument rules the server enforces:**

- `category` and `value` are navi's `--c`/`--v` pair — supply **both or
  neither**; one alone raises.
- `operator` only has meaning with `vpr_score`; alone it raises.
- `threads` must be 1–20.
- `plugin_id`, `state` and `severity` are **lists** (`plugin_id=[19506,
  51192]`, `state=["open", "reopened"]`), not repeated arguments. A bare
  string is accepted for `state`/`severity` and treated as a one-element
  list. An empty list raises — omit it instead. Duplicates collapse; order
  is preserved.
- `state` and `severity` **replace navi's default rather than narrowing it** —
  see "`state` and `severity` replace, they don't narrow" below before using
  either.

**Warnings come back in the result.** Combinations navi accepts but silently
resolves one way are surfaced as a `_warning` field rather than an error:

- `days` + `since` → "`since` overrides `days` for the vuln export"
- `days` + `updated_at` → "`updated_at` overrides `days` for the asset export"
- `exid` + any other filter → the export already exists, so the filters don't
  re-scope it; chunks come back exactly as that export was built

Read `_warning` when it's present and tell the user what actually ran — it is
the safety net for the override traps described below.

**On timeout, the error carries the equivalent CLI command**, shell-quoted
with the same scoping you asked for and `--threads 1` appended. Hand that to
the user verbatim rather than composing a fresh full sync.

`since` and `updated_at` are not interchangeable, and neither is just a
fancier `days` — **read "Choosing a sync window" below before setting up any
recurring sync.** It covers what each one actually filters on and the one
behavior that surprises people (`since` returns state *changes*, not
last-seen).

> **Certificates are NOT a `config update` kind.** The SSL/TLS cert table is
> populated by **`navi_config(kind="certificates")`** (CLI: `navi config
> certificates`), which parses plugin 10863 into the `certs` table. There is no
> `navi config update certificates`. See "Other configuration" below.

**Standalone CLI equivalents:**

```bash
navi config update assets
navi config update vulns
navi config update compliance
navi config update agents
navi config update route
navi config update paths
navi config update was
navi config update fixed
navi config update plugins --size 10000
navi config certificates          # cert table — NOT `config update certificates`
```

**Agents note:** `navi_config_update(kind="agents")` is NOT included in the
foundational `navi config update full` CLI command — it must be run
explicitly whenever agent data is needed.

---

## Choosing a sync window — `days` vs. `since` / `updated_at`

There are two ways to bound an asset or vuln sync, and they behave
differently. Picking the right one is the single biggest lever on how long
a refresh takes and how much you re-download.

| Lever | Applies to | Meaning | Shape |
|---|---|---|---|
| `days=N` | assets, vulns, fixed | Look back N days **from now** | Relative, recomputed every run |
| `since=<unix>` | vulns | Findings whose **state changed** after this timestamp | Absolute watermark |
| `updated_at=<unix>` | assets | Assets **updated** after this timestamp | Absolute watermark |

**`since` and `updated_at` override `days`.** Passing both is not an error —
the timestamp wins and `days` is ignored. Don't pass both; it only makes the
call ambiguous to whoever reads it later.

`days` and the timestamp filters answer different questions. `days` is a
rolling window: "give me everything from the last week," which on every run
re-downloads the overlap with the previous run. The timestamp filters are a
watermark: "give me everything I haven't seen yet." On a large tenant the
difference between a nightly `days=7` and a nightly watermark sync is
usually an order of magnitude in transferred rows.

### The watermark pattern

The reason these filters exist. Record the moment a sync *starts*, sync,
then use that recorded moment as the next run's floor:

```
t0 = <unix timestamp taken BEFORE the sync starts>
navi_config_update(kind="vulns",  since=t0)
navi_config_update(kind="assets", updated_at=t0)
# persist t0_next = <timestamp taken before THIS run> for the next cycle
```

CLI form:

```bash
# capture the watermark first, then sync
WATERMARK=$(date +%s)
navi config update vulns  --since $(cat ~/.navi/last_vuln_sync 2>/dev/null || echo 0)
navi config update assets --updated_at $(cat ~/.navi/last_asset_sync 2>/dev/null || echo 0)
echo "$WATERMARK" | tee ~/.navi/last_vuln_sync > ~/.navi/last_asset_sync
```

Take the timestamp **before** the sync, not after. A sync that runs for
twenty minutes will miss anything that changed during those twenty minutes
if you stamp the finish time. Overlapping slightly is free — the update is
idempotent; a gap is not.

Both filters take a **Unix epoch integer in seconds**, not a date string
and not milliseconds. Get one with `date +%s` on macOS/Linux,
`[int][double]::Parse((Get-Date -UFormat %s))` in PowerShell, or
`int(time.time())` in Python.

### `since` on vulns is a STATE-CHANGE filter, not a last-seen filter

This is the sharp edge. `--since` returns findings whose **state**
transitioned (open → fixed, new open, reopened) after the timestamp. A
finding that has been sitting open and unchanged since last quarter will
**not** come back in a `since` sync, even though it was re-observed by
every scan in between.

That is exactly what you want for "what changed since I last looked," and
exactly wrong for "rebuild my current picture." Practical consequences:

- **Don't seed a fresh navi.db with `since`.** It will look sparse and the
  gaps won't be obvious. Seed with `update full` or a wide `days`, then
  switch to watermarks.
- **Reconcile periodically.** Run a wider `days` sweep (weekly or monthly,
  e.g. `days=30`) alongside the nightly watermark syncs to catch drift and
  anything the state-change stream missed.
- **`last_found` will look stale** for unchanged findings between
  reconciliation sweeps. That's the filter working as designed — not the
  "stale data" symptom in navi-troubleshooting. Check when you last ran a
  `days` sweep before chasing it.

`updated_at` on assets is less treacherous — Tenable bumps an asset's
`updated_at` on essentially any change to the asset record — but the same
seed-then-watermark advice applies.

### When to reach for which

| Situation | Use |
|---|---|
| First sync / empty navi.db | `navi config update full` (CLI) |
| Nightly or hourly incremental on a large tenant | `since` / `updated_at` watermark |
| "Catch me up, I've been away a week" | `days=7` |
| A vulns sync that keeps blowing the MCP call budget | `since` watermark — usually the smallest possible job |
| Periodic reconciliation against drift | `days=30` sweep |
| Backfilling after "zero chunks" | `days=365` (see navi-troubleshooting) |

---

## Full option reference — `navi config update`

`navi_config_update` mirrors nearly all of these — only `-rebuild` and the
`full` subcommand stay CLI-only. Parameter names mostly match the flags, with
two exceptions worth memorising: `--c`/`--v` become `category`/`value`, and
`--plugin_id` becomes a list.

### `update assets`

| Option | MCP param | Notes |
|---|---|---|
| `--days N` | `days=N` | Relative lookback window |
| `--updated_at <unix>` | `updated_at=<unix>` | Assets updated after this epoch; **overrides `--days`** |
| `--exid <id>` | `exid="<uuid>"` | Download an export that already exists instead of requesting a new one — the recovery path when the export succeeded on Tenable's side but the local ingest died. Other filters do **not** re-scope it; the server returns a `_warning` if you pass any |
| `--threads N` | `threads=N` | 1–20, enforced. Lower on slow disks / low RAM (see navi-troubleshooting's DB-lock section) |
| `--c <category>` / `--v <value>` | `category=` + `value=` | Restrict the sync to one tag — the basis of the multi-workload pattern below. **Both or neither** |
| `-rebuild` | **separate tool:** `navi_config_rebuild(kind="assets")` | **DESTRUCTIVE.** Drops and re-creates the `assets` table, then syncs into it fresh. Single hyphen on the CLI. See "`navi_config_rebuild`" below |

### `update vulns`

| Option | MCP param | Notes |
|---|---|---|
| `--days N` | `days=N` | Relative lookback window |
| `--since <unix>` | `since=<unix>` | Findings with **state changes** after this epoch; **overrides `--days`** |
| `--exid <id>` | `exid="<uuid>"` | Download an existing export by UUID; other filters don't re-scope it |
| `--threads N` | `threads=N` | 1–20, enforced |
| `--c` / `--v` | `category=` + `value=` | Restrict to one tag. **Both or neither** |
| `--state [open\|reopened\|fixed]` (repeatable) | `state=["open", "reopened"]` | A **list**. **REPLACES** navi's default of open+reopened — see "`state` and `severity` replace, they don't narrow" below |
| `--severity [critical\|high\|medium\|low\|info]` (repeatable) | `severity=["critical", "high"]` | A **list**. **REPLACES** navi's default of all five. `info` is usually the bulk of a tenant's rows, so naming the other four is the cheapest way to shrink a vulns sync — and it's now one call, not four |
| `--vpr_score N` + `--operator [gte\|gt\|lt\|lte]` | `vpr_score=7.0` + `operator="gte"` | VPR threshold. `operator` without `vpr_score` raises |
| `--plugin_id N` (repeatable) | `plugin_id=[19506, 51192]` | A **list** through MCP, a repeated flag on the CLI. Empty list raises. The purpose-built-workload lever (see below) |
| `-rebuild` | **separate tool:** `navi_config_rebuild(kind="vulns")` | **DESTRUCTIVE.** Drops and re-creates the `vulns` table, then syncs into it fresh. Single hyphen on the CLI. See "`navi_config_rebuild`" below |

### `update full`

Defaults to **30 days of vulns / 90 days of assets**.

| Option | Notes |
|---|---|
| `--days N` | Moves both windows |
| `--since <unix>` | Overrides `--days` **for the vuln export only** |
| `--updated_at <unix>` | Overrides `--days` **for the asset export only** |
| `--threads N` | 1–20 |
| `--c` / `--v` | Scope the whole sync to one tag |
| `--state` / `--severity` | Applied to the vuln export; both repeatable, and both REPLACE their default |
| `-rebuild` | **DESTRUCTIVE.** Drops and re-creates **both** tables. CLI-only — from MCP it's two `navi_config_rebuild` calls. See below |

Because `--since` and `--updated_at` are per-export overrides here, one
`update full` can carry a wide asset history and a narrow vuln window (or
the reverse) in a single command:

```bash
# assets back to a fixed watermark, vulns only what changed since Monday
navi config update full --updated_at 1750000000 --since 1755000000
```

**Composition:** the filters are AND-ed. `--severity critical --plugin_id
19506 --since <unix>` gives critical findings for plugin 19506 whose state
changed after the watermark. A narrow combination is what makes the
purpose-built workload pattern below cheap to maintain.

### `state` and `severity` replace, they don't narrow

Both are repeatable (`multiple=True` in navi), so through MCP both take a
**list** — `state=["open", "reopened"]`, `severity=["critical", "high"]`. A
bare string still works and is treated as a one-element list; an empty list
raises; duplicates collapse and order is preserved.

> **The trap: supplying either flag REPLACES navi's default rather than
> narrowing it.**
>
> - `--state` defaults to **open + reopened** — *not* fixed.
> - `--severity` defaults to **all five**.
>
> So `state=["fixed"]` gives you fixed findings **only** — it does not add
> fixed to what you already pull. Getting everything including fixed means
> naming all three: `state=["open", "reopened", "fixed"]`.

The practical win is on the severity side. `info` is usually the bulk of a
tenant's rows, and dropping it is now a single call rather than four:

```
navi_config_update(kind="vulns", severity=["critical", "high", "medium", "low"])
```

### `navi_config_rebuild` — start the table over

**DESTRUCTIVE, and its own tool.** `-rebuild` is not a parameter on
`navi_config_update`; it is a separate MCP tool, `navi_config_rebuild`. That
split is deliberate — MCP's `destructiveHint` is per-tool, so a boolean on
`navi_config_update` would have to mark every ordinary refresh destructive or
misreport the rebuild. Keeping them apart lets `navi_config_update` stay
honestly non-destructive.

```
navi_config_rebuild(kind="vulns", days=365, confirm=True)
```

```bash
navi config update vulns -rebuild --days 365      # note the SINGLE hyphen
```

**Gates:** `NAVI_MCP_ALLOW_WRITES=1` **and** per-call `confirm=True`.

**`kind` is `assets` or `vulns` — there is no `full`.** Rebuilding both in one
shot is `navi config update full -rebuild` at the terminal; from MCP it is two
calls.

Every ordinary `config update` is additive — it merges into the existing table.
Rebuild drops the table, re-creates it empty, and downloads into it fresh.

### Why `confirm=True` is structural here, not ceremony

navi calls `click.confirm()` before dropping the table. Under MCP, stdin is
closed, so that prompt would hit EOF and abort the command — which is why
`-rebuild` did not work through MCP at all until this tool existed. The tool
answers navi's prompt on your behalf, and **your `confirm=True` IS that
answer.** It is not a second, decorative confirmation layered on top of
navi's; it is the same one, forwarded. Narrate the drop and get the user's
agreement before you pass it.

### What is and isn't destroyed

**The local navi.db table only. Nothing in Tenable VM changes.** What you lose
is the cached copy and the download time it cost — on a large tenant, hours.
navi.db itself survives, along with everything in it that isn't the dropped
table: API keys, `tags`, `fixed`, `agents`, `epss`, `zipper`, and the WAS
`apps` / `findings` tables.

**Derived tables go stale, not empty.** `certs`, `software`, `vuln_route` and
`vuln_paths` are all computed from asset/vuln data, so after a rebuild they
describe records that no longer exist. The tool's `_notice` says so on every
call — pass it along and refresh them:

```
navi_config(kind="certificates")
navi_config(kind="software")
navi_config_update(kind="route")
navi_config_update(kind="paths")
```

**Expect the indexes to go too.** navi-mcp doesn't say so, but dropping a
table drops its indexes with it in SQLite — so a rebuilt `vulns` should come
back unindexed, and tagging would slow to its pre-optimize speed. Re-running
`navi config optimize` at the CLI costs seconds against a populated table, so
it's worth doing rather than checking.

### When this is the right tool

- A schema mismatch after a navi upgrade.
- A partially-downloaded table from an interrupted sync.
- Duplicate or stale rows an ordinary update won't clear — because an update
  *merges* rather than replaces.

**If the user just wants fresher data, this is the wrong tool.**
`navi_config_update` does that without discarding anything, and is almost
always what was actually meant.

> **⚠️ The dangerous combination is rebuild plus a filter.** The drop is
> unconditional, but the download that follows obeys every scoping parameter —
> so whatever the filter excludes is simply gone, and nothing downstream
> announces it. `navi_config_rebuild(kind="vulns", severity=["critical"],
> confirm=True)` leaves a `vulns` table containing **only** criticals: a much
> smaller database than you started with, not a fresher one. From then on
> every query, tag, export, and dashboard silently reports against that subset.
>
> `state` bites hardest here, because it replaces rather than narrows:
> `state=["open"]` discards your reopened findings too, and the old table is
> already gone by the time the narrowed download runs.
>
> If a deliberately scoped table is the goal, this is the right tool — see the
> multi-workload pattern below. If the goal was "clean up my data," drop the
> filters.

**Never pair a rebuild with `since` / `updated_at`.** It is the worst
combination available: you empty the table, then re-fill it from a watermark
that returns only what changed after that timestamp — and on vulns, only state
*changes*. You end up with a thin slice of recent churn and no baseline
underneath it. Rebuild against a wide `days` (or the defaults), then switch to
watermarks for the refreshes that follow.

**Full sequence after a vulns rebuild:**

```
navi_config_rebuild(kind="vulns", days=365, confirm=True)
navi_config(kind="certificates")
navi_config(kind="software")
navi_config_update(kind="route")
navi_config_update(kind="paths")
```
```bash
navi config optimize      # CLI — the drop very likely took the indexes too
```

---

## Other configuration (MCP-exposed)

### SLA thresholds

`navi config sla` is a **group**, not a single command — it has two subcommands:
`calculate` (compute SLA times against your `fixed` data) and `reset`
(set/overwrite SLA threshold values). A bare `navi config sla` does nothing.

`navi_config(kind="sla")` runs **`config sla calculate`** — **not write-gated,
no confirm required.** It computes SLA times, so populate the `fixed` table
first with `navi_config_update(kind="fixed")`. Meaningful
`navi_export(subcommand="failures")` output depends on this.

```bash
navi config sla calculate          # what the MCP tool runs
```

**Setting/overwriting the thresholds themselves** is `navi config sla reset`,
which is **interactive** (it prompts for per-severity values). Run it at the
terminal — the MCP tool does not drive it:

```bash
navi config sla reset
```

### Software table build (not write-gated)

Parses software inventory plugins (22869, 20811, 83991) into the `software`
table. Local DB operation, doesn't touch the Tenable platform.

`navi_config(kind="software")`

```bash
navi config software
```

### Certificate table build (not write-gated)

Parses plugin 10863 (SSL Certificate Information) into the `certs` table. Local
DB operation, doesn't touch the Tenable platform. Required before large-scale
cert tagging (see Scale Fork below).

`navi_config(kind="certificates")`

```bash
navi config certificates
```

This is the correct cert-table command. It is **not** `navi config update
certificates` — that subcommand does not exist. (Plugin 10863 doubles as an
IoT/appliance fingerprint — dumped certs identify devices — not just an
expiry source; see navi-enrich's device-fingerprinting playbook.)

### FedRAMP / custom base URL (write-gated)

Change the Tenable base URL (FedRAMP tenants, test environments).

`navi_config(kind="url", url="https://fedcloud.tenable.com", confirm=True)`

```bash
navi config url "https://fedcloud.tenable.com"
```

---

## Tagging timing

After a tagging write (`navi_enrich_tag`, `navi_enrich_acr`), allow **up to
30 minutes** for tags to be fully visible in the Tenable UI/API before
re-syncing. This is a platform-side propagation delay, not a navi delay.

Two implications for MCP workflows:

1. **Verification via `navi_explore_query` reflects reality fast** — it
   reads navi.db, which navi just wrote to. Use this for fast verification
   that the tag was applied.
2. **Verification via Tenable UI or `navi_explore_info` can lag** — these
   read from the platform, which is still propagating. If the user looks
   at the UI immediately after a tag write and doesn't see it, that's
   expected, not broken.

To surface the new tags back into navi.db after the propagation window,
run `navi_config_update(kind="assets")` or a targeted refresh. For a full
data refresh after significant tag changes, `navi config update full` at
the CLI is the authoritative sync.

---

## navi.db — location, scope, and the multi-workload pattern

`navi.db` is created in **whichever directory you run navi commands from**.
This is a deliberate design feature, not a limitation.

Under navi-mcp, the workdir is fixed by the server config. Check
`navi://workdir` to see where it is.

**Why this matters**: you can maintain multiple, purpose-built navi
databases by running navi from different directories. Each database
contains only the data you synced into it — making queries faster and
tagging operations significantly quicker when working on a specific subset.

```bash
# Full environment database
mkdir ~/navi-full && cd ~/navi-full
navi config keys --a <KEY> --s <KEY>
navi config update full          # everything — large, comprehensive

# Purpose-built workload: only assets with a specific plugin
mkdir ~/navi-jenkins && cd ~/navi-jenkins
navi config keys --a <KEY> --s <KEY>
navi config update vulns --plugin_id 12345 --days 365
# Results: smaller DB, faster tagging, faster queries

# Keep it current cheaply — only what changed since the last run
navi config update vulns --plugin_id 12345 --since 1755000000
```

`--plugin_id` is repeatable, so a workload can cover a set of related
plugins: `--plugin_id 22869 --plugin_id 20811 --plugin_id 83991` builds a
software-inventory-only database. Pair the initial wide pull with a
`--since` watermark for refreshes and the workload stays small
indefinitely.

**The Exposure Management Environment pattern**: treat each navi directory
as a scoped workload environment — a compliance audit, a specific
vulnerability campaign, a WAS-only view, a single business unit. Navi runs
independently in each directory. The smaller the database, the faster
every operation against it.

**If tagging against a specific plugin is slow**: create a purpose-built
workload that only contains assets where that plugin fired. Smaller
dataset = faster tagging. The alternative is adding a SQL index (see
Troubleshooting below).

**Under navi-mcp, the multi-workload pattern is operator-side.** Each
workload environment would need its own navi-mcp server instance pointed
at its own directory. Claude operates against whichever single workdir
the current server is configured for.

---

## Scale Fork — 50K asset threshold

Two workflows exist for certificate and software tagging depending on
environment size. Always check first:

`navi_explore_query(sql="SELECT count(uuid) FROM assets;")`

```bash
navi explore data query "SELECT count(uuid) FROM assets;"
```

- **Under 50K**: use `plugin` + `plugin_output` or `plugin_regexp` (simpler, no
  extra download)
- **Over 50K**: use dedicated tables (`certs`, `software`) via `query=...`
  (much faster at scale)

See navi-enrich for full PATH A / PATH B workflows on both certs and
software tagging.

---

## Key SSL/TLS Certificate Plugins

| Plugin | Description |
|--------|-------------|
| `10863` | SSL Certificate Information (expiry dates) |
| `15901` | Weak Hashing Algorithm (SHA-1) |
| `42981` | Cannot Be Trusted (chain) |
| `51192` | Untrusted / expired / self-signed |
| `69511` | RSA key < 2048 bits |
| `60108` | Weak RSA key in chain |

---

## Database Schema Reference

The full table-by-table schema for navi.db — every table, its columns, how it's
populated, and how tables join — lives in **`references/schema.md`** (via the
resource: `navi://skill/core/schema`). Load it when composing non-trivial
queries. For a single table's columns, prefer the live `navi://schema/{table}`
resource, which can't go stale.

Quick orientation: `vulns`/`assets`/`plugins`/`tags`/`fixed`/`agents` come from
core syncs; `certs`/`software`/`compliance`/`epss`/`zipper` are targeted builds;
`vuln_route`/`vuln_paths` are routing tables; `apps`/`findings` are WAS.

---


## DISTINCT — the workload reality check

The `vuln_paths` table shows each path × plugin combination. A single path
can have 10+ plugins firing against it — but it's still **one fix location**.

```sql
-- Raw count (inflated — same path appears many times)
SELECT count(*) FROM vuln_paths;

-- TRUE workload — distinct locations a remediator actually needs to visit
SELECT count(DISTINCT path) FROM vuln_paths;
```

Real example: 148 raw entries → 28 distinct fix locations = **81% workload
reduction**. Always use DISTINCT when communicating workload to remediators.

---

## Quick Command Map

| Need | MCP tool call / CLI |
|------|---------|
| Set API keys | CLI only, out-of-band: `navi config keys --a ... --s ...` |
| Full foundational sync | CLI only: `navi config update full` (30d vulns / 90d assets by default) |
| Sync assets | `navi_config_update(kind="assets")` |
| Sync vulns | `navi_config_update(kind="vulns")` |
| Sync only what changed since last time (vulns) | `navi_config_update(kind="vulns", since=<unix>)` |
| Sync only what changed since last time (assets) | `navi_config_update(kind="assets", updated_at=<unix>)` |
| Sync one plugin / severity / state only | `navi_config_update(kind="vulns", plugin_id=[N])` / `severity=` / `state=` |
| Re-download a failed export by ID | `navi_config_update(kind="vulns", exid="<uuid>")` |
| Drop and re-create a table, then sync fresh | `navi_config_rebuild(kind="vulns", confirm=True)` — destructive, write-gated |
| Sync agents | `navi_config_update(kind="agents")` |
| Build routing + paths tables | `navi_config_update(kind="route")` then `navi_config_update(kind="paths")` |
| Build cert table | `navi_config(kind="certificates")` (CLI: `navi config certificates`) |
| Build fixed table (SLA) | `navi_config_update(kind="fixed")` |
| Build full plugin DB | `navi_config_update(kind="plugins", size=10000)` (size required) |
| Build software table | `navi_config(kind="software")` |
| Build EPSS table | CLI only: `navi config epss` (downloads EPSS CSV and populates the `epss` table) |
| Build indexes for fast tagging/querying (8.5.31+) | CLI only: `navi config optimize` |
| Check version | `navi_explore_info(subcommand="version")` |
| Inspect table schema | `navi://schema/{table}` resource, or `navi_explore_data(subcommand="db_info", table=...)` |
| Spot-check an asset | `navi_explore_data(subcommand="asset", asset=<IP_or_UUID>)` |
| See workdir + write-gate status | `navi://workdir` resource |
| Reset after upgrade | See "After upgrading navi" above |

---

## Troubleshooting — see navi-troubleshooting

Full per-symptom fix guidance lives in the `navi-troubleshooting` skill.
The most frequent issues and their fixes:

| Symptom | Most likely cause | Fix |
|---|---|---|
| "Zero chunks" on update | Empty window, broken scanners, or key scope | Wider window first (`--days 365`), then scanner health, then key scope. See navi-troubleshooting |
| DB locked error | Slow disk | `--threads 1` on full sync |
| DB locked + low RAM | Under 4GB RAM | `--threads 1` + close other apps |
| Tagging very slow | Large DB, no index | SQL index or purpose-built workload |
| No results from any command (MCP) | navi.db empty or keys out-of-band | Run `navi config update full` at CLI; verify with operator |
| No results from any command (standalone) | Keys not set | `navi config keys --a ... --s ...` |
| DB errors after upgrade | Schema mismatch | `rm navi.db` + re-keys + `update full` |
| Missing assets | Key scoped to subset | Check key permissions in Tenable One |
| Agent tags return zero | Stale agents table | `navi_config_update(kind="agents")` |
| `navi_config_update` times out after ~4 min | Sync longer than MCP client timeout (big tenant, usually vulns) | Shrink with `since=<last sync>` first, then `days=N`; else CLI: `navi config update vulns --threads 1` |
| Vulns look stale but syncs report success | Running `since` watermarks only — unchanged findings never re-appear | Run a periodic `days=30` reconciliation sweep. See "Choosing a sync window" |
| A table lost most of its rows | `-rebuild` run with a filter — the drop is unconditional, the re-fill is filtered | Re-run `-rebuild` with a wide `--days` and no filters. See "`-rebuild`" |

For full context on each symptom — root cause, resolution steps, MCP vs.
standalone variants — see **navi-troubleshooting**.

**Preventive context**: the key-scope reminder in "Standalone installation"
above (and the full "API key permissions matter" detail in
`references/installation.md`) explains why scoped keys cause Zero Chunks later.
The multi-workload pattern explains how purpose-built navi directories reduce
tagging slowness structurally. Both are install-time concerns;
navi-troubleshooting covers the reactive fixes.
