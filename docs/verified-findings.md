# Phase A — Verified Findings & Server Patches

Reconciled against `navi_documentation.txt` (recursive `--help` dump, generated
**2026-06-07**, navi tree exit 0 throughout). This supersedes the *provisional*
coverage status of ledger item A6 — coverage is now verified against ground truth.

Line numbers reference `server__1_.py` (1601 lines).

---

## 0. Read this first — how "broken" was determined

These findings come from reading navi's Usage signatures in the dump, **not** from
executing navi (no install/keys in the review environment). The inference is
high-confidence because Click rejects any `--option` a command does not declare:
if the current navi prints `Usage: navi explore data cve [OPTIONS] CVE_ID`, then
`navi explore data cve --cve <X>` fails with "No such option: --cve."

**Decisive validation before mass-patching:** run one live call and watch it fail —
`navi_explore_data(subcommand="cve", cve="CVE-2021-44228")`. If it errors on
`--cve`, the reading is confirmed and every bug below follows the same pattern.

---

## 1. Root cause

The server models nearly every navi argument as a `--flag`. The current navi takes
many arguments **positionally**. Three failure shapes result:

1. **Positional-as-flag** — server sends `--cve X`; navi wants `X`. → Click error.
2. **Wrong command path** — server calls `explore plugin` / `explore asset`; the
   real commands are `explore data plugin` / `explore uuid`. → Click error.
3. **Non-existent subcommand / missing required arg** — server exposes enum values
   navi doesn't have (`delete agent`, `update certificates`), or omits a required
   positional (`action cancel` needs an export UUID). → Click error / no-op.

What works: no-argument subcommands, and the genuinely flag-based commands
(`enrich tag`, `enrich acr`, `export bytag`, `explore data db-info`,
`config url`, `config software`). All verified correct.

---

## 2. Correctness bugs — paste-ready fixes (Blocker)

### 2.1 `navi_explore_data` — 8 of 17 subcommands

| Sub | Does | Current (wrong) | Correct | Line |
|---|---|---|---|---|
| cve | assets with a CVE | `["explore","data","cve","--cve",cve]` | `["explore","data","cve",cve]` | 445 |
| name | plugin-name contains text | `[...,"name","--name",name]` | `[...,"name",name]` | 453 |
| output | plugin-output contains text | `[...,"output","--output",output]` | `[...,"output",output]` | 458 |
| xrefs | by cross-reference | `[...,"xrefs","--type",xref_type]` (+`"--id",xref_id`) | `[...,"xrefs",xref_type]` (+`"--xid",xref_id`) | 463–466 |
| scantime | slow-scanned assets | `[...,"scantime","--minutes",str(minutes)]` | `[...,"scantime",str(minutes)]` | 480 |
| plugin | single plugin lookup | `["explore","plugin",str(plugin_id)]` | `["explore","data","plugin",str(plugin_id)]` | 491 |
| port | assets with vuln on port | `[...,"port","--port",str(port)]` | `[...,"port",str(port)]` | 496 |
| asset | one asset's full detail | `["explore","asset",asset]` | `["explore","uuid",asset]` | 507 |

`db_info` (L512) and the no-arg subs (exploit, docker, webapp, creds, software,
audits, route, paths) are correct — leave them.

> `explore uuid` (the corrected `asset` target) also exposes a rich flag set
> (`-patch`, `-tracert`, `-processes`, `-connections`, `-services`, `-cves`,
> `-vulns`, `-compliance`, `--plugin_id`, …). Out of scope for the bug fix, but a
> strong **coverage** add later — single-asset deep-dive is high-value.

### 2.2 `navi_was` — 5 of 8 subcommands

| Sub | Current (wrong) | Correct | Line |
|---|---|---|---|
| scans | `["was","scans","--config",config_id]` | `["was","scans",config_id]` (positional `CONFIG_UUID`) | 1175 |
| details | `["was","details","--scan",scan_id]` | `["was","details",scan_id]` (positional `SCAN_UUID`) | 1180 |
| scan | `["was","scan","--target",target]` | `["was","scan",target]` (positional `SCAN_TARGET`) | 1195 |
| start | `["was","start","--config",config_id]` | `["was","start",config_id]` (positional `SCAN_ID`) | 1200 |
| upload | `["was","upload","--file",file]` | `["was","upload",file]` (positional `FILENAME`) | 1208 |

configs / stats / export (no-arg) are correct.

### 2.3 `navi_action_delete` — 5 of 6 kinds (most destructive tool)

| Kind | Issue | Fix | Line |
|---|---|---|---|
| asset | `--uuid X` → positional | `["action","delete","asset",uuid]` | 1281 |
| scan | `--id X` → positional | `["action","delete","scan",id]` | 1277 |
| user | `--username X` → positional, **and it's a numeric User ID, not an email** | `["action","delete","user",user_id]`; rename param `username`→`user_id`, fix docstring | 1273 |
| agent | **not a real `action delete` subcommand** | remove from `DeleteKind`. (navi's `config agent remove --aid --gid` is group-membership removal, different semantics — don't silently remap) | 1221, 1282–1285 |
| exclusion | **not a real `action delete` subcommand** | remove from `DeleteKind`. (Exclusions are managed via `config exclude`, unexposed) | 1221, 1286–1289 |

`tag` (`--c`/`--v`, L1269) is correct — keep.

### 2.4 Other tools

| Tool | Issue | Fix | Line |
|---|---|---|---|
| `navi_config_update` | `kind="certificates"` runs `config update certificates`, which **doesn't exist** | Remove `"certificates"` from `UpdateKind`. Populate certs via the real command — add `"certificates"` to `navi_config` (`ConfigKind`) → `["config","certificates"]` (no args, not write-gated, parses plugin 10863; mirrors how `software` is handled) | 195–198, 238 |
| `navi_config` | `kind="sla"` runs bare `config sla`, which is a **group** (`calculate`/`reset`) — bare call is a no-op | Route `kind="sla"` → `["config","sla","calculate"]` (computes SLA times; needs `config update fixed`). Threshold setup (`config sla reset`) is interactive → keep on CLI, document | 270–273 |
| `navi_action_cancel` | never passes the **required** export `UUID` (`action cancel [-a/-v] UUID`) | Add required `uuid: str` param → `["action","cancel",flag,uuid]`. Source the UUID from `explore info exports` | 1318–1332 |
| `navi_enrich_add` | bulk import uses `--list`; the real flag is `--file` | `["enrich","add","--file",list_csv,...]` | 872 |
| `navi_scan` | `create` passes `--name`, which is **not a valid option** | Drop `--name` (and the `name` param, or repurpose). Optional adds: `-discovery`, `--custom <template>` | 1111–1112 |

---

## 3. Coverage gaps (Gap) — real navi commands, neither exposed nor in the exclusion ledger

These are the true blind spots: `U − (M ∪ S − exclusions)`.

### 3.1 `navi scan` — only 4 of 16 subcommands exposed
Exposed: create, start, stop, evaluate. **Missing:**

| Missing | Value | Read/Write |
|---|---|---|
| status | scan run status — natural pair for start/stop | Read |
| details | scan configuration detail | Read |
| history | scan history | Read |
| latest | latest results | Read |
| hosts | hosts in a scan | Read |
| download | download scan results | Read (writes file) |
| pause / resume | scan control — natural pair with start/stop | Write |
| move / change / bridge | scanner reassignment / scan edits | Write |
| upload | import scan results | Write |

Highest-value, lowest-risk adds: **status, details, history, latest, hosts** (reads)
and **pause/resume** (control). This is the single biggest expansion opportunity.

### 3.2 `navi action delete` — valid kinds not exposed
bytag (`TAG_STRING`), category, network, policy, tgroup, tone, usergroup, value,
table, rules. Safe-and-useful: **bytag** (delete assets by tag), **tgroup**,
**usergroup**, **tone**. Dangerous metadata wipes (**table**, **rules**, **value**,
**category**) — expose only deliberately, write-gated, with extra narration.

### 3.3 `navi config` sub-areas — entirely unexposed
- `config certificates` — the real cert populate command (see §2.4). **Expose.**
- `config update` missing kinds: **fixed** (SLA data), **plugins** (plugin DB),
  **tone** (Tenable One), everything, zipper (EPSS+plugin merge). `full` stays CLI.
  Add at least fixed / plugins / tone.
- `config agent` (add/bytag/create/remove/unlink) — agent-group management.
- `config exclude` — scan exclusion windows.
- `config network` (change/move/new) — Tenable network management.
- `config user` (add/disable/enable/group …) — user lifecycle (create/enable/disable).
- `config permissions` (create/migrate) — sensitive; likely intentional exclusion,
  but **record the decision** (currently unrecorded).

### 3.4 `navi explore` — `explore api`, `explore uuid` (known "may expose later")
`explore api` is the passthrough that export-status polling needs (ledger A4).
`explore uuid` is the rich single-asset detail the broken `asset` sub should target.

---

## 4. Exclusion-ledger validation (framework §3)

**Confirmed correct exclusions** (present in navi, rightly not exposed): action
automate, action deploy (+11 subcommands), action plan (+4), action mail, action
push, enrich attribute (+2), enrich migrate, enrich tagrule, config epss, config
optimize, config smtp, config ssh, config scan.

**Naming fix:** the ledger lists `navi keys`; the actual command is **`navi config keys`** (L1097). Update the exclusion-ledger row.

**Unrecorded blind spots** (neither exposed nor in any exclusion list — decide
expose-or-record): everything in §3.1–§3.3 plus `config update {everything, fixed,
plugins, tone, zipper}`. These are the gaps the first pass missed.

---

## 5. Cascade into skills (feeds Phase B)

The arg-form bugs and missing commands surface in the skill docs — fold these in
during the relevant skill passes:

- **router (navi)** — the Executive Dashboard workflow calls
  `navi_config_update(kind="certificates")` (router L263), a **broken path**. After
  the §2.4 fix it becomes `navi_config(kind="certificates")`. Also the dashboard's
  cert query and the `navi explore uuid` row (router L352) tie in.
- **navi-mcp** — must document the corrected cert path, the sla reality
  (calculate via tool / reset via CLI), and (carried from A13) the
  `navi://skill/{name}` resource + `navi_workflow` prompt.
- **navi-explore** — every `explore data` example that implies a `--flag` form for
  cve/name/output/xrefs/scantime/port needs review; `asset`→`uuid` and
  `plugin`→`data plugin` corrections.
- **navi-scan** — the §3.1 coverage expansion changes what the skill should teach.
- **navi-action** — delete-kind corrections (drop agent/exclusion; the real delete
  surface), cancel-UUID requirement.
- **navi-was** — positional-arg corrections across scans/details/scan/start/upload.

---

## 6. Suggested fix order

1. **Validate** the root cause with the one CVE-lookup call (§0).
2. **Patch the positional/path bugs** (§2.1–§2.4) — pure correctness; the surface
   goes from broadly broken to working. Re-run a few calls per tool.
3. **Wire annotations** (ledger A3) and the **error-on-non-zero guard** (A1/A12) —
   they touch the same functions, do them in the same edit pass.
4. **Address the 4-min ceiling** (A2) — timeouts + docstrings + CLI fallback.
5. **Coverage expansion** (§3) — scan reads first (highest value, lowest risk).
6. **Then** the skill passes, folding §5 corrections into each.
