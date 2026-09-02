# navi-mcp & Skills — Gap Ledger

The running record of every finding from the improvement effort, per §9 of the
operating framework. This is the source of truth between sessions: if context
resets, restart here.

**Conventions**
- **ID:** `A*` = Phase A (MCP server) · `B-<skill>*` = Phase B (skills) · `C*` = Phase C (doc reconciliation)
- **Type:** Coverage · Schema · Gating · Currency · Consistency · Error-handling · Other
- **Severity:** Blocker (wrong/misleading/will-fail) · Gap (missing coverage) · Polish (consistency/style)
- **Status:** Open · Drafted · Applied · Deferred · Won't-fix (+reason)

Anchored to **navi-mcp v8.5.31**. Line numbers reference `server__1_.py` (1601 lines).

---

## Phase A — MCP server (source review)

Source review, **now reconciled against `navi_documentation.txt`** (the recursive
`--help` dump, dated 2026-06-07). Reconciliation escalated the picture sharply:
beyond the original A1–A13 items, the server has **23 verified arg-form / command-path
bugs** (root cause: positional navi arguments sent as `--flags`). Full inventory +
paste-ready fixes in **`navi_phaseA_verified_findings.md`**; tracked here as **A14**.
navi itself was not executed — bugs are inferred from Usage signatures (Click rejects
undeclared options); validate with one live CVE-lookup call before mass-patching.

| ID | Source (file / lines) | Type | Severity | Description | Canonical home | Status |
|----|----------------------|------|----------|-------------|----------------|--------|
| **A1** | `navi_enrich_tag` L737–742; `navi_enrich_acr` L826–833 | Error-handling | **Blocker** | Success `_notice` ("Tag created" / "ACR updated") appended unconditionally, ignoring `returncode`. A failed write reports success. `navi_export` checks returncode (L999) — enrich tools don't. Fix: shared `_raise_on_error()` guard before the notice. | navi-mcp skill (output contract) | Open — patch drafted |
| **A2** | `run_navi` L104–155; long-timeout tools: `config_update` L235 (900s), `enrich_tag` L737 (1800s), `export` L994 (1800s), `config` software L276 (900s) | Error-handling / Currency | **Blocker** | The ~4-min MCP **host** call ceiling is undocumented; subprocess timeouts (900s/1800s) exceed it, so long ops fail opaquely with an orphaned navi subprocess. The documented #1 limitation is invisible in the server, and the timeouts mislead (imply a 25-min tag completes via the tool). Fix: `MCP_CALL_BUDGET` (~220s) below the ceiling → clean actionable error; docstring warnings; CLI fallback (`days=N`, `--threads 1`, `config optimize`). Tradeoff to decide: sub-ceiling timeout kills sync/tag mid-flight (partial DB / partial tag) vs. today's orphan+opaque-timeout. | navi-core / navi-troubleshooting (timeout) | Open — patch drafted |
| **A3** | All 16 `@mcp.tool()` decorators | Schema | **Gap** | No MCP tool annotations (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`). mcp-builder standard unmet; clients can't auto-detect destructive vs read-only ops. Mixed read/write tools take the conservative value. Per-tool mapping in the Phase A write-up. | mcp-builder standard | Open — pattern + table drafted |
| **A4** | `navi_export` / `ExportSub` L883–887 (sync export, no `status`) | Coverage | **Gap** | No export-status capability; status polling is CLI-only (`navi explore api '/vulns/export/<UUID>/status'`). navi-export skill triggers on "is my export finished" the surface can't answer. Same root as A2: synchronous export blocks on the full run, colliding with the 4-min wall; async status polling is the escape hatch. Decide in Phase C: promote `explore api`, add a `status` subcommand, or scope skill to CLI. | navi-export skill + Phase C | Open |
| **A5** | Server (no eval file referenced) | Other (process) | **Gap** | No evaluation set. mcp-builder Phase 4 wants ~10 read-only, verifiable, stable questions to prove the surface end-to-end. | mcp-builder eval guide | Open |
| **A6** | All enums: `UpdateKind` L195, `ExploreDataSub` L391, `ExploreInfoSub` L517, `ExportSub` L883, `WasSub` L1132 | Coverage | **Gap** | **RESOLVED — verified against doc.** `ExploreInfoSub` (26) and `ExportSub` (15) match navi exactly. `ExploreDataSub` (17) and `WasSub` (8) have correct *names* but wrong *invocations* (→ A14). `UpdateKind` has an invalid value (`certificates`) and is missing real kinds (→ A14 / findings §3.3). | Phase C doc reconciliation | **Resolved → folded into A14** |
| **A7** | Most tools (return raw `run_navi` dict) | Consistency | Polish | No `outputSchema` / `structuredContent`. `navi_export` (L1018–1049) and `navi_explore_query` read (L351–358) are the structured exemplars to extend to high-value tools. | mcp-builder | Open |
| **A8** | `navi://workdir` L1404–1420 | Consistency | Polish | Could surface navi.db freshness (newest `last_found`) so the freshness check is one resource read instead of a separate `navi_explore_query`. | navi-mcp skill (freshness check) | Open |
| **A9** | `navi_config(kind="sla")` L270–273 | Error-handling | **Blocker** | **Verified:** `config sla` is a group (`calculate` / `reset`) — bare invocation is a no-op, sets nothing. Fix: route to `["config","sla","calculate"]`; threshold setup (`reset`, interactive) stays CLI. Folded into A14 / findings §2.4. | navi-core (sla setup) | Open — fix in findings doc |
| **A10** | `navi_action_delete` param `id` L1233 | Consistency | Polish | `id` shadows the Python builtin. Rename (e.g. `object_id`) — note this changes the public schema param name. | — | Open |
| **A11** | `_explore_query_write` L363–388 | Error-handling | Polish | sqlite3 `execute` runs only the first statement; multi-statement writes silently drop the rest. Document "one statement per call" or use `executescript` for the write path. | navi-mcp skill (explore_query writes) | Open |
| **A12** | `run_navi` L150–155 + all write tools | Consistency | Polish | Non-zero `returncode` raised only by `navi_export`; other tools pass the dict through. Shared `_raise_on_error()` (also resolves A1) unifies behavior across the surface. | navi-mcp skill | Open — folded into A1 patch |
| **A13** | **navi-mcp** SKILL.md, Resources § (L164–178 of that file) | Coverage | **Gap** | Skill documents only `navi://schema` + `navi://workdir`; the server also exposes `navi://skill/{name}` (L1440) and the `navi_workflow` prompt (L1497). Skill is out of date with its own server. | navi-mcp skill | Open — **resolve in Phase B navi-mcp pass** |
| **A14** | `navi_explore_data` (8/17), `navi_was` (5/8), `navi_action_delete` (5/6), `navi_config_update`, `navi_config(sla)`, `navi_action_cancel`, `navi_enrich_add`, `navi_scan(create)` | Schema / Coverage | **Blocker** | **23 verified arg-form / command-path bugs.** Root cause: positional navi args sent as `--flags`; two non-existent enum values (`delete agent/exclusion`, `update certificates`); one missing required positional (`action cancel` UUID). Full inventory + exact current→correct calls + line numbers in **`navi_phaseA_verified_findings.md` §2**. Subsumes A6 + A9. | per-tool (see findings §5 cascade) | Open — paste-ready fixes done |
| **A15** | `navi scan` (4/16 exposed), `action delete` (valid kinds), `config` sub-areas, `config update` missing kinds | Coverage | **Gap** | Verified blind spots — real commands neither exposed nor recorded as excluded. Biggest: `scan` reads (status/details/history/latest/hosts) + pause/resume. Detail in **findings §3**; exclusion-ledger naming fix (`navi keys` → `config keys`) in §4. | Phase C | Open |

**Phase A tally (post-verification):** 4 Blockers (A1, A2, A9→A14, **A14 = 23 bugs**),
4 Gaps (A3, A4, A5, **A15**), 4 Polish (A7, A8, A10, A11), 1 cross-phase (A13).
A6 resolved. Paste-ready fixes drafted for A1, A2, A3, and all of A14. See
`navi_phaseA_verified_findings.md` for the full bug inventory and fix order.

---

## Phase B — Skills

*(populated as each skill is reviewed, in dependency order: navi-mcp → navi-core
→ navi-explore → navi-enrich → navi-acr → navi-export → navi-scan → navi-was →
navi-action → navi-troubleshooting → navi router)*

| ID | Source | Type | Severity | Description | Canonical home | Status |
|----|--------|------|----------|-------------|----------------|--------|
| ~~B-mcp-1~~ | navi-mcp SKILL.md | Coverage | Gap | **RESOLVED.** Resources section now documents `navi://skill/{name}`, `navi://skill/{name}/{ref}`, and the `navi_workflow` prompt. | navi-mcp | **Applied** |
| **B-mcp-2** | navi-mcp SKILL.md (write-gate list) | Currency | Blocker | Updated platform-write list for the new server: `action_cancel` requires `uuid`; `explore_api` POST/PUT gated; `scan` pause/resume added; `sla`→calculate (not "sets thresholds"); `certificates` not-gated. | navi-mcp | **Applied** |
| **B-mcp-3** | navi-mcp SKILL.md (api-keys, not-exposed) | Currency | Blocker | `navi keys`→`navi config keys`; `explore api` and `config certificates` moved out of not-exposed (now exposed). | navi-mcp | **Applied** |
| **B-mcp-4** | navi-mcp SKILL.md | Consistency | Polish | Cross-referenced navi-core as the 4-min-ceiling canonical home (no duplication); noted `navi://workdir` now answers the freshness check in one read (A8). | navi-mcp / navi-core | **Applied** |
| **B-troubleshooting-1** | navi-troubleshooting SKILL.md | Currency | Blocker | `navi keys`→`navi config keys` (3 spots incl. summary table + post-upgrade recovery). | navi-troubleshooting | **Applied** |
| **B-troubleshooting-2** | navi-troubleshooting (timeout section) | Currency | Blocker | Timeout section rewritten for the corrected server: leads with the clean ~220s budget error + cli_hint (and DB-lock chain now unlikely), keeps the opaque host-timeout path for uncorrected servers. Summary row updated. | navi-troubleshooting | **Applied** |
| **B-troubleshooting-3** | navi-troubleshooting (triage step 2) | Currency | Blocker | Export-status polling is now tool-driven: `navi_explore_info(subcommand="exports")` + `navi_explore_api(url="/vulns/export/<UUID>/status")` (was "CLI-only, no MCP tool yet"). navi-export cross-ref updated to match. | navi-troubleshooting | **Applied** |
| **B-export-1** | navi-export SKILL.md (freshness paragraph) | Accuracy | Blocker | **Bug caught.** `certificates` was listed as a `navi_config_update` kind — invalid (same cert-family bug). Corrected to the real update kinds (assets/vulns/agents/compliance/route/paths/was/fixed/plugins) + note that certs populate via `navi_config(kind="certificates")`. | navi-export | **Applied** |
| **B-export-2** | navi-export ("In-flight export status") | Currency | Blocker | Status/chunk polling rewritten as tool-driven via `navi_explore_api(url="/.../export/<UUID>/status")` (was "no MCP tool today" + future-tense "when it becomes a tool"). Added `navi_action_cancel` uuid note. Subcommand surface verified correct against server (bytag `--c`/`--v`, route `--route`, group `--name`). | navi-export | **Applied** |
| **B-scan-1** | navi-scan SKILL.md | Accuracy | Blocker | **Bug caught (confirmed vs doc tree).** `navi scan create` has NO `--name` option — removed `name=`/`--name` from all examples, the optional-params list, both workflow examples, and NL index. Noted the real CLI-only flags (`-discovery`, `--custom`) the tool doesn't expose. | navi-scan | **Applied** |
| **B-scan-2** | navi-scan SKILL.md | Coverage | Blocker | Added the subcommands the new server exposes but the skill lacked: read views `status`/`details`/`history`/`hosts`/`latest` (positional `scan_id`; `latest` none) + write `pause`/`resume`. New sections + NL index rows + intro tool-surface line. All 11 subcommands now documented and match server `ScanSub`. | navi-scan | **Applied** |
| **B-was-1** | navi-was SKILL.md (CLI forms) | Accuracy | Blocker | **Bug caught (confirmed vs doc tree).** All 5 CLI equivalents used non-existent flags — `navi was scans --config`, `details --scan`, `scan --target`, `start --config`, `upload --file`. Doc shows positional (`scans CONFIG_UUID`, `details SCAN_UUID`, `scan SCAN_TARGET`, `start SCAN_ID`, `upload FILENAME`). Fixed all five. | navi-was | **Applied** |
| **B-action-1** | navi-action (`navi_action_delete`) | Accuracy | Blocker | **Multiple bugs caught vs doc tree.** Removed nonexistent `kind="agent"`/`"exclusion"` (no such CLI subcommands); fixed `user` to numeric `user_id` (was email `username`); `scan`/`asset` to `object_id` positional (were `id`/`uuid` + `--id`/`--uuid` CLI). Added the real kinds the tool exposes: `bytag` (deletes ASSETS), `tone`, `tgroup`, `usergroup`. | navi-action | **Applied** |
| **B-action-2** | navi-action (`navi_action_cancel`) | Accuracy | Blocker | Cancel now passes the **required export `uuid`** (`navi_action_cancel(kind=..., uuid=..., confirm=True)`; CLI `navi action cancel <UUID> -a`). Was missing it entirely. | navi-action | **Applied** |
| **B-action-3** | navi-action + **navi-mcp ref** (`navi action push`) | Accuracy | Blocker | **Cross-skill bug.** Doc shows push takes `--target <IP>` (required) + `--command`/`--file` — **no `--tag`**. Rewrote push to target one IP and loop over a tag's enumerated IPs; fixed the Route→Tag→Push→Verify cycle here AND the copy in `navi-mcp/references/commands-not-exposed.md`. (`mail` `--to`/`--file`/`--subject` verified correct; `rotate` `username` verified.) | navi-action, navi-mcp | **Applied** |
| **B-action-4** | navi-action (468→410) | Consistency | Polish | **Option A applied.** Extracted the operational-hygiene workflow to `references/operational-hygiene.md`. SKILL.md 410 lines. | navi-action | **Applied** |
| **B-core-1** | navi-core SKILL.md (8 places) | Currency | Blocker | `navi keys --a --s` is not a command — it's `navi config keys` (flags `--a`/`--s` valid). Verified vs doc (no top-level `navi keys`). | navi-core | **Applied** |
| **B-core-2** | navi-core SKILL.md (5 places: targeted-sync list, CLI block, certs schema, Quick Map, version note) | Schema/Currency | Blocker | Cert table populated by `navi_config(kind="certificates")` / `navi config certificates` — NOT `config update certificates` (which doesn't exist). Mirrors server fix. | navi-core | **Applied** |
| **B-core-3** | navi-core SKILL.md L238 (version syntax note) | Currency | Blocker | `navi explore asset` doesn't exist → `navi explore uuid`. Propagated server bug. | navi-core | **Applied** |
| **B-core-4** | navi-core SKILL.md (SLA section) | Schema/Currency | Blocker | `config sla` is a group (calculate/reset); bare is a no-op. `navi_config(kind="sla")` now runs `config sla calculate`; threshold setup is `config sla reset` (interactive, CLI). | navi-core | **Applied** |
| **B-core-5** | navi-core SKILL.md (targeted-sync list, CLI block, Quick Map, fixed schema) | Coverage | Gap | Added newly-exposed `navi_config_update(kind="fixed")` and `(kind="plugins", size=N)` (size REQUIRED); extended `days` validity to include `fixed`. Corrected `fixed` populate path (was "part of vulns"). | navi-core | **Applied** |
| **B-core-6** | navi-core SKILL.md (zipper schema) | Currency | Polish | `zipper` is the EPSS+plugins merge table, populated by `navi config update zipper` (CLI, not exposed) — was vaguely described. | navi-core | **Applied** |
| B-core-7 | navi-core SKILL.md | Consistency | Polish | **RESOLVED (Option A).** Split into lean SKILL.md (490 lines, <500) + `references/schema.md` + `references/installation.md`. Established the progressive-disclosure template for the remaining skills. | navi-core | **Applied** |
| **A16** | server.py `navi://skill/{name}` resource | Coverage | Gap | **Applied.** Extended for Option A: SKILL.md output now advertises bundled references, and a new `navi://skill/{name}/{ref}` resource serves `references/*.md` so MCP-resource consumers (not just filesystem/installed-skill consumers) get the deep material. Path-traversal guarded. | server.py | **Applied** |

**Phase B navi-core tally:** 4 Blockers, 1 Gap, 2 Polish — **all corrections applied**;
one Polish (length) deferred. Delivered: `navi-core.skill` (installable) +
`navi-core-SKILL.md` (review). The 4-min MCP-timeout section was already correct
(A2's canonical home lives here) and was kept; cross-reference it from navi-mcp.
| — | *(next: navi-mcp pass)* | | | | | |

---

## Phase C — Doc reconciliation (master gap close)

*(populated once `navi_documentation.txt` is generated and the full U-vs-(M∪S)
diff runs; re-validate every exclusion-ledger row here)*

| ID | Source | Type | Severity | Description | Resolution |
|----|--------|------|----------|-------------|------------|
| — | *(blocked on crawler output)* | | | | |

**Carried into Phase C:** A4 (export-status decision), A6 (enum verification),
plus the full exclusion-ledger re-validation from framework §3.

---

## Article-derived context — for navi-explore / navi-enrich build (syntax IGNORED per user; use validated modern commands only)

Source: user-supplied navi articles 1–2. The articles use the OLD command
generation — pre-7.5.x names that were later moved under `action`:
`navi tag … --output` → `navi enrich tag`, `navi mail` → `navi action mail`,
`navi push` → `navi action push` (`navi keys` → `navi config keys`). The bare
old forms no longer exist and must not be reproduced. ALL article command syntax
is disregarded; only the use-case context below is retained, expressed with the
validated `navi_*` tool surface / current CLI.

**Device fingerprinting via informational plugins (core navi-enrich theme; matches user's standing IoT-fingerprinting interest):**
- `10863` SSL Certificate Information — dumps X.509 certs from SSL ports. Beyond cert-expiry tracking, the cert content fingerprints IoT/appliances (e.g. Buffalo TeraStation, Splunk). Cross-ref navi-core cert plugins.
- `66717` mDNS Detection — **local-network scanner only**. Finds obscure IoT (e.g. Chromecast). Key insight: Nessus fingerprints such devices as "Linux" (underlying OS), which **skews OS metrics**; tagging them corrects classification.
- `35716` Ethernet MAC / OUI (from user memory) — reliable per-asset fingerprinting via MAC OUI.

**Software-inventory tagging (security-software hunt use case):**
- `20811` (Windows), `22869` (Linux), `83991` (Mac) enumerate installed software → `software` table (built by `navi config software`).
- Canonical example: find `tcpdump`/`wireshark` (or any package) — useful for locating risky tooling (e.g. packet capture exposing creds pre-LDAPS).
- Nuance: package in a plugin *name* (vs output) implies a vuln in that software.

**Other:**
- `19506` = scan information ("king of plugins"); already used by navi-scan optimize index (`idx_plugin_2`) and scantime/evaluate.

**Build implications:**
- navi-enrich: foreground the tag-by-plugin / tag-by-plugin-output use cases (IoT fingerprinting, software inventory) using the validated `navi_enrich_tag` surface; the certs/software/epss tables are tag sources.
- navi-explore: ensure plugin-output search (`output`) and `software`-table queries cover finding misclassified IoT + security-software inventory.
- Minor addables (fold in during assembly): name software plugin IDs (20811/22869/83991) in navi-core software section; note 10863 doubles as an IoT signal.

**Article 3 — user-access tagging (offboarding / asset ownership):**
- `95928` enumerates LOCAL USERS on Linux (credentialed); `71246` enumerates LOCAL user/group memberships on Windows (credentialed).
- Use case: identify which assets a (local) user can access — for account remediation on offboarding, and asset-ownership / who-has-access mapping. Tag assets whose enumeration-plugin output contains the username → a "Known Users:<user>" style tag.
- navi-enrich: this is the THIRD tag-by-plugin-output pattern (alongside device-fingerprinting and software-inventory). Ties into navi-action's user-offboarding flow. Express with validated `navi_enrich_tag` query-based tagging; article syntax (`navi tag`) disregarded.

**Article 4 — RETAINED CODE (user request): CVE-keyed external-CSV enrichment.**
- Pattern: download an external CSV whose primary key is a CVE ID → parse (pandas) → loop → tag per CVE. Concrete example: MITRE ATT&CK→CVE mapping (attack_to_cve), 3 tags/CVE (Primary/Secondary Impact, Exploit Technique).
- Retained (modernized) as a pre-staged navi-enrich reference: `/home/claude/navi-enrich/references/tag-by-cve-external-csv.md` → will ship in `navi-enrich/references/`. Commands updated to `navi config keys` / `navi config update full` / `navi enrich tag --cve` (+ `navi_enrich_tag(cve=…, confirm=True)` MCP equivalent); old `navi tag`/`navi keys`/`navi update full` removed.
- Reinforces navi-enrich tag-by-CVE selector + the "bulk runs are CLI (call-budget), single tags are MCP" rule. Verified vs server: `cve` is a valid primary selector (`args.extend(["--cve", cve])`); doc line 2140 `--cve TEXT  Tag based on a CVE ID`.

**Article 5 — context only (code ignored, = article-4 pattern): CISA KEV tagging.**
- Use case: tag assets carrying CVEs from CISA's Known Exploited Vulnerabilities catalog → prioritize / report / remediate actively-exploited risk.
- EPHEMERAL tag: KEV catalog grows continuously → refresh with `remove=True` per release (matches navi-enrich health/risk-tag guidance), don't accrete stale state.
- BUILD TASK for navi-enrich: verify the *current native* CISA KEV tagging method (likely `xrefs`/`CISA-KNOWN-EXPLOITED` selector, or a KEV-aware path) vs the article's manual CVE-list loop; document the validated approach. CISA KEV is a first-class navi-enrich tag dimension.

**Article 6 — context (syntax ignored): tag/find by PLUGIN FAMILY.**
- Use case: "where am I using <tech>?" — plugin families group detections (e.g. `Artificial Intelligence` ≈ 36 plugins). CIS Control #2 / software-inventory theme.
- VERIFIED vs doc tree: the article's predicted natives (`navi tag --byfam`, `navi display ai`, `navi deploy ai`) did NOT ship. No `--byfam`/family selector exists. **Current method = query selector** on `vulns.plugin_family` (confirmed: `plugin_family` is a real column in vulns AND plugins tables).
  - navi-enrich: `navi_enrich_tag(category=…, value=…, query="SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_family='Artificial Intelligence';", confirm=True)`.
  - navi-explore: plugin-family search = raw `navi_explore_query` on `vulns.plugin_family` (no dedicated subcommand).
- Reinforces: `query` is the catch-all selector for any dimension without a native flag.

**Article 7 — confirms navi-acr (already built); minor refinement.**
- ACR-by-tag + `mod` set/inc/dec + inc/dec clamping at 1/10 + "default ACR lacks owner context / if everything's important nothing is" — ALL already in navi-acr (verified). Article syntax (`navi lumin --acr -b --mod`) ignored; current = `navi_enrich_acr`/`navi enrich acr`.
- Refinement applied: broadened the inc/dec use case to **intra-tag heterogeneous criticality** (e.g. a DB inside an app-stack tag) — the article's core motivating example — beyond the incident-only framing. navi-acr repackaged.

**Article 8 — context (syntax ignored): scan-duration / scanner evaluation.**
- Method (confirms navi-scan evaluate; informs navi-explore): 19506 holds scan DURATION. Evaluate averages across 3 dimensions — Scanner IPs, Scan Schedules, Scan Policies; stark delta in any → investigate (under-provisioned scanner, restricted net, policy diff).
- Rules of thumb: >30 min/asset avg = investigate; ~21 min typical at scale; up to ~60 min acceptable on slow/old/MPLS-VPN.
- Long-scan causes: high port count (65k vs ~4000 default), Max Hosts / Max Checks misconfig, target CPU/RAM, software+vuln volume, connectivity (asset on/offline).
- Drill-down: evaluate (averages) → scan history (run deltas) → evaluate scanid+histid (specific run) → scantime threshold (find long-scan assets) → tag them → per-asset informational plugins.
- Key informational plugins: 19506 (scan info/duration), 45432 (Processor), 45433 (Memory), 22869/20811 (software count ↔ scan time).

**navi-explore build inputs (from article 8 + doc):**
- `scantime` data subcommand: `navi explore data scantime [OPTIONS] MINUTE` (positional MINUTE → `minutes` param). Find assets over N min scan time.
- Per-asset informational views: get all info plugins on an asset; specific plugin output by asset (modern: `navi explore uuid` / plugin+output views — verify exact form at build).
- Investigate `--method [plugin|name|group|output|scantime|scanid|query|cve|xrefs|route_id|cpe]` (doc line 750) when building the explore data subcommand docs.

**navi-enrich build input:** tag-by-scantime selector confirmed — doc line 2153 `--scantime TEXT  Create a Tag for assets that took longer than…` → `navi_enrich_tag(category="Long Scan Times", value="Over 30 mins", scantime=30, confirm=True)`.

---

## ASSEMBLY TASKS (batch during final assembly)
1. **server.py** — `navi_scan(subcommand="evaluate")`: add optional `histid` (→ `--histid`) and a `full` flag (→ `-full`). Doc: `navi scan evaluate` supports `--scanid`/`--histid`/`-full`; tool currently passes only `--scanid`. Update `ScanSub`/signature accordingly.
2. **navi-scan** — document evaluate `histid` + `-full` (review a specific historical run / entire history); ties to the scan-comparison workflow (article 8).
3. **navi-core** — software section: name plugin IDs 20811 (Windows) / 22869 (Linux) / 83991 (Mac); note 10863 doubles as an IoT/appliance fingerprint signal (not just cert-expiry).
4. **navi-core** — note `navi config update full --c "<cat>" --v "<val>"` scopes a full sync to a tag (article 1).

---

| **B-explore-1** | navi-explore (data CLI forms) | Accuracy | Blocker | **Bugs caught vs server/doc.** CLI forms made positional: `cve`/`name`/`output`/`port`/`scantime` (were `--cve`/`--name`/etc.); `xrefs <type> --xid <id>` (was `--type`/`--id`); `plugin`→`navi explore data plugin`; **`navi explore asset`→`navi explore uuid`**. Tool subcommand `"asset"` kept correct (server maps it to `explore uuid`). | navi-explore | **Applied** |
| **B-explore-2** | navi-explore ("coming to MCP") | Currency | Blocker | Rewrote stale block: `explore api` shipped → `navi_explore_api` (GET free / POST-PUT gated); single-asset basic lookup is the `asset` subcommand, flag views (`-software`/`-patches`/`--plugin`) remain CLI-only. Folded in article-8 per-asset scan-diagnosis plugins (19506/45432/45433; software count ↔ scan time). | navi-explore | **Applied** |
| **B-explore-3** | navi-explore subcommand surface | Consistency | — | **Verified:** all 16 data subcommands match `ExploreDataSub`; all referenced info subcommands valid in `ExploreInfoSub` (26). Platform-write list updated (scan pause/resume, `explore_api` POST/PUT, cancel `uuid`). | navi-explore | **Applied** |
| **B-explore-4** | navi-explore (459→406) | Consistency | Polish | **Option A applied.** Extracted SQL cookbook to `references/query-patterns.md`, adding article-informed recipes: plugin-family ("where am I using <tech>") + package search (e.g. wireshark) + software-plugin-ID note. SKILL.md 406 lines. | navi-explore | **Applied** |

---

| **B-enrich-1** | navi-enrich (`navi_enrich_add` CLI) | Accuracy | Blocker | **Bug caught vs server.** Bulk-import CLI `--list`→`--file` (tool param `list_csv` is correct; navi's flag is `--file`). Added `mac`/`netbios` identity fields (MAC = OT/IoT fingerprint) + CSV column order (IP, MAC, FQDN, Hostname). | navi-enrich | **Applied** |
| **B-enrich-2** | navi-enrich (selector catalog) | Consistency | — | **All 25+ selector CLI flags verified** vs doc `navi enrich tag --help` (`--c`/`--v`/`--cve`/`--cpe`/`--plugin`/`--output`/`--name`/`--group`/`--xrefs`/`--xid`/`--route_id`/`--port`/`--file`/`--scantime`/`--scanid`/`--histid`/`--query`/`--manual`/`--missed`/`--byadgroup`/`-regexp`/`-tone`/`-all`/`-remove`/`--by_tag`/`--by_cat`/`--by_val`/`--cc`/`--cv`). No flag bugs. | navi-enrich | **Applied** |
| **B-enrich-3** | navi-enrich (566→386) | Coverage / Consistency | Polish | **Option A applied + article context.** Exhaustive selector catalog → `references/selectors.md`; pre-staged `references/tag-by-cve-external-csv.md` shipped. Added inline a lean **selector quick-map** + a **use-case playbook** mapping every article pattern (IoT fingerprinting 10863/66717/35716, software inventory 20811/22869/83991, user-access 95928/71246, plugin-family via `query`, CISA KEV via `xrefs`, bulk-CVE-CSV, scantime) to validated selectors. SKILL.md 386 lines. | navi-enrich | **Applied** |

## ASSEMBLY — COMPLETE
1. ✅ **server.py** — `navi_scan` evaluate now takes optional `histid` (→ `--histid`) and `full` (→ `-full`); `scan_id` optional (no-args = cross-dimension averages). Compiles clean.
2. ✅ **navi-scan** — evaluate section documents the four scopes (no-args / scan_id / +histid / full=True). 453 lines.
3. ✅ **navi-core** — software plugin IDs already named (20811/22869/83991); added 10863-as-IoT-signal note + tag-scoped `navi config update full --c --v`. 495 lines.
4. ✅ **navi (router)** — fixed residual `push --tag` in NL index → per-IP `--target` loop (caught in final cross-suite sweep).
5. ✅ **GitHub-ready folder** `navi-mcp-suite/` assembled: `server/server.py`, `skills/` (11 folders, NAVI_SKILL_DIR layout, 8 reference files), `dist/` (11 .skill), `docs/` (framework, ledger, findings, crawler), `README.md`.
6. ✅ Final cross-suite residual sweep: 0 real occurrences of any known bug pattern; all 11 SKILL.md < 500 lines.

**PROJECT COMPLETE: 11/11 skills + corrected server, validated against the authoritative `navi --help` tree. Runtime validation against a live tenant still recommended (one read call) per the README.**

---

## ROUND C — 2026-08-21 (source-verified against navi-pro 8.6.4 wheel)

Method change worth noting: earlier rounds validated flags against a captured
`--help` tree. This round read `navi/plugins/*.py` out of the published
`navi_pro-8.6.4-py3-none-any.whl`, which surfaces behaviour `--help` cannot —
notably guards that warn without exiting, and flags whose effect depends on
which selector they accompany.

| ID | Area | Class | Severity | Finding | Owner | Status |
|---|---|---|---|---|---|---|
| **C-navi-1** | navi CLI — `navi/plugins/tag_rules.py` | Accuracy | **Blocker** | **Bug in navi itself, not the MCP.** `run_rules_now()` shells out with `--xref` for every `xref`-type rule (lines 69, 70, 73, 74). The option declared on `enrich.tag` is `--xrefs` (enrich.py:406); `--xref` does not exist and click does **not** do prefix abbreviation, so the subprocess dies with `Error: No such option: --xref (Possible options: --xref-id, --xrefs)`. Because the call goes through `os.system`, the failure is invisible to the rule runner — every stored cross-reference rule silently never re-tags. The other nine rule branches (`plugin_id`, `plugin_name`, `plugin_output`, `cve`, `group`, `scantime`, `scanid`, `ports`, …) use correct flags. Fix: `--xref` → `--xrefs` in all four strings. Note `--xid` in the same strings IS valid (enrich.py:407 declares `--xid`/`--xref-id`). | packetchaos/navi | **Reported — fix prompt written** |
| **C-mcp-1** | server.py — `navi_enrich_tag` xrefs spelling | Accuracy | — | **Verified correct, no change.** The MCP emits `--xrefs` + `--xid`, matching enrich.py:406–407. Confirms B-enrich-2. `--xref-id` exists only as a click alias of `--xid`; click resolves the parameter name to `xid`, so the MCP's spelling is the canonical one. | navi-mcp | **Verified** |
| **C-mcp-2** | server.py — `xid` without `xrefs` | Correctness | **Blocker** | navi's own guard (enrich.py:480–481) `click.echo()`s "You must supply a Cross Reference Type using --xrefs option" and **does not `exit()`** — unlike the neighbouring `--output`-without-`--plugin` guard at 476–478, which does. navi therefore proceeds with no selector, creates an EMPTY tag, and returns exit code 0, which `_raise_on_error` reads as success. The MCP guarded this only on the `remove=False` path. Fix applied: the guard now fires on **every** path, remove included, and its message explains why the tool is stricter than the CLI. | navi-mcp | **Applied** |
| **C-mcp-3** | server.py — `-regexp` scope | Coverage | Blocker | `-regexp` is a **global** LIKE→REGEXP switch in navi, honoured by `by_val` (458), `by_cat` (468), `plugin`+`output` (490), `name` (542), `cpe` (803) and `xrefs` (825). The MCP modelled it as `plugin_regexp`, a string that required `plugin` — so **regexp cross-reference tagging was unreachable through MCP entirely** (`xrefs="CISA\|IAVA"` had no path). Fix applied: added `regexp: bool`; passing it without a regexp-capable selector raises rather than silently degrading to a literal LIKE match. `plugin_regexp` retained as a deprecated alias that emits a `_warning`. | navi-mcp | **Applied** |
| **C-mcp-4** | server.py — `xrefs` + `xid` + `regexp` | Accuracy | Polish | navi's `xid` branch (enrich.py:822) is a two-term literal `LIKE '%xrefs%' AND LIKE '%xid%'` and never reaches the REGEXP branch below it, so `-regexp` is accepted and ignored. Fix applied: that combination returns a `_warning` saying the pattern was treated as literal text. | navi-mcp | **Applied** |
| **C-mcp-6** | server.py — `navi_explore_data` `-regexp` | Coverage | Blocker | **Same class of bug as C-mcp-3, swept across the whole CLI.** An AST walk of the 8.6.4 wheel (parsing `@click.option`/`@click.argument` decorators rather than grepping) found exactly **six** commands declaring an xref or regexp option: `enrich tag`, `export vulns`, and four `explore data` subcommands — `plugin` (explore.py: `--out`, `-regexp`), `output`, `name`, and `xrefs` (`--xid`/`--xref-id`, `-regexp`). `navi_explore_data` passed `-regexp` for **none** of them, so every regexp read was silently a literal LIKE. Fix applied: `regexp: bool` honoured for those four subcommands and raising for the other thirteen. On `plugin`, navi's `-regexp` only switches the `--out` text search, so `regexp=True` without `output` raises. | navi-mcp | **Applied** |
| **C-mcp-7** | server.py — `explore data plugin --out` | Coverage | Blocker | The `--out` option on `explore data plugin` (narrow a plugin lookup to assets whose output for THAT plugin contains text) was dropped entirely — the tool's `output` param only fed `subcommand='output'`. So "which assets did plugin 19506 report `<text>` on" had no path through MCP. Fix applied: `output` now maps to `--out` for `subcommand='plugin'`. Naming trap for future work: navi spells this **`--out`** on `explore data plugin` but **`--output`** on `enrich tag`. | navi-mcp | **Applied** |
| **C-mcp-5** | server.py — `navi_export` vulns filters | Coverage | — | **Not a gap — by design.** `navi export vulns` accepts `--c`/`--v`/`--severity`/`--plugin`/`--name`/`--output`/`--cve`/`--xrefs`/`-regexp` (export.py:125–137), none of which `navi_export` exposes. The intended navi pattern is **tag then export by tag**: narrow once with `navi_enrich_tag` (full selector surface, xrefs included), then `navi_export(subcommand='bytag')` — which is also the only export carrying ACR + AES, so it yields a strictly richer CSV than a filtered `export vulns`. For a one-off slice not worth a tag, `navi_export(subcommand='query', sql=…)` already expresses any of those filters. Documented in the server docstring; no code change. | navi-mcp | **Closed — no change** |

## ROUND D — 2026-08-21 (`-rebuild`, verified against the dev checkout)

Source of truth this round: `C:\Users\packe\claud_navi\navi`,
`navi/plugins/config.py` — newer than the 8.6.4 PyPI wheel used in Round C.

| ID | Area | Class | Severity | Finding | Owner | Status |
|---|---|---|---|---|---|---|
| **D-mcp-1** | server.py — `navi_config_rebuild` | Coverage | — | New `-rebuild` flag on `config update assets` / `vulns` / `full` drops the named local table(s), re-creates them, then downloads fresh. Exposed as a **separate tool**, not a flag on `navi_config_update`: MCP's `destructiveHint` is per-tool, so a boolean on the existing tool would either mark every ordinary refresh destructive or misreport the rebuild. `navi_config_rebuild` carries `destructiveHint=True`; `navi_config_update` stays honestly non-destructive. Gated `NAVI_MCP_ALLOW_WRITES=1` + `confirm=True`. Tool count 19 → 20. | navi-mcp | **Applied** |
| **D-mcp-2** | server.py — `run_navi(stdin_text=…)` | Correctness | **Blocker** | `rebuild_tables()` calls `click.confirm()` **before** dropping. `run_navi` passes `stdin=subprocess.DEVNULL`, so click hits EOF, raises `Abort`, and the command exits 1 without touching the table — `-rebuild` was simply **unusable** through MCP (it failed closed, which is the good failure, but it never worked). Added `stdin_text` to `run_navi`, used only by the rebuild path, which answers `"y\n"`. This is why `confirm=True` is mandatory *first*: the caller's confirm IS the answer handed to navi. Verified end-to-end against a real `click.confirm` subprocess — DEVNULL → rc=1, `"y\n"` → rc=0. Default stays DEVNULL everywhere else, so an unforeseen prompt still aborts rather than hangs. | navi-mcp | **Applied** |
| **D-mcp-3** | server.py — `_build_update_call()` | Consistency | Polish | Validation, argv construction, warnings and `cli_hint` extracted from `navi_config_update` into a shared helper the rebuild tool also calls. The destructive path therefore inherits the identical per-kind allow-list — the two tools cannot drift on which flags a kind accepts. | navi-mcp | **Applied** |
| **D-mcp-4** | server.py — post-rebuild `_notice` | Coverage | — | navi's `rebuild_reminder()` warns that `certs`, `software`, `vuln_route` and `vuln_paths` are derived from assets/vulns and are stale after a drop. That reminder only reaches stdout; the tool now returns it as a `_notice` naming the MCP calls that refresh each one. | navi-mcp | **Applied** |
| **D-mcp-5** | server.py — `config update full` docstring | Currency | — | `full`'s help no longer reads "Delete the current Database" — the delete moved behind `-rebuild`, so the stated reason for keeping `full` CLI-only was stale. Corrected: it stays CLI-only purely because a 30d-vuln + 90d-asset pull runs for hours, well past the ~4-min call budget. Rebuilding both tables at once remains `navi config update full -rebuild` at the terminal; from MCP it is two calls. | navi-mcp | **Applied** |
| **D-mcp-6** | server.py — `--state` / `--severity` arity | Coverage | — | navi declares both as `multiple=True` with defaults `["open","reopened"]` and all five severities. The MCP models each as a single value, so `state="open"` **replaces** the default pair rather than narrowing within it — you cannot ask for open+reopened but not fixed. Not wrong, but less expressive than the CLI. Fixed by mirroring `plugin_id`: both accept a list and repeat the flag, on the update and rebuild paths alike (shared through `_build_update_call`). `_as_flag_list()` also accepts a bare string as a one-element list — existing callers keep working, and a model that passes a scalar where a list is wanted lands correctly instead of tripping a pydantic schema error. Empty list raises; order preserved, duplicates collapsed. The replaces-not-narrows semantics are now documented at the call site, and called out again on the rebuild path where it bites hardest: a rebuild with `state=['open']` discards reopened findings *and* the old table is already gone. | navi-mcp | **Applied** |

### Regression coverage added
- `server/tests/test_enrich_tag_xrefs.py` — 33 checks: flag spelling, the xid
  guard on both paths, every regexp-capable and regexp-incapable selector,
  single `-regexp` emission, the deprecation alias, and the pre-existing
  add-then-remove warning.
- `server/tests/test_explore_regexp.py` — 27 checks: `-regexp` on all four
  supported subcommands, rejection on the nine that ignore it, `--out` on
  `plugin`, the xid literal-LIKE warning, and the bare-call regressions.
- `server/tests/test_config_update.py` — 34 checks over the `config update`
  scoping surface, including state/severity list arity.
- `server/tests/test_config_rebuild.py` — 35 checks: argv and flag ordering,
  the answered stdin prompt (and that the safe path leaves stdin closed), both
  gates, the per-tool destructive annotations, inherited validation, the stale
  derived-table notice, and abort propagation.

140 checks, all green.

### Method note for the next sweep
Grepping for a flag name finds where it is *used*; AST-walking the click
decorators finds where it is *declared*, which is what you need to prove a
surface is fully covered. The script that produced the six-command list walks
every `FunctionDef` carrying a `@*.command`/`@*.group` decorator and collects
its `@click.option`/`@click.argument` string literals. Worth re-running against
each new navi release — the same one-liner will flag any newly added flag that
navi-mcp does not pass through.
