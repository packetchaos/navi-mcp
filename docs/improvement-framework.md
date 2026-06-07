# navi-mcp & Skills Improvement — Operating Framework

A working manual for systematically improving the navi-mcp server and the 11
navi skills. The goal is not a rewrite — it's a disciplined coverage-and-quality
pass that closes the "small gaps I missed the first time" problem at scale,
while preserving the hard-won operational knowledge already encoded in the
skills.

Anchored to **navi-mcp v8.5.31**. Read top to bottom once; thereafter use
§5 (work order), §6 (checklists), and §9 (the ledger) as the day-to-day tools.

---

## 1. Purpose & definition of done

**Purpose.** Make the MCP tool surface and the skills *complete* (they cover
everything navi can do that's worth exposing/teaching) and *correct* (what they
cover is accurate, current to v8.5.31, internally consistent, and idiomatic).

**Done looks like:**

- Every navi command in the authoritative command tree is accounted for — either
  exposed as a tool, taught in a skill, or *deliberately excluded with a recorded
  reason*. No silent blind spots.
- Every MCP tool has a correct schema (params, types, enums, write-gating) and an
  actionable error/empty-result story.
- Every skill triggers on the right phrasing without colliding with its siblings,
  documents its full slice of navi, and cross-references the rest bidirectionally.
- Every operational gotcha has exactly one canonical home and is linked from
  everywhere it's relevant.
- A gap ledger (§9) captures every finding and its resolution, so the work
  survives across sessions.

---

## 2. Inputs & their status

Honest accounting of what's actually in hand, because two of the three things
named aren't fully here yet.

| Input | What it gives us | Status |
|---|---|---|
| **MCP tool surface** (16 `navi_*` tools) | The exposed surface: tool names, params, enums, write-gating | **Have** — schemas are loadable on demand (`tool_search`); the 16 tools are enumerated in §3 |
| **MCP server source code** | Implementation: error handling, timeout behavior, resource defs, the write-gate mechanism | **Don't have** — only the *surface* is visible to me. Needed for implementation-level review (§6.A items 6–9); not needed for the coverage diff |
| **11 skill files** | The full `SKILL.md` set | **Have** — installed and read |
| **`navi_documentation.txt`** (recursive `--help` dump) | The **authoritative command tree** — ground truth for what navi can do | **Don't have yet** — last session we built the *crawler script* (`navi_help_crawler.py`), not the output. It has to be run on a navi-configured machine and uploaded |

Two consequences worth being explicit about:

1. **The doc file is the spine of this whole effort.** Until it's generated, every
   coverage claim I make is measured against my own knowledge of navi + the skills,
   not against ground truth. I can do a great deal of useful work now, but the
   *authoritative* gap close (§5 Phase C) needs that file. Run the crawler whenever
   convenient — earlier is strictly better.
2. **Without the server source, Phase A is a surface review, not a code review.** I
   can audit what's exposed, the schemas, the write-gating, and the naming against
   the doc tree — that's most of the value for "what's missing." If you also want
   implementation improvements (better error messages, timeout handling, new
   resources), drop the server source in and Phase A deepens accordingly.

---

## 3. The command universe (the analytical core)

Everything reduces to three sets and the gaps between them.

- **U** = *all* navi commands — from `navi_documentation.txt` (ground truth).
- **M** = commands exposed as MCP tools.
- **S** = commands documented in the skills.

**M today (16 tools):**

```
navi_config            navi_explore_data      navi_action_delete
navi_config_update     navi_explore_info      navi_action_rotate
navi_enrich_tag        navi_explore_query     navi_action_cancel
navi_enrich_acr        navi_export            navi_action_encrypt
navi_enrich_add        navi_scan              navi_action_decrypt
                       navi_was
```

**The gaps we hunt:**

| Gap | Meaning | Action |
|---|---|---|
| **U − (M ∪ S)** | True blind spots — commands nobody exposes or teaches | Decide: expose, teach, or record as deliberately excluded |
| **M − S** | Exposed but undocumented — a tool exists, no skill teaches it well | Add/extend skill coverage |
| **S − M** | Taught as CLI-only — is that intentional or a candidate for a tool? | Validate against the exclusion rationale |
| **Schema drift** | Tool enums/params lag navi's real options (e.g. a `subcommand` enum missing values that exist in `--help`) | Reconcile schema to doc tree |
| **Stale exclusions** | The "not exposed" decisions made for an earlier navi version | Re-litigate each against v8.5.31 |

**The existing exclusion ledger** (from `navi` + `navi-mcp` skills) is our
starting baseline — every row gets re-validated in Phase C:

- *Hazardous, kept CLI:* `navi action push`, `navi action mail`
- *Too heavy, kept CLI:* `navi config update full`
- *One-time setup, kept CLI:* `navi config optimize`, `navi config epss`,
  `navi config smtp`, `navi config ssh`, `navi config scan`, `navi keys`
- *Out of scope:* `navi action deploy`, `navi action automate`, `navi action plan`,
  `navi enrich attribute`, `navi enrich migrate`, `navi enrich tagrule`
- *CLI-only "may expose later":* `navi explore uuid`, `navi explore api`

That last category is the highest-value re-examination: `navi explore api`
passthrough is exactly what export-status polling currently leans on
(`navi explore api '/vulns/export/<UUID>/status'`), so whether to promote it is a
real design question, not a rubber stamp.

---

## 4. Two review lenses

Every artifact is examined through both, never just one:

- **Coverage (breadth):** Does it cover everything navi can do in its domain?
  Measured against U. This is the "gaps I missed" problem.
- **Quality (depth):** Is what it covers correct, current to v8.5.31, internally
  consistent, idiomatic, and free of stale claims? This is the "make it better"
  problem.

A skill can have perfect coverage and poor quality (documents every flag, but the
examples are wrong) or vice versa. Both lenses, every file.

---

## 5. Work order

Your sequence: **MCP server → 11 skills → doc reconciliation.** Kept as-is, with
the skill phase ordered by dependency so foundational facts are settled before the
skills that cite them.

### Phase A — MCP server (surface review)

Audit the 16-tool surface against the checklist in §6.A. Produces a tool-by-tool
findings list + the first entries in the gap ledger. Deepens to a code review if
the server source is provided.

### Phase B — the 11 skills, in dependency order

Foundations first, router last (the router indexes everything, so it's verified
*after* the domains it points to are settled):

| # | Skill | Why here |
|---|---|---|
| 1 | **navi-mcp** | Conventions every other skill relies on; also the bridge from Phase A's surface findings into skill-land |
| 2 | **navi-core** | Canonical home for the foundational facts (setup, schema, sync, 30-min propagation, 50K scale fork, optimize/epss) that every other skill cites |
| 3 | **navi-explore** | The read surface — most-used; defines the query/info patterns other skills reference |
| 4 | **navi-enrich** | The primary write surface; the `remove=True` ephemeral pattern and tag-UUID preservation |
| 5 | **navi-acr** | Builds directly on navi-enrich tagging as a prerequisite |
| 6 | **navi-export** | CSV; leans on explore/query patterns |
| 7 | **navi-scan** | Scan control (create/start/stop/evaluate) |
| 8 | **navi-was** | Self-contained WAS/DAST domain |
| 9 | **navi-action** | delete/rotate/cancel/encrypt + CLI push/mail; push targeting depends on enrich tags |
| 10 | **navi-troubleshooting** | Failure patterns that cross-cut every domain — review after the domains whose failures it documents |
| 11 | **navi** (router) | Indexes every other skill; verify its tables, natural-language index, and canonical-home map only once the domains are final |

### Phase C — doc reconciliation (the master gap close)

With `navi_documentation.txt` in hand, run the full U-vs-(M∪S) diff from §3 across
the whole tree at once. This is the authoritative pass that catches everything the
per-file reviews couldn't, because it's the only one measured against ground truth.
Re-validate every row of the exclusion ledger here. Output: the definitive gap list
and the final ledger reconciliation.

> **Sequencing note.** Phases A and B can start now against my knowledge + the
> installed skills, and they're genuinely productive. But their findings stay
> *provisional* until Phase C confirms them against the doc tree. If the crawler
> output lands early, we fold it in immediately and skip the provisional status.

---

## 6. Per-artifact review checklists

Each pass applies the same checklist, so every handoff has the same shape and
nothing slips between sessions. Grounded in the house standards (mcp-builder for
the server, skill-creator for the skills).

### 6.A — MCP server checklist

1. **Coverage vs U** — every navi command that *should* be a tool is exposed;
   every exclusion is justified against v8.5.31 (§3 ledger).
2. **Tool granularity** — the subcommand pattern (`navi_explore_info` with 26
   subcommands, `navi_explore_data`, `navi_export`, etc.) is the right grain;
   high-traffic subcommands aren't buried where they should be promoted.
3. **Schema correctness** — params, types, and **enums match navi's real options**
   (the most common drift: a `subcommand`/`kind` enum that's missing values present
   in `--help`).
4. **Naming consistency** — `navi_<domain>_<action>`, action-oriented, consistent
   prefixes. (Already strong; verify no outliers.)
5. **Write-gating correctness** — every platform-write tool requires `confirm=True`
   **and** `NAVI_MCP_ALLOW_WRITES=1`; reads are free; local-only `navi.db` writes
   (`navi_explore_query` DDL, `navi_config_update`) gate on `confirm` but not the
   env var. Annotations (`readOnlyHint`/`destructiveHint`/`idempotentHint`) match
   reality per tool. *(Source review)*
6. **Error & empty-result handling** — actionable messages; the silent-partial-data
   failure (key scoped to a subset) is distinguished from empty-because-stale.
   *(Source review)*
7. **Timeout-prone operations** — the ~4-minute MCP host ceiling. Which tools can
   exceed it (`navi_config_update(kind="vulns")` on large tenants), are they flagged
   with the CLI fallback, and is a scoping param (`days=N`, thread count) exposed?
   *(Surface + source)*
8. **Resources** — `navi://schema/{table}`, `navi://workdir` complete and correct;
   decide whether export-status polling belongs as a resource/tool vs. staying CLI
   (`navi explore api '/vulns/export/<UUID>/status'`). *(Source review)*
9. **Output shape** — structured content where possible; exports return path +
   preview with the "preview ≠ full export" contract. *(Source review)*
10. **Evaluations** — a set of ~10 read-only, verifiable, stable eval questions
    exists to prove the surface works end-to-end (mcp-builder Phase 4). Propose one
    if absent.

### 6.B — Skill checklist (applied to each of the 11)

1. **Description / triggering** — fires on the right phrasing, "pushy" enough to
   avoid undertriggering, and **doesn't collide with siblings** (the navi /
   navi-core / navi-troubleshooting routing boundary is the one to watch). All
   "when to use" lives in the description, not the body.
2. **Progressive disclosure** — `SKILL.md` ideally <500 lines; depth >300 lines
   pushed to reference files with a TOC; the body stays a working index.
3. **Command coverage vs U (domain-scoped)** — every relevant command, subcommand,
   and **flag** for this domain is present.
4. **Tool-call correctness** — param names match the actual MCP schema; write
   examples include `confirm=True`; read examples don't.
5. **CLI-example correctness** — flags and syntax match navi's real CLI (the user's
   stated preference: concrete CLI examples with specific flags).
6. **Bidirectional cross-references** — one canonical home per fact; every other
   mention links to it *and* the home is reachable back. (User preference: links go
   both directions, with concrete examples — not bare "see X".)
7. **Currency** — matches v8.5.31; no stale version claims; new flags/commands since
   the skill was last touched are folded in.
8. **Convention consistency** — obeys navi-mcp: tool-invocation-first, read-first,
   write-gate narration, freshness check, output format.
9. **Gotcha capture** — each operational gotcha is in its canonical home and linked:
   the 4-min timeout, export-status CLI polling, cert-binds-to-scanner-UUID, MAC OUI
   fingerprinting (plugin 35716), 30-min propagation, 50K scale fork, `remove=True`
   UUID preservation, "`update full` doesn't build indexes."
10. **Writing style** — imperative; explains *why* a thing matters instead of bare
    MUSTs; realistic examples.
11. **Safe-edit hygiene** — the installed path is read-only; copy to a writeable
    location, **preserve the skill name** (no `-v2`), snapshot before editing.
12. **Test prompts (optional per skill)** — 2–3 realistic prompts to sanity-check
    triggering + behavior. On this platform there are no subagents, so they're run
    one at a time, qualitatively.

---

## 7. Standing invariants (apply to every edit, every file)

- **One canonical home per fact.** Everywhere else cross-references it. Never
  duplicate a fact across skills — duplication is how they drift out of sync.
- **Cross-references are bidirectional and concrete.** Home + back-link, with a real
  CLI example and the specific flags, not a bare pointer. *(User preference.)*
- **Read-first, then write-gated narration.** Every platform-write is described in
  prose, stated as an exact call, and confirmed before invocation. Never batch
  write-gated calls behind one confirmation.
- **Currency is anchored to v8.5.31.** Flag, don't silently assume, anything that
  may have changed across versions.
- **Edits are paste-ready.** Findings come with drop-in replacement text the user
  can apply directly — matching the established workflow.
- **Preserve the operational knowledge.** The non-obvious facts already in the
  skills are the most valuable thing here. Refactor in place; never reset.
- **Principle of lack of surprise.** No change makes a skill do something its
  description wouldn't lead a reader to expect.

---

## 8. What each pass produces

For every file reviewed, the output is the same three things:

1. **Findings list**, severity-tagged:
   - **Blocker** — wrong/misleading (bad param name, wrong flag, incorrect
     write-gating, stale behavior that will fail).
   - **Gap** — missing coverage (command/subcommand/flag absent).
   - **Polish** — consistency, cross-reference, or style.
2. **Paste-ready edits** — the exact replacement text, scoped to the file.
3. **Ledger updates** — new rows appended to §9 so the running state is current.

---

## 9. The gap ledger (running, cross-session state)

The single accumulating record that lets this span many sessions without losing
state. Populated as we go; spun out into its own living file once Phase A begins.

| ID | Source (file / tool) | Type | Severity | Description | Canonical home | Status |
|----|---------------------|------|----------|-------------|----------------|--------|
| — | *(populated during Phase A onward)* | | | | | |

**Conventions:** Type ∈ {Coverage, Schema, Gating, Currency, Consistency,
Xref, Error-handling, Other}. Severity ∈ {Blocker, Gap, Polish}.
Status ∈ {Open, Drafted, Applied, Deferred, Won't-fix (with reason)}.

---

## 10. Session handoff protocol

This is a long effort, so each pass ends the same way:

1. **Findings summary** for the file just reviewed.
2. **Ledger delta** — what got added/changed in §9.
3. **Next file** named explicitly, with what (if anything) I need from you to start
   it.

The ledger is the source of truth between sessions — if context resets, it's the
restart point.

---

### Immediate next step

**Phase A — the MCP server.** I can begin now: load each of the 16 tool schemas,
audit them against §6.A items 1–5 and 7, and open the ledger with whatever surfaces.

Two things that would change the depth of that pass:

- **The crawler output (`navi_documentation.txt`).** Without it, Phase A coverage
  findings are measured against my knowledge of navi, not ground truth — provisional
  until Phase C. *Reminder: we built the crawler script last session but never ran
  it; the doc file doesn't exist yet.*
- **The server source.** Without it, Phase A is a surface review (items 1–5, 7);
  with it, items 6, 8, 9 (error handling, resources, output shape) come into scope.

Neither is required to start. Tell me whether to run Phase A now on the installed
surface, or hold until you've generated the doc file and/or can share the server
source — and I'll proceed accordingly.
