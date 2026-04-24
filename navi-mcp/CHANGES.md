# server.py changes for navi-claude-skills integration

Five patches applied to `server.py` to align with the `navi-claude-skills`
split-skill design and to fix three tool signatures that had drifted from
the current navi CLI surface.

## 1. Skill loader: `SKILL_PATH` → `SKILL_DIR` with legacy fallback

**What changed.** The server previously injected a single SKILL.md file
via the `navi_workflow` prompt. The new `navi-claude-skills` repo is 11
separate skills — one router plus ten domain skills. The server now:

- Reads from `NAVI_SKILL_DIR` (a directory containing the full
  navi-claude-skills repo).
- Exposes each domain skill via a new `navi://skill/{name}` resource.
- Injects the router (`navi/SKILL.md`) via the `navi_workflow` prompt.
- Tells Claude in the prompt framing that domain skills are available on
  demand via the resource.

**Backward compatibility.** If the old `NAVI_SKILL_PATH` env var is set
(pointing at a single monolithic SKILL.md), the server continues to work
that way — it injects the monolith and the `navi://skill/{name}` resource
returns a migration notice directing operators to set `NAVI_SKILL_DIR`
instead. No breaking change for existing deployments.

**New env var:**
- `NAVI_SKILL_DIR` (default: `<server_dir>/resources/skills`) — path to
  the navi-claude-skills directory.

**Deprecated but still honored:**
- `NAVI_SKILL_PATH` — triggers legacy single-file mode. Deprecation
  message appears in `navi://workdir` output and the skill loader.

**Operator migration:**
```bash
git clone https://github.com/packetchaos/navi-claude-skills
export NAVI_SKILL_DIR=/path/to/navi-claude-skills
unset NAVI_SKILL_PATH  # if previously set
python -m navi_mcp
```

## 2. `navi_explore_query`: allow writes with `confirm=True`

**What changed.** Previously strictly read-only — the server enforced
`mode=ro` on the SQLite connection and banned all non-SELECT statements.

Now supports both:
- **Reads** (SELECT/WITH) — default, no confirmation required, unchanged
  behavior.
- **Writes** (CREATE INDEX, UPDATE, DELETE, DDL) — require `confirm=True`.
  Opens DB in read-write mode, commits, returns `rows_affected`.

**Permanent guardrails remain.** `ATTACH DATABASE` and
`PRAGMA journal_mode` are banned in all modes (even with confirm=True) —
they can corrupt navi.db beyond recovery via `navi_config_update`.

**`NAVI_MCP_ALLOW_WRITES` is NOT required for this tool.** Rationale:
the platform-write gate exists to protect Tenable platform state.
Local-only navi.db writes are recoverable via `navi_config_update(kind=...)`.
Requiring both confirm AND the env var would be heavy-handed for DDL like
`CREATE INDEX` that's used to accelerate workflows.

**Skill impact.** navi-core's Troubleshooting "Slow tagging (SQL index)"
section and navi-explore's "reads and writes" section now work as
documented.

## 3. `navi_enrich_acr`: new signature

**What changed.** The old tool signature was `(category, value, acr,
confirm)` — it passed `--acr` to the CLI and omitted `--mod`. The current
navi CLI expects `--score` (not `--acr`) and requires `--mod` to be set
explicitly. The old signature would likely fail against current navi.

New signature:

```python
navi_enrich_acr(
    category: str,
    value: str,
    score: int,                    # was `acr`; maps to --score
    mod: Literal["set","inc","dec"] = "set",  # new; maps to --mod
    note: str | None = None,       # new; maps to --note
    business: bool = False,        # new; maps to -business
    compliance: bool = False,      # new; maps to -compliance
    mitigation: bool = False,      # new; maps to -mitigation
    development: bool = False,     # new; maps to -development
    confirm: bool = False,
)
```

**New validation.** At least one Change Reason flag (`business`,
`compliance`, `mitigation`, `development`) is required — Tenable One
requires a reason on every ACR adjustment for audit compliance. Raises
NaviError if all four are False.

**Breaking change warning.** Any existing caller using the old `acr=N`
parameter name will break. The parameter is now `score=N`. Document this
clearly in release notes.

**Skill impact.** navi-acr fully documents the new signature including
Change Reason mapping, mod semantics (set/inc/dec), and the note
parameter for audit trail.

## 4. `navi_was`: add `file` parameter for upload

**What changed.** The `upload` subcommand previously took no arguments —
it called `navi was upload` with nothing. That's non-functional if navi's
upload expects a file path.

New signature adds `file: str | None = None`. When
`subcommand="upload"`, `file` is required and maps to `--file <path>`.

**Breaking change warning.** Any existing caller invoking
`navi_was(subcommand="upload", confirm=True)` without a file parameter
will now get a clear error instead of silently running without a file.

**Skill impact.** navi-was's upload example now matches the documented
tool form.

## 5. Module docstring and startup log

**What changed.** The module docstring at the top of `server.py` was
updated to reflect:
- Corrected subcommand counts (17 for `navi_explore_data`, 26 for
  `navi_explore_info`)
- `navi_explore_query` supporting reads + writes
- `navi_enrich_acr` with mod + Change Reasons
- `navi_was` upload taking a file
- New `navi://skill/{name}` resource
- Skill directory (not single file)

The startup log in `main()` now reports skill mode (split vs. legacy) and
skill location, so operators can verify their configuration at boot.

---

## Summary

| Change | Breaking? | Affected callers |
|---|---|---|
| `NAVI_SKILL_DIR` added, `NAVI_SKILL_PATH` deprecated | No — legacy fallback | Operators who want split skills must set new env var |
| `navi_explore_query` supports writes via `confirm=True` | No — reads unchanged | Enables new skill patterns (SQL index workflows) |
| `navi_enrich_acr` new signature | **Yes** | Replace `acr=N` with `score=N, mod="set", <reason>=True` |
| `navi_was(upload)` now requires `file` | **Yes** | Add `file="..."` argument |
| Module docstring + startup log | No | Documentation only |

## Testing checklist

Before tagging a release:

- [ ] Unset `NAVI_SKILL_PATH`, set `NAVI_SKILL_DIR=/path/to/navi-claude-skills`, verify the router loads via the `navi_workflow` prompt.
- [ ] Verify each domain skill loads via `navi://skill/{name}` for all 11 names (router, mcp, core, troubleshooting, enrich, acr, explore, export, scan, action, was).
- [ ] Verify `navi://workdir` shows `skill dir: /path/to/navi-claude-skills`.
- [ ] Set legacy `NAVI_SKILL_PATH`, verify the prompt injects that file and `navi://skill/{name}` returns the migration notice.
- [ ] `navi_explore_query(sql="SELECT count(*) FROM vulns;")` — works, reads 500 rows max.
- [ ] `navi_explore_query(sql="CREATE INDEX idx_test ON vulns(plugin_id);")` — fails without confirm.
- [ ] `navi_explore_query(sql="CREATE INDEX idx_test ON vulns(plugin_id);", confirm=True)` — succeeds, returns `mode: "write"`.
- [ ] `navi_explore_query(sql="ATTACH DATABASE ...", confirm=True)` — fails (banned always).
- [ ] `navi_enrich_acr(category="X", value="Y", score=10, confirm=True)` — fails (no Change Reason).
- [ ] `navi_enrich_acr(category="X", value="Y", score=10, business=True, confirm=True)` — succeeds (writes enabled).
- [ ] `navi_enrich_acr(..., mod="inc", score=3, business=True, confirm=True)` — verify `--mod inc` appears in CLI args.
- [ ] `navi_was(subcommand="upload", confirm=True)` — fails with clear error about missing file.
- [ ] `navi_was(subcommand="upload", file="/path/to/scan.nessus", confirm=True)` — succeeds.
- [ ] Startup log shows `skill_mode=split` when `NAVI_SKILL_DIR` is set and
  `skill_mode=legacy single-file` when `NAVI_SKILL_PATH` is set.
