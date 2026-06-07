# navi-mcp suite

An MCP server for the [Tenable **navi** CLI](https://github.com/packetchaos/navi)
(Tenable Vulnerability Management / Tenable One), plus a set of 11 companion
Claude skills that document how to drive it well.

This repository is the result of a full audit and rebuild: the server's tool
surface was corrected against an authoritative recursive `navi --help` capture,
and all 11 skills were corrected to match the server + CLI and restructured for
progressive disclosure.

## Layout

```
server/      server.py — the MCP server (17 tools + resources)
skills/      the 11 corrected skills, in NAVI_SKILL_DIR layout
             (<skill>/SKILL.md, plus references/ on the denser ones)
dist/        the same 11 skills packaged as .skill files
tools/       navi_mcp_config.py — auto-detects paths, emits the install config
docs/        audit framework, gap ledger, verified findings, help-crawler
INSTALL.md   step-by-step install for Claude Desktop
README.md    this file
```

### The 11 skills

`navi` (router) · `navi-core` · `navi-mcp` · `navi-troubleshooting` ·
`navi-acr` · `navi-export` · `navi-scan` · `navi-was` · `navi-action` ·
`navi-explore` · `navi-enrich`

Each `SKILL.md` is under 500 lines. Deep material (full schema, exhaustive
selector catalog, long worked examples) lives in `references/*.md` and is
pulled on demand.

## Running the MCP server

The server shells out to the `navi` binary and reads the local `navi.db`. It
does **not** manage API keys — set those out-of-band with `navi config keys`
first (see `skills/navi-core`).

Launch it over stdio (for Claude Desktop / Claude Code) or HTTP:

```bash
python server/server.py            # stdio (default); waits for a client
python server/server.py --http     # streamable HTTP on :8000
```

Environment variables:

| Var | Purpose | Default |
|---|---|---|
| `NAVI_SKILL_DIR` | Path to the **`skills/`** directory in this repo (so the `navi://skill/...` resources resolve) | — |
| `NAVI_MCP_ALLOW_WRITES` | Set to `1` to enable platform-write tools (tagging, ACR, delete, rotate, scan control, …). Off = read-only. | unset (read-only) |
| `NAVI_WORKDIR` | Directory holding `navi.db` and CSV exports | cwd |
| `NAVI_BIN` | Path to the `navi` executable | `navi` |

Point `NAVI_SKILL_DIR` at this repo's `skills/` folder (not `dist/` — the
server reads unpacked folders, not `.skill` zips).

### Install in Claude Desktop

Full walkthrough in **[INSTALL.md](INSTALL.md)**. The short version: don't
hand-write paths — run the helper with the Python interpreter you want Claude
Desktop to use (the one that has `mcp` and `navi`), and it discovers
`server/server.py`, your `navi.db`, the `navi` binary, and `skills/`, then
prints (or, with `--write`, installs) the config:

```bash
python tools/navi_mcp_config.py            # print the mcpServers JSON
python tools/navi_mcp_config.py --write    # merge it into your Claude Desktop config (backs up first)
```

The launched server entry is `server/server.py` (use an **absolute** path in
the config — Claude Desktop won't have your shell's `PATH`). After editing the
config, fully quit and reopen Claude Desktop, then read `navi://workdir` to
confirm it connected.

### Tools (17) and the write-gate

Read tools (`navi_explore_data`, `navi_explore_info`, `navi_explore_query`
SELECT, `navi_export`, `navi_explore_api` GET, scan read views, …) run freely.
**Platform-write tools require both `NAVI_MCP_ALLOW_WRITES=1` and `confirm=True`**
and are meant to be narrated to the user before invocation:
`navi_enrich_tag`, `navi_enrich_acr`, `navi_enrich_add`, `navi_scan`
(create/start/stop/pause/resume), `navi_was` (scan/start/upload),
`navi_action_delete`, `navi_action_rotate`, `navi_action_cancel`,
`navi_config(kind="url")`, and `navi_explore_api` POST/PUT.

### Resources

- `navi://schema/{table}` — live column definitions for a navi.db table
- `navi://workdir` — workdir, write-gate status, binary, call budget, and navi.db freshness
- `navi://skill/{name}` — load a skill (router/core/mcp/…); lists its references
- `navi://skill/{name}/{ref}` — load a bundled reference (e.g. `navi://skill/core/schema`)

Plus the `navi_workflow` prompt, which injects the router skill.

### Long-running operations

navi exports can run for tens of minutes on large tenants — past the MCP host's
~4-minute tool-call ceiling. The server enforces a call budget (~220s) and
returns a clean error naming the CLI command to run instead. Foundational syncs
(`navi config update full`) and remote command execution (`navi action push`)
are intentionally CLI-only. See `skills/navi-core` and `skills/navi-troubleshooting`.

## Installing the skills as Claude skills

The files in `dist/` are packaged for installing in Claude.ai / Claude Cowork /
Claude Code as skills. (The MCP server uses the unpacked `skills/` folders via
`NAVI_SKILL_DIR`; the two are the same content in two delivery formats.)

## Validation status

`server.py` compiles cleanly and every tool is annotated. It has **not** been
runtime-tested against a live Tenable tenant. Before relying on it, validate the
root-cause fix with one live read, e.g.
`navi_explore_data(subcommand="cve", cve="CVE-2021-44228")`. The tool
annotations require a recent `mcp` SDK.

See `docs/verified-findings.md` for the per-bug inventory and
`docs/gap-ledger.md` for the full audit trail.
