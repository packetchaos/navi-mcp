# navi-mcp

**Model Context Protocol (MCP) server for [navi](https://github.com/packetchaos/navi)** — giving
Claude direct, tool-based access to Tenable Vulnerability Management through the
navi CLI.

Claude sees a curated set of MCP tools (`navi_enrich_tag`, `navi_explore_query`,
`navi_export`, etc.) instead of generating raw `navi` bash commands for the user
to copy-paste. Writes require explicit confirmation. Destructive operations are
double-gated — an environment variable AND a per-call flag. The accompanying
[navi-claude-skills](https://github.com/packetchaos/navi-claude-skills) repo
teaches Claude how to use every tool effectively.

**Status: 1.0 — stable.**

---

## What it does

Runs the navi CLI on behalf of Claude via MCP. Instead of:

> Run this command:
> ```bash
> navi enrich tag --c "Environment" --v "Production" --group "Production Servers"
> ```

Claude does:

> I'll tag production servers with `Environment:Production`. This writes to
> Tenable — confirm and I'll apply it.
>
> *[calls `navi_enrich_tag(category="Environment", value="Production", group="Production Servers", confirm=True)`]*

The server handles CLI invocation, subprocess timeouts, write-gate enforcement,
CSV export path tracking, and result parsing. Claude handles intent, narration,
and user confirmation.

---

## Installation

### Prerequisites

- **Python 3.12 or higher.** navi itself requires 3.12+; the MCP server only
  needs 3.10+ (it uses `str | None` syntax), but since both run under the same
  interpreter, 3.12+ is the practical floor.
- **navi CLI** installed and on `PATH` (`pip install navi-hostio` — see
  [packetchaos/navi](https://github.com/packetchaos/navi)).
- **API keys set in navi** before starting the server
  (`navi config keys --a <ACCESS_KEY> --s <SECRET_KEY>`).

### Install from source

```bash
git clone https://github.com/packetchaos/navi-mcp
cd navi-mcp
pip install -e .
```

This makes the package importable as `navi_mcp` (so `python -m navi_mcp` works).
You can also run the server file directly without installing — see
[Running it](#running-it).

### Skill set (recommended)

For Claude to drive navi-mcp effectively, pair it with the skills repo:

```bash
git clone https://github.com/packetchaos/navi-claude-skills
export NAVI_SKILL_DIR=/path/to/navi-claude-skills
```

navi-mcp works without the skills — Claude will still call the tools correctly
based on their schemas — but the skills add operational context (write-gate
ceremony, tag UUID preservation, ACR Change Reasons, freshness checks, the
Executive Dashboard workflow) that makes Claude's output significantly sharper.

---

## Running it

### stdio (for Claude Desktop, Claude Code)

```bash
python -m navi_mcp                      # if installed as a package
python /path/to/navi-mcp/server.py      # or run the file directly
```

A stdio server prints a startup line to **stderr** and then waits silently for
a client to connect — that's normal, not a hang.

### Streamable HTTP (for remote MCP clients)

```bash
python -m navi_mcp --http               # serves on :8000
```

### Claude Desktop config

Open **Settings → Developer → Edit Config** and add a `navi` server. Two
things trip people up, so the example below addresses both:

- **Use an absolute path to the Python interpreter**, not a bare `"python"`.
  Claude Desktop launches the server with a minimal environment, so `"python"`
  often resolves to the wrong interpreter (or none). Use the interpreter that
  has both `mcp` and `navi` installed.
- **Point at the server explicitly** — either the absolute path to `server.py`,
  or `-m navi_mcp` if you `pip install -e .`'d it into that same interpreter.

```json
{
  "mcpServers": {
    "navi": {
      "command": "/absolute/path/to/python3",
      "args": ["/absolute/path/to/navi-mcp/server.py"],
      "env": {
        "NAVI_BIN": "/absolute/path/to/navi",
        "NAVI_WORKDIR": "/absolute/path/to/folder-with-navi.db",
        "NAVI_SKILL_DIR": "/absolute/path/to/navi-claude-skills",
        "NAVI_MCP_ALLOW_WRITES": "0"
      }
    }
  }
}
```

Not sure of your paths? Run `tools/navi_mcp_config.py` (included in this repo)
with the interpreter you intend to use — it discovers `server.py`, `navi.db`,
the `navi` binary, and the skills directory, and prints this exact block.

Save, then **fully quit and reopen Claude Desktop** — config is read only at
launch. The `navi_workflow` prompt then appears as a slash command: type
`/navi_workflow` in a chat to load the navi router skill and start working
against your Tenant.

To enable writes (tag creation, ACR adjustment, scan control, deletion), change
`"NAVI_MCP_ALLOW_WRITES": "0"` to `"1"` and restart. See
[Write-gate design](#write-gate-design) below.

### Other MCP clients

navi-mcp follows the standard MCP protocol — any compliant client should work.
stdio and streamable HTTP transports are both supported. If you test against a
specific client and hit issues, please file them.

---

## What's exposed

### Tools

| Tool | Purpose | Writes? |
|---|---|---|
| `navi_config_update` | Targeted database refreshes (vulns, assets, agents, etc.) | No |
| `navi_config` | Configure SLA, software table, certificate table, FedRAMP URL | URL only |
| `navi_explore_query` | SQL against navi.db — reads free, writes need `confirm=True` | Local only |
| `navi_explore_data` | Canned query subcommands (cve, exploit, xrefs, plugin, port, db-info, etc.) | No |
| `navi_explore_info` | Live platform lookups (scanners, scans, users, policies, tags...) | No |
| `navi_enrich_tag` | Tagging with 20+ selectors | **Yes** |
| `navi_enrich_acr` | ACR adjustment with Change Reasons (set/inc/dec, business/compliance/mitigation/development) | **Yes** |
| `navi_enrich_add` | Import assets from CMDB / AWS / external sources | **Yes** |
| `navi_export` | 15 CSV export subcommands (bytag includes ACR+AES) | No |
| `navi_scan` | Scan control (create/start/stop/pause/resume), read views (status/details/history/hosts/latest), and `evaluate` performance analysis | Create/start/stop/pause/resume |
| `navi_was` | Web App Scanning (DAST) — configs, scans, details, stats, export, upload | Scan/start/upload |
| `navi_action_delete` | Delete Tenable objects: tags, by-tag, assets, scans, users, target groups, user groups, ACR tone | **Yes** (destructive) |
| `navi_action_rotate` | Rotate a user's API keys | **Yes** |
| `navi_action_cancel` | Cancel a running export (by `uuid`) | **Yes** |
| `navi_action_encrypt` | Encrypt a local file | Local file only |
| `navi_action_decrypt` | Decrypt a local file | Local file only |

### Resources

- **`navi://schema/{table}`** — column definitions for any navi.db table
- **`navi://workdir`** — workdir path, navi.db status + freshness, write-gate state, skill directory
- **`navi://skill/{name}`** — load a [navi-claude-skills](https://github.com/packetchaos/navi-claude-skills) domain skill on demand (`router`, `core`, `mcp`, `troubleshooting`, `enrich`, `acr`, `explore`, `export`, `scan`, `action`, `was`)
- **`navi://skill/{name}/{ref}`** — load a skill's bundled reference file (e.g. `navi://skill/core/schema`, `navi://skill/enrich/selectors`)

### Prompts

- **`navi_workflow [task]`** — surfaces as the `/navi_workflow` slash command.
  Injects the navi router skill and frames the user's task; Claude pulls in
  additional domain skills on demand via the `navi://skill/{name}` resource.

---

## Write-gate design

Any operation that changes state on the Tenable platform is double-gated:

1. **Environment variable** — `NAVI_MCP_ALLOW_WRITES=1` must be set when the
   server starts. Without it, every write-gated tool call fails with a clear
   error and no retry.
2. **Per-call flag** — every write-gated tool requires `confirm=True`. Without
   it, the call fails even when writes are globally enabled.

This protects against two different failure modes:

- **Accidental server misuse** — a read-only deployment can't accidentally
  become a write-capable one (the env var controls it at startup).
- **Accidental LLM writes** — even in a write-capable deployment, Claude can't
  fire off writes silently (it has to narrate + confirm first).

Claude's convention (documented in `navi-claude-skills/navi-mcp/SKILL.md`) is
to describe the operation in prose, state the exact tool call, wait for the
user's confirmation in chat, and only then invoke with `confirm=True`.

### Local writes against `navi.db`

`navi_explore_query` is a special case. Writes (CREATE INDEX, UPDATE, DELETE,
DDL) require `confirm=True` but do NOT require `NAVI_MCP_ALLOW_WRITES`. Local
navi.db modifications are recoverable via `navi_config_update`, so they don't
need the platform-write gate.

Two operations are banned even with `confirm=True`: `ATTACH DATABASE` and
`PRAGMA journal_mode` changes — they can corrupt navi.db in ways
`navi_config_update` can't recover from.

### Commands not exposed

Some navi commands are intentionally NOT wrapped as MCP tools:

- **Hazardous to automate** — `navi action push` (remote shell execution),
  `navi action mail` (email delivery). Kept CLI-only. Skills explain them to
  users as CLI steps when a workflow needs them.
- **Too heavy / too slow for a tool call** — `navi config update full`
  (first-run syncs can pull hundreds of GB and run for hours). Operators run
  this at their terminal. Note that even *targeted* refreshes
  (`navi_config_update(kind="vulns")`) can exceed an MCP client's call timeout
  on a large tenant — see [Troubleshooting](#troubleshooting).
- **Out of scope** — `navi action deploy`, `navi action automate`, `navi action
  plan`, `navi enrich attribute`, `navi enrich migrate`, `navi enrich tagrule`,
  `navi config keys`.

See `navi-claude-skills/navi-mcp/SKILL.md` for the full rationale.

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_WORKDIR` | `~/.navi-mcp` | Where `navi.db` and CSVs live. **Set this** — the default is rarely where your `navi.db` actually is. |
| `NAVI_BIN` | `navi` | Path to the navi executable. Set to an absolute path when launched from Claude Desktop (its `PATH` won't include your shell's). |
| `NAVI_MCP_ALLOW_WRITES` | unset | Set to `1` to enable platform-write tools. |
| `NAVI_SKILL_DIR` | `<pkg>/resources/skills` | Path to a [navi-claude-skills](https://github.com/packetchaos/navi-claude-skills) checkout. |
| `NAVI_SKILL_PATH` | unset | **Deprecated** — legacy single-file skill path. Use `NAVI_SKILL_DIR` instead. |

---

## API keys

**Claude never sees your API keys.** They're set once, out-of-band, before
the server starts:

```bash
navi config keys --a <ACCESS_KEY> --s <SECRET_KEY>
python -m navi_mcp
```

The keys live in `navi.db` alongside the tenant data. If `navi.db` is deleted
(e.g. after a navi upgrade that triggers a schema mismatch), keys need to be
re-entered before the server can do anything useful again. Store them in a
password manager or environment secret store so re-entry is quick.

---

## Troubleshooting

Most issues have fixes documented in the
[navi-claude-skills/navi-troubleshooting](https://github.com/packetchaos/navi-claude-skills/blob/main/navi-troubleshooting/SKILL.md)
skill. Common ones:

- **`can't open file '.../server.py'` on startup** → the `args` path in your
  config doesn't exist. Zip extraction often nests a folder
  (`navi-mcp-suite/navi-mcp-suite/server/server.py`). Run
  `tools/navi_mcp_config.py` to detect the real path.
- **`No module named navi_mcp`** → you're launching with `-m navi_mcp` but the
  package isn't installed in *that* interpreter. Either `pip install -e .` into
  it, or switch the config to the direct `server.py` path.
- **`No module named mcp`** → the MCP SDK isn't in the launching interpreter:
  `</absolute/python3> -m pip install --upgrade mcp`.
- **Tool calls time out (`MCP error -32001: Request timed out`)** → the call
  exceeded the client's ~4-minute ceiling. Long syncs — `navi_config_update`
  for `vulns`/`assets` on a large tenant — must be run at the CLI
  (`navi config update vulns`), not through a tool call.
- **"Unauthorized / You may not be authorized or your keys are invalid"** →
  API key permissions or invalid/expired keys. Re-check `navi config keys` and
  that the keys carry the needed permissions.
- **`sqlite3.OperationalError: database is locked`** → disk speed; drop
  `--threads` on full sync, and don't run a CLI sync and a tool call against the
  same `navi.db` simultaneously.
- **Commands return empty results** → navi.db empty (needs
  `navi config update full`) or keys not set.
- **Schema errors after upgrade** → `rm navi.db && navi config keys ... && navi config update full`.

If the server fails to start, check:

- Python version is 3.12+ (3.10+ for the server alone)
- `navi` is on `PATH` or `NAVI_BIN` points at the binary (absolute path)
- `navi config keys` has been set (the server itself doesn't check, but nothing
  works without them)

Logs go to stderr. Start the server from a terminal to see them, or check your
MCP client's logs (Claude Desktop: `~/Library/Logs/Claude/mcp.log`).

---

## Contributing

Issues and PRs welcome. A few guidelines:

- **Tool signatures must match navi's CLI.** If navi's CLI changes, tools need
  to follow. If you're adding a new tool, wrap an existing navi command —
  don't re-implement logic.
- **Write-gate new tools by default.** Anything that mutates Tenable platform
  state needs both `_require_writes()` and `_require_confirm()` guards. If
  you're unsure whether a new tool needs gating, it probably does.
- **Keep skills in sync.** The
  [navi-claude-skills](https://github.com/packetchaos/navi-claude-skills) repo
  documents the tool interface. Breaking signature changes need matching
  skill updates — open PRs on both repos in the same week.

### Running tests

```bash
pip install -e ".[dev]"
pytest
```

---

## Related projects

- **[navi](https://github.com/packetchaos/navi)** — the underlying CLI
- **[navi-claude-skills](https://github.com/packetchaos/navi-claude-skills)** — Claude skill set for driving navi-mcp

---

## License

MIT.
