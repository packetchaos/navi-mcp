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

- **Python 3.10 or higher** (the server uses `str | None` syntax)
- **navi CLI** installed and on `PATH` (`pip install navi-hostio` — see
  [packetchaos/navi](https://github.com/packetchaos/navi))
- **API keys set in navi** before starting the server (`navi keys --a <ACCESS_KEY> --s <SECRET_KEY>`)

### Install from source

```bash
git clone https://github.com/packetchaos/navi-mcp
cd navi-mcp
pip install -e .
```

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
python -m navi_mcp
```

### Streamable HTTP (for remote MCP clients)

```bash
python -m navi_mcp --http    # serves on :8000
```

### Claude Desktop config

Add to `claude_desktop_config.json` (location varies by OS — check Anthropic's
docs for your platform):

```json
{
  "mcpServers": {
    "navi": {
      "command": "python",
      "args": ["-m", "navi_mcp"],
      "env": {
        "NAVI_SKILL_DIR": "/absolute/path/to/navi-claude-skills",
        "NAVI_MCP_ALLOW_WRITES": "0"
      }
    }
  }
}
```

Restart Claude Desktop. The `navi_workflow` prompt appears as a slash command;
type `/navi_workflow` in a chat to load the navi router skill and start working
against your Tenable tenant.

To enable writes (tag creation, ACR adjustment, scan control, deletion), change
`"NAVI_MCP_ALLOW_WRITES": "0"` to `"1"` and restart the server. See
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
| `navi_config` | Configure SLA, software table, FedRAMP URL | URL only |
| `navi_explore_query` | SQL against navi.db — reads free, writes need `confirm=True` | Local only |
| `navi_explore_data` | 17 canned query subcommands (cve, exploit, xrefs, etc.) | No |
| `navi_explore_info` | 26 live platform lookups (scanners, scans, users, policies...) | No |
| `navi_enrich_tag` | Tagging with 20+ selectors | **Yes** |
| `navi_enrich_acr` | ACR adjustment with Change Reasons (set/inc/dec, business/compliance/mitigation/development) | **Yes** |
| `navi_enrich_add` | Import assets from CMDB / AWS / external sources | **Yes** |
| `navi_export` | 15 CSV export subcommands (bytag includes ACR+AES) | No |
| `navi_scan` | Create/start/stop/evaluate scans | Create/start/stop |
| `navi_was` | Web App Scanning (DAST) — configs, scans, details, stats, export, upload | Scan/start/upload |
| `navi_action_delete` | Delete tags, users, scans, assets, agents, exclusions | **Yes** (destructive) |
| `navi_action_rotate` | Rotate a user's API keys | **Yes** |
| `navi_action_cancel` | Cancel a running export | **Yes** |
| `navi_action_encrypt` | Encrypt a local file | Local file only |
| `navi_action_decrypt` | Decrypt a local file | Local file only |

### Resources

- **`navi://schema/{table}`** — column definitions for any navi.db table
- **`navi://workdir`** — workdir path, navi.db status, write-gate state, skill directory
- **`navi://skill/{name}`** — load a [navi-claude-skills](https://github.com/packetchaos/navi-claude-skills) domain skill on demand (`mcp`, `core`, `troubleshooting`, `enrich`, `acr`, `explore`, `export`, `scan`, `action`, `was`, `router`)

### Prompts

- **`navi_workflow [task]`** — injects the navi router skill and frames the
  user's task. Claude pulls in additional domain skills on demand via the
  `navi://skill/{name}` resource.

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
- **Too heavy for a tool call** — `navi config update full` (first-run syncs
  can pull hundreds of GB, take hours). Operators run this at their terminal.
- **Out of scope** — `navi action deploy`, `navi action automate`, `navi action
  plan`, `navi enrich attribute`, `navi enrich migrate`, `navi enrich tagrule`,
  `navi keys`.

See `navi-claude-skills/navi-mcp/SKILL.md` for the full rationale.

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_WORKDIR` | `~/.navi-mcp` | Where `navi.db` and CSVs live |
| `NAVI_BIN` | `navi` | Path to the navi executable (override if not on `PATH`) |
| `NAVI_MCP_ALLOW_WRITES` | unset | Set to `1` to enable platform-write tools |
| `NAVI_SKILL_DIR` | `<pkg>/resources/skills` | Path to a [navi-claude-skills](https://github.com/packetchaos/navi-claude-skills) checkout |
| `NAVI_SKILL_PATH` | unset | **Deprecated** — legacy single-file skill path. Use `NAVI_SKILL_DIR` instead. |

---

## API keys

**Claude never sees your API keys.** They're set once, out-of-band, before
the server starts:

```bash
navi keys --a <ACCESS_KEY> --s <SECRET_KEY>
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

- **"Zero chunks" on update commands** → API key permissions
- **`sqlite3.OperationalError: database is locked`** → disk speed; drop
  `--threads` on full sync
- **Commands return empty results** → navi.db empty (needs
  `navi config update full`) or keys not set
- **Schema errors after upgrade** → `rm navi.db && navi keys ... && navi config update full`

If the server fails to start, check:

- Python version is 3.10+
- `navi` is on `PATH` or `NAVI_BIN` points at the binary
- `navi keys` has been set (the server itself doesn't check, but nothing works
  without them)

Logs go to stderr. Start the server from a terminal to see them, or redirect
with your MCP client's logging.

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
