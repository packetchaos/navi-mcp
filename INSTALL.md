# Installing the navi-mcp server in Claude Desktop

This server runs the `navi` CLI on your behalf. It does **not** manage API keys —
those are set out-of-band in navi before you start.

## 1. Prerequisites

- **Python 3.12+** (navi requires it).
- **navi installed and configured**, with a populated database:
  ```bash
  pip3 install navi-pro
  navi config keys --a "<ACCESS_KEY>" --s "<SECRET_KEY>"
  navi config update full          # populates navi.db — do this before connecting
  ```
- **The MCP SDK** in the *same* Python you'll point Claude Desktop at:
  ```bash
  <that-python> -m pip install --upgrade mcp
  ```

## 2. Generate your config (recommended)

You don't have to hand-write paths. Run the included helper **with the Python
interpreter you want Claude Desktop to use** — the one that has `mcp` and `navi`:

```bash
/path/to/python3 tools/navi_mcp_config.py
```

It searches the usual locations, finds `server/server.py`, your `navi.db`
(→ `NAVI_WORKDIR`), the `navi` binary (→ `NAVI_BIN`), and `skills/`
(→ `NAVI_SKILL_DIR`), and prints a ready-to-paste `mcpServers` block. A
diagnostic checklist goes to stderr so you can see what it found (and what it
didn't).

To merge it straight into your Claude Desktop config (it backs up the existing
file first, then adds a `navi` entry — your other settings are preserved):

```bash
/path/to/python3 tools/navi_mcp_config.py --write
```

Add `--allow-writes` when you want tagging / ACR / delete enabled (it sets
`NAVI_MCP_ALLOW_WRITES=1`). Leave it off to start read-only.

If a path comes back wrong or missing, pin it explicitly, e.g.:

```bash
/path/to/python3 tools/navi_mcp_config.py \
  --server /abs/path/to/navi-mcp-suite/server/server.py \
  --skills /abs/path/to/navi-mcp-suite/skills \
  --workdir /abs/path/to/folder-with-navi.db
```

## 3. Or write the config by hand

Open **Settings → Developer → Edit Config** and add a `navi` server. Use
**absolute paths** — Claude Desktop launches the server with a minimal
environment, so a bare `"python"` or relying on `PATH` for `navi` will fail.

```json
{
  "mcpServers": {
    "navi": {
      "command": "/absolute/path/to/python3",
      "args": ["/absolute/path/to/navi-mcp-suite/server/server.py"],
      "env": {
        "NAVI_BIN": "/absolute/path/to/navi",
        "NAVI_WORKDIR": "/absolute/path/to/folder-with-navi.db",
        "NAVI_SKILL_DIR": "/absolute/path/to/navi-mcp-suite/skills",
        "NAVI_MCP_ALLOW_WRITES": "0"
      }
    }
  }
}
```

Path reference for this suite:

| Config key | Points at |
|---|---|
| `args[0]` | `navi-mcp-suite/server/server.py` |
| `NAVI_SKILL_DIR` | `navi-mcp-suite/skills` (the unpacked folders, **not** `dist/`) |
| `NAVI_WORKDIR` | the folder that contains your `navi.db` |
| `NAVI_BIN` | the `navi` executable (often next to your `python3`) |
| `command` | the `python3` that has `mcp` installed |

If you already have an `"mcpServers"` block, add the `navi` entry inside it
rather than creating a second one.

## 4. Restart and verify

**Fully quit Claude Desktop (⌘Q) and reopen** — the config is read only at
launch. Then confirm it connected: ask Claude to read the `navi://workdir`
resource. It should report your `navi.db` location, freshness, and whether
writes are enabled. The `navi_workflow` prompt also becomes available (it
surfaces as `/navi` in Desktop — that's the connector name).

## Troubleshooting

- **`can't open file '.../server.py'`** — the `args` path doesn't exist. Zip
  extraction often nests a folder (`navi-mcp-suite/navi-mcp-suite/server/...`).
  Re-run `tools/navi_mcp_config.py` to get the real path.
- **`No module named mcp`** — the SDK isn't in the launching interpreter:
  `</abs/python3> -m pip install --upgrade mcp`.
- **`No module named navi_mcp`** — you're launching with `-m navi_mcp` but the
  package isn't installed in that interpreter. Use the direct `server/server.py`
  path instead (what the helper emits).
- **Tool call times out (`Request timed out`)** — it exceeded the client's
  ~4-minute ceiling. Run long syncs (`navi config update vulns`/`assets` on a
  big tenant) at the CLI, not through a tool call.
- **"Unauthorized / keys invalid"** — API key permissions, or invalid/expired
  keys. Re-check `navi config keys`.
- **Where are the logs?** macOS: `~/Library/Logs/Claude/mcp.log`.
