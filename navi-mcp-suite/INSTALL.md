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
  Note **where** you run that last command: navi writes `navi.db` into the
  current directory, and that directory is what `NAVI_WORKDIR` must point at.
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
didn't) — read it, especially the `navi.db` line.

To merge it straight into your Claude Desktop config (it backs up the existing
file first, then adds a `navi` entry — your other settings are preserved):

```bash
/path/to/python3 tools/navi_mcp_config.py --write
```

### Gate flags

Leave them all off to start read-only. That is the recommended first install:
connect, verify it is pointed at the right database, then open gates.

| Flag | Sets | Enables |
|---|---|---|
| `--allow-writes` | `NAVI_MCP_ALLOW_WRITES=1` | tagging, ACR, asset import, scan/WAS control, deletes, key rotation, export cancel, local table rebuild |
| `--allow-email` | `NAVI_EMAIL=1` | `navi_action_mail` — **requires `--allow-writes` too** |
| `--allow-remote-code-execution` | `NAVI_REMOTE_CODE_EXECUTION=1` | `navi_action_push` — **requires `--allow-writes` too** |

The last two have no effect on their own: each stacks *on top of* the write
gate, so that enabling ordinary writes never silently grants you email or a
remote shell. Only add them if you actually want the server to send mail or run
commands on other machines. Email also needs `navi config smtp` and push needs
`navi config ssh`, both set out-of-band in navi itself.

Every gated tool additionally requires `confirm=True` on each individual call —
that one is not configured here, it is passed at call time after the assistant
tells you what it is about to do. See the README's **Gates** section for how the
three layers compose.

Example: `... --write --allow-writes --allow-email`

If a path comes back wrong or missing, pin it explicitly:

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
        "NAVI_MCP_ALLOW_WRITES": "0",
        "NAVI_EMAIL": "0",
        "NAVI_REMOTE_CODE_EXECUTION": "0"
      }
    }
  }
}
```

Only the literal string `"1"` opens a gate. `"0"`, `"true"`, `"yes"`, and an
absent key all mean off — so a typo fails closed.

Path reference for this suite:

| Config key | Points at |
|---|---|
| `args[0]` | `navi-mcp-suite/server/server.py` |
| `NAVI_SKILL_DIR` | `navi-mcp-suite/skills` (the unpacked folders, not a packaged `.plugin`) |
| `NAVI_WORKDIR` | the folder that contains your `navi.db` |
| `NAVI_BIN` | the `navi` executable (often next to your `python3`) |
| `command` | the `python3` that has `mcp` installed |

Both path defaults are traps if you omit the key: `NAVI_WORKDIR` falls back to
`~/.navi-mcp` (which the server creates empty, so every read returns nothing),
and `NAVI_SKILL_DIR` falls back to a `resources/skills` folder beside
`server.py` that does not exist in this layout (so skill resources 404). Set
both explicitly.

If you already have an `"mcpServers"` block, add the `navi` entry inside it
rather than creating a second one.

## 4. Smoke-test before connecting

From the checkout, on the machine you just installed on:

```bash
/path/to/python3 server/tests/run_all.py
```

This imports `server.py`, registers all 20 tools, and asserts on the arguments
each one builds. It stubs the navi subprocess and redirects `NAVI_WORKDIR` to a
temp directory, so it never calls navi and never touches your database — safe
against a production install. It catches a missing/old `mcp` SDK, a Python too
old for the type syntax, and partial checkouts before a client is involved.

## 5. Restart and verify

**Fully quit Claude Desktop (⌘Q on macOS, exit from the tray on Windows) and
reopen** — the config is read only at launch. Then ask Claude to read the
`navi://workdir` resource. It reports:

- the resolved workdir, and whether `navi.db` is actually there, its size, and
  how fresh its newest vuln/scan data is
- **all three gate states** — writes, email, remote code execution
- the navi binary in use, the call budget, and the skill-dir status

Check the workdir line first. `navi.db present: False` means the path is wrong,
not that your tenant is empty. The `navi_workflow` prompt also becomes available
(it surfaces as `/navi` in Desktop — that's the connector name).

## Troubleshooting

- **`can't open file '.../server.py'`** — the `args` path doesn't exist. Zip
  extraction often nests a folder (`navi-mcp-suite/navi-mcp-suite/server/...`).
  Re-run `tools/navi_mcp_config.py` to get the real path.
- **`No module named mcp`** — the SDK isn't in the launching interpreter:
  `</abs/python3> -m pip install --upgrade mcp`.
- **`No module named navi_mcp`** — you're launching with `-m navi_mcp` but the
  package isn't installed in that interpreter. Use the direct `server/server.py`
  path instead (what the helper emits).
- **Every read comes back empty** — almost always `NAVI_WORKDIR` pointing
  somewhere without your `navi.db`. Read `navi://workdir` and check
  `navi.db present`.
- **"…is a platform-write operation. Restart the server with
  NAVI_MCP_ALLOW_WRITES=1"** — working as designed. Gates are read at startup
  and cannot be opened from inside a tool call; edit the config and fully restart.
- **A write tool says it "requires confirm=True"** — also by design. The
  assistant is expected to describe the action and get your answer first, then
  repeat the call with `confirm=True`.
- **Tool call times out (`Request timed out`)** — it exceeded the client's
  ~4-minute ceiling. The error names the exact CLI command to run instead. Narrow
  the scope (`days`, `since`, `severity`, `plugin_id`, a tag pair) or run long
  syncs at the CLI.
- **"Unauthorized / keys invalid"** — API key permissions, or invalid/expired
  keys. Re-check `navi config keys`.
- **Where are the logs?** macOS: `~/Library/Logs/Claude/mcp.log`. Windows:
  `%APPDATA%\Claude\logs\`.
