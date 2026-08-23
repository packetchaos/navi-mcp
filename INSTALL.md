# Installing the navi-mcp server in Claude Desktop

This server runs the `navi` CLI on your behalf. It does **not** manage API keys —
those are set out-of-band in navi before you start.

> ## ⚠️ SDK compatibility — read this first
>
> This server requires **`mcp` >= 1.9, < 2**.
>
> `mcp` 2.0 is a breaking release: `mcp.server.fastmcp` was renamed to
> `mcp.server.mcpserver`, and the `FastMCP` class became `MCPServer`. `FastMCP`
> does not exist anywhere in 2.x. Installing `mcp` 2.x against this server
> produces, at import time and before any tool runs:
>
> ```
> ModuleNotFoundError: No module named 'mcp.server.fastmcp'
> ```
>
> Claude Desktop surfaces that only as **"Server disconnected"** — the real
> traceback is in the log file (paths at the bottom of this page).
>
> **Therefore: never run `pip install --upgrade mcp` for this server.** That
> command installs 2.x and breaks it. Installing this project as a package
> (below) pins the SDK correctly and makes the mistake impossible.

## 1. Prerequisites

- **Python 3.10+** for the server. (navi itself wants 3.12+ — if you install
  both into the same interpreter, follow navi's floor.)
- **navi installed and configured**, with a populated database:
  ```bash
  pip3 install navi-pro
  navi config keys --a "<ACCESS_KEY>" --s "<SECRET_KEY>"
  navi config update full          # populates navi.db — do this before connecting
  ```
  Note **where** you run that last command: navi writes `navi.db` into the
  current directory, and that directory is what `NAVI_WORKDIR` must point at.

## 2. Install the server (recommended)

Install the package. pip resolves and pins the MCP SDK for you — this is the
step that prevents the failure described at the top of this page.

```bash
# from PyPI
python3 -m pip install navi-mcp

# from a checkout
python3 -m pip install .

# or straight from the repo
python3 -m pip install "git+https://github.com/packetchaos/navi-mcp"
```

To get the `navi` CLI into the *same* environment, so `NAVI_BIN` resolves
without an absolute path:

```bash
python3 -m pip install "navi-mcp[navi]"     # or ".[navi]" from a checkout
```

This installs a `navi-mcp` console script. Verify before touching any config:

```bash
navi-mcp --help          # prints usage; a traceback here means the env is wrong
which navi-mcp           # the absolute path for your config's "command"
```

For a self-contained install that cannot be disturbed by other packages in the
interpreter, use a dedicated environment — `pipx install "navi-mcp[navi]"`, or a
venv you point the config at.

### Then configure Claude Desktop

Open **Settings → Developer → Edit Config**:

```json
{
  "mcpServers": {
    "navi": {
      "command": "/absolute/path/to/navi-mcp",
      "env": {
        "NAVI_WORKDIR": "/absolute/path/to/folder-with-navi.db",
        "NAVI_MCP_ALLOW_WRITES": "0",
        "NAVI_EMAIL": "0",
        "NAVI_REMOTE_CODE_EXECUTION": "0"
      }
    }
  }
}
```

That is the whole config. Note what is **no longer needed**:

- **no `args`** — the console script is the entry point
- **no `NAVI_SKILL_DIR`** — the skills ship inside the package, and the server's
  default (`<package>/resources/skills`) now resolves to them
- **no `NAVI_BIN`** — if you installed the `[navi]` extra, `navi` sits beside
  the server in the same environment

Use the **absolute** path from `which navi-mcp`. Claude Desktop launches the
server with a minimal environment and will not have your shell's `PATH`.

`python -m navi_mcp` works as an equivalent entry point if you prefer it:
`"command": "/abs/path/to/python3", "args": ["-m", "navi_mcp"]`.

## 3. Alternative: run from the checkout

Supported, and still useful while developing. You are responsible for the SDK
version yourself:

```bash
<that-python> -m pip install 'mcp>=1.9,<2'      # NOT --upgrade mcp
```

Then let the helper discover your paths — run it **with the interpreter you want
Claude Desktop to use**:

```bash
/path/to/python3 tools/navi_mcp_config.py            # print the mcpServers JSON
/path/to/python3 tools/navi_mcp_config.py --write    # merge it in (backs up first)
```

It finds `server/server.py`, your `navi.db` (→ `NAVI_WORKDIR`), the `navi`
binary (→ `NAVI_BIN`), and `skills/` (→ `NAVI_SKILL_DIR`), and writes a
diagnostic checklist to stderr — read it, especially the `navi.db` line.

Pin anything it gets wrong:

```bash
/path/to/python3 tools/navi_mcp_config.py \
  --server /abs/path/to/navi-mcp-suite/server/server.py \
  --skills /abs/path/to/navi-mcp-suite/skills \
  --workdir /abs/path/to/folder-with-navi.db
```

In this mode both path defaults are traps if you omit the key: `NAVI_WORKDIR`
falls back to `~/.navi-mcp` (which the server creates empty, so every read
returns nothing), and `NAVI_SKILL_DIR` falls back to a `resources/skills` folder
beside `server.py` that only exists in the *packaged* layout (so skill resources
404). Set both explicitly.

| Config key | Points at |
|---|---|
| `command` | the `python3` that has a 1.x `mcp` installed |
| `args[0]` | `navi-mcp-suite/server/server.py` |
| `NAVI_SKILL_DIR` | `navi-mcp-suite/skills` (unpacked folders, not a packaged `.plugin`) |
| `NAVI_WORKDIR` | the folder that contains your `navi.db` |
| `NAVI_BIN` | the `navi` executable (often next to your `python3`) |

## 4. Gates

Leave them all off to start read-only. That is the recommended first install:
connect, verify it is pointed at the right database, then open gates.

| Env var | Helper flag | Enables |
|---|---|---|
| `NAVI_MCP_ALLOW_WRITES=1` | `--allow-writes` | tagging, ACR, asset import, scan/WAS control, deletes, key rotation, export cancel, local table rebuild |
| `NAVI_EMAIL=1` | `--allow-email` | `navi_action_mail` — **requires the write gate too** |
| `NAVI_REMOTE_CODE_EXECUTION=1` | `--allow-remote-code-execution` | `navi_action_push` — **requires the write gate too** |

The last two have no effect on their own: each stacks *on top of* the write
gate, so enabling ordinary writes never silently grants email or a remote shell.
Only add them if you actually want the server to send mail or run commands on
other machines. Email also needs `navi config smtp` and push needs
`navi config ssh`, both set out-of-band in navi itself.

Only the literal string `"1"` opens a gate. `"0"`, `"true"`, `"yes"`, and an
absent key all mean off — a typo fails closed.

Every gated tool additionally requires `confirm=True` on each individual call —
that one is not configured here, it is passed at call time after the assistant
tells you what it is about to do. See the README's **Gates** section for how the
three layers compose.

> **On `NAVI_REMOTE_CODE_EXECUTION`.** With it open, `navi_action_push` can run
> shell commands on remote hosts, in the same context that holds scan output —
> HTTP banners, certificate fields, and plugin text pulled from machines on your
> network. That text is attacker-influencable. Treat this gate as something you
> open for a specific task and close afterwards, not as a standing default.

## 5. Smoke-test before connecting

```bash
python3 navi-mcp-suite/server/tests/run_all.py
```

This imports `server.py`, registers all 20 tools, and asserts on the arguments
each one builds. It stubs the navi subprocess and redirects `NAVI_WORKDIR` to a
temp directory, so it never calls navi and never touches your database — safe
against a production install. It catches a missing or incompatible `mcp` SDK, a
Python too old for the type syntax, and partial checkouts before a client is
involved.

There is also a doctor script that checks the whole chain — interpreter, SDK
version, `navi` binary, config paths, gate states — and installs a compatible
SDK if one is missing:

```bash
./fix-mcp.sh            # diagnose and repair
./fix-mcp.sh --check    # diagnose only, change nothing
NAVI_PY=/path/to/python3 ./fix-mcp.sh    # target a specific interpreter
```

## 6. Restart and verify

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

- **`No module named 'mcp.server.fastmcp'`** — you have `mcp` 2.x. See the box
  at the top. Fix: `<that-python> -m pip install 'mcp>=1.9,<2'`, or install this
  project as a package so the pin is enforced. Confirm with
  `<that-python> -m pip show mcp`.
- **`No module named mcp`** — the SDK isn't in the launching interpreter at all:
  `<that-python> -m pip install 'mcp>=1.9,<2'`.
- **`No module named navi_mcp.__main__`** — an older packaged install without
  `__main__.py`. Reinstall the current package, or launch the console script.
- **`can't open file '.../server.py'`** — the `args` path doesn't exist. Zip
  extraction often nests a folder
  (`navi-mcp-suite/navi-mcp-suite/server/...`). Re-run
  `tools/navi_mcp_config.py`, or install the package and drop `args` entirely.
- **`navi binary not found at 'navi'`** — `NAVI_BIN` is unset and `navi` isn't on
  the minimal `PATH` Claude Desktop provides. Set `NAVI_BIN` to an absolute path,
  or install with the `[navi]` extra.
- **Every read comes back empty** — almost always `NAVI_WORKDIR` pointing
  somewhere without your `navi.db`. Read `navi://workdir` and check
  `navi.db present`.
- **Skill resources 404** — running from a checkout without `NAVI_SKILL_DIR`
  set. Set it, or install the package (which ships the skills).
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
- **"Server disconnected" with no other detail** — the server died during
  startup. The traceback is in the log, not in the UI. Read it before changing
  anything.
- **Where are the logs?** macOS: `~/Library/Logs/Claude/mcp.log` and
  `mcp-server-navi.log`. Windows: `%APPDATA%\Claude\logs\`.
