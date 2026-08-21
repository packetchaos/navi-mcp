# navi-mcp suite

An MCP server for the [Tenable **navi** CLI](https://github.com/packetchaos/navi)
(Tenable Vulnerability Management / Tenable One), plus the companion
[navi-claude-skills](https://github.com/packetchaos/navi-claude-skills) set,
vendored here so the server can serve them.

The tool surface is validated against navi's **source** — the `@click.option`
declarations in `navi/plugins/*.py`, not a `--help` capture — because help text
cannot show you a guard that warns without exiting, a flag that is silently
ignored for the selector you paired it with, or a prompt that will deadlock a
tool call. `docs/gap-ledger.md` carries the per-finding trail.

## Layout

```
server/      server.py — the MCP server (20 tools + resources)
server/tests/  argv-level check suites + run_all.py (no live tenant needed)
skills/      the 17 skills, in NAVI_SKILL_DIR layout — a vendored copy of
             upstream (<skill>/SKILL.md, plus references/ on the denser ones)
tools/       navi_mcp_config.py — auto-detects paths, emits the install config
             sync_skills.py     — refresh skills/ from upstream, verify vs server
docs/        audit framework, gap ledger, verified findings, help-crawler,
             fix-xref-prompt.md (a reported bug in the navi CLI, not this repo)
INSTALL.md   step-by-step install for Claude Desktop
README.md    this file
```

### The 17 skills

Driving the server: `navi` (router) · `navi-core` · `navi-mcp` ·
`navi-troubleshooting` · `navi-acr` · `navi-export` · `navi-scan` · `navi-was` ·
`navi-action` · `navi-mail` · `navi-remote-exec` · `navi-explore` · `navi-enrich`

Authoring Nessus compliance content: `navi-audit` · `navi-audit-syntax` ·
`navi-audit-platforms` · `navi-audit-catalog`. These do not use the MCP server,
but the router routes to them, so they travel with the set.

Deep material (full schema, exhaustive selector catalog, long worked examples)
lives in `references/*.md` and is pulled on demand.

**These are a vendored copy.** They are maintained at
[packetchaos/navi-claude-skills](https://github.com/packetchaos/navi-claude-skills)
and live here only so `NAVI_SKILL_DIR` has something to serve. Refresh them —
and check them against the server's actual tool surface — with:

```bash
python tools/sync_skills.py --dry-run     # what would change
python tools/sync_skills.py --verify      # sync, then cross-check vs server.py
```

`--verify` parses every `navi_*(...)` call written in the skills and flags tool
names the server doesn't register, keyword arguments a tool doesn't accept, and
tools no skill documents. Run it whenever the tool surface changes: it is how
`navi_action_delete(kind="scan", id=…)` was caught, where the real parameter is
`object_id`.

## Running the MCP server

The server shells out to the `navi` binary and reads the local `navi.db`. It
does **not** manage API keys — set those out-of-band with `navi config keys`
first (see `skills/navi-core`).

```bash
python server/server.py            # stdio (default); waits for a client
python server/server.py --http     # streamable HTTP on :8000
```

## Environment variables

Every one of these is read **once, at server start**. Changing any of them means
restarting the server (and, in Claude Desktop, fully quitting the app) — none of
them can be changed from inside a tool call, which is the point for the gates.

| Var | Purpose | Default if unset |
|---|---|---|
| `NAVI_WORKDIR` | Directory holding `navi.db` and CSV exports. The server runs every navi subprocess with this as its cwd. | **`~/.navi-mcp`** — created on startup if missing |
| `NAVI_BIN` | Path to the `navi` executable | `navi` (resolved on `PATH`) |
| `NAVI_SKILL_DIR` | The **`skills/`** directory in this repo, so the `navi://skill/...` resources resolve | **`<dir of server.py>/resources/skills`** — which does not exist in this layout, so skill resources 404 until you set it |
| `NAVI_SKILL_PATH` | Legacy: a single monolithic `SKILL.md`. Setting it puts the server in single-file mode and `NAVI_SKILL_DIR` is ignored. Prefer `NAVI_SKILL_DIR`. | unset |
| `NAVI_MCP_ALLOW_WRITES` | `1` opens the master write gate (see below) | unset → **read-only** |
| `NAVI_EMAIL` | `1` enables `navi_action_mail`. Stacks on the write gate. | unset → off |
| `NAVI_REMOTE_CODE_EXECUTION` | `1` enables `navi_action_push`. Stacks on the write gate. | unset → off |

> **First-install trap.** `NAVI_WORKDIR` defaults to `~/.navi-mcp`, *not* your
> current directory. The navi CLI writes `navi.db` into whatever directory you
> ran it from, so if you leave `NAVI_WORKDIR` unset the server will quietly
> create an empty `~/.navi-mcp`, find no database there, and every read will come
> back empty — looking like a broken tenant rather than a wrong path. Read
> `navi://workdir` first: it prints the resolved workdir and whether `navi.db` is
> actually present.

Point `NAVI_SKILL_DIR` at this repo's `skills/` folder. The server reads
unpacked skill folders, not packaged `.skill`/`.plugin` zips.

## The gates

Three independent layers. A tool runs only when **every** layer that applies to
it is satisfied; they are `AND`ed, never `OR`ed.

```
Layer 1  NAVI_MCP_ALLOW_WRITES=1      master write gate      server env, restart
Layer 2  NAVI_EMAIL=1                 email capability       server env, restart
         NAVI_REMOTE_CODE_EXECUTION=1 remote-exec capability server env, restart
Layer 3  confirm=True                 per-call intent        in the tool call
```

**Layer 1 — the master write gate.** Off by default, so a fresh install is
read-only and safe to point at production. Opening it enables everything that
changes state in your Tenable tenant: tagging, ACR, asset import, scan control,
WAS launches, deletes, key rotation, export cancellation, `navi_config(kind='url')`,
and `navi_explore_api` POST/PUT. It also covers `navi_config_rebuild` — that one
destroys *local* data rather than tenant data (see below), but it is destructive
enough to belong behind the same switch.

**Layer 2 — capability gates.** Two capabilities are hazardous in ways ordinary
platform writes are not, so each needs its own separate opt-in *on top of* layer
1. Opening the write gate alone does **not** enable either:

- `NAVI_EMAIL=1` → `navi_action_mail` may send mail as you. Also needs SMTP
  configured out-of-band via `navi config smtp`. Harness: `skills/navi-mail`.
- `NAVI_REMOTE_CODE_EXECUTION=1` → `navi_action_push` may run shell commands on
  remote hosts. Also needs SSH credentials via `navi config ssh`. This is the
  highest-risk capability in navi. Harness: `skills/navi-remote-exec`.

**Layer 3 — `confirm=True`.** A per-call flag on every gated tool. Layers 1 and 2
are standing decisions made once by the operator; layer 3 is a decision about
*this specific call*, and the convention is that the model narrates exactly what
it is about to do and gets a human answer before passing it. Because it lives in
the tool call rather than the environment, it is the only layer a model can
satisfy on its own — which is precisely why it is never the only layer for
anything that touches the tenant.

### What needs what

| Tool | Writes gate | Capability gate | `confirm=True` |
|---|---|---|---|
| `navi_enrich_tag`, `navi_enrich_acr`, `navi_enrich_add` | ✅ | — | ✅ |
| `navi_scan` (create/start/stop/pause/resume) | ✅ | — | ✅ |
| `navi_was` (scan/start/upload) | ✅ | — | ✅ |
| `navi_action_delete`, `navi_action_rotate`, `navi_action_cancel` | ✅ | — | ✅ |
| `navi_config(kind='url')` | ✅ | — | ✅ |
| `navi_explore_api` POST/PUT | ✅ | — | ✅ |
| `navi_config_rebuild` | ✅ | — | ✅ |
| `navi_action_mail` | ✅ | `NAVI_EMAIL=1` | ✅ |
| `navi_action_push` | ✅ | `NAVI_REMOTE_CODE_EXECUTION=1` | ✅ |
| `navi_explore_query` non-SELECT | — | — | ✅ |
| everything else (reads, exports, `navi_explore_api` GET, encrypt/decrypt) | — | — | — |

Two asymmetries worth knowing rather than discovering:

- **`navi_explore_query` non-SELECT is confirm-only.** A `DELETE`/`DROP` through
  it hits your local navi.db, never the tenant, so it sits outside the write
  gate — but it *is* destructive, and unlike `navi_config_rebuild` nothing but
  `confirm=True` stands in front of it. If you want a strictly read-only local
  database as well as a read-only tenant, that is not what the write gate gives
  you today.
- **`navi_config_rebuild`'s `confirm=True` is doing literal work.** navi's own
  `-rebuild` path calls `click.confirm()` before dropping the table. Under MCP,
  stdin is closed, so that prompt would abort the command — the server answers it
  on your behalf. Your `confirm=True` *is* the "y" being typed. That is why the
  tool refuses without it rather than treating it as a formality.

### Read-only by default

With no environment variables set beyond `NAVI_WORKDIR` and `NAVI_BIN`, the
server exposes reads only. That is the recommended starting posture: connect it,
read `navi://workdir`, run a query or two, and open gates deliberately once you
trust what it is pointed at.

### Destructive tools

Only two tools destroy anything, and neither touches Tenable:

- **`navi_config_rebuild`** — DROPs a local `assets` or `vulns` table, re-creates
  it, and re-downloads. Nothing in Tenable VM changes; what you lose is the local
  cache and the hours it took to build on a large tenant. Tables *derived* from
  those (`certs`, `software`, `vuln_route`, `vuln_paths`) go stale at the same
  moment — the tool's `_notice` names the calls that refresh each. Annotated
  `destructiveHint=True`, which `navi_config_update` deliberately is not: an
  update merges into the existing table and never drops.
- **`navi_action_delete`** — removes tags, users, scans, assets, target groups,
  user groups, or TONE tags **in the tenant**. Write-gated and confirm-gated.

Rebuilding both tables at once is `navi config update full -rebuild` at the CLI;
`full` is not exposed as a tool because it runs for hours regardless.

### Install in Claude Desktop

Full walkthrough in **[INSTALL.md](INSTALL.md)**. The short version: don't
hand-write paths — run the helper with the Python interpreter you want Claude
Desktop to use (the one that has `mcp` and `navi`), and it discovers
`server/server.py`, your `navi.db`, the `navi` binary, and `skills/`, then
prints (or, with `--write`, installs) the config:

```bash
python tools/navi_mcp_config.py            # print the mcpServers JSON
python tools/navi_mcp_config.py --write    # merge into your Claude Desktop config (backs up first)
```

Gate flags on the helper map one-to-one to the env vars above:
`--allow-writes`, `--allow-email`, `--allow-remote-code-execution`. The last two
have no effect without the first.

The launched server entry is `server/server.py` (use an **absolute** path — Claude
Desktop won't have your shell's `PATH`). After editing the config, fully quit and
reopen Claude Desktop, then read `navi://workdir` to confirm it connected.

### Resources

- `navi://schema/{table}` — live column definitions for a navi.db table
- `navi://workdir` — resolved workdir, `navi.db` presence/size/freshness, all
  three gate states, navi binary, call budget, and skill-dir status
- `navi://skill/{name}` — load a skill (router/core/mcp/…); lists its references
- `navi://skill/{name}/{ref}` — load a bundled reference (e.g. `navi://skill/core/schema`)

Plus the `navi_workflow` prompt, which injects the router skill.

### Long-running operations

navi exports can run for tens of minutes on large tenants — past the MCP host's
~4-minute tool-call ceiling. The server enforces a call budget (~220s) and
returns a clean error naming the exact CLI command to run instead, scoped
identically to the call that timed out. Foundational syncs
(`navi config update full`) remain intentionally CLI-only. The main lever for
fitting a sync inside the budget is scope: `days`, `since`, `severity`,
`plugin_id`, or a `category`/`value` tag pair on `navi_config_update`. See
`skills/navi-core` and `skills/navi-troubleshooting`.

## Tests

```bash
python server/tests/run_all.py        # summary
python server/tests/run_all.py -v     # every check
```

The suites stub the navi subprocess and assert on the **argv** each tool builds,
so they need no tenant, no API keys, and no `navi.db`. `NAVI_WORKDIR` is
redirected to a temp directory and the real `navi` binary is never invoked —
safe to run against a production install. Run them after installing on a new
machine: they will catch a broken `mcp` SDK, a Python too old for the type
syntax, or a partial checkout before you connect a client.

## Installing the skills as Claude skills

Install them from
[packetchaos/navi-claude-skills](https://github.com/packetchaos/navi-claude-skills),
which builds a `navi-skills.plugin` bundle for Claude.ai / Claude Cowork /
Claude Code. This repo no longer ships packaged copies: a second distribution
channel is a second thing to forget to update, and that is precisely how the
skills here ended up describing a server that had moved on without them. The
`skills/` folder stays because the MCP server reads it directly.

## Validation status

`server.py` compiles cleanly, every tool is annotated, all 20 register, and the
suites in `server/tests/` are green. Tool annotations require a recent `mcp` SDK.

It has **not** been runtime-tested against a live Tenable tenant. The checks
verify what the server *asks navi to do*; they cannot verify what navi and the
Tenable API do in response. Before relying on it, validate with one live read —
`navi_explore_data(subcommand="cve", cve="CVE-2021-44228")` — and read
`navi://workdir` to confirm the workdir and gate states are what you intended.

See `docs/verified-findings.md` for the per-bug inventory and
`docs/gap-ledger.md` for the full audit trail.
