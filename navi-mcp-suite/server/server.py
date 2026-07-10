"""
navi-mcp: An MCP server that wraps the `navi` CLI (packetchaos/navi) for
Tenable Vulnerability Management.

================================================================================
CHANGELOG vs server__1_.py (Phase A verified findings, reconciled against the
navi --help tree dated 2026-06-07). See navi_phaseA_verified_findings.md.
================================================================================
CORRECTNESS (A14 — 23 verified bugs; root cause: positional navi args sent as
--flags, plus wrong command paths and non-existent subcommands):
  • navi_explore_data: cve/name/output/xrefs/scantime/port now pass POSITIONAL
    args; `plugin` -> `explore data plugin`; `asset` -> `explore uuid`;
    xrefs id -> --xid.
  • navi_was: scans/details/scan/start/upload now pass POSITIONAL args.
  • navi_action_delete: asset/scan/user now POSITIONAL; `user` takes a numeric
    User ID (not email); dropped `agent` and `exclusion` (not real subcommands).
  • navi_config_update: dropped invalid `certificates`; added `fixed`, `plugins`
    (plugins requires --size).
  • navi_config: `sla` now runs `config sla calculate` (bare was a no-op group);
    added `certificates` (the real cert-table command, plugin 10863).
  • navi_action_cancel: now passes the REQUIRED export UUID.
  • navi_enrich_add: bulk import uses `--file` (was `--list`); added mac/netbios.
  • navi_scan: dropped invalid `--name` on create.
QUALITY:
  • _raise_on_error(): every tool raises on non-zero exit (A1/A12) — no more
    "success" notices on failed writes.
  • MCP_CALL_BUDGET + run_navi(cli_hint=...): subprocess timeouts sit below the
    ~4-min MCP host ceiling and time out with the exact CLI fallback (A2).
  • ToolAnnotations on every tool (A3).
  • navi://workdir reports navi.db freshness (A8).
COVERAGE (A15, verified-safe additions):
  • navi_explore_api (GET free / POST/PUT gated) — export-status escape hatch (A4).
  • navi_scan: status/details/history/latest/hosts (read) + pause/resume (write).
  • navi_action_delete: bytag/tgroup/usergroup/tone.
  • navi_action_mail / navi_action_push (previously CLI-only): now exposed but
    DOUBLE-GATED. Each requires NAVI_MCP_ALLOW_WRITES=1 AND its own capability
    env var (NAVI_EMAIL / NAVI_REMOTE_CODE_EXECUTION) AND confirm=True. mail
    always passes --to/--subject so navi never drops into its interactive
    prompt (which would deadlock under MCP). push enforces exactly one of
    command/file and targets a single host (no --tag; loop per IP for groups).
  • navi_enrich_tag remove semantics clarified: -remove is a CLEAR of the tag's
    CURRENT membership and ignores any selector. remove=True with no selector is
    now allowed (a pure clear). remove=True WITH a selector still runs, but the
    tool attaches a `_warning`: navi runs add-then-remove as two jobs in one
    call, only adding/updating vs current membership rather than cleanly
    refreshing. Accurate refresh = clear -> wait ~30 min -> re-apply (two calls).
DEFERRED (documented at each site — request to add):
  • config agent/network/user/permissions/exclude management.
  • destructive metadata deletes (table/rules/value/category/network/policy).
  • config update tone (-assets/-findings) / everything / zipper.
  • a rich `navi_explore_uuid` tool exposing uuid's per-plugin views.
================================================================================

Exposes:
  Tools (19):
    navi_config_update      targeted DB refresh
    navi_config             software / sla / url / certificates setup
    navi_explore_query      SQL against navi.db — reads free, writes confirm
    navi_explore_data       17 explore data subcommands (reads navi.db)
    navi_explore_info       26 explore info subcommands (live API)
    navi_explore_api        raw Tenable API passthrough (GET free / POST,PUT gated)
    navi_enrich_tag         create a tag — write-gated
    navi_enrich_acr         set ACR with mod + Change Reasons — write-gated
    navi_enrich_add         import assets from external sources — write-gated
    navi_export             15 CSV export subcommands
    navi_scan               scan create/start/stop/pause/resume + read views
    navi_was                8 WAS subcommands
    navi_action_delete      delete tag/bytag/asset/scan/user/tgroup/usergroup/tone
    navi_action_rotate      rotate API keys — write-gated
    navi_action_cancel      cancel a running export (needs UUID) — write-gated
    navi_action_encrypt     encrypt a local file
    navi_action_decrypt     decrypt a local file
    navi_action_mail        email a report/file — gated by NAVI_EMAIL (+writes)
    navi_action_push        remote command/file to a Linux host — gated by
                            NAVI_REMOTE_CODE_EXECUTION (+writes)

  Resources:
    navi://schema/{table}   column definitions for a navi.db table
    navi://workdir          workdir + write gate + navi.db freshness
    navi://skill/{name}     load a navi-claude-skills domain skill (lean index)
    navi://skill/{name}/{ref}  load a bundled reference file (progressive disclosure)

  Prompts:
    navi_workflow           inject the navi router skill as context

Run it:
    pip install "mcp[cli]"
    python -m navi_mcp             # stdio (Claude Desktop / Code)
    python -m navi_mcp --http      # streamable HTTP on :8000
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shlex
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

# Tool annotations are optional and SDK-version dependent. Degrade gracefully so
# the server still imports/runs on older `mcp` packages that lack them.
try:
    from mcp.types import ToolAnnotations

    def _anno(**kwargs) -> "ToolAnnotations | None":
        return ToolAnnotations(**kwargs)
except Exception:  # pragma: no cover - older SDK
    def _anno(**kwargs):  # type: ignore[misc]
        return None

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Where navi.db and navi's own state live. Override with NAVI_WORKDIR.
NAVI_WORKDIR = Path(os.environ.get("NAVI_WORKDIR", Path.home() / ".navi-mcp")).expanduser()
NAVI_WORKDIR.mkdir(parents=True, exist_ok=True)

# Must be "1" to allow any platform-write operation (tags, ACR, adds, deletes…).
ALLOW_WRITES = os.environ.get("NAVI_MCP_ALLOW_WRITES") == "1"

# Extra capability gates for the two hazardous action commands. Each stacks ON
# TOP of NAVI_MCP_ALLOW_WRITES — the master write gate must be open AND the
# specific capability gate must be set to "1" before the tool will run. This
# forces the operator to opt into email and remote-shell execution as separate,
# explicit decisions rather than folding them into the general write gate.
#
#   NAVI_EMAIL=1                 -> navi_action_mail may send email
#   NAVI_REMOTE_CODE_EXECUTION=1 -> navi_action_push may run remote commands
ALLOW_EMAIL = os.environ.get("NAVI_EMAIL") == "1"
ALLOW_REMOTE_CODE_EXECUTION = os.environ.get("NAVI_REMOTE_CODE_EXECUTION") == "1"

# Path to the navi binary. Override with NAVI_BIN if it's not on PATH.
NAVI_BIN = os.environ.get("NAVI_BIN", "navi")

# MCP hosts (Claude Desktop / Claude Code) cap a single tool call at ~4 minutes.
# Keep subprocess timeouts at/below this so the server returns a clean, actionable
# error BEFORE the host kills the call (which otherwise orphans the navi
# subprocess behind an opaque timeout). Operations that legitimately run longer
# (full vuln sync, large-tenant tagging) must run at the CLI — each long tool
# passes a `cli_hint` so the timeout error tells the user exactly what to run.
MCP_CALL_BUDGET = 220.0  # seconds

# navi-claude-skills directory (repo root containing navi/, navi-mcp/, …).
SKILL_DIR = Path(
    os.environ.get("NAVI_SKILL_DIR", Path(__file__).parent / "resources" / "skills")
).expanduser()

# Backward-compat: NAVI_SKILL_PATH points at a single monolithic SKILL.md.
SKILL_PATH_LEGACY = os.environ.get("NAVI_SKILL_PATH")
SKILL_PATH_LEGACY = Path(SKILL_PATH_LEGACY).expanduser() if SKILL_PATH_LEGACY else None

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # stdout is reserved for JSON-RPC on stdio transport
    format="%(asctime)s [navi-mcp] %(levelname)s %(message)s",
)
log = logging.getLogger("navi-mcp")

mcp = FastMCP("navi-mcp")

# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

class NaviError(RuntimeError):
    """Raised when a navi CLI call fails in a way the caller should see."""


async def run_navi(
    args: list[str],
    *,
    timeout: float = MCP_CALL_BUDGET,
    cli_hint: str | None = None,
) -> dict:
    """
    Execute `navi <args>` inside NAVI_WORKDIR and return a structured result.

    `cli_hint`, if given, is appended to the timeout error so the user knows the
    exact terminal command to run when an operation exceeds the MCP call budget.

    Uses blocking subprocess.run in a thread (the async variant deadlocks on
    Windows when a Python process spawns another Python entry-point exe).
    """
    argv = [NAVI_BIN, *args]
    log.info("exec: %s (cwd=%s)", shlex.join(argv), NAVI_WORKDIR)

    def _run() -> subprocess.CompletedProcess:
        return subprocess.run(
            argv,
            cwd=str(NAVI_WORKDIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    try:
        result = await asyncio.to_thread(_run)
    except FileNotFoundError as e:
        raise NaviError(
            f"navi binary not found at '{NAVI_BIN}'. "
            f"Install navi (`pip install navi-hostio`) or set NAVI_BIN."
        ) from e
    except subprocess.TimeoutExpired as e:
        partial_out = (
            (e.stdout or b"").decode("utf-8", "replace")[-1500:]
            if isinstance(e.stdout, bytes)
            else (e.stdout or "")[-1500:]
        )
        msg = (
            f"navi exceeded the {timeout:.0f}s MCP call budget: {shlex.join(argv)}\n"
            f"The MCP host caps a single tool call at ~4 minutes, so this "
            f"operation is too long to run as a tool.\n"
        )
        if cli_hint:
            msg += f"Run it at your terminal instead:\n    {cli_hint}\n"
        msg += f"partial output:\n{partial_out}"
        raise NaviError(msg)

    log.info("done: rc=%s stdout=%d bytes", result.returncode, len(result.stdout or ""))
    return {
        "argv": argv,
        "returncode": result.returncode,
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
    }


def _raise_on_error(result: dict, label: str) -> dict:
    """
    Raise NaviError if a navi CLI call exited non-zero; return result on success.

    Every tool runs its result through this so a failed operation never reports
    success (the original server appended "Tag created"/"ACR updated" regardless
    of exit code — A1/A12).
    """
    if result["returncode"] != 0:
        raise NaviError(
            f"{label} failed (exit {result['returncode']}). "
            f"stderr: {result['stderr'][-2000:] or '(empty)'}\n"
            f"stdout tail: {result['stdout'][-500:] or '(empty)'}"
        )
    return result


def _require_writes(tool_name: str) -> None:
    """Raise NaviError if the platform-write gate is closed."""
    if not ALLOW_WRITES:
        raise NaviError(
            f"{tool_name} is a platform-write operation. Restart the server with "
            f"NAVI_MCP_ALLOW_WRITES=1 to enable. This affects every future "
            f"session and is a security-sensitive change made on the server, not "
            f"from inside the tool surface."
        )


def _require_confirm(tool_name: str, confirm: bool) -> None:
    """Raise NaviError if the per-call confirm flag is not set."""
    if not confirm:
        raise NaviError(
            f"{tool_name} requires confirm=True. Narrate the intended action to "
            f"the user first, then call again with confirm=True."
        )


def _require_email(tool_name: str) -> None:
    """
    Gate email delivery. Stacks on the master write gate: BOTH
    NAVI_MCP_ALLOW_WRITES=1 and NAVI_EMAIL=1 must be set.
    """
    _require_writes(tool_name)
    if not ALLOW_EMAIL:
        raise NaviError(
            f"{tool_name} sends email on your behalf and is disabled. Restart the "
            f"server with NAVI_EMAIL=1 (in addition to NAVI_MCP_ALLOW_WRITES=1) to "
            f"enable it. This is a separate, security-sensitive opt-in made on the "
            f"server, not from inside the tool surface, and affects every future "
            f"session."
        )


def _require_remote_code_execution(tool_name: str) -> None:
    """
    Gate remote command execution. Stacks on the master write gate: BOTH
    NAVI_MCP_ALLOW_WRITES=1 and NAVI_REMOTE_CODE_EXECUTION=1 must be set.
    """
    _require_writes(tool_name)
    if not ALLOW_REMOTE_CODE_EXECUTION:
        raise NaviError(
            f"{tool_name} runs shell commands on remote hosts and is disabled. "
            f"Restart the server with NAVI_REMOTE_CODE_EXECUTION=1 (in addition to "
            f"NAVI_MCP_ALLOW_WRITES=1) to enable it. Remote code execution is the "
            f"highest-risk capability in navi — this is a deliberate, separate "
            f"opt-in made on the server, not from inside the tool surface, and "
            f"affects every future session."
        )


def _newest_csv_after(mtime_floor: float) -> Path | None:
    """Find the newest .csv in NAVI_WORKDIR modified after mtime_floor."""
    candidates = [p for p in NAVI_WORKDIR.glob("*.csv") if p.stat().st_mtime > mtime_floor]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# Config tools
# ---------------------------------------------------------------------------

# `certificates` removed — it is NOT a `config update` subcommand; the cert table
# is populated by `navi config certificates` (see navi_config). `fixed` and
# `plugins` added. Deferred (not simple slice syncs, would no-op or need extra
# flags): `tone` (-assets/-findings), `everything` (heavy, CLI), `zipper` (niche),
# `full` (foundational, CLI-only).
UpdateKind = Literal[
    "assets", "vulns", "agents", "compliance",
    "route", "paths", "was", "fixed", "plugins",
]
_UPDATE_DAYS_OK = {"assets", "vulns", "fixed"}


@mcp.tool(
    annotations=_anno(
        title="Refresh a slice of navi.db",
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_config_update(
    kind: UpdateKind,
    days: int | None = None,
    size: int | None = None,
) -> dict:
    """
    Refresh one slice of the local navi.db from the Tenable platform.

    kind:
      assets       — asset inventory
      vulns        — vulnerability findings
      agents       — required before any agent-group tagging
      compliance   — compliance check results (only if you scan for them)
      route        — vuln routing table (vulns grouped by technology)
      paths        — vuln paths table (vuln -> filesystem/URL path)
      was          — Web Application Scanning: apps + findings tables
      fixed        — fixed-vuln data for SLA processing (needed by export failures)
      plugins      — populate the full Tenable plugin DB (REQUIRES `size`)

    days (assets/vulns/fixed only) — limits the lookback window. Passing it for
    any other kind raises so the caller knows their intent didn't land. `days`
    is also the primary lever for fitting a large vulns sync under the call
    budget below.

    size (plugins only) — page size, 1000–10000. Required for kind='plugins'.

    NOTE — MCP call ceiling. A single tool call is capped at ~4 min by the host.
    On large tenants kind='vulns' (sometimes 'assets'/'plugins') exceeds this and
    will time out here even though it would succeed at the CLI. Mitigations:
      • narrow:   days=N            (assets/vulns/fixed)
      • CLI:      navi config update vulns --threads 1
      • indexes:  navi config optimize   (run once; makes later work fast)

    To populate the certificate table, use navi_config(kind='certificates').
    The foundational full sync (`navi config update full`) is intentionally
    CLI-only — it can pull hundreds of GB and run for hours.
    """
    if days is not None and kind not in _UPDATE_DAYS_OK:
        raise NaviError(
            f"--days is only supported for kind in {sorted(_UPDATE_DAYS_OK)}, not '{kind}'."
        )

    if kind == "plugins":
        size = size if size is not None else 10000
        if not 1000 <= size <= 10000:
            raise NaviError("kind='plugins' requires size between 1000 and 10000.")
        args = ["config", "update", "plugins", "--size", str(size)]
    else:
        if size is not None:
            raise NaviError("`size` is only valid for kind='plugins'.")
        args = ["config", "update", kind]
        if days is not None:
            args.extend(["--days", str(days)])

    cli_map = {
        "vulns": "navi config update vulns --threads 1",
        "assets": "navi config update assets --threads 1",
        "plugins": f"navi config update plugins --size {size or 10000}",
    }
    result = await run_navi(args, cli_hint=cli_map.get(kind))
    return _raise_on_error(result, f"navi config update {kind}")


# `certificates` added (the real cert command). `sla` now targets `calculate`.
ConfigKind = Literal["software", "sla", "url", "certificates"]


@mcp.tool(
    annotations=_anno(
        title="navi config (software/sla/url/certificates)",
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_config(
    kind: ConfigKind,
    url: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Run a non-update `navi config` command.

    kind:
      software     — parse software plugins (22869, 20811, 83991) into the
                     software table. Populates navi.db only (not write-gated).
      certificates — parse plugin 10863 into the certs table. Populates navi.db
                     only (not write-gated). This is the correct cert command —
                     it is NOT `config update certificates`.
      sla          — runs `config sla calculate` (computes SLA times from the
                     `fixed` data; run navi_config_update(kind='fixed') first).
                     SETTING/overwriting SLA thresholds is `config sla reset`,
                     which is interactive — run it at the CLI.
      url          — change the Tenable API base URL (e.g. FedRAMP). Requires
                     confirm=True and NAVI_MCP_ALLOW_WRITES=1 — it reconfigures
                     where every subsequent call goes.

    url is required when kind='url' and ignored otherwise.
    """
    if kind == "url":
        _require_writes("navi_config(kind='url')")
        _require_confirm("navi_config(kind='url')", confirm)
        if not url:
            raise NaviError("kind='url' requires the `url` parameter.")
        return _raise_on_error(await run_navi(["config", "url", url], timeout=30), "navi config url")

    if kind == "sla":
        # `config sla` is a group (calculate/reset); bare invocation is a no-op.
        return _raise_on_error(
            await run_navi(["config", "sla", "calculate"], timeout=120), "navi config sla calculate"
        )

    if kind == "certificates":
        return _raise_on_error(
            await run_navi(["config", "certificates"]), "navi config certificates"
        )

    # software
    return _raise_on_error(
        await run_navi(["config", "software"], cli_hint="navi config software"),
        "navi config software",
    )


# ---------------------------------------------------------------------------
# Explore tools
# ---------------------------------------------------------------------------

@mcp.tool(
    annotations=_anno(
        title="SQL against navi.db",
        readOnlyHint=False,  # write path exists (gated by confirm)
        destructiveHint=False, idempotentHint=False, openWorldHint=False,
    )
)
async def navi_explore_query(
    sql: str,
    limit: int = 500,
    confirm: bool = False,
) -> dict:
    """
    Run a SQL query against navi.db.

    Reads (SELECT / WITH) are the default and need no confirmation. Call freely.

    Writes (CREATE INDEX, UPDATE, DELETE, DDL) work but require confirm=True.
    These modify navi.db ONLY — no Tenable platform interaction — so they do NOT
    require NAVI_MCP_ALLOW_WRITES=1; confirm alone is the write signal. Run one
    statement per call (multi-statement writes execute only the first).

    limit caps rows on reads (default 500); no effect on writes.

    Always banned (even with confirm): ATTACH DATABASE and PRAGMA journal_mode,
    which can corrupt navi.db beyond recovery via navi_config_update.
    """
    lowered = sql.strip().lower()
    if not lowered:
        raise NaviError("Empty SQL query.")

    if any(tok in lowered for tok in ("attach ", "pragma journal_mode")):
        raise NaviError(
            "ATTACH and PRAGMA journal_mode statements are not permitted; "
            "they can corrupt navi.db beyond recovery via navi_config_update."
        )

    if lowered.startswith(("select", "with")):
        return await _explore_query_read(sql, limit)

    _require_confirm("navi_explore_query (non-SELECT)", confirm)
    return await _explore_query_write(sql)


async def _explore_query_read(sql: str, limit: int) -> dict:
    db_path = NAVI_WORKDIR / "navi.db"
    if not db_path.exists():
        raise NaviError(f"navi.db not found at {db_path}. Run navi_config_update('assets') first.")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql)
        rows = [dict(r) for r in cur.fetchmany(limit)]
        truncated = cur.fetchone() is not None
        return {
            "columns": [d[0] for d in cur.description] if cur.description else [],
            "rows": rows,
            "row_count": len(rows),
            "truncated": truncated,
            "limit": limit,
            "mode": "read",
        }
    finally:
        conn.close()


async def _explore_query_write(sql: str) -> dict:
    db_path = NAVI_WORKDIR / "navi.db"
    if not db_path.exists():
        raise NaviError(f"navi.db not found at {db_path}. Run navi_config_update('assets') first.")

    conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True)
    try:
        cur = conn.execute(sql)
        conn.commit()
        return {
            "rows_affected": cur.rowcount,
            "mode": "write",
            "_notice": (
                "Wrote to navi.db. If this affected cache tables, a "
                "navi_config_update(kind=...) refresh may be needed to restore "
                "consistency. CREATE INDEX persists until navi.db is rebuilt."
            ),
        }
    finally:
        conn.close()


ExploreDataSub = Literal[
    "cve", "exploit", "name", "output", "xrefs",
    "docker", "webapp", "creds", "scantime", "software",
    "audits", "plugin", "port", "route", "paths",
    "asset", "db_info",
]


@mcp.tool(
    annotations=_anno(
        title="navi explore data (reads navi.db)",
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False,
    )
)
async def navi_explore_data(
    subcommand: ExploreDataSub,
    cve: str | None = None,
    plugin_id: int | None = None,
    asset: str | None = None,  # IP or UUID
    table: str | None = None,
    name: str | None = None,
    output: str | None = None,
    xref_type: str | None = None,
    xref_id: str | None = None,
    port: int | None = None,
    minutes: int | None = None,
) -> dict:
    """
    Run a `navi explore data` subcommand. Reads navi.db — no API calls.

    Subcommand -> required arg (most are POSITIONAL in navi, not flags):
      cve        cve         (CVE-ID)
      exploit    (none)      all exploitable assets
      name       name        plugin name contains text
      output     output      plugin output contains text
      xrefs      xref_type   e.g. "CISA"; optional xref_id
      docker     (none)      Docker hosts (plugin 93561)
      webapp     (none)      potential web apps
      creds      (none)      credential failures (plugin 104410)
      scantime   minutes     assets that scanned > N minutes
      software   (none)      requires navi_config(kind='software') first
      audits     (none)      compliance results
      plugin     plugin_id   single plugin lookup
      port       port        assets with a vuln on a port
      route      (none)      vuln_route table
      paths      (none)      vuln_paths table
      asset      asset       all data for one asset (IP or UUID)
      db_info    table       schema inspector (prefer navi://schema/{table})

    For freeform SELECT, prefer navi_explore_query (direct sqlite, faster).
    """
    if subcommand == "cve":
        if not cve:
            raise NaviError("subcommand='cve' requires `cve`.")
        return _raise_on_error(await run_navi(["explore", "data", "cve", cve]), "explore data cve")
    if subcommand == "exploit":
        return _raise_on_error(await run_navi(["explore", "data", "exploit"]), "explore data exploit")
    if subcommand == "name":
        if not name:
            raise NaviError("subcommand='name' requires `name`.")
        return _raise_on_error(await run_navi(["explore", "data", "name", name]), "explore data name")
    if subcommand == "output":
        if not output:
            raise NaviError("subcommand='output' requires `output`.")
        return _raise_on_error(await run_navi(["explore", "data", "output", output]), "explore data output")
    if subcommand == "xrefs":
        if not xref_type:
            raise NaviError("subcommand='xrefs' requires `xref_type`.")
        args = ["explore", "data", "xrefs", xref_type]
        if xref_id:
            args.extend(["--xid", xref_id])
        return _raise_on_error(await run_navi(args), "explore data xrefs")
    if subcommand == "docker":
        return _raise_on_error(await run_navi(["explore", "data", "docker"]), "explore data docker")
    if subcommand == "webapp":
        return _raise_on_error(await run_navi(["explore", "data", "webapp"]), "explore data webapp")
    if subcommand == "creds":
        return _raise_on_error(await run_navi(["explore", "data", "creds"]), "explore data creds")
    if subcommand == "scantime":
        if minutes is None:
            raise NaviError("subcommand='scantime' requires `minutes`.")
        return _raise_on_error(await run_navi(["explore", "data", "scantime", str(minutes)]), "explore data scantime")
    if subcommand == "software":
        return _raise_on_error(await run_navi(["explore", "data", "software"]), "explore data software")
    if subcommand == "audits":
        return _raise_on_error(await run_navi(["explore", "data", "audits"]), "explore data audits")
    if subcommand == "plugin":
        if plugin_id is None:
            raise NaviError("subcommand='plugin' requires `plugin_id`.")
        return _raise_on_error(await run_navi(["explore", "data", "plugin", str(plugin_id)]), "explore data plugin")
    if subcommand == "port":
        if port is None:
            raise NaviError("subcommand='port' requires `port`.")
        return _raise_on_error(await run_navi(["explore", "data", "port", str(port)]), "explore data port")
    if subcommand == "route":
        return _raise_on_error(await run_navi(["explore", "data", "route"]), "explore data route")
    if subcommand == "paths":
        return _raise_on_error(await run_navi(["explore", "data", "paths"]), "explore data paths")
    if subcommand == "asset":
        if not asset:
            raise NaviError("subcommand='asset' requires `asset` (IP or UUID).")
        # Single-asset detail is `explore uuid <ip|uuid>` (there is no `explore asset`).
        return _raise_on_error(await run_navi(["explore", "uuid", asset]), "explore uuid")
    if subcommand == "db_info":
        if not table:
            raise NaviError("subcommand='db_info' requires `table`.")
        return _raise_on_error(await run_navi(["explore", "data", "db-info", "--table", table]), "explore data db-info")

    raise NaviError(f"Unknown subcommand '{subcommand}'.")


ExploreInfoSub = Literal[
    "users", "scanners", "scans", "running", "policies",
    "credentials", "agents", "agent_groups", "networks", "tags",
    "categories", "assets", "licensed", "status", "sla",
    "logs", "permissions", "auth", "exclusions", "target_groups",
    "templates", "exports", "tone", "attributes", "user_groups",
    "version",
]


@mcp.tool(
    annotations=_anno(
        title="navi explore info (live Tenable API)",
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
    )
)
async def navi_explore_info(subcommand: ExploreInfoSub) -> dict:
    """
    Run a `navi explore info` subcommand. Reads LIVE from the Tenable API —
    reflects current platform state, not navi.db.

    Use for IDs (scanners/scans/policies/credentials/categories/target_groups),
    live state (running/status/sla/logs/auth), access inventories
    (users/user_groups/permissions), platform inventories, and version.

    Underscored values map to hyphenated navi subcommands
    (agent_groups -> agent-groups, etc.) — the MCP schema prefers underscores.
    """
    hyphenated = {
        "agent_groups": "agent-groups",
        "target_groups": "target-groups",
        "user_groups": "user-groups",
    }
    navi_sub = hyphenated.get(subcommand, subcommand)
    return _raise_on_error(await run_navi(["explore", "info", navi_sub]), f"explore info {navi_sub}")


ApiMethod = Literal["GET", "POST", "PUT"]


@mcp.tool(
    annotations=_anno(
        title="Raw Tenable API passthrough",
        readOnlyHint=False,  # POST/PUT paths exist
        destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_explore_api(
    url: str,
    method: ApiMethod = "GET",
    raw: bool = False,
    limit: int | None = None,
    offset: int | None = None,
    payload: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Raw Tenable API passthrough via `navi explore api`. For endpoints navi has
    no dedicated command for — most importantly EXPORT STATUS POLLING:

      navi_explore_api(url="/vulns/export/<UUID>/status")
      navi_explore_api(url="/assets/export/<UUID>/status")

    This is the async escape hatch for large exports: navi_export blocks on the
    full run and can hit the ~4-min call ceiling, so start the export, then poll
    status here until it's FINISHED before downloading.

    method:
      GET           — read; no confirmation needed.
      POST / PUT     — WRITE to the Tenable platform. Require confirm=True AND
                       NAVI_MCP_ALLOW_WRITES=1. Pass the body via `payload`
                       (well-formed JSON string).

    raw=True returns raw JSON. limit/offset adjust API paging.

    Note: this is a broad capability. Prefer a dedicated tool when one exists;
    reach for this for status polling and read-only endpoints navi doesn't wrap.
    """
    args = ["explore", "api", url]
    if method in ("POST", "PUT"):
        _require_writes(f"navi_explore_api(method='{method}')")
        _require_confirm(f"navi_explore_api(method='{method}')", confirm)
        args.append("-post" if method == "POST" else "-put")
        if payload:
            args.extend(["--payload", payload])
    elif payload:
        raise NaviError("`payload` is only valid with method='POST' or 'PUT'.")

    if raw:
        args.append("-raw")
    if limit is not None:
        args.extend(["--limit", str(limit)])
    if offset is not None:
        args.extend(["--offset", str(offset)])

    return _raise_on_error(await run_navi(args), f"explore api {method} {url}")


# ---------------------------------------------------------------------------
# Enrich tools
# ---------------------------------------------------------------------------

@mcp.tool(
    annotations=_anno(
        title="Create a Tenable tag (write)",
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_enrich_tag(
    category: str,
    value: str,
    description: str | None = None,
    plugin: int | None = None,
    plugin_output: str | None = None,
    plugin_regexp: str | None = None,
    plugin_name: str | None = None,
    cve: str | None = None,
    cpe: str | None = None,
    xrefs: str | None = None,
    xid: str | None = None,
    port: int | None = None,
    route_id: str | None = None,
    file: str | None = None,
    manual: str | None = None,
    group: str | None = None,
    byadgroup: str | None = None,
    missed: int | None = None,
    scanid: str | None = None,
    histid: str | None = None,
    scantime: int | None = None,
    query: str | None = None,
    by_tag: str | None = None,
    by_val: str | None = None,
    by_cat: str | None = None,
    parent_category: str | None = None,  # --cc
    parent_value: str | None = None,     # --cv
    require_both: bool = False,          # -all
    tone: bool = False,                  # -tone
    remove: bool = False,                # -remove
    confirm: bool = False,
) -> dict:
    """
    Create a tag in Tenable VM via `navi enrich tag`.

    WRITE against a production tenant. Requires NAVI_MCP_ALLOW_WRITES=1 and
    confirm=True after narrating intent.

    Pass exactly ONE primary selector:
      plugin / plugin_output / plugin_regexp / plugin_name — by vuln content
      cve / cpe / xrefs (+xid) — by identifier
      port / route_id — by exposure / route
      file / manual / group / byadgroup / missed — by asset identity
      scanid (+histid) / scantime — by scan data
      query — raw SELECT returning asset_uuid
      by_tag / by_val / by_cat — derive from existing tags

    plugin_output and plugin_regexp are MODIFIERS to plugin.
    Hierarchical: parent_category + parent_value; require_both=True for AND (-all).
    tone=True creates a TONE tag.

    EPHEMERAL REFRESH — `remove=True` is a CLEAR operation, NOT a reassignment.
    In navi, `-remove` strips the tag from EVERY asset currently carrying it
    (read from the local tag membership) and IGNORES any selector. You MAY pass
    a selector together with remove=True, but the tool returns a `_warning`:
    navi runs the add and the remove as two separate jobs in one call, so it
    only adds/updates against the CURRENT membership rather than doing a clean
    refresh, and can strip assets that should stay tagged. For an accurate
    refresh, run TWO steps:
      1. Clear:    navi_enrich_tag(category=X, value=Y, remove=True, confirm=True)
      2. Wait ~30 minutes for propagation.
      3. Re-apply: navi_enrich_tag(category=X, value=Y, <selector>, confirm=True)
    The tag UUID is preserved throughout (downstream references keep working).
    Use this for point-in-time health tags, not stable classifications.

    After tagging, allow up to 30 MINUTES for results in the Tenable UI before
    verifying. On large tenants this can exceed the ~4-min call budget; if it
    times out, run the same at the CLI, and consider `navi config optimize` to
    make tagging seconds instead of minutes.
    """
    _require_writes("navi_enrich_tag")
    _require_confirm("navi_enrich_tag", confirm)

    primary_selectors = [
        ("plugin", plugin), ("cve", cve), ("cpe", cpe), ("xrefs", xrefs),
        ("port", port), ("route_id", route_id), ("file", file), ("manual", manual),
        ("group", group), ("byadgroup", byadgroup), ("missed", missed),
        ("scanid", scanid), ("scantime", scantime), ("query", query),
        ("by_tag", by_tag), ("by_val", by_val), ("by_cat", by_cat),
        ("plugin_name", plugin_name),
    ]
    provided = [n for n, v in primary_selectors if v is not None]

    # When remove=True, a selector is OPTIONAL:
    #   - no selector  -> a pure CLEAR of the tag's current membership.
    #   - with selector -> allowed, but flagged: navi runs add-then-remove as two
    #     independent jobs in one call, which only adds/updates against the
    #     CURRENT membership rather than doing a clean refresh (see combine_warning).
    # When remove=False, exactly one selector is required (normal tag create).
    combine_warning = None
    if remove:
        modifiers = [
            n for n, v in (
                ("plugin_output", plugin_output), ("plugin_regexp", plugin_regexp),
                ("xid", xid), ("histid", histid),
                ("parent_category", parent_category), ("parent_value", parent_value),
            ) if v is not None
        ]
        if require_both:
            modifiers.append("require_both")
        if provided + modifiers:
            combine_warning = (
                "You combined remove=True with a selector "
                f"({provided + modifiers}). navi runs the add and the -remove as two "
                "separate jobs in one call, so this ADDS/UPDATES against the tag's "
                "CURRENT membership rather than doing a clean refresh — the result "
                "may be inaccurate (assets that should stay tagged can be stripped). "
                "For an accurate refresh, run two steps instead: (1) clear with "
                "remove=True and NO selector, (2) wait ~30 minutes, (3) re-apply the "
                "selector with no remove. The tag UUID is preserved either way."
            )
    else:
        if len(provided) != 1:
            raise NaviError(f"Pass exactly one primary selector. Got {len(provided)}: {provided}")
        if (plugin_output or plugin_regexp) and plugin is None:
            raise NaviError("plugin_output and plugin_regexp are modifiers — they require `plugin`.")
        if xid is not None and xrefs is None:
            raise NaviError("xid requires xrefs.")
        if histid is not None and scanid is None:
            raise NaviError("histid requires scanid.")
        if require_both and not (parent_category and parent_value):
            raise NaviError("require_both=True needs parent_category + parent_value.")

    args = ["enrich", "tag", "--c", category, "--v", value]
    if description:
        args.extend(["--d", description])
    if plugin is not None:
        args.extend(["--plugin", str(plugin)])
    if plugin_output is not None:
        args.extend(["--output", plugin_output])
    if plugin_regexp is not None:
        args.append("-regexp")
        # -regexp modifies a text option; pass the pattern via --output if not already.
        if plugin_output is None:
            args.extend(["--output", plugin_regexp])
    if plugin_name is not None:
        args.extend(["--name", plugin_name])
    if cve is not None:
        args.extend(["--cve", cve])
    if cpe is not None:
        args.extend(["--cpe", cpe])
    if xrefs is not None:
        args.extend(["--xrefs", xrefs])
    if xid is not None:
        args.extend(["--xid", xid])
    if port is not None:
        args.extend(["--port", str(port)])
    if route_id is not None:
        args.extend(["--route_id", route_id])
    if file is not None:
        args.extend(["--file", file])
    if manual is not None:
        args.extend(["--manual", manual])
    if group is not None:
        args.extend(["--group", group])
    if byadgroup is not None:
        args.extend(["--byadgroup", byadgroup])
    if missed is not None:
        args.extend(["--missed", str(missed)])
    if scanid is not None:
        args.extend(["--scanid", scanid])
    if histid is not None:
        args.extend(["--histid", histid])
    if scantime is not None:
        args.extend(["--scantime", str(scantime)])
    if query is not None:
        args.extend(["--query", query])
    if by_tag is not None:
        args.extend(["--by_tag", by_tag])
    if by_val is not None:
        args.extend(["--by_val", by_val])
    if by_cat is not None:
        args.extend(["--by_cat", by_cat])
    if parent_category is not None:
        args.extend(["--cc", parent_category])
    if parent_value is not None:
        args.extend(["--cv", parent_value])
    if require_both:
        args.append("-all")
    if tone:
        args.append("-tone")
    if remove:
        args.append("-remove")

    result = _raise_on_error(
        await run_navi(args, cli_hint='navi enrich tag (rerun at CLI; see --help)'),
        "navi enrich tag",
    )
    if combine_warning is not None:
        result["_warning"] = combine_warning
        result["_notice"] = (
            "Tag add + remove ran together (see _warning). Allow up to 30 minutes "
            "for results in the Tenable UI before verifying."
        )
    elif remove:
        result["_notice"] = (
            "Tag CLEARED from its current assets (UUID preserved). Allow ~30 minutes "
            "for the removal to propagate, THEN re-apply with the same category/value "
            "and a selector (no remove=True) to complete the ephemeral refresh."
        )
    else:
        result["_notice"] = (
            "Tag created. Allow up to 30 minutes for results to appear in the "
            "Tenable UI before running verification queries."
        )
    return result


AcrMod = Literal["set", "inc", "dec"]


@mcp.tool(
    annotations=_anno(
        title="Set Asset Criticality Rating (write)",
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_enrich_acr(
    category: str,
    value: str,
    score: int,
    mod: AcrMod = "set",
    note: str | None = None,
    business: bool = False,
    compliance: bool = False,
    mitigation: bool = False,
    development: bool = False,
    confirm: bool = False,
) -> dict:
    """
    Set Asset Criticality Rating (ACR) for all assets carrying a tag.

    ACR (1–10) is what Tenable One multiplies against severity to produce AES.

    category/value — the tag whose assets get adjusted
    score — 1–10; meaning depends on mod
    mod — "set" (absolute, default), "inc" (add), "dec" (subtract)
    note — optional audit text
    business/compliance/mitigation/development — Change Reasons; at least one is
      required (Tenable One mandates a reason on every ACR change).

    Suggested mapping for mod="set": 10 Prod+PII (business+compliance),
    9 Internet-facing (business), 8 Prod (business), 6 Staging (development),
    3 Dev/test (development), 2 Isolated (mitigation).

    WRITE. Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True. Allow up to 30 min
    for Tenable One to recompute AES; re-sync afterward.
    """
    _require_writes("navi_enrich_acr")
    _require_confirm("navi_enrich_acr", confirm)

    if not 1 <= score <= 10:
        raise NaviError(f"score must be between 1 and 10 (got {score}).")
    if not any([business, compliance, mitigation, development]):
        raise NaviError(
            "At least one Change Reason flag is required "
            "(business, compliance, mitigation, development)."
        )

    args = ["enrich", "acr", "--c", category, "--v", value, "--score", str(score), "--mod", mod]
    if note:
        args.extend(["--note", note])
    if business:
        args.append("-business")
    if compliance:
        args.append("-compliance")
    if mitigation:
        args.append("-mitigation")
    if development:
        args.append("-development")

    result = _raise_on_error(await run_navi(args), "navi enrich acr")
    result["_notice"] = (
        "ACR updated. Allow up to 30 minutes for Tenable One to propagate before "
        "new AES scores appear. For the authoritative refresh afterward, run "
        "`navi config update full` at the CLI."
    )
    return result


@mcp.tool(
    annotations=_anno(
        title="Add assets to Tenable (write)",
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_enrich_add(
    ip: str | None = None,
    hostname: str | None = None,
    fqdn: str | None = None,
    mac: str | None = None,
    netbios: str | None = None,
    list_csv: str | None = None,
    source: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Add assets to Tenable VM from external sources (CMDB, AWS, OT/IoT).

    Single asset: pass `ip`, optionally hostname/fqdn/mac/netbios.
    Bulk import:  pass `list_csv` (CSV in order: IP, MAC, FQDN, Hostname) and
                  `source` (e.g. "CMDB", "AWS").

    WRITE. Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.
    """
    _require_writes("navi_enrich_add")
    _require_confirm("navi_enrich_add", confirm)

    if list_csv and ip:
        raise NaviError("Pass either `ip` (single) or `list_csv` (bulk), not both.")
    if not list_csv and not ip:
        raise NaviError("Pass either `ip` or `list_csv`.")

    args = ["enrich", "add"]
    if ip:
        args.extend(["--ip", ip])
        if hostname:
            args.extend(["--hostname", hostname])
        if fqdn:
            args.extend(["--fqdn", fqdn])
        if mac:
            args.extend(["--mac", mac])
        if netbios:
            args.extend(["--netbios", netbios])
    else:
        args.extend(["--file", list_csv])  # navi uses --file for the CSV (not --list)
        if source:
            args.extend(["--source", source])

    return _raise_on_error(await run_navi(args), "navi enrich add")


# ---------------------------------------------------------------------------
# Export tools
# ---------------------------------------------------------------------------

ExportSub = Literal[
    "assets", "bytag", "network", "licensed", "vulns",
    "failures", "route", "compliance", "agents", "group",
    "users", "policy", "parsed", "compare", "query",
]


@mcp.tool(
    annotations=_anno(
        title="Export navi data to CSV",
        readOnlyHint=False,  # writes a CSV file
        destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_export(
    subcommand: ExportSub,
    category: str | None = None,
    value: str | None = None,
    network: str | None = None,
    route_id: str | None = None,
    group_name: str | None = None,
    sql: str | None = None,
) -> dict:
    """
    Run a `navi export *` subcommand. Writes a CSV to NAVI_WORKDIR and returns
    the path + row count so Claude can surface it.

    Subcommand -> required params:
      assets/licensed/vulns/failures/compliance/agents/users/policy/parsed/compare — none
      bytag       category + value   (ONLY export with ACR + AES)
      network     network
      route       route_id
      group       group_name
      query       sql                (custom SELECT — no ACR/AES; use bytag)

    Response: csv_path, csv_bytes, csv_rows, csv_header, csv_preview (up to 5
    rows — a PREVIEW, not the full export). For analysis, prefer
    navi_explore_query against navi.db over loading the whole CSV.

    Large exports (vulns/assets) can exceed the ~4-min call budget. If this times
    out, start the export and poll with navi_explore_api(url=
    "/vulns/export/<UUID>/status") until FINISHED, or run the export at the CLI.
    """
    mtime_floor = max((p.stat().st_mtime for p in NAVI_WORKDIR.glob("*.csv")), default=0.0)

    if subcommand == "assets":
        args = ["export", "assets"]
    elif subcommand == "bytag":
        if not (category and value):
            raise NaviError("subcommand='bytag' requires `category` and `value`.")
        args = ["export", "bytag", "--c", category, "--v", value]
    elif subcommand == "network":
        if not network:
            raise NaviError("subcommand='network' requires `network`.")
        args = ["export", "network", "--network", network]
    elif subcommand == "licensed":
        args = ["export", "licensed"]
    elif subcommand == "vulns":
        args = ["export", "vulns"]
    elif subcommand == "failures":
        args = ["export", "failures"]
    elif subcommand == "route":
        if not route_id:
            raise NaviError("subcommand='route' requires `route_id`.")
        args = ["export", "route", "--route", route_id]
    elif subcommand == "compliance":
        args = ["export", "compliance"]
    elif subcommand == "agents":
        args = ["export", "agents"]
    elif subcommand == "group":
        if not group_name:
            raise NaviError("subcommand='group' requires `group_name`.")
        args = ["export", "group", "--name", group_name]
    elif subcommand == "users":
        args = ["export", "users"]
    elif subcommand == "policy":
        args = ["export", "policy"]
    elif subcommand == "parsed":
        args = ["export", "parsed"]
    elif subcommand == "compare":
        args = ["export", "compare"]
    elif subcommand == "query":
        if not sql:
            raise NaviError("subcommand='query' requires `sql`.")
        args = ["export", "query", sql]
    else:
        raise NaviError(f"Unknown subcommand '{subcommand}'.")

    cli_hint = f"navi {' '.join(shlex.quote(a) for a in args)}"
    result = _raise_on_error(await run_navi(args, cli_hint=cli_hint), f"navi export {subcommand}")

    csv = _newest_csv_after(mtime_floor)
    if csv is None:
        raise NaviError(
            f"navi export {subcommand} returned success but no new CSV appeared in "
            f"{NAVI_WORKDIR}. stdout tail: {result['stdout'][-500:] or '(empty)'}"
        )

    result["csv_path"] = str(csv)
    result["csv_bytes"] = csv.stat().st_size
    try:
        with csv.open("r", encoding="utf-8", errors="replace") as f:
            header = f.readline().rstrip("\n")
            preview_lines: list[str] = []
            row_count = 0
            for line in f:
                row_count += 1
                if len(preview_lines) < 5:
                    preview_lines.append(line.rstrip("\n"))
        result["csv_rows"] = row_count
        result["csv_header"] = header
        result["csv_preview"] = preview_lines
    except OSError as e:
        log.warning("could not read CSV for preview: %s", e)

    result["_notice"] = (
        f"Export succeeded. Full CSV at {csv} "
        f"({result.get('csv_rows', '?')} rows, {result['csv_bytes']} bytes). "
        f"`csv_preview` shows only the first {len(result.get('csv_preview', []))} "
        f"data rows — NOT the complete export. Tell the user this and point them "
        f"at the file path. For analysis, prefer navi_explore_query over loading "
        f"the whole CSV."
    )
    return result


# ---------------------------------------------------------------------------
# Scan tools
# ---------------------------------------------------------------------------

# Reads: status/details/history/hosts/latest/evaluate. Writes: create/start/stop/
# pause/resume. Deferred (scanner reassignment / I/O): move/change/bridge/
# download/upload — request to add.
ScanSub = Literal[
    "create", "start", "stop", "pause", "resume", "evaluate",
    "status", "details", "history", "hosts", "latest",
]
_SCAN_READS = {"evaluate", "status", "details", "history", "hosts", "latest"}


@mcp.tool(
    annotations=_anno(
        title="Control and inspect Tenable scans",
        readOnlyHint=False,  # mixed; create/start/stop/pause/resume write
        destructiveHint=True,  # stop/pause interrupt running scans
        idempotentHint=False, openWorldHint=True,
    )
)
async def navi_scan(
    subcommand: ScanSub,
    scan_id: str | None = None,
    targets: str | None = None,
    scanner_id: str | None = None,
    policy_id: str | None = None,
    credential_uuid: str | None = None,
    plugin: int | None = None,
    histid: str | None = None,
    full: bool = False,
    confirm: bool = False,
) -> dict:
    """
    Control and inspect Tenable scans.

    READ (no gate):
      status    — run status for scan_id
      details   — configuration detail for scan_id
      history   — run history for scan_id
      hosts     — hosts in scan_id
      latest    — latest scan results (no scan_id)
      evaluate  — scan-time performance. No args = averages across scanners/
                  schedules/policies. scan_id = one scan; + histid = a specific
                  run; full=True = entire available history.

    WRITE (NAVI_MCP_ALLOW_WRITES=1 + confirm=True):
      create    — new scan; requires targets. scanner_id/policy_id/
                  credential_uuid/plugin optional.
      start / stop / pause / resume — by scan_id.

    Look up IDs via navi_explore_info(subcommand='scanners'|'policies'|
    'credentials'|'scans'). Recurring scans: use the Tenable UI.
    """
    # Reads first.
    if subcommand in _SCAN_READS:
        if subcommand == "latest":
            return _raise_on_error(await run_navi(["scan", "latest"]), "scan latest")
        if subcommand == "evaluate":
            # scan_id is OPTIONAL for evaluate (no args = cross-dimension averages).
            args = ["scan", "evaluate"]
            if scan_id:
                args.extend(["--scanid", scan_id])
                if histid:
                    args.extend(["--histid", histid])
            elif histid:
                raise NaviError("histid requires scan_id.")
            if full:
                args.append("-full")
            return _raise_on_error(
                await run_navi(args, cli_hint="navi " + " ".join(args)), "scan evaluate"
            )
        if not scan_id:
            raise NaviError(f"subcommand='{subcommand}' requires `scan_id`.")
        # status/details/history/hosts take a positional SCAN_ID
        return _raise_on_error(await run_navi(["scan", subcommand, scan_id]), f"scan {subcommand}")

    # Writes below.
    _require_writes(f"navi_scan(subcommand='{subcommand}')")
    _require_confirm(f"navi_scan(subcommand='{subcommand}')", confirm)

    if subcommand == "create":
        if not targets:
            raise NaviError("subcommand='create' requires `targets`.")
        args = ["scan", "create", targets]
        if scanner_id:
            args.extend(["--scanner", scanner_id])
        if policy_id:
            args.extend(["--policy", policy_id])
        if credential_uuid:
            args.extend(["--cred", credential_uuid])
        if plugin is not None:
            args.extend(["--plugin", str(plugin)])
        # Note: navi `scan create` has no --name option; do not pass one.
        return _raise_on_error(await run_navi(args), "scan create")

    if subcommand in ("start", "stop", "pause", "resume"):
        if not scan_id:
            raise NaviError(f"subcommand='{subcommand}' requires `scan_id`.")
        return _raise_on_error(await run_navi(["scan", subcommand, scan_id]), f"scan {subcommand}")

    raise NaviError(f"Unknown subcommand '{subcommand}'.")


# ---------------------------------------------------------------------------
# WAS tools
# ---------------------------------------------------------------------------

WasSub = Literal[
    "configs", "scans", "details", "scan",
    "start", "stats", "export", "upload",
]


@mcp.tool(
    annotations=_anno(
        title="Tenable Web Application Scanning (DAST)",
        readOnlyHint=False,  # scan/start/upload write
        destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_was(
    subcommand: WasSub,
    config_id: str | None = None,
    scan_id: str | None = None,
    target: str | None = None,
    file: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Tenable Web Application Scanning (DAST). Requires a WAS license.

    READ:  configs (none) · scans (config_id) · details (scan_id) ·
           stats (none) · export (none)
    WRITE: scan (target URL) · start (config_id) · upload (file)
           — require NAVI_MCP_ALLOW_WRITES=1 + confirm=True.

    Drill-down: configs -> scans(config_id) -> details(scan_id).
    Prerequisite for local-data queries: navi_config_update('was').

    (All identifiers below are POSITIONAL in navi.)
    """
    if subcommand == "configs":
        return _raise_on_error(await run_navi(["was", "configs"]), "was configs")
    if subcommand == "scans":
        if not config_id:
            raise NaviError("subcommand='scans' requires `config_id`.")
        return _raise_on_error(await run_navi(["was", "scans", config_id]), "was scans")
    if subcommand == "details":
        if not scan_id:
            raise NaviError("subcommand='details' requires `scan_id`.")
        return _raise_on_error(await run_navi(["was", "details", scan_id]), "was details")
    if subcommand == "stats":
        return _raise_on_error(await run_navi(["was", "stats"]), "was stats")
    if subcommand == "export":
        return _raise_on_error(await run_navi(["was", "export"], cli_hint="navi was export"), "was export")

    _require_writes(f"navi_was(subcommand='{subcommand}')")
    _require_confirm(f"navi_was(subcommand='{subcommand}')", confirm)

    if subcommand == "scan":
        if not target:
            raise NaviError("subcommand='scan' requires `target` URL.")
        return _raise_on_error(await run_navi(["was", "scan", target]), "was scan")
    if subcommand == "start":
        if not config_id:
            raise NaviError("subcommand='start' requires `config_id`.")
        return _raise_on_error(await run_navi(["was", "start", config_id]), "was start")
    if subcommand == "upload":
        if not file:
            raise NaviError("subcommand='upload' requires `file`.")
        return _raise_on_error(await run_navi(["was", "upload", file]), "was upload")

    raise NaviError(f"Unknown subcommand '{subcommand}'.")


# ---------------------------------------------------------------------------
# Action tools — delete / rotate / cancel / encrypt / decrypt
# ---------------------------------------------------------------------------
# Intentionally NOT exposed: `navi action plan` (CSV batch tagger — compose
# per-rule navi_enrich_tag instead, more auditable), `navi action automate`,
# `navi action deploy` (containers). `navi action mail` / `navi action push`
# ARE now exposed (navi_action_mail / navi_action_push), but each is
# double-gated behind its own capability env var on top of the write gate.
# See navi-mail / navi-remote-exec / navi-action skills.

# `agent` and `exclusion` removed — they are NOT `action delete` subcommands.
# (Agent group-membership: `config agent remove`. Exclusions: `config exclude`.
# Both deferred — request to add.) Added: bytag/tgroup/usergroup/tone.
# Deferred destructive metadata wipes: category/value/table/rules/network/policy.
DeleteKind = Literal["tag", "bytag", "asset", "scan", "user", "tgroup", "usergroup", "tone"]


@mcp.tool(
    annotations=_anno(
        title="Delete Tenable objects (DESTRUCTIVE)",
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_action_delete(
    kind: DeleteKind,
    category: str | None = None,   # tag / tone
    value: str | None = None,      # tag / tone
    tag_string: str | None = None, # bytag, "category:value"
    user_id: str | None = None,    # user (numeric User ID — not UUID, not email)
    object_id: str | None = None,  # scan / asset (UUID) / tgroup / usergroup
    remove: bool = False,          # tone: remove assets from tag instead
    confirm: bool = False,
) -> dict:
    """
    Delete objects from Tenable VM. IRREVERSIBLE for most kinds.

    kind -> required params:
      tag        category + value
      bytag      tag_string ("category:value") — deletes ASSETS matching the tag
      asset      object_id (Asset UUID)
      scan       object_id (Scan ID)
      user       user_id (numeric User ID — NOT UUID, NOT email)
      tgroup     object_id (target-group ID)
      usergroup  object_id (user-group ID)
      tone       category + value (TONE tag; case-sensitive). remove=True removes
                 assets from the tag instead of deleting the tag.

    The most destructive tool here. Narrate the specific object and get explicit
    confirmation in chat. Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.

    Reversibility: tag/bytag/tone/tgroup/usergroup recreatable; scan/asset/user
    are not (Tenable may re-discover assets on next scan).
    """
    _require_writes(f"navi_action_delete(kind='{kind}')")
    _require_confirm(f"navi_action_delete(kind='{kind}')", confirm)

    if kind == "tag":
        if not (category and value):
            raise NaviError("kind='tag' requires `category` and `value`.")
        args = ["action", "delete", "tag", "--c", category, "--v", value]
    elif kind == "tone":
        if not (category and value):
            raise NaviError("kind='tone' requires `category` and `value`.")
        args = ["action", "delete", "tone", "--c", category, "--v", value]
        if remove:
            args.append("-remove")
    elif kind == "bytag":
        if not tag_string:
            raise NaviError("kind='bytag' requires `tag_string` ('category:value').")
        args = ["action", "delete", "bytag", tag_string]
    elif kind == "user":
        if not user_id:
            raise NaviError("kind='user' requires `user_id` (numeric User ID, not UUID/email).")
        args = ["action", "delete", "user", user_id]
    elif kind in ("scan", "asset", "tgroup", "usergroup"):
        if not object_id:
            raise NaviError(f"kind='{kind}' requires `object_id`.")
        args = ["action", "delete", kind, object_id]
    else:
        raise NaviError(f"Unknown kind '{kind}'.")

    return _raise_on_error(await run_navi(args), f"action delete {kind}")


@mcp.tool(
    annotations=_anno(
        title="Rotate a user's API keys (DESTRUCTIVE)",
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_action_rotate(username: str, confirm: bool = False) -> dict:
    """
    Rotate a user's API keys in Tenable VM.

    The old keys stop working immediately — anything using them (automations,
    other navi workloads) fails until updated. WRITE; requires
    NAVI_MCP_ALLOW_WRITES=1 and confirm=True.
    """
    _require_writes("navi_action_rotate")
    _require_confirm("navi_action_rotate", confirm)
    return _raise_on_error(
        await run_navi(["action", "rotate", "--username", username], timeout=60),
        "action rotate",
    )


CancelKind = Literal["assets", "vulns"]


@mcp.tool(
    annotations=_anno(
        title="Cancel a running export",
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_action_cancel(kind: CancelKind, uuid: str, confirm: bool = False) -> dict:
    """
    Cancel a running Tenable export by its export UUID.

    kind='assets' cancels an asset export (-a); kind='vulns' a vuln export (-v).
    `uuid` is REQUIRED — the export UUID to cancel (find it via
    navi_explore_info(subcommand='exports') or navi_explore_api status polling).

    WRITE; requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.
    """
    _require_writes("navi_action_cancel")
    _require_confirm("navi_action_cancel", confirm)
    flag = "-a" if kind == "assets" else "-v"
    return _raise_on_error(
        await run_navi(["action", "cancel", flag, uuid], timeout=60), "action cancel"
    )


@mcp.tool(
    annotations=_anno(
        title="Encrypt a local file",
        readOnlyHint=False,  # writes <file>.enc
        destructiveHint=False, idempotentHint=True, openWorldHint=False,
    )
)
async def navi_action_encrypt(file: str) -> dict:
    """
    Encrypt a local file via `navi action encrypt`. Produces <file>.enc.
    Local-filesystem only — no API calls. `file` is absolute or relative to
    NAVI_WORKDIR.
    """
    return _raise_on_error(await run_navi(["action", "encrypt", "--file", file]), "action encrypt")


@mcp.tool(
    annotations=_anno(
        title="Decrypt a local file",
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False,
    )
)
async def navi_action_decrypt(file: str) -> dict:
    """
    Decrypt a local .enc file via `navi action decrypt`. Local-filesystem only.
    `file` is absolute or relative to NAVI_WORKDIR.
    """
    return _raise_on_error(await run_navi(["action", "decrypt", "--file", file]), "action decrypt")


@mcp.tool(
    annotations=_anno(
        title="Email a report/file (gated: NAVI_EMAIL)",
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_action_mail(
    to: str,
    subject: str = "navi report",
    file: str | None = None,
    message: str = "",
    confirm: bool = False,
) -> dict:
    """
    Send an email via `navi action mail`, optionally attaching a file.

    DOUBLE-GATED: requires NAVI_MCP_ALLOW_WRITES=1 AND NAVI_EMAIL=1 on the
    server, plus confirm=True after you narrate the recipient/subject/attachment
    to the user. Email delivery uses the SMTP settings configured out-of-band via
    `navi config smtp` (not exposed here).

    Args:
      to       Recipient email address (REQUIRED — always passed so navi never
               drops into its interactive prompt, which would hang under MCP).
      subject  Email subject. navi appends " - Emailed by navi". Always passed.
      file     Optional path to a file to attach (absolute or relative to
               NAVI_WORKDIR). Encrypt sensitive files first via
               navi_action_encrypt and attach the .enc.
      message  Optional body text.

    Compose with navi_export (produce the CSV) or navi_action_encrypt (secure a
    sensitive attachment) before mailing.
    """
    _require_email("navi_action_mail")
    _require_confirm("navi_action_mail", confirm)
    if not to.strip():
        raise NaviError("`to` (recipient email) is required and cannot be empty.")

    # navi's mail command prompts via input() when --to/--subject are empty,
    # which deadlocks under MCP (stdin is DEVNULL). Always pass both non-empty.
    args = ["action", "mail", "--to", to, "--subject", subject or "navi report"]
    if message:
        args += ["--message", message]
    if file:
        args += ["--file", file]
    return _raise_on_error(await run_navi(args, timeout=120), "action mail")


@mcp.tool(
    annotations=_anno(
        title="Run a command on a remote host (DANGEROUS: NAVI_REMOTE_CODE_EXECUTION)",
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True,
    )
)
async def navi_action_push(
    target: str,
    command: str | None = None,
    file: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Run a shell command on — or push a file to — a single Linux host via
    `navi action push` (SSH). This is REMOTE CODE EXECUTION.

    DOUBLE-GATED: requires NAVI_MCP_ALLOW_WRITES=1 AND
    NAVI_REMOTE_CODE_EXECUTION=1 on the server, plus confirm=True after you spell
    out the exact target and command to the user. SSH credentials come from
    `navi config ssh`, set out-of-band.

    Args:
      target   Target host IP (REQUIRED). push hits ONE host — there is no --tag.
               To run across a tagged group, enumerate the tag's asset IPs and
               call this tool once per IP.
      command  Shell command to run on the target (mutually exclusive with file).
      file     Local file to copy to the target via scp (mutually exclusive with
               command).

    Exactly one of `command` or `file` must be provided. Narrate the literal
    command and target before every call — a bad command here can take a host
    down.
    """
    _require_remote_code_execution("navi_action_push")
    _require_confirm("navi_action_push", confirm)
    if not target.strip():
        raise NaviError("`target` (host IP) is required and cannot be empty.")
    if bool(command) == bool(file):
        raise NaviError("Provide exactly one of `command` or `file` (not both, not neither).")

    args = ["action", "push", "--target", target]
    if command:
        args += ["--command", command]
    if file:
        args += ["--file", file]
    return _raise_on_error(await run_navi(args, timeout=180), "action push")


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("navi://schema/{table}")
def navi_schema(table: str) -> str:
    """
    Column definitions for a navi.db table. Use before writing a SELECT.
    Known tables: assets, vulns, tags, vuln_route, vuln_paths, certs, agents,
    plugins, fixed, software, compliance, apps, findings, epss.
    """
    db_path = NAVI_WORKDIR / "navi.db"
    if not db_path.exists():
        return f"navi.db not found at {db_path}. Run a config update first."

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table,)
        ).fetchone()
        if not exists:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )]
            return f"Unknown table '{table}'. Available: {', '.join(tables)}"
        quoted = '"' + table.replace('"', '""') + '"'
        cols = conn.execute(f"PRAGMA table_info({quoted})").fetchall()
        lines = [f"{table}:"]
        for _, name, col_type, notnull, _default, pk in cols:
            flags = []
            if pk:
                flags.append("PK")
            if notnull:
                flags.append("NOT NULL")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(f"  {name}: {col_type}{suffix}")
        return "\n".join(lines)
    finally:
        conn.close()


@mcp.resource("navi://workdir")
def navi_workdir() -> str:
    """Report workdir, write-gate, navi binary, skill dir, and navi.db freshness."""
    db_path = NAVI_WORKDIR / "navi.db"
    skill_status = (
        f"skill dir: {SKILL_DIR} (exists: {SKILL_DIR.is_dir()})"
        if SKILL_PATH_LEGACY is None
        else f"skill path: {SKILL_PATH_LEGACY} (legacy single-file mode)"
    )

    # A8: surface freshness here so the freshness check is one resource read.
    freshness = "navi.db freshness: (db not present)"
    if db_path.exists():
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                row = conn.execute(
                    "SELECT MAX(last_found) AS newest_vuln, "
                    "MAX(last_licensed_scan_date) AS newest_scan FROM vulns"
                ).fetchone()
                freshness = (
                    f"navi.db freshness: newest vuln last_found={row[0] or 'NULL'}, "
                    f"newest scan={row[1] or 'NULL'}"
                )
            finally:
                conn.close()
        except sqlite3.Error as e:
            freshness = f"navi.db freshness: (could not read vulns table: {e})"

    return (
        f"workdir: {NAVI_WORKDIR}\n"
        f"navi.db present: {db_path.exists()}\n"
        f"navi.db size: {db_path.stat().st_size if db_path.exists() else 0} bytes\n"
        f"writes enabled: {ALLOW_WRITES}\n"
        f"email enabled (NAVI_EMAIL): {ALLOW_EMAIL}\n"
        f"remote code execution enabled (NAVI_REMOTE_CODE_EXECUTION): {ALLOW_REMOTE_CODE_EXECUTION}\n"
        f"navi binary: {NAVI_BIN}\n"
        f"call budget: {MCP_CALL_BUDGET:.0f}s (operations longer than this must run at the CLI)\n"
        f"{freshness}\n"
        f"{skill_status}\n"
    )


SKILL_NAMES = {
    "router": "navi",
    "mcp": "navi-mcp",
    "core": "navi-core",
    "troubleshooting": "navi-troubleshooting",
    "enrich": "navi-enrich",
    "acr": "navi-acr",
    "explore": "navi-explore",
    "export": "navi-export",
    "scan": "navi-scan",
    "action": "navi-action",
    "mail": "navi-mail",
    "remote-exec": "navi-remote-exec",
    "was": "navi-was",
}


@mcp.resource("navi://skill/{name}")
def navi_skill(name: str) -> str:
    """
    Load a navi-claude-skills domain skill by short name.

    Valid names: router, mcp, core, troubleshooting, enrich, acr, explore,
    export, scan, action, mail, remote-exec, was. The router is injected by the navi_workflow
    prompt; load others on demand when the request matches their scope.

    Domain skills use progressive disclosure: SKILL.md is the lean index, and
    deep material lives in bundled `references/*.md`. When a skill has
    references, they're listed at the end of the returned content — fetch one
    with the `navi://skill/{name}/{ref}` resource (ref = filename without .md).
    """
    if SKILL_PATH_LEGACY is not None:
        try:
            return (
                "# NOTICE: navi-mcp is running in legacy SKILL_PATH mode.\n"
                "# Only the router skill is available. Set NAVI_SKILL_DIR for the\n"
                "# full split-skill experience and unset NAVI_SKILL_PATH.\n\n"
                + SKILL_PATH_LEGACY.read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            return f"SKILL_PATH_LEGACY set to {SKILL_PATH_LEGACY} but file not found."

    if name not in SKILL_NAMES:
        return f"Unknown skill '{name}'. Available: {', '.join(sorted(SKILL_NAMES))}"

    skill_dir = SKILL_DIR / SKILL_NAMES[name]
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return (
            f"Skill file not found at {skill_md}. Check NAVI_SKILL_DIR ({SKILL_DIR}) "
            f"points at a navi-claude-skills directory."
        )

    content = skill_md.read_text(encoding="utf-8")

    # Progressive disclosure: advertise bundled references so the model knows
    # what deeper material it can pull on demand.
    refs_dir = skill_dir / "references"
    if refs_dir.is_dir():
        refs = sorted(p.stem for p in refs_dir.glob("*.md"))
        if refs:
            listing = "\n".join(
                f"- `navi://skill/{name}/{r}` — {r.replace('-', ' ')}" for r in refs
            )
            content += (
                f"\n\n---\n\n## Bundled references (load on demand)\n\n"
                f"This skill's deep reference material is split out. Fetch a "
                f"reference only when you need it:\n\n{listing}\n"
            )
    return content


@mcp.resource("navi://skill/{name}/{ref}")
def navi_skill_ref(name: str, ref: str) -> str:
    """
    Load a bundled reference file from a domain skill's `references/` directory.

    Example: navi://skill/core/schema -> <skill>/navi-core/references/schema.md
    `ref` is the filename without the .md extension. The set of available refs
    for a skill is listed at the end of its navi://skill/{name} output.
    """
    if SKILL_PATH_LEGACY is not None:
        return (
            "References are unavailable in legacy SKILL_PATH mode. Set "
            "NAVI_SKILL_DIR to a navi-claude-skills directory to use them."
        )
    if name not in SKILL_NAMES:
        return f"Unknown skill '{name}'. Available: {', '.join(sorted(SKILL_NAMES))}"

    refs_dir = SKILL_DIR / SKILL_NAMES[name] / "references"
    # Defend against path traversal — ref is a bare filename, no separators.
    safe = ref.replace("/", "").replace("\\", "").replace("..", "")
    ref_md = refs_dir / f"{safe}.md"
    if not ref_md.exists():
        avail = sorted(p.stem for p in refs_dir.glob("*.md")) if refs_dir.is_dir() else []
        return (
            f"Reference '{ref}' not found for skill '{name}'. "
            f"Available: {', '.join(avail) or '(none)'}"
        )
    return ref_md.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Prompt — inject the navi router skill; domain skills load on demand
# ---------------------------------------------------------------------------

_TOOL_LINE = (
    "navi_config_update, navi_config, navi_explore_query, navi_explore_data, "
    "navi_explore_info, navi_explore_api, navi_enrich_tag, navi_enrich_acr, "
    "navi_enrich_add, navi_export, navi_scan, navi_was, navi_action_delete, "
    "navi_action_rotate, navi_action_cancel, navi_action_encrypt, navi_action_decrypt, "
    "navi_action_mail, navi_action_push"
)


@mcp.prompt()
def navi_workflow(task: str = "") -> str:
    """
    Load the navi router skill as context and frame the user's task. In Claude
    Desktop this is the /navi_workflow slash command. Domain skills load on
    demand via navi://skill/{name}.
    """
    if SKILL_PATH_LEGACY is not None:
        try:
            skill = SKILL_PATH_LEGACY.read_text(encoding="utf-8")
        except FileNotFoundError:
            skill = f"# navi SKILL\n(SKILL.md not found at {SKILL_PATH_LEGACY}.)"
        skill_framing = (
            f"You have MCP tools wrapping nearly all non-destructive navi commands: "
            f"{_TOOL_LINE}, plus navi://schema/{{table}} and navi://workdir. Prefer "
            f"tools over suggesting manual commands. Narrate before any write and "
            f"include confirm=True only after the user approves in chat.\n\n"
        )
    else:
        router_md = SKILL_DIR / "navi" / "SKILL.md"
        try:
            skill = router_md.read_text(encoding="utf-8")
        except FileNotFoundError:
            skill = f"# navi router SKILL\n(Router not found at {router_md}.)"
        skill_framing = (
            f"You have MCP tools wrapping nearly all non-destructive navi commands: "
            f"{_TOOL_LINE}. Resources: navi://schema/{{table}}, navi://workdir, "
            f"navi://skill/{{name}}. Prefer tools over manual commands. Narrate "
            f"before any write; include confirm=True only after the user approves.\n\n"
            f"The skill below is the navi ROUTER — it says which domain skill to "
            f"load for a task. Domain skills load on demand via navi://skill/{{name}} "
            f"where {{name}} is one of: {', '.join(sorted(SKILL_NAMES))}. Load the "
            f"matching skill before producing detailed command guidance.\n\n"
        )

    task_block = f"\n\n---\n\n**User task:** {task}\n" if task.strip() else ""
    return (
        "You are operating a Tenable Vulnerability Management tenant through the "
        "`navi` CLI via the navi-mcp server.\n\n"
        f"{skill_framing}{skill}{task_block}"
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(prog="navi-mcp")
    parser.add_argument(
        "--http", action="store_true",
        help="Serve over streamable HTTP on :8000 instead of stdio.",
    )
    args = parser.parse_args()

    skill_mode = "legacy single-file" if SKILL_PATH_LEGACY is not None else "split"
    skill_location = SKILL_PATH_LEGACY if SKILL_PATH_LEGACY is not None else SKILL_DIR
    log.info(
        "starting navi-mcp (workdir=%s, writes=%s, email=%s, rce=%s, budget=%.0fs, "
        "skill_mode=%s, skill_location=%s)",
        NAVI_WORKDIR, ALLOW_WRITES, ALLOW_EMAIL, ALLOW_REMOTE_CODE_EXECUTION,
        MCP_CALL_BUDGET, skill_mode, skill_location,
    )
    mcp.run(transport="streamable-http" if args.http else "stdio")


if __name__ == "__main__":
    main()
