"""
navi-mcp: An MCP server that wraps the `navi` CLI (packetchaos/navi) for
Tenable Vulnerability Management.

Exposes:
  Tools:
    navi_config_update      targeted DB refresh
    navi_config             software / sla / url setup
    navi_explore_query      SQL against navi.db — reads free, writes require confirm
    navi_explore_data       17 explore data subcommands
    navi_explore_info       26 explore info subcommands (incl. version)
    navi_enrich_tag         create a tag — write-gated
    navi_enrich_acr         set ACR with mod + Change Reasons — write-gated
    navi_enrich_add         import assets from external sources — write-gated
    navi_export             15 CSV export subcommands
    navi_scan               scan create / start / stop / evaluate
    navi_was                8 WAS subcommands (upload now takes a file)
    navi_action_delete      delete tag/user/scan/asset/agent/exclusion — write-gated, destructive
    navi_action_rotate      rotate API keys — write-gated
    navi_action_cancel      cancel running export — write-gated
    navi_action_encrypt     encrypt a local file
    navi_action_decrypt     decrypt a local file

  Resources:
    navi://schema/{table}   column definitions for a navi.db table
    navi://workdir          workdir + write gate status
    navi://skill/{name}     load a navi-claude-skills domain skill
                            (names: mcp, core, troubleshooting, enrich, acr,
                            explore, export, scan, action, was)

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

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Where navi.db and navi's own state live. Override with NAVI_WORKDIR.
NAVI_WORKDIR = Path(os.environ.get("NAVI_WORKDIR", Path.home() / ".navi-mcp")).expanduser()
NAVI_WORKDIR.mkdir(parents=True, exist_ok=True)

# Must be "1" to allow any write operation (tags, ACR, adds, deletes, etc.)
ALLOW_WRITES = os.environ.get("NAVI_MCP_ALLOW_WRITES") == "1"

# Path to the navi binary. Override with NAVI_BIN if it's not on PATH.
NAVI_BIN = os.environ.get("NAVI_BIN", "navi")

# Path to the navi-claude-skills directory (the repo root — containing navi/,
# navi-mcp/, navi-core/, etc.). The navi_workflow prompt injects the router
# from <SKILL_DIR>/navi/SKILL.md; domain skills are available on demand via
# the navi://skill/{name} resource.
#
# Backward-compat: if NAVI_SKILL_PATH is set (points at a single monolithic
# SKILL.md), it still works — the prompt injects that file and the
# navi://skill/{name} resource returns a migration notice.
SKILL_DIR = Path(
    os.environ.get(
        "NAVI_SKILL_DIR",
        Path(__file__).parent / "resources" / "skills",
    )
).expanduser()

SKILL_PATH_LEGACY = os.environ.get("NAVI_SKILL_PATH")
SKILL_PATH_LEGACY = Path(SKILL_PATH_LEGACY).expanduser() if SKILL_PATH_LEGACY else None

# Log to stderr — stdout is reserved for JSON-RPC when using stdio transport.
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
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
    timeout: float = 120.0,
) -> dict:
    """
    Execute `navi <args>` inside NAVI_WORKDIR and return a structured result.

    Uses blocking subprocess.run in a thread rather than asyncio.create_subprocess_exec
    because the async variant exhibits deadlocks on Windows when one Python process
    spawns another Python-backed entry-point executable (like navi.exe).
    CREATE_NO_WINDOW prevents Windows from trying to allocate a console for the child.
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
        # Preserve partial output — it's often the most useful forensic info
        # for long-running commands like tagging.
        raise NaviError(
            f"navi command timed out after {timeout}s: {shlex.join(argv)}\n"
            f"partial stdout: {(e.stdout or b'').decode('utf-8', 'replace')[-2000:] if isinstance(e.stdout, bytes) else (e.stdout or '')[-2000:]}\n"
            f"partial stderr: {(e.stderr or b'').decode('utf-8', 'replace')[-2000:] if isinstance(e.stderr, bytes) else (e.stderr or '')[-2000:]}"
        )

    log.info("done: rc=%s stdout=%d bytes", result.returncode, len(result.stdout or ""))
    return {
        "argv": argv,
        "returncode": result.returncode,
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
    }


def _require_writes(tool_name: str) -> None:
    """Raise NaviError if the write gate is closed."""
    if not ALLOW_WRITES:
        raise NaviError(
            f"{tool_name} is a write operation. Restart the server with "
            f"NAVI_MCP_ALLOW_WRITES=1 to enable."
        )


def _require_confirm(tool_name: str, confirm: bool) -> None:
    """Raise NaviError if per-call confirm flag is not set."""
    if not confirm:
        raise NaviError(
            f"{tool_name} requires confirm=True. Narrate the intended action "
            f"to the user first, then call again with confirm=True."
        )


def _newest_csv_after(mtime_floor: float) -> Path | None:
    """
    Find the newest .csv file in NAVI_WORKDIR modified after mtime_floor.
    navi's export commands write CSVs to the current working directory
    with varying names — this lets us report the actual path back.
    """
    candidates = [
        p for p in NAVI_WORKDIR.glob("*.csv")
        if p.stat().st_mtime > mtime_floor
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# Config tools
# ---------------------------------------------------------------------------

UpdateKind = Literal[
    "assets", "vulns", "agents", "compliance",
    "certificates", "route", "paths", "was",
]


@mcp.tool()
async def navi_config_update(
    kind: UpdateKind,
    days: int | None = None,
) -> dict:
    """
    Refresh one slice of the local navi.db.

    `kind` is one of:
      assets        — asset inventory
      vulns         — vulnerability findings
      agents        — required before any agent-group tagging
      compliance    — compliance check results (only if you scan for them)
      certificates  — SSL/TLS certificate table
      route         — vuln routing table (vulns grouped by technology)
      paths         — vuln paths table (vuln -> filesystem/URL path)
      was           — Web Application Scanning: apps + findings tables

    `days` (optional) limits the lookback window. Only honored by
    assets/vulns — for any other kind, passing `days` raises NaviError
    so the caller knows their intent didn't land.

    This tool intentionally does NOT expose `navi config update full` — that
    can take 20+ minutes on a large tenant and should be a deliberate human
    action, not something the model fires off.
    """
    if days is not None and kind not in {"assets", "vulns"}:
        raise NaviError(
            f"--days is only supported for kind='assets' or 'vulns', not '{kind}'."
        )
    args = ["config", "update", kind]
    if days is not None:
        args.extend(["--days", str(days)])
    # Give targeted updates up to 15 minutes.
    return await run_navi(args, timeout=900)


ConfigKind = Literal["software", "sla", "url"]


@mcp.tool()
async def navi_config(
    kind: ConfigKind,
    url: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Run `navi config <kind>` for the non-update config commands.

    `kind`:
      software — parse software plugins (22869, 20811, 83991) into the
                 software table. Read-only-ish; populates navi.db only.
      sla      — configure SLA thresholds per severity. Required before
                 `navi export failures`. This is interactive in navi
                 itself and may prompt — consider running it outside
                 the MCP session.
      url      — change Tenable API base URL (e.g. FedRAMP). REQUIRES
                 confirm=True and NAVI_MCP_ALLOW_WRITES=1 because it
                 reconfigures where every subsequent call goes.

    `url` is required when kind='url' and ignored otherwise.
    """
    if kind == "url":
        _require_writes("navi_config(kind='url')")
        _require_confirm("navi_config(kind='url')", confirm)
        if not url:
            raise NaviError("kind='url' requires the `url` parameter.")
        return await run_navi(["config", "url", url], timeout=30)

    if kind == "sla":
        # sla can prompt interactively; stdin is DEVNULL so it'll just hit
        # whatever defaults the user has set. Document that and move on.
        return await run_navi(["config", "sla"], timeout=60)

    # software
    return await run_navi(["config", "software"], timeout=900)


# ---------------------------------------------------------------------------
# Explore tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def navi_explore_query(
    sql: str,
    limit: int = 500,
    confirm: bool = False,
) -> dict:
    """
    Run a SQL query against navi.db.

    Reads (statements starting with SELECT or WITH) are the default and
    require no confirmation. Call freely.

    Writes (CREATE INDEX, UPDATE, DELETE, DDL, etc.) work too, but require
    `confirm=True`. These modify navi.db ONLY — no Tenable platform
    interaction. Unlike platform-write tools, local writes do NOT require
    NAVI_MCP_ALLOW_WRITES=1; the confirm flag alone is the signal of
    write intent. Worst-case outcome is a stale/inconsistent local cache,
    recoverable via navi_config_update.

    `limit` caps the number of rows returned on reads (default 500) — if
    you need more, ask the user before raising it. `limit` has no effect
    on writes.

    Banned in all modes (even with confirm=True): ATTACH DATABASE and
    PRAGMA journal_mode changes, which can corrupt navi.db in ways
    navi_config_update cannot recover.
    """
    lowered = sql.strip().lower()
    if not lowered:
        raise NaviError("Empty SQL query.")

    # Always-banned statements — even confirm=True cannot unlock these.
    # ATTACH can pull in external databases; PRAGMA journal_mode=off can
    # leave the DB unrecoverable.
    always_banned = ("attach ", "pragma journal_mode")
    if any(tok in lowered for tok in always_banned):
        raise NaviError(
            "ATTACH and PRAGMA journal_mode statements are not permitted; "
            "they can corrupt navi.db beyond recovery via navi_config_update."
        )

    is_read = lowered.startswith(("select", "with"))

    if is_read:
        return await _explore_query_read(sql, limit)

    # Write path — require confirm=True. Does NOT check ALLOW_WRITES
    # because the platform-write gate only applies to tools that change
    # Tenable state. Local navi.db writes are recoverable.
    _require_confirm("navi_explore_query (non-SELECT)", confirm)
    return await _explore_query_write(sql)


async def _explore_query_read(sql: str, limit: int) -> dict:
    """Execute a SELECT/WITH query against navi.db in read-only mode."""
    db_path = NAVI_WORKDIR / "navi.db"
    if not db_path.exists():
        raise NaviError(
            f"navi.db not found at {db_path}. Run navi_config_update('assets') first."
        )

    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
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
    """Execute a non-SELECT statement against navi.db in read-write mode."""
    db_path = NAVI_WORKDIR / "navi.db"
    if not db_path.exists():
        raise NaviError(
            f"navi.db not found at {db_path}. Run navi_config_update('assets') first."
        )

    # Read-write URI — explicit so it's obvious this path mutates.
    uri = f"file:{db_path}?mode=rw"
    conn = sqlite3.connect(uri, uri=True)
    try:
        cur = conn.execute(sql)
        conn.commit()
        return {
            "rows_affected": cur.rowcount,
            "mode": "write",
            "_notice": (
                "Wrote to navi.db. If this statement affected cache tables, "
                "a navi_config_update(kind=...) refresh may be needed to "
                "restore consistency. Indexes created via CREATE INDEX persist "
                "until navi.db is rebuilt."
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


@mcp.tool()
async def navi_explore_data(
    subcommand: ExploreDataSub,
    # Identifiers — only one is meaningful for any given subcommand
    cve: str | None = None,
    plugin_id: int | None = None,
    asset: str | None = None,  # IP or UUID
    table: str | None = None,
    # Filters
    name: str | None = None,
    output: str | None = None,
    xref_type: str | None = None,
    xref_id: str | None = None,
    port: int | None = None,
    minutes: int | None = None,
) -> dict:
    """
    Run a `navi explore data` subcommand. Reads navi.db — no API calls.

    Subcommand → required arg:
      cve         --cve <CVE-ID>        (via `cve` parameter)
      exploit     (none)                list all exploitable assets
      name        --name <text>         plugin name contains text
      output      --output <text>       plugin output contains text
      xrefs       --type <xref_type>    e.g. "CISA", "IAVA"
                  optional: --id        specific xref ID
      docker      (none)                Docker hosts (plugin 93561)
      webapp      (none)                potential web apps
      creds       (none)                credential failures
      scantime    --minutes <N>         assets scanned > N minutes
      software    (none)                requires `navi config software` first
      audits      (none)                compliance results
      plugin      <PLUGIN_ID>           (positional; via `plugin_id`)
      port        --port <N>            assets with vulns on port
      route       (none)                vuln_route table
      paths       (none)                vuln_paths table
      asset       <IP_or_UUID>          all data for one asset
      db_info     --table <name>        schema inspector
                                        (prefer navi://schema/{table} resource)

    For freeform SELECT queries, use navi_explore_query — it reads navi.db
    directly with mode=ro and is significantly faster than shelling out.
    """
    if subcommand == "cve":
        if not cve:
            raise NaviError("subcommand='cve' requires the `cve` parameter.")
        return await run_navi(["explore", "data", "cve", "--cve", cve])

    if subcommand == "exploit":
        return await run_navi(["explore", "data", "exploit"])

    if subcommand == "name":
        if not name:
            raise NaviError("subcommand='name' requires the `name` parameter.")
        return await run_navi(["explore", "data", "name", "--name", name])

    if subcommand == "output":
        if not output:
            raise NaviError("subcommand='output' requires the `output` parameter.")
        return await run_navi(["explore", "data", "output", "--output", output])

    if subcommand == "xrefs":
        if not xref_type:
            raise NaviError("subcommand='xrefs' requires the `xref_type` parameter.")
        args = ["explore", "data", "xrefs", "--type", xref_type]
        if xref_id:
            args.extend(["--id", xref_id])
        return await run_navi(args)

    if subcommand == "docker":
        return await run_navi(["explore", "data", "docker"])

    if subcommand == "webapp":
        return await run_navi(["explore", "data", "webapp"])

    if subcommand == "creds":
        return await run_navi(["explore", "data", "creds"])

    if subcommand == "scantime":
        if minutes is None:
            raise NaviError("subcommand='scantime' requires the `minutes` parameter.")
        return await run_navi(["explore", "data", "scantime", "--minutes", str(minutes)])

    if subcommand == "software":
        return await run_navi(["explore", "data", "software"])

    if subcommand == "audits":
        return await run_navi(["explore", "data", "audits"])

    if subcommand == "plugin":
        if plugin_id is None:
            raise NaviError("subcommand='plugin' requires the `plugin_id` parameter.")
        return await run_navi(["explore", "plugin", str(plugin_id)])

    if subcommand == "port":
        if port is None:
            raise NaviError("subcommand='port' requires the `port` parameter.")
        return await run_navi(["explore", "data", "port", "--port", str(port)])

    if subcommand == "route":
        return await run_navi(["explore", "data", "route"])

    if subcommand == "paths":
        return await run_navi(["explore", "data", "paths"])

    if subcommand == "asset":
        if not asset:
            raise NaviError("subcommand='asset' requires the `asset` parameter (IP or UUID).")
        return await run_navi(["explore", "asset", asset])

    if subcommand == "db_info":
        if not table:
            raise NaviError("subcommand='db_info' requires the `table` parameter.")
        return await run_navi(["explore", "data", "db-info", "--table", table])

    raise NaviError(f"Unknown subcommand '{subcommand}'.")


ExploreInfoSub = Literal[
    "users", "scanners", "scans", "running", "policies",
    "credentials", "agents", "agent_groups", "networks", "tags",
    "categories", "assets", "licensed", "status", "sla",
    "logs", "permissions", "auth", "exclusions", "target_groups",
    "templates", "exports", "tone", "attributes", "user_groups",
    "version",
]


@mcp.tool()
async def navi_explore_info(subcommand: ExploreInfoSub) -> dict:
    """
    Run a `navi explore info` subcommand. Reads LIVE from the Tenable API —
    reflects current platform state, not navi.db.

    Use these when you need:
      — IDs for follow-up commands (scanners, scans, policies, credentials,
        categories, target_groups)
      — current live state (running, status, sla, logs, auth)
      — access inventories (users, user_groups, permissions)
      — platform inventories (agents, agent_groups, networks, exclusions,
        templates, exports, tone, attributes, tags, categories)
      — version reporting (version)

    Note: several underscored subcommands map to hyphenated navi commands
    (agent_groups → agent-groups, target_groups → target-groups,
    user_groups → user-groups). MCP schema is happier with underscores.
    """
    # Map underscored Literal values back to navi's hyphenated subcommand names.
    hyphenated = {
        "agent_groups": "agent-groups",
        "target_groups": "target-groups",
        "user_groups": "user-groups",
    }
    navi_sub = hyphenated.get(subcommand, subcommand)
    # Live API calls — usually quick but give them headroom.
    return await run_navi(["explore", "info", navi_sub], timeout=120)


# ---------------------------------------------------------------------------
# Enrich tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def navi_enrich_tag(
    category: str,
    value: str,
    description: str | None = None,
    # Vulnerability-content selectors
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
    # Asset-identity selectors
    file: str | None = None,       # CSV path of IPs
    manual: str | None = None,     # asset UUID
    group: str | None = None,      # agent group name
    byadgroup: str | None = None,  # AD group CSV path
    missed: int | None = None,     # missed auth N days
    # Scan-data selectors
    scanid: str | None = None,
    histid: str | None = None,
    scantime: int | None = None,
    # Custom / derivation
    query: str | None = None,
    by_tag: str | None = None,
    by_val: str | None = None,
    by_cat: str | None = None,
    # Hierarchical
    parent_category: str | None = None,  # --cc
    parent_value: str | None = None,     # --cv
    require_both: bool = False,          # -all (AND logic with parent)
    # Modes
    tone: bool = False,     # -tone (TONE tag instead of TVM tag)
    remove: bool = False,   # -remove (clear all before re-applying)
    confirm: bool = False,
) -> dict:
    """
    Create a tag in Tenable VM via `navi enrich tag`.

    WRITE OPERATION against a production tenant. Two guardrails:
      1. Server must be started with NAVI_MCP_ALLOW_WRITES=1.
      2. Caller must pass confirm=True after narrating intent to the user.

    Selection criteria — pass exactly ONE primary selector:
      plugin / plugin_output / plugin_regexp / plugin_name — by vuln content
      cve / cpe / xrefs (+ xid) — by vulnerability identifier
      port / route_id — by exposure / technology route
      file / manual / group / byadgroup / missed — by asset identity
      scanid (+ histid) / scantime — by scan data
      query — raw SELECT returning asset_uuid values
      by_tag / by_val / by_cat — derive from existing tags

    `plugin_output` and `plugin_regexp` are MODIFIERS to `plugin` — pass
    plugin + one of them together to filter by text/regex within that
    plugin's output.

    Hierarchical tags: pass `parent_category` + `parent_value` to create
    a child tag. Set `require_both=True` for AND logic (maps to -all).

    `remove=True` (ephemeral pattern) clears the tag from all assets before
    re-applying. Use for operational health tags (cred failures, slow scans,
    CISA KEV) so stale state gets flushed. Do NOT use for stable
    classifications like Environment/OS/Route.

    `tone=True` creates a Tenable One Exposure (TONE) tag instead of a
    standard TVM tag.

    After tagging, allow up to 30 MINUTES for results to appear in the
    Tenable UI before running verification queries. Do not loop immediately.
    """
    _require_writes("navi_enrich_tag")
    _require_confirm("navi_enrich_tag", confirm)

    # Primary-selector validation. `plugin_output` and `plugin_regexp` require
    # `plugin`; they're modifiers, not standalone selectors.
    primary_selectors = [
        ("plugin", plugin), ("cve", cve), ("cpe", cpe),
        ("xrefs", xrefs), ("port", port), ("route_id", route_id),
        ("file", file), ("manual", manual), ("group", group),
        ("byadgroup", byadgroup), ("missed", missed),
        ("scanid", scanid), ("scantime", scantime),
        ("query", query), ("by_tag", by_tag),
        ("by_val", by_val), ("by_cat", by_cat),
        ("plugin_name", plugin_name),
    ]
    provided = [name for name, val in primary_selectors if val is not None]
    if len(provided) != 1:
        raise NaviError(
            f"Pass exactly one primary selector. Got {len(provided)}: {provided}"
        )
    if (plugin_output or plugin_regexp) and plugin is None:
        raise NaviError(
            "plugin_output and plugin_regexp are modifiers — they require `plugin` too."
        )
    if xid is not None and xrefs is None:
        raise NaviError("xid requires xrefs.")
    if histid is not None and scanid is None:
        raise NaviError("histid requires scanid.")
    if require_both and not (parent_category and parent_value):
        raise NaviError("require_both=True is only meaningful with parent_category + parent_value.")

    args = ["enrich", "tag", "--c", category, "--v", value]
    if description:
        args.extend(["--d", description])

    # Vulnerability-content
    if plugin is not None:
        args.extend(["--plugin", str(plugin)])
    if plugin_output is not None:
        args.extend(["--output", plugin_output])
    if plugin_regexp is not None:
        args.extend(["-regexp", plugin_regexp])
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

    # Asset-identity
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

    # Scan-data
    if scanid is not None:
        args.extend(["--scanid", scanid])
    if histid is not None:
        args.extend(["--histid", histid])
    if scantime is not None:
        args.extend(["--scantime", str(scantime)])

    # Custom / derivation
    if query is not None:
        args.extend(["--query", query])
    if by_tag is not None:
        args.extend(["--by_tag", by_tag])
    if by_val is not None:
        args.extend(["--by_val", by_val])
    if by_cat is not None:
        args.extend(["--by_cat", by_cat])

    # Hierarchical
    if parent_category is not None:
        args.extend(["--cc", parent_category])
    if parent_value is not None:
        args.extend(["--cv", parent_value])
    if require_both:
        args.append("-all")

    # Modes
    if tone:
        args.append("-tone")
    if remove:
        args.append("-remove")

    # Tagging against large tenants can take several minutes.
    result = await run_navi(args, timeout=1800)
    result["_notice"] = (
        "Tag created. Allow up to 30 minutes for results to appear in the "
        "Tenable UI before running verification queries."
    )
    return result


AcrMod = Literal["set", "inc", "dec"]


@mcp.tool()
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

    ACR is the 1–10 score Tenable One multiplies against vulnerability
    severity to produce Asset Exposure Score (AES). Adjusting ACR is how
    you teach Tenable One that your payment processor is not the same as
    a dev laptop.

    Parameters:
      category / value — target the tag whose assets will be adjusted
      score            — 1–10; meaning depends on `mod`
      mod              — "set" (absolute, default), "inc" (add), "dec" (subtract)
      note             — optional free-form audit trail text
      business /       — Tenable One Change Reasons. At least one is required
      compliance /       for audit compliance on every ACR adjustment. Pass
      mitigation /       multiple if appropriate (e.g. production + PII =
      development        business=True, compliance=True).

    Pattern:
      1. Tag assets by business tier (navi_enrich_tag).
      2. navi_enrich_acr to push ACR values that match business reality.
      3. navi_config_update('assets') to resync — AES recalculates tenant-wide.

    Suggested mapping for mod="set":
      10  — Production + PII/PCI/PHI (business + compliance)
       9  — Internet-facing / DMZ (business)
       8  — Production (business)
       6  — Staging / pre-prod (development)
       3  — Development / test (development)
       2  — Isolated / air-gapped (mitigation)

    WRITE operation. Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.
    """
    _require_writes("navi_enrich_acr")
    _require_confirm("navi_enrich_acr", confirm)

    if not 1 <= score <= 10:
        raise NaviError(f"score must be between 1 and 10 (got {score}).")

    if not any([business, compliance, mitigation, development]):
        raise NaviError(
            "At least one Change Reason flag is required "
            "(business, compliance, mitigation, development) — "
            "Tenable One requires a reason on every ACR adjustment for "
            "audit compliance."
        )

    args = [
        "enrich", "acr",
        "--c", category,
        "--v", value,
        "--score", str(score),
        "--mod", mod,
    ]
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

    result = await run_navi(args, timeout=600)
    result["_notice"] = (
        "ACR updated. Allow up to 30 minutes for Tenable One to propagate "
        "the change before new AES scores appear in dashboards. For the "
        "authoritative refresh afterward, run `navi config update full` "
        "at the CLI."
    )
    return result


@mcp.tool()
async def navi_enrich_add(
    ip: str | None = None,
    hostname: str | None = None,
    fqdn: str | None = None,
    list_csv: str | None = None,
    source: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Add assets to Tenable VM from external sources (CMDB, AWS inventory,
    OT/IoT devices that can't be actively scanned).

    Two modes:
      Single asset: pass `ip`, optionally with `hostname` and `fqdn`.
      Bulk import: pass `list_csv` (path to CSV with IP, MAC, FQDN, Hostname
                   columns) and `source` (e.g. "CMDB", "AWS").

    WRITE operation. Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.
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
    else:
        args.extend(["--list", list_csv])  # type: ignore[arg-type]
        if source:
            args.extend(["--source", source])

    return await run_navi(args, timeout=600)


# ---------------------------------------------------------------------------
# Export tools
# ---------------------------------------------------------------------------

ExportSub = Literal[
    "assets", "bytag", "network", "licensed", "vulns",
    "failures", "route", "compliance", "agents", "group",
    "users", "policy", "parsed", "compare", "query",
]


@mcp.tool()
async def navi_export(
    subcommand: ExportSub,
    # bytag
    category: str | None = None,
    value: str | None = None,
    # network
    network: str | None = None,
    # route
    route_id: str | None = None,
    # group
    group_name: str | None = None,
    # query
    sql: str | None = None,
) -> dict:
    """
    Run a `navi export *` subcommand. Writes a CSV to NAVI_WORKDIR and
    returns the path + row count so Claude can surface it to the user.

    Subcommand → required params:
      assets      (none)                       full asset dump
      bytag       category + value             ONLY export with ACR + AES
      network     network                      assets in a specific network
      licensed    (none)                       licensed assets only
      vulns       (none)                       full vuln dump
      failures    (none)                       SLA breaches (needs `navi config sla`)
      route       route_id                     vulns for a specific route
      compliance  (none)                       needs `config update compliance`
      agents      (none)                       full agent inventory
      group       group_name                   agents in a specific group
      users       (none)                       all users with roles
      policy      (none)                       scan policies (for migration)
      parsed      (none)                       normalized plugin output
      compare     (none)                       cross-asset CVE comparison
      query       sql                          custom SELECT — does NOT
                                               include ACR/AES (use bytag)

    Response shape on success:
      csv_path     — absolute path to the CSV navi just wrote
      csv_bytes    — file size
      csv_rows     — number of data rows (excluding header)
      csv_header   — the CSV's header line as a string
      csv_preview  — up to 5 data rows, for quick display. THIS IS A PREVIEW,
                     NOT THE FULL EXPORT. The `_notice` field repeats this
                     warning so Claude surfaces it to the user rather than
                     treating the preview as the answer.

    This tool verifies both that navi exited 0 AND that a new CSV actually
    appeared in NAVI_WORKDIR. Either failure raises NaviError — we don't
    silently return success if the export didn't produce output.

    For analysis, prefer navi_explore_query against navi.db over loading
    the full CSV — navi.db is already the source of the export data.
    """
    # Snapshot mtime so we can identify the newly-written CSV.
    mtime_floor = max(
        (p.stat().st_mtime for p in NAVI_WORKDIR.glob("*.csv")),
        default=0.0,
    )

    if subcommand == "assets":
        args = ["export", "assets"]
    elif subcommand == "bytag":
        if not (category and value):
            raise NaviError("subcommand='bytag' requires `category` and `value`.")
        args = ["export", "bytag", "--c", category, "--v", value]
    elif subcommand == "network":
        if not network:
            raise NaviError("subcommand='network' requires the `network` parameter.")
        args = ["export", "network", "--network", network]
    elif subcommand == "licensed":
        args = ["export", "licensed"]
    elif subcommand == "vulns":
        args = ["export", "vulns"]
    elif subcommand == "failures":
        args = ["export", "failures"]
    elif subcommand == "route":
        if not route_id:
            raise NaviError("subcommand='route' requires the `route_id` parameter.")
        args = ["export", "route", "--route", route_id]
    elif subcommand == "compliance":
        args = ["export", "compliance"]
    elif subcommand == "agents":
        args = ["export", "agents"]
    elif subcommand == "group":
        if not group_name:
            raise NaviError("subcommand='group' requires the `group_name` parameter.")
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
            raise NaviError("subcommand='query' requires the `sql` parameter.")
        args = ["export", "query", sql]
    else:
        raise NaviError(f"Unknown subcommand '{subcommand}'.")

    # Exports can take a while — vulns in particular.
    result = await run_navi(args, timeout=1800)

    # Fail loud on non-zero exit. Without this check, a silently-failed
    # export could still match a pre-existing CSV by mtime and produce a
    # misleading success response.
    if result["returncode"] != 0:
        raise NaviError(
            f"navi export {subcommand} exited with code {result['returncode']}. "
            f"stderr: {result['stderr'][-2000:] or '(empty)'}\n"
            f"stdout tail: {result['stdout'][-500:] or '(empty)'}"
        )

    # Locate the CSV navi wrote. Report path + size; do NOT inline full contents.
    csv = _newest_csv_after(mtime_floor)
    if csv is None:
        # rc==0 but no CSV appeared. Navi considers this success but from
        # the user's standpoint the export didn't produce anything — treat
        # as a failure so we don't quietly drop it.
        raise NaviError(
            f"navi export {subcommand} returned success but no new CSV was "
            f"written to {NAVI_WORKDIR}. stdout tail: "
            f"{result['stdout'][-500:] or '(empty)'}"
        )

    result["csv_path"] = str(csv)
    result["csv_bytes"] = csv.stat().st_size

    # Count rows (minus header) and grab a small preview so Claude has
    # something to show the user without loading the whole file.
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

    # Make it unmistakable to Claude (and therefore the user) that the
    # returned rows are a small preview, not the export itself.
    result["_notice"] = (
        f"Export succeeded. Full CSV written to {csv} "
        f"({result.get('csv_rows', '?')} rows, {result['csv_bytes']} bytes). "
        f"`csv_preview` above shows only the first {len(result.get('csv_preview', []))} "
        f"data rows — it is NOT the complete export. Tell the user this "
        f"explicitly, and point them at the file path for the full data. "
        f"For ad-hoc analysis, prefer navi_explore_query against navi.db "
        f"over loading the whole CSV."
    )
    return result


# ---------------------------------------------------------------------------
# Scan tools
# ---------------------------------------------------------------------------

ScanSub = Literal["create", "start", "stop", "evaluate"]


@mcp.tool()
async def navi_scan(
    subcommand: ScanSub,
    scan_id: str | None = None,
    targets: str | None = None,
    scanner_id: str | None = None,
    policy_id: str | None = None,
    credential_uuid: str | None = None,
    plugin: int | None = None,
    name: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Control Tenable scans.

    Subcommands:
      create   — create a new scan. Requires targets. scanner_id/policy_id
                 /credential_uuid optional but usually needed. WRITE.
      start    — start an existing scan by scan_id. WRITE.
      stop     — stop a running scan by scan_id. WRITE.
      evaluate — scanner performance / parsed stats for a scan_id. READ.

    Use navi_explore_info with subcommand='scanners', 'policies',
    'credentials', or 'scans' to look up IDs before creating or starting.

    WRITE subcommands (create/start/stop) require NAVI_MCP_ALLOW_WRITES=1
    and confirm=True. 'evaluate' is read-only and has no gate.
    """
    if subcommand == "evaluate":
        if not scan_id:
            raise NaviError("subcommand='evaluate' requires `scan_id`.")
        return await run_navi(
            ["scan", "evaluate", "--scanid", scan_id],
            timeout=600,
        )

    # Everything below is a write.
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
        if name:
            args.extend(["--name", name])
        return await run_navi(args, timeout=120)

    if subcommand == "start":
        if not scan_id:
            raise NaviError("subcommand='start' requires `scan_id`.")
        return await run_navi(["scan", "start", scan_id], timeout=60)

    if subcommand == "stop":
        if not scan_id:
            raise NaviError("subcommand='stop' requires `scan_id`.")
        return await run_navi(["scan", "stop", scan_id], timeout=60)

    raise NaviError(f"Unknown subcommand '{subcommand}'.")


# ---------------------------------------------------------------------------
# WAS tools
# ---------------------------------------------------------------------------

WasSub = Literal[
    "configs", "scans", "details", "scan",
    "start", "stats", "export", "upload",
]


@mcp.tool()
async def navi_was(
    subcommand: WasSub,
    config_id: str | None = None,
    scan_id: str | None = None,
    target: str | None = None,
    file: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Tenable Web Application Scanning (DAST) commands. Requires a WAS license
    separate from TVM.

    Subcommands:
      configs   — list all WAS scan configurations. READ.
      scans     — scan runs for a config_id. READ. (config_id required)
      details   — findings for a scan_id. READ. (scan_id required)
      scan      — launch ad-hoc WAS scan against `target` URL. WRITE.
      start     — start saved WAS config_id. WRITE.
      stats     — statistics across all WAS scans. READ.
      export    — export WAS data to CSV. READ.
      upload    — upload a completed scan file. WRITE. (file required)

    3-step drill-down: configs → scans (with config_id) → details (with scan_id).

    WRITE subcommands (scan/start/upload) require NAVI_MCP_ALLOW_WRITES=1
    and confirm=True.

    Prerequisite for local-data queries: run navi_config_update('was') first
    to populate the apps + findings tables.
    """
    if subcommand == "configs":
        return await run_navi(["was", "configs"], timeout=120)

    if subcommand == "scans":
        if not config_id:
            raise NaviError("subcommand='scans' requires `config_id`.")
        return await run_navi(["was", "scans", "--config", config_id], timeout=120)

    if subcommand == "details":
        if not scan_id:
            raise NaviError("subcommand='details' requires `scan_id`.")
        return await run_navi(["was", "details", "--scan", scan_id], timeout=120)

    if subcommand == "stats":
        return await run_navi(["was", "stats"], timeout=120)

    if subcommand == "export":
        return await run_navi(["was", "export"], timeout=600)

    # Writes below
    _require_writes(f"navi_was(subcommand='{subcommand}')")
    _require_confirm(f"navi_was(subcommand='{subcommand}')", confirm)

    if subcommand == "scan":
        if not target:
            raise NaviError("subcommand='scan' requires `target` URL.")
        return await run_navi(["was", "scan", "--target", target], timeout=300)

    if subcommand == "start":
        if not config_id:
            raise NaviError("subcommand='start' requires `config_id`.")
        return await run_navi(["was", "start", "--config", config_id], timeout=120)

    if subcommand == "upload":
        if not file:
            raise NaviError(
                "subcommand='upload' requires `file` — path to a completed "
                "scan file to upload."
            )
        return await run_navi(["was", "upload", "--file", file], timeout=600)

    raise NaviError(f"Unknown subcommand '{subcommand}'.")


# ---------------------------------------------------------------------------
# Action tools — delete / rotate / cancel / encrypt / decrypt
# ---------------------------------------------------------------------------
# Note: `navi action plan` (create/update/run) is intentionally NOT exposed.
# The plan file is a CSV-driven batch tagger; Claude can compose the same
# outcome by calling navi_enrich_tag per rule, which is more auditable and
# keeps the "narrate each write before firing" pattern intact.

DeleteKind = Literal["tag", "user", "scan", "asset", "agent", "exclusion"]


@mcp.tool()
async def navi_action_delete(
    kind: DeleteKind,
    # tag
    category: str | None = None,
    value: str | None = None,
    # user
    username: str | None = None,
    # scan / agent / exclusion
    id: str | None = None,
    # asset
    uuid: str | None = None,
    confirm: bool = False,
) -> dict:
    """
    Delete objects from Tenable VM. IRREVERSIBLE.

    Kind → required params:
      tag        category + value
      user       username (email)
      scan       id
      asset      uuid
      agent      id
      exclusion  id

    This is the most destructive tool in the server. Narrate the specific
    object to be deleted and get explicit user confirmation in the chat
    before calling.

    Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.

    Reversibility note:
      tag        — reversible (re-run the tagging rule)
      user       — partially (user data gone; can recreate account)
      scan       — irreversible (scan history lost)
      asset      — irreversible in this DB; Tenable may re-discover on next scan
      agent      — irreversible; agent needs re-linking
      exclusion  — reversible (recreate the exclusion)
    """
    _require_writes(f"navi_action_delete(kind='{kind}')")
    _require_confirm(f"navi_action_delete(kind='{kind}')", confirm)

    if kind == "tag":
        if not (category and value):
            raise NaviError("kind='tag' requires `category` and `value`.")
        args = ["action", "delete", "tag", "--c", category, "--v", value]
    elif kind == "user":
        if not username:
            raise NaviError("kind='user' requires `username`.")
        args = ["action", "delete", "user", "--username", username]
    elif kind == "scan":
        if not id:
            raise NaviError("kind='scan' requires `id`.")
        args = ["action", "delete", "scan", "--id", id]
    elif kind == "asset":
        if not uuid:
            raise NaviError("kind='asset' requires `uuid`.")
        args = ["action", "delete", "asset", "--uuid", uuid]
    elif kind == "agent":
        if not id:
            raise NaviError("kind='agent' requires `id`.")
        args = ["action", "delete", "agent", "--id", id]
    elif kind == "exclusion":
        if not id:
            raise NaviError("kind='exclusion' requires `id`.")
        args = ["action", "delete", "exclusion", "--id", id]
    else:
        raise NaviError(f"Unknown kind '{kind}'.")

    return await run_navi(args, timeout=300)


@mcp.tool()
async def navi_action_rotate(username: str, confirm: bool = False) -> dict:
    """
    Rotate a user's API keys in Tenable VM.

    Use for offboarding, security incidents, credential hygiene. The old
    keys stop working immediately — anything using them (automations,
    scripts, other navi workloads) will fail until they get the new keys.

    WRITE operation. Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.
    """
    _require_writes("navi_action_rotate")
    _require_confirm("navi_action_rotate", confirm)
    return await run_navi(
        ["action", "rotate", "--username", username],
        timeout=60,
    )


CancelKind = Literal["assets", "vulns"]


@mcp.tool()
async def navi_action_cancel(kind: CancelKind, confirm: bool = False) -> dict:
    """
    Cancel a running Tenable export.

    kind='assets' cancels an asset export (-a).
    kind='vulns'  cancels a vuln export  (-v).

    WRITE operation in the sense that it mutates tenant export state.
    Requires NAVI_MCP_ALLOW_WRITES=1 and confirm=True.
    """
    _require_writes("navi_action_cancel")
    _require_confirm("navi_action_cancel", confirm)
    flag = "-a" if kind == "assets" else "-v"
    return await run_navi(["action", "cancel", flag], timeout=60)


@mcp.tool()
async def navi_action_encrypt(file: str) -> dict:
    """
    Encrypt a local file via `navi action encrypt`. Produces <file>.enc
    alongside the original. Local-filesystem only — no API calls.

    `file` should be an absolute path or a path relative to NAVI_WORKDIR.
    """
    return await run_navi(["action", "encrypt", "--file", file], timeout=120)


@mcp.tool()
async def navi_action_decrypt(file: str) -> dict:
    """
    Decrypt a local file via `navi action decrypt`. Expects a .enc file
    produced by `navi action encrypt`. Local-filesystem only — no API calls.

    `file` should be an absolute path or a path relative to NAVI_WORKDIR.
    """
    return await run_navi(["action", "decrypt", "--file", file], timeout=120)


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("navi://schema/{table}")
def navi_schema(table: str) -> str:
    """
    Return the column definitions for a navi.db table.

    Use this before writing a SELECT so you don't guess at column names.
    Known useful tables: assets, vulns, tags, vuln_route, vuln_paths, certs,
    agents, plugins, fixed, software, compliance, apps, findings, epss.
    """
    db_path = NAVI_WORKDIR / "navi.db"
    if not db_path.exists():
        return f"navi.db not found at {db_path}. Run a config update first."

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
            (table,),
        ).fetchone()
        if not exists:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )]
            return f"Unknown table '{table}'. Available: {', '.join(tables)}"

        # Quote the identifier to make this robust-by-construction even
        # though the existence check above would already reject injection.
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
    """Report where navi.db lives, whether writes are enabled, and skill dir."""
    db_path = NAVI_WORKDIR / "navi.db"
    skill_status = (
        f"skill dir: {SKILL_DIR} (exists: {SKILL_DIR.is_dir()})"
        if SKILL_PATH_LEGACY is None
        else f"skill path: {SKILL_PATH_LEGACY} (legacy single-file mode)"
    )
    return (
        f"workdir: {NAVI_WORKDIR}\n"
        f"navi.db present: {db_path.exists()}\n"
        f"navi.db size: {db_path.stat().st_size if db_path.exists() else 0} bytes\n"
        f"writes enabled: {ALLOW_WRITES}\n"
        f"navi binary: {NAVI_BIN}\n"
        f"{skill_status}\n"
    )


# Valid domain skill names. Must match directory names under SKILL_DIR
# (minus the "navi-" prefix). "router" maps to the top-level "navi" directory.
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
    "was": "navi-was",
}


@mcp.resource("navi://skill/{name}")
def navi_skill(name: str) -> str:
    """
    Load a navi-claude-skills domain skill by short name.

    Valid names:
      router          — the navi router (entry point, Executive Dashboard, NL index)
      mcp             — MCP conventions (write-gate, resources, commands not exposed)
      core            — setup, schema, scale fork, multi-workload
      troubleshooting — fix-it workflows for errors and unexpected results
      enrich          — tagging, ephemeral remove=True pattern, add assets
      acr             — ACR calibration, Change Reasons, tier mapping
      explore         — querying: explore data, explore info, raw SQL
      export          — CSV exports (all 15 subcommands)
      scan            — scan create/start/stop/evaluate
      action          — delete/rotate/cancel/encrypt; plus push/mail CLI-only
      was             — Web Application Scanning

    The router is always loaded by the navi_workflow prompt. Claude loads
    other domain skills on demand via this resource when the user's request
    matches their scope.
    """
    # Legacy single-file mode — warn and return the monolith's content as
    # the router, so at least something loads.
    if SKILL_PATH_LEGACY is not None:
        try:
            return (
                "# NOTICE: navi-mcp is running in legacy SKILL_PATH mode.\n"
                "# Only the router skill is available. For the full split-skill\n"
                "# experience, set NAVI_SKILL_DIR to a navi-claude-skills directory\n"
                "# and unset NAVI_SKILL_PATH.\n\n"
                + SKILL_PATH_LEGACY.read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            return f"SKILL_PATH_LEGACY set to {SKILL_PATH_LEGACY} but file not found."

    if name not in SKILL_NAMES:
        return (
            f"Unknown skill '{name}'. "
            f"Available: {', '.join(sorted(SKILL_NAMES))}"
        )

    skill_dir_name = SKILL_NAMES[name]
    skill_md = SKILL_DIR / skill_dir_name / "SKILL.md"
    if not skill_md.exists():
        return (
            f"Skill file not found at {skill_md}. "
            f"Check that NAVI_SKILL_DIR ({SKILL_DIR}) points at a "
            f"navi-claude-skills directory containing a {skill_dir_name}/ subdir."
        )
    return skill_md.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Prompt — inject the navi router skill; domain skills load on demand
# ---------------------------------------------------------------------------

@mcp.prompt()
def navi_workflow(task: str = "") -> str:
    """
    Load the navi router skill as context and frame the user's task.

    In Claude Desktop this surfaces as a slash command — the user types
    /navi_workflow and optionally supplies a `task`. The router gets
    injected up front; Claude pulls in domain skills (navi-enrich,
    navi-acr, navi-explore, etc.) on demand via the navi://skill/{name}
    resource based on what the user actually asks.

    Backward-compat: if NAVI_SKILL_PATH is set (legacy single-file mode),
    that file is injected instead and the navi://skill/{name} resource
    returns a migration notice. Setting NAVI_SKILL_DIR unlocks the full
    split-skill experience.
    """
    # Legacy single-file mode
    if SKILL_PATH_LEGACY is not None:
        try:
            skill = SKILL_PATH_LEGACY.read_text(encoding="utf-8")
        except FileNotFoundError:
            skill = (
                "# navi SKILL\n"
                f"(SKILL.md not found at {SKILL_PATH_LEGACY}. "
                "Set NAVI_SKILL_PATH or NAVI_SKILL_DIR.)"
            )
        skill_framing = (
            "You have MCP tools available that wrap nearly all non-destructive navi "
            "commands: navi_config_update, navi_config, navi_explore_query, "
            "navi_explore_data, navi_explore_info, navi_enrich_tag, navi_enrich_acr, "
            "navi_enrich_add, navi_export, navi_scan, navi_was, "
            "navi_action_delete, navi_action_rotate, navi_action_cancel, "
            "navi_action_encrypt, navi_action_decrypt, plus navi://schema/{table} "
            "and navi://workdir resources. Prefer those over suggesting commands "
            "the user should run manually. Narrate what you're about to do before "
            "any write operation, and include confirm=True only after the user "
            "approves in chat.\n\n"
        )
    else:
        # New split-skill mode — load router, tell Claude about domain skills
        router_md = SKILL_DIR / "navi" / "SKILL.md"
        try:
            skill = router_md.read_text(encoding="utf-8")
        except FileNotFoundError:
            skill = (
                "# navi router SKILL\n"
                f"(Router not found at {router_md}. "
                "Set NAVI_SKILL_DIR to a navi-claude-skills directory.)"
            )
        skill_framing = (
            "You have MCP tools available that wrap nearly all non-destructive navi "
            "commands: navi_config_update, navi_config, navi_explore_query, "
            "navi_explore_data, navi_explore_info, navi_enrich_tag, navi_enrich_acr, "
            "navi_enrich_add, navi_export, navi_scan, navi_was, "
            "navi_action_delete, navi_action_rotate, navi_action_cancel, "
            "navi_action_encrypt, navi_action_decrypt. Resources: "
            "navi://schema/{table}, navi://workdir, navi://skill/{name}. "
            "Prefer MCP tools over suggesting commands the user should run manually. "
            "Narrate what you're about to do before any write operation, and "
            "include confirm=True only after the user approves in chat.\n\n"
            "The skill below is the navi ROUTER — it tells you which domain "
            "skill to load for a given task. Domain skills are available on "
            "demand via the navi://skill/{name} resource where {name} is one of: "
            f"{', '.join(sorted(SKILL_NAMES))}. Load the matching skill before "
            "producing detailed command guidance for its area.\n\n"
        )

    task_block = f"\n\n---\n\n**User task:** {task}\n" if task.strip() else ""

    return (
        "You are operating a Tenable Vulnerability Management tenant through the "
        "`navi` CLI via the navi-mcp server.\n\n"
        f"{skill_framing}"
        f"{skill}"
        f"{task_block}"
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(prog="navi-mcp")
    parser.add_argument(
        "--http",
        action="store_true",
        help="Serve over streamable HTTP on :8000 instead of stdio.",
    )
    args = parser.parse_args()

    skill_mode = "legacy single-file" if SKILL_PATH_LEGACY is not None else "split"
    skill_location = SKILL_PATH_LEGACY if SKILL_PATH_LEGACY is not None else SKILL_DIR
    log.info(
        "starting navi-mcp (workdir=%s, writes=%s, skill_mode=%s, skill_location=%s)",
        NAVI_WORKDIR, ALLOW_WRITES, skill_mode, skill_location,
    )
    if args.http:
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
