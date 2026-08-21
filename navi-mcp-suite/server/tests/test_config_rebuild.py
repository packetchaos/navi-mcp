"""Checks for navi_config_rebuild (the -rebuild flag).

Ground truth: navi dev checkout, navi/plugins/config.py
  rebuild_tables(["assets"])          <- update assets -rebuild
  rebuild_tables(["vulns"])           <- update vulns  -rebuild
  rebuild_tables(["assets","vulns"])  <- update full   -rebuild   (CLI only)
  rebuild_tables() calls click.confirm() BEFORE dropping -> needs stdin
  rebuild_reminder(): certs/software/vuln_route/vuln_paths go stale
Only the local navi.db is touched; nothing in TVM changes.
"""
import asyncio, importlib.util, os, sys
import tempfile
from pathlib import Path

# server.py sits one level up from server/tests/ — resolve it relative to this
# file so the suite runs from any checkout, not just the machine it was written on.
SERVER_PY = str(Path(__file__).resolve().parents[1] / "server.py")

os.environ["NAVI_MCP_ALLOW_WRITES"] = "1"
os.environ["NAVI_WORKDIR"] = tempfile.mkdtemp(prefix="navi-mcp-test-")

spec = importlib.util.spec_from_file_location("navi_server5", SERVER_PY)
srv = importlib.util.module_from_spec(spec)
sys.modules["navi_server5"] = srv
spec.loader.exec_module(srv)

CALLS = []

async def fake_run_navi(args, *, timeout=None, cli_hint=None, stdin_text=None):
    CALLS.append({"args": list(args), "cli_hint": cli_hint, "stdin": stdin_text})
    return {"argv": ["navi", *args], "returncode": 0, "stdout": "ok", "stderr": ""}

srv.run_navi = fake_run_navi
rebuild = getattr(srv.navi_config_rebuild, "fn", srv.navi_config_rebuild)
update = getattr(srv.navi_config_update, "fn", srv.navi_config_update)

def run(fn, **kw):
    CALLS.clear()
    res = asyncio.run(fn(**kw))
    return CALLS[-1], res

def expect_raises(fn, **kw):
    try:
        asyncio.run(fn(**kw))
    except srv.NaviError as e:
        return str(e)
    raise AssertionError(f"expected NaviError for {kw}")

fails = []
def check(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"  -> {detail}" if not cond else ""))
    if not cond:
        fails.append(label)

# --- argv ------------------------------------------------------------------
c, r = run(rebuild, kind="assets", confirm=True)
check("assets rebuild argv",
      c["args"] == ["config", "update", "assets", "-rebuild"], c["args"])
c, r = run(rebuild, kind="vulns", confirm=True)
check("vulns rebuild argv",
      c["args"] == ["config", "update", "vulns", "-rebuild"], c["args"])
check("-rebuild is last", c["args"][-1] == "-rebuild", c["args"])

c, r = run(rebuild, kind="vulns", confirm=True, severity="critical", threads=4, days=7)
check("scoping flags precede -rebuild",
      c["args"] == ["config", "update", "vulns", "--days", "7", "--threads", "4",
                    "--severity", "critical", "-rebuild"], c["args"])

# --- the interactive prompt must be answered -------------------------------
check("rebuild answers navi's click.confirm", c["stdin"] == "y\n", c["stdin"])
c, r = run(update, kind="vulns", days=7)
check("plain update leaves stdin closed", c.get("stdin") is None, c.get("stdin"))

# --- gates -----------------------------------------------------------------
m = expect_raises(rebuild, kind="vulns")
check("rebuild requires confirm=True", "confirm=True" in m, m)
m = expect_raises(rebuild, kind="vulns", confirm=False)
check("confirm=False rejected", "confirm=True" in m, m)

srv.ALLOW_WRITES = False
m = expect_raises(rebuild, kind="vulns", confirm=True)
check("rebuild requires the write gate", "NAVI_MCP_ALLOW_WRITES=1" in m, m)
srv.ALLOW_WRITES = True
c, r = run(rebuild, kind="vulns", confirm=True)
check("write gate restored", c["args"][-1] == "-rebuild", c["args"])

# --- annotations: the destructive label lives on the right tool -------------
async def _annos():
    return {t.name: t.annotations for t in await srv.mcp.list_tools()}
annos = asyncio.run(_annos())
check("navi_config_rebuild is destructiveHint=True",
      getattr(annos.get("navi_config_rebuild"), "destructiveHint", None) is True,
      annos.get("navi_config_rebuild"))
check("navi_config_update stays destructiveHint=False",
      getattr(annos.get("navi_config_update"), "destructiveHint", None) is False,
      annos.get("navi_config_update"))
check("tool count is 20", len(annos) == 20, len(annos))

# --- shared validation: rebuild inherits the per-kind allow-list -------------
m = expect_raises(rebuild, kind="assets", confirm=True, severity="critical")
check("rebuild rejects severity on assets", "does not accept ['severity']" in m, m)
m = expect_raises(rebuild, kind="vulns", confirm=True, updated_at=1)
check("rebuild rejects updated_at on vulns", "does not accept ['updated_at']" in m, m)
m = expect_raises(rebuild, kind="vulns", confirm=True, threads=99)
check("rebuild enforces thread bounds", "between 1 and 20" in m, m)
m = expect_raises(rebuild, kind="assets", confirm=True, category="Prod")
check("rebuild enforces the --c/--v pair", "--c/--v" in m, m)

# --- warnings and notices ---------------------------------------------------
c, r = run(rebuild, kind="vulns", confirm=True, days=30, since=1750000000)
check("rebuild still warns on since-vs-days",
      "overrides `days`" in r.get("_warning", ""), r.get("_warning"))
c, r = run(rebuild, kind="vulns", confirm=True)
for derived in ("certificates", "software", "route", "paths"):
    check(f"notice names the stale {derived} table", derived in r.get("_notice", ""),
          r.get("_notice"))
check("notice says DROPPED", "DROPPED" in r.get("_notice", ""), r.get("_notice"))
c, r = run(rebuild, kind="assets", confirm=True)
check("assets notice names the assets table",
      "assets table was DROPPED" in r.get("_notice", ""), r.get("_notice"))

# --- cli_hint ---------------------------------------------------------------
c, r = run(rebuild, kind="vulns", confirm=True, severity="high")
check("cli_hint carries -rebuild",
      c["cli_hint"] == "navi config update vulns --severity high --threads 1 -rebuild",
      c["cli_hint"])

# --- full is not reachable as a rebuild kind --------------------------------
import typing
check("RebuildKind is assets|vulns only",
      set(typing.get_args(srv.RebuildKind)) == {"assets", "vulns"},
      typing.get_args(srv.RebuildKind))
check("'full' is not an update kind either",
      "full" not in set(typing.get_args(srv.UpdateKind)),
      typing.get_args(srv.UpdateKind))

# --- update path is genuinely non-destructive -------------------------------
for kw in ({"kind": "assets"}, {"kind": "vulns", "days": 7}, {"kind": "plugins"}):
    c, r = run(update, **kw)
    check(f"update never emits -rebuild ({kw['kind']})", "-rebuild" not in c["args"], c["args"])

# --- state/severity multiples reach the destructive path too -----------------
c, r = run(rebuild, kind="vulns", confirm=True, state=["open", "reopened"],
           severity=["critical", "high"])
check("rebuild repeats state and severity",
      c["args"] == ["config", "update", "vulns",
                    "--state", "open", "--state", "reopened",
                    "--severity", "critical", "--severity", "high", "-rebuild"], c["args"])
c, r = run(rebuild, kind="vulns", confirm=True, state="fixed")
check("rebuild accepts a bare string state",
      c["args"] == ["config", "update", "vulns", "--state", "fixed", "-rebuild"], c["args"])
m = expect_raises(rebuild, kind="vulns", confirm=True, state=[])
check("rebuild rejects an empty state list", "empty list" in m, m)

# --- failure still propagates ------------------------------------------------
async def failing(args, *, timeout=None, cli_hint=None, stdin_text=None):
    return {"argv": args, "returncode": 1, "stdout": "", "stderr": "Aborted!"}
srv.run_navi = failing
m = expect_raises(rebuild, kind="vulns", confirm=True)
check("aborted rebuild raises", "failed (exit 1)" in m, m)
check("error surfaces navi's stderr", "Aborted!" in m, m)

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
