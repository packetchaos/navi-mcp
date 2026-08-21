"""Behavioural checks for the upgraded navi_config_update."""
import asyncio, importlib.util, sys, os
import tempfile
from pathlib import Path

# server.py sits one level up from server/tests/ — resolve it relative to this
# file so the suite runs from any checkout, not just the machine it was written on.
SERVER_PY = str(Path(__file__).resolve().parents[1] / "server.py")

os.environ["NAVI_WORKDIR"] = tempfile.mkdtemp(prefix="navi-mcp-test-")

spec = importlib.util.spec_from_file_location("navi_server", SERVER_PY)
srv = importlib.util.module_from_spec(spec)
sys.modules["navi_server"] = srv
spec.loader.exec_module(srv)

CALLS = []

async def fake_run_navi(args, *, timeout=None, cli_hint=None):
    CALLS.append({"args": list(args), "cli_hint": cli_hint})
    return {"argv": ["navi", *args], "returncode": 0, "stdout": "ok", "stderr": ""}

srv.run_navi = fake_run_navi

fn = srv.navi_config_update
fn = getattr(fn, "fn", fn)  # unwrap if FastMCP wrapped it

def run(**kw):
    CALLS.clear()
    res = asyncio.run(fn(**kw))
    return CALLS[-1], res

def expect_raises(**kw):
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

# --- happy paths -----------------------------------------------------------
c, r = run(kind="assets")
check("assets bare", c["args"] == ["config", "update", "assets"], c["args"])

c, r = run(kind="assets", days=90, threads=8, category="Prod", value="Yes")
check("assets days+threads+tag",
      c["args"] == ["config","update","assets","--days","90","--threads","8","--c","Prod","--v","Yes"],
      c["args"])

c, r = run(kind="assets", updated_at=1750000000)
check("assets updated_at",
      c["args"] == ["config","update","assets","--updated_at","1750000000"], c["args"])

c, r = run(kind="vulns", state="open", severity="critical", vpr_score=7.0,
           operator="gte", plugin_id=[19506, 51192], since=1750000000, exid="abc-123")
check("vulns full filter set",
      c["args"] == ["config","update","vulns","--exid","abc-123","--state","open",
                    "--severity","critical","--vpr_score","7.0","--operator","gte",
                    "--plugin_id","19506","--plugin_id","51192","--since","1750000000"],
      c["args"])

c, r = run(kind="plugins", size=5000)
check("plugins size", c["args"] == ["config","update","plugins","--size","5000"], c["args"])
c, r = run(kind="plugins")
check("plugins default size 10000",
      c["args"] == ["config","update","plugins","--size","10000"], c["args"])

c, r = run(kind="fixed", days=30)
check("fixed days", c["args"] == ["config","update","fixed","--days","30"], c["args"])

c, r = run(kind="route")
check("route bare", c["args"] == ["config","update","route"], c["args"])

# --- per-kind allow-list ---------------------------------------------------
m = expect_raises(kind="route", days=30)
check("route rejects days", "does not accept ['days']" in m, m)
m = expect_raises(kind="assets", severity="critical")
check("assets rejects severity", "does not accept ['severity']" in m, m)
m = expect_raises(kind="assets", since=1)
check("assets rejects since", "does not accept ['since']" in m, m)
m = expect_raises(kind="vulns", updated_at=1)
check("vulns rejects updated_at", "does not accept ['updated_at']" in m, m)
m = expect_raises(kind="vulns", size=5000)
check("vulns rejects size", "does not accept ['size']" in m, m)
m = expect_raises(kind="fixed", threads=4)
check("fixed rejects threads", "does not accept ['threads']" in m, m)
m = expect_raises(kind="was", category="a", value="b")
check("was rejects tag pair", "no scoping flags" in m, m)

# --- value validation ------------------------------------------------------
m = expect_raises(kind="vulns", threads=21)
check("threads upper bound", "between 1 and 20" in m, m)
m = expect_raises(kind="vulns", threads=0)
check("threads lower bound", "between 1 and 20" in m, m)
m = expect_raises(kind="assets", category="Prod")
check("category without value", "--c/--v" in m, m)
m = expect_raises(kind="assets", value="Yes")
check("value without category", "--c/--v" in m, m)
m = expect_raises(kind="vulns", operator="gte")
check("operator without vpr_score", "alongside `vpr_score`" in m, m)
m = expect_raises(kind="vulns", plugin_id=[])
check("empty plugin_id", "empty list" in m, m)
m = expect_raises(kind="plugins", size=500)
check("plugins size bound", "between 1000 and 10000" in m, m)

# --- warnings --------------------------------------------------------------
c, r = run(kind="vulns", days=30, since=1750000000)
check("since overrides days warning", "overrides `days`" in r.get("_warning",""), r.get("_warning"))
c, r = run(kind="assets", days=30, updated_at=1750000000)
check("updated_at overrides days warning", "overrides `days`" in r.get("_warning",""), r.get("_warning"))
c, r = run(kind="vulns", exid="abc", severity="high")
check("exid ignores filters warning", "do not " in r.get("_warning",""), r.get("_warning"))
c, r = run(kind="vulns", exid="abc", threads=4)
check("exid+threads: no spurious warning", "_warning" not in r, r.get("_warning"))
c, r = run(kind="vulns", days=30)
check("plain days: no warning", "_warning" not in r, r.get("_warning"))

# --- cli_hint --------------------------------------------------------------
c, r = run(kind="vulns", severity="critical", days=7)
check("cli_hint echoes scope + threads 1",
      c["cli_hint"] == "navi config update vulns --days 7 --severity critical --threads 1",
      c["cli_hint"])
c, r = run(kind="vulns", threads=4)
check("cli_hint keeps caller threads",
      c["cli_hint"] == "navi config update vulns --threads 4", c["cli_hint"])
c, r = run(kind="plugins", size=2000)
check("cli_hint plugins",
      c["cli_hint"] == "navi config update plugins --size 2000", c["cli_hint"])
c, r = run(kind="route")
check("cli_hint none for route", c["cli_hint"] is None, c["cli_hint"])
c, r = run(kind="assets", category="Business Unit", value="Finance & Ops")
check("cli_hint quotes spaces",
      c["cli_hint"] == "navi config update assets --c 'Business Unit' --v 'Finance & Ops' --threads 1",
      c["cli_hint"])

# --- kind coverage ---------------------------------------------------------
import typing
kinds = set(typing.get_args(srv.UpdateKind))
check("every kind has a flag entry", kinds == set(srv._UPDATE_FLAGS), kinds ^ set(srv._UPDATE_FLAGS))

# --- state / severity as repeatable multiples ------------------------------
c, r = run(kind="vulns", state=["open", "reopened"])
check("state list repeats the flag",
      c["args"] == ["config","update","vulns","--state","open","--state","reopened"], c["args"])
c, r = run(kind="vulns", severity=["critical", "high"])
check("severity list repeats the flag",
      c["args"] == ["config","update","vulns","--severity","critical","--severity","high"], c["args"])
c, r = run(kind="vulns", state=["open","reopened","fixed"], severity=["critical","high","medium","low","info"])
check("all states + all severities",
      c["args"] == ["config","update","vulns",
                    "--state","open","--state","reopened","--state","fixed",
                    "--severity","critical","--severity","high","--severity","medium",
                    "--severity","low","--severity","info"], c["args"])

# a bare string still works (models pass scalars)
c, r = run(kind="vulns", state="open")
check("bare string state accepted",
      c["args"] == ["config","update","vulns","--state","open"], c["args"])
c, r = run(kind="vulns", severity="critical")
check("bare string severity accepted",
      c["args"] == ["config","update","vulns","--severity","critical"], c["args"])

# ordering preserved, duplicates collapsed
c, r = run(kind="vulns", state=["fixed", "open"])
check("state order preserved",
      c["args"] == ["config","update","vulns","--state","fixed","--state","open"], c["args"])
c, r = run(kind="vulns", state=["open", "open", "reopened", "open"])
check("duplicate states collapsed",
      c["args"] == ["config","update","vulns","--state","open","--state","reopened"], c["args"])

m = expect_raises(kind="vulns", state=[])
check("empty state list raises", "empty list" in m, m)
m = expect_raises(kind="vulns", severity=[])
check("empty severity list raises", "empty list" in m, m)

# still per-kind gated
m = expect_raises(kind="assets", state=["open"])
check("assets still rejects state list", "does not accept ['state']" in m, m)

# cli_hint echoes every repetition
c, r = run(kind="vulns", state=["open","fixed"], threads=2)
check("cli_hint repeats state",
      c["cli_hint"] == "navi config update vulns --threads 2 --state open --state fixed",
      c["cli_hint"])

# --- non-zero exit still raises -------------------------------------------
async def failing(args, *, timeout=None, cli_hint=None):
    return {"argv": args, "returncode": 1, "stdout": "", "stderr": "boom"}
srv.run_navi = failing
m = expect_raises(kind="assets", days=1)
check("non-zero exit raises", "failed (exit 1)" in m, m)

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
