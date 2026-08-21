"""Checks for navi_explore_data -regexp / --out coverage.

Ground truth: navi-pro 8.6.4, navi/plugins/explore.py
  plugin : @click.argument('plugin_id') --out -regexp   (regexp only affects --out)
  output : @click.argument('out_put')   -regexp
  name   : @click.argument('plugin_name') -regexp
  xrefs  : @click.argument('xref') --xid/--xref-id -regexp
           (xid branch = two-term literal LIKE, never reaches REGEXP)
No other `explore data` subcommand declares -regexp.
"""
import asyncio, importlib.util, os, sys
import tempfile
from pathlib import Path

# server.py sits one level up from server/tests/ — resolve it relative to this
# file so the suite runs from any checkout, not just the machine it was written on.
SERVER_PY = str(Path(__file__).resolve().parents[1] / "server.py")

os.environ["NAVI_WORKDIR"] = tempfile.mkdtemp(prefix="navi-mcp-test-")
spec = importlib.util.spec_from_file_location("navi_server3", SERVER_PY)
srv = importlib.util.module_from_spec(spec)
sys.modules["navi_server3"] = srv
spec.loader.exec_module(srv)

CALLS = []

async def fake_run_navi(args, *, timeout=None, cli_hint=None):
    CALLS.append(list(args))
    return {"argv": ["navi", *args], "returncode": 0, "stdout": "ok", "stderr": ""}

srv.run_navi = fake_run_navi
fn = getattr(srv.navi_explore_data, "fn", srv.navi_explore_data)

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

# --- regexp on the four supported subcommands ------------------------------
a, _ = run(subcommand="name", name="OpenSSL.*", regexp=True)
check("name -regexp", a == ["explore", "data", "name", "OpenSSL.*", "-regexp"], a)
a, _ = run(subcommand="output", output="Apache/2\\.4\\..*", regexp=True)
check("output -regexp", a == ["explore", "data", "output", "Apache/2\\.4\\..*", "-regexp"], a)
a, _ = run(subcommand="xrefs", xref_type="CISA|IAVA", regexp=True)
check("xrefs -regexp", a == ["explore", "data", "xrefs", "CISA|IAVA", "-regexp"], a)
a, _ = run(subcommand="plugin", plugin_id=19506, output="Apache.*", regexp=True)
check("plugin --out + -regexp",
      a == ["explore", "data", "plugin", "19506", "--out", "Apache.*", "-regexp"], a)

# --- --out on plugin (was dropped entirely) --------------------------------
a, _ = run(subcommand="plugin", plugin_id=19506, output="TLSv1.0")
check("plugin --out without regexp",
      a == ["explore", "data", "plugin", "19506", "--out", "TLSv1.0"], a)
a, _ = run(subcommand="plugin", plugin_id=19506)
check("plugin bare unchanged", a == ["explore", "data", "plugin", "19506"], a)
check("plugin uses --out not --output", "--output" not in a, a)

# --- regexp rejected where navi ignores it ---------------------------------
for sub, kw in (("cve", {"cve": "CVE-2024-1"}), ("port", {"port": 443}),
                ("scantime", {"minutes": 30}), ("exploit", {}), ("software", {}),
                ("asset", {"asset": "10.0.0.1"}), ("creds", {}), ("route", {}),
                ("db_info", {"table": "vulns"})):
    m = expect_raises(subcommand=sub, regexp=True, **kw)
    check(f"regexp rejected for {sub}", "honours -regexp only for" in m, m)

m = expect_raises(subcommand="plugin", plugin_id=19506, regexp=True)
check("plugin regexp without output raises", "also needs `output`" in m, m)

# --- xrefs + xid + regexp warning ------------------------------------------
a, r = run(subcommand="xrefs", xref_type="CISA", xref_id="2024-001", regexp=True)
check("xrefs xid + regexp emits both",
      a == ["explore", "data", "xrefs", "CISA", "--xid", "2024-001", "-regexp"], a)
check("xrefs xid + regexp warns", "literal text" in r.get("_warning", ""), r.get("_warning"))
a, r = run(subcommand="xrefs", xref_type="CISA", xref_id="2024-001")
check("xrefs xid alone: no warning", "_warning" not in r, r.get("_warning"))
a, r = run(subcommand="xrefs", xref_type="CISA", regexp=True)
check("xrefs regexp alone: no warning", "_warning" not in r, r.get("_warning"))

# --- regressions -----------------------------------------------------------
a, _ = run(subcommand="xrefs", xref_type="CISA")
check("xrefs bare unchanged", a == ["explore", "data", "xrefs", "CISA"], a)
a, _ = run(subcommand="name", name="OpenSSL")
check("name bare: no -regexp", a == ["explore", "data", "name", "OpenSSL"], a)
a, _ = run(subcommand="asset", asset="10.0.0.1")
check("asset still maps to explore uuid", a == ["explore", "uuid", "10.0.0.1"], a)
a, _ = run(subcommand="db_info", table="vulns")
check("db_info unchanged", a == ["explore", "data", "db-info", "--table", "vulns"], a)
m = expect_raises(subcommand="name")
check("name still requires name", "requires `name`" in m, m)

# --- coverage: the regexp set matches navi's source -------------------------
check("regexp set is exactly the four navi supports",
      srv._EXPLORE_REGEXP_SUBS == {"name", "output", "xrefs", "plugin"},
      srv._EXPLORE_REGEXP_SUBS)

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
