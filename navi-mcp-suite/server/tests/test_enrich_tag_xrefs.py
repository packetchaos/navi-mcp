"""Behavioural checks for navi_enrich_tag cross-reference + regexp handling.

Ground truth: navi-pro 8.6.4, navi/plugins/enrich.py
  406  @click.option('--xrefs', ...)
  407  @click.option('--xid', '--xref-id', ...)
  480  if xid != '' and xrefs == '':  -> click.echo ONLY, no exit()
  822  if xrefs: ... if xid: two-term LIKE (no REGEXP branch)
  regexp honoured at: by_val(458) by_cat(468) plugin+output(490) name(542)
                      cpe(803) xrefs(825)
"""
import asyncio, importlib.util, os, sys
import tempfile
from pathlib import Path

# server.py sits one level up from server/tests/ — resolve it relative to this
# file so the suite runs from any checkout, not just the machine it was written on.
SERVER_PY = str(Path(__file__).resolve().parents[1] / "server.py")

os.environ["NAVI_MCP_ALLOW_WRITES"] = "1"
os.environ["NAVI_WORKDIR"] = tempfile.mkdtemp(prefix="navi-mcp-test-")

spec = importlib.util.spec_from_file_location("navi_server2", SERVER_PY)
srv = importlib.util.module_from_spec(spec)
sys.modules["navi_server2"] = srv
spec.loader.exec_module(srv)

CALLS = []

async def fake_run_navi(args, *, timeout=None, cli_hint=None):
    CALLS.append(list(args))
    return {"argv": ["navi", *args], "returncode": 0, "stdout": "ok", "stderr": ""}

srv.run_navi = fake_run_navi
fn = getattr(srv.navi_enrich_tag, "fn", srv.navi_enrich_tag)

def run(**kw):
    CALLS.clear()
    kw.setdefault("confirm", True)
    res = asyncio.run(fn(**kw))
    return CALLS[-1], res

def expect_raises(**kw):
    kw.setdefault("confirm", True)
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

BASE = ["enrich", "tag", "--c", "CISA", "--v", "KEV"]

# --- flag spelling: --xrefs (plural), --xid ---------------------------------
a, r = run(category="CISA", value="KEV", xrefs="CISA")
check("xrefs emits --xrefs (plural)", a == BASE + ["--xrefs", "CISA"], a)
check("no --xref anywhere", "--xref" not in a, a)

a, r = run(category="CISA", value="KEV", xrefs="IAVA", xid="2024-001")
check("xid emits --xid", a == BASE + ["--xrefs", "IAVA", "--xid", "2024-001"], a)

# --- xid requires xrefs on EVERY path --------------------------------------
m = expect_raises(category="CISA", value="KEV", xid="2024-001")
check("xid without xrefs raises (create)", "xid requires xrefs" in m, m)
m = expect_raises(category="CISA", value="KEV", xid="2024-001", remove=True)
check("xid without xrefs raises (remove path)", "xid requires xrefs" in m, m)
check("raise explains navi's silent empty tag", "EMPTY tag" in m, m)

# --- regexp is global, not plugin-only -------------------------------------
a, r = run(category="CISA", value="KEV", xrefs="CISA|IAVA", regexp=True)
check("regexp xrefs tag now reachable",
      a == BASE + ["--xrefs", "CISA|IAVA", "-regexp"], a)
a, r = run(category="CISA", value="KEV", cpe="cpe:/o:microsoft.*2012", regexp=True)
check("regexp cpe", a == BASE + ["--cpe", "cpe:/o:microsoft.*2012", "-regexp"], a)
a, r = run(category="CISA", value="KEV", plugin_name="OpenSSL.*", regexp=True)
check("regexp plugin_name", a == BASE + ["--name", "OpenSSL.*", "-regexp"], a)
a, r = run(category="CISA", value="KEV", by_val="Prod.*", regexp=True)
check("regexp by_val", a == BASE + ["--by_val", "Prod.*", "-regexp"], a)
a, r = run(category="CISA", value="KEV", by_cat="Tier[12]", regexp=True)
check("regexp by_cat", a == BASE + ["--by_cat", "Tier[12]", "-regexp"], a)
a, r = run(category="CISA", value="KEV", plugin=19506, plugin_output="Apache/2\\.4\\..*", regexp=True)
check("regexp plugin+output",
      a == BASE + ["--plugin", "19506", "--output", "Apache/2\\.4\\..*", "-regexp"], a)

# regexp with a selector navi ignores it for
for sel, kw in (("cve", {"cve": "CVE-2024-1234"}), ("port", {"port": 443}),
                ("manual", {"manual": "uuid-1"}), ("query", {"query": "select 1"}),
                ("scanid", {"scanid": "12"}), ("group", {"group": "g1"})):
    m = expect_raises(category="CISA", value="KEV", regexp=True, **kw)
    check(f"regexp rejected for {sel}", "regexp-capable selector" in m, m)

m = expect_raises(category="CISA", value="KEV", regexp=True)
check("regexp with no selector raises", "regexp-capable selector" in m, m)

# --- -regexp emitted exactly once ------------------------------------------
a, r = run(category="CISA", value="KEV", plugin=19506, plugin_regexp="Apache.*", regexp=True)
check("-regexp appears once", a.count("-regexp") == 1, a)
check("plugin_regexp still sets --output", "--output" in a and "Apache.*" in a, a)
check("plugin_regexp deprecation warned", "deprecated" in r.get("_warning", ""), r.get("_warning"))

a, r = run(category="CISA", value="KEV", plugin=19506, plugin_output="Apache.*")
check("plugin_output alone: no -regexp", "-regexp" not in a, a)
check("plugin_output alone: no warning", "_warning" not in r, r.get("_warning"))

a, r = run(category="CISA", value="KEV", plugin=19506,
           plugin_output="literal", plugin_regexp="ignored")
check("plugin_output wins over plugin_regexp",
      a == BASE + ["--plugin", "19506", "--output", "literal", "-regexp"], a)

# --- xrefs + xid + regexp warning ------------------------------------------
a, r = run(category="CISA", value="KEV", xrefs="CISA", xid="2024-001", regexp=True)
check("xid+regexp warns navi ignores the pattern",
      "literal text" in r.get("_warning", ""), r.get("_warning"))
a, r = run(category="CISA", value="KEV", xrefs="CISA", xid="2024-001")
check("xid without regexp: no warning", "_warning" not in r, r.get("_warning"))

# --- unchanged behaviour regressions ---------------------------------------
a, r = run(category="CISA", value="KEV", remove=True)
check("pure clear still works", a == BASE + ["-remove"], a)
check("clear notice intact", "CLEARED" in r.get("_notice", ""), r.get("_notice"))
a, r = run(category="CISA", value="KEV", xrefs="CISA", remove=True)
check("combine warning still fires", "two" in r.get("_warning", "").lower(), r.get("_warning"))
m = expect_raises(category="CISA", value="KEV", cve="CVE-1", xrefs="CISA")
check("two selectors still rejected", "exactly one primary selector" in m, m)
# pre-existing ordering: the "exactly one primary selector" check fires first,
# since plugin_output is a modifier and contributes no primary selector.
m = expect_raises(category="CISA", value="KEV", plugin_output="x")
check("plugin_output without plugin still rejected",
      "exactly one primary selector" in m or "require `plugin`" in m, m)
m = expect_raises(category="CISA", value="KEV", xrefs="CISA", confirm=False)
check("confirm still required", "confirm=True" in m, m)

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
