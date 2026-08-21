#!/usr/bin/env python3
"""
Run every navi-mcp check suite and summarise.

    python server/tests/run_all.py          # summary only
    python server/tests/run_all.py -v       # every check line

This is the smoke test to run after installing on a new machine: it imports
server.py, registers the whole tool surface, and asserts on the argv each tool
builds. It never calls the real navi binary and never touches your navi.db —
`run_navi` is stubbed and NAVI_WORKDIR is redirected to a temp dir — so it is
safe to run against a production install.

Exit code 0 = all green.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERBOSE = any(a in ("-v", "--verbose") for a in sys.argv[1:])

suites = sorted(p for p in HERE.glob("test_*.py"))
if not suites:
    print(f"No test_*.py found in {HERE}", file=sys.stderr)
    sys.exit(2)

total = failed_suites = 0
for suite in suites:
    proc = subprocess.run(
        [sys.executable, str(suite)], capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    out = proc.stdout or ""
    passed = out.count("\nPASS  ") + out.startswith("PASS  ")
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL  ")]
    total += passed
    ok = proc.returncode == 0 and not fails
    if not ok:
        failed_suites += 1

    print(f"{'PASS' if ok else 'FAIL'}  {suite.name:28} {passed:>3} checks")
    if VERBOSE:
        print("\n".join("      " + ln for ln in out.splitlines() if ln.startswith(("PASS", "FAIL"))))
    elif not ok:
        for ln in fails:
            print("      " + ln)
        if proc.returncode != 0 and not fails:
            # crashed rather than failed a check — show why
            tail = (proc.stderr or out).strip().splitlines()[-12:]
            print("\n".join("      " + ln for ln in tail))

print("-" * 52)
print(f"{total} checks across {len(suites)} suites — "
      f"{'ALL GREEN' if not failed_suites else f'{failed_suites} SUITE(S) FAILING'}")
sys.exit(1 if failed_suites else 0)
