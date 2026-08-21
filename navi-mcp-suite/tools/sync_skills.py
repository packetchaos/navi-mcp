#!/usr/bin/env python3
"""
Refresh navi-mcp-suite/skills/ from the upstream navi-claude-skills repo.

    python tools/sync_skills.py --dry-run     # show what would change
    python tools/sync_skills.py               # do it
    python tools/sync_skills.py --verify      # ...then cross-check against server.py

Why this exists: the skills are vendored here so the MCP server can serve them
via NAVI_SKILL_DIR, but upstream is where they are actually maintained. A
hand-copied vendor directory drifts silently — this repo once shipped a server
that had `navi_config_rebuild` alongside skills that had never heard of it.
Run this whenever the server's tool surface changes, or before a release.

Upstream: https://github.com/packetchaos/navi-claude-skills
A "skill" is any top-level directory there containing a SKILL.md.

--verify parses every `navi_*(...)` call written in the skills and checks the
tool name and its keyword arguments against the tools server.py actually
registers. It is how the `navi_action_delete(kind="scan", id=...)` typo was
caught — the real parameter is `object_id`. Notes on false positives: a
`navi_*` token inside a SQL string or prose can look like a call, so read the
file before believing a hit.
"""
from __future__ import annotations

import argparse
import filecmp
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

UPSTREAM = "https://github.com/packetchaos/navi-claude-skills.git"
HERE = Path(__file__).resolve().parent
SKILLS_DIR = HERE.parent / "skills"
SERVER_PY = HERE.parent / "server" / "server.py"


def clone(dest: Path, ref: str | None) -> str:
    cmd = ["git", "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [UPSTREAM, str(dest)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("git not found on PATH — install git, or copy the skills by hand.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"clone failed:\n{e.stderr.strip()}")
    head = subprocess.run(
        ["git", "-C", str(dest), "log", "-1", "--format=%h %ad %s", "--date=short"],
        capture_output=True, text=True,
    )
    return head.stdout.strip()


def tree_differs(a: Path, b: Path) -> bool:
    """True if two skill directories differ in any file, at any depth."""
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return True
    return any(tree_differs(a / sub, b / sub) for sub in cmp.common_dirs)


def sync(dry_run: bool, ref: str | None) -> int:
    with tempfile.TemporaryDirectory(prefix="navi-skills-") as tmp:
        checkout = Path(tmp) / "upstream"
        head = clone(checkout, ref)
        print(f"upstream HEAD: {head}\n")

        incoming = sorted(p for p in checkout.iterdir()
                          if p.is_dir() and (p / "SKILL.md").is_file())
        if not incoming:
            sys.exit("no skill directories found upstream — has the layout changed?")

        local = {p.name for p in SKILLS_DIR.iterdir() if p.is_dir()} if SKILLS_DIR.is_dir() else set()
        added = updated = unchanged = 0

        for src in incoming:
            dst = SKILLS_DIR / src.name
            if not dst.exists():
                print(f"  + {src.name}  (new)")
                added += 1
            elif tree_differs(src, dst):
                print(f"  ~ {src.name}  (updated — local edits here are overwritten)")
                updated += 1
            else:
                unchanged += 1
            if not dry_run:
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)

        # Present locally but gone upstream: report, never delete. A stale skill
        # is a decision for a human — it may be intentionally local.
        stale = sorted(local - {p.name for p in incoming})
        for name in stale:
            print(f"  ! {name}  (not upstream — left in place, remove by hand if dead)")

        print(f"\n{added} added, {updated} updated, {unchanged} unchanged, "
              f"{len(stale)} local-only"
              + ("   [dry run — nothing written]" if dry_run else ""))
        return added + updated


def verify() -> int:
    """Cross-check navi_* calls written in the skills against server.py."""
    import asyncio, importlib.util, os, re

    os.environ["NAVI_WORKDIR"] = tempfile.mkdtemp(prefix="navi-mcp-verify-")
    spec = importlib.util.spec_from_file_location("navi_server_verify", str(SERVER_PY))
    srv = importlib.util.module_from_spec(spec)
    sys.modules["navi_server_verify"] = srv
    spec.loader.exec_module(srv)

    tools = asyncio.run(srv.mcp.list_tools())
    sig = {t.name: set(t.inputSchema.get("properties", {})) for t in tools}
    print(f"\nserver registers {len(sig)} tools")

    call_re = re.compile(r"\b(navi_[a-z_]+)\s*\(([^)]{0,400})", re.S)
    kw_re = re.compile(r"(?:^|[,(\s])([a-z_][a-z0-9_]*)\s*=")

    unknown: dict[str, set[str]] = {}
    bad: dict[tuple[str, str], set[str]] = {}
    seen: set[str] = set()

    for md in sorted(SKILLS_DIR.rglob("*.md")):
        rel = md.relative_to(SKILLS_DIR).as_posix()
        for m in call_re.finditer(md.read_text(encoding="utf-8", errors="replace")):
            name, args = m.group(1), m.group(2)
            if name not in sig:
                unknown.setdefault(name, set()).add(rel)
                continue
            seen.add(name)
            for kw in kw_re.findall(args):
                if kw not in sig[name]:
                    bad.setdefault((name, kw), set()).add(rel)

    problems = 0
    print("\ntool names used in skills but NOT registered by the server:")
    for n, files in sorted(unknown.items()):
        print(f"  {n}  <- {', '.join(sorted(files)[:3])}")
        problems += 1
    print("  none" if not unknown else "")

    print("keyword args used that the tool does not accept:")
    for (n, k), files in sorted(bad.items()):
        print(f"  {n}({k}=...)  <- {', '.join(sorted(files)[:3])}")
        problems += 1
    print("  none" if not bad else "")

    undocumented = sorted(set(sig) - seen)
    print("registered tools never mentioned in any skill:")
    for m in undocumented:
        print(f"  {m}")
        problems += 1
    print("  none" if not undocumented else "")

    if problems:
        print(f"\n{problems} thing(s) to look at (check for SQL strings and prose "
              f"before treating one as a bug).")
    else:
        print("\nskills and server agree.")
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="show what would change")
    ap.add_argument("--ref", help="upstream branch or tag (default: the repo's default branch)")
    ap.add_argument("--verify", action="store_true",
                    help="after syncing, cross-check skill tool calls against server.py")
    args = ap.parse_args()

    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    sync(args.dry_run, args.ref)
    if args.verify:
        verify()


if __name__ == "__main__":
    main()
