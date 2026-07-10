#!/usr/bin/env python3
"""
navi-mcp config helper
======================

Discovers the paths Claude Desktop needs to launch the navi-mcp server and
prints the `mcpServers` JSON block. Optionally (--write) merges it into your
Claude Desktop config, keeping a timestamped backup.

It finds, by searching common locations:
  * the navi-mcp server.py          -> "args"
  * the navi.db's folder            -> NAVI_WORKDIR
  * the navi executable             -> NAVI_BIN
  * a navi skills directory         -> NAVI_SKILL_DIR
  * the Python running this script  -> "command"

IMPORTANT: run this with the SAME Python you want Claude Desktop to use —
the one that has both `mcp` and `navi` installed. For example:

    /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 navi_mcp_config.py

Usage:
    python3 navi_mcp_config.py                 # discover + print JSON
    python3 navi_mcp_config.py --allow-writes  # set NAVI_MCP_ALLOW_WRITES=1
    python3 navi_mcp_config.py --allow-writes --allow-email  # + NAVI_EMAIL=1 (mail tool)
    python3 navi_mcp_config.py --allow-writes --allow-remote-code-execution  # + RCE (push tool)
    python3 navi_mcp_config.py --write          # merge into Claude Desktop config (with backup)
    python3 navi_mcp_config.py --root ~/code    # add an extra search root
    # any path can be pinned explicitly to skip discovery:
    python3 navi_mcp_config.py --server ... --workdir ... --navi ... --skills ...
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import sys
from pathlib import Path

# Directories we never descend into (slow / irrelevant).
SKIP_DIRS = {
    "node_modules", "Library", ".git", ".hg", ".svn", ".Trash", "__pycache__",
    ".venv", "venv", "env", ".tox", ".cache", "site-packages", ".npm",
    "Photos Library.photoslibrary", ".DS_Store",
}
MAX_DEPTH = 6  # how deep to walk under each root


# ----------------------------------------------------------------------------
# Bounded directory walk
# ----------------------------------------------------------------------------
def walk(root: Path, max_depth: int = MAX_DEPTH):
    """Yield files under root, pruning heavy/irrelevant dirs and capping depth."""
    root = root.expanduser()
    if not root.is_dir():
        return
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda e: None):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        # prune
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def default_roots(script_dir: Path) -> list[Path]:
    home = Path.home()
    roots = [
        Path.cwd(),
        script_dir,
        Path(sys.executable).resolve().parent,   # the interpreter's bin dir
        home / "navi",
        home / "Downloads",
        home / "Documents",
        home / "Desktop",
        home / "code",
        home / "src",
        home / "projects",
    ]
    # de-dupe while preserving order, keep only existing dirs
    seen, out = set(), []
    for r in roots:
        r = r.expanduser()
        try:
            key = r.resolve()
        except OSError:
            continue
        if key in seen or not r.is_dir():
            continue
        seen.add(key)
        out.append(r)
    return out


# ----------------------------------------------------------------------------
# Recognisers
# ----------------------------------------------------------------------------
def looks_like_navi_server(path: Path) -> bool:
    """A navi-mcp server.py contains FastMCP setup + navi tool definitions."""
    if path.name != "server.py":
        return False
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return False
    return ("FastMCP(" in text) and ("navi_enrich_tag" in text or "navi-mcp" in text)


def collect(roots: list[Path]):
    """Single pass per root collecting server.py, navi.db, and skills SKILL.md."""
    servers: list[Path] = []
    dbs: list[Path] = []
    skill_dirs: list[Path] = []
    for root in roots:
        for f in walk(root):
            name = f.name
            if name == "server.py":
                if looks_like_navi_server(f):
                    servers.append(f)
            elif name == "navi.db":
                dbs.append(f)
            elif name == "SKILL.md":
                # The skills dir is the parent of the navi-mcp/ (or navi/) folder.
                parent = f.parent
                if parent.name in ("navi-mcp", "navi"):
                    skill_dirs.append(parent.parent)
    return servers, dbs, skill_dirs


def pick(paths: list[Path]):
    """Prefer the shallowest path, then the most recently modified."""
    def key(p: Path):
        try:
            mtime = p.stat().st_mtime
        except OSError:
            mtime = 0
        # bonus for living under a navi-mcp-suite / navi-mcp tree
        bonus = 0 if any(part in ("navi-mcp-suite", "navi-mcp") for part in p.parts) else 1
        return (bonus, len(p.parts), -mtime)
    uniq = sorted({p.resolve() for p in paths}, key=key)
    return uniq[0] if uniq else None


def find_navi(python_path: Path) -> Path | None:
    """navi usually sits next to the interpreter; fall back to PATH."""
    sibling = python_path.parent / "navi"
    if sibling.is_file():
        return sibling
    found = shutil.which("navi")
    return Path(found) if found else None


def claude_config_path() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    if os.name == "nt":
        base = os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming"))
        return Path(base) / "Claude/claude_desktop_config.json"
    return Path.home() / ".config/Claude/claude_desktop_config.json"


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the navi-mcp Claude Desktop config.")
    ap.add_argument("--server", help="Path to server.py (skip discovery)")
    ap.add_argument("--workdir", help="NAVI_WORKDIR — folder containing navi.db (skip discovery)")
    ap.add_argument("--navi", help="Path to the navi binary (skip discovery)")
    ap.add_argument("--skills", help="NAVI_SKILL_DIR — skills checkout (skip discovery)")
    ap.add_argument("--python", help="Interpreter for 'command' (default: this one)")
    ap.add_argument("--name", default="navi", help="mcpServers key name (default: navi)")
    ap.add_argument("--allow-writes", action="store_true", help="Set NAVI_MCP_ALLOW_WRITES=1")
    ap.add_argument("--allow-email", action="store_true",
                    help="Set NAVI_EMAIL=1 (enables navi_action_mail; also needs --allow-writes)")
    ap.add_argument("--allow-remote-code-execution", action="store_true",
                    help="Set NAVI_REMOTE_CODE_EXECUTION=1 (enables navi_action_push; also needs --allow-writes)")
    ap.add_argument("--root", action="append", default=[], help="Extra directory to search (repeatable)")
    ap.add_argument("--write", action="store_true", help="Merge into the Claude Desktop config (with backup)")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    roots = default_roots(script_dir) + [Path(r) for r in args.root]

    # --- Python interpreter -------------------------------------------------
    python_path = Path(args.python).expanduser() if args.python else Path(sys.executable)
    python_path = python_path.resolve()

    # --- Discover (unless pinned) ------------------------------------------
    need_discovery = not (args.server and args.workdir and args.skills)
    servers, dbs, skill_dirs = collect(roots) if need_discovery else ([], [], [])

    server = Path(args.server).expanduser().resolve() if args.server else pick(servers)
    if args.workdir:
        workdir = Path(args.workdir).expanduser().resolve()
    else:
        db = pick(dbs)
        workdir = db.parent if db else None
    navi = Path(args.navi).expanduser().resolve() if args.navi else find_navi(python_path)
    skills = Path(args.skills).expanduser().resolve() if args.skills else pick(skill_dirs)

    # --- Verify the interpreter has the MCP SDK -----------------------------
    mcp_ok, mcp_ver = False, ""
    try:
        import importlib
        m = importlib.import_module("mcp")
        mcp_ok, mcp_ver = True, getattr(m, "__version__", "unknown")
    except Exception:
        pass

    # --- Report -------------------------------------------------------------
    def status(label, value, *, required=True):
        mark = "OK " if value else ("MISSING" if required else "skip")
        print(f"  [{mark:>7}] {label:<13} {value if value else '(not found)'}", file=sys.stderr)

    print("navi-mcp discovery", file=sys.stderr)
    print(f"  searched roots: {', '.join(str(r) for r in roots)}", file=sys.stderr)
    if mcp_ok:
        mcp_line = f"mcp SDK v{mcp_ver}"
    else:
        mcp_line = f"mcp SDK NOT importable here — run: {python_path} -m pip install --upgrade mcp"
    print(f"  [{'OK ' if mcp_ok else 'MISSING':>7}] {mcp_line}", file=sys.stderr)
    status("python", python_path)
    status("server.py", server)
    status("navi binary", navi)
    status("workdir", workdir)
    status("skills dir", skills, required=False)
    if need_discovery and len(servers) > 1:
        print(f"  note: {len(servers)} server.py candidates; chose the best match. "
              f"Override with --server if wrong:", file=sys.stderr)
        for s in sorted({p.resolve() for p in servers}):
            print(f"        - {s}", file=sys.stderr)
    print("", file=sys.stderr)

    # --- Build the JSON entry ----------------------------------------------
    env = {}
    env["NAVI_BIN"] = str(navi) if navi else "SET_ME-absolute-path-to-navi"
    env["NAVI_WORKDIR"] = str(workdir) if workdir else "SET_ME-folder-containing-navi.db"
    if skills:
        env["NAVI_SKILL_DIR"] = str(skills)
    env["NAVI_MCP_ALLOW_WRITES"] = "1" if args.allow_writes else "0"
    env["NAVI_EMAIL"] = "1" if args.allow_email else "0"
    env["NAVI_REMOTE_CODE_EXECUTION"] = "1" if args.allow_remote_code_execution else "0"

    # The two capability gates stack on the master write gate — warn if one is
    # requested without it, since the tool will refuse to run.
    if (args.allow_email or args.allow_remote_code_execution) and not args.allow_writes:
        print("WARNING: --allow-email / --allow-remote-code-execution have no effect "
              "without --allow-writes (both gates must be open).", file=sys.stderr)

    entry = {
        "command": str(python_path),
        "args": [str(server) if server else "SET_ME-absolute-path-to-server.py"],
        "env": env,
    }
    block = {"mcpServers": {args.name: entry}}

    cfg_path = claude_config_path()

    if args.write:
        # Merge into the existing config, preserving everything else.
        existing = {}
        if cfg_path.exists():
            try:
                existing = json.loads(cfg_path.read_text())
            except json.JSONDecodeError as e:
                print(f"ERROR: {cfg_path} is not valid JSON ({e}); not writing.", file=sys.stderr)
                print("Fix the file or paste the block below by hand.", file=sys.stderr)
                print(json.dumps(block, indent=2, ensure_ascii=False))
                return 1
            backup = cfg_path.with_suffix(cfg_path.suffix + ".bak." +
                                          _dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
            backup.write_text(cfg_path.read_text())
            print(f"backed up existing config -> {backup}", file=sys.stderr)
        existing.setdefault("mcpServers", {})[args.name] = entry
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {cfg_path}", file=sys.stderr)
        print("Fully quit (Cmd+Q) and reopen Claude Desktop to load it.", file=sys.stderr)
    else:
        print(f"# Paste into {cfg_path}", file=sys.stderr)
        print(f"# (Settings -> Developer -> Edit Config). Merge the \"{args.name}\" entry into", file=sys.stderr)
        print(f"# an existing \"mcpServers\" block if you already have one. Then Cmd+Q + reopen.", file=sys.stderr)
        print(json.dumps(block, indent=2, ensure_ascii=False))

    # Non-zero exit if a required path is missing, so it's scriptable.
    return 0 if (server and workdir and navi and mcp_ok) else 2


if __name__ == "__main__":
    raise SystemExit(main())
