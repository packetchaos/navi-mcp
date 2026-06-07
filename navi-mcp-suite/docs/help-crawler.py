#!/usr/bin/env python3
"""
navi_help_crawler.py

Recursively walks the entire `navi` Click command tree and captures the
`--help` output of every command and subcommand, at any depth, into a single
documentation file.

How it works
------------
1. Runs `navi --help` (the root).
2. Parses the "Commands:" section to discover subcommands.
3. For each subcommand, runs `navi <cmd> --help`, parses *its* Commands
   section, and recurses — handling groups nested 3, 4, or N levels deep.
4. Writes everything to navi_documentation.txt with clear section banners and
   the exact command path that produced each block.

It is Click-aware: Click groups list their children under a "Commands:" header,
while leaf commands do not — that's how depth is detected automatically.

Usage
-----
    python3 navi_help_crawler.py
    python3 navi_help_crawler.py --base-cmd navi --out navi_documentation.txt
    python3 navi_help_crawler.py --max-depth 8 --timeout 60

If `navi` isn't on PATH, pass the full path, e.g.:
    python3 navi_help_crawler.py --base-cmd /usr/local/bin/navi
"""

import argparse
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone


def run_help(cmd_parts, timeout):
    """Run `<cmd_parts> --help` and return (returncode, stdout, stderr)."""
    full = cmd_parts + ["--help"]
    try:
        proc = subprocess.run(
            full,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"[TIMEOUT after {timeout}s running: {' '.join(full)}]"
    except FileNotFoundError:
        return 127, "", f"[NOT FOUND: {full[0]}]"
    except Exception as e:  # pragma: no cover - defensive
        return 1, "", f"[ERROR running {' '.join(full)}: {e}]"


def parse_subcommands(help_text):
    """
    Extract subcommand names from a Click `--help` output.

    Click prints a section like:

        Commands:
          enrich   Tag assets ...
          export   Export to CSV ...

    We capture the first token of each indented line under that header until
    the indentation block ends. Returns a list of subcommand names (order
    preserved). Empty list => leaf command (no subcommands).
    """
    lines = help_text.splitlines()
    subs = []
    in_cmds = False

    # Match the "Commands:" header (Click sometimes localizes/varies spacing).
    header_re = re.compile(r"^\s*Commands:\s*$")
    # An entry line: leading whitespace, then a command token (letters, digits,
    # dash, underscore), then whitespace or end of line.
    entry_re = re.compile(r"^\s+([A-Za-z0-9][A-Za-z0-9_-]*)\b")
    # Another section header (e.g. "Options:") ends the Commands block.
    other_header_re = re.compile(r"^\S.*:\s*$")

    for line in lines:
        if not in_cmds:
            if header_re.match(line):
                in_cmds = True
            continue

        # We're inside the Commands block.
        if line.strip() == "":
            # Blank line: Click may have blank separators; keep scanning but
            # a blank line typically still sits inside the block. We continue.
            continue

        # A new top-level header (no leading space, ends with ':') ends it.
        if other_header_re.match(line) and not line.startswith((" ", "\t")):
            break

        m = entry_re.match(line)
        if m:
            name = m.group(1)
            if name not in subs:
                subs.append(name)
        else:
            # Indented continuation of a previous command's description, or
            # something unexpected — skip it.
            continue

    return subs


def crawl(base_parts, out, max_depth, timeout, stats):
    """
    Depth-first walk. `base_parts` is the command path as a list, e.g.
    ['navi', 'enrich', 'tag']. Writes each node's help to `out`.
    """
    stack = [base_parts]
    seen = set()

    while stack:
        parts = stack.pop()
        key = tuple(parts)
        if key in seen:
            continue
        seen.add(key)

        depth = len(parts) - len(base_parts)
        path_str = " ".join(parts)

        rc, stdout, stderr = run_help(parts, timeout)
        stats["count"] += 1
        if rc not in (0,):
            stats["errors"] += 1

        banner = "=" * 100
        out.write(f"\n{banner}\n")
        out.write(f"COMMAND: {path_str} --help\n")
        out.write(f"DEPTH:   {depth}\n")
        out.write(f"EXIT:    {rc}\n")
        out.write(f"{banner}\n\n")
        if stdout:
            out.write(stdout)
            if not stdout.endswith("\n"):
                out.write("\n")
        if stderr.strip():
            out.write("\n--- STDERR ---\n")
            out.write(stderr)
            if not stderr.endswith("\n"):
                out.write("\n")
        out.flush()

        print(f"[{stats['count']:3d}] depth={depth} exit={rc}  {path_str} --help")

        if depth >= max_depth:
            print(f"      (max-depth {max_depth} reached; not descending)")
            continue

        subs = parse_subcommands(stdout)
        # Push in reverse so they pop in listed order (nice, readable output).
        for name in reversed(subs):
            stack.append(parts + [name])

    return seen


def main():
    ap = argparse.ArgumentParser(
        description="Recursively capture `--help` for an entire Click CLI tree."
    )
    ap.add_argument(
        "--base-cmd",
        default="navi",
        help="Root command (name on PATH or full path). Default: navi",
    )
    ap.add_argument(
        "--out",
        default="navi_documentation.txt",
        help="Output file. Default: navi_documentation.txt",
    )
    ap.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum subcommand depth to descend. Default: 10",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-command timeout in seconds. Default: 60",
    )
    args = ap.parse_args()

    # Resolve the base command into argv parts (supports things like
    # "python -m navi" if ever needed).
    base_parts = shlex.split(args.base_cmd)

    # Sanity check the executable exists (only if it's a bare command).
    exe = base_parts[0]
    if shutil.which(exe) is None and not exe.startswith(("/", "./", "../")):
        print(
            f"WARNING: '{exe}' not found on PATH. The crawler will still try, "
            f"but you may want --base-cmd /full/path/to/navi.",
            file=sys.stderr,
        )

    stats = {"count": 0, "errors": 0}
    start = time.time()

    with open(args.out, "w", encoding="utf-8") as out:
        header = (
            f"navi CLI documentation — recursive --help dump\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"Base command: {args.base_cmd}\n"
            f"Max depth: {args.max_depth}  Timeout: {args.timeout}s\n"
        )
        out.write(header)
        print(header)

        crawl(base_parts, out, args.max_depth, args.timeout, stats)

        elapsed = time.time() - start
        footer = (
            f"\n{'=' * 100}\n"
            f"DONE. {stats['count']} commands captured "
            f"({stats['errors']} non-zero exits) in {elapsed:.1f}s.\n"
        )
        out.write(footer)
        print(footer)


if __name__ == "__main__":
    main()
