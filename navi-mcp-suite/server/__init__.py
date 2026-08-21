"""navi-mcp — an MCP server wrapping the Tenable `navi` CLI.

Installed layout (see pyproject.toml for the build mapping):

    navi_mcp/server.py              the server (repo: navi-mcp-suite/server/server.py)
    navi_mcp/resources/skills/**    the skill tree (repo: navi-mcp-suite/skills/**)

Entry points:

    navi-mcp                        console script -> navi_mcp.server:main
    python -m navi_mcp              equivalent, via __main__.py

`main()` is intentionally NOT imported here. Importing it would pull in
mcp.server.fastmcp at package-import time, so `import navi_mcp` would fail on a
broken SDK install with a traceback pointing at this file instead of at the
real import site. Keep this module dependency-free.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
