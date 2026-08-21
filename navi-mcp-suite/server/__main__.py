"""Allow `python -m navi_mcp` alongside the `navi-mcp` console script.

Historical note: Claude Desktop configs from before the packaging change
launched this server with `python -m navi_mcp`. That broke with

    No module named navi_mcp.__main__; 'navi_mcp' is a package and cannot be
    directly executed

because the installed package had no __main__.py. This file makes that
invocation a supported entry point rather than an accident.
"""

from navi_mcp.server import main

if __name__ == "__main__":
    main()
