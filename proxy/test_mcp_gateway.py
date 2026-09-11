"""Minimal local MCP client for proxy/mcp_gateway.py.

Launches mcp_gateway.py as a stdio subprocess (the same way Claude
Desktop would, per an MCP server config), lists its tools, and calls
"calculator" and "docs" once each — printing exactly what comes back,
so the gateway's clean-state and mutated-state behavior can be checked
by eye without needing Claude Desktop.

Assumes calculator_server (:8001) and docs_server (:8002) are already
running; the gateway subprocess talks to them, same as the other
attack/demo scripts in this repo.

Run standalone:

    python proxy/test_mcp_gateway.py
"""

import asyncio
import sys
from pathlib import Path

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def _auto_confirm_elicitation(context, params: types.ElicitRequestParams):
    """Simulates a user always accepting MCP Guard's confirm-once-per-
    session prompt, so this script can exercise the real call path
    (including the permission gate) without a human in the loop."""
    print(f"[client] elicitation request: {params.message!r} -> auto-accepting")
    return types.ElicitResult(action="accept", content={"confirm": True})


def _print_result(result: types.CallToolResult):
    print("isError:", result.isError)
    for block in result.content:
        print(" ", getattr(block, "text", block))


async def main():
    gateway_path = str(Path(__file__).parent / "mcp_gateway.py")
    server_params = StdioServerParameters(command=sys.executable, args=[gateway_path])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write, elicitation_callback=_auto_confirm_elicitation) as session:
            await session.initialize()

            print("=" * 70)
            print("TOOLS")
            print("=" * 70)
            tools = await session.list_tools()
            for tool in tools.tools:
                print(f"\n- {tool.name}")
                print(f"    {tool.description}")

            print("\n" + "=" * 70)
            print("CALL: calculator(a=5, b=3, operation='add')")
            print("=" * 70)
            result = await session.call_tool("calculator", {"a": 5, "b": 3, "operation": "add"})
            _print_result(result)

            print("\n" + "=" * 70)
            print("CALL: docs(q='revenue')")
            print("=" * 70)
            result = await session.call_tool("docs", {"q": "revenue"})
            _print_result(result)


if __name__ == "__main__":
    asyncio.run(main())
