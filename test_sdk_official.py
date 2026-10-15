#!/usr/bin/env python3
"""Stage 3.8 Step 4: 官方 MCP Python SDK (2026-07-28) 标准 Streamable HTTP Client 测试."""
import asyncio
import sqlite3


def get_token():
    conn = sqlite3.connect('/home/hermes/mcp_servers/oauth.db')
    row = conn.execute("SELECT access_token FROM tokens ORDER BY created_at DESC LIMIT 1").fetchone()
    conn.close()
    return row[0] if row else ""


async def main():
    token = get_token()
    if not token:
        print("❌ 无 OAuth token")
        return

    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client, create_mcp_http_client

    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "https://chatgpt.com",
    }
    url = "https://mcp.hermes.toothingbeginning.com/mcp"
    http_client = create_mcp_http_client(headers=headers)

    results = []

    def check(name, ok, detail=""):
        results.append((name, ok))
        print(f"  {'✅' if ok else '❌'} {name}: {detail}")

    try:
        async with streamable_http_client(url, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                # 2026-07-28: discover (server/discover)
                try:
                    disc = await session.discover()
                    check("SDK discover", disc is not None,
                          f"resultType={getattr(disc, 'resultType', '?') if disc else 'None'}, "
                          f"supportedVersions={getattr(disc, 'supportedVersions', '?')}")
                except Exception as e:
                    check("SDK discover", False, f"{type(e).__name__}: {e}")
                    # fallback to initialize
                    try:
                        init = await session.initialize()
                        check("SDK initialize (fallback)", True,
                              f"protocolVersion={getattr(init, 'protocolVersion', '?')}")
                    except Exception as e2:
                        check("SDK initialize", False, f"{type(e2).__name__}: {e2}")

                # list_tools
                tools = await session.list_tools()
                names = [t.name for t in tools.tools]
                check("SDK tools/list", len(names) == 6, f"{len(names)} tools: {names}")

                # call hermes_health_check
                hc = await session.call_tool("hermes_health_check", {})
                txt = hc.content[0].text if hc.content else ""
                check("SDK call hermes_health_check", '"ok"' in txt or 'ok' in txt.lower(), txt[:150])

                # call hermes_system_status
                ss = await session.call_tool("hermes_system_status", {})
                stxt = ss.content[0].text if ss.content else ""
                check("SDK call hermes_system_status", 'cs_inbox' in stxt or 'health' in stxt.lower(), stxt[:150])

    except Exception as e:
        check("SDK 整体流程", False, f"{type(e).__name__}: {e}")

    print(f"\n=== 结果: {sum(1 for _, ok in results if ok)}/{len(results)} 通过 ===")
    for n, ok in results:
        if not ok:
            print(f"  ❌ {n}")


if __name__ == "__main__":
    asyncio.run(main())