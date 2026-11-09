from __future__ import annotations

import json

from rule_sets.waf_gateway_rules import PROTOCOL_VERSION, GatewayRequest

from .catalog import sample_gateway_config
from .gateway import RemoteMcpGateway


def main() -> int:
    gateway = RemoteMcpGateway(sample_gateway_config())
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            }
        },
    }
    request = GatewayRequest(
        method="POST",
        content_type="application/json",
        body=json.dumps(body).encode("utf-8"),
        headers={
            "Origin": "https://chat.example",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": "tools/list",
        },
    )
    response = gateway.handle(request, session_id="demo-session")
    print(response.body_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

