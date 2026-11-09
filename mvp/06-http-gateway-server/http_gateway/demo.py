from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from injection_throttle import RequestRateThrottle
from mcp_guard.registry import GuardRegistry
from rule_sets.waf_gateway_rules import PROTOCOL_VERSION
from server_registry.loader import load_gateway_config

from .adapter import HttpGatewayAdapter
from .models import HttpRequest


def main() -> int:
    here = Path(__file__).resolve().parents[1]
    root = here.parents[1]
    policy = GuardRegistry.from_path(root / "configs" / "example-policy.json")
    config = load_gateway_config(
        root / "mvp" / "03-server-registration-config" / "configs" / "servers.json",
        policy,
    )
    adapter = HttpGatewayAdapter(config, throttle=RequestRateThrottle())
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
    response = adapter.handle(
        HttpRequest(
            method="POST",
            path="/mcp",
            headers={
                "content-type": "application/json",
                "origin": "https://chat.example",
                "mcp-protocol-version": PROTOCOL_VERSION,
                "mcp-method": "tools/list",
                "mcp-guard-session-id": "demo-session",
            },
            body=json.dumps(body).encode("utf-8"),
            client_ip="203.0.113.10",
        ),
        now=datetime(2026, 10, 30, tzinfo=UTC),
    )
    print(
        json.dumps(
            {
                "status_code": response.status_code,
                "headers": response.headers,
                "body": json.loads(response.body.decode("utf-8")),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

