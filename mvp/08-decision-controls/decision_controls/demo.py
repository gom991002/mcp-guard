from __future__ import annotations

import json
from datetime import UTC, datetime

from .activation import decide_activation
from .token_custody import GatewayTokenIssuer


def main() -> int:
    issuer = GatewayTokenIssuer(b"demo-signing-key-32-bytes-minimum", ttl_seconds=300)
    token = issuer.issue(
        "user-1",
        ("tools/list", "tools/call"),
        now=datetime(2026, 10, 30, tzinfo=UTC),
    )
    activation = decide_activation(
        enable_guard=True,
        gateway_url="https://guard.example/mcp",
        origin_server_url="https://mcp.company.example/mcp",
    )
    print(
        json.dumps(
            {
                "gateway_token_subject": token.subject,
                "gateway_token_scopes": list(token.scopes),
                "activation": {
                    "mode": activation.mode.value,
                    "target_url": activation.target_url,
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

