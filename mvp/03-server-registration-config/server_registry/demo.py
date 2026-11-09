from __future__ import annotations

import json
from pathlib import Path

from mcp_guard.registry import GuardRegistry

from .loader import load_gateway_config


def main() -> int:
    here = Path(__file__).resolve().parents[1]
    root = here.parents[1]
    policy = GuardRegistry.from_path(root / "configs" / "example-policy.json")
    config = load_gateway_config(here / "configs" / "servers.json", policy)
    result = {
        "allowed_origins": sorted(config.allowed_origins),
        "servers": [
            {
                "name": upstream.name,
                "tools": [tool.name for tool in upstream.tools],
            }
            for upstream in config.upstreams
        ],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

