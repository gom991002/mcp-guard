"""Write the demo gateway configuration from demo_upstream's tool definitions.

python mvp/09-cloud-entry/deploy/demo/make_config.py

Writes config/policy.json (for the signed-in gateway, with the M4 value policy),
config/policy-open.json (the same without it: value approval needs sign-in) and
config/servers.json beside this file. Every demo
tool is approved with the hash of its schema, including the poisoned get_time:
the demo shows that an approved definition is still held when its description
orders the model to call another tool first (B_DESCRIPTION_CROSS_TOOL_DIRECTIVE, D6-51). users.json is made by the
compose service at start with the demo password, never stored here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[3] / "src"))

from demo_upstream import SERVERS  # noqa: E402
from mcp_guard.definitions import schema_hash  # noqa: E402

# Each gateway shares its network with its own demo upstream: stage 0 accepts plain
# http only on loopback, any other upstream must be HTTPS.
UPSTREAM = "http://127.0.0.1:9000"


def build() -> tuple[dict, dict]:
    servers = {"allowed_origins": ["http://localhost:8080", "http://localhost:8081"], "servers": [
        {"name": name, "namespace": "demo", "transport": "streamable_http", "url": f"{UPSTREAM}/{name}/mcp",
         "enabled": True, "source": "gateway",
         "tools": [{"name": t["name"], "description": t["description"], "schema_hash": schema_hash(t["inputSchema"]),
                    "input_schema": t["inputSchema"]} for t in tools]}
        for name, tools in SERVERS.items()]}
    policy = {
        "trusted_namespaces": ["demo"], "trusted_registry_publishers": [],
        "protected_tool_names": ["send_email"], "suspicious_phrases": ["ignore previous instructions"],
        "registered_servers": sorted(SERVERS), "trusted_sources": ["gateway"],
        "approved_schema_hashes": {f"{name}:{t['name']}": schema_hash(t["inputSchema"])
                                   for name, tools in SERVERS.items() for t in tools},
        "external_send_tools": ["mail:send_email"],
        "m4_value_policy": {"internal_domains": ["company.example"], "allowed_url_hosts": []},
    }
    return policy, servers


def main() -> int:
    policy, servers = build()
    folder = HERE / "config"
    folder.mkdir(exist_ok=True)
    open_policy = {k: v for k, v in policy.items() if k != "m4_value_policy"}
    for name, data in (("policy.json", policy), ("policy-open.json", open_policy), ("servers.json", servers)):
        (folder / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {folder}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
