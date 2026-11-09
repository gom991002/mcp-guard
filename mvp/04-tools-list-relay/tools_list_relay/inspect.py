"""Read-only preview of actual upstream definitions for operator review."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from gateway_mvp.models import UpstreamServer
from mcp_guard.admission import ServerIdentity, Stage0Admission
from mcp_guard.models import Verdict
from mcp_guard.registry import GuardRegistry
from server_registry.loader import load_server_registry

from .client import HttpToolsListClient


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview live MCP tools for manual approval.")
    parser.add_argument("--policy", default="configs/example-policy.json")
    parser.add_argument("--servers", default="mvp/03-server-registration-config/configs/servers.json")
    parser.add_argument("--server", required=True)
    args = parser.parse_args(argv)

    policy = GuardRegistry.from_path(Path(args.policy))
    config = load_server_registry(Path(args.servers))
    server = next((item for item in config.enabled_servers() if item.name == args.server), None)
    if server is None:
        parser.error("server must be enabled and present in --servers")
    decision = Stage0Admission().check(ServerIdentity(
        server.name, server.namespace, server.transport, server.url, server.source,
    ), policy)
    if decision.verdict != Verdict.ALLOW:
        parser.error(decision.findings[0].message)
    upstream = UpstreamServer(
        server.name, server.namespace, (),
        transport=server.transport, url=server.url, source=server.source,
    )
    snapshot = HttpToolsListClient().fetch(upstream)
    print(json.dumps({
        "server": server.name,
        "tools": [{
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "schema_hash": tool.schema_hash,
        } for tool in snapshot.tools],
        "approved_schema_hashes": {
            f"{server.name}:{tool.name}": tool.schema_hash for tool in snapshot.tools
        },
    }, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
