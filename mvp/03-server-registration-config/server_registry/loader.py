from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gateway_mvp.models import GatewayConfig, ToolDefinition, UpstreamServer
from mcp_guard.registry import GuardRegistry

from .models import RegisteredServer, RegisteredTool, ServerRegistryConfig
from .validation import validate_server_registry


def load_server_registry(path: str | Path) -> ServerRegistryConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return server_registry_from_dict(payload)


def load_gateway_config(
    server_config_path: str | Path,
    policy: GuardRegistry,
) -> GatewayConfig:
    registry_config = load_server_registry(server_config_path)
    validate_server_registry(registry_config, policy)
    return GatewayConfig(
        registry=policy,
        upstreams=tuple(_to_upstream(server) for server in registry_config.enabled_servers()),
        allowed_origins=registry_config.allowed_origins,
    )


def server_registry_from_dict(payload: dict[str, Any]) -> ServerRegistryConfig:
    servers = payload.get("servers", [])
    origins = payload.get("allowed_origins", [])
    if not isinstance(servers, list):
        raise ValueError("servers must be a list")
    if not isinstance(origins, list) or not all(isinstance(origin, str) for origin in origins):
        raise ValueError("allowed_origins must be a list of strings")
    return ServerRegistryConfig(
        allowed_origins=frozenset(origins),
        servers=tuple(_server_from_dict(server) for server in servers),
    )


def _server_from_dict(payload: dict[str, Any]) -> RegisteredServer:
    if not isinstance(payload, dict):
        raise ValueError("server entries must be objects")
    tools = payload.get("tools", [])
    if not isinstance(tools, list):
        raise ValueError("server tools must be a list")
    return RegisteredServer(
        name=_required_str(payload, "name"),
        namespace=_required_str(payload, "namespace"),
        transport=_required_str(payload, "transport"),
        url=_required_str(payload, "url"),
        enabled=_optional_bool(payload, "enabled", True),
        source=_optional_str(payload, "source", "gateway"),
        tools=tuple(_tool_from_dict(tool) for tool in tools),
    )


def _tool_from_dict(payload: dict[str, Any]) -> RegisteredTool:
    if not isinstance(payload, dict):
        raise ValueError("tool entries must be objects")
    input_schema = payload.get("input_schema", {})
    if not isinstance(input_schema, dict):
        raise ValueError("tool input_schema must be an object")
    schema_hash = payload.get("schema_hash")
    if schema_hash is not None and not isinstance(schema_hash, str):
        raise ValueError("tool schema_hash must be a string")
    return RegisteredTool(
        name=_required_str(payload, "name"),
        description=_required_str(payload, "description"),
        input_schema=input_schema,
        schema_hash=schema_hash,
    )


def _to_upstream(server: RegisteredServer) -> UpstreamServer:
    return UpstreamServer(
        name=server.name,
        namespace=server.namespace,
        tools=tuple(
            ToolDefinition(
                server_name=server.name,
                namespace=server.namespace,
                name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema,
                schema_hash=tool.schema_hash,
                source=server.source,
            )
            for tool in server.tools
        ),
        transport=server.transport,
        url=server.url,
        source=server.source,
    )


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_str(payload: dict[str, Any], key: str, default: str) -> str:
    value = payload.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_bool(payload: dict[str, Any], key: str, default: bool) -> bool:
    value = payload.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value

