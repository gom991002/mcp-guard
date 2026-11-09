from __future__ import annotations

from mcp_guard.registry import GuardRegistry

from .models import RegisteredServer, ServerRegistryConfig


def validate_server_registry(
    config: ServerRegistryConfig,
    policy: GuardRegistry,
) -> None:
    enabled_servers = config.enabled_servers()
    _require_unique_server_names(enabled_servers)
    _require_registered_servers(enabled_servers, policy)
    for server in enabled_servers:
        _require_unique_tool_names(server)
        _require_http_url(server)
    _require_unique_exposed_tool_names(enabled_servers)


def _require_unique_server_names(servers: tuple[RegisteredServer, ...]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for server in servers:
        if server.name in seen:
            duplicates.add(server.name)
        seen.add(server.name)
    if duplicates:
        raise ValueError(f"duplicate server names: {', '.join(sorted(duplicates))}")


def _require_registered_servers(
    servers: tuple[RegisteredServer, ...],
    policy: GuardRegistry,
) -> None:
    unknown = sorted(
        server.name for server in servers if server.name not in policy.registered_servers
    )
    if unknown:
        raise ValueError(f"servers are not in policy registered_servers: {', '.join(unknown)}")


def _require_unique_tool_names(server: RegisteredServer) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for tool in server.tools:
        if tool.name in seen:
            duplicates.add(tool.name)
        seen.add(tool.name)
    if duplicates:
        raise ValueError(
            f"{server.name} has duplicate tool names: {', '.join(sorted(duplicates))}"
        )


def _require_unique_exposed_tool_names(servers: tuple[RegisteredServer, ...]) -> None:
    owners: dict[str, list[str]] = {}
    for server in servers:
        for tool in server.tools:
            owners.setdefault(tool.name, []).append(server.name)

    duplicates = {
        tool_name: server_names
        for tool_name, server_names in owners.items()
        if len(server_names) > 1
    }
    if duplicates:
        details = [
            f"{tool_name} ({', '.join(sorted(server_names))})"
            for tool_name, server_names in sorted(duplicates.items())
        ]
        raise ValueError(f"duplicate exposed tool names: {', '.join(details)}")


def _require_http_url(server: RegisteredServer) -> None:
    if server.transport != "streamable_http":
        raise ValueError(f"{server.name} uses unsupported transport: {server.transport}")
    if not server.url.startswith(("https://", "http://")):
        raise ValueError(f"{server.name} url must be http or https")

