from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from mcp_guard.audit import AuditEvent
from mcp_guard.models import ToolRegistration
from mcp_guard.registry import GuardRegistry


@dataclass(frozen=True)
class ToolDefinition:
    server_name: str
    namespace: str
    name: str
    description: str
    input_schema: dict[str, Any]
    schema_hash: str | None
    source: str = "gateway"

    def registration(self) -> ToolRegistration:
        return ToolRegistration(
            server_name=self.server_name,
            namespace=self.namespace,
            tool_name=self.name,
            description=self.description,
            source=self.source,
            schema_hash=self.schema_hash,
        )

    def to_mcp_tool(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass(frozen=True)
class UpstreamServer:
    name: str
    namespace: str
    tools: tuple[ToolDefinition, ...]
    transport: str = "streamable_http"
    url: str = ""
    source: str = "gateway"

    def find_tool(self, tool_name: str) -> ToolDefinition | None:
        for tool in self.tools:
            if tool.name == tool_name:
                return tool
        return None


class ToolCallClient(Protocol):
    def call_tool(
        self,
        upstream: UpstreamServer,
        tool: ToolDefinition,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Call an upstream tool and return a JSON-RPC result object."""


@dataclass(frozen=True)
class ToolListSnapshot:
    tools: tuple[ToolDefinition, ...]
    ttl_ms: int = 0
    cache_scope: str = "private"


class LiveToolsListClient(Protocol):
    def fetch(self, upstream: UpstreamServer) -> ToolListSnapshot:
        """Fetch the complete current tools/list result from an upstream."""


@dataclass(frozen=True)
class GatewayConfig:
    registry: GuardRegistry
    upstreams: tuple[UpstreamServer, ...]
    allowed_origins: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        duplicates = _duplicate_tool_names(self.upstreams)
        if duplicates:
            raise ValueError(
                "duplicate gateway tool names: " + ", ".join(sorted(duplicates))
            )

    def iter_tools(self) -> tuple[ToolDefinition, ...]:
        return tuple(tool for upstream in self.upstreams for tool in upstream.tools)

    def find_tool(self, tool_name: str) -> ToolDefinition | None:
        found = self.find_tool_owner(tool_name)
        if found is None:
            return None
        _, tool = found
        return tool

    def find_tool_owner(self, tool_name: str) -> tuple[UpstreamServer, ToolDefinition] | None:
        for upstream in self.upstreams:
            tool = upstream.find_tool(tool_name)
            if tool is not None:
                return upstream, tool
        return None


def _duplicate_tool_names(upstreams: tuple[UpstreamServer, ...]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for upstream in upstreams:
        for tool in upstream.tools:
            if tool.name in seen:
                duplicates.add(tool.name)
            seen.add(tool.name)
    return duplicates


@dataclass(frozen=True)
class GatewayResponse:
    status_code: int
    body: dict[str, Any]
    headers: dict[str, str] = field(
        default_factory=lambda: {"content-type": "application/json"}
    )
    audit_events: tuple[AuditEvent, ...] = ()
    edge_findings: tuple[str, ...] = ()

    def body_json(self) -> str:
        return json.dumps(self.body, ensure_ascii=False, indent=2)

