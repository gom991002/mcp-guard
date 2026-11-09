from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    schema_hash: str | None


@dataclass(frozen=True)
class RegisteredServer:
    name: str
    namespace: str
    transport: str
    url: str
    enabled: bool
    source: str
    tools: tuple[RegisteredTool, ...]


@dataclass(frozen=True)
class ServerRegistryConfig:
    allowed_origins: frozenset[str]
    servers: tuple[RegisteredServer, ...]

    def enabled_servers(self) -> tuple[RegisteredServer, ...]:
        return tuple(server for server in self.servers if server.enabled)

