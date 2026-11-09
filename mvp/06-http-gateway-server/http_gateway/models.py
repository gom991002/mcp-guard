from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HttpRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes = b""
    client_ip: str = ""


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

