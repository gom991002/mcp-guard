"""C3: the gateway alone holds upstream credentials.

Credentials are configured as secret references (``env:NAME`` or
``file:/path``), never as literal values, and are resolved at request time.
Client tokens are never forwarded upstream: MCP 2026-07-28 forbids an MCP
server from transiting tokens it did not issue for the upstream.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from gateway_mvp.models import UpstreamServer

_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
# Headers the gateway itself controls on upstream requests.
_RESERVED = frozenset({
    "content-type", "accept", "content-length", "host",
    "mcp-protocol-version", "mcp-method", "mcp-name",
})


@dataclass(frozen=True)
class UpstreamCredential:
    header: str
    secret_ref: str
    scheme: str = ""

    def __post_init__(self) -> None:
        if not _HEADER_NAME.fullmatch(self.header) or self.header.lower() in _RESERVED:
            raise ValueError(f"credential header is not allowed: {self.header!r}")
        if not self.secret_ref.startswith(("env:", "file:")):
            raise ValueError("secret_ref must be env:NAME or file:PATH, never a literal secret")
        if self.scheme and not _HEADER_NAME.fullmatch(self.scheme):
            raise ValueError("credential scheme is invalid")


class SecretUnavailable(ValueError):
    """A ValueError, so upstream clients treat it as a failed call (fail closed)."""


def resolve_secret(reference: str) -> str:
    kind, _, target = reference.partition(":")
    if kind == "env":
        value = os.environ.get(target)
        if not value:
            raise SecretUnavailable(f"environment variable {target} is not set")
    elif kind == "file":
        value = Path(target).read_text(encoding="utf-8").strip()
        if not value:
            raise SecretUnavailable(f"secret file {target} is empty")
    else:
        raise SecretUnavailable("unsupported secret reference")
    if "\r" in value or "\n" in value:
        raise SecretUnavailable("secret must not contain line breaks")
    return value


class UpstreamCredentials:
    """Per server: ``"mode": "shared"`` (one gateway-held credential, default) or
    ``"mode": "per_user"`` (each gateway user links their own upstream account).

    Use per_user for servers that handle a person's own data, shared for
    common tools (decision: C3 chosen per server).
    """

    def __init__(
        self,
        credentials: dict[str, UpstreamCredential] | None = None,
        per_user: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self._credentials = dict(credentials or {})
        self._per_user = dict(per_user or {})
        self._oauth: Any = None

    @classmethod
    def from_path(cls, path: str | Path) -> "UpstreamCredentials":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        servers = payload.get("servers", {})
        if not isinstance(servers, dict):
            raise ValueError("credentials file must contain a 'servers' object")
        shared, per_user = {}, {}
        for name, entry in servers.items():
            mode = entry.get("mode", "shared")
            if mode == "per_user":
                if entry.get("client_secret_ref") and not str(entry["client_secret_ref"]).startswith(("env:", "file:")):
                    raise ValueError("client_secret_ref must be env:NAME or file:PATH")
                per_user[name] = {k: str(entry.get(k, "")) for k in
                                  ("client_id", "client_secret_ref", "authorization_server")}
            elif mode == "shared":
                shared[name] = UpstreamCredential(
                    header=str(entry["header"]),
                    secret_ref=str(entry["secret_ref"]),
                    scheme=str(entry.get("scheme", "")),
                )
            else:
                raise ValueError(f"unknown credential mode for {name}: {mode!r}")
        return cls(shared, per_user)

    def per_user_names(self) -> frozenset[str]:
        return frozenset(self._per_user)

    def per_user_servers(self, upstreams: tuple[UpstreamServer, ...]) -> dict[str, Any]:
        """Combine per-user entries with the approved upstream URLs."""
        from .upstream_oauth import PerUserServer

        by_name = {upstream.name: upstream for upstream in upstreams}
        missing = set(self._per_user) - set(by_name)
        if missing:
            raise ValueError(f"per_user servers are not enabled in servers.json: {sorted(missing)}")
        return {name: PerUserServer(name=name, url=by_name[name].url, **entry)
                for name, entry in self._per_user.items()}

    def attach(self, oauth: Any) -> None:
        """Attach the UpstreamOAuth manager that holds per-user tokens."""
        self._oauth = oauth

    def headers_for(self, upstream: UpstreamServer) -> dict[str, str]:
        """Headers to add to an upstream request; raises SecretUnavailable if missing."""
        if upstream.name in self._per_user:
            if self._oauth is None:
                raise SecretUnavailable(f"{upstream.name} is per_user but no OAuth manager is attached")
            return self._oauth.headers_for(upstream.name)
        credential = self._credentials.get(upstream.name)
        if credential is None:
            return {}
        secret = resolve_secret(credential.secret_ref)
        value = f"{credential.scheme} {secret}" if credential.scheme else secret
        return {credential.header: value}


class PerUserListClient:
    """Wrap a tools/list client so per-user upstream lists are never cached.

    The live catalog caches lists an upstream marks public; a list fetched
    with one user's token must not be served to another user.
    """

    def __init__(self, inner: Any, per_user_names: frozenset[str]) -> None:
        self._inner = inner
        self._per_user = per_user_names

    def fetch(self, upstream: UpstreamServer) -> Any:
        snapshot = self._inner.fetch(upstream)
        if upstream.name in self._per_user:
            return replace(snapshot, cache_scope="private")
        return snapshot

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)
