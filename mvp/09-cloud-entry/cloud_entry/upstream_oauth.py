"""C3 per-user mode: the gateway is an OAuth client of each per-user upstream server.

For servers that handle a person's own data, each gateway user links their
own upstream account. The gateway discovers the upstream authorization server
through Protected Resource Metadata (RFC 9728) and RFC 8414 / OpenID metadata,
identifies itself with a pre-registered client, its own Client ID Metadata
Document, or Dynamic Client Registration (MCP priority order), runs the
authorization code flow with S256 PKCE and the RFC 8707 ``resource``
parameter, checks the RFC 9207 ``iss`` parameter, and stores the tokens per
(gateway user, server). Upstream tokens never reach the client.
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlencode, urlsplit

from decision_controls.token_custody import SecretStore
from mcp_guard.audit import AuditRecorder, audit_event

# The gateway user a request is served for; set by the adapter per request.
current_user: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mcp_guard_current_user", default=None
)

_PENDING_SECONDS = 600
_REFRESH_MARGIN_SECONDS = 60
_MAX_BODY = 256_000
# AWS Secrets Manager: no more than one PutSecretValue every 10 minutes per secret.
_MIN_WRITE_SECONDS = 600
_SECRET_PREFIX = re.compile(r"[A-Za-z0-9/_+=.@-]{1,200}")


class UpstreamAuthError(ValueError):
    """Upstream authorization failed; a ValueError so callers fail closed."""


@dataclass(frozen=True)
class PerUserServer:
    name: str
    url: str
    client_id: str = ""
    client_secret_ref: str = ""
    authorization_server: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise UpstreamAuthError("upstream authorization endpoints must not redirect")


class TokenStore(Protocol):
    """Where per-user upstream tokens and registered upstream clients live."""

    def token(self, key: str) -> dict[str, Any] | None: ...
    def set_token(self, key: str, record: dict[str, Any]) -> None: ...
    def forget_token(self, key: str) -> None: ...
    def client(self, issuer: str) -> dict[str, Any] | None: ...
    def set_client(self, issuer: str, client: dict[str, Any]) -> None: ...
    def flush(self) -> None: ...


class UpstreamTokenStore:
    """Per-user upstream tokens and registered clients, saved by atomic replace.

    Tokens are stored unencrypted with owner-only file permissions. For a
    deployment, ``SecretManagerTokenStore`` keeps them in a secret manager.
    """

    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path else None
        self.lock = threading.Lock()
        self.tokens: dict[str, dict[str, Any]] = {}
        self.clients: dict[str, dict[str, Any]] = {}
        if self._path and self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            self.tokens = dict(payload.get("tokens", {}))
            self.clients = dict(payload.get("clients", {}))

    def token(self, key: str) -> dict[str, Any] | None:
        with self.lock:
            record = self.tokens.get(key)
            return dict(record) if record else None

    def set_token(self, key: str, record: dict[str, Any]) -> None:
        with self.lock:
            self.tokens[key] = record
            self.save()

    def forget_token(self, key: str) -> None:
        with self.lock:
            self.tokens.pop(key, None)
            self.save()

    def client(self, issuer: str) -> dict[str, Any] | None:
        with self.lock:
            return self.clients.get(issuer)

    def set_client(self, issuer: str, client: dict[str, Any]) -> None:
        with self.lock:
            self.clients[issuer] = client
            self.save()

    def flush(self) -> None:
        """Every change is already saved."""

    def save(self) -> None:
        """Call with ``lock`` held."""
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        temporary.write_text(json.dumps({"tokens": self.tokens, "clients": self.clients}),
                             encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self._path)


class SecretManagerTokenStore:
    """Per-user upstream tokens in a secret manager, one secret per entry.

    ``backend`` is an MVP 8 ``SecretStore`` whose ``get`` accepts the key given
    to ``put`` and raises ``KeyError`` for a missing secret, such as
    ``AwsSecretsManagerStore``. Secret names are hashes, so user names and
    issuers do not appear in them.

    When a refresh token exists, the access token stays in memory only and the
    stored record holds the refresh token and client data. Writes to one secret
    are at least ``min_write_seconds`` apart (AWS asks for no more than one
    PutSecretValue every 10 minutes per secret): a newer value waits in memory
    and is written by the first store call after the interval, or by
    ``flush()``. If the process stops first, the stored refresh token may have
    been rotated away and the user links the account again. A forgotten entry
    is overwritten with ``{}`` instead of deleted, because a deleted AWS secret
    name stays reserved during its recovery window. The cache assumes one
    gateway instance writes these secrets.
    """

    def __init__(
        self,
        backend: SecretStore,
        prefix: str = "mcp-guard/upstream",
        min_write_seconds: float = _MIN_WRITE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        prefix = prefix.strip("/")
        if not _SECRET_PREFIX.fullmatch(prefix):
            raise ValueError("secret prefix may use letters, digits, and /_+=.@- only")
        self._backend = backend
        self._prefix = prefix
        self._min_write = min_write_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any] | None] = {}
        self._stored: dict[str, str | None] = {}  # value in the backend; None if absent
        self._written_at: dict[str, float] = {}
        self._pending: dict[str, str] = {}

    def token(self, key: str) -> dict[str, Any] | None:
        return self._read(self._name("token", key))

    def set_token(self, key: str, record: dict[str, Any]) -> None:
        stored = record
        if record.get("refresh_token"):
            stored = {k: v for k, v in record.items() if k not in ("access_token", "expires_at")}
        self._write(self._name("token", key), record, stored)

    def forget_token(self, key: str) -> None:
        self._write(self._name("token", key), None, None)

    def client(self, issuer: str) -> dict[str, Any] | None:
        return self._read(self._name("client", issuer))

    def set_client(self, issuer: str, client: dict[str, Any]) -> None:
        self._write(self._name("client", issuer), client, client)

    def flush(self) -> None:
        """Write every waiting value now, e.g. at shutdown."""
        with self._lock:
            for name in list(self._pending):
                self._put(name, self._pending[name])

    def _name(self, kind: str, key: str) -> str:
        return f"{self._prefix}/{kind}/{hashlib.sha256(key.encode('utf-8')).hexdigest()[:40]}"

    def _read(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            self._flush_due()
            if name not in self._cache:
                self._load(name)
            record = self._cache[name]
            return dict(record) if record else None

    def _load(self, name: str) -> None:
        """Call with the lock held: learn what the backend holds for ``name``."""
        try:
            raw: str | None = self._backend.get(name)
            record = json.loads(raw) if raw else None
        except KeyError:
            raw, record = None, None
        except (OSError, ValueError) as error:
            raise UpstreamAuthError(f"secret manager read failed: {error}") from error
        if record is not None and not isinstance(record, dict):
            raise UpstreamAuthError(f"secret {name} is not a JSON object")
        self._stored[name] = raw
        self._cache[name] = record or None

    def _write(self, name: str, record: dict[str, Any] | None,
               stored: dict[str, Any] | None) -> None:
        value = json.dumps(stored, sort_keys=True) if stored else "{}"
        with self._lock:
            self._flush_due()
            if name not in self._stored:
                self._load(name)  # skip writes the backend already holds
            self._cache[name] = dict(record) if record else None
            current = self._stored[name]
            if current == value or (value == "{}" and current is None):
                self._pending.pop(name, None)  # the backend already holds it
                return
            if self._clock() - self._written_at.get(name, float("-inf")) < self._min_write:
                self._pending[name] = value
                return
            self._put(name, value)

    def _flush_due(self) -> None:
        now = self._clock()
        for name in [n for n in self._pending if now - self._written_at.get(n, float("-inf"))
                     >= self._min_write]:
            self._put(name, self._pending[name])

    def _put(self, name: str, value: str) -> None:
        """Call with the lock held; a failed write stays pending and is retried."""
        self._pending[name] = value
        try:
            self._backend.put(name, value)
        except (OSError, ValueError) as error:
            raise UpstreamAuthError(f"secret manager write failed: {error}") from error
        self._stored[name] = value
        self._written_at[name] = self._clock()
        del self._pending[name]


class UpstreamOAuth:
    def __init__(
        self,
        gateway_issuer: str,
        servers: dict[str, PerUserServer],
        store: TokenStore,
        resolve_secret: Callable[[str], str],
        clock: Callable[[], float] = time.time,
        allow_insecure_loopback: bool = False,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._audit = audit or AuditRecorder()
        self._issuer = gateway_issuer.rstrip("/")
        self._servers = dict(servers)
        self._store = store
        self._resolve_secret = resolve_secret
        self._clock = clock
        self._insecure_loopback = allow_insecure_loopback
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._pending: dict[str, dict[str, Any]] = {}
        self._pending_lock = threading.Lock()

    @property
    def callback_url(self) -> str:
        return f"{self._issuer}/upstream/callback"

    @property
    def metadata_url(self) -> str:
        return f"{self._issuer}/oauth/client-metadata.json"

    def server_names(self) -> tuple[str, ...]:
        return tuple(self._servers)

    def client_metadata_document(self) -> dict[str, Any]:
        """The gateway's own CIMD, used when an upstream server supports CIMD."""
        return {
            "client_id": self.metadata_url,
            "client_name": "mcp-guard gateway",
            "redirect_uris": [self.callback_url],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }

    # Token lookup -----------------------------------------------------------

    def missing(self, user: str, names: tuple[str, ...] | None = None) -> list[str]:
        return [n for n in (names or self.server_names()) if self.access_token(user, n) is None]

    def access_token(self, user: str, server: str) -> str | None:
        key = f"{user}|{server}"
        record = self._store.token(key)
        if not record:
            return None
        if record.get("expires_at", 0) > self._clock() + _REFRESH_MARGIN_SECONDS:
            return record["access_token"]
        if not record.get("refresh_token"):
            self._forget(key, "expired without a refresh token")
            return None
        try:
            tokens = self._token_request(record["token_endpoint"], record, {
                "grant_type": "refresh_token",
                "refresh_token": record["refresh_token"],
                "resource": self._servers[server].url,
            })
        except (OSError, ValueError) as error:
            self._forget(key, f"refresh failed: {error}")  # the user must link again
            return None
        self._remember(key, record, tokens)
        return tokens["access_token"]

    def headers_for(self, server: str) -> dict[str, str]:
        user = current_user.get()
        if user is None:
            return {}  # background work such as list watchers runs unauthenticated
        token = self.access_token(user, server)
        if token is None:
            raise UpstreamAuthError(f"user has not linked upstream server {server}")
        return {"authorization": f"Bearer {token}"}

    # Authorization flow -----------------------------------------------------

    def begin(self, user: str, server: str, chain: dict[str, Any]) -> str:
        """Return the upstream authorization URL to send the user's browser to."""
        config = self._servers[server]
        metadata = self._authorization_server(config)
        client = self._client_for(config, metadata)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
        state = secrets.token_urlsafe(24)
        with self._pending_lock:
            now = self._clock()
            self._pending = {k: v for k, v in self._pending.items() if v["expires"] > now}
            self._pending[state] = {
                "user": user, "server": server, "verifier": verifier, "chain": chain,
                "issuer": metadata["issuer"], "token_endpoint": metadata["token_endpoint"],
                "iss_required": bool(metadata.get("authorization_response_iss_parameter_supported")),
                "client_id": client["client_id"], "client_secret": client.get("client_secret", ""),
                "expires": now + _PENDING_SECONDS,
            }
        params = {
            "response_type": "code", "client_id": client["client_id"],
            "redirect_uri": self.callback_url, "code_challenge": challenge,
            "code_challenge_method": "S256", "state": state, "resource": config.url,
        }
        if metadata.get("_scope"):
            params["scope"] = metadata["_scope"]
        endpoint = metadata["authorization_endpoint"]
        separator = "&" if urlsplit(endpoint).query else "?"
        return endpoint + separator + urlencode(params)

    def complete(self, params: dict[str, str]) -> tuple[str, dict[str, Any]]:
        """Finish a callback; return (user, chain) for the caller to continue."""
        with self._pending_lock:
            pending = self._pending.pop(params.get("state", ""), None)
        if pending is None or pending["expires"] <= self._clock():
            raise UpstreamAuthError("upstream authorization state is unknown or expired")
        iss = params.get("iss")
        if (pending["iss_required"] and iss is None) or (iss is not None and iss != pending["issuer"]):
            raise UpstreamAuthError("upstream iss does not match its authorization server")
        if "error" in params or not params.get("code"):
            raise UpstreamAuthError(f"upstream authorization failed: {params.get('error', 'no code')}")
        tokens = self._token_request(pending["token_endpoint"], pending, {
            "grant_type": "authorization_code", "code": params["code"],
            "redirect_uri": self.callback_url, "code_verifier": pending["verifier"],
            "resource": self._servers[pending["server"]].url,
        })
        self._remember(f"{pending['user']}|{pending['server']}", pending, tokens)
        self._audit.record(audit_event(
            "upstream_linked", verdict="allow", user=pending["user"], server_name=pending["server"],
            client=str(pending["chain"].get("client_id", "")),
            details={"outcome": "success", "issuer": pending["issuer"]}))
        return pending["user"], pending["chain"]

    # Discovery and registration ----------------------------------------------

    def _authorization_server(self, config: PerUserServer) -> dict[str, Any]:
        scope = ""
        issuer = config.authorization_server
        if not issuer:
            parts = urlsplit(config.url)
            origin = f"{parts.scheme}://{parts.netloc}"
            path = parts.path.rstrip("/")
            resource = None
            for url in (f"{origin}/.well-known/oauth-protected-resource{path}",
                        f"{origin}/.well-known/oauth-protected-resource"):
                try:
                    resource = self._get_json(url)
                    break
                except (OSError, ValueError):
                    continue
            if not resource or not resource.get("authorization_servers"):
                raise UpstreamAuthError(f"{config.name}: no protected resource metadata")
            issuer = str(resource["authorization_servers"][0])
            scope = " ".join(str(s) for s in resource.get("scopes_supported", []))
        parts = urlsplit(issuer)
        origin, path = f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")
        for url in (f"{origin}/.well-known/oauth-authorization-server{path}",
                    f"{issuer.rstrip('/')}/.well-known/openid-configuration"):
            try:
                metadata = self._get_json(url)
            except (OSError, ValueError):
                continue
            if metadata.get("issuer") != issuer:
                raise UpstreamAuthError(f"{config.name}: authorization server issuer mismatch")
            if "S256" not in metadata.get("code_challenge_methods_supported", []):
                raise UpstreamAuthError(f"{config.name}: authorization server lacks S256 PKCE")
            for endpoint in ("authorization_endpoint", "token_endpoint"):
                self._check_url(str(metadata.get(endpoint, "")))
            return {**metadata, "_scope": scope}
        raise UpstreamAuthError(f"{config.name}: no authorization server metadata")

    def _client_for(self, config: PerUserServer, metadata: dict[str, Any]) -> dict[str, Any]:
        if config.client_id:  # 1. pre-registered
            secret = self._resolve_secret(config.client_secret_ref) if config.client_secret_ref else ""
            return {"client_id": config.client_id, "client_secret": secret}
        if (metadata.get("client_id_metadata_document_supported")  # 2. our CIMD
                and urlsplit(self.metadata_url).scheme == "https"):
            return {"client_id": self.metadata_url}
        issuer = metadata["issuer"]
        registered = self._store.client(issuer)
        if registered:
            return registered
        endpoint = metadata.get("registration_endpoint")  # 3. DCR
        if not endpoint:
            raise UpstreamAuthError(f"{config.name}: no way to register with the upstream server")
        self._check_url(str(endpoint))
        body = json.dumps({
            "client_name": "mcp-guard gateway", "redirect_uris": [self.callback_url],
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none", "application_type": "web",
        }).encode("utf-8")
        request = urllib.request.Request(str(endpoint), data=body, method="POST",
                                         headers={"content-type": "application/json"})
        payload = self._open_json(request)
        if not isinstance(payload.get("client_id"), str):
            raise UpstreamAuthError(f"{config.name}: registration returned no client_id")
        client = {"client_id": payload["client_id"],
                  "client_secret": str(payload.get("client_secret", ""))}
        self._store.set_client(issuer, client)  # bound to the issuer that issued it
        return client

    # HTTP helpers --------------------------------------------------------------

    def _token_request(self, endpoint: str, client: dict[str, Any], form: dict[str, str]) -> dict[str, Any]:
        headers = {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
        form = {**form, "client_id": client["client_id"]}
        if client.get("client_secret"):
            basic = base64.b64encode(f"{client['client_id']}:{client['client_secret']}".encode()).decode()
            headers["authorization"] = f"Basic {basic}"
        self._check_url(endpoint)
        request = urllib.request.Request(endpoint, data=urlencode(form).encode("ascii"),
                                         method="POST", headers=headers)
        tokens = self._open_json(request)
        if not isinstance(tokens.get("access_token"), str):
            raise UpstreamAuthError("upstream token response has no access_token")
        return tokens

    def _remember(self, key: str, source: dict[str, Any], tokens: dict[str, Any]) -> None:
        expires_in = tokens.get("expires_in")
        lifetime = expires_in if isinstance(expires_in, int) and expires_in > 0 else 3600
        record = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token") or source.get("refresh_token", ""),
            "expires_at": self._clock() + lifetime,
            "token_endpoint": source["token_endpoint"],
            "client_id": source["client_id"],
            "client_secret": source.get("client_secret", ""),
        }
        self._store.set_token(key, record)

    def _forget(self, key: str, reason: str) -> None:
        self._store.forget_token(key)
        user, _, server = key.rpartition("|")
        self._audit.record(audit_event("upstream_unlinked", user=user, server_name=server,
                                       details={"reason": reason}))

    def _get_json(self, url: str) -> dict[str, Any]:
        self._check_url(url)
        return self._open_json(urllib.request.Request(url, headers={"accept": "application/json"}))

    def _open_json(self, request: urllib.request.Request) -> dict[str, Any]:
        try:
            with self._opener.open(request, timeout=10) as response:
                raw = response.read(_MAX_BODY + 1)
        except urllib.error.HTTPError as error:
            raise UpstreamAuthError(f"upstream returned HTTP {error.code}") from error
        if len(raw) > _MAX_BODY:
            raise UpstreamAuthError("upstream response is too large")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise UpstreamAuthError("upstream response is not a JSON object")
        return payload

    def _check_url(self, url: str) -> None:
        """HTTPS to public addresses only (SSRF guard); loopback HTTP only in tests."""
        parts = urlsplit(url)
        host = parts.hostname or ""
        if self._insecure_loopback and host in ("127.0.0.1", "localhost"):
            return
        if parts.scheme != "https" or not host:
            raise UpstreamAuthError(f"upstream URL must be https: {url}")
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, parts.port or 443)}
        except OSError as error:
            raise UpstreamAuthError(f"cannot resolve {host}") from error
        for address in addresses:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
            if not ip.is_global:
                raise UpstreamAuthError(f"{host} resolves to a non-public address")
