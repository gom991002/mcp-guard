"""C2: minimal OAuth 2.1 authorization server and resource-server check.

The gateway is its own authorization server so that it needs no external
identity provider: Protected Resource Metadata (RFC 9728), authorization server
metadata (RFC 8414), Client ID Metadata Documents from allow-listed hosts and
Dynamic Client Registration (RFC 7591) for public clients, authorization code
with S256 PKCE, refresh token rotation, and the RFC 9207 ``iss`` response
parameter. Access tokens are MVP 8 gateway tokens bound to this resource
(RFC 8707 audience). With per-user upstream servers, a successful sign-in
continues into each upstream authorization the user has not linked yet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit

from decision_controls.token_custody import GatewayTokenIssuer
from mcp_guard.audit import AuditRecorder, audit_event

from .upstream_oauth import UpstreamOAuth, current_user

SCOPE = "mcp"
# Claude's hosted apps (claude.ai, Desktop, mobile, Cowork); claude.com may replace it.
# ChatGPT uses its stable redirect when the server returns RFC 9207 ``iss`` (this one does).
HOSTED_CALLBACKS = frozenset({
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
})
# ChatGPT's per-server redirect, used when it does not pick the stable one.
_CHATGPT_CALLBACK = re.compile(r"https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]{1,128}")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})
_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
_PKCE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_MAX_CLIENTS = 10_000
_MAX_REDIRECT_URIS = 10
_MAX_CIMD_BYTES = 64_000
# Claude, ChatGPT and Codex publish their Client ID Metadata Documents on these hosts.
CIMD_HOSTS = frozenset({"claude.ai", "claude.com", "chatgpt.com"})


@dataclass(frozen=True)
class OAuthResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass(frozen=True)
class OAuthSettings:
    """``issuer`` is the public origin, e.g. https://mcp.example.com."""

    issuer: str
    access_token_seconds: int = 3600
    refresh_token_seconds: int = 30 * 86400
    code_seconds: int = 60
    login_form_seconds: int = 600
    extra_redirect_uris: frozenset[str] = frozenset()
    cimd_hosts: frozenset[str] = CIMD_HOSTS

    def __post_init__(self) -> None:
        parts = urlsplit(self.issuer)
        local = parts.hostname in _LOOPBACK_HOSTS
        if parts.scheme != "https" and not (parts.scheme == "http" and local):
            raise ValueError("issuer must be an https URL (http only for localhost)")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("issuer must be an origin without path, query, or fragment")
        object.__setattr__(self, "issuer", self.issuer.rstrip("/"))

    @property
    def resource(self) -> str:
        return f"{self.issuer}/mcp"

    @property
    def resource_metadata_url(self) -> str:
        return f"{self.issuer}/.well-known/oauth-protected-resource/mcp"


class UserDirectory:
    """Users who may sign in, with PBKDF2-SHA256 password hashes."""

    def __init__(self, users: dict[str, dict[str, object]]) -> None:
        self._users = users
        # Verify a dummy hash with the same cost for unknown users, so response
        # time does not reveal which names exist.
        costs = [
            record.get("iterations") for record in users.values() if isinstance(record, dict)
        ]
        iterations = max((c for c in costs if isinstance(c, int)), default=600_000)
        self._dummy = hash_password(secrets.token_hex(16), iterations=iterations)

    @classmethod
    def from_path(cls, path: str | Path) -> "UserDirectory":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        users = payload.get("users")
        if not isinstance(users, dict):
            raise ValueError("users file must contain a 'users' object")
        return cls(users)

    def __contains__(self, username: object) -> bool:
        return isinstance(self._users.get(username), dict) if isinstance(username, str) else False

    def verify(self, username: str, password: str) -> bool:
        record = self._users.get(username)
        valid = isinstance(record, dict)
        record = record if valid else self._dummy
        try:
            salt = bytes.fromhex(str(record["salt"]))
            expected = bytes.fromhex(str(record["hash"]))
            iterations = int(record["iterations"])
        except (KeyError, TypeError, ValueError):
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected) and valid


def hash_password(password: str, iterations: int = 600_000) -> dict[str, object]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": iterations}


def load_or_create_key(path: str | Path) -> bytes:
    """Persist the signing key so tokens survive restarts."""
    key_path = Path(path)
    if key_path.exists():
        key = bytes.fromhex(key_path.read_text(encoding="ascii").strip())
        if len(key) < 32:
            raise ValueError("signing key must be at least 32 bytes")
        return key
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(key.hex())
    return key


class OAuthStateStore:
    """Registered clients and refresh-token digests, saved by atomic replace."""

    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path else None
        self.lock = threading.Lock()
        self.clients: dict[str, dict[str, object]] = {}
        self.refresh: dict[str, dict[str, object]] = {}
        if self._path and self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            self.clients = dict(payload.get("clients", {}))
            self.refresh = dict(payload.get("refresh", {}))

    def save(self) -> None:
        """Call with ``lock`` held."""
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        temporary.write_text(
            json.dumps({"clients": self.clients, "refresh": self.refresh}), encoding="utf-8"
        )
        os.replace(temporary, self._path)


class AuthorizationServer:
    def __init__(
        self,
        settings: OAuthSettings,
        users: UserDirectory,
        signing_key: bytes,
        state: OAuthStateStore | None = None,
        clock: Callable[[], datetime] | None = None,
        upstream: UpstreamOAuth | None = None,
        fetch_document: Callable[[str], tuple[bytes, str]] | None = None,
        audit: AuditRecorder | None = None,
        static_clients: dict[str, dict[str, object]] | None = None,
    ) -> None:
        """``static_clients`` are administrator-registered clients with a secret
        (``load_static_clients``), for clients that cannot use DCR or CIMD such
        as Gemini Enterprise."""
        self._static_clients = dict(static_clients or {})
        if len(signing_key) < 32:
            raise ValueError("signing key must be at least 32 bytes")
        self._settings = settings
        self._users = users
        self._audit = audit or AuditRecorder()
        self._state = state or OAuthStateStore(None)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._tokens = GatewayTokenIssuer(signing_key, ttl_seconds=settings.access_token_seconds)
        self._form_key = hmac.new(signing_key, b"mcp-guard authorize form", hashlib.sha256).digest()
        self._codes: dict[str, dict[str, object]] = {}
        self._codes_lock = threading.Lock()
        self._upstream = upstream
        self._fetch_document = fetch_document or _fetch_https_document
        self._cimd_cache: dict[str, tuple[dict[str, object], float]] = {}
        self._cimd_lock = threading.Lock()

    # Discovery ---------------------------------------------------------------

    def protected_resource_metadata(self) -> dict[str, object]:
        return {
            "resource": self._settings.resource,
            "authorization_servers": [self._settings.issuer],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_name": "mcp-guard",
        }

    def authorization_server_metadata(self) -> dict[str, object]:
        issuer = self._settings.issuer
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "registration_endpoint": f"{issuer}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            # "none" stays first: Claude and Codex pick CIMD only when it is listed.
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic",
                                                      "client_secret_post"],
            "scopes_supported": [SCOPE],
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": True,
        }

    # Routing -----------------------------------------------------------------

    def handle(
        self, method: str, path: str, query: str, headers: dict[str, str], body: bytes,
    ) -> OAuthResponse | None:
        """Answer OAuth endpoints; return None for every other path."""
        method = method.upper()
        if path in (
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ):
            return _json(200, self.protected_resource_metadata()) if method == "GET" else _not_allowed()
        if path == "/.well-known/oauth-authorization-server":
            return _json(200, self.authorization_server_metadata()) if method == "GET" else _not_allowed()
        if path == "/register":
            return self._register(body) if method == "POST" else _not_allowed()
        if path == "/authorize":
            if method == "GET":
                return self._authorize_page(dict(parse_qsl(query)))
            if method == "POST":
                return self._authorize_submit(_form(headers, body))
            return _not_allowed()
        if path == "/token":
            return self._token(_form(headers, body), headers) if method == "POST" else _not_allowed()
        if self._upstream is not None and path == "/upstream/callback" and method == "GET":
            return self._upstream_callback(dict(parse_qsl(query)))
        if self._upstream is not None and path == "/oauth/client-metadata.json" and method == "GET":
            return _json(200, self._upstream.client_metadata_document())
        return None

    # Per-user upstream accounts ----------------------------------------------

    @contextmanager
    def user_context(self, subject: str) -> Iterator[None]:
        """Make per-user upstream credentials resolve for this gateway user."""
        token = current_user.set(subject)
        try:
            yield
        finally:
            current_user.reset(token)

    def missing_upstreams(self, subject: str, names: tuple[str, ...] | None = None) -> list[str]:
        if self._upstream is None:
            return []
        known = self._upstream.server_names()
        wanted = tuple(n for n in (names or known) if n in known)
        return self._upstream.missing(subject, wanted) if wanted else []

    def step_up(self, servers: list[str]) -> OAuthResponse:
        """403 insufficient_scope: Claude re-authorizes and retries the call."""
        scope = " ".join([SCOPE, *(f"upstream:{name}" for name in servers)])
        challenge = (f'Bearer error="insufficient_scope", scope="{scope}", '
                     f'resource_metadata="{self._settings.resource_metadata_url}", '
                     'error_description="link your upstream account"')
        return _json(403, {"error": "insufficient_scope",
                           "error_description": f"link upstream accounts: {', '.join(servers)}"},
                     {"www-authenticate": challenge})

    def _upstream_callback(self, params: dict[str, str]) -> OAuthResponse:
        try:
            subject, chain = self._upstream.complete(params)
        except (OSError, ValueError) as error:
            self._audit.record(audit_event("upstream_linked", verdict="block",
                                           details={"outcome": "failure", "error": str(error)}))
            return _page(400, f"원 서버 연결에 실패했습니다: {error}")
        return self._continue_chain(subject, chain)

    def _continue_chain(self, subject: str, chain: dict[str, object]) -> OAuthResponse:
        try:
            remaining = self.missing_upstreams(subject)
        except ValueError as error:  # the upstream token store failed
            self._audit.record(audit_event(
                "credential_store_unavailable", verdict="block", user=subject,
                client=str(chain.get("client_id", "")), details={"error": str(error)}))
            return _page(503, f"원 서버 자격증명 저장소를 사용할 수 없습니다: {error}")
        if remaining:
            try:
                location = self._upstream.begin(subject, remaining[0], chain)
            except (OSError, ValueError) as error:
                return _page(502, f"원 서버 {remaining[0]} 연결을 시작하지 못했습니다: {error}")
            return OAuthResponse(302, {"location": location, "cache-control": "no-store",
                                       "content-length": "0"})
        return self._issue_code(chain, subject)

    # Resource server ---------------------------------------------------------

    def verify_bearer(self, authorization: str | None) -> dict[str, object] | None:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        try:
            claims = self._tokens.verify(
                token.strip(), now=self._clock(), audience=self._settings.resource
            )
        except ValueError:
            return None
        if SCOPE not in claims.get("scopes", []):
            return None
        return claims

    def challenge(self, invalid_token: bool) -> OAuthResponse:
        parts = [
            f'resource_metadata="{self._settings.resource_metadata_url}"',
            f'scope="{SCOPE}"',
        ]
        if invalid_token:
            parts.insert(0, 'error="invalid_token"')
        return _json(
            401,
            {"error": "invalid_token" if invalid_token else "unauthorized"},
            {"www-authenticate": "Bearer " + ", ".join(parts)},
        )

    # Dynamic Client Registration ---------------------------------------------

    def _register(self, body: bytes) -> OAuthResponse:
        try:
            metadata = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _client_metadata_error("request body must be JSON")
        if not isinstance(metadata, dict):
            return _client_metadata_error("request body must be a JSON object")
        redirect_uris = metadata.get("redirect_uris")
        if (not isinstance(redirect_uris, list) or not redirect_uris
                or len(redirect_uris) > _MAX_REDIRECT_URIS
                or not all(isinstance(uri, str) for uri in redirect_uris)):
            return _error(400, "invalid_redirect_uri", "redirect_uris must be a non-empty list")
        if not all(self._redirect_allowed(uri) for uri in redirect_uris):
            return _error(400, "invalid_redirect_uri", "redirect URI is not allowed")
        if metadata.get("token_endpoint_auth_method", "none") != "none":
            return _client_metadata_error("only public clients (token_endpoint_auth_method none)")
        grant_types = metadata.get("grant_types", ["authorization_code", "refresh_token"])
        if (not isinstance(grant_types, list)
                or not set(grant_types) <= {"authorization_code", "refresh_token"}):
            return _client_metadata_error("unsupported grant_types")
        client_name = metadata.get("client_name", "")
        client_name = client_name[:100] if isinstance(client_name, str) else ""
        client_id = "mcpg_" + secrets.token_urlsafe(24)
        issued_at = int(self._clock().timestamp())
        record = {
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "client_name": client_name,
            "issued_at": issued_at,
        }
        with self._state.lock:
            self._state.clients[client_id] = record
            while len(self._state.clients) > _MAX_CLIENTS:
                self._state.clients.pop(next(iter(self._state.clients)))
            self._state.save()
        return _json(201, {
            "client_id": client_id,
            "client_id_issued_at": issued_at,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "client_name": client_name,
        })

    def _redirect_allowed(self, uri: str) -> bool:
        if (uri in HOSTED_CALLBACKS or uri in self._settings.extra_redirect_uris
                or _CHATGPT_CALLBACK.fullmatch(uri)):
            return True
        parts = urlsplit(uri)
        # Claude Code and Codex use an RFC 8252 loopback redirect on an ephemeral port.
        return parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS and not parts.fragment

    # Authorization endpoint --------------------------------------------------

    def _client(self, client_id: object) -> dict[str, object] | None:
        if not isinstance(client_id, str):
            return None
        if client_id in self._static_clients:
            return self._static_clients[client_id]
        if client_id.startswith("https://"):
            return self._cimd_client(client_id)
        with self._state.lock:
            return self._state.clients.get(client_id)

    def client_family(self, client_id: object) -> str:
        """Which LLM client an OAuth client is: claude, chatgpt, codex, gemini, or other.

        Used to keep each client's sessions apart (D6-26), not to authorize.
        DCR client names are self-asserted, so a loopback client is labeled by
        name only when nothing better identifies it.
        """
        if not isinstance(client_id, str):
            return "other"
        static = self._static_clients.get(client_id)
        if static is not None:
            return str(static.get("family") or "other")
        if client_id.startswith("https://"):
            parts = urlsplit(client_id)
            host = (parts.hostname or "").lower()
            if host in ("claude.ai", "claude.com"):
                return "claude"
            if host == "chatgpt.com":
                return "codex" if parts.path.startswith("/oauth/codex/") else "chatgpt"
            return "other"
        with self._state.lock:
            record = self._state.clients.get(client_id) or {}
        hosts = {(urlsplit(str(uri)).hostname or "").lower() for uri in record.get("redirect_uris", [])}
        if hosts & {"claude.ai", "claude.com"}:
            return "claude"
        if "chatgpt.com" in hosts:
            return "chatgpt"
        name = str(record.get("client_name", "")).lower()
        for family in ("gemini", "codex", "claude", "chatgpt"):
            if family in name:
                return family
        return "other"

    def _cimd_client(self, url: str) -> dict[str, object] | None:
        """Client ID Metadata Document from an allow-listed host (SSRF guard)."""
        parts = urlsplit(url)
        if ((parts.hostname or "").lower() not in self._settings.cimd_hosts
                or parts.path in ("", "/") or parts.query or parts.fragment
                or parts.port not in (None, 443)):
            return None
        now = self._clock().timestamp()
        with self._cimd_lock:
            cached = self._cimd_cache.get(url)
        if cached and cached[1] > now:
            return cached[0]
        try:
            raw, cache_control = self._fetch_document(url)
            document = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(document, dict) or document.get("client_id") != url:
            return None
        uris = document.get("redirect_uris")
        if (not isinstance(document.get("client_name"), str) or not isinstance(uris, list)
                or not all(isinstance(u, str) for u in uris)
                or not _public_client(document)):
            return None
        allowed = [u for u in uris if self._redirect_allowed(u)]
        if not allowed:
            return None
        # Name the client by its host: the document's client_name is self-asserted.
        record = {"redirect_uris": allowed, "client_name": parts.hostname, "cimd": True}
        with self._cimd_lock:
            self._cimd_cache[url] = (record, now + _max_age(cache_control))
        return record

    def _registered_redirect(self, client: dict[str, object], redirect_uri: object) -> bool:
        if not isinstance(redirect_uri, str):
            return False
        for registered in client["redirect_uris"]:
            if redirect_uri == registered:
                return True
            if _loopback_equal(registered, redirect_uri):
                return True
        return False

    def _authorize_page(self, params: dict[str, str]) -> OAuthResponse:
        client = self._client(params.get("client_id"))
        redirect_uri = params.get("redirect_uri")
        # Never redirect to an unverified URI (open redirect protection).
        if client is None or not self._registered_redirect(client, redirect_uri):
            return _page(400, "알 수 없는 클라이언트이거나 등록되지 않은 redirect URI입니다.")
        problem = self._authorize_problem(params)
        if problem:
            return self._redirect(redirect_uri, {"error": "invalid_request",
                                                 "error_description": problem,
                                                 "state": params.get("state")})
        request = {
            "client_id": params["client_id"],
            "redirect_uri": redirect_uri,
            "code_challenge": params["code_challenge"],
            "state": params.get("state"),
            "scope": SCOPE,
            "exp": int(self._clock().timestamp()) + self._settings.login_form_seconds,
        }
        return self._login_form(self._sign(request), client, redirect_uri, error="")

    def _authorize_problem(self, params: dict[str, str]) -> str:
        if params.get("response_type") != "code":
            return "response_type must be code"
        if params.get("code_challenge_method") != "S256":
            return "PKCE with code_challenge_method S256 is required"
        if not _PKCE_CHALLENGE.fullmatch(params.get("code_challenge", "")):
            return "code_challenge is invalid"
        resource = params.get("resource")
        if resource is not None and resource.rstrip("/") != self._settings.resource:
            return "resource does not name this MCP server"
        requested = set((params.get("scope") or SCOPE).split())
        upstream = {f"upstream:{n}" for n in (self._upstream.server_names() if self._upstream else ())}
        if not requested <= {SCOPE, "offline_access"} | upstream:
            return "unsupported scope"
        return ""

    def _authorize_submit(self, form: dict[str, str]) -> OAuthResponse:
        request = self._unsign(form.get("request", ""))
        if request is None:
            return _page(400, "로그인 요청이 만료되었거나 변조되었습니다. 처음부터 다시 연결하세요.")
        client = self._client(request["client_id"])
        if client is None or not self._registered_redirect(client, request["redirect_uri"]):
            return _page(400, "알 수 없는 클라이언트입니다.")
        username = form.get("username", "")
        if not self._users.verify(username, form.get("password", "")):
            # An unknown name is not recorded: it may be a password typed in the wrong field.
            self._audit.record(audit_event(
                "sign_in", verdict="block", client=str(request["client_id"]),
                user=username if username in self._users else "",
                details={"outcome": "failure", "known_user": username in self._users}))
            return self._login_form(form["request"], client, request["redirect_uri"],
                                    error="사용자 이름이나 비밀번호가 맞지 않습니다.", status=401)
        self._audit.record(audit_event("sign_in", verdict="allow", user=username,
                                       client=str(request["client_id"]),
                                       details={"outcome": "success"}))
        # Per-user upstream servers: link every account the user has not linked
        # yet before the client gets its code (fails closed if a link fails).
        return self._continue_chain(username, request)

    def _issue_code(self, request: dict[str, object], username: str) -> OAuthResponse:
        code = secrets.token_urlsafe(32)
        with self._codes_lock:
            now = self._clock()
            self._codes = {k: v for k, v in self._codes.items() if v["expires"] > now}
            self._codes[code] = {
                "client_id": request["client_id"],
                "redirect_uri": request["redirect_uri"],
                "code_challenge": request["code_challenge"],
                "subject": username,
                "scope": request["scope"],
                "expires": now + timedelta(seconds=self._settings.code_seconds),
            }
        return self._redirect(str(request["redirect_uri"]), {"code": code, "state": request["state"]})

    def _redirect(self, redirect_uri: str, params: dict[str, object]) -> OAuthResponse:
        values = {k: v for k, v in params.items() if v is not None}
        values["iss"] = self._settings.issuer
        separator = "&" if urlsplit(redirect_uri).query else "?"
        return OAuthResponse(302, {
            "location": redirect_uri + separator + urlencode(values),
            "cache-control": "no-store",
            "content-length": "0",
        })

    def _login_form(
        self, signed: str, client: dict[str, object], redirect_uri: str,
        error: str, status: int = 200,
    ) -> OAuthResponse:
        host = urlsplit(redirect_uri).hostname or redirect_uri
        name = client.get("client_name") or "MCP 클라이언트"
        message = f'<p class="err">{html.escape(error)}</p>' if error else ""
        body = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
<title>mcp-guard 로그인</title><style>body{{font-family:sans-serif;max-width:420px;margin:60px auto}}
label{{display:block;margin-top:12px}}input{{width:100%;padding:8px}}.err{{color:#b00020}}</style></head>
<body><h1>mcp-guard 로그인</h1>
<p><b>{html.escape(str(name))}</b>이(가) mcp-guard 게이트웨이 접근을 요청합니다.</p>
<p>로그인 후 돌아갈 곳: <b>{html.escape(host)}</b></p>{message}
<form method="post" action="/authorize">
<input type="hidden" name="request" value="{html.escape(signed)}">
<label>사용자 이름<input name="username" autocomplete="username" required></label>
<label>비밀번호<input name="password" type="password" autocomplete="current-password" required></label>
<p><button type="submit">로그인하고 허용</button></p></form></body></html>"""
        return OAuthResponse(status, {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            "referrer-policy": "no-referrer",
        }, body.encode("utf-8"))

    def _sign(self, request: dict[str, object]) -> str:
        payload = _b64(json.dumps(request, separators=(",", ":")).encode("utf-8"))
        signature = _b64(hmac.new(self._form_key, payload.encode("ascii"), hashlib.sha256).digest())
        return f"{payload}.{signature}"

    def _unsign(self, signed: str) -> dict[str, object] | None:
        payload, _, signature = signed.partition(".")
        if not payload or not payload.isascii() or not signature.isascii():
            return None
        expected = _b64(hmac.new(self._form_key, payload.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        request = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if int(self._clock().timestamp()) >= int(request["exp"]):
            return None
        return request

    # Token endpoint ----------------------------------------------------------

    def _token(self, form: dict[str, str], headers: dict[str, str] | None = None) -> OAuthResponse:
        grant_type = form.get("grant_type")
        basic_id, basic_secret = _basic_credentials(headers or {})
        client_id = basic_id or form.get("client_id")
        client = self._client(client_id)
        if client is None:
            return _error(401, "invalid_client", "unknown client_id")
        expected = client.get("secret_sha256")
        if expected:  # a confidential, administrator-registered client
            secret = basic_secret or form.get("client_secret", "")
            if not hmac.compare_digest(_digest(secret), str(expected)):
                return _error(401, "invalid_client", "client authentication failed")
        form = {**form, "client_id": str(client_id)}
        resource = form.get("resource")
        if resource is not None and resource.rstrip("/") != self._settings.resource:
            return _error(400, "invalid_target", "resource does not name this MCP server")
        if grant_type == "authorization_code":
            return self._exchange_code(form)
        if grant_type == "refresh_token":
            return self._refresh(form)
        return _error(400, "unsupported_grant_type", "unsupported grant_type")

    def _exchange_code(self, form: dict[str, str]) -> OAuthResponse:
        with self._codes_lock:
            grant = self._codes.pop(form.get("code", ""), None)  # single use
        if grant is None or grant["expires"] <= self._clock():
            return _error(400, "invalid_grant", "authorization code is invalid or expired")
        if grant["client_id"] != form.get("client_id") or grant["redirect_uri"] != form.get("redirect_uri"):
            return _error(400, "invalid_grant", "code was issued to another client or redirect URI")
        verifier = form.get("code_verifier", "")
        if not _PKCE_VERIFIER.fullmatch(verifier):
            return _error(400, "invalid_grant", "code_verifier is invalid")
        challenge = _b64(hashlib.sha256(verifier.encode("ascii")).digest())
        if not hmac.compare_digest(challenge, str(grant["code_challenge"])):
            return _error(400, "invalid_grant", "PKCE verification failed")
        return self._issue(str(grant["subject"]), str(grant["client_id"]))

    def _refresh(self, form: dict[str, str]) -> OAuthResponse:
        digest = _digest(form.get("refresh_token", ""))
        with self._state.lock:
            record = self._state.refresh.pop(digest, None)  # rotation: old token dies
            self._state.save()
        if (record is None or record["client_id"] != form.get("client_id")
                or int(record["expires"]) <= int(self._clock().timestamp())):
            return _error(400, "invalid_grant", "refresh token is invalid or expired")
        return self._issue(str(record["subject"]), str(record["client_id"]))

    def _issue(self, subject: str, client_id: str) -> OAuthResponse:
        now = self._clock()
        access = self._tokens.issue(
            subject, (SCOPE,), now=now, audience=self._settings.resource, client_id=client_id
        )
        refresh = secrets.token_urlsafe(32)
        with self._state.lock:
            self._state.refresh[_digest(refresh)] = {
                "client_id": client_id,
                "subject": subject,
                "expires": int(now.timestamp()) + self._settings.refresh_token_seconds,
            }
            self._state.save()
        return _json(200, {
            "access_token": access.token,
            "token_type": "Bearer",
            "expires_in": self._settings.access_token_seconds,
            "refresh_token": refresh,
            "scope": SCOPE,
        }, {"cache-control": "no-store", "pragma": "no-cache"})


def _public_client(document: dict[str, object]) -> bool:
    """The client can authenticate with ``none``, the only method this server offers.

    ChatGPT lists ``none`` and ``private_key_jwt`` and names ``private_key_jwt`` as its
    preference; it picks from the intersection with our metadata, so the list decides.
    """
    methods = document.get("token_endpoint_auth_methods_supported")
    if isinstance(methods, list):
        return "none" in methods
    return document.get("token_endpoint_auth_method", "none") == "none"


def _basic_credentials(headers: dict[str, str]) -> tuple[str, str]:
    """client_secret_basic (RFC 6749 2.3.1): form-encoded id and secret, base64 joined by ':'."""
    value = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    scheme, _, encoded = value.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return "", ""
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return "", ""
    client_id, separator, secret = decoded.partition(":")
    if not separator:
        return "", ""
    return unquote_plus(client_id), unquote_plus(secret)


def load_static_clients(path: str | Path) -> dict[str, dict[str, object]]:
    """Administrator-registered confidential clients (``cloud_entry.admin add-client``)."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    clients = payload.get("clients")
    if not isinstance(clients, dict):
        raise ValueError("oauth clients file must contain a 'clients' object")
    for client_id, record in clients.items():
        uris = record.get("redirect_uris") if isinstance(record, dict) else None
        if (not isinstance(uris, list) or not uris
                or not all(isinstance(u, str) and u.startswith("https://") for u in uris)
                or not isinstance(record.get("secret_sha256"), str)):
            raise ValueError(f"oauth client {client_id!r} needs https redirect_uris and a secret")
    return clients


def _loopback_equal(registered: str, candidate: str) -> bool:
    """RFC 8252 7.3: loopback redirects match regardless of port."""
    left, right = urlsplit(registered), urlsplit(candidate)
    return (
        left.scheme == right.scheme == "http"
        and left.hostname in _LOOPBACK_HOSTS
        and left.hostname == right.hostname
        and left.path == right.path
        and left.query == right.query
    )


def _form(headers: dict[str, str], body: bytes) -> dict[str, str]:
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    if content_type.split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
        return {}
    try:
        return dict(parse_qsl(body.decode("utf-8"), keep_blank_values=True))
    except UnicodeDecodeError:
        return {}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _json(status: int, payload: dict[str, object], headers: dict[str, str] | None = None) -> OAuthResponse:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return OAuthResponse(status, {"content-type": "application/json", **(headers or {})}, body)


def _error(status: int, code: str, description: str) -> OAuthResponse:
    return _json(status, {"error": code, "error_description": description}, {"cache-control": "no-store"})


def _client_metadata_error(description: str) -> OAuthResponse:
    return _error(400, "invalid_client_metadata", description)


def _not_allowed() -> OAuthResponse:
    return _json(405, {"error": "method_not_allowed"})


def _page(status: int, message: str) -> OAuthResponse:
    body = (
        '<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>mcp-guard</title></head>'
        f"<body><h1>mcp-guard</h1><p>{html.escape(message)}</p></body></html>"
    )
    return OAuthResponse(status, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    }, body.encode("utf-8"))


def _fetch_https_document(url: str) -> tuple[bytes, str]:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("client metadata documents must not redirect")

    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={"accept": "application/json"})
    with opener.open(request, timeout=5) as response:
        raw = response.read(_MAX_CIMD_BYTES + 1)
        if len(raw) > _MAX_CIMD_BYTES:
            raise ValueError("client metadata document is too large")
        return raw, response.headers.get("cache-control", "")


def _max_age(cache_control: str) -> float:
    """Respect Cache-Control max-age within 1 minute to 1 day (default 1 hour)."""
    match = re.search(r"max-age=(\d+)", cache_control or "")
    seconds = int(match.group(1)) if match else 3600
    return float(min(max(seconds, 60), 86_400))
