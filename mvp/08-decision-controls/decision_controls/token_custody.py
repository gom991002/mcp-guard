from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol


class SecretStore(Protocol):
    def put(self, key: str, secret: str) -> str:
        """Store or reference a secret and return a stable reference."""

    def get(self, reference: str) -> str:
        """Return the secret for a reference when the backend supports retrieval."""


@dataclass(frozen=True)
class GatewayToken:
    token: str
    subject: str
    expires_at: datetime
    scopes: tuple[str, ...]


class GatewayTokenIssuer:
    def __init__(self, signing_key: bytes, ttl_seconds: int = 900) -> None:
        if not signing_key:
            raise ValueError("signing_key must not be empty")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._signing_key = signing_key
        self._ttl_seconds = ttl_seconds

    @classmethod
    def with_random_key(cls, ttl_seconds: int = 900) -> "GatewayTokenIssuer":
        return cls(secrets.token_bytes(32), ttl_seconds=ttl_seconds)

    def issue(
        self,
        subject: str,
        scopes: tuple[str, ...],
        now: datetime | None = None,
        audience: str | None = None,
        client_id: str | None = None,
    ) -> GatewayToken:
        now = now or datetime.now(UTC)
        expires_at = now + timedelta(seconds=self._ttl_seconds)
        payload = {
            "sub": subject,
            "scopes": list(scopes),
            "exp": int(expires_at.timestamp()),
            "nonce": secrets.token_hex(8),
        }
        # RFC 8707: a token names the one resource it is valid for.
        if audience is not None:
            payload["aud"] = audience
        if client_id is not None:
            payload["client_id"] = client_id
        payload_b64 = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signature = _b64(hmac.new(self._signing_key, payload_b64.encode("ascii"), hashlib.sha256).digest())
        return GatewayToken(
            token=f"{payload_b64}.{signature}",
            subject=subject,
            expires_at=expires_at,
            scopes=scopes,
        )

    def verify(
        self,
        token: str,
        now: datetime | None = None,
        audience: str | None = None,
    ) -> dict[str, object]:
        now = now or datetime.now(UTC)
        payload_b64, sep, signature = token.partition(".")
        if not sep or not payload_b64.isascii() or not signature.isascii():
            raise ValueError("token is malformed")
        expected = _b64(hmac.new(self._signing_key, payload_b64.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("token signature is invalid")
        payload = json.loads(base64.urlsafe_b64decode(_pad(payload_b64)).decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("exp"), int):
            raise ValueError("token payload is invalid")
        if int(now.timestamp()) >= payload["exp"]:
            raise ValueError("token is expired")
        if audience is not None and payload.get("aud") != audience:
            raise ValueError("token audience is invalid")
        return payload


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _pad(value: str) -> bytes:
    return (value + "=" * (-len(value) % 4)).encode("ascii")

