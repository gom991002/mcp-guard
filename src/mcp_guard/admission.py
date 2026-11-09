"""Stage 0 admission of administrator-configured MCP upstream identities.

The record binds a trusted configuration to a server; it is not a remote
attestation or a substitute for client-side enforcement of the gateway path.
"""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from urllib.parse import urlsplit

from .models import GuardDecision, InspectionFinding, RuleAction, Severity, Verdict
from .registry import GuardRegistry


@dataclass(frozen=True)
class ServerIdentity:
    name: str
    namespace: str
    transport: str
    url: str
    source: str


class Stage0Admission:
    """Pin the first valid configuration, then fail closed on identity changes.

    Initial enrollment must be explicitly enabled by the operator. A missing
    file never silently resets prior approvals on a normal restart.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        enroll: bool = False,
        on_enroll: Callable[[ServerIdentity], None] | None = None,
    ) -> None:
        """``on_enroll`` is told about each first-use enrollment (for the M1 audit log)."""
        self._path = Path(path) if path is not None else None
        self._lock = RLock()
        self._initial_enrollment = self._path is None or enroll
        self._on_enroll = on_enroll
        self._records = self._load() if self._path is not None and self._path.exists() else {}

    def check(self, identity: ServerIdentity, registry: GuardRegistry) -> GuardDecision:
        with self._lock:
            failure = _validate(identity, registry)
            if failure:
                return _block("S0_SERVER_IDENTITY_INVALID", failure)

            previous = self._records.get(identity.name)
            if previous is not None:
                if previous != identity:
                    return _block(
                        "S0_SERVER_IDENTITY_CHANGED",
                        "Approved upstream identity changed; explicit reapproval is required.",
                    )
                return GuardDecision(Verdict.ALLOW)

            if not self._initial_enrollment:
                return _block(
                    "S0_SERVER_NOT_APPROVED",
                    "New upstream is not in the recorded approvals.",
                )
            try:
                self._save({**self._records, identity.name: identity})
            except OSError:
                return _block("S0_APPROVAL_STORE_UNAVAILABLE", "Could not record approval.")
            self._records[identity.name] = identity
            if self._on_enroll is not None:
                self._on_enroll(identity)
            return GuardDecision(Verdict.ALLOW)

    def approve(self, identity: ServerIdentity, registry: GuardRegistry) -> GuardDecision:
        """Explicit operator reapproval after inspecting a changed config."""
        with self._lock:
            failure = _validate(identity, registry)
            if failure:
                return _block("S0_SERVER_IDENTITY_INVALID", failure)
            try:
                self._save({**self._records, identity.name: identity})
            except OSError:
                return _block("S0_APPROVAL_STORE_UNAVAILABLE", "Could not record approval.")
            self._records[identity.name] = identity
            return GuardDecision(Verdict.ALLOW)

    def _load(self) -> dict[str, ServerIdentity]:
        assert self._path is not None
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError("invalid stage 0 approval file")
        records = payload.get("servers")
        if not isinstance(records, list):
            raise ValueError("invalid stage 0 approval records")
        result: dict[str, ServerIdentity] = {}
        keys = set(ServerIdentity.__dataclass_fields__)
        for record in records:
            if (not isinstance(record, dict) or set(record) != keys
                    or not all(isinstance(value, str) for value in record.values())):
                raise ValueError("invalid stage 0 approval record")
            identity = ServerIdentity(**record)
            if not identity.name or identity.name in result:
                raise ValueError("duplicate or empty stage 0 approval name")
            result[identity.name] = identity
        return result

    def _save(self, records: dict[str, ServerIdentity]) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self._path.parent,
                prefix=".stage0-", suffix=".tmp", delete=False,
            ) as stream:
                temporary = stream.name
                json.dump({
                    "version": 1,
                    "servers": [asdict(records[name]) for name in sorted(records)],
                }, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path)
        finally:
            if temporary is not None and os.path.exists(temporary):
                os.unlink(temporary)


def _validate(identity: ServerIdentity, registry: GuardRegistry) -> str | None:
    if not identity.name or identity.name not in registry.registered_servers:
        return "Upstream server is not registered in policy."
    if not identity.namespace or identity.namespace not in registry.trusted_namespaces:
        return "Upstream namespace is not trusted."
    if not identity.source or identity.source not in registry.trusted_sources:
        return "Upstream registration source is not trusted."
    if identity.transport != "streamable_http":
        return "Upstream transport is not supported."
    try:
        parsed = urlsplit(identity.url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "Upstream URL is invalid."
    if (parsed.scheme not in {"https", "http"} or not host or
            parsed.username is not None or parsed.password is not None or
            parsed.fragment or port == 0):
        return "Upstream URL is invalid."
    if parsed.scheme == "http":
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            return "Remote upstream must use HTTPS."
    return None


def _block(code: str, message: str) -> GuardDecision:
    return GuardDecision(Verdict.BLOCK, (
        InspectionFinding(
            code=code, marker="A", stage="0-entry", action=RuleAction.BLOCK,
            severity=Severity.CRITICAL, message=message,
        ),
    ))
