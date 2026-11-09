"""M1 audit records: one event model for the core, both entry paths, and the correlation rules.

Every event says who (user, client, path, session), what (server, tool, event
type), where (stage and marker of the event and of each finding), and the
decision. Tool arguments and results are recorded only as SHA-256 digests and
sizes; tokens, secrets, and passwords are never recorded. Server-published tool
descriptions are recorded when a definition changes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TextIO

from .models import GuardDecision, ToolRegistration

# event type -> (stage, marker). Events checked by several modules (a tool
# list entry, a call) have no single marker; their findings carry markers.
EVENT_TYPES: dict[str, tuple[str, str]] = {
    "server_admission": ("0-entry", "A"),
    "server_approved": ("0-entry", "A"),
    "gateway_edge_rejected": ("0-entry", "A"),
    "config_rewrapped": ("0-entry", "L3"),  # client-side tooling, not a core check
    "integration_checked": ("1-integration", "A"),
    "dependencies_checked": ("1-integration", ""),  # lock findings carry A or B markers
    "dependencies_reviewed": ("1-integration", ""),
    "code_scanned": ("1-integration", "B"),  # D6-30: Semgrep code-behavior signals
    "code_scan_reviewed": ("1-integration", "B"),
    "review_assisted": ("1-integration", "B"),  # D6-36: advisory LLM summary, no decision
    "registration_evaluated": ("2-registration", ""),
    "definition_changed": ("2-registration", "M3"),
    "definition_approved": ("2-registration", "M3"),
    "definition_rejected": ("2-registration", "M3"),  # D6-45 re-approval flow
    "definition_accepted": ("2-registration", "M3"),  # a user's own acceptance, where allowed
    "acceptance_revoked": ("2-registration", "M3"),
    "tools_list_changed": ("2-registration", ""),
    "tool_call_checked": ("2-registration", ""),  # pre-call recheck runs the stage 2 rules
    "upstream_call": ("audit", "M1"),
    "response_contaminated": ("3-response", "M4"),
    "response_classified": ("3-response", "B"),
    "external_tool_call": ("4-containment", "M4"),
    "value_policy_checked": ("4-containment", "M4"),
    "approval_requested": ("4-containment", "3-A4"),
    "approval_decided": ("4-containment", "3-A4"),
    "taint_exception_changed": ("4-containment", "3-A4"),
    "session_reset": ("3-response", "M4"),  # a signed-in user started a new gateway session  # D6-49: a user's own exception list
    # Gateway security outside the drawings (design discussion).
    "sign_in": ("0-entry", "C2"),
    "upstream_linked": ("0-entry", "C3"),
    "upstream_unlinked": ("0-entry", "C3"),
    "credential_store_unavailable": ("0-entry", "C3"),
    "rate_limited": ("0-entry", "A"),
    "shared_egress_updated": ("0-entry", "A"),  # a published client egress list fetched or kept
    "startup_override": ("0-entry", "A"),  # operator accepted a weaker setting, e.g. unbound sessions
    # M1 correlation rules over the audit stream (D6-25): alerts, not decisions.
    "correlation_alert": ("audit", "M1"),
}


@dataclass(frozen=True)
class AuditFinding:
    code: str
    marker: str
    stage: str


@dataclass(frozen=True)
class AuditEvent:
    timestamp: datetime
    event_type: str
    server_name: str = ""
    tool_name: str = ""
    verdict: str = ""
    finding_codes: tuple[str, ...] = field(default_factory=tuple)
    # mcp-guard session, not an MCP protocol session: M4 taint is tracked per
    # client session, and MCP 2026-07-28 has no protocol-level sessions.
    session_id: str = ""
    findings: tuple[AuditFinding, ...] = field(default_factory=tuple)
    namespace: str = ""
    path: str = ""  # "local" (L entry) or "remote" (C entry)
    client: str = ""
    user: str = ""
    request_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    # Content hashes of what decided (engine code, policy, approvals): see decision_model().
    decision_model: dict[str, Any] = field(default_factory=dict)

    @property
    def stage(self) -> str:
        return EVENT_TYPES.get(self.event_type, ("", ""))[0]

    @property
    def marker(self) -> str:
        return EVENT_TYPES.get(self.event_type, ("", ""))[1]

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "stage": self.stage,
            "marker": self.marker,
            "path": self.path,
            "client": self.client,
            "user": self.user,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "server_name": self.server_name,
            "namespace": self.namespace,
            "tool_name": self.tool_name,
            "verdict": self.verdict,
            "finding_codes": list(self.finding_codes),
            "findings": [vars(finding) for finding in self.findings],
            "details": self.details,
            "decision_model": self.decision_model,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditEvent":
        return cls(
            timestamp=datetime.fromisoformat(str(payload["timestamp"])),
            event_type=str(payload["event_type"]),
            server_name=str(payload.get("server_name", "")),
            tool_name=str(payload.get("tool_name", "")),
            verdict=str(payload.get("verdict", "")),
            finding_codes=tuple(payload.get("finding_codes", ())),
            session_id=str(payload.get("session_id", "")),
            findings=tuple(AuditFinding(**finding) for finding in payload.get("findings", ())),
            namespace=str(payload.get("namespace", "")),
            path=str(payload.get("path", "")),
            client=str(payload.get("client", "")),
            user=str(payload.get("user", "")),
            request_id=str(payload.get("request_id", "")),
            details=dict(payload.get("details", {})),
            event_id=str(payload.get("event_id") or uuid.uuid4().hex),
            decision_model=dict(payload.get("decision_model", {})),
        )


def read_audit_log(path: str | Path, include_rotated: bool = False,
                   since: datetime | None = None) -> list[AuditEvent]:
    """Events of a JSON Lines audit log, e.g. to run the M1 correlation rules."""
    files = audit_log_files(path) if include_rotated else [Path(path)]
    events = []
    for file in files:
        if not file.exists():
            continue
        for line in file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                event = AuditEvent.from_dict(json.loads(line))
                if since is None or event.timestamp >= since:
                    events.append(event)
    return events


def audit_event(event_type: str, decision: GuardDecision | None = None, **fields: Any) -> AuditEvent:
    """Build an event of a known type; a decision fills the verdict and findings."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown audit event type: {event_type}")
    if decision is not None:
        fields.setdefault("verdict", decision.verdict.value)
        fields.setdefault("finding_codes", tuple(f.code for f in decision.findings))
        fields.setdefault("findings", tuple(
            AuditFinding(f.code, f.marker, f.stage) for f in decision.findings))
    fields.setdefault("timestamp", datetime.now(UTC))
    return AuditEvent(event_type=event_type, **fields)


def audit_event_for_decision(
    registration: ToolRegistration,
    decision: GuardDecision,
    timestamp: datetime | None = None,
    session_id: str = "",
    event_type: str = "registration_evaluated",
    **fields: Any,
) -> AuditEvent:
    details = dict(fields.pop("details", {}))
    if registration.schema_hash:
        details.setdefault("schema_hash", registration.schema_hash)
    if decision.b_scores:
        details["b_scores"] = list(decision.b_scores)
    return audit_event(
        event_type, decision,
        timestamp=timestamp or datetime.now(UTC),
        server_name=registration.server_name,
        namespace=registration.namespace,
        tool_name=registration.tool_name,
        session_id=session_id,
        details=details,
        **fields,
    )


def digest(value: Any) -> dict[str, object]:
    """SHA-256 and size of a JSON value, recorded instead of the value itself."""
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                     default=str).encode("utf-8")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def definition_change_details(observed: ToolRegistration,
                              approved: ToolRegistration | None) -> dict[str, object]:
    return {
        "approved_schema_hash": approved.schema_hash if approved else None,
        "observed_schema_hash": observed.schema_hash,
        "description_changed": approved is None or approved.description != observed.description,
        "description": observed.description,  # published by the server, not user data
    }


DEFINITION_CHANGE_CODES = frozenset({"M3_SCHEMA_HASH_CHANGED", "M3_DESCRIPTION_CHANGED"})


# Decision model ---------------------------------------------------------------
# Like OPA's per-decision bundle revision and engine version, but as content
# hashes, so the recorded value cannot stay the same while what it names changes.
# State that changes while running (stage 0 approvals, session taint) is not part
# of the model; its changes are audit events of their own.

def file_digest(path: str | Path | None) -> str | None:
    """SHA-256 of a file's bytes; None when no path is configured or it is missing."""
    if not path or not Path(path).is_file():
        return None
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_digest(directory: str | Path) -> str:
    """SHA-256 over the relative paths and bytes of every .py file under ``directory``."""
    root = Path(directory)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


ENGINE_DIGEST = source_digest(Path(__file__).resolve().parent)


def decision_model(files: dict[str, str | Path | None] | None = None,
                   sources: dict[str, str | Path] | None = None) -> dict[str, Any]:
    """What decided: the core engine's code, plus the named files and rule code.

    ``files`` are configuration such as the policy and approvals; ``sources``
    are code directories outside the core that also decide, such as the
    gateway's edge rules. B models will add their exact model names here.
    """
    model: dict[str, Any] = {"engine_sha256": ENGINE_DIGEST}
    for name, directory in (sources or {}).items():
        model[f"{name}_sha256"] = source_digest(directory)
    for name, path in (files or {}).items():
        if path:
            model[f"{name}_sha256"] = file_digest(path)
    return model


# Sinks and the recorder -------------------------------------------------------

class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class JsonlAuditSink:
    """Append one JSON object per line, owner-only on creation.

    Several local processes (wrappers, hook runs, the L3 watcher) may share the
    file, so each append holds an OS lock on a sidecar ``.lock`` file.

    With ``retention_days`` (D6-24: 180), the file is rotated monthly: when the
    month of the last write differs from now, ``audit.jsonl`` becomes
    ``audit.YYYY-MM.jsonl``, and rotated files whose month ended more than
    ``retention_days`` ago are deleted.
    """

    def __init__(self, path: str | Path, retention_days: int | None = None) -> None:
        self._path = Path(path)
        self._retention_days = retention_days
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        line = (json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"),
                           default=str) + "\n").encode("utf-8")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, _file_lock(self._path.with_name(self._path.name + ".lock")):
            if self._retention_days is not None:
                self._rotate(datetime.now(UTC))
            descriptor = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, line)
            finally:
                os.close(descriptor)

    def _rotate(self, now: datetime) -> None:
        """Call with the file lock held."""
        if self._path.exists():
            written = datetime.fromtimestamp(self._path.stat().st_mtime, UTC)
            if (written.year, written.month) != (now.year, now.month):
                target = _rotated_path(self._path, written.year, written.month)
                if target.exists():  # a second rotation in the same month: keep both
                    target = target.with_name(f"{target.stem}.{uuid.uuid4().hex[:8]}{target.suffix}")
                os.replace(self._path, target)
                self._prune(now)

    def _prune(self, now: datetime) -> None:
        for path, (year, month) in _rotated_files(self._path):
            month_end = datetime(year + month // 12, month % 12 + 1, 1, tzinfo=UTC)
            if (now - month_end).days > self._retention_days:
                path.unlink(missing_ok=True)


def _rotated_path(path: Path, year: int, month: int) -> Path:
    return path.with_name(f"{path.stem}.{year:04d}-{month:02d}{path.suffix}")


def _rotated_files(path: Path) -> list[tuple[Path, tuple[int, int]]]:
    found = []
    for candidate in path.parent.glob(f"{path.stem}.*{path.suffix}"):
        stamp = candidate.name[len(path.stem) + 1:].split(".", 1)[0]
        year, _, month = stamp.partition("-")
        if year.isdigit() and month.isdigit() and len(year) == 4 and len(month) == 2:
            found.append((candidate, (int(year), int(month))))
    return sorted(found, key=lambda item: (item[1], item[0].name))


def audit_log_files(path: str | Path) -> list[Path]:
    """Rotated monthly files, oldest first, then the active file."""
    path = Path(path)
    return [p for p, _ in _rotated_files(path)] + ([path] if path.exists() else [])


class RecentEventsSink:
    """Keep the last ``window_seconds`` of events in memory for the correlation rules."""

    def __init__(self, window_seconds: float) -> None:
        self._window = window_seconds
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def load(self, events: list[AuditEvent]) -> None:
        with self._lock:
            self._events = [*events, *self._events]

    def events(self, now: datetime | None = None) -> list[AuditEvent]:
        cutoff = (now or datetime.now(UTC)).timestamp() - self._window
        with self._lock:
            self._events = [e for e in self._events if e.timestamp.timestamp() >= cutoff]
            return list(self._events)


class TeeAuditSink:
    """Write each event to every sink, e.g. the local JSON Lines copy and CloudWatch Logs.

    A failing sink never stops the others; the failures are raised together
    afterwards so the recorder can report them.
    """

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = sinks

    def emit(self, event: AuditEvent) -> None:
        errors = []
        for sink in self._sinks:
            try:
                sink.emit(event)
            except OSError as error:
                errors.append(str(error))
        if errors:
            raise OSError("; ".join(errors))

    def close(self) -> None:
        for sink in self._sinks:
            close = getattr(sink, "close", None)
            if close is not None:
                close()


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)  # retries for about 10 s
            try:
                yield
            finally:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
    finally:
        os.close(descriptor)


class AuditRecorder:
    """Send events to a sink, filling empty context fields from ``defaults``.

    What to do when recording fails is an open decision; until it is made a
    failed write is reported on stderr and the request continues, as before
    audit persistence existed.
    """

    def __init__(self, sink: AuditSink | None = None, log: TextIO | None = None,
                 **defaults: Any) -> None:
        self._sink = sink
        self._log = log
        self._defaults = defaults

    @property
    def enabled(self) -> bool:
        return self._sink is not None

    def record(self, event: AuditEvent, **context: Any) -> None:
        if self._sink is None:
            return
        updates = {key: value for key, value in {**self._defaults, **context}.items()
                   if value and not getattr(event, key)}
        if updates:
            event = replace(event, **updates)
        try:
            self._sink.emit(event)
        except OSError as error:
            print(f"mcp-guard: audit record failed ({error})", file=self._log or sys.stderr,
                  flush=True)

    def record_all(self, events: Any, **context: Any) -> None:
        for event in events:
            self.record(event, **context)

    def close(self) -> None:
        """Flush and stop sinks that send in the background (CloudWatch Logs)."""
        close = getattr(self._sink, "close", None)
        if close is not None:
            close()


def local_user() -> str:
    try:
        import getpass

        return getpass.getuser()
    except (ImportError, KeyError, OSError):
        return ""
