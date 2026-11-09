"""Remote 3-A4: exceptions to the tainted-session send block, and their approvals (D6-49).

In a tainted session M4 blocks every tool that can send data out (D6-07). A
user may name some of those tools as exceptions, only among the tools the
administrator allows, and only for themselves. An exception is never a pass:
each call in a tainted session waits for the user's own approval of that exact
input, shown raw, on the gateway's approval page.

* taint-exceptions.json (beside the other gateway state): ``allowed`` holds the
  administrator's list, ``users`` each user's choices. Users change theirs only
  on the signed-in page, never through an MCP call, so text in a tool result
  cannot add an exception (Docs/Core_mds/architecture.md, stage 4).
* approval-requests.json holds pending and decided requests, including the raw
  input shown on the approval page. POSIX mode 0600 and a Windows ACL without
  inherited access protect new writes. It survives a restart, and entries
  expire after 10 minutes. This file is for one gateway process only.

An approval is bound to the user, the session, the tool and the SHA-256 of
the input; it is used once. Inputs too long to show whole are refused rather
than shown cut.
"""

from __future__ import annotations

import hashlib
import csv
import json
import math
import os
import re
import secrets
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .reapproval_store import JsonFolder

EXCEPTIONS = "taint-exceptions.json"
REQUESTS = "approval-requests.json"
APPROVAL_SECONDS = 10 * 60
MAX_SHOWN_ARGUMENTS = 4000  # characters of compact JSON; the local hook shows the same amount
MAX_OPEN_PER_USER = 20


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str  # random; the page link carries it, the page still requires the signed-in user
    user: str
    session_id: str
    rpc_id: str  # the JSON-RPC id of the call that asked, for the audit record
    key: str  # server:tool
    arguments_json: str
    arguments_sha256: str
    tainted_by: str
    created_at: float
    status: str = "pending"  # pending, approved, refused, used, expired
    decided_at: float | None = None

    @property
    def expires_at(self) -> float:
        return self.created_at + APPROVAL_SECONDS


def canonical_arguments(arguments: dict[str, Any]) -> str:
    return json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def arguments_digest(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_arguments(arguments).encode("utf-8")).hexdigest()


def _restrict_windows_acl(path: Path) -> None:
    identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, text=True, check=True)
    rows = list(csv.reader(identity.stdout.splitlines()))
    if len(rows) != 1 or len(rows[0]) != 2 or not re.fullmatch(r"S-\d+(?:-\d+)+", rows[0][1]):
        raise OSError("cannot identify the Windows account for approval storage")
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                    f"*{rows[0][1]}:F"], capture_output=True, text=True, check=True)


class TaintExceptionStore(JsonFolder):
    def __init__(self, folder: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        super().__init__(folder)
        self._clock = clock
        saved = self.folder / REQUESTS
        if os.name == "nt" and saved.exists():
            _restrict_windows_acl(saved)
        self._requests = self._load_requests()
        self._requests_lock = threading.Lock()

    def _write(self, name: str, data: dict[str, Any]) -> None:
        if name != REQUESTS or os.name != "nt":
            return super()._write(name, data)
        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / name
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.unlink(missing_ok=True)
        try:
            # Restrict the empty file before writing raw tool arguments. chmod on
            # Windows does not remove inherited directory access entries.
            temporary.write_bytes(b"")
            _restrict_windows_acl(temporary)
            temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temporary, path)
            self._cache.pop(name, None)
        finally:
            temporary.unlink(missing_ok=True)

    def _load_requests(self) -> dict[str, ApprovalRequest]:
        saved = self._read(REQUESTS).get("requests", {})
        if not isinstance(saved, dict):
            raise ValueError("invalid approval request store")
        requests = {}
        for request_id, values in saved.items():
            if not isinstance(request_id, str) or not isinstance(values, dict) or \
                    set(values) != set(ApprovalRequest.__dataclass_fields__):
                raise ValueError("invalid approval request record")
            try:
                item = ApprovalRequest(**values)
                arguments = json.loads(item.arguments_json)
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid approval request record") from exc
            if (item.request_id != request_id or
                    not all(isinstance(value, str) for value in (
                        item.user, item.session_id, item.rpc_id, item.key,
                        item.arguments_json, item.arguments_sha256, item.tainted_by)) or
                    not isinstance(arguments, dict) or
                    canonical_arguments(arguments) != item.arguments_json or
                    arguments_digest(arguments) != item.arguments_sha256 or
                    not isinstance(item.created_at, (int, float)) or
                    not math.isfinite(item.created_at) or
                    (item.decided_at is not None and
                     (not isinstance(item.decided_at, (int, float)) or
                      not math.isfinite(item.decided_at))) or
                    item.status not in {"pending", "approved", "refused", "used", "expired"}):
                raise ValueError("invalid approval request record")
            requests[request_id] = item
        return requests

    def _save_requests(self, requests: dict[str, ApprovalRequest]) -> None:
        # Write before exposing a request or using an approval. A failed write
        # must never leave an approved call executable only in process memory.
        self._write(REQUESTS, {"requests": {key: asdict(value) for key, value in requests.items()}})
        self._requests = requests

    def now(self) -> float:
        return self._clock()

    # exceptions ------------------------------------------------------------------

    def allowed(self) -> dict[str, dict[str, Any]]:
        return self._read(EXCEPTIONS).get("allowed", {})

    def designations(self) -> dict[str, dict[str, dict[str, Any]]]:
        return self._read(EXCEPTIONS).get("users", {})

    def exceptions_for(self, user: str) -> set[str]:
        """The user's own exceptions that the administrator still allows."""
        if not user:
            return set()
        return set(self.designations().get(user, {})) & set(self.allowed())

    def allow(self, key: str, by: str) -> None:
        with self._lock:
            data = self._read(EXCEPTIONS)
            data.setdefault("allowed", {})[key] = {"allowed_by": by, "allowed_at": _now()}
            self._write(EXCEPTIONS, data)

    def disallow(self, key: str) -> None:
        """Users' choices of the tool stay on file but stop counting."""
        with self._lock:
            data = self._read(EXCEPTIONS)
            if key not in data.get("allowed", {}):
                raise KeyError(f"{key} is not allowed as an exception")
            del data["allowed"][key]
            self._write(EXCEPTIONS, data)

    def designate(self, user: str, key: str) -> None:
        with self._lock:
            if key not in self.allowed():
                raise PermissionError("the administrator has not allowed this tool as an exception")
            data = self._read(EXCEPTIONS)
            data.setdefault("users", {}).setdefault(user, {})[key] = {"added_at": _now()}
            self._write(EXCEPTIONS, data)

    def remove(self, user: str, key: str) -> None:
        with self._lock:
            data = self._read(EXCEPTIONS)
            if key not in data.get("users", {}).get(user, {}):
                raise KeyError(f"{user} has not chosen {key}")
            del data["users"][user][key]
            if not data["users"][user]:
                del data["users"][user]
            self._write(EXCEPTIONS, data)

    # approval requests -----------------------------------------------------------

    def request(self, user: str, session_id: str, rpc_id: str, key: str,
                arguments: dict[str, Any], tainted_by: str) -> ApprovalRequest:
        """An open request for this exact call, reusing one already waiting."""
        digest = arguments_digest(arguments)
        with self._requests_lock:
            now = self._clock()
            for item in self._requests.values():
                if (item.user, item.session_id, item.key, item.arguments_sha256) == \
                        (user, session_id, key, digest) and item.status == "pending" and now < item.expires_at:
                    return item
            if sum(1 for r in self._requests.values()
                   if r.user == user and r.status == "pending" and now < r.expires_at) >= MAX_OPEN_PER_USER:
                raise OverflowError("too many approvals are waiting; answer or let them expire")
            item = ApprovalRequest(secrets.token_urlsafe(18), user, session_id, rpc_id, key,
                                   canonical_arguments(arguments), digest, tainted_by, now)
            self._save_requests({**self._requests, item.request_id: item})
            return item

    def open_for(self, user: str) -> list[ApprovalRequest]:
        now = self._clock()
        with self._requests_lock:
            return sorted((r for r in self._requests.values()
                           if r.user == user and r.status == "pending" and now < r.expires_at),
                          key=lambda r: r.created_at)

    def decide(self, user: str, request_id: str, approve: bool) -> ApprovalRequest:
        """The signed-in user answers their own request; nobody else can."""
        with self._requests_lock:
            item = self._requests.get(request_id)
            if item is None or item.user != user:
                raise KeyError("no such approval request for this user")
            if item.status != "pending":
                raise ValueError(f"this request is already {item.status}")
            now = self._clock()
            if now >= item.expires_at:
                raise ValueError("this request expired; ask again")
            item = replace(item, status="approved" if approve else "refused", decided_at=now)
            self._save_requests({**self._requests, request_id: item})
            return item

    def use(self, user: str, session_id: str, key: str, arguments_sha256: str) -> ApprovalRequest | None:
        """Spend an approval of this exact call, once."""
        with self._requests_lock:
            now = self._clock()
            for request_id, item in self._requests.items():
                if (item.user, item.session_id, item.key, item.arguments_sha256) == \
                        (user, session_id, key, arguments_sha256) and item.status == "approved" \
                        and now < item.expires_at:
                    item = replace(item, status="used")
                    self._save_requests({**self._requests, request_id: item})
                    return item
        return None

    def sweep(self) -> list[ApprovalRequest]:
        """Requests that ran out unanswered or unused since the last sweep; finished ones are dropped."""
        expired = []
        with self._requests_lock:
            now = self._clock()
            remaining = dict(self._requests)
            for request_id, item in list(remaining.items()):
                if item.status in ("pending", "approved") and now >= item.expires_at:
                    expired.append(replace(item, status="expired"))
                    del remaining[request_id]
                elif item.status in ("refused", "used") and now >= item.expires_at:
                    del remaining[request_id]
            if remaining != self._requests:
                self._save_requests(remaining)
        return expired


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
