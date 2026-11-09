"""Re-approval records for the remote gateway (D6-45, REAPPROVAL.md).

The reviewed configuration (servers.json, policy) is never rewritten. Three
files sit beside the stage 0 approvals instead:

* pending-definitions.json: changed or new definitions the gateway is hiding,
  with the guard's classification and change summary (written by the gateway);
* definition-approvals.json: definitions the administrator approved again;
* user-acceptances.json: changes users accepted for themselves, used only when
  the administrator allows it.

Files are re-read when their modification time changes, so the gateway picks
up an administrator's approval without a restart. Writes are atomic.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PENDING, APPROVALS, ACCEPTANCES = "pending-definitions.json", "definition-approvals.json", "user-acceptances.json"


class JsonFolder:
    """JSON files in one folder, re-read when they change, written atomically."""

    def __init__(self, folder: str | Path) -> None:
        self.folder = Path(folder)
        self._lock = threading.RLock()
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    def _read(self, name: str) -> dict[str, Any]:
        path = self.folder / name
        try:
            mtime = path.stat().st_mtime_ns
        except FileNotFoundError:
            return {}
        with self._lock:
            cached = self._cache.get(name)
            if cached and cached[0] == mtime:
                return json.loads(json.dumps(cached[1]))  # a copy callers may change
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"{path} is not a JSON object")
            self._cache[name] = (mtime, data)
            return json.loads(json.dumps(data))

    def _write(self, name: str, data: dict[str, Any]) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / name
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        self._cache.pop(name, None)


class ReapprovalStore(JsonFolder):
    def __init__(self, folder: str | Path, *, allow_user: bool = False) -> None:
        super().__init__(folder)
        self.allow_user = allow_user

    # reading -------------------------------------------------------------------

    def pending(self) -> dict[str, dict[str, Any]]:
        return self._read(PENDING).get("definitions", {})

    def approvals(self) -> dict[str, dict[str, Any]]:
        return self._read(APPROVALS).get("definitions", {})

    def acceptances(self) -> dict[str, dict[str, dict[str, Any]]]:
        return self._read(ACCEPTANCES).get("users", {})

    def admin_approved(self, key: str, schema_hash: str | None, description_sha256: str) -> bool:
        entry = self.approvals().get(key)
        return bool(entry) and entry.get("schema_hash") == schema_hash and \
            entry.get("description_sha256") == description_sha256

    def user_accepted(self, user: str, key: str, schema_hash: str | None, description_sha256: str) -> bool:
        if not (self.allow_user and user):
            return False
        entry = self.acceptances().get(user, {}).get(key)
        return bool(entry) and entry.get("schema_hash") == schema_hash and \
            entry.get("description_sha256") == description_sha256

    # writing (gateway) -----------------------------------------------------------

    def record_pending(self, key: str, record: dict[str, Any], user: str = "") -> None:
        """Record a held definition; repeated sightings of the same one only add the user."""
        with self._lock:
            data = self._read(PENDING)
            definitions = data.setdefault("definitions", {})
            current = definitions.get(key)
            same = current and current.get("schema_hash") == record["schema_hash"] and \
                current.get("description_sha256") == record["description_sha256"]
            if same and (not user or user in current.get("seen_by", [])):
                return
            entry = dict(current) if same else {**record, "first_seen": _now(), "seen_by": []}
            if user:
                entry["seen_by"] = sorted({*entry.get("seen_by", []), user})
            definitions[key] = entry
            self._write(PENDING, data)

    def accept(self, user: str, key: str) -> dict[str, Any]:
        """A user accepts the pending change for themselves; only user-acceptable changes."""
        with self._lock:
            entry = self.pending().get(key)
            if not self.allow_user:
                raise PermissionError("user re-approval is not allowed on this gateway")
            if not entry or not entry.get("classification", {}).get("user_acceptable"):
                raise PermissionError("this change needs the administrator")
            data = self._read(ACCEPTANCES)
            record = {"schema_hash": entry["schema_hash"], "description_sha256": entry["description_sha256"],
                      "accepted_at": _now()}
            data.setdefault("users", {}).setdefault(user, {})[key] = record
            self._write(ACCEPTANCES, data)
            return record

    # writing (administrator) -----------------------------------------------------

    def approve(self, key: str, approver: str, *, schema_hash: str | None = None,
                external_send: bool | None = None) -> dict[str, Any]:
        """Approve the pending definition; ``schema_hash`` guards against a change since it was shown."""
        with self._lock:
            pending = self._read(PENDING)
            entry = pending.get("definitions", {}).get(key)
            if not entry:
                raise KeyError(f"nothing pending for {key}")
            if schema_hash is not None and schema_hash != entry["schema_hash"]:
                raise ValueError("the pending definition changed since it was shown; show it again")
            record = {"schema_hash": entry["schema_hash"], "description_sha256": entry["description_sha256"],
                      "approved_by": approver, "approved_at": _now()}
            if external_send is not None:
                record["external_send"] = external_send
            data = self._read(APPROVALS)
            data.setdefault("definitions", {})[key] = record
            self._write(APPROVALS, data)
            del pending["definitions"][key]
            self._write(PENDING, pending)
            return record

    def reject(self, key: str) -> None:
        with self._lock:
            pending = self._read(PENDING)
            if key not in pending.get("definitions", {}):
                raise KeyError(f"nothing pending for {key}")
            del pending["definitions"][key]
            self._write(PENDING, pending)

    def revoke(self, user: str, key: str) -> None:
        with self._lock:
            data = self._read(ACCEPTANCES)
            if key not in data.get("users", {}).get(user, {}):
                raise KeyError(f"{user} has not accepted {key}")
            del data["users"][user][key]
            if not data["users"][user]:
                del data["users"][user]
            self._write(ACCEPTANCES, data)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
