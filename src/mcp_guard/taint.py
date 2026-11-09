"""Session taint state (M4, stage 3): which sessions have taken in third-party content.

A session is the mcp-guard unit described in Docs/Core_mds/architecture.md (one client
conversation or agent run). Taint is never cleared within a session; B
signals cannot clear it either. Each session is one small JSON file so that
concurrent hook processes do not overwrite each other.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class TaintRecord:
    session_id: str
    first_source: str
    tainted_at: str


class SessionTaintStore:
    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    def mark(self, session_id: str, source: str, now: datetime | None = None) -> TaintRecord:
        """Mark a session tainted; the first source is kept."""
        existing = self.get(session_id)
        if existing is not None:
            return existing
        record = TaintRecord(session_id, source, (now or datetime.now(UTC)).isoformat())
        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._path(session_id)
        temporary = path.with_suffix(f".{os.getpid()}.tmp")
        temporary.write_text(json.dumps(record.__dict__), encoding="utf-8")
        os.replace(temporary, path)
        return record

    def get(self, session_id: str) -> TaintRecord | None:
        path = self._path(session_id)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return TaintRecord(**payload)

    def _path(self, session_id: str) -> Path:
        if not session_id:
            raise ValueError("session_id is required")
        name = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
        return self._directory / f"{name}.json"
