"""A signed-in user's "start a new session" for remote M4 taint (2026-11-04).

Claude and Gemini send no conversation id, so a signed-in user's gateway
session is the user within that client (D6-26) and its taint, never cleared
within a session, would last for good. The user can start a new session on the
approval page: the gateway then counts the user's later requests as a new
session. The old session and its taint record stay as they were; nothing in a
chat or a tool result can press the button (it needs the signed-in browser
session and a form token).

The gateway cannot tell which chat the user continues: starting a new session
helps only if the user also opens a new chat, as the page says.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from gateway_mvp.reapproval_store import JsonFolder

EPOCHS = "session-epochs.json"


class SessionEpochs(JsonFolder):
    def __init__(self, folder: str | Path) -> None:
        super().__init__(folder)

    def epoch(self, user: str) -> int:
        entry = self._read(EPOCHS).get("users", {}).get(user, {})
        value = entry.get("epoch", 0)
        return value if isinstance(value, int) and value >= 0 else 0

    def last_reset(self, user: str) -> str:
        return str(self._read(EPOCHS).get("users", {}).get(user, {}).get("reset_at", ""))

    def start_new(self, user: str) -> int:
        with self._lock:
            data = self._read(EPOCHS)
            entry = data.setdefault("users", {}).setdefault(user, {})
            entry["epoch"] = self.epoch(user) + 1
            entry["reset_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            self._write(EPOCHS, data)
            return entry["epoch"]
