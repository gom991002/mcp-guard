from __future__ import annotations

import threading
from collections import OrderedDict, deque
from datetime import datetime, timedelta


class SlidingWindowStore:
    """Temporary in-memory request log, one entry per rate-limit key.

    Each key keeps at most ``keep`` recent timestamps, so memory per key stays
    bounded the way nginx keeps a fixed-size state per key. Keys expire once
    their window has passed, and the least recently used key is evicted when
    the store is full (nginx ``limit_req_zone`` behaviour).
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be positive")
        self._max_keys = max_keys
        self._entries: OrderedDict[str, tuple[timedelta, deque[datetime]]] = OrderedDict()
        self._lock = threading.Lock()

    def hit(
        self,
        key: str,
        now: datetime,
        window_seconds: int,
        keep: int,
    ) -> tuple[datetime, ...]:
        """Record one request and return the key's timestamps inside the window, oldest first."""
        window = timedelta(seconds=window_seconds)
        with self._lock:
            self._expire(now)
            entry = self._entries.get(key)
            if entry is None:
                entry = (window, deque(maxlen=keep))
                self._entries[key] = entry
            else:
                self._entries.move_to_end(key)
            timestamps = entry[1]
            timestamps.append(now)
            while timestamps and timestamps[0] <= now - window:
                timestamps.popleft()
            while len(self._entries) > self._max_keys:
                self._entries.popitem(last=False)
            return tuple(timestamps)

    def forget(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def keys(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _expire(self, now: datetime) -> None:
        # Entries are kept in last-hit order, so expired keys gather at the front.
        # Keys with a shorter window behind a live key wait for a later pass;
        # max_keys still bounds the store in the meantime.
        while self._entries:
            key, (window, timestamps) = next(iter(self._entries.items()))
            if timestamps and timestamps[-1] > now - window:
                return
            del self._entries[key]
