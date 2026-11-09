"""Bounded cache for actual upstream tool lists."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import RLock
from typing import Callable

from .models import LiveToolsListClient, ToolListSnapshot, UpstreamServer


@dataclass(frozen=True)
class _CacheEntry:
    snapshot: ToolListSnapshot
    expires_at: float


class LiveToolCatalog:
    def __init__(
        self, client: LiveToolsListClient, *, max_ttl_ms: int = 60_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_ttl_ms < 0:
            raise ValueError("max_ttl_ms must be nonnegative")
        self._client = client
        self._max_ttl_ms = max_ttl_ms
        self._clock = clock
        self._entries: dict[tuple[str, str, str, str, str], _CacheEntry] = {}
        self._locks: dict[tuple[str, str, str, str, str], RLock] = {}
        self._guard = RLock()

    def get(self, upstream: UpstreamServer, *, force: bool = False) -> ToolListSnapshot:
        return self.get_with_source(upstream, force=force)[0]

    def get_with_source(self, upstream: UpstreamServer, *, force: bool = False) -> tuple[ToolListSnapshot, bool]:
        """Return a snapshot and whether this request reused a cached copy."""
        key = (
            upstream.name, upstream.namespace, upstream.transport,
            upstream.url, upstream.source,
        )
        with self._guard:
            lock = self._locks.setdefault(key, RLock())
        with lock:
            entry = self._entries.get(key)
            if not force and entry is not None and self._clock() < entry.expires_at:
                return entry.snapshot, True
            try:
                snapshot = self._client.fetch(upstream)
            except (OSError, ValueError, ConnectionError, TimeoutError):
                self._entries.pop(key, None)
                raise
            if snapshot.cache_scope == "public" and snapshot.ttl_ms > 0:
                ttl_ms = min(snapshot.ttl_ms, self._max_ttl_ms)
                self._entries[key] = _CacheEntry(
                    snapshot, self._clock() + ttl_ms / 1000,
                )
            else:
                self._entries.pop(key, None)
            return snapshot, False

    def invalidate(self, server_name: str) -> None:
        with self._guard:
            keys = [key for key in self._locks if key[0] == server_name]
        for key in keys:
            with self._locks[key]:
                self._entries.pop(key, None)
