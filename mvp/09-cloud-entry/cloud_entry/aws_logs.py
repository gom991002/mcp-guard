"""M1 audit sink: AWS CloudWatch Logs, the main remote store (D6-22).

Events are queued and sent by a background thread with PutLogEvents, so a slow
or failing CloudWatch never holds a request. The gateway also writes the local
JSON Lines file (``TeeAuditSink``), which is the copy to rely on when
CloudWatch is down: CloudWatch rejects events older than 14 days, so an outage
longer than that cannot be backfilled from this queue.

PutLogEvents limits kept here: a batch is at most 1,048,576 bytes (messages plus
26 bytes per event) and 10,000 events, sorted by time, spanning at most 24 hours.
The log group is created by the operator, with its retention and deletion
protection; this sink creates only its own log stream.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Callable
from typing import Any, TextIO

from .aws_secrets import AwsApiError, AwsCredentials, AwsJsonApi

_MAX_BATCH_BYTES = 1_048_576
_EVENT_OVERHEAD = 26
_MAX_BATCH_EVENTS = 10_000
_MAX_EVENT_BYTES = _MAX_BATCH_BYTES - _EVENT_OVERHEAD
_MAX_SPAN_MS = 24 * 3600 * 1000
# CloudWatch rejects events older than 14 days; keep an hour of margin.
_MAX_AGE_MS = (14 * 24 - 1) * 3600 * 1000


class CloudWatchLogsSink:
    def __init__(
        self,
        region: str,
        log_group: str,
        log_stream: str,
        credentials: Callable[[], AwsCredentials],
        endpoint: str | None = None,
        flush_seconds: float = 2.0,
        max_queue: int = 10_000,
        max_batch_events: int = _MAX_BATCH_EVENTS,
        log: TextIO | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._api = AwsJsonApi("logs", "Logs_20140328", region, credentials, endpoint)
        self._group = log_group
        self._stream = log_stream
        self._flush_seconds = flush_seconds
        self._max_queue = max_queue
        self._max_batch_events = min(max_batch_events, _MAX_BATCH_EVENTS)
        self._log = log
        self._now = now
        self._queue: list[tuple[int, str]] = []
        self._cond = threading.Condition()
        self._send_lock = threading.Lock()
        self._stopping = False
        self._failing = False
        self._thread = threading.Thread(target=self._run, daemon=True, name="mcp-guard-cloudwatch")
        self._thread.start()

    def emit(self, event: Any) -> None:
        message = json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"), default=str)
        if len(message.encode("utf-8")) > _MAX_EVENT_BYTES:
            raise OSError("audit event is larger than a CloudWatch Logs event may be")
        with self._cond:
            if len(self._queue) >= self._max_queue:
                raise OSError("CloudWatch Logs queue is full; the event is only in the local copy")
            self._queue.append((int(event.timestamp.timestamp() * 1000), message))
            if len(self._queue) >= self._max_batch_events:
                self._cond.notify()

    def flush(self) -> None:
        """Send everything queued now; failed batches stay queued."""
        self._send_pending()

    def close(self) -> None:
        with self._cond:
            self._stopping = True
            self._cond.notify()
        self._thread.join(timeout=30)
        self._send_pending()

    def pending(self) -> int:
        with self._cond:
            return len(self._queue)

    # background --------------------------------------------------------------

    def _run(self) -> None:
        while True:
            with self._cond:
                self._cond.wait_for(
                    lambda: self._stopping or len(self._queue) >= self._max_batch_events,
                    timeout=self._flush_seconds)
                stopping = self._stopping
            self._send_pending()
            if stopping:
                return

    def _send_pending(self) -> None:
        with self._send_lock:
            with self._cond:
                pending, self._queue = sorted(self._queue), []
            if not pending:
                return
            cutoff = int(self._now() * 1000) - _MAX_AGE_MS
            fresh = [item for item in pending if item[0] >= cutoff]
            if len(fresh) < len(pending):
                self._warn(f"dropped {len(pending) - len(fresh)} audit events older than 14 days "
                           "from the CloudWatch queue (they remain in the local copy)")
            remaining = fresh
            while remaining:
                batch, remaining = self._next_batch(remaining)
                try:
                    self._put(batch)
                except AwsApiError as error:
                    with self._cond:  # keep order: the failed batch goes back to the front
                        self._queue = batch + remaining + self._queue
                    if not self._failing:
                        self._warn(f"CloudWatch Logs write failed, will retry: {error}")
                    self._failing = True
                    return
            if self._failing:
                self._warn("CloudWatch Logs writes recovered")
            self._failing = False

    def _next_batch(self, events: list[tuple[int, str]]) -> tuple[list[tuple[int, str]],
                                                                   list[tuple[int, str]]]:
        size, end = 0, 0
        first = events[0][0]
        for timestamp, message in events:
            cost = len(message.encode("utf-8")) + _EVENT_OVERHEAD
            if (end >= self._max_batch_events or size + cost > _MAX_BATCH_BYTES
                    or timestamp - first > _MAX_SPAN_MS):
                break
            size, end = size + cost, end + 1
        return events[:end], events[end:]

    def _put(self, batch: list[tuple[int, str]]) -> None:
        payload = {"logGroupName": self._group, "logStreamName": self._stream,
                   "logEvents": [{"timestamp": t, "message": m} for t, m in batch]}
        try:
            result = self._api.call("PutLogEvents", payload)
        except AwsApiError as error:
            if error.code != "ResourceNotFoundException":
                raise
            self._create_stream()
            result = self._api.call("PutLogEvents", payload)
        rejected = result.get("rejectedLogEventsInfo")
        if rejected:
            self._warn(f"CloudWatch Logs rejected some audit events: {rejected}")

    def _create_stream(self) -> None:
        try:
            self._api.call("CreateLogStream", {"logGroupName": self._group,
                                               "logStreamName": self._stream})
        except AwsApiError as error:
            if error.code != "ResourceAlreadyExistsException":
                raise

    def _warn(self, text: str) -> None:
        print(f"mcp-guard: {text}", file=self._log or sys.stderr, flush=True)
