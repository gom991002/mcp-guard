"""M1 correlation rules run on a schedule over the audit stream (D6-25).

Modeled on SIEM scheduled rules: Microsoft Sentinel runs a rule every interval
over a look-back period of 5 minutes to 14 days that must cover the interval,
and Elastic does not create an alert again for a match found inside the
look-back it already alerted on. Here the rules run every ``interval`` seconds
(default 5 minutes) over the last ``lookback`` seconds (default 24 hours, the
longest rule window), and a match is alerted once while it stays in the look-back.

Alerts are ``correlation_alert`` audit events. They go wherever the audit log
goes (the local copy and CloudWatch Logs), so operators route them with a
CloudWatch metric filter and alarm. Alerts never change a stage 2-4 decision.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from mcp_guard.audit import AuditFinding, AuditRecorder, RecentEventsSink, audit_event
from rule_sets.sigma_correlation_rules import correlate_events

DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_LOOKBACK_SECONDS = 24 * 3600


class CorrelationRunner:
    def __init__(
        self,
        window: RecentEventsSink,
        audit: AuditRecorder,
        interval: float = DEFAULT_INTERVAL_SECONDS,
        lookback: float = DEFAULT_LOOKBACK_SECONDS,
        correlate: Callable[[list[Any]], list[Any]] = correlate_events,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if lookback < interval:
            raise ValueError("look-back must cover the interval, or matches fall in the gap")
        self._window = window
        self._audit = audit
        self._interval = interval
        self._lookback = lookback
        self._correlate = correlate
        self._clock = clock
        self._alerted: dict[str, float] = {}  # match key -> when it was alerted

    def run_once(self) -> list[Any]:
        """Evaluate the rules once; return the matches alerted for the first time."""
        now = self._clock()
        window_events = self._window.events(datetime.fromtimestamp(now, UTC))
        events = [e for e in window_events if e.event_type != "correlation_alert"]
        self._alerted = {k: t for k, t in self._alerted.items()
                         if now - t <= self._lookback + self._interval}
        # The local audit copy is loaded into the window on startup. Rebuild
        # suppression from recorded alerts so a restart does not resend them.
        for event in window_events:
            if event.event_type != "correlation_alert":
                continue
            rule_id, metadata = event.details.get("rule_id"), event.details.get("metadata")
            if isinstance(rule_id, str) and isinstance(metadata, dict):
                key = json.dumps([rule_id, metadata], sort_keys=True, default=str)
                self._alerted[key] = event.timestamp.timestamp()
        fresh = []
        for match in self._correlate(events):
            metadata = {k: str(v) for k, v in match.metadata.items()}
            key = json.dumps([match.rule.rule_id, metadata], sort_keys=True, default=str)
            if key in self._alerted:
                continue
            self._alerted[key] = now
            fresh.append(match)
            self._audit.record(audit_event(
                "correlation_alert",
                server_name=metadata.get("server_name", metadata.get("call_server", "")),
                tool_name=metadata.get("tool_name", metadata.get("call_tool", "")),
                session_id=metadata.get("session_id", ""),
                finding_codes=(match.rule.rule_id,),
                findings=(AuditFinding(match.rule.rule_id, match.rule.marker, match.rule.stage),),
                details={"rule_id": match.rule.rule_id, "title": match.rule.title,
                         "severity": match.rule.severity.value, "message": match.message,
                         "metadata": metadata},
            ))
        return fresh

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.wait(self._interval):
            self.run_once()
