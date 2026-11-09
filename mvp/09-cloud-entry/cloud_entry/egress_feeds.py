"""Published egress ranges of LLM clients, kept current for the IP delay (MVP 5).

Many users of one hosted client reach the gateway from the same addresses,
so those ranges are "shared egress": IP-only delay rules skip them for
signed-in /mcp requests (the per-token rule still counts each user). Some
providers publish their ranges as a file that changes over time:

* chatgpt: https://openai.com/chatgpt-connectors.json (``creationTime`` and
  ``prefixes`` of ``ipv4Prefix``/``ipv6Prefix``), fetched on 2026-11-04.

Anthropic lists its outbound ranges on a documentation page, not in a file,
and Gemini Enterprise has no published list (dynamic Google ranges, or static
addresses per data store shown in the console); give those with
--shared-egress.

The gateway fetches each feed at start and once a day over HTTPS without
redirects. A failed or malformed fetch keeps the last good list, saved beside
the other gateway state, and is recorded; after seven days without a good
fetch every refresh records that the list is stale. A prefix broader than
/12 (IPv4) or /32 (IPv6) is refused as implausible for one provider's egress
(design discussion), so a broken file cannot exempt most of the internet.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

from mcp_guard.audit import AuditRecorder, audit_event

FEEDS = {"chatgpt": "https://openai.com/chatgpt-connectors.json"}
REFRESH_SECONDS = 24 * 3600
STALE_SECONDS = 7 * 24 * 3600
MAX_BYTES = 1_000_000
MAX_PREFIXES = 10_000
MIN_PREFIXLEN = {4: 12, 6: 32}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("egress feed redirected")


def fetch(url: str, timeout: float = 20) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("egress feeds are fetched over https only")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(urllib.request.Request(url, headers={"accept": "application/json"}), timeout=timeout) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("egress feed is too large")
    return body


def parse(raw: bytes) -> tuple[str, tuple[str, ...]]:
    """The feed's creation time and its prefixes, or ValueError for anything unexpected."""
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("prefixes"), list):
        raise ValueError("egress feed has no prefixes list")
    prefixes = []
    for item in data["prefixes"]:
        if not isinstance(item, dict):
            raise ValueError("egress feed prefix is not an object")
        values = [v for k, v in item.items() if k in ("ipv4Prefix", "ipv6Prefix")]
        if len(values) != 1 or not isinstance(values[0], str):
            raise ValueError("egress feed prefix needs one ipv4Prefix or ipv6Prefix")
        network = ipaddress.ip_network(values[0])  # strict: host bits must be zero
        if network.prefixlen < MIN_PREFIXLEN[network.version]:
            raise ValueError(f"egress feed prefix {network} is broader than /{MIN_PREFIXLEN[network.version]}")
        prefixes.append(str(network))
    if not prefixes or len(prefixes) > MAX_PREFIXES:
        raise ValueError(f"egress feed has {len(prefixes)} prefixes")
    return str(data.get("creationTime", "")), tuple(sorted(set(prefixes)))


class EgressFeed:
    def __init__(self, name: str, state_dir: str | Path, apply: Callable[[str, tuple[str, ...]], None], *,
                 url: str | None = None, audit: AuditRecorder | None = None,
                 fetcher: Callable[[str], bytes] = fetch, clock: Callable[[], float] = time.time) -> None:
        self.name, self.url = name, url or FEEDS[name]
        self._cache = Path(state_dir) / f"egress-{name}.json"
        self._apply, self._audit, self._fetch, self._clock = apply, audit or AuditRecorder(), fetcher, clock
        self._fetched_at: float | None = None

    def load_cached(self) -> bool:
        """Apply the last good list saved by an earlier run, if any."""
        try:
            data = json.loads(self._cache.read_text(encoding="utf-8"))
            prefixes = tuple(str(ipaddress.ip_network(p)) for p in data["prefixes"])
            self._fetched_at = float(data["fetched_at"])
        except (OSError, ValueError, KeyError, TypeError):
            return False
        self._apply(self.name, prefixes)
        return True

    def refresh(self) -> bool:
        now = self._clock()
        try:
            created, prefixes = parse(self._fetch(self.url))
        except (OSError, ValueError, UnicodeDecodeError) as error:
            stale = self._fetched_at is None or now - self._fetched_at >= STALE_SECONDS
            self._record("failed", error=type(error).__name__, message=str(error)[:200],
                         kept_last_good=self._fetched_at is not None, stale=stale,
                         last_good_at=self._fetched_at)
            return False
        self._cache.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._cache.with_suffix(".tmp")
        temporary.write_text(json.dumps({"url": self.url, "fetched_at": now, "creation_time": created,
                                         "prefixes": list(prefixes)}, indent=1), encoding="utf-8")
        os.replace(temporary, self._cache)
        self._fetched_at = now
        self._apply(self.name, prefixes)
        self._record("updated", prefixes=len(prefixes), creation_time=created)
        return True

    def run_forever(self, stop: threading.Event, interval: float = REFRESH_SECONDS) -> None:
        self.load_cached()
        while not stop.is_set():
            self.refresh()
            stop.wait(interval)

    def _record(self, outcome: str, **details: Any) -> None:
        self._audit.record(audit_event("shared_egress_updated", verdict="" if outcome == "updated" else "block",
                                       details={"feed": self.name, "url": self.url, "outcome": outcome, **details}))


class SharedEgress:
    """Joins the feeds' lists and hands the union to the throttle."""

    def __init__(self, set_networks: Callable[[tuple[str, ...]], None]) -> None:
        self._set, self._lists, self._lock = set_networks, {}, threading.Lock()

    def apply(self, name: str, prefixes: tuple[str, ...]) -> None:
        with self._lock:
            self._lists[name] = prefixes
            self._set(tuple(sorted({p for values in self._lists.values() for p in values})))
