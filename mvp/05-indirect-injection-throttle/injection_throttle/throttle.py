from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import threading
from collections import OrderedDict
from datetime import datetime, timedelta

from .models import RateRule, ThrottleDecision, ThrottlePolicy
from .store import SlidingWindowStore


class RequestRateThrottle:
    """Delay a client whose request count inside a rule's window exceeds its limit,
    and reject (ban) a client that keeps getting delayed."""

    def __init__(
        self,
        policy: ThrottlePolicy | None = None,
        store: SlidingWindowStore | None = None,
    ) -> None:
        self._policy = policy or ThrottlePolicy()
        # An empty store is falsy (it defines __len__), so compare with None.
        self._store = (
            store if store is not None
            else SlidingWindowStore(self._policy.max_tracked_keys)
        )
        self._strikes = SlidingWindowStore(self._policy.max_tracked_keys)
        # key -> (banned until, ban count, last ban start)
        self._bans: OrderedDict[str, tuple[datetime, int, datetime]] = OrderedDict()
        self._bans_lock = threading.Lock()
        self._configured_shared = tuple(ipaddress.ip_network(c) for c in self._policy.shared_networks)
        self._shared = self._configured_shared
        # Header values such as Authorization are stored only as keyed digests.
        self._digest_key = secrets.token_bytes(16)

    def set_fetched_shared_networks(self, cidrs: tuple[str, ...]) -> None:
        """Add shared egress ranges from a published feed to the configured ones (replaces the last set)."""
        fetched = tuple(ipaddress.ip_network(c) for c in cidrs)
        self._shared = self._configured_shared + fetched  # one assignment: readers see old or new

    def check(
        self,
        ip_address: str,
        headers: dict[str, str],
        now: datetime,
        signed_in: bool = True,
    ) -> ThrottleDecision:
        """Record one request and decide whether it waits, is rejected, or passes.

        ``signed_in``: the request carries a valid gateway token. Shared egress
        ranges skip the IP-only rules only then; sign-in and token requests
        from a shared range are still counted per IP, since anyone in that
        range can send them with any header values.
        """
        keys = [(rule, self._key(rule, ip_address, headers))
                for rule in self._rules_for(ip_address, signed_in)]
        for rule, key in keys:
            banned = self._banned_until(key, now)
            if banned is not None:  # rejected requests are not counted
                return self._rejected(ip_address, rule, banned - now, "banned after repeated delays")
        worst: ThrottleDecision | None = None
        for rule, key in keys:
            recent = self._store.hit(key, now, rule.window_seconds, keep=rule.limit + 1)
            if len(recent) <= rule.limit:
                continue
            ban = self._strike(key, now)
            if ban is not None:
                return self._rejected(ip_address, rule, ban, f"{rule.name} kept exceeding its limit")
            # The client is back under the limit once the oldest kept request
            # leaves the window.
            wait = recent[0] + timedelta(seconds=rule.window_seconds) - now
            delay = min(self._policy.max_delay_seconds, wait.total_seconds())
            if worst is None or delay > worst.delay_seconds:
                worst = ThrottleDecision(
                    ip_address=ip_address,
                    should_delay=True,
                    delay_seconds=delay,
                    reason=f"{rule.name} limit exceeded",
                    rule_name=rule.name,
                    counted_requests=len(recent),
                    limit=rule.limit,
                    window_seconds=rule.window_seconds,
                )
        return worst or ThrottleDecision(
            ip_address=ip_address,
            should_delay=False,
            delay_seconds=0.0,
            reason="below rate limits",
        )

    def _rules_for(self, ip_address: str, signed_in: bool = True) -> tuple[RateRule, ...]:
        if not signed_in:
            return self._policy.rules
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return self._policy.rules
        if any(ip in network for network in self._shared):
            return tuple(rule for rule in self._policy.rules if rule.key_headers)
        return self._policy.rules

    def _strike(self, key: str, now: datetime) -> timedelta | None:
        """Count one delay; return the ban length when the strike limit is reached."""
        ban = self._policy.ban
        if ban is None:
            return None
        strikes = self._strikes.hit(f"strike|{key}", now, ban.findtime_seconds, keep=ban.strikes)
        if len(strikes) < ban.strikes:
            return None
        self._strikes.forget(f"strike|{key}")
        with self._bans_lock:
            previous = self._bans.pop(key, None)
            repeat = previous is not None and now - previous[2] < timedelta(
                seconds=ban.repeat_window_seconds)
            count = previous[1] + 1 if repeat else 1
            # fail2ban bantime.increment: 1, 2, 4, 8 ... times the base, capped.
            seconds = min(ban.max_ban_seconds, ban.ban_seconds * 2 ** (count - 1))
            self._bans[key] = (now + timedelta(seconds=seconds), count, now)
            self._prune(now)
        return timedelta(seconds=seconds)

    def _banned_until(self, key: str, now: datetime) -> datetime | None:
        with self._bans_lock:
            entry = self._bans.get(key)
        if entry is not None and entry[0] > now:
            return entry[0]
        return None

    def _prune(self, now: datetime) -> None:
        """Call with the bans lock held; drop records too old to escalate."""
        window = timedelta(seconds=self._policy.ban.repeat_window_seconds)
        for key in [k for k, v in self._bans.items() if now - v[2] >= window]:
            del self._bans[key]
        while len(self._bans) > self._policy.max_tracked_keys:
            self._bans.popitem(last=False)

    @staticmethod
    def _rejected(ip_address: str, rule: RateRule, wait: timedelta, reason: str) -> ThrottleDecision:
        return ThrottleDecision(
            ip_address=ip_address,
            should_delay=False,
            delay_seconds=0.0,
            reason=reason,
            rule_name=rule.name,
            limit=rule.limit,
            window_seconds=rule.window_seconds,
            rejected=True,
            retry_after_seconds=wait.total_seconds(),
        )

    def _key(self, rule: RateRule, ip_address: str, headers: dict[str, str]) -> str:
        if not rule.key_headers:
            return f"{rule.name}|{ip_address}"
        lowered = {name.lower(): value for name, value in headers.items()}
        # A missing header counts as an empty value, so omitting it does not
        # skip the rule (unlike AWS WAF, which skips requests missing a key).
        material = "\x00".join(
            f"{header}={lowered.get(header, '').strip()}" for header in rule.key_headers
        )
        digest = hmac.new(self._digest_key, material.encode("utf-8"), hashlib.sha256)
        return f"{rule.name}|{ip_address}|{digest.hexdigest()[:32]}"
