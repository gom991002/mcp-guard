from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Window bounds follow the widest range offered by Cloudflare rate limiting
# periods and Google Cloud Armor interval_sec (10 s to 3600 s).
MIN_WINDOW_SECONDS = 10
MAX_WINDOW_SECONDS = 3600


@dataclass(frozen=True)
class RateRule:
    """Count requests per key inside a trailing window (AWS WAF rate-based rule style)."""

    name: str
    window_seconds: int
    limit: int
    key_headers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or "|" in self.name:
            raise ValueError("rule name must be non-empty and must not contain '|'")
        if not MIN_WINDOW_SECONDS <= self.window_seconds <= MAX_WINDOW_SECONDS:
            raise ValueError(
                f"window_seconds must be between {MIN_WINDOW_SECONDS} and {MAX_WINDOW_SECONDS}"
            )
        if self.limit < 1:
            raise ValueError("limit must be at least 1")
        if not all(isinstance(header, str) and header for header in self.key_headers):
            raise ValueError("key_headers must contain non-empty header names")
        object.__setattr__(
            self, "key_headers", tuple(header.lower() for header in self.key_headers)
        )


# Per-IP: OWASP CRS DoS protection plugin default (100 requests in 60 seconds).
# Per-client: nginx limit_req documentation example rate (1 request per second).
# The per-IP rule ignores headers, so rotating header values cannot raise the
# per-IP budget (same idea as nginx's combined perip/perserver zones).
DEFAULT_RULES: tuple[RateRule, ...] = (
    RateRule(name="per-ip", window_seconds=60, limit=100),
    RateRule(
        name="per-client",
        window_seconds=60,
        limit=60,
        key_headers=("authorization", "user-agent"),
    ),
)


@dataclass(frozen=True)
class BanPolicy:
    """Reject a key that keeps getting delayed, instead of delaying it again.

    Defaults follow fail2ban (maxretry 5 within findtime 10m, bantime 10m,
    bantime.increment doubling) and OWASP CRS DoS protection (block 600 s).
    The cap is Google Cloud Armor's longest ban_duration_sec (3600 s).
    """

    strikes: int = 5
    findtime_seconds: int = 600
    ban_seconds: int = 600
    max_ban_seconds: int = 3600
    # How long an earlier ban counts toward doubling (design discussion).
    repeat_window_seconds: int = 86_400

    def __post_init__(self) -> None:
        if self.strikes < 1:
            raise ValueError("strikes must be at least 1")
        if not MIN_WINDOW_SECONDS <= self.findtime_seconds <= MAX_WINDOW_SECONDS:
            raise ValueError("findtime_seconds must be between 10 and 3600")
        # Cloud Armor ban_duration_sec range 60-3600; Cloudflare allows up to 86400.
        if not 60 <= self.ban_seconds <= self.max_ban_seconds <= 86_400:
            raise ValueError("ban seconds must satisfy 60 <= ban <= max_ban <= 86400")
        if self.repeat_window_seconds < self.max_ban_seconds:
            raise ValueError("repeat_window_seconds must cover max_ban_seconds")


@dataclass(frozen=True)
class ThrottlePolicy:
    rules: tuple[RateRule, ...] = DEFAULT_RULES
    max_delay_seconds: float = 30.0
    max_tracked_keys: int = 10_000
    ban: BanPolicy | None = BanPolicy()
    # Egress ranges shared by many users (e.g. Anthropic's 160.79.104.0/21):
    # IP-only rules are skipped there so one busy user cannot ban everyone.
    shared_networks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.rules:
            raise ValueError("rules must not be empty")
        names = [rule.name for rule in self.rules]
        if len(names) != len(set(names)):
            raise ValueError("rule names must be unique")
        if self.max_delay_seconds <= 0:
            raise ValueError("max_delay_seconds must be positive")
        if self.max_tracked_keys < len(self.rules):
            raise ValueError("max_tracked_keys must allow at least one key per rule")
        for cidr in self.shared_networks:
            ipaddress.ip_network(cidr)  # raises ValueError on a bad CIDR


@dataclass(frozen=True)
class ThrottleDecision:
    ip_address: str
    should_delay: bool
    delay_seconds: float
    reason: str
    rule_name: str = ""
    counted_requests: int = 0
    limit: int = 0
    window_seconds: int = 0
    rejected: bool = False
    retry_after_seconds: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "rejected": self.rejected,
            "retry_after_seconds": round(self.retry_after_seconds, 3),
            "ip_address": self.ip_address,
            "should_delay": self.should_delay,
            "delay_seconds": round(self.delay_seconds, 3),
            "reason": self.reason,
            "rule_name": self.rule_name,
            "counted_requests": self.counted_requests,
            "limit": self.limit,
            "window_seconds": self.window_seconds,
        }
