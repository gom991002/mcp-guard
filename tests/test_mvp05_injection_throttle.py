import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mvp" / "05-indirect-injection-throttle"))

from injection_throttle import (  # noqa: E402
    DEFAULT_RULES,
    BanPolicy,
    RateRule,
    RequestRateThrottle,
    SlidingWindowStore,
    ThrottlePolicy,
)

IP = "203.0.113.10"


class RequestRateThrottleTests(unittest.TestCase):
    now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)

    def _throttle(self, *rules: RateRule, **policy: object) -> RequestRateThrottle:
        return RequestRateThrottle(ThrottlePolicy(rules=rules, **policy))

    def _send(self, throttle, count, headers=None, step=1.0, ip=IP):
        decision = None
        for index in range(count):
            decision = throttle.check(
                ip, headers or {}, self.now + timedelta(seconds=index * step)
            )
        return decision

    def test_requests_within_limit_are_not_delayed(self) -> None:
        throttle = self._throttle(RateRule("per-ip", window_seconds=60, limit=3))

        decision = self._send(throttle, 3)

        self.assertFalse(decision.should_delay)
        self.assertEqual(decision.delay_seconds, 0)

    def test_request_over_limit_waits_until_oldest_leaves_window(self) -> None:
        throttle = self._throttle(RateRule("per-ip", window_seconds=60, limit=3))

        decision = self._send(throttle, 4, step=10.0)

        # Requests at 0, 10, 20, 30 s: the one at 0 s leaves the window at 60 s.
        self.assertTrue(decision.should_delay)
        self.assertAlmostEqual(decision.delay_seconds, 30.0)
        self.assertEqual(decision.rule_name, "per-ip")
        self.assertEqual(decision.limit, 3)
        self.assertEqual(decision.window_seconds, 60)

    def test_delay_is_capped(self) -> None:
        throttle = self._throttle(
            RateRule("per-ip", window_seconds=600, limit=1), max_delay_seconds=5.0
        )

        decision = self._send(throttle, 2)

        self.assertEqual(decision.delay_seconds, 5.0)

    def test_count_resets_after_window(self) -> None:
        throttle = self._throttle(RateRule("per-ip", window_seconds=60, limit=2))
        self._send(throttle, 3)

        decision = throttle.check(IP, {}, self.now + timedelta(seconds=200))

        self.assertFalse(decision.should_delay)

    def test_other_ips_are_counted_separately(self) -> None:
        throttle = self._throttle(RateRule("per-ip", window_seconds=60, limit=2))
        self._send(throttle, 5)

        decision = throttle.check("198.51.100.7", {}, self.now)

        self.assertFalse(decision.should_delay)

    def test_header_rule_separates_clients_behind_one_ip(self) -> None:
        throttle = self._throttle(
            RateRule("per-client", window_seconds=60, limit=2, key_headers=("User-Agent",))
        )
        self._send(throttle, 3, headers={"user-agent": "agent-a"})

        decision = throttle.check(IP, {"User-Agent": "agent-b"}, self.now)

        self.assertFalse(decision.should_delay)

    def test_rotating_headers_still_hit_per_ip_rule(self) -> None:
        throttle = self._throttle(
            RateRule("per-ip", window_seconds=60, limit=5),
            RateRule("per-client", window_seconds=60, limit=2, key_headers=("user-agent",)),
        )

        decision = None
        for index in range(6):
            decision = throttle.check(
                IP, {"user-agent": f"rotated-{index}"}, self.now + timedelta(seconds=index)
            )

        self.assertTrue(decision.should_delay)
        self.assertEqual(decision.rule_name, "per-ip")

    def test_missing_header_is_counted_not_skipped(self) -> None:
        throttle = self._throttle(
            RateRule("per-client", window_seconds=60, limit=2, key_headers=("authorization",))
        )

        decision = self._send(throttle, 3, headers={})

        self.assertTrue(decision.should_delay)

    def test_store_keeps_header_digests_not_raw_values(self) -> None:
        store = SlidingWindowStore()
        throttle = RequestRateThrottle(
            ThrottlePolicy(
                rules=(RateRule("per-client", 60, 5, key_headers=("authorization",)),)
            ),
            store=store,
        )

        throttle.check(IP, {"Authorization": "Bearer secret-token"}, self.now)

        self.assertEqual(len(store), 1)
        self.assertNotIn("secret-token", store.keys()[0])

    def test_store_evicts_least_recently_used_key(self) -> None:
        store = SlidingWindowStore(max_keys=2)
        for index, key in enumerate(("a", "b", "a", "c")):
            store.hit(key, self.now + timedelta(seconds=index), 60, keep=5)

        self.assertEqual(store.keys(), ("a", "c"))

    def test_store_expires_keys_after_window(self) -> None:
        store = SlidingWindowStore()
        store.hit("a", self.now, 60, keep=5)

        store.hit("b", self.now + timedelta(seconds=61), 60, keep=5)

        self.assertEqual(store.keys(), ("b",))

    def test_store_memory_per_key_is_bounded(self) -> None:
        store = SlidingWindowStore()
        recent = ()
        for index in range(50):
            recent = store.hit("a", self.now + timedelta(seconds=index * 0.1), 60, keep=4)

        self.assertEqual(len(recent), 4)

    def test_default_rules_follow_documented_values(self) -> None:
        rules = {rule.name: rule for rule in DEFAULT_RULES}

        self.assertEqual((rules["per-ip"].window_seconds, rules["per-ip"].limit), (60, 100))
        self.assertEqual(
            (rules["per-client"].window_seconds, rules["per-client"].limit), (60, 60)
        )
        self.assertEqual(rules["per-client"].key_headers, ("authorization", "user-agent"))

    def test_rejects_window_outside_firewall_range(self) -> None:
        for window in (9, 3601):
            with self.subTest(window=window):
                with self.assertRaisesRegex(ValueError, "window_seconds"):
                    RateRule("bad", window_seconds=window, limit=10)

    def test_rejects_invalid_policy(self) -> None:
        with self.assertRaisesRegex(ValueError, "limit"):
            RateRule("bad", window_seconds=60, limit=0)
        with self.assertRaisesRegex(ValueError, "unique"):
            ThrottlePolicy(rules=(RateRule("a", 60, 1), RateRule("a", 60, 2)))
        with self.assertRaisesRegex(ValueError, "rules"):
            ThrottlePolicy(rules=())


class BanTests(unittest.TestCase):
    now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)

    def _throttle(self, **policy) -> RequestRateThrottle:
        return RequestRateThrottle(ThrottlePolicy(
            rules=(RateRule("per-ip", window_seconds=60, limit=1),), **policy))

    def _hammer(self, throttle, count, start=0.0, ip=IP):
        return [throttle.check(ip, {}, self.now + timedelta(seconds=start + i)) for i in range(count)]

    def test_defaults_follow_fail2ban_and_cloud_armor(self) -> None:
        ban = BanPolicy()

        self.assertEqual((ban.strikes, ban.findtime_seconds, ban.ban_seconds), (5, 600, 600))
        self.assertEqual(ban.max_ban_seconds, 3600)

    def test_fifth_delay_in_findtime_bans_the_key(self) -> None:
        decisions = self._hammer(self._throttle(), 6)

        # Request 1 passes, requests 2-5 are delayed (4 strikes), request 6 is the 5th strike.
        self.assertEqual([d.should_delay for d in decisions[1:5]], [True] * 4)
        self.assertTrue(decisions[5].rejected)
        self.assertEqual(decisions[5].retry_after_seconds, 600)

    def test_banned_requests_are_rejected_without_counting(self) -> None:
        throttle = self._throttle()
        self._hammer(throttle, 6)

        during = self._hammer(throttle, 3, start=100)
        after = throttle.check(IP, {}, self.now + timedelta(seconds=5 + 601))

        self.assertTrue(all(d.rejected for d in during))
        self.assertFalse(after.rejected)

    def test_repeat_bans_double_up_to_the_cap(self) -> None:
        throttle = self._throttle()
        lengths, start = [], 0.0
        for _ in range(5):
            decisions = self._hammer(throttle, 6, start=start)
            lengths.append(decisions[-1].retry_after_seconds)
            start += decisions[-1].retry_after_seconds + 10

        self.assertEqual(lengths, [600, 1200, 2400, 3600, 3600])

    def test_other_ips_are_not_affected(self) -> None:
        throttle = self._throttle()
        self._hammer(throttle, 6)

        self.assertFalse(throttle.check("198.51.100.7", {}, self.now + timedelta(seconds=7)).rejected)

    def test_shared_egress_skips_ip_only_rules(self) -> None:
        throttle = RequestRateThrottle(ThrottlePolicy(
            rules=(RateRule("per-ip", 60, 1),
                   RateRule("per-client", 60, 1, key_headers=("authorization",))),
            shared_networks=("160.79.104.0/21",)))
        shared_ip = "160.79.104.20"

        for user in ("a", "b", "c", "d", "e", "f"):
            decision = throttle.check(shared_ip, {"authorization": f"Bearer {user}"}, self.now)
            self.assertFalse(decision.should_delay or decision.rejected)
        self.assertTrue(throttle.check(shared_ip, {"authorization": "Bearer a"}, self.now).should_delay)

    def test_ban_can_be_disabled_and_is_validated(self) -> None:
        decisions = self._hammer(self._throttle(ban=None), 10)
        self.assertFalse(any(d.rejected for d in decisions))
        with self.assertRaises(ValueError):
            BanPolicy(ban_seconds=30)
        with self.assertRaises(ValueError):
            ThrottlePolicy(shared_networks=("not-a-cidr",))


if __name__ == "__main__":
    unittest.main()
