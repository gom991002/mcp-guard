"""Published client egress ranges for the IP delay, and the signed-in-only exemption."""

import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp", "mvp/05-indirect-injection-throttle",
               "mvp/06-http-gateway-server", "mvp/08-decision-controls", "mvp/09-cloud-entry"):
    sys.path.insert(0, str(ROOT / folder))

from cloud_entry.egress_feeds import STALE_SECONDS, EgressFeed, SharedEgress, fetch, parse  # noqa: E402
from injection_throttle import RateRule, RequestRateThrottle, ThrottlePolicy  # noqa: E402
from mcp_guard.audit import AuditRecorder  # noqa: E402

FEED = {"creationTime": "2026-10-27T18:18:51.926871",
        "prefixes": [{"ipv4Prefix": "9.129.0.0/16"}, {"ipv4Prefix": "104.192.219.204/30"},
                     {"ipv6Prefix": "2001:db8::/48"}]}


class _Sink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class ParseTests(unittest.TestCase):
    def test_the_published_shape_is_read(self):
        created, prefixes = parse(json.dumps(FEED).encode())
        self.assertEqual(created, "2026-10-27T18:18:51.926871")
        self.assertEqual(set(prefixes), {"9.129.0.0/16", "104.192.219.204/30", "2001:db8::/48"})

    def test_anything_unexpected_is_refused(self):
        for bad in ({"prefixes": []}, {"prefixes": [{"ipv4Prefix": "0.0.0.0/0"}]},
                    {"prefixes": [{"ipv4Prefix": "10.0.0.0/8"}]}, {"prefixes": [{"ipv4Prefix": "1.2.3.4/24"}]},
                    {"prefixes": [{"ipv4Prefix": "1.2.3.0/24", "ipv6Prefix": "2001:db8::/48"}]},
                    {"prefixes": ["1.2.3.0/24"]}, ["not", "an", "object"]):
            with self.assertRaises(ValueError, msg=bad):
                parse(json.dumps(bad).encode())
        with self.assertRaises(ValueError):
            parse(b"not json")

    def test_only_https_is_fetched(self):
        with self.assertRaises(ValueError):
            fetch("http://openai.com/chatgpt-connectors.json")


class FeedTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        self.now = [1_000_000.0]
        self.body = json.dumps(FEED).encode()
        self.applied = {}
        self.sink = _Sink()

    def tearDown(self):
        self._folder.cleanup()

    def _feed(self):
        def fetcher(url):
            if isinstance(self.body, Exception):
                raise self.body
            return self.body
        return EgressFeed("chatgpt", self._folder.name, self.applied.__setitem__,
                          audit=AuditRecorder(self.sink), fetcher=fetcher, clock=lambda: self.now[0])

    def test_a_good_fetch_is_applied_saved_and_recorded(self):
        self.assertTrue(self._feed().refresh())
        self.assertIn("9.129.0.0/16", self.applied["chatgpt"])
        self.assertEqual(self.sink.events[-1].details["outcome"], "updated")
        self.applied.clear()
        self.assertTrue(self._feed().load_cached())  # a restart starts from the saved list
        self.assertIn("9.129.0.0/16", self.applied["chatgpt"])

    def test_a_failed_fetch_keeps_the_last_good_list_and_says_when_it_is_stale(self):
        feed = self._feed()
        feed.refresh()
        self.body, self.applied = OSError("offline"), {}
        self.assertFalse(feed.refresh())
        self.assertEqual(self.applied, {})  # nothing replaced
        failed = self.sink.events[-1].details
        self.assertEqual((failed["outcome"], failed["kept_last_good"], failed["stale"]), ("failed", True, False))
        self.now[0] += STALE_SECONDS
        self.body = json.dumps({"prefixes": [{"ipv4Prefix": "0.0.0.0/0"}]}).encode()
        feed.refresh()
        self.assertTrue(self.sink.events[-1].details["stale"])
        self.assertEqual(self.sink.events[-1].event_type, "shared_egress_updated")

    def test_feeds_are_joined_for_the_throttle(self):
        got = []
        shared = SharedEgress(got.append)
        shared.apply("chatgpt", ("9.129.0.0/16",))
        shared.apply("other", ("104.192.219.204/30",))
        shared.apply("chatgpt", ("1.2.3.0/24",))
        self.assertEqual(got[-1], ("1.2.3.0/24", "104.192.219.204/30"))


class SignedInExemptionTests(unittest.TestCase):
    def _throttle(self):
        rules = (RateRule("per-ip", 60, 2), RateRule("per-client", 60, 100, key_headers=("authorization",)))
        throttle = RequestRateThrottle(ThrottlePolicy(rules=rules, ban=None))
        throttle.set_fetched_shared_networks(("9.129.0.0/16",))
        return throttle

    def test_shared_ranges_skip_ip_rules_only_for_signed_in_requests(self):
        now = datetime(2026, 11, 4, tzinfo=UTC)
        throttle = self._throttle()
        signed = [throttle.check("9.129.1.1", {"authorization": f"Bearer t{n}"}, now) for n in range(5)]
        self.assertFalse(any(d.should_delay for d in signed))
        anonymous = [throttle.check("9.129.1.1", {"authorization": f"Bearer x{n}"}, now, signed_in=False)
                     for n in range(5)]
        self.assertTrue(anonymous[-1].should_delay)
        self.assertEqual(anonymous[-1].rule_name, "per-ip")

    def test_the_adapter_counts_sign_in_traffic_from_shared_ranges_per_ip(self):
        from http_gateway.adapter import HttpGatewayAdapter
        from http_gateway.models import HttpRequest
        from gateway_mvp.models import GatewayConfig
        from mcp_guard.registry import GuardRegistry

        class Auth:
            def verify_bearer(self, authorization):
                return {"sub": "alice"} if authorization == "Bearer good" else None

        adapter = HttpGatewayAdapter(GatewayConfig(GuardRegistry.from_dict({}), ()), throttle=self._throttle(),
                                     auth=Auth())
        now = datetime(2026, 11, 4, tzinfo=UTC)

        def admit(path, token):
            request = HttpRequest("POST", path, {"authorization": token}, b"", client_ip="9.129.1.1")
            return adapter.admit(request, now)[1]

        self.assertFalse(any(admit("/mcp", "Bearer good").should_delay for _ in range(5)))
        self.assertTrue([admit("/token", f"Bearer forged{n}") for n in range(5)][-1].should_delay)


if __name__ == "__main__":
    unittest.main()
