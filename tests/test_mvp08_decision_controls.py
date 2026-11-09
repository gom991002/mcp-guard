import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mvp" / "08-decision-controls"))

from decision_controls import (  # noqa: E402
    ActivationMode,
    GatewayTokenIssuer,
    decide_activation,
)


class DecisionControlsMvpTests(unittest.TestCase):
    now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)

    def test_gateway_token_issue_and_verify(self) -> None:
        issuer = GatewayTokenIssuer(b"test-signing-key", ttl_seconds=60)
        token = issuer.issue("user-1", ("tools/call",), now=self.now)

        payload = issuer.verify(token.token, now=self.now + timedelta(seconds=30))

        self.assertEqual(payload["sub"], "user-1")
        self.assertEqual(payload["scopes"], ["tools/call"])

    def test_gateway_token_rejects_expired_token(self) -> None:
        issuer = GatewayTokenIssuer(b"test-signing-key", ttl_seconds=60)
        token = issuer.issue("user-1", ("tools/call",), now=self.now)

        with self.assertRaisesRegex(ValueError, "expired"):
            issuer.verify(token.token, now=self.now + timedelta(seconds=61))

    def test_activation_yes_no_branch(self) -> None:
        enabled = decide_activation(
            True,
            "https://guard.example/mcp",
            "https://origin.example/mcp",
        )
        disabled = decide_activation(
            False,
            "https://guard.example/mcp",
            "https://origin.example/mcp",
        )

        self.assertEqual(enabled.mode, ActivationMode.GUARD)
        self.assertEqual(enabled.target_url, "https://guard.example/mcp")
        self.assertEqual(disabled.mode, ActivationMode.DIRECT)
        self.assertIn("bypass", disabled.warning)



if __name__ == "__main__":
    unittest.main()
