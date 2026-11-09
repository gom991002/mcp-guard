"""Pinned feed refresh and Stage 1 scan parity."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys

from mcp_guard import similarity
from mcp_guard.similarity_feed import checked_snapshot, refresh

ROOT = Path(__file__).resolve().parents[1]
for folder in ("mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))
from local_entry import code_scan  # noqa: E402
from local_entry.manifest import GuardManifest  # noqa: E402


class _Response:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, count: int) -> bytes:
        return self.raw[:count]


class FeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = similarity.INDEX_PATH.read_bytes()
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def test_verified_refresh_preserves_index_results(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "feed.json"
            opener = mock.Mock()
            opener.open.return_value = _Response(self.raw)
            with mock.patch("mcp_guard.similarity_feed.urllib.request.build_opener", return_value=opener):
                refresh("https://feed.example/index.json", self.digest, target)
            self.assertEqual(checked_snapshot(target, self.digest), self.raw)
            original = similarity.load_index()
            external = similarity.load_index(str(target))
            self.assertEqual(original.labels, external.labels)
            self.assertEqual(original.signatures, external.signatures)
            for sig in original.signatures[:20]:
                self.assertEqual(original.best(sig), external.best(sig))

    def test_wrong_pin_and_bad_payload_do_not_replace_existing_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "feed.json"
            target.write_bytes(self.raw)
            opener = mock.Mock()
            opener.open.return_value = _Response(b"{}")
            with mock.patch("mcp_guard.similarity_feed.urllib.request.build_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    refresh("https://feed.example/index.json", self.digest, target)
                with self.assertRaises(ValueError):
                    refresh("https://feed.example/index.json", hashlib.sha256(b"{}").hexdigest(), target)
            self.assertEqual(target.read_bytes(), self.raw)
            target.write_bytes(self.raw + b" ")
            with self.assertRaises(ValueError):
                checked_snapshot(target, self.digest)

    def test_rejects_insecure_url_and_invalid_fingerprint(self) -> None:
        with self.assertRaises(ValueError):
            refresh("http://feed.example/index.json", self.digest, "unused")
        payload = json.loads(self.raw)
        payload["entries"][0][1] = "xyz"
        from mcp_guard.similarity_feed import validate_snapshot

        with self.assertRaises(ValueError):
            validate_snapshot(json.dumps(payload).encode())

    def test_scan_uses_pinned_feed_and_report_becomes_stale_when_changed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "feed.json"
            path.write_bytes(self.raw)
            feed = {"path": str(path), "url": "https://feed.example/index.json", "sha256": self.digest}
            body = code_scan.similar_to_known_malware({"findings": []}, [], feed=feed)
            self.assertEqual(body["similarity_index"], "loaded")
            entry = {"stage1": {"provider": "local"}}
            report = code_scan.new_report("test", entry, {**body, "rules_sha256": code_scan.rules_sha256()})
            self.assertEqual(code_scan.report_status(report, entry, feed)[0], "ok")
            path.write_bytes(self.raw + b" ")
            self.assertEqual(code_scan.report_status(report, entry, feed)[0], "stale")
            with self.assertRaises(ValueError):
                code_scan.similar_to_known_malware({"findings": []}, [], feed=feed)

    def test_manifest_keeps_feed_pin_and_rejects_unpinned_url(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            base = {"policy": "policy.json", "approvals": "approvals.json", "servers": {},
                    "code_scan": {"similarity_feed": {"url": "https://feed.example/index.json",
                                                       "sha256": self.digest,
                                                       "path": str(Path(folder) / "feed.json")}}}
            path.write_text(json.dumps(base), encoding="utf-8")
            self.assertEqual(GuardManifest.from_path(path).code_scan["similarity_feed"]["sha256"],
                             self.digest)
            base["code_scan"]["similarity_feed"]["url"] = "http://feed.example/index.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(ValueError):
                GuardManifest.from_path(path)


if __name__ == "__main__":
    unittest.main()
