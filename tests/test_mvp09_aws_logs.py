import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp", "mvp/03-server-registration-config",
    "mvp/04-tools-list-relay", "mvp/05-indirect-injection-throttle", "mvp/06-http-gateway-server",
    "mvp/07-tools-call-upstream-relay", "mvp/08-decision-controls", "mvp/09-cloud-entry",
):
    sys.path.insert(0, str(ROOT / folder))

from cloud_entry.aws_logs import CloudWatchLogsSink  # noqa: E402
from cloud_entry.aws_secrets import AwsCredentials, sign_v4  # noqa: E402
from http_gateway.server import main as gateway_main  # noqa: E402
from http_gateway.state_storage import prepare_state_dir  # noqa: E402
from mcp_guard.audit import (  # noqa: E402
    AuditRecorder, JsonlAuditSink, TeeAuditSink, audit_event, read_audit_log,
)

CREDENTIALS = AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")


class FakeCloudWatchLogs:
    """CloudWatch Logs JSON API that checks SigV4 and the PutLogEvents batch rules."""

    def __init__(self) -> None:
        self.streams: dict[str, list[dict]] = {}
        self.calls: list[tuple[str, int]] = []
        self.failing = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/x-amz-json-1.1")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                now = datetime.strptime(self.headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
                expected = sign_v4("POST", f"http://{self.headers['host']}/",
                                   {"content-type": self.headers["content-type"],
                                    "x-amz-target": self.headers["x-amz-target"]},
                                   body, CREDENTIALS, "us-east-1", "logs", now)
                if self.headers["authorization"] != expected["authorization"]:
                    return self._send(403, {"__type": "InvalidSignatureException"})
                action = self.headers["x-amz-target"].removeprefix("Logs_20140328.")
                request = json.loads(body)
                if outer.failing:
                    outer.calls.append((action, 0))
                    return self._send(500, {"__type": "ServiceUnavailableException"})
                if request.get("logGroupName") != "/mcp-guard/audit":
                    return self._send(400, {"__type": "ResourceNotFoundException"})
                if action == "CreateLogStream":
                    outer.calls.append((action, 0))
                    outer.streams.setdefault(request["logStreamName"], [])
                    return self._send(200, {})
                if action == "PutLogEvents":
                    events = request["logEvents"]
                    outer.calls.append((action, len(events)))
                    if request["logStreamName"] not in outer.streams:
                        return self._send(400, {"__type": "ResourceNotFoundException"})
                    stamps = [e["timestamp"] for e in events]
                    size = sum(len(e["message"].encode()) + 26 for e in events)
                    assert stamps == sorted(stamps) and len(events) <= 10_000 and size <= 1_048_576
                    outer.streams[request["logStreamName"]].extend(events)
                    return self._send(200, {})
                self._send(400, {"__type": "UnknownOperationException"})

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def messages(self, stream="gw-1"):
        return [json.loads(e["message"]) for e in self.streams.get(stream, [])]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class CloudWatchLogsSinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.aws = FakeCloudWatchLogs()
        self.addCleanup(self.aws.close)
        self.log = io.StringIO()

    def _sink(self, **options):
        sink = CloudWatchLogsSink("us-east-1", "/mcp-guard/audit", "gw-1", lambda: CREDENTIALS,
                                  endpoint=self.aws.endpoint, flush_seconds=60, log=self.log,
                                  **options)
        self.addCleanup(sink.close)
        return sink

    def test_events_arrive_in_time_order_after_the_stream_is_created(self) -> None:
        sink = self._sink()
        now = datetime.now(UTC)
        sink.emit(audit_event("sign_in", timestamp=now, user="bob"))
        sink.emit(audit_event("sign_in", timestamp=now - timedelta(seconds=5), user="alice"))
        sink.flush()

        self.assertEqual([m["user"] for m in self.aws.messages()], ["alice", "bob"])
        self.assertEqual([c[0] for c in self.aws.calls],
                         ["PutLogEvents", "CreateLogStream", "PutLogEvents"])

    def test_batches_are_split_by_count(self) -> None:
        sink = self._sink(max_batch_events=2)
        for _ in range(5):
            sink.emit(audit_event("tools_list_changed", server_name="s"))
        sink.flush()

        # The first batch is sent twice: once before the stream exists, once after.
        self.assertEqual([n for action, n in self.aws.calls if action == "PutLogEvents"], [2, 2, 2, 1])
        self.assertEqual(len(self.aws.messages()), 5)

    def test_failed_writes_are_kept_and_retried(self) -> None:
        sink = self._sink()
        self.aws.failing = True
        sink.emit(audit_event("sign_in", user="bob"))
        sink.flush()
        self.assertEqual(sink.pending(), 1)
        self.assertIn("will retry", self.log.getvalue())

        self.aws.failing = False
        sink.flush()
        self.assertEqual(sink.pending(), 0)
        self.assertEqual([m["user"] for m in self.aws.messages()], ["bob"])
        self.assertIn("recovered", self.log.getvalue())

    def test_events_older_than_14_days_are_dropped_from_the_queue(self) -> None:
        sink = self._sink()
        sink.emit(audit_event("sign_in", timestamp=datetime.now(UTC) - timedelta(days=15)))
        sink.flush()

        self.assertEqual(self.aws.messages(), [])
        self.assertIn("older than 14 days", self.log.getvalue())

    def test_full_queue_is_reported(self) -> None:
        sink = self._sink(max_queue=1)
        sink.emit(audit_event("sign_in"))

        with self.assertRaises(OSError):
            sink.emit(audit_event("sign_in"))

    def test_local_copy_is_written_when_cloudwatch_is_down(self) -> None:
        self.aws.failing = True
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / "audit.jsonl"
            recorder = AuditRecorder(TeeAuditSink(JsonlAuditSink(local), self._sink()), log=self.log)
            recorder.record(audit_event("sign_in", user="bob"))
            recorder.close()

            self.assertEqual([e.user for e in read_audit_log(local)], ["bob"])


class GatewayCloudWatchTests(unittest.TestCase):
    def test_gateway_sends_audit_events_to_cloudwatch_and_the_local_copy(self) -> None:
        aws = FakeCloudWatchLogs()
        self.addCleanup(aws.close)
        environment = {"AWS_ACCESS_KEY_ID": CREDENTIALS.access_key,
                       "AWS_SECRET_ACCESS_KEY": CREDENTIALS.secret_key}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, environment):
            state = prepare_state_dir(Path(folder) / "state")
            local = state / "audit.jsonl"
            with redirect_stdout(io.StringIO()):
                gateway_main([
                    "--policy", str(ROOT / "configs" / "example-policy.json"),
                    "--servers", str(ROOT / "mvp" / "03-server-registration-config" / "configs"
                                     / "servers.json"),
                    "--state-dir", str(state),
                    "--approvals", str(state / "approved.json"),
                    "--audit-log", str(local), "--aws-region", "us-east-1",
                    "--audit-cloudwatch-group", "/mcp-guard/audit",
                    "--audit-cloudwatch-stream", "gw-1",
                    "--audit-cloudwatch-endpoint", aws.endpoint,
                    "--approve-server", "company-tools",
                ])
            local_events = read_audit_log(local)

        self.assertEqual([m["event_type"] for m in aws.messages()], ["server_approved"])
        self.assertEqual(aws.messages()[0]["event_id"], local_events[0].event_id)

    def test_cloudwatch_needs_a_local_copy_and_a_region(self) -> None:
        with redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()), \
                self.assertRaises(SystemExit):
            gateway_main(["--audit-cloudwatch-group", "/mcp-guard/audit", "--aws-region", "us-east-1"])


if __name__ == "__main__":
    unittest.main()
