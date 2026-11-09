"""Shared gateway state in DynamoDB (cloud_entry/dynamo_state.py), against a fake DynamoDB."""

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in ("src", "mvp/02-remote-gateway-mcp", "mvp/08-decision-controls", "mvp/09-cloud-entry"):
    sys.path.insert(0, str(ROOT / folder))

from cloud_entry.aws_secrets import AwsCredentials  # noqa: E402
from cloud_entry.dynamo_state import (  # noqa: E402
    UNREADABLE, DynamoSessionEpochs, DynamoTable, DynamoTaintStore,
)


class FakeDynamo:
    """GetItem, conditional PutItem and UpdateItem ADD, as the gateway uses them."""

    def __init__(self) -> None:
        self.items: dict[str, dict] = {}
        self.requests: list[tuple[str, dict, dict]] = []
        self.down = False
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                action = self.headers["x-amz-target"].split(".", 1)[1]
                fake.requests.append((action, {k.lower(): v for k, v in self.headers.items()}, body))
                if fake.down:
                    return self._send(500, {"__type": "com.amazonaws#InternalServerError"})
                key = body["Key"]["pk"]["S"] if "Key" in body else body["Item"]["pk"]["S"]
                if action == "GetItem":
                    return self._send(200, {"Item": fake.items[key]} if key in fake.items else {})
                if action == "PutItem":
                    if key in fake.items:
                        return self._send(400, {"__type": "com.amazonaws.dynamodb.v20120810#"
                                                          "ConditionalCheckFailedException"})
                    fake.items[key] = body["Item"]
                    return self._send(200, {})
                item = fake.items.setdefault(key, {"pk": {"S": key}})
                value = int(item.get("epoch", {"N": "0"})["N"]) + 1
                item["epoch"] = {"N": str(value)}
                item["reset_at"] = body["ExpressionAttributeValues"][":at"]
                return self._send(200, {"Attributes": {"epoch": {"N": str(value)}}})

            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/x-amz-json-1.0")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class DynamoStateTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeDynamo()
        credentials = AwsCredentials("AKIDEXAMPLE", "secret")
        self.table = DynamoTable("mcp-guard-state", "ap-northeast-2", lambda: credentials, endpoint=self.fake.url)

    def tearDown(self):
        self.fake.close()

    def test_two_gateways_see_one_taint_and_the_first_source_stays(self):
        a, b = DynamoTaintStore(self.table), DynamoTaintStore(self.table)
        self.assertIsNone(b.get("claude:user:abc"))
        a.mark("claude:user:abc", "mail:read_inbox")
        self.assertEqual(b.get("claude:user:abc").first_source, "mail:read_inbox")
        b.mark("claude:user:abc", "web:fetch")
        self.assertEqual(a.get("claude:user:abc").first_source, "mail:read_inbox")
        self.assertNotIn("claude:user:abc", json.dumps(self.fake.items))  # stored hashed

    def test_calls_are_signed_dynamodb_json_1_0(self):
        DynamoTaintStore(self.table).get("s-1")
        action, headers, body = self.fake.requests[-1]
        self.assertEqual(action, "GetItem")
        self.assertEqual(headers["content-type"], "application/x-amz-json-1.0")
        self.assertIn("AWS4-HMAC-SHA256", headers["authorization"])
        self.assertTrue(body["ConsistentRead"])

    def test_an_unreadable_table_counts_as_tainted_and_unsaved_taint_is_kept(self):
        store = DynamoTaintStore(self.table)
        self.fake.down = True
        self.assertEqual(store.get("s-1").first_source, UNREADABLE)  # fail closed: sends are blocked
        store.mark("s-2", "mail:read_inbox")
        self.fake.down = False
        self.assertEqual(store.get("s-2").first_source, "mail:read_inbox")  # still known in this process
        store.mark("s-2", "mail:read_inbox")  # retried and saved now
        self.assertEqual(DynamoTaintStore(self.table).get("s-2").first_source, "mail:read_inbox")

    def test_new_session_counters_are_shared(self):
        a, b = DynamoSessionEpochs(self.table), DynamoSessionEpochs(self.table)
        self.assertEqual(a.epoch("alice"), 0)
        self.assertEqual(a.start_new("alice"), 1)
        self.assertEqual(b.epoch("alice"), 1)
        self.assertTrue(b.last_reset("alice"))
        self.assertEqual(b.epoch("bob"), 0)

    def test_the_server_needs_a_table_and_region(self):
        import io
        from contextlib import redirect_stderr

        for folder in ("mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp",
                       "mvp/03-server-registration-config", "mvp/04-tools-list-relay",
                       "mvp/05-indirect-injection-throttle", "mvp/06-http-gateway-server",
                       "mvp/07-tools-call-upstream-relay"):
            sys.path.insert(0, str(ROOT / folder))
        from http_gateway.server import main as server_main

        with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            server_main(["--state-backend", "dynamodb"])
        self.assertIn("--state-backend dynamodb needs --dynamodb-table and --aws-region", err.getvalue())


if __name__ == "__main__":
    unittest.main()
