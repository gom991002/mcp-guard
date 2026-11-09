import json
import sys
import threading
import unittest
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp", "mvp/03-server-registration-config",
    "mvp/04-tools-list-relay", "mvp/07-tools-call-upstream-relay", "mvp/08-decision-controls",
    "mvp/09-cloud-entry",
):
    sys.path.insert(0, str(ROOT / folder))

from cloud_entry.aws_secrets import (  # noqa: E402
    AwsCredentials, AwsSecretsManagerStore, InstanceMetadataCredentials, SecretManagerError,
    environment_credentials, sign_v4,
)

# AWS SigV4 test suite as shipped in botocore (tests/unit/auth/aws4_testsuite).
SUITE_CREDENTIALS = AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
SUITE_TIME = datetime(2015, 8, 30, 12, 36, tzinfo=UTC)
CREDENTIALS = AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "session")


class SigV4Tests(unittest.TestCase):
    def test_get_vanilla(self) -> None:
        headers = sign_v4("GET", "https://example.amazonaws.com/", {}, b"",
                          SUITE_CREDENTIALS, "us-east-1", "service", SUITE_TIME)

        self.assertEqual(headers["authorization"], (
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
            "SignedHeaders=host;x-amz-date, "
            "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"))

    def test_post_x_www_form_urlencoded(self) -> None:
        headers = sign_v4("POST", "https://example.amazonaws.com/",
                          {"Content-Type": "application/x-www-form-urlencoded"}, b"Param1=value1",
                          SUITE_CREDENTIALS, "us-east-1", "service", SUITE_TIME)

        self.assertTrue(headers["authorization"].endswith(
            "SignedHeaders=content-type;host;x-amz-date, "
            "Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"))

    def test_session_token_is_sent_and_signed(self) -> None:
        headers = sign_v4("POST", "https://example.amazonaws.com/", {}, b"",
                          CREDENTIALS, "us-east-1", "service", SUITE_TIME)

        self.assertEqual(headers["x-amz-security-token"], "session")
        self.assertIn("SignedHeaders=host;x-amz-date;x-amz-security-token,", headers["authorization"])


class FakeSecretsManager:
    """Secrets Manager JSON 1.1 API that checks each request's SigV4 signature."""

    def __init__(self) -> None:
        self.secrets: dict[str, list[str]] = {}
        self.kms_keys: dict[str, str] = {}
        self.actions: list[str] = []
        self.fail_with_500 = False
        self.create_race = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/x-amz-json-1.1")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _error(self, code):
                self._send(400, {"__type": code, "message": code})

            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                now = datetime.strptime(self.headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
                expected = sign_v4(
                    "POST", f"http://{self.headers['host']}/",
                    {"content-type": self.headers["content-type"],
                     "x-amz-target": self.headers["x-amz-target"]},
                    body, CREDENTIALS, "us-east-1", "secretsmanager", now)
                if self.headers["authorization"] != expected["authorization"]:
                    return self._send(403, {"__type": "InvalidSignatureException"})
                action = self.headers["x-amz-target"].removeprefix("secretsmanager.")
                outer.actions.append(action)
                if outer.fail_with_500:
                    return self._send(500, {"__type": "InternalServiceError"})
                request = json.loads(body)
                if action == "GetSecretValue":
                    versions = outer.secrets.get(request["SecretId"])
                    if not versions:
                        return self._error("ResourceNotFoundException")
                    return self._send(200, {"Name": request["SecretId"], "SecretString": versions[-1]})
                assert 32 <= len(request["ClientRequestToken"]) <= 64
                if action == "PutSecretValue":
                    if request["SecretId"] not in outer.secrets:
                        return self._error("ResourceNotFoundException")
                    outer.secrets[request["SecretId"]].append(request["SecretString"])
                    return self._send(200, {"Name": request["SecretId"]})
                if action == "CreateSecret":
                    if outer.create_race:  # another writer creates it first
                        outer.secrets[request["Name"]] = ["other"]
                    if request["Name"] in outer.secrets:
                        return self._error("com.amazonaws.secretsmanager#ResourceExistsException")
                    outer.secrets[request["Name"]] = [request["SecretString"]]
                    if "KmsKeyId" in request:
                        outer.kms_keys[request["Name"]] = request["KmsKeyId"]
                    return self._send(200, {"Name": request["Name"]})
                self._send(400, {"__type": "UnknownOperationException"})

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class AwsSecretsManagerStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.aws = FakeSecretsManager()
        self.store = AwsSecretsManagerStore("us-east-1", lambda: CREDENTIALS, endpoint=self.aws.endpoint)

    def tearDown(self) -> None:
        self.aws.close()

    def test_put_creates_then_adds_versions_and_get_reads_latest(self) -> None:
        self.assertEqual(self.store.put("mcp-guard/upstream/token/a", "v1"), "mcp-guard/upstream/token/a")
        self.store.put("mcp-guard/upstream/token/a", "v2")

        self.assertEqual(self.store.get("mcp-guard/upstream/token/a"), "v2")
        self.assertEqual(self.aws.actions, ["PutSecretValue", "CreateSecret", "PutSecretValue",
                                            "GetSecretValue"])
        self.assertEqual(self.aws.secrets["mcp-guard/upstream/token/a"], ["v1", "v2"])

    def test_missing_secret_is_a_key_error(self) -> None:
        with self.assertRaises(KeyError):
            self.store.get("mcp-guard/upstream/token/none")

    def test_service_failure_is_not_mistaken_for_a_missing_secret(self) -> None:
        self.aws.fail_with_500 = True
        with self.assertRaises(SecretManagerError) as caught:
            self.store.get("mcp-guard/upstream/token/a")

        self.assertEqual(caught.exception.code, "InternalServiceError")

    def test_create_race_falls_back_to_a_new_version(self) -> None:
        self.aws.create_race = True
        self.store.put("name", "mine")

        self.assertEqual(self.aws.secrets["name"], ["other", "mine"])

    def test_kms_key_applies_to_new_secrets(self) -> None:
        store = AwsSecretsManagerStore("us-east-1", lambda: CREDENTIALS, endpoint=self.aws.endpoint,
                                       kms_key_id="alias/mcp-guard")
        store.put("name", "v1")

        self.assertEqual(self.aws.kms_keys, {"name": "alias/mcp-guard"})

    def test_plain_http_endpoint_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            AwsSecretsManagerStore("us-east-1", lambda: CREDENTIALS, endpoint="http://example.com/")


class FakeImds:
    def __init__(self, expiration: str) -> None:
        self.fetches = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, text):
                data = text.encode()
                self.send_response(status)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_PUT(self):
                if self.path != "/latest/api/token" or not self.headers["x-aws-ec2-metadata-token-ttl-seconds"]:
                    return self._send(400, "")
                self._send(200, "imds-token")

            def do_GET(self):
                if self.headers["x-aws-ec2-metadata-token"] != "imds-token":
                    return self._send(401, "")
                if self.path == "/latest/meta-data/iam/security-credentials/":
                    return self._send(200, "gateway-role\n")
                if self.path == "/latest/meta-data/iam/security-credentials/gateway-role":
                    outer.fetches += 1
                    return self._send(200, json.dumps({
                        "Code": "Success", "AccessKeyId": f"ASIA{outer.fetches}",
                        "SecretAccessKey": "secret", "Token": "token", "Expiration": expiration}))
                self._send(404, "")

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class CredentialTests(unittest.TestCase):
    def test_environment_credentials(self) -> None:
        self.assertIsNone(environment_credentials({}))
        self.assertEqual(
            environment_credentials({"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "s",
                                     "AWS_SESSION_TOKEN": "t"}),
            AwsCredentials("AKID", "s", "t"))

    def test_instance_role_credentials_are_cached_until_near_expiry(self) -> None:
        imds = FakeImds("2030-01-01T00:00:00Z")
        self.addCleanup(imds.close)
        expiry = datetime(2030, 1, 1, tzinfo=UTC).timestamp()
        now = [expiry - 3600]
        credentials = InstanceMetadataCredentials(imds.endpoint, clock=lambda: now[0])

        first = credentials()
        self.assertEqual(credentials(), first)
        now[0] = expiry - 200  # inside the five-minute refresh margin
        second = credentials()

        self.assertEqual((first.access_key, second.access_key), ("ASIA1", "ASIA2"))
        self.assertEqual(first.session_token, "token")
        self.assertEqual(imds.fetches, 2)


if __name__ == "__main__":
    unittest.main()
