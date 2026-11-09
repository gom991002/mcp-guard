"""AWS Secrets Manager as the MVP 8 ``SecretStore`` for per-user upstream tokens.

Standard library only: requests are signed with AWS Signature Version 4 and sent
to the Secrets Manager JSON 1.1 API. Credentials come from the standard
environment variables or, on EC2, from the instance role over IMDSv2.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

_MAX_BODY = 256_000
# IMDS publishes new role credentials at least five minutes before expiry.
_REFRESH_MARGIN_SECONDS = 300
_IMDS = "http://169.254.169.254"


class SecretManagerError(OSError):
    """The secret manager could not be reached or refused the request."""

    def __init__(self, message: str, code: str = "") -> None:
        super().__init__(message)
        self.code = code


AwsApiError = SecretManagerError  # the same error for every AwsJsonApi service


@dataclass(frozen=True)
class AwsCredentials:
    access_key: str
    secret_key: str
    session_token: str = ""
    expires_at: float | None = None


def sign_v4(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    credentials: AwsCredentials,
    region: str,
    service: str,
    now: datetime,
) -> dict[str, str]:
    """Return ``headers`` plus host, x-amz-date, session token, and Authorization.

    Every header passed in is signed, so pass only headers that proxies keep.
    """
    parts = urlsplit(url)
    amz_date = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    signed = {key.lower(): " ".join(str(value).split()) for key, value in headers.items()}
    signed["host"] = parts.netloc
    signed["x-amz-date"] = amz_date
    if credentials.session_token:
        signed["x-amz-security-token"] = credentials.session_token
    names = sorted(signed)
    canonical = "\n".join([
        method.upper(),
        quote(parts.path or "/", safe="/-_.~"),
        _canonical_query(parts.query),
        "".join(f"{name}:{signed[name]}\n" for name in names),
        ";".join(names),
        hashlib.sha256(body).hexdigest(),
    ])
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    ])
    key = ("AWS4" + credentials.secret_key).encode("utf-8")
    for part in (amz_date[:8], region, service, "aws4_request"):
        key = hmac.new(key, part.encode("utf-8"), hashlib.sha256).digest()
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    signed["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{scope}, "
        f"SignedHeaders={';'.join(names)}, Signature={signature}"
    )
    return signed


def _canonical_query(query: str) -> str:
    pairs = []
    for item in query.split("&") if query else ():
        name, _, value = item.partition("=")
        pairs.append((quote(name, safe="-_.~"), quote(value, safe="-_.~")))
    return "&".join(f"{name}={value}" for name, value in sorted(pairs))


# Credentials ------------------------------------------------------------------

def environment_credentials(environ: Mapping[str, str] | None = None) -> AwsCredentials | None:
    environ = os.environ if environ is None else environ
    access_key = environ.get("AWS_ACCESS_KEY_ID", "")
    secret_key = environ.get("AWS_SECRET_ACCESS_KEY", "")
    if not access_key or not secret_key:
        return None
    return AwsCredentials(access_key, secret_key, environ.get("AWS_SESSION_TOKEN", ""))


class InstanceMetadataCredentials:
    """EC2 instance role credentials over IMDSv2, fetched again before they expire."""

    def __init__(
        self, endpoint: str = _IMDS, clock: Callable[[], float] = time.time, timeout: float = 2.0,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._clock = clock
        self._timeout = timeout
        self._lock = threading.Lock()
        self._cached: AwsCredentials | None = None

    def __call__(self) -> AwsCredentials:
        with self._lock:
            cached = self._cached
            if cached and (cached.expires_at is None
                           or cached.expires_at - self._clock() > _REFRESH_MARGIN_SECONDS):
                return cached
            self._cached = self._fetch()
            return self._cached

    def _fetch(self) -> AwsCredentials:
        try:
            token = self._open("PUT", "/latest/api/token",
                               {"x-aws-ec2-metadata-token-ttl-seconds": "21600"})
            headers = {"x-aws-ec2-metadata-token": token}
            role = self._open("GET", "/latest/meta-data/iam/security-credentials/",
                              headers).split()[0]
            payload = json.loads(self._open(
                "GET", f"/latest/meta-data/iam/security-credentials/{role}", headers))
        except (OSError, IndexError, ValueError) as error:
            raise SecretManagerError(f"no instance role credentials: {error}") from error
        expiration = datetime.fromisoformat(str(payload["Expiration"]).replace("Z", "+00:00"))
        return AwsCredentials(payload["AccessKeyId"], payload["SecretAccessKey"],
                              payload.get("Token", ""), expiration.timestamp())

    def _open(self, method: str, path: str, headers: dict[str, str]) -> str:
        request = urllib.request.Request(self._endpoint + path, method=method, headers=headers)
        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            return response.read(_MAX_BODY).decode("utf-8")


def default_credentials() -> Callable[[], AwsCredentials]:
    """Environment variables first, then the EC2 instance role."""
    static = environment_credentials()
    if static is not None:
        return lambda: static
    return InstanceMetadataCredentials()


# Secrets Manager --------------------------------------------------------------

class AwsJsonApi:
    """A SigV4-signed AWS JSON API (Secrets Manager and CloudWatch Logs use 1.1, DynamoDB 1.0)."""

    def __init__(
        self,
        service: str,
        target_prefix: str,
        region: str,
        credentials: Callable[[], AwsCredentials],
        endpoint: str | None = None,
        timeout: float = 10.0,
        clock: Callable[[], datetime] | None = None,
        json_version: str = "1.1",
    ) -> None:
        self._service = service
        self._content_type = f"application/x-amz-json-{json_version}"
        self._target_prefix = target_prefix
        self._region = region
        self._credentials = credentials
        self._endpoint = endpoint or f"https://{service}.{region}.amazonaws.com/"
        parts = urlsplit(self._endpoint)
        if parts.scheme != "https" and parts.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError(f"{service} endpoint must be https (http only for localhost)")
        self._timeout = timeout
        self._clock = clock or (lambda: datetime.now(UTC))

    def call(self, action: str, payload: dict[str, Any]) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        headers = sign_v4(
            "POST", self._endpoint,
            {"content-type": self._content_type,
             "x-amz-target": f"{self._target_prefix}.{action}"},
            body, self._credentials(), self._region, self._service, self._clock(),
        )
        headers.pop("host")  # urllib sends it; the signed value is the same
        request = urllib.request.Request(self._endpoint, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read(_MAX_BODY + 1)
        except urllib.error.HTTPError as error:
            raise _aws_error(action, error) from error
        except OSError as error:
            raise SecretManagerError(f"{action} failed: {error}") from error
        if len(raw) > _MAX_BODY:
            raise SecretManagerError(f"{action} response is too large")
        try:
            result = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SecretManagerError(f"{action} returned invalid JSON") from error
        if not isinstance(result, dict):
            raise SecretManagerError(f"{action} returned a non-object")
        return result


class AwsSecretsManagerStore:
    """MVP 8 ``SecretStore`` backed by AWS Secrets Manager.

    ``put`` writes a new version (creating the secret on first use) and returns
    the secret name, which ``get`` accepts. ``get`` raises ``KeyError`` for a
    secret that does not exist and ``SecretManagerError`` for anything else.
    """

    def __init__(
        self,
        region: str,
        credentials: Callable[[], AwsCredentials],
        endpoint: str | None = None,
        kms_key_id: str = "",
        timeout: float = 10.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._api = AwsJsonApi("secretsmanager", "secretsmanager", region, credentials,
                               endpoint, timeout, clock)
        self._kms_key_id = kms_key_id

    def put(self, key: str, secret: str) -> str:
        try:
            self._call("PutSecretValue", {"SecretId": key, "SecretString": secret,
                                          "ClientRequestToken": str(uuid.uuid4())})
        except SecretManagerError as error:
            if error.code != "ResourceNotFoundException":
                raise
            create = {"Name": key, "SecretString": secret, "ClientRequestToken": str(uuid.uuid4())}
            if self._kms_key_id:
                create["KmsKeyId"] = self._kms_key_id
            try:
                self._call("CreateSecret", create)
            except SecretManagerError as again:
                if again.code != "ResourceExistsException":  # another thread created it
                    raise
                self._call("PutSecretValue", {"SecretId": key, "SecretString": secret,
                                              "ClientRequestToken": str(uuid.uuid4())})
        return key

    def get(self, reference: str) -> str:
        try:
            payload = self._call("GetSecretValue", {"SecretId": reference})
        except SecretManagerError as error:
            if error.code == "ResourceNotFoundException":
                raise KeyError(reference) from error
            raise
        value = payload.get("SecretString")
        if not isinstance(value, str):
            raise SecretManagerError(f"secret {reference} has no SecretString")
        return value

    def _call(self, action: str, payload: dict[str, str]) -> dict[str, object]:
        return self._api.call(action, payload)


def _aws_error(action: str, error: urllib.error.HTTPError) -> SecretManagerError:
    """Error code from the JSON ``__type`` (``ns#Code``) or the x-amzn-ErrorType header."""
    code = ""
    try:
        payload = json.loads(error.read(_MAX_BODY).decode("utf-8"))
        if isinstance(payload, dict):
            code = str(payload.get("__type", "")).rsplit("#", 1)[-1]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    if not code:
        code = (error.headers.get("x-amzn-ErrorType") or "").split(":", 1)[0]
    return SecretManagerError(f"{action} failed: HTTP {error.code} {code}".rstrip(), code)
