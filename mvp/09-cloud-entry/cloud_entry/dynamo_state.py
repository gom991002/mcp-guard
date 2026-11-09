"""Gateway state shared by several gateway instances, in one DynamoDB table (2026-11-04).

With one gateway the private state folder is enough. Behind a load balancer a
session can reach any instance, so the state that decides what may be sent
out must be shared: M4 session taint (an instance that missed a taint would
let a tainted session send) and the users' new-session counters. Both stores
keep the interface of their file versions (mcp_guard.taint.SessionTaintStore,
http_gateway.session_epochs.SessionEpochs).

Table: one string partition key ``pk``; items ``taint#<sha256 of session>`` and
``epoch#<sha256 of user>``. Session ids and user names are stored hashed.
A taint is written once with a condition, so the first source stays.

Failures fail closed. If the table cannot be read, a session counts as tainted
(its sending tools are blocked); a taint that cannot be written is kept in
this process and retried on the next mark. The standard library signs the
calls (SigV4, as for Secrets Manager); this was tested against a fake
DynamoDB only, not against AWS.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime
from typing import Any, Callable

from mcp_guard.taint import TaintRecord

from .aws_secrets import AwsCredentials, AwsJsonApi, SecretManagerError

UNREADABLE = "state store unavailable"


def _key(kind: str, value: str) -> str:
    return f"{kind}#{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


class DynamoTable:
    def __init__(self, table: str, region: str, credentials: Callable[[], AwsCredentials],
                 endpoint: str | None = None, timeout: float = 5.0) -> None:
        if not table:
            raise ValueError("a DynamoDB table name is required")
        self.table = table
        self._api = AwsJsonApi("dynamodb", "DynamoDB_20120810", region, credentials, endpoint,
                               timeout, json_version="1.0")

    def get(self, pk: str) -> dict[str, Any] | None:
        item = self._api.call("GetItem", {"TableName": self.table, "Key": {"pk": {"S": pk}},
                                          "ConsistentRead": True}).get("Item")
        return item if isinstance(item, dict) else None

    def put_new(self, pk: str, attributes: dict[str, dict[str, str]]) -> bool:
        """Write an item only if none exists; False when one already did."""
        try:
            self._api.call("PutItem", {"TableName": self.table, "Item": {"pk": {"S": pk}, **attributes},
                                       "ConditionExpression": "attribute_not_exists(pk)"})
        except SecretManagerError as error:
            if error.code == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def increment(self, pk: str, field: str, stamp: str) -> int:
        result = self._api.call("UpdateItem", {
            "TableName": self.table, "Key": {"pk": {"S": pk}},
            "UpdateExpression": "ADD #n :one SET reset_at = :at",
            "ExpressionAttributeNames": {"#n": field},
            "ExpressionAttributeValues": {":one": {"N": "1"}, ":at": {"S": stamp}},
            "ReturnValues": "UPDATED_NEW"})
        return int(result["Attributes"][field]["N"])


class DynamoTaintStore:
    """M4 session taint in DynamoDB, with the file store's get/mark."""

    def __init__(self, table: DynamoTable) -> None:
        self._table = table
        self._unsaved: dict[str, TaintRecord] = {}
        self._lock = threading.Lock()

    def mark(self, session_id: str, source: str, now: datetime | None = None) -> TaintRecord:
        if not session_id:
            raise ValueError("session_id is required")
        record = TaintRecord(session_id, source, (now or datetime.now(UTC)).isoformat())
        with self._lock:
            self._unsaved.setdefault(session_id, record)
        try:
            self._table.put_new(_key("taint", session_id), {
                "first_source": {"S": record.first_source}, "tainted_at": {"S": record.tainted_at}})
        except SecretManagerError:
            return record  # kept in this process; retried on the next mark, read back by get
        with self._lock:
            self._unsaved.pop(session_id, None)
        return self.get(session_id) or record

    def get(self, session_id: str) -> TaintRecord | None:
        if not session_id:
            raise ValueError("session_id is required")
        with self._lock:
            unsaved = self._unsaved.get(session_id)
        if unsaved is not None:
            return unsaved
        try:
            item = self._table.get(_key("taint", session_id))
        except SecretManagerError:
            return TaintRecord(session_id, UNREADABLE, datetime.now(UTC).isoformat())  # fail closed
        if item is None:
            return None
        return TaintRecord(session_id, item["first_source"]["S"], item["tainted_at"]["S"])


class DynamoSessionEpochs:
    """A user's "start a new session" counter in DynamoDB, with SessionEpochs' interface."""

    def __init__(self, table: DynamoTable) -> None:
        self._table = table

    def epoch(self, user: str) -> int:
        try:
            item = self._table.get(_key("epoch", user))
        except SecretManagerError:
            return 0  # the user's first session: never a fresh one when unsure
        return int(item["epoch"]["N"]) if item and "epoch" in item else 0

    def last_reset(self, user: str) -> str:
        try:
            item = self._table.get(_key("epoch", user))
        except SecretManagerError:
            return ""
        return item["reset_at"]["S"] if item and "reset_at" in item else ""

    def start_new(self, user: str) -> int:
        return self._table.increment(_key("epoch", user), "epoch", datetime.now(UTC).isoformat(timespec="seconds"))
