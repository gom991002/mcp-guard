"""Administrator commands for the cloud entry path.

python -m cloud_entry.admin add-user --users /config/users.json alice
python -m cloud_entry.admin add-client --clients /config/oauth-clients.json --family gemini \
    --redirect-uri https://vertexaisearch.cloud.google.com/oauth-redirect gemini-enterprise
python -m cloud_entry.admin init-key --key /data/signing.key
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from .oauth import hash_password, load_or_create_key


def add_user(users_path: Path, username: str, password: str) -> None:
    if not username or not username.isprintable() or len(username) > 64:
        raise ValueError("username must be 1-64 printable characters")
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    payload = {"users": {}}
    if users_path.exists():
        payload = json.loads(users_path.read_text(encoding="utf-8"))
    payload.setdefault("users", {})[username] = hash_password(password)
    users_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = users_path.with_suffix(users_path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, users_path)


FAMILIES = ("claude", "chatgpt", "codex", "gemini", "other")


def add_client(clients_path: Path, client_id: str, redirect_uris: list[str], family: str,
               name: str = "") -> str:
    """Register a confidential client; return its secret, which is stored only as a hash."""
    if not client_id or not client_id.isprintable() or client_id.startswith("https://"):
        raise ValueError("client id must be printable and not a URL")
    if not redirect_uris or not all(uri.startswith("https://") for uri in redirect_uris):
        raise ValueError("redirect URIs must be https")
    if family not in FAMILIES:
        raise ValueError(f"family must be one of {', '.join(FAMILIES)}")
    secret = secrets.token_urlsafe(32)
    payload = {"clients": {}}
    if clients_path.exists():
        payload = json.loads(clients_path.read_text(encoding="utf-8"))
    payload.setdefault("clients", {})[client_id] = {
        "client_name": name or client_id, "family": family, "redirect_uris": redirect_uris,
        "secret_sha256": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
    }
    clients_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = clients_path.with_suffix(clients_path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, clients_path)
    return secret


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mcp-guard cloud entry administration")
    commands = parser.add_subparsers(dest="command", required=True)
    user = commands.add_parser("add-user", help="add or reset a user who may sign in")
    user.add_argument("--users", required=True, type=Path)
    user.add_argument("username")
    client = commands.add_parser("add-client",
                                 help="register a confidential OAuth client, e.g. Gemini Enterprise")
    client.add_argument("--clients", required=True, type=Path)
    client.add_argument("--redirect-uri", action="append", required=True)
    client.add_argument("--family", required=True, choices=FAMILIES)
    client.add_argument("--name", default="")
    client.add_argument("client_id")
    key = commands.add_parser("init-key", help="create the token signing key if missing")
    key.add_argument("--key", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "add-user":
        password = os.environ.get("MCP_GUARD_NEW_PASSWORD") or getpass.getpass("password: ")
        add_user(args.users, args.username, password)
        print(f"user {args.username} saved to {args.users}", file=sys.stderr)
    elif args.command == "add-client":
        secret = add_client(args.clients, args.client_id, args.redirect_uri, args.family, args.name)
        print(f"client {args.client_id} saved to {args.clients}; its secret (shown once):",
              file=sys.stderr)
        print(secret)
    else:
        load_or_create_key(args.key)
        print(f"signing key ready at {args.key}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
