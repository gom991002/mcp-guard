"""Prepare and check a private state folder for one gateway process.

Run the setup command while the gateway is stopped, then start the gateway.
Use --state-dir only when choosing a nondefault prepared folder. The old folder is retained
after migration so an operator can check the new gateway before removing it.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

MIGRATION_MARKER = "state-migration.json"


def default_state_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise OSError("LOCALAPPDATA is needed for the default private state folder")
        return Path(base) / "mcp-guard" / "private-state"
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "mcp-guard"

def _windows_identity() -> tuple[str, str]:
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                            capture_output=True, text=True, check=True)
    rows = list(csv.reader(result.stdout.splitlines()))
    if len(rows) != 1 or len(rows[0]) != 2 or not re.fullmatch(r"S-\d+(?:-\d+)+", rows[0][1]):
        raise OSError("cannot identify the gateway's Windows account")
    return rows[0][0], rows[0][1]


def _windows_acl(path: Path) -> dict:
    command = (
        "$a=Get-Acl -LiteralPath $env:MCP_GUARD_ACL_PATH; "
        "[pscustomobject]@{owner=([System.Security.Principal.NTAccount]$a.Owner)."
        "Translate([System.Security.Principal.SecurityIdentifier]).Value; "
        "protected=$a.AreAccessRulesProtected; "
        "aces=@($a.Access | ForEach-Object { [pscustomobject]@{"
        "identity=$_.IdentityReference.Translate("
        "[System.Security.Principal.SecurityIdentifier]).Value; "
        "type=$_.AccessControlType.ToString(); rights=$_.FileSystemRights.ToString(); "
        "mask=[int]$_.FileSystemRights"
        "} })} | ConvertTo-Json -Depth 4 -Compress"
    )
    env = {**os.environ, "MCP_GUARD_ACL_PATH": str(path)}
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, check=True, env=env)
    return json.loads(result.stdout)


def verify_state_dir(folder: str | Path) -> Path:
    """Reject a state folder writable by another ordinary account."""
    requested = Path(folder)
    if requested.is_symlink():
        raise OSError(f"state folder must not be a link: {requested}")
    path = requested.resolve(strict=True)
    if not path.is_dir():
        raise OSError(f"state folder is not a regular directory: {path}")
    if os.name == "nt":
        _, sid = _windows_identity()
        acl = _windows_acl(path)
        entries = acl.get("aces") or []
        permitted = {sid, "S-1-5-18", "S-1-5-32-544", "S-1-3-4"}
        if (not acl.get("protected") or acl.get("owner") != sid
                or any(entry.get("identity") not in permitted
                       or entry.get("type") != "Allow" for entry in entries)
                or not any(entry.get("identity") == sid and entry.get("rights") == "FullControl"
                           for entry in entries)
                or not entries):
            raise PermissionError(f"state folder permissions are not private and writable by the gateway account: {path}")
        parent_acl = _windows_acl(path.parent)
        # A parent that can remove or alter its child can replace the state
        # folder even when the child's own ACL is private.
        unsafe = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000
        if (parent_acl.get("owner") not in permitted or
                any(entry.get("type") == "Allow" and entry.get("identity") not in permitted
                    and (entry.get("mask", 0) & unsafe)
                    for entry in parent_acl.get("aces") or [])):
            raise PermissionError(f"state folder parent allows another account to replace state: {path.parent}")
    else:
        mode = path.stat()
        if mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) != 0o700:
            raise PermissionError(f"state folder must be owned by this account with mode 0700: {path}")
        parent = path.parent.stat()
        if parent.st_uid not in {os.getuid(), 0} or stat.S_IMODE(parent.st_mode) & 0o022:
            raise PermissionError(f"state folder parent is writable by another account: {path.parent}")
    return path


def check_legacy_state(old_folder: str | Path, new_folder: str | Path) -> None:
    """Require an explicit migration before ignoring an old gateway state."""
    old = Path(old_folder)
    if not old.is_dir() or not any(old.iterdir()):
        return
    new = Path(new_folder)
    marker = new / MIGRATION_MARKER
    try:
        record = json.loads(marker.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        record = {}
    if record.get("source") != str(old.resolve()):
        raise RuntimeError(
            f"old gateway state exists in {old}; stop the gateway and run "
            f"python -m http_gateway.state_storage {new} --migrate-from {old}"
        )


def prepare_state_dir(folder: str | Path, *, migrate_from: str | Path | None = None) -> Path:
    """Create an empty private folder, optionally copying the old state folder."""
    path = Path(folder).absolute()
    if path.is_symlink():
        raise ValueError("new state folder must not be a link")
    old = None
    if migrate_from is not None:
        old_requested = Path(migrate_from)
        if old_requested.is_symlink():
            raise ValueError("migration source must not be a link")
        old = old_requested.resolve(strict=True)
        target = path.resolve(strict=False)
        if not old.is_dir() or target == old or target.is_relative_to(old):
            raise ValueError("new state folder must be outside the old state folder")
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise FileExistsError(f"state folder must be new or empty: {path}")
    else:
        path.mkdir(parents=True)
    if os.name == "nt":
        _, sid = _windows_identity()
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F"], capture_output=True, text=True, check=True)
    else:
        path.chmod(0o700)
    verify_state_dir(path)
    if old is not None:
        entries = list(old.iterdir())
        for source in entries:
            if source.is_symlink() or (source.is_dir() and
                    any(item.is_symlink() for item in source.rglob("*"))):
                raise ValueError(f"refusing to migrate a link: {source}")
        for source in entries:
            target = path / source.name
            if source.is_dir():
                shutil.copytree(source, target)
            elif source.is_file():
                shutil.copyfile(source, target)
            else:
                raise ValueError(f"unexpected state entry: {source}")
        if os.name != "nt":
            for item in path.rglob("*"):
                item.chmod(0o700 if item.is_dir() else 0o600)
        marker = path / MIGRATION_MARKER
        marker.write_text(json.dumps({"source": str(old)}), encoding="utf-8")
        if os.name != "nt":
            marker.chmod(0o600)
    return verify_state_dir(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Set up a private gateway state folder")
    parser.add_argument("folder", help="new empty folder for gateway state")
    parser.add_argument("--migrate-from", help="copy files from a stopped gateway's old state folder")
    args = parser.parse_args(argv)
    try:
        path = prepare_state_dir(args.folder, migrate_from=args.migrate_from)
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"private state folder ready: {path}")
    if args.migrate_from:
        print("old state was kept; verify the new gateway before removing the old copy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
