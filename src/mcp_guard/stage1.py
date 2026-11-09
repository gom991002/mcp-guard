"""Stage 1 admission for guarded local MCP servers, before a child is started.

The official MCP Registry establishes the advertised publisher/package link.
The package registry supplies the release digest. For npm and PyPI, a
dependency lock (``dependencies.py``) compares every installed package with its
published archive at approval time, which also ties the installed top-level
package to the verified release. Docker Toolkit verifies image signatures when
the pinned catalog is launched with --verify-signatures.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

REGISTRY = "https://registry.modelcontextprotocol.io"
OFFICIAL_META = "io.modelcontextprotocol.registry/official"
MAX_METADATA_BYTES = 2_000_000
_HEX_SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
_SERVER_NAME = re.compile(r"[A-Za-z0-9.-]+/[A-Za-z0-9._-]+\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+\-]*\Z")


class Stage1Error(ValueError):
    def __init__(self, code: str, message: str, marker: str = "A", verdict: str = "block") -> None:
        super().__init__(message)
        self.code = code
        self.marker = marker
        # "review" holds the start until a person accepts; everything else blocks.
        self.verdict = verdict


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise Stage1Error("S1_METADATA_REDIRECT", "Metadata endpoint redirected")


def fetch_json(url: str, max_bytes: int = MAX_METADATA_BYTES) -> dict[str, Any]:
    """Read bounded metadata from a fixed official HTTPS endpoint."""
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers={
        "Accept": "application/json", "User-Agent": "mcp-guard-stage1/0.1"})
    try:
        with opener.open(request, timeout=5) as response:
            if response.headers.get_content_type() != "application/json":
                raise Stage1Error("S1_METADATA_INVALID", "Metadata is not JSON")
            raw = response.read(max_bytes + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise Stage1Error("S1_PACKAGE_NOT_PUBLISHED", "Release is not published") from error
        raise Stage1Error("S1_METADATA_UNAVAILABLE", "Could not retrieve stage 1 metadata") from error
    except (OSError, urllib.error.URLError) as error:
        raise Stage1Error("S1_METADATA_UNAVAILABLE", "Could not retrieve stage 1 metadata") from error
    if len(raw) > max_bytes:
        raise Stage1Error("S1_METADATA_INVALID", "Metadata exceeds size limit")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Stage1Error("S1_METADATA_INVALID", "Metadata is malformed") from error
    if not isinstance(result, dict):
        raise Stage1Error("S1_METADATA_INVALID", "Metadata must be an object")
    return result


def verify_stage1(entry: dict[str, Any], *,
                  fetch: Callable[[str], dict[str, Any]] = fetch_json,
                  osv: Callable[[list[tuple[str, str, str]]], list[list[str]]] | None = None,
                  b_scored_elsewhere: frozenset[str] = frozenset(),
                  trusted_publishers: frozenset[str] = frozenset(),
                  ) -> dict[str, str]:
    """Fail closed unless a guarded local entry has a complete, pinned source.

    ``trusted_publishers``: the policy's ``trusted_registry_publishers``; when
    set, an npm/PyPI server's Registry name must start with one of them.
    Docker and ``local`` servers have no Registry publisher and are not checked.

    npm and PyPI entries also need a pinned dependency lock (``dependencies``);
    ``osv`` replaces the OSV malicious-package lookup in tests.
    ``b_scored_elsewhere``: lock signals the code scan's B score weighs (D6-35).
    """
    spec = entry.get("stage1")
    if not isinstance(spec, dict):
        raise Stage1Error("S1_SOURCE_NOT_PINNED", "Guarded local server needs stage1 settings")
    provider = spec.get("provider")
    if provider == "docker":
        return _verify_docker(entry, spec)
    if provider == "local":
        return _verify_local(entry, spec)
    if provider not in {"npm", "pypi"}:
        raise Stage1Error("S1_SOURCE_UNSUPPORTED", "Stage 1 provider must be npm, pypi, docker, or local")
    return _verify_package(entry, spec, fetch, osv, b_scored_elsewhere, trusted_publishers)


def _verify_package(entry: dict[str, Any], spec: dict[str, Any],
                    fetch: Callable[[str], dict[str, Any]],
                    osv: Callable[[list[tuple[str, str, str]]], list[list[str]]] | None,
                    b_scored_elsewhere: frozenset[str] = frozenset(),
                    trusted_publishers: frozenset[str] = frozenset(),
                    ) -> dict[str, str]:
    provider = spec["provider"]
    name = _required(spec, "registry_name")
    if not _SERVER_NAME.fullmatch(name):
        raise Stage1Error("S1_REGISTRY_ID_INVALID", "Registry name is not a full namespace/server name")
    publisher = name.partition("/")[0]
    if trusted_publishers and publisher not in trusted_publishers:
        raise Stage1Error("S1_REGISTRY_PUBLISHER_NOT_ALLOWED",
                          f"Registry publisher {publisher} is not in the policy's trusted_registry_publishers")
    registry_version = _version(spec, "registry_version")
    identifier = _required(spec, "package_identifier")
    package_version = _version(spec, "package_version")
    archive = _local_file(spec, "artifact_path")
    approved_digest = _sha256(spec, "artifact_sha256")
    install_root = _local_directory(spec, "install_root")
    installed_digest = _sha256(spec, "install_tree_sha256")
    executable = _local_file(entry, "command")
    executable_digest = _sha256(spec, "executable_sha256")
    if not executable.is_relative_to(install_root):
        raise Stage1Error("S1_LOCAL_FILE_UNVERIFIED", "Server executable is outside the approved install tree")
    if tree_digest(install_root) != installed_digest:
        from .dependencies import describe_tree_change

        raise Stage1Error("2-A5_INSTALL_CHANGED", "Installed package tree changed" +
                          describe_tree_change(spec, install_root), "2-A5")
    if _hash_file(archive) != approved_digest:
        raise Stage1Error("2-A5_ARTIFACT_CHANGED", "Local package archive changed", "2-A5")
    if _hash_file(executable) != executable_digest:
        raise Stage1Error("2-A5_EXECUTABLE_CHANGED", "Local server executable changed", "2-A5")

    url = (f"{REGISTRY}/v0.1/servers/{quote(name, safe='')}/versions/"
           f"{quote(registry_version, safe='')}")
    record = fetch(url)
    server = record.get("server")
    official = record.get("_meta", {}).get(OFFICIAL_META) if isinstance(record.get("_meta"), dict) else None
    if (not isinstance(server, dict) or server.get("name") != name or
            server.get("version") != registry_version or
            not isinstance(official, dict) or official.get("status") != "active"):
        raise Stage1Error("S1_REGISTRY_ID_MISMATCH", "Registry record or status differs from approval")
    packages = server.get("packages")
    if not isinstance(packages, list):
        raise Stage1Error("S1_PACKAGE_NOT_LISTED", "Registry has no matching package")
    expected_base = "https://registry.npmjs.org" if provider == "npm" else "https://pypi.org"
    matched = [p for p in packages if isinstance(p, dict) and
               p.get("registryType") == provider and p.get("registryBaseUrl") == expected_base and
               p.get("identifier") == identifier and p.get("version") == package_version and
               isinstance(p.get("transport"), dict) and p["transport"].get("type") == "stdio"]
    if len(matched) != 1:
        raise Stage1Error("S1_PACKAGE_NOT_LISTED", "Package is not uniquely listed by the registry")
    file_sha = matched[0].get("fileSha256")
    if file_sha is not None and file_sha != approved_digest:
        raise Stage1Error("2-A5_ARTIFACT_CHANGED", "Registry package digest differs", "2-A5")

    if provider == "npm":
        _verify_npm(fetch, identifier, package_version, archive, approved_digest)
    else:
        _verify_pypi(fetch, identifier, package_version, archive, approved_digest)
    from .dependencies import query_osv, verify_dependency_lock

    dependencies = verify_dependency_lock(spec, provider, install_root, installed_digest,
                                          identifier, package_version, osv=osv or query_osv,
                                          scored_elsewhere=b_scored_elsewhere)
    return {**dependencies, "provider": provider, "registry_name": name,
            "registry_version": registry_version, "package_identifier": identifier,
            "package_version": package_version, "artifact_sha256": approved_digest,
            "executable_sha256": executable_digest, "install_tree_sha256": installed_digest}


def _verify_npm(fetch: Callable[[str], dict[str, Any]], identifier: str,
                version: str, archive: Path, approved_digest: str) -> None:
    url = f"https://registry.npmjs.org/{quote(identifier, safe='')}/{quote(version, safe='')}"
    release = fetch(url)
    dist = release.get("dist")
    if release.get("name") != identifier or release.get("version") != version or not isinstance(dist, dict):
        raise Stage1Error("S1_PACKAGE_RELEASE_MISMATCH", "npm release identity differs")
    integrity = dist.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "npm release has no SHA-512 integrity")
    try:
        expected = base64.b64decode(integrity[7:], validate=True)
    except (ValueError, binascii.Error) as error:
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "npm integrity is malformed") from error
    if len(expected) != 64 or _hash_file(archive, "sha512") != expected.hex():
        raise Stage1Error("2-A5_ARTIFACT_CHANGED", "npm tarball digest differs", "2-A5")
    if _hash_file(archive) != approved_digest:
        raise Stage1Error("2-A5_ARTIFACT_CHANGED", "npm tarball changed", "2-A5")


def _verify_pypi(fetch: Callable[[str], dict[str, Any]], identifier: str,
                 version: str, archive: Path, approved_digest: str) -> None:
    url = f"https://pypi.org/pypi/{quote(identifier, safe='')}/{quote(version, safe='')}/json"
    release = fetch(url)
    info = release.get("info")
    normalized = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    if (not isinstance(info, dict) or info.get("version") != version or
            not isinstance(info.get("name"), str) or normalized(info["name"]) != normalized(identifier)):
        raise Stage1Error("S1_PACKAGE_RELEASE_MISMATCH", "PyPI release version differs")
    files = release.get("urls")
    if not isinstance(files, list):
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "PyPI release has no files")
    matches = [item for item in files if isinstance(item, dict) and
               item.get("filename") == archive.name and not item.get("yanked")]
    if len(matches) != 1:
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "PyPI distribution is absent or yanked")
    digests = matches[0].get("digests")
    expected = digests.get("sha256") if isinstance(digests, dict) else None
    if not isinstance(expected, str) or not _HEX_SHA256.fullmatch(expected):
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "PyPI release has no SHA-256 digest")
    if expected.lower() != approved_digest:
        raise Stage1Error("2-A5_ARTIFACT_CHANGED", "PyPI distribution digest differs", "2-A5")


def _verify_docker(entry: dict[str, Any], spec: dict[str, Any]) -> dict[str, str]:
    catalog = _local_file(spec, "catalog_path")
    approved_digest = _sha256(spec, "catalog_sha256")
    if _hash_file(catalog) != approved_digest:
        raise Stage1Error("2-A5_CATALOG_CHANGED", "Docker catalog changed", "2-A5")
    server_id = _required(spec, "server_id")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", server_id):
        raise Stage1Error("S1_DOCKER_CONFIG_INVALID", "Docker server ID is invalid")
    executable = _local_file(entry, "command")
    executable_digest = _sha256(spec, "executable_sha256")
    if _hash_file(executable) != executable_digest:
        raise Stage1Error("2-A5_EXECUTABLE_CHANGED", "Docker executable changed", "2-A5")
    if executable.stem.lower() != "docker":
        raise Stage1Error("S1_DOCKER_CONFIG_INVALID", "Docker provider requires the Docker CLI")
    expected_args = ["mcp", "gateway", "run", "--catalog", str(catalog),
                     "--servers", server_id, "--verify-signatures", "--watch=false"]
    if entry.get("args") != expected_args:
        raise Stage1Error("S1_DOCKER_CONFIG_INVALID", "Docker gateway must use the pinned catalog and signature verification")
    return {"provider": "docker", "server_id": server_id,
            "catalog_sha256": approved_digest, "executable_sha256": executable_digest}


def _verify_local(entry: dict[str, Any], spec: dict[str, Any]) -> dict[str, str]:
    """Explicitly approved private executable and supporting code files."""
    executable = _local_file(entry, "command")
    approved = _sha256(spec, "executable_sha256")
    if _hash_file(executable) != approved:
        raise Stage1Error("2-A5_EXECUTABLE_CHANGED", "Local executable changed", "2-A5")
    files = spec.get("files")
    if not isinstance(files, dict) or not files:
        raise Stage1Error("S1_SOURCE_NOT_PINNED", "Local provider needs pinned code files")
    for name, value in files.items():
        if not isinstance(name, str):
            raise Stage1Error("S1_SOURCE_NOT_PINNED", "Pinned file path must be a string")
        path = _local_file({"path": name}, "path")
        if _hash_file(path) != _sha256({"sha256": value}, "sha256"):
            raise Stage1Error("2-A5_FILE_CHANGED", "Local server code file changed", "2-A5")
    return {"provider": "local", "executable_sha256": approved,
            "pinned_files": str(len(files))}


def _required(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise Stage1Error("S1_SOURCE_NOT_PINNED", f"Stage 1 requires {key}")
    return value


def _version(payload: dict[str, Any], key: str) -> str:
    value = _required(payload, key)
    if not _VERSION.fullmatch(value) or value.lower() == "latest":
        raise Stage1Error("2-A5_VERSION_NOT_PINNED", f"{key} must be an exact version", "2-A5")
    return value


def _sha256(payload: dict[str, Any], key: str) -> str:
    value = _required(payload, key)
    if not _HEX_SHA256.fullmatch(value):
        raise Stage1Error("S1_SOURCE_NOT_PINNED", f"{key} must be a SHA-256 hex digest")
    return value.lower()


def _local_file(payload: dict[str, Any], key: str) -> Path:
    value = _required(payload, key)
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise Stage1Error("S1_LOCAL_FILE_UNVERIFIED", f"{key} must be an existing absolute regular file")
    return path.resolve()


def _local_directory(payload: dict[str, Any], key: str) -> Path:
    value = _required(payload, key)
    path = Path(value)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Stage1Error("S1_LOCAL_FILE_UNVERIFIED", f"{key} must be an existing absolute directory")
    return path.resolve()


def tree_files(root: Path) -> dict[str, str]:
    """SHA-256 of every installed file by relative path; reject links and empty trees."""
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise Stage1Error("S1_LOCAL_FILE_UNVERIFIED", "Installed tree contains a symbolic link")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = _hash_file(path)
    if not files:
        raise Stage1Error("S1_LOCAL_FILE_UNVERIFIED", "Installed tree is empty")
    return files


def tree_digest(root: Path, files: dict[str, str] | None = None) -> str:
    """One hash over every installed file and its relative path."""
    digest = hashlib.sha256()
    for relative, sha in (files if files is not None else tree_files(root)).items():
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(bytes.fromhex(sha))
    return digest.hexdigest()


def _hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise Stage1Error("S1_LOCAL_FILE_UNVERIFIED", "Could not read pinned file") from error
    return digest.hexdigest()
