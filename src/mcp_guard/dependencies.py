"""Stage 1 dependency checks: every installed package, not only the server's own.

The MCP Registry and the release digest vouch for the top-level package only.
An npm or PyPI install also brings in dependencies, which is where lookalike
(typosquatted) names and hijacked releases usually enter. This module builds a
dependency lock at approval time and checks it before every start.

At approval (``build_dependency_lock``), for each installed package:

* the release must exist on the public registry, and every installed file must
  equal the published archive (npm tarball, PyPI wheel); this also proves the
  top-level install came from the verified release;
* OSV malicious-package records (``MAL-``) block;
* other OSV advisories (known vulnerabilities, ``GHSA-``/``PYSEC-``/CVE ...) hold the
  start for review: patch management is updating the package, or accepting it;
* a release younger than ``MIN_RELEASE_AGE_DAYS``, files the archive does not
  contain, and builds that cannot be compared hold the start for review;
* B signals (review only): a name that looks like a popular package, install
  scripts, and an npm release without the provenance earlier releases had.

Before every start (``verify_dependency_lock``) the lock must be pinned, made
over the same install tree, free of block findings, accepted if it has review
findings, and the locked versions are checked against OSV again, so a release
reported malicious after approval stops the server, and a vulnerability reported
after approval holds it for review until the package is updated or accepted again.
"""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import json
import re
import tarfile
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from email.parser import HeaderParser
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import quote

from .stage1 import Stage1Error, _NoRedirect, _hash_file, fetch_json, tree_digest, tree_files

STAGE = "1-integration"
MIN_RELEASE_AGE_DAYS = 30  # D6-31: a hijacked release is usually reported within this time
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH = 1000
MAX_PACKUMENT_BYTES = 64_000_000
MAX_ARCHIVE_BYTES = 256_000_000
_NPM_SCRIPTS = ("preinstall", "install", "postinstall")
_DATA = Path(__file__).resolve().parent / "data"
# Files a PyPI installer writes itself, not taken from the wheel.
_INSTALLER_FILES = {"INSTALLER", "REQUESTED", "RECORD", "direct_url.json"}

Fetch = Callable[[str], dict[str, Any]]
FetchBytes = Callable[[str], bytes]
Osv = Callable[[list[tuple[str, str, str]]], list[list[str]]]


# network ---------------------------------------------------------------------


def fetch_metadata(url: str) -> dict[str, Any]:
    return fetch_json(url, max_bytes=MAX_PACKUMENT_BYTES)


def fetch_archive(url: str) -> bytes:
    """Download a release archive from the registry's own file host only."""
    if not url.startswith(("https://registry.npmjs.org/", "https://files.pythonhosted.org/")):
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "Archive is not on the registry file host")
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "mcp-guard-stage1/0.1"})
    try:
        with opener.open(request, timeout=60) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise Stage1Error("S1_METADATA_UNAVAILABLE", "Could not download a release archive") from error
    if len(data) > MAX_ARCHIVE_BYTES:
        raise Stage1Error("S1_METADATA_INVALID", "Release archive exceeds size limit")
    return data


def query_osv(packages: list[tuple[str, str, str]]) -> list[list[str]]:
    """OSV advisory ids for each (ecosystem, name, version); fail closed."""
    ids: list[list[str]] = []
    opener = urllib.request.build_opener(_NoRedirect())
    for start in range(0, len(packages), OSV_BATCH):
        chunk = packages[start:start + OSV_BATCH]
        body = json.dumps({"queries": [
            {"package": {"ecosystem": eco, "name": name}, "version": version}
            for eco, name, version in chunk]}).encode()
        request = urllib.request.Request(OSV_URL, data=body, method="POST", headers={
            "Content-Type": "application/json", "User-Agent": "mcp-guard-stage1/0.1"})
        try:
            with opener.open(request, timeout=30) as response:
                payload = json.loads(response.read(MAX_PACKUMENT_BYTES))
        except (OSError, urllib.error.URLError, ValueError) as error:
            raise Stage1Error("S1_METADATA_UNAVAILABLE", "Could not query OSV") from error
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            raise Stage1Error("S1_METADATA_INVALID", "OSV answer does not match the query")
        for result in results:
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            ids.append([str(v.get("id", "")) for v in vulns if isinstance(v, dict)])
    return ids


# installed packages ----------------------------------------------------------


def installed_packages(provider: str, root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """(packages, unclaimed files) under an install root.

    A package is {"name", "version", "path", "files": {relative path: sha256}};
    paths are relative to ``root``. Unclaimed files belong to no package.
    """
    if provider == "npm":
        return _npm_installed(root)
    if provider == "pypi":
        return _pypi_installed(root)
    raise Stage1Error("S1_SOURCE_UNSUPPORTED", "Dependency checks support npm and pypi")


def _npm_installed(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    packages: list[dict[str, Any]] = []
    claimed: set[str] = set()

    def visit(folder: Path) -> None:
        manifest = folder / "package.json"
        if not folder.is_dir() or folder.is_symlink() or not manifest.is_file():
            return
        try:
            meta = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise Stage1Error("S1_DEPENDENCY_INVALID", f"Unreadable {_rel(root, manifest)}") from error
        files = {}
        for path in folder.rglob("*"):
            relative = path.relative_to(folder)
            if relative.parts[0] == "node_modules" or not path.is_file():
                continue  # nested dependencies are packages of their own
            files[relative.as_posix()] = _hash_file(path)
            claimed.add(_rel(root, path))
        packages.append({"name": str(meta.get("name", "")), "version": str(meta.get("version", "")),
                         "path": _rel(root, folder), "files": files})
        scan(folder / "node_modules")

    def scan(modules: Path) -> None:
        if not modules.is_dir():
            return
        for child in sorted(modules.iterdir()):
            if child.name.startswith("."):
                continue  # .bin launchers and .package-lock.json are written by npm
            if child.name.startswith("@") and child.is_dir():
                for scoped in sorted(child.iterdir()):
                    visit(scoped)
            else:
                visit(child)

    for modules in _top_level(root, "node_modules"):
        scan(modules)
    unclaimed = []
    for modules in _top_level(root, "node_modules"):
        for path in modules.rglob("*"):
            relative = path.relative_to(modules).parts
            if path.is_file() and relative[0] not in {".bin", ".package-lock.json"} \
                    and _rel(root, path) not in claimed:
                unclaimed.append(_rel(root, path))
    return packages, sorted(unclaimed)


def _top_level(root: Path, name: str) -> list[Path]:
    """Directories called ``name`` that are not inside another such directory."""
    found: list[Path] = []
    stack = [root]
    while stack:
        folder = stack.pop()
        for child in sorted(folder.iterdir()):
            if child.is_dir() and not child.is_symlink():
                (found.append(child) if child.name == name else stack.append(child))
    return sorted(found)


def _pypi_installed(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    packages: list[dict[str, Any]] = []
    claimed: set[str] = set()
    sites: set[Path] = set()
    for dist_info in sorted(root.rglob("*.dist-info")):
        if not (dist_info / "METADATA").is_file() or not (dist_info / "RECORD").is_file():
            continue
        site = dist_info.parent
        sites.add(site)
        headers = HeaderParser().parsestr((dist_info / "METADATA").read_text(encoding="utf-8"))
        files = {}
        claimed.add(_rel(root, dist_info / "RECORD"))  # rewritten by the installer
        record = (dist_info / "RECORD").read_text(encoding="utf-8")
        for row in csv.reader(io.StringIO(record)):
            if not row:
                continue
            path = (site / row[0]).resolve()
            if path.is_file() and path.is_relative_to(root):
                files[_rel(site, path) if path.is_relative_to(site) else "../" + _rel(root, path)] = \
                    _hash_file(path)
                claimed.add(_rel(root, path))
        packages.append({"name": str(headers.get("Name", "")), "version": str(headers.get("Version", "")),
                         "path": _rel(root, dist_info), "site": _rel(root, site), "files": files,
                         "tags": [line.split(":", 1)[1].strip() for line in
                                  (dist_info / "WHEEL").read_text(encoding="utf-8").splitlines()
                                  if line.startswith("Tag:")] if (dist_info / "WHEEL").is_file() else []})
    unclaimed = sorted(_rel(root, p) for site in sites for p in site.rglob("*")
                       if p.is_file() and _rel(root, p) not in claimed)
    return packages, unclaimed


def _rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


# approval: the lock ----------------------------------------------------------


def build_dependency_lock(entry: dict[str, Any], *, fetch: Fetch = fetch_metadata,
                          fetch_bytes: FetchBytes = fetch_archive, osv: Osv = query_osv,
                          now: datetime | None = None) -> dict[str, Any]:
    spec = entry.get("stage1") if isinstance(entry.get("stage1"), dict) else {}
    provider = spec.get("provider")
    root = Path(str(spec.get("install_root", "")))
    if provider not in {"npm", "pypi"} or not root.is_absolute() or not root.is_dir():
        raise Stage1Error("S1_SOURCE_NOT_PINNED", "Dependency lock needs an npm or pypi install_root")
    root = root.resolve()
    now = now or datetime.now(UTC)
    packages, unclaimed = installed_packages(provider, root)
    findings: list[dict[str, Any]] = []
    popular = _popular(provider)
    if not popular:  # the PyPI list is downloaded by the user (D6-31)
        findings.append(_finding("B_DEPENDENCY_LOOKALIKE_UNCHECKED", "", f"no popular {provider} "
                                 "name list; run: python mvp/10-local-entry/update_popular_packages.py "
                                 f"--ecosystem {provider}", "review", "B"))
    for package in packages:
        label = f"{package['name']}@{package['version']}"
        try:
            check = _check_npm if provider == "npm" else _check_pypi
            findings += [{**f, "package": label} for f in check(package, root, fetch, fetch_bytes, now)]
        except Stage1Error as error:  # one unreachable package does not hide the rest
            code = "S1_DEPENDENCY_NOT_PUBLISHED" if error.code == "S1_PACKAGE_NOT_PUBLISHED" else error.code
            findings.append(_finding(code, label, str(error), "block", error.marker))
        similar = lookalike(package["name"], popular, provider)
        if similar:
            findings.append(_finding("B_DEPENDENCY_LOOKALIKE_NAME", label,
                                     f"name looks like the popular package {similar!r}", "review", "B"))
    if unclaimed:
        findings.append(_finding("S1_DEPENDENCY_EXTRA_FILE", "", _sample(unclaimed) +
                                 " belong to no installed package", "review"))
    ecosystem = "npm" if provider == "npm" else "PyPI"
    for package, ids in zip(packages, osv([(ecosystem, p["name"], p["version"]) for p in packages])):
        malicious = [i for i in ids if i.startswith("MAL-")]
        if malicious:
            findings.append(_finding("S1_DEPENDENCY_MALICIOUS", f"{package['name']}@{package['version']}",
                                     "OSV malicious package: " + ", ".join(malicious), "block"))
        vulnerable = sorted(i for i in ids if not i.startswith("MAL-"))
        if vulnerable:  # patch management: update the package, or accept knowingly
            findings.append({**_finding("S1_DEPENDENCY_VULNERABLE", f"{package['name']}@{package['version']}",
                                        "known vulnerabilities, update to a fixed release: "
                                        + ", ".join(vulnerable[:10]), "review"),
                             "advisories": vulnerable})
    files = tree_files(root)
    if spec.get("allow_source_builds") is True:  # an explicit exception per server
        findings = [{**f, "verdict": "review"} if f["code"] == "S1_DEPENDENCY_SOURCE_BUILD" else f
                    for f in findings]
    return {"provider": provider, "install_root": str(root),
            "install_tree_sha256": tree_digest(root, files),
            # Lets a later start say which files changed (describe_tree_change).
            "install_tree_files": files,
            "created_at": now.isoformat(timespec="seconds"),
            "packages": [{"name": p["name"], "version": p["version"], "path": p["path"],
                          "files_sha256": _sha256_json(p["files"])} for p in packages],
            "findings": findings, "findings_sha256": _sha256_json(findings), "accepted": None}


def accept_dependency_lock(lock: dict[str, Any], approver: str, user: str) -> dict[str, Any]:
    """Accept the review findings of a lock; block findings cannot be accepted."""
    blocks = [f for f in lock.get("findings", []) if f.get("verdict") == "block"]
    if blocks:
        raise Stage1Error(blocks[0]["code"], "Block findings cannot be accepted: " + blocks[0]["detail"])
    return {**lock, "accepted": {"approver": approver, "user": user,
                                 "at": datetime.now(UTC).isoformat(timespec="seconds"),
                                 "findings_sha256": _sha256_json(lock.get("findings", []))}}


def _check_npm(package: dict[str, Any], root: Path, fetch: Fetch, fetch_bytes: FetchBytes,
               now: datetime) -> list[dict[str, Any]]:
    name, version = package["name"], package["version"]
    if not name or not version:
        return [_finding("S1_DEPENDENCY_INVALID", "", f"{package['path']} has no name or version", "block")]
    # Full document: per-version publish times and earlier releases' provenance.
    packument = fetch(f"https://registry.npmjs.org/{quote(name, safe='@')}")
    versions = packument.get("versions") if isinstance(packument.get("versions"), dict) else {}
    release = versions.get(version)
    if packument.get("name") != name or not isinstance(release, dict):
        return [_finding("S1_DEPENDENCY_NOT_PUBLISHED", "", "release is not on the npm registry", "block")]
    dist = release.get("dist") if isinstance(release.get("dist"), dict) else {}
    expected = _sri_sha512(dist.get("integrity"))
    data = fetch_bytes(str(dist.get("tarball", "")))
    if hashlib.sha512(data).digest() != expected:
        return [_finding("2-A5_DEPENDENCY_TAMPERED", "", "tarball differs from its registry integrity",
                         "block", "2-A5")]
    archive = _tar_files(data)
    findings = _compare(package["files"], archive, ignore=lambda path: False)
    times = packument.get("time") if isinstance(packument.get("time"), dict) else {}
    findings += _age(times.get(version), now)
    scripts = release.get("scripts") if isinstance(release.get("scripts"), dict) else {}
    hooks = [s for s in _NPM_SCRIPTS if s in scripts] + (["node-gyp"] if release.get("gypfile") else [])
    if hooks:
        findings.append(_finding("B_DEPENDENCY_INSTALL_SCRIPT", "", "install scripts: " + ", ".join(hooks),
                                 "review", "B"))
    published = times.get(version, "")
    earlier = [v for v, r in versions.items() if isinstance(r, dict) and v != version and
               str(times.get(v, "")) < str(published) and isinstance(r.get("dist"), dict) and
               r["dist"].get("attestations")]
    if earlier and not dist.get("attestations"):
        findings.append(_finding("B_DEPENDENCY_PROVENANCE_DROPPED", "",
                                 f"earlier releases (e.g. {sorted(earlier)[-1]}) had provenance "
                                 "attestations and this one has none", "review", "B"))
    return findings


def _check_pypi(package: dict[str, Any], root: Path, fetch: Fetch, fetch_bytes: FetchBytes,
                now: datetime) -> list[dict[str, Any]]:
    name, version = package["name"], package["version"]
    if not name or not version:
        return [_finding("S1_DEPENDENCY_INVALID", "", f"{package['path']} has no name or version", "block")]
    release = fetch(f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json")
    info = release.get("info") if isinstance(release.get("info"), dict) else {}
    files = [f for f in release.get("urls", []) if isinstance(f, dict)] \
        if isinstance(release.get("urls"), list) else []
    if _normalize(str(info.get("name", ""))) != _normalize(name) or info.get("version") != version or not files:
        return [_finding("S1_DEPENDENCY_NOT_PUBLISHED", "", "release is not on PyPI", "block")]
    uploads = sorted(str(f.get("upload_time_iso_8601", "")) for f in files if f.get("upload_time_iso_8601"))
    findings = _age(uploads[0] if uploads else None, now)
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel" and
              set(package["tags"]) & _wheel_tags(str(f.get("filename", "")))]
    if not wheels:
        # D6-37: a source build ran the package's setup.py at install time.
        return findings + [_finding("S1_DEPENDENCY_SOURCE_BUILD", "", "no published wheel matches the "
                                    "installed build: it was built from source, which runs setup.py "
                                    "(install with --only-binary :all:)", "block")]
    wheel = next((w for w in wheels if not w.get("yanked")), wheels[0])
    if wheel.get("yanked"):
        findings.append(_finding("S1_DEPENDENCY_YANKED", "", f"{wheel['filename']} is yanked", "review"))
    data = fetch_bytes(str(wheel.get("url", "")))
    digests = wheel.get("digests") if isinstance(wheel.get("digests"), dict) else {}
    if hashlib.sha256(data).hexdigest() != str(digests.get("sha256", "")).lower():
        return findings + [_finding("2-A5_DEPENDENCY_TAMPERED", "", "wheel differs from its PyPI digest",
                                    "block", "2-A5")]
    dist_info = PurePosixPath(package["path"]).name
    return findings + _compare(package["files"], _wheel_files(data), ignore=lambda path: (
        path.startswith("../") or path.endswith(".pyc") or
        (path.startswith(dist_info + "/") and path.split("/", 1)[1] in _INSTALLER_FILES)))


def _compare(installed: dict[str, str], archive: dict[str, str],
             ignore: Callable[[str], bool]) -> list[dict[str, Any]]:
    changed = sorted(p for p, sha in archive.items() if installed.get(p) != sha)
    extra = sorted(p for p in installed if p not in archive and not ignore(p))
    bytecode = sorted(p for p in installed if p.endswith(".pyc"))
    findings = []
    if changed:
        findings.append(_finding("2-A5_DEPENDENCY_TAMPERED", "", _sample(changed) +
                                 " differ from or are missing against the published archive",
                                 "block", "2-A5"))
    if extra:
        findings.append(_finding("S1_DEPENDENCY_EXTRA_FILE", "", _sample(extra) +
                                 " are not in the published archive", "review"))
    if bytecode:
        findings.append(_finding("S1_DEPENDENCY_UNVERIFIED", "", _sample(bytecode) +
                                 " are compiled bytecode that cannot be compared (install with "
                                 "--no-compile)", "review"))
    return findings


def _tar_files(data: bytes) -> dict[str, str]:
    files = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                parts = PurePosixPath(member.name.removeprefix("./")).parts
                if len(parts) < 2 or ".." in parts:
                    raise Stage1Error("2-A5_DEPENDENCY_TAMPERED", "Tarball has an unsafe path", "2-A5")
                stream = archive.extractfile(member)
                files["/".join(parts[1:])] = hashlib.sha256(stream.read() if stream else b"").hexdigest()
    except (tarfile.TarError, OSError, EOFError) as error:
        raise Stage1Error("2-A5_DEPENDENCY_TAMPERED", "Tarball is not a valid archive", "2-A5") from error
    return files


def _wheel_files(data: bytes) -> dict[str, str]:
    files = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            for info in wheel.infolist():
                name = info.filename
                if info.is_dir() or name.endswith(".dist-info/RECORD"):
                    continue
                if ".." in PurePosixPath(name).parts or name.startswith("/"):
                    raise Stage1Error("2-A5_DEPENDENCY_TAMPERED", "Wheel has an unsafe path", "2-A5")
                first, _, rest = name.partition("/")
                if first.endswith(".data"):
                    scheme, _, inside = rest.partition("/")
                    if scheme not in {"purelib", "platlib"}:
                        continue  # scripts, headers, data go outside site-packages
                    name = inside
                files[name] = hashlib.sha256(wheel.read(info)).hexdigest()
    except (zipfile.BadZipFile, OSError) as error:
        raise Stage1Error("2-A5_DEPENDENCY_TAMPERED", "Wheel is not a valid archive", "2-A5") from error
    return files


def _wheel_tags(filename: str) -> set[str]:
    parts = filename.removesuffix(".whl").split("-")
    if len(parts) < 5:
        return set()
    python, abi, platform = parts[-3:]
    return {f"{p}-{a}-{t}" for p in python.split(".") for a in abi.split(".") for t in platform.split(".")}


def _age(published: Any, now: datetime) -> list[dict[str, Any]]:
    try:
        when = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
    except ValueError:
        return [_finding("S1_DEPENDENCY_TOO_NEW", "", "release has no publish time", "review")]
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    if now - when < timedelta(days=MIN_RELEASE_AGE_DAYS):
        return [_finding("S1_DEPENDENCY_TOO_NEW", "", f"published {when.date()}, less than "
                         f"{MIN_RELEASE_AGE_DAYS} days ago", "review")]
    return []


def _sri_sha512(value: Any) -> bytes:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "npm release has no SHA-512 integrity")
    try:
        digest = base64.b64decode(value[7:], validate=True)
    except (ValueError, binascii.Error) as error:
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "npm integrity is malformed") from error
    if len(digest) != 64:
        raise Stage1Error("S1_PACKAGE_INTEGRITY_MISSING", "npm integrity is malformed")
    return digest


# before every start ----------------------------------------------------------

# Lock signals the stage 1 B score also weighs per package (D6-35). With the
# code scan on, they are scored there instead of each needing acceptance here.
SCORED_BY_CODE_SCAN = frozenset({"B_DEPENDENCY_LOOKALIKE_NAME", "B_DEPENDENCY_INSTALL_SCRIPT"})


def describe_tree_change(spec: dict[str, Any], root: Path) -> str:
    """": added a, changed b" from the pinned lock, so a changed tree can be explained.

    Diagnostics only: the decision is the tree hash. Runtime writes into the
    install tree (Python bytecode, npm caches) show up here.
    """
    path = Path(str(spec.get("dependency_lock", "")))
    try:
        if _hash_file(path) != str(spec.get("dependency_lock_sha256", "")).lower():
            return ""
        before = json.loads(path.read_text(encoding="utf-8")).get("install_tree_files")
        after = tree_files(root)
    except (Stage1Error, OSError, ValueError):
        return ""
    if not isinstance(before, dict):
        return ""
    parts = []
    for label, paths in (("added", sorted(set(after) - set(before))),
                         ("changed", sorted(p for p in after if p in before and after[p] != before[p])),
                         ("removed", sorted(set(before) - set(after)))):
        if paths:
            parts.append(f"{label} {_sample(paths)}")
    hint = (" (Python bytecode written at run time: start the server through the wrapper, "
            "which sets PYTHONDONTWRITEBYTECODE, or reinstall with --no-compile)"
            if any(p.endswith(".pyc") for p in after if p not in before) else "")
    return (": " + "; ".join(parts) + hint) if parts else ""



def verify_dependency_lock(spec: dict[str, Any], provider: str, root: Path, tree_sha256: str,
                           identifier: str, version: str, *, osv: Osv = query_osv,
                           scored_elsewhere: frozenset[str] = frozenset()) -> dict[str, str]:
    """Raise Stage1Error unless the pinned lock clears this install (call after tree_digest)."""
    path = Path(str(spec.get("dependency_lock", "")))
    pinned = str(spec.get("dependency_lock_sha256", "")).lower()
    if not path.is_absolute() or not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", pinned):
        raise Stage1Error("S1_DEPENDENCY_LOCK_MISSING", "Stage 1 requires a pinned dependency_lock")
    if _hash_file(path) != pinned:
        raise Stage1Error("2-A5_DEPENDENCY_LOCK_CHANGED", "Dependency lock changed", "2-A5")
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Stage1Error("S1_DEPENDENCY_LOCK_MISSING", "Dependency lock is unreadable") from error
    if lock.get("provider") != provider or lock.get("install_tree_sha256") != tree_sha256:
        raise Stage1Error("2-A5_DEPENDENCY_CHANGED", "Dependency lock was made over another install", "2-A5")
    packages = lock.get("packages", [])
    match = _normalize if provider == "pypi" else (lambda name: name)
    if not any(match(p.get("name", "")) == match(identifier) and p.get("version") == version
               for p in packages):
        raise Stage1Error("S1_PACKAGE_NOT_INSTALLED", "The verified package is not in the install tree")
    findings = lock.get("findings", [])
    blocks = [f for f in findings if f.get("verdict") == "block"]
    if blocks:
        raise Stage1Error(blocks[0]["code"], f"{blocks[0]['package']}: {blocks[0]['detail']}",
                          blocks[0].get("marker", "A"))
    accepted = lock.get("accepted")
    needing = [f for f in findings if f["code"] not in scored_elsewhere]
    if needing and not (isinstance(accepted, dict) and
                        accepted.get("findings_sha256") == _sha256_json(findings)):
        codes = sorted({f["code"] for f in needing})
        raise Stage1Error(codes[0], f"{len(needing)} dependency finding(s) wait for review "
                          f"({', '.join(codes)})", "B" if codes[0].startswith("B_") else "A",
                          verdict="review")
    ecosystem = "npm" if provider == "npm" else "PyPI"
    for package, ids in zip(packages, osv([(ecosystem, p["name"], p["version"]) for p in packages])):
        malicious = [i for i in ids if i.startswith("MAL-")]
        if malicious:
            raise Stage1Error("S1_DEPENDENCY_MALICIOUS",
                              f"{package['name']}@{package['version']} is reported malicious "
                              f"({', '.join(malicious)})")
        label = f"{package['name']}@{package['version']}"
        known = {a for f in findings if f.get("code") == "S1_DEPENDENCY_VULNERABLE" and f.get("package") == label
                 for a in f.get("advisories", [])}
        new = sorted(i for i in ids if not i.startswith("MAL-") and i not in known)
        if new:
            raise Stage1Error("S1_DEPENDENCY_VULNERABLE",
                              f"{label} has vulnerability reports newer than its approval ({', '.join(new[:10])}); "
                              "update it, or run deps again and accept", verdict="review")
    return {"dependencies": str(len(packages)), "dependency_lock_sha256": pinned,
            "dependency_findings_accepted": str(len(findings))}


# lookalike names ---------------------------------------------------------------


def lookalike(name: str, popular: tuple[str, ...], provider: str) -> str | None:
    """The popular name ``name`` imitates, if any (D6-31).

    Damerau-Levenshtein distance 1 (one insertion, deletion, or swap of
    neighbours for names of 5+ characters; one substitution for 7+), found
    through a deletion index instead of comparing with every popular name; and
    three rule-based forms from the typosquatting literature: different
    separators (crossenv), reordered parts (env-cross), and ASCII homographs
    (l0dash, rnocha). Jaro-Winkler and Dice need a pass over every popular name
    and weigh shared prefixes, which legitimate plugin families share.
    """
    if not popular:
        return None
    names, rank, squashed, deletions, reordered, homographs = _index(popular, provider)
    key = _normalize(name) if provider == "pypi" else name.lower()
    if key in names:
        return None
    for match in (squashed.get(_squash(key)), reordered.get(_tokens(key)),
                  homographs.get(_homograph(key))):
        if match and match != key:
            return match
    candidates = set(deletions.get(key, ()))
    for shorter in _deletions(key):
        candidates |= deletions.get(shorter, set())
        if shorter in names:
            candidates.add(shorter)
    candidates = {c for c in candidates if _distance(key, c) == 1 and
                  # A one-letter substitution in a short name is too often a real,
                  # different package (server/semver); require a longer name.
                  len(c) >= (7 if _substitution(key, c) else 5)}
    return min(candidates, key=rank.__getitem__) if candidates else None


def _substitution(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    differ = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
    return not (len(differ) == 2 and differ[1] == differ[0] + 1 and
                left[differ[0]] == right[differ[1]] and left[differ[1]] == right[differ[0]])


@lru_cache(maxsize=4)
def _index(popular: tuple[str, ...], provider: str):
    keys = [_normalize(n) if provider == "pypi" else n.lower() for n in popular]
    rank = {k: i for i, k in reversed(list(enumerate(keys)))}
    squashed: dict[str, str] = {}
    deletions: dict[str, set[str]] = {}
    reordered: dict[tuple[str, ...], str] = {}
    homographs: dict[str, str] = {}
    for key in keys:  # most popular first, so setdefault keeps the most popular
        squashed.setdefault(_squash(key), key)
        if len(_tokens(key)) > 1:
            reordered.setdefault(_tokens(key), key)
        homographs.setdefault(_homograph(key), key)
        for shorter in _deletions(key):
            deletions.setdefault(shorter, set()).add(key)
    return set(keys), rank, squashed, deletions, reordered, homographs


def _squash(key: str) -> str:
    return re.sub(r"[-_.]", "", key)


def _tokens(key: str) -> tuple[str, ...]:
    return tuple(sorted(t for t in re.split(r"[-_./]", key.lstrip("@")) if t))


# ASCII characters that read as others in a package name.
_HOMOGRAPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("i", "l"))


def _homograph(key: str) -> str:
    for source, target in _HOMOGRAPHS:
        key = key.replace(source, target)
    return key


def _deletions(text: str) -> set[str]:
    return {text[:i] + text[i + 1:] for i in range(len(text))}


def _distance(left: str, right: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance."""
    rows = [list(range(len(right) + 1))]
    for i, a in enumerate(left, 1):
        row = [i]
        for j, b in enumerate(right, 1):
            row.append(min(rows[-1][j] + 1, row[j - 1] + 1, rows[-1][j - 1] + (a != b)))
            if i > 1 and j > 1 and a == right[j - 2] and left[i - 2] == b:
                row[j] = min(row[j], rows[-2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


@lru_cache(maxsize=2)
def _popular(provider: str) -> tuple[str, ...]:
    path = _DATA / f"popular_{provider}.txt"
    if not path.is_file():
        return ()
    return tuple(line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.startswith("#"))


# helpers -------------------------------------------------------------------------


def _finding(code: str, package: str, detail: str, verdict: str, marker: str = "A") -> dict[str, Any]:
    return {"code": code, "package": package, "detail": detail, "verdict": verdict,
            "marker": marker, "stage": STAGE}


def _sample(paths: list[str]) -> str:
    shown = ", ".join(paths[:5])
    return f"{len(paths)} file(s) ({shown}{', ...' if len(paths) > 5 else ''})"


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha256_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
