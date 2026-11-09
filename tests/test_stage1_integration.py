"""Stage 1 must check an advertised publisher, release, and the bytes used locally."""

import base64
import csv
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from mcp_guard.dependencies import accept_dependency_lock, build_dependency_lock, lookalike
from mcp_guard.stage1 import Stage1Error, tree_digest, verify_stage1

OLD = "2024-01-01T00:00:00.000Z"
NOW = datetime(2026, 11, 2, tzinfo=UTC)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tgz(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo("package/" + name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class FakeNpm:
    """npm registry, OSV, and the MCP Registry for one install tree."""

    def __init__(self) -> None:
        self.packages: dict[str, dict] = {}  # name -> packument
        self.tarballs: dict[str, bytes] = {}
        self.malicious: set[tuple[str, str]] = set()

    def publish(self, name, version, files, time=OLD, scripts=None, attestations=False) -> bytes:
        data = _tgz(files)
        url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"
        self.tarballs[url] = data
        dist = {"integrity": _sri(data), "tarball": url}
        if attestations:
            dist["attestations"] = {"url": "https://registry.npmjs.org/-/npm/v1/attestations/x"}
        packument = self.packages.setdefault(name, {"name": name, "versions": {}, "time": {}})
        packument["versions"][version] = {"name": name, "version": version, "dist": dist,
                                          "scripts": scripts or {}}
        packument["time"][version] = time
        return data

    def fetch(self, url):
        if "registry.modelcontextprotocol.io" in url:
            return {"server": {
                "name": "io.github.owner/server", "version": "1.2.3",
                "packages": [{"registryType": "npm", "registryBaseUrl": "https://registry.npmjs.org",
                              "identifier": "@owner/server", "version": "1.2.3",
                              "transport": {"type": "stdio"}}],
            }, "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active"}}}
        path = url.removeprefix("https://registry.npmjs.org/").replace("%2F", "/").replace("%40", "@")
        for name, packument in self.packages.items():
            if path == name:
                return packument
            if path.startswith(name + "/"):
                return packument["versions"][path[len(name) + 1:]]
        raise Stage1Error("S1_PACKAGE_NOT_PUBLISHED", "Release is not published")

    def fetch_bytes(self, url):
        return self.tarballs[url]

    def osv(self, packages):
        return [["MAL-2026-1"] if (name, version) in self.malicious
                else sorted(getattr(self, "vulnerable", {}).get((name, version), []))
                for _, name, version in packages]


def _install(root: Path, name: str, files: dict[str, bytes]) -> None:
    folder = root / "node_modules" / name
    for relative, data in files.items():
        (folder / relative).parent.mkdir(parents=True, exist_ok=True)
        (folder / relative).write_bytes(data)


class Stage1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.install_root = self.root / "installed"
        self.install_root.mkdir()
        self.npm = FakeNpm()
        server_files = {"package.json": b'{"name": "@owner/server", "version": "1.2.3"}',
                        "server.js": b"approved program"}
        self.archive = self.root / "server-1.2.3.tgz"
        self.archive.write_bytes(self.npm.publish("@owner/server", "1.2.3", server_files))
        _install(self.install_root, "@owner/server", server_files)
        self.dependency = {"package.json": b'{"name": "left-pad", "version": "1.3.0"}',
                           "index.js": b"module.exports = pad"}
        self.npm.publish("left-pad", "1.3.0", self.dependency, attestations=False)
        _install(self.install_root, "left-pad", self.dependency)
        self.executable = self.install_root / "node_modules" / "@owner" / "server" / "server.js"
        self.entry = {"command": str(self.executable), "args": [], "stage1": {
            "provider": "npm", "registry_name": "io.github.owner/server",
            "registry_version": "1.2.3", "package_identifier": "@owner/server",
            "package_version": "1.2.3", "artifact_path": str(self.archive),
            "artifact_sha256": _sha(self.archive.read_bytes()),
            "executable_sha256": _sha(self.executable.read_bytes()),
            "install_root": str(self.install_root),
        }}
        self._lock()

    def _lock(self, accept=False) -> dict:
        spec = self.entry["stage1"]
        spec["install_tree_sha256"] = tree_digest(self.install_root)
        lock = build_dependency_lock(self.entry, fetch=self.npm.fetch,
                                     fetch_bytes=self.npm.fetch_bytes, osv=self.npm.osv, now=NOW)
        if accept:
            lock = accept_dependency_lock(lock, "service", "admin")
        path = self.root / "lock.json"
        path.write_text(json.dumps(lock), encoding="utf-8")
        spec.update(dependency_lock=str(path), dependency_lock_sha256=_sha(path.read_bytes()))
        return lock

    def _verify(self):
        return verify_stage1(self.entry, fetch=self.npm.fetch, osv=self.npm.osv)

    def _codes(self, lock) -> set[str]:
        return {f["code"] for f in lock["findings"]}

    def _error(self) -> Stage1Error:
        with self.assertRaises(Stage1Error) as error:
            self._verify()
        return error.exception

    def test_npm_release_and_both_local_files_must_match(self) -> None:
        evidence = self._verify()
        self.assertEqual(evidence["artifact_sha256"], _sha(self.archive.read_bytes()))
        self.assertEqual(evidence["dependencies"], "2")

        self.archive.write_bytes(b"changed archive")
        self.assertEqual(self._error().code, "2-A5_ARTIFACT_CHANGED")

    def test_policy_can_limit_registry_publishers(self) -> None:
        def verify(publishers):
            return verify_stage1(self.entry, fetch=self.npm.fetch, osv=self.npm.osv,
                                 trusted_publishers=frozenset(publishers))

        self.assertEqual(verify(())["provider"], "npm")  # no list: any publisher, as before
        self.assertEqual(verify(("io.github.owner",))["provider"], "npm")
        with self.assertRaises(Stage1Error) as error:
            verify(("io.github.company",))
        self.assertEqual(error.exception.code, "S1_REGISTRY_PUBLISHER_NOT_ALLOWED")
        with self.assertRaises(Stage1Error):
            verify(("io.github",))  # the whole namespace, not a prefix of it

    def test_registry_identity_cannot_be_substituted(self) -> None:
        original = self.npm.fetch

        def fake(url):
            record = original(url)
            if "registry.modelcontextprotocol.io" in url:
                record["server"]["name"] = "io.github.other/server"
            return record

        self.npm.fetch = fake
        self.assertEqual(self._error().code, "S1_REGISTRY_ID_MISMATCH")

    def test_changes_to_installed_dependencies_block_launch(self) -> None:
        (self.install_root / "node_modules" / "left-pad" / "index.js").write_bytes(b"new code")
        error = self._error()
        self.assertEqual(error.code, "2-A5_INSTALL_CHANGED")
        self.assertIn("changed 1 file(s) (node_modules/left-pad/index.js)", str(error))

    def test_runtime_bytecode_is_named_with_a_hint(self) -> None:
        cache = self.install_root / "node_modules" / "left-pad" / "__pycache__"
        cache.mkdir()
        (cache / "x.cpython-313.pyc").write_bytes(b"bytecode")
        message = str(self._error())
        self.assertIn("added 1 file(s)", message)
        self.assertIn("PYTHONDONTWRITEBYTECODE", message)

    def test_unpinned_and_dynamic_launches_fail_closed(self) -> None:
        self.entry["stage1"]["registry_version"] = "latest"
        self.assertEqual(self._error().code, "2-A5_VERSION_NOT_PINNED")
        self.entry["stage1"] = None
        self.assertEqual(self._error().code, "S1_SOURCE_NOT_PINNED")

    # dependencies -----------------------------------------------------------

    def test_lock_is_required_and_pinned(self) -> None:
        lock_path = Path(self.entry["stage1"]["dependency_lock"])
        lock_path.write_text(lock_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        self.assertEqual(self._error().code, "2-A5_DEPENDENCY_LOCK_CHANGED")
        del self.entry["stage1"]["dependency_lock"]
        self.assertEqual(self._error().code, "S1_DEPENDENCY_LOCK_MISSING")

    def test_installed_file_that_differs_from_the_published_tarball_blocks(self) -> None:
        # Tampered before approval: the tree hash is pinned over the bad file.
        (self.install_root / "node_modules" / "left-pad" / "index.js").write_bytes(b"stealer")
        lock = self._lock(accept=False)

        self.assertIn("2-A5_DEPENDENCY_TAMPERED", self._codes(lock))
        self.assertEqual(self._error().code, "2-A5_DEPENDENCY_TAMPERED")
        with self.assertRaises(Stage1Error):
            accept_dependency_lock(lock, "service", "admin")  # blocks cannot be accepted

    def test_top_level_install_is_tied_to_the_verified_release(self) -> None:
        self.executable.write_bytes(b"not from the tarball")
        self.entry["stage1"]["executable_sha256"] = _sha(self.executable.read_bytes())
        lock = self._lock()

        tampered = [f for f in lock["findings"] if f["code"] == "2-A5_DEPENDENCY_TAMPERED"]
        self.assertEqual(tampered[0]["package"], "@owner/server@1.2.3")

    def test_lookalike_dependency_holds_for_review_until_accepted(self) -> None:
        files = {"package.json": b'{"name": "crossenv", "version": "6.1.1"}', "index.js": b"x"}
        self.npm.publish("crossenv", "6.1.1", files)
        _install(self.install_root, "crossenv", files)
        lock = self._lock()

        self.assertIn("B_DEPENDENCY_LOOKALIKE_NAME", self._codes(lock))
        error = self._error()
        self.assertEqual(error.verdict, "review")  # B raises to review, never block
        # With the code scan on, the per-package B score weighs it instead (D6-35).
        from mcp_guard.dependencies import SCORED_BY_CODE_SCAN

        self.assertEqual(verify_stage1(self.entry, fetch=self.npm.fetch, osv=self.npm.osv,
                                       b_scored_elsewhere=SCORED_BY_CODE_SCAN)["dependencies"], "3")
        self._lock(accept=True)
        self.assertEqual(self._verify()["dependencies"], "3")

    def test_hijack_signals_new_release_install_script_and_dropped_provenance(self) -> None:
        old = {"package.json": b'{"name": "tiny-lib", "version": "2.0.0"}', "index.js": b"ok"}
        new = {"package.json": b'{"name": "tiny-lib", "version": "2.0.1"}', "index.js": b"bad"}
        self.npm.publish("tiny-lib", "2.0.0", old, attestations=True)
        self.npm.publish("tiny-lib", "2.0.1", new, time="2026-11-01T00:00:00.000Z",
                         scripts={"postinstall": "node steal.js"})
        _install(self.install_root, "tiny-lib", new)
        lock = self._lock()

        found = {f["code"] for f in lock["findings"] if f["package"] == "tiny-lib@2.0.1"}
        self.assertEqual(found, {"S1_DEPENDENCY_TOO_NEW", "B_DEPENDENCY_INSTALL_SCRIPT",
                                 "B_DEPENDENCY_PROVENANCE_DROPPED"})
        self.assertEqual(self._error().verdict, "review")

    def test_malicious_report_blocks_at_lock_time_and_after_approval(self) -> None:
        self.npm.malicious.add(("left-pad", "1.3.0"))
        self.assertIn("S1_DEPENDENCY_MALICIOUS", self._codes(self._lock()))

        self.npm.malicious.clear()
        self._lock()
        self.assertEqual(self._verify()["dependencies"], "2")
        self.npm.malicious.add(("left-pad", "1.3.0"))  # reported after approval
        error = self._error()
        self.assertEqual((error.code, error.verdict), ("S1_DEPENDENCY_MALICIOUS", "block"))

    def test_known_vulnerabilities_wait_for_an_update_or_acceptance(self) -> None:
        """Patch management: a vulnerable release is held; a report after approval holds it again."""
        self.npm.vulnerable = {("left-pad", "1.3.0"): ["GHSA-aaaa"]}
        lock = self._lock()
        finding = next(f for f in lock["findings"] if f["code"] == "S1_DEPENDENCY_VULNERABLE")
        self.assertEqual((finding["package"], finding["advisories"], finding["verdict"]),
                         ("left-pad@1.3.0", ["GHSA-aaaa"], "review"))
        self.assertEqual(self._error().code, "S1_DEPENDENCY_VULNERABLE")  # not accepted yet
        self._lock(accept=True)
        self.assertEqual(self._verify()["dependencies"], "2")
        self.npm.vulnerable = {("left-pad", "1.3.0"): ["GHSA-aaaa", "GHSA-bbbb"]}  # reported later
        error = self._error()
        self.assertEqual((error.code, error.verdict), ("S1_DEPENDENCY_VULNERABLE", "review"))
        self.assertIn("GHSA-bbbb", str(error))

    def test_unpublished_dependency_and_stray_files_are_found(self) -> None:
        files = {"package.json": b'{"name": "internal-only", "version": "1.0.0"}'}
        _install(self.install_root, "internal-only", files)
        (self.install_root / "node_modules" / "stray.js").write_bytes(b"x")
        lock = self._lock()

        self.assertIn("S1_DEPENDENCY_NOT_PUBLISHED", self._codes(lock))
        self.assertIn("S1_DEPENDENCY_EXTRA_FILE", self._codes(lock))

    def test_osv_outage_fails_closed(self) -> None:
        def down(packages):
            raise Stage1Error("S1_METADATA_UNAVAILABLE", "Could not query OSV")

        self.npm.osv = down
        self.assertEqual(self._error().code, "S1_METADATA_UNAVAILABLE")

    # other providers ----------------------------------------------------------

    def test_pypi_checks_exact_distribution_dependencies_and_yanked_status(self) -> None:
        site = self.root / "venv" / "Lib" / "site-packages"
        wheels = {}

        def install(name, version, modules):
            files = {f"{name}/{m}": data for m, data in modules.items()}
            dist_info = f"{name}-{version}.dist-info"
            files[f"{dist_info}/METADATA"] = f"Name: {name}\nVersion: {version}\n".encode()
            files[f"{dist_info}/WHEEL"] = b"Wheel-Version: 1.0\nTag: py3-none-any\n"
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as wheel:
                for path, data in files.items():
                    wheel.writestr(path, data)
            filename = f"{name}-{version}-py3-none-any.whl"
            wheels[filename] = buffer.getvalue()
            record = io.StringIO()
            for path, data in files.items():
                (site / path).parent.mkdir(parents=True, exist_ok=True)
                (site / path).write_bytes(data)
                csv.writer(record).writerow([path, "", ""])
            for written in ("INSTALLER", "RECORD"):  # pip lists the files it writes itself
                csv.writer(record).writerow([f"{dist_info}/{written}", "", ""])
            (site / dist_info / "INSTALLER").write_text("pip\n", encoding="utf-8")
            (site / dist_info / "RECORD").write_text(record.getvalue(), encoding="utf-8")
            return filename

        server_wheel = install("server", "1.2.3", {"__init__.py": b"approved"})
        install("idna", "3.7", {"core.py": b"idna"})
        self.archive = self.root / server_wheel
        self.archive.write_bytes(wheels[server_wheel])
        executable = site / "server" / "__init__.py"
        yanked = {"value": False}

        def fetch(url):
            if "registry.modelcontextprotocol.io" in url:
                record = self.npm.fetch(url)
                record["server"]["packages"][0].update(
                    registryType="pypi", registryBaseUrl="https://pypi.org", identifier="server")
                return record
            name, version = url.removeprefix("https://pypi.org/pypi/").split("/")[:2]
            filename = f"{name}-{version}-py3-none-any.whl"
            return {"info": {"name": name, "version": version}, "urls": [{
                "filename": filename, "packagetype": "bdist_wheel",
                "url": f"https://files.pythonhosted.org/{filename}",
                "digests": {"sha256": _sha(wheels[filename])}, "upload_time_iso_8601": OLD,
                "yanked": yanked["value"] and name == "server"}]}

        self.entry = {"command": str(executable), "args": [], "stage1": {
            "provider": "pypi", "registry_name": "io.github.owner/server", "registry_version": "1.2.3",
            "package_identifier": "server", "package_version": "1.2.3",
            "artifact_path": str(self.archive), "artifact_sha256": _sha(self.archive.read_bytes()),
            "executable_sha256": _sha(executable.read_bytes()),
            "install_root": str(self.root / "venv"),
            "install_tree_sha256": tree_digest(self.root / "venv")}}
        fetch_bytes = lambda url: wheels[url.rsplit("/", 1)[1]]
        # The PyPI name list is downloaded per installation (D6-31); use a fixed one.
        self.enterContext(mock.patch("mcp_guard.dependencies._popular", lambda provider: ("requests",)))
        lock = build_dependency_lock(self.entry, fetch=fetch, fetch_bytes=fetch_bytes,
                                     osv=self.npm.osv, now=NOW)
        path = self.root / "pypi-lock.json"
        path.write_text(json.dumps(lock), encoding="utf-8")
        self.entry["stage1"].update(dependency_lock=str(path),
                                    dependency_lock_sha256=_sha(path.read_bytes()))

        self.assertEqual(lock["findings"], [])
        self.assertEqual(verify_stage1(self.entry, fetch=fetch, osv=self.npm.osv)["provider"], "pypi")
        yanked["value"] = True
        with self.assertRaises(Stage1Error) as error:
            verify_stage1(self.entry, fetch=fetch, osv=self.npm.osv)
        self.assertEqual(error.exception.code, "S1_PACKAGE_INTEGRITY_MISSING")

        (site / "idna" / "evil.pth").write_bytes(b"import os")  # unclaimed startup hook
        (site / "idna" / "core.py").write_bytes(b"changed")
        self.entry["stage1"]["install_tree_sha256"] = tree_digest(self.root / "venv")
        yanked["value"] = False
        codes = {f["code"] for f in build_dependency_lock(
            self.entry, fetch=fetch, fetch_bytes=fetch_bytes, osv=self.npm.osv, now=NOW)["findings"]}
        self.assertEqual(codes, {"2-A5_DEPENDENCY_TAMPERED", "S1_DEPENDENCY_EXTRA_FILE"})

        # A build no published wheel matches was built from source: setup.py ran (D6-37).
        (site / "idna-3.7.dist-info" / "WHEEL").write_text("Wheel-Version: 1.0\nTag: cp27-none-any\n",
                                                           encoding="utf-8")
        lock = build_dependency_lock(self.entry, fetch=fetch, fetch_bytes=fetch_bytes, osv=self.npm.osv, now=NOW)
        built = [f for f in lock["findings"] if f["code"] == "S1_DEPENDENCY_SOURCE_BUILD"]
        self.assertEqual([f["verdict"] for f in built], ["block"])
        self.entry["stage1"]["allow_source_builds"] = True
        lock = build_dependency_lock(self.entry, fetch=fetch, fetch_bytes=fetch_bytes, osv=self.npm.osv, now=NOW)
        self.assertEqual([f["verdict"] for f in lock["findings"] if f["code"] == "S1_DEPENDENCY_SOURCE_BUILD"],
                         ["review"])

    def test_docker_requires_pinned_catalog_and_signature_option(self) -> None:
        docker = self.root / "docker.exe"
        docker.write_bytes(b"docker cli")
        catalog = self.root / "catalog.yaml"
        catalog.write_bytes(b"approved catalog")
        self.entry = {"command": str(docker), "args": [
            "mcp", "gateway", "run", "--catalog", str(catalog), "--servers", "files",
            "--verify-signatures", "--watch=false"], "stage1": {
                "provider": "docker", "catalog_path": str(catalog),
                "catalog_sha256": _sha(catalog.read_bytes()),
                "server_id": "files", "executable_sha256": _sha(docker.read_bytes())}}
        self.assertEqual(verify_stage1(self.entry)["provider"], "docker")
        self.entry["args"].remove("--verify-signatures")
        self.assertEqual(self._error().code, "S1_DOCKER_CONFIG_INVALID")


class LookalikeTests(unittest.TestCase):
    POPULAR = ("react", "preact", "cross-env", "lodash", "requests", "ms", "express")

    def test_one_edit_or_separator_lookalikes(self) -> None:
        for name, target in (("crossenv", "cross-env"), ("lodahs", "lodash"), ("expres", "express"),
                             ("expresss", "express"), ("cross-enw", "cross-env")):
            with self.subTest(name=name):
                self.assertEqual(lookalike(name, self.POPULAR, "npm"), target)

    def test_popular_names_short_names_and_unrelated_names_pass(self) -> None:
        for name in ("preact", "react", "mz", "zod", "my-own-tool", "lodasb"):
            with self.subTest(name=name):
                self.assertIsNone(lookalike(name, self.POPULAR, "npm"))

    def test_pypi_names_are_normalized(self) -> None:
        self.assertIsNone(lookalike("Requests", self.POPULAR, "pypi"))
        self.assertEqual(lookalike("reqeusts", self.POPULAR, "pypi"), "requests")

    def test_reordered_parts_and_homographs(self) -> None:
        self.assertEqual(lookalike("env-cross", self.POPULAR, "npm"), "cross-env")
        self.assertEqual(lookalike("l0dash", self.POPULAR, "npm"), "lodash")
        self.assertEqual(lookalike("expre55", self.POPULAR, "npm"), None)  # two edits, no rule
        self.assertEqual(lookalike("reqiuests", self.POPULAR, "pypi"), "requests")

    def test_bundled_npm_list_loads(self) -> None:
        from mcp_guard.dependencies import _popular

        self.assertIn("react", _popular("npm"))
        self.assertEqual(lookalike("crossenv", _popular("npm"), "npm"), "cross-env")

    def test_missing_list_holds_for_review(self) -> None:
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch("mcp_guard.dependencies._popular", lambda provider: ()):
            root = Path(folder)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "x.js").write_bytes(b"x")
            lock = build_dependency_lock({"stage1": {"provider": "npm", "install_root": folder}},
                                         osv=lambda packages: [])
        self.assertIn("B_DEPENDENCY_LOOKALIKE_UNCHECKED", {f["code"] for f in lock["findings"]})


if __name__ == "__main__":
    unittest.main()
