"""Regenerate the popular package name lists used by the lookalike check.

Sources (fetched at generation time; each list records its source and date):
- npm: the ``npm-high-impact`` package by Titus Wormer (MIT), ``lib/top.js``,
  downloaded from the npm registry and checked against its SHA-512 integrity.
- PyPI: Hugo van Kemenade's top-pypi-packages (30-day downloads, from the
  PyPI BigQuery dataset). The project declares no license, so the list is
  not shipped: each installation downloads it (D6-31). It is gitignored.

Run: python mvp/10-local-entry/update_popular_packages.py --ecosystem pypi [--count 5000]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import tarfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

DATA = Path(__file__).resolve().parents[2] / "src" / "mcp_guard" / "data"
NPM_PACKAGE = "npm-high-impact"
PYPI_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "mcp-guard-data/0.1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def npm_names(count: int) -> tuple[list[str], str]:
    release = json.loads(_get(f"https://registry.npmjs.org/{NPM_PACKAGE}/latest"))
    tarball = _get(release["dist"]["tarball"])
    expected = base64.b64decode(release["dist"]["integrity"].removeprefix("sha512-"))
    if hashlib.sha512(tarball).digest() != expected:
        raise SystemExit("npm-high-impact tarball does not match its registry integrity")
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        source = archive.extractfile("package/lib/top.js").read().decode("utf-8")
    names = re.findall(r"^\s*'([^']+)',?$", source, re.MULTILINE)
    return names[:count], f"{NPM_PACKAGE}@{release['version']} lib/top.js (MIT)"


def pypi_names(count: int) -> tuple[list[str], str]:
    payload = json.loads(_get(PYPI_URL))
    names = [row["project"] for row in payload["rows"]]
    return names[:count], f"{PYPI_URL} (last_update {payload['last_update']}; no declared license)"


def write(path: Path, names: list[str], source: str) -> None:
    header = [f"# {len(names)} popular package names, most popular first.",
              f"# Source: {source}",
              f"# Generated: {datetime.now(UTC).date().isoformat()} by mvp/10-local-entry/update_popular_packages.py"]
    path.write_text("\n".join(header + names) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(names)} names)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--ecosystem", choices=("npm", "pypi"), action="append",
                        help="list to regenerate (repeatable; default both)")
    args = parser.parse_args()
    for ecosystem in args.ecosystem or ("npm", "pypi"):
        source = npm_names if ecosystem == "npm" else pypi_names
        write(DATA / f"popular_{ecosystem}.txt", *source(args.count))


if __name__ == "__main__":
    main()
