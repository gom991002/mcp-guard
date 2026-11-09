"""Build the labelled stage 1 dataset for the B score (D6-35).

Malicious packages: Datadog's malicious-software-packages-dataset (Apache-2.0,
human-triaged npm and PyPI malware, both "malicious intent" packages and
compromised versions of real libraries). Benign packages: established npm and
PyPI packages (npm-high-impact and top-pypi-packages ranks), minus anything in
the Datadog manifests or with an OSV MAL- record.

Safety: samples are only read and written as files for static analysis; nothing
is installed, imported, or run. Each batch folder is deleted after Semgrep has
read it, and only the derived features are kept (no malware is stored).

Features come from the same functions the stage 1 scan uses
(local_entry.code_scan.run_semgrep and package_features).

PyPI malware is published as source distributions. setup.py runs only when a
source distribution is built, which stage 1 already holds for review
(S1_DEPENDENCY_UNVERIFIED), and it is absent from an installed wheel. So
setup.py and build metadata are excluded from the features, and their Semgrep
hits are kept in a separate column for the report.

Run: python mvp/10-local-entry/b_score/build_dataset.py --out mvp/10-local-entry/b_score/data/features.csv
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[3]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from local_entry import code_scan  # noqa: E402
from mcp_guard import similarity  # noqa: E402

DATASET = "DataDog/malicious-software-packages-dataset"
RAW = f"https://raw.githubusercontent.com/{DATASET}/main/"
PYPI_TOP = "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"
BUILD_ONLY = re.compile(r"(^|/)(setup\.py|setup\.cfg|pyproject\.toml|PKG-INFO|MANIFEST\.in)$|"
                        r"\.egg-info/")
SAMPLE_CAPS = {  # (count, max zip bytes)
    ("npm", "malicious_intent"): (400, 2_000_000),
    ("npm", "compromised_lib"): (100, 3_000_000),
    ("pypi", "malicious_intent"): (400, 2_000_000),
    ("pypi", "compromised_lib"): (29, 20_000_000),
}
BENIGN = {"npm": (450, 150), "pypi": (400, 150)}  # (ranks 5001+, top 5000)
# D6-37: benign packages sampled without regard to popularity, published at
# least a year (npm) or two years (PyPI) ago so undiscovered malware is unlikely.
RANDOM = {"npm": 250, "pypi": 250}
PYPI_INDEX = "https://pypi.org/simple/"
MAX_BENIGN_BYTES = 8_000_000


def get(url: str, data: bytes | None = None, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, data=data, headers={
        "User-Agent": "mcp-guard-b-score/0.1", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def get_json(url: str) -> object:
    return json.loads(get(url))


# sampling --------------------------------------------------------------------


def dataset_listing(clone: Path) -> list[str]:
    """Path of every sample, from a blob-less clone (trees only, no malware).

    The GitHub API truncates a tree this large, which would bias the sample
    towards names early in the alphabet. Sizes are not asked for: git would
    download every blob to report them. The size cap applies at download.
    """
    if not (clone / ".git").is_dir():
        subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
                        "--depth", "1", f"https://github.com/{DATASET}.git", str(clone)], check=True)
    listing = subprocess.run(["git", "-C", str(clone), "ls-tree", "-r", "--name-only", "HEAD", "--",
                              "samples/npm", "samples/pypi"], check=True, capture_output=True,
                             text=True, encoding="utf-8").stdout
    return [path for path in listing.splitlines() if path.endswith(".zip")]


def _npm_name(directory: str) -> str:
    # the dataset writes "@scope/name" as "@scope@name"
    return "@" + directory[1:].replace("@", "/", 1) if directory.startswith("@") else directory


def malicious_samples(rng: random.Random, clone: Path) -> list[dict]:
    entries = dataset_listing(clone)
    picks = []
    for (ecosystem, category), (count, cap) in SAMPLE_CAPS.items():
        prefix = f"samples/{ecosystem}/{category}/"
        by_name: dict[str, str] = {}
        for path in sorted(entries):
            if path.startswith(prefix):
                # one version per package, so near-duplicates do not dominate
                by_name.setdefault(path[len(prefix):].split("/")[0], path)
        # oversample: samples over the size cap are skipped at download
        chosen = rng.sample(sorted(by_name.values()), min(count * 2, len(by_name)))
        for path in chosen:
            parts = path[len(prefix):].split("/")
            discovered = re.match(r"(\d{4}-\d{2}-\d{2})-", PurePosixPath(path).name)
            picks.append({"ecosystem": ecosystem, "label": 1, "category": category, "cap": cap,
                          "discovered": discovered.group(1) if discovered else "",
                          "name": _npm_name(parts[0]) if ecosystem == "npm" else parts[0],
                          "version": parts[1] if len(parts) > 2 else "", "source": path})
    return picks


def benign_names(rng: random.Random, manifests: dict[str, set[str]]) -> list[dict]:
    release = get_json("https://registry.npmjs.org/npm-high-impact/latest")
    tarball = get(release["dist"]["tarball"])
    if hashlib.sha512(tarball).digest() != base64.b64decode(release["dist"]["integrity"][7:]):
        raise SystemExit("npm-high-impact integrity mismatch")
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        top = archive.extractfile("package/lib/top.js").read().decode("utf-8")
    npm = re.findall(r"^\s*'([^']+)',?$", top, re.MULTILINE)
    pypi = [row["project"] for row in get_json(PYPI_TOP)["rows"]]
    picks = []
    for ecosystem, names in (("npm", npm), ("pypi", pypi)):
        names = [n for n in names if n.lower() not in manifests[ecosystem]]
        tail, head = BENIGN[ecosystem]
        # oversample: some downloads are skipped (too large, no wheel, MAL record)
        chosen = rng.sample(names[5000:], min(len(names) - 5000, tail * 2)) + \
            rng.sample(names[:5000], head * 2)
        picks += [{"ecosystem": ecosystem, "label": 0,
                   "category": "rank_5001_plus" if i < min(len(names) - 5000, tail * 2) else "top_5000",
                   "name": n, "version": "", "source": ""} for i, n in enumerate(chosen)]
    return picks


def random_benign(rng: random.Random, manifests: dict[str, set[str]], popular: set[str]) -> list[dict]:
    """Benign candidates not chosen by popularity (D6-37)."""
    picks = []
    # PyPI: the full project index
    request = urllib.request.Request(PYPI_INDEX, headers={
        "Accept": "application/vnd.pypi.simple.v1+json", "User-Agent": "mcp-guard-b-score/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        projects = [p["name"] for p in json.loads(response.read())["projects"]]
    projects = [n for n in projects if n.lower() not in manifests["pypi"] and n.lower() not in popular]
    picks += [{"ecosystem": "pypi", "label": 0, "category": "random", "name": n, "version": "",
               "source": ""} for n in rng.sample(projects, RANDOM["pypi"] * 6)]
    # npm has no full index: search with random three-letter words
    cutoff = datetime.now(UTC).replace(year=datetime.now(UTC).year - 1).isoformat()
    seen: dict[str, None] = {}
    letters = "abcdefghijklmnopqrstuvwxyz"
    for _ in range(60):
        word = "".join(rng.choice(letters) for _ in range(3))
        try:
            found = get_json(f"https://registry.npmjs.org/-/v1/search?text={word}&size=100")
        except (OSError, ValueError, urllib.error.URLError):
            continue
        for entry in found.get("objects", []):
            package = entry.get("package", {})
            name = package.get("name", "")
            if (name and name.lower() not in manifests["npm"] and name.lower() not in popular
                    and str(package.get("date", "9999")) < cutoff):
                seen.setdefault(name)
    names = sorted(seen)
    picks += [{"ecosystem": "npm", "label": 0, "category": "random", "name": n, "version": "",
               "source": ""} for n in rng.sample(names, min(len(names), RANDOM["npm"] * 3))]
    return picks


def manifests() -> dict[str, set[str]]:
    result = {}
    for ecosystem in ("npm", "pypi"):
        data = get_json(RAW + f"samples/{ecosystem}/manifest.json")
        result[ecosystem] = {name.lower() for name in data}
    return result


# writing package files ---------------------------------------------------------


def get_capped(url: str, cap: int, timeout: int = 120) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "mcp-guard-b-score/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(cap + 1)
    if len(data) > cap:
        raise ValueError("over the size cap")
    return data


def write_malicious(item: dict, folder: Path, setup_folder: Path) -> int:
    data = get_capped(RAW + item["source"], item["cap"])
    written = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.setpassword(b"infected")
        for info in archive.infolist():
            parts = PurePosixPath(info.filename).parts
            if info.is_dir() or ".." in parts:
                continue
            if item["ecosystem"] == "npm":
                if "package" not in parts:
                    continue
                relative = "/".join(parts[parts.index("package") + 1:])
            else:
                if len(parts) < 3:
                    continue
                relative = "/".join(parts[2:])
            if not relative:
                continue
            target_root = folder
            if item["ecosystem"] == "pypi" and relative == "PKG-INFO":
                item["metadata_text"] = archive.read(info).decode("utf-8", "replace")
            if item["ecosystem"] == "pypi" and BUILD_ONLY.search(relative):
                if not relative.endswith("setup.py"):
                    continue
                target_root = setup_folder
            target = target_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
            written += target_root is folder  # setup.py goes elsewhere, not counted
    return written


def write_benign(item: dict, folder: Path) -> int:
    if item["ecosystem"] == "npm":
        # the recorded version when re-fetching a dataset row, else the latest
        meta = get_json(f"https://registry.npmjs.org/{item['name'].replace('/', '%2F')}/"
                        f"{item.get('version') or 'latest'}")
        dist = meta["dist"]
        data = get(dist["tarball"], timeout=120)
        if len(data) > MAX_BENIGN_BYTES:
            raise ValueError("too large")
        if hashlib.sha512(data).digest() != base64.b64decode(dist["integrity"][7:]):
            raise ValueError("integrity mismatch")
        item["version"] = meta["version"]
        written = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                parts = PurePosixPath(member.name.removeprefix("./")).parts
                if not member.isfile() or len(parts) < 2 or ".." in parts:
                    continue
                target = folder / "/".join(parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                target.write_bytes(stream.read() if stream else b"")
                written += 1
        return written
    meta = get_json(f"https://pypi.org/pypi/{item['name']}/" +
                    (f"{item['version']}/json" if item.get("version") else "json"))
    if item.get("category") == "random" and not item.get("version"):
        uploads = sorted(f["upload_time_iso_8601"] for files in meta.get("releases", {}).values()
                         for f in files if f.get("upload_time_iso_8601"))
        two_years = datetime.now(UTC).replace(year=datetime.now(UTC).year - 2).isoformat()
        if not uploads or uploads[0] > two_years:
            raise ValueError("first release less than two years old")
    wheels = [u for u in meta["urls"] if u["packagetype"] == "bdist_wheel" and not u.get("yanked")]
    wheels.sort(key=lambda u: (not u["filename"].endswith("-none-any.whl"), u["size"]))
    if not wheels or wheels[0]["size"] > MAX_BENIGN_BYTES:
        raise ValueError("no usable wheel")
    data = get(wheels[0]["url"], timeout=120)
    if hashlib.sha256(data).hexdigest() != wheels[0]["digests"]["sha256"]:
        raise ValueError("digest mismatch")
    item["version"] = meta["info"]["version"]
    written = 0
    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
        for info in wheel.infolist():
            parts = PurePosixPath(info.filename).parts
            if info.is_dir() or ".." in parts:
                continue
            target = folder / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(wheel.read(info))
            written += 1
    return written


def osv_malicious(items: list[dict]) -> set[int]:
    queries = [{"package": {"ecosystem": "npm" if i["ecosystem"] == "npm" else "PyPI",
                            "name": i["name"]}, "version": i["version"]} for i in items]
    flagged = set()
    for start in range(0, len(queries), 500):
        result = json.loads(get("https://api.osv.dev/v1/querybatch",
                                json.dumps({"queries": queries[start:start + 500]}).encode()))
        for offset, entry in enumerate(result["results"]):
            if any(v.get("id", "").startswith("MAL-") for v in entry.get("vulns", [])):
                flagged.add(start + offset)
    return flagged


# features ----------------------------------------------------------------------


def features_for_batch(batch: list[dict], work: Path, semgrep: str,
                       fingerprints: list[dict] | None = None, keep: Path | None = None) -> list[dict]:
    body = code_scan.run_semgrep([work / "pkg"], semgrep, timeout=7200)
    setup_body = (code_scan.run_semgrep([work / "setup"], semgrep, timeout=3600)
                  if any((work / "setup").rglob("setup.py")) else {"findings": []})
    hits: dict[str, set[str]] = {}
    hit_files: set[Path] = set()
    incomplete: dict[str, int] = {}
    setup_hits: dict[str, set[str]] = {}
    for source, target in ((body, hits), (setup_body, setup_hits)):
        base = work / ("pkg" if source is body else "setup")
        for finding in source["findings"]:
            try:
                key = Path(finding["path"]).resolve().relative_to(base.resolve()).parts[0]
            except (ValueError, IndexError):
                continue
            if finding["code"] in code_scan.SCORED_RULE_CODES:
                target.setdefault(key, set()).add(finding["code"])
                if source is body:
                    hit_files.add(Path(finding["path"]).resolve())
            elif source is body and finding["code"] in code_scan.GAP_CODES:
                incomplete[key] = incomplete.get(key, 0) + 1
    rows = []
    for item in batch:
        folder = work / "pkg" / item["key"]
        files = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()) \
            if folder.is_dir() else []
        blocked = 0
        for path in folder.rglob("*") if folder.is_dir() else []:
            if path.is_file():
                try:
                    with path.open("rb") as stream:
                        stream.read(1)
                except OSError:  # an antivirus refusing to open a detected file
                    blocked += 1
        package_json = None
        if item["ecosystem"] == "npm" and (folder / "package.json").is_file():
            try:
                package_json = json.loads((folder / "package.json").read_text("utf-8", "replace"))
            except (OSError, ValueError):
                package_json = None
        if fingerprints is not None:  # D6-36: signatures only, never code
            prints = []
            for name in files:
                path = folder / name
                if path.suffix.lower() not in code_scan.CODE_SUFFIXES:
                    continue
                sig = similarity.file_signature(path)
                if sig is not None:
                    prints.append([name, similarity.encode(sig), path.resolve() in hit_files])
            fingerprints.append({k: item[k] for k in ("ecosystem", "label", "category", "name", "version")}
                                | {"files": prints})
        metadata_text = item.get("metadata_text")
        if item["ecosystem"] == "pypi" and metadata_text is None:
            for path in folder.glob("*.dist-info/METADATA"):
                if path.is_file():  # samples may be crafted: METADATA can be a folder
                    try:
                        metadata_text = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        metadata_text = None
        features = code_scan.package_features(item["name"], item["ecosystem"], files,
                                              hits.get(item["key"], set()),
                                              package_json if isinstance(package_json, dict) else None,
                                              metadata_text=metadata_text)
        uid = f"{item['ecosystem']}-{item['label']}-" + re.sub(r"[^A-Za-z0-9._-]", "_", item["name"])
        if keep is not None and folder.is_dir():  # D6-37: GuardDog scans these in a second pass
            shutil.copytree(folder, keep / uid, dirs_exist_ok=True)
        rows.append({**{k: item[k] for k in ("ecosystem", "label", "category", "name", "version",
                                              "source")}, "uid": uid, "discovered": item.get("discovered", ""),
                     "files": len(files), "missing_files": item["written"] - len(files),
                     "av_blocked": blocked,
                     "incomplete": incomplete.get(item["key"], 0),
                     "setup_py_hits": ";".join(sorted(setup_hits.get(item["key"], set()))),
                     **features})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261102)
    parser.add_argument("--batch", type=int, default=150)
    parser.add_argument("--scale", type=float, default=1.0, help="shrink sample counts for a trial run")
    parser.add_argument("--fingerprints", type=Path, help="also write code file signatures (JSON Lines)")
    parser.add_argument("--keep", type=Path, help="copy each package folder here for the GuardDog pass")
    parser.add_argument("--semgrep", default=str(ROOT / ".venv" / "Scripts" / "semgrep.exe"))
    parser.add_argument("--work", type=Path, default=Path(tempfile.gettempdir()) / "mcp-guard-b-score",
                        help="scratch folder outside the repository for samples and the listing")
    args = parser.parse_args()
    semgrep = code_scan.find_semgrep(args.semgrep)
    rng = random.Random(args.seed)
    for key, (count, cap) in list(SAMPLE_CAPS.items()):
        SAMPLE_CAPS[key] = (max(1, round(count * args.scale)), cap)
    for key, (tail, head) in list(BENIGN.items()):
        BENIGN[key] = (max(1, round(tail * args.scale)), max(1, round(head * args.scale)))
    for key in list(RANDOM):
        RANDOM[key] = max(1, round(RANDOM[key] * args.scale))
    known = manifests()
    if args.work.resolve().is_relative_to(ROOT):
        raise SystemExit("--work must be outside the repository: it holds malware samples")
    args.work.mkdir(parents=True, exist_ok=True)
    items = malicious_samples(rng, args.work / "datadog-listing") + benign_names(rng, known)
    popular = {i["name"].lower() for i in items if i["label"] == 0}
    from mcp_guard.dependencies import _popular

    popular |= {n.lower() for eco in ("npm", "pypi") for n in _popular(eco)}
    items += random_benign(rng, known, popular)  # after the others: their picks stay the same
    if args.keep:
        args.keep.mkdir(parents=True, exist_ok=True)
    print(f"{sum(i['label'] for i in items)} malicious, {sum(1 - i['label'] for i in items)} "
          "benign candidates", flush=True)
    done = set()
    if args.out.exists():
        with args.out.open(encoding="utf-8") as stream:
            done = {(r["ecosystem"], r["name"], r["label"]) for r in csv.DictReader(stream)}
    kept: dict[tuple[str, str], int] = {}
    quotas = {**{key: count for key, (count, _) in SAMPLE_CAPS.items()},
              **{(e, "rank_5001_plus"): t for e, (t, _) in BENIGN.items()},
              **{(e, "top_5000"): h for e, (_, h) in BENIGN.items()},
              **{(e, "random"): n for e, n in RANDOM.items()}}
    if args.out.exists():
        with args.out.open(encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                kept[(row["ecosystem"], row["category"])] = kept.get((row["ecosystem"], row["category"]), 0) + 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    new_file = not args.out.exists()
    with args.out.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=[
            "ecosystem", "label", "category", "name", "version", "source", "uid", "discovered", "files",
            "missing_files", "av_blocked", "incomplete", "setup_py_hits", *code_scan.FEATURES])
        if new_file:
            writer.writeheader()
        pending = [i for i in items if (i["ecosystem"], i["name"], str(i["label"])) not in done]
        for start in range(0, len(pending), args.batch):
            batch, ready = pending[start:start + args.batch], []
            with tempfile.TemporaryDirectory(prefix="batch-", dir=args.work) as temp:
                work = Path(temp)
                for n, item in enumerate(batch):
                    group = (item["ecosystem"], item["category"])
                    if kept.get(group, 0) >= quotas[group]:
                        continue
                    item["key"] = f"p{n:04d}"
                    try:
                        writer_fn = write_malicious if item["label"] else write_benign
                        args_fn = (item, work / "pkg" / item["key"], work / "setup" / item["key"]) \
                            if item["label"] else (item, work / "pkg" / item["key"])
                        item["written"] = writer_fn(*args_fn)
                    except (OSError, ValueError, KeyError, urllib.error.URLError, zipfile.BadZipFile,
                            tarfile.TarError) as error:
                        print(f"  skip {item['ecosystem']} {item['name']}: {error}", flush=True)
                        shutil.rmtree(work / "pkg" / item["key"], ignore_errors=True)
                        continue
                    if item["written"] == 0:
                        continue
                    ready.append(item)
                    kept[group] = kept.get(group, 0) + 1
                flagged = osv_malicious([i for i in ready if i["label"] == 0])
                benign = [i for i in ready if i["label"] == 0]
                drop = {id(benign[k]) for k in flagged}
                ready = [i for i in ready if id(i) not in drop]
                if not ready:
                    continue
                prints: list[dict] | None = [] if args.fingerprints else None
                rows = features_for_batch(ready, work, semgrep, prints, args.keep)
                writer.writerows(rows)
                stream.flush()
                if prints is not None:
                    with args.fingerprints.open("a", encoding="utf-8") as out:
                        for record in prints:
                            out.write(json.dumps(record) + "\n")
            print(f"batch {start // args.batch + 1}: {len(rows)} rows "
                  f"({sum(r['label'] for r in rows)} malicious)", flush=True)


if __name__ == "__main__":
    main()
