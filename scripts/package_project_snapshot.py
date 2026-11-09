"""Package the current distributable source and documentation into one ZIP."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "mcp-guard_전체작업_2026-11-04.zip"


def file_list() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return sorted(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)


def main() -> None:
    paths = file_list()
    records = []
    for rel in paths:
        path = ROOT / rel
        if path == OUTPUT or not path.is_file():
            continue
        data = path.read_bytes()
        records.append(
            {
                "path": rel.replace("\\", "/"),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    counts = Counter(record["path"].split("/")[0] for record in records)
    readme = """mcp-guard 전체 작업물 묶음 (2026-11-04)

저장소의 코드, 테스트, 설정 예시, Markdown/HWPX 문서, 원본 설계도와 Progress map 이미지를 하나의 ZIP으로 묶었습니다.
파일별 크기와 SHA-256은 파일목록.tsv 및 manifest.json에서 확인할 수 있습니다.

주요 위치
- src/mcp_guard: 공통 검사 엔진
- mvp/01~11: MVP별 구현, 평가 자료 및 배포 예시
- tests: 테스트 코드
- Docs/Core_mds: 설계 문서와 서비스 설명서
- Docs/Core_images: 원본 도면 및 Progress map v1~v14
- scripts: Progress map과 HWPX 생성 스크립트
- configs, .github, .vscode 및 루트 파일: 설정 예시와 프로젝트 안내

제외
- .git 이력, .venv 가상환경, .hf-cache 내려받은 모델, 이전 재정리 백업
- __pycache__ 등 실행 중 생성된 파일, .env 및 실제 자격 증명/상태 파일
- .gitignore에서 배포 대상이 아니라고 지정한 다운로드 데이터와 비공개 설정
이 ZIP은 소스/문서 스냅샷입니다. 실행 환경이나 대용량 모델 가중치는 포함하지 않습니다.
"""
    manifest = {
        "snapshot_date": "2026-11-04",
        "scope": "git tracked + unignored untracked files in project",
        "file_count": len(records),
        "total_source_bytes": sum(record["bytes"] for record in records),
        "top_level_counts": dict(sorted(counts.items())),
        "files": records,
    }
    index = "path\tbytes\tsha256\n" + "".join(
        f"{record['path']}\t{record['bytes']}\t{record['sha256']}\n"
        for record in records
    )

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("00_읽어주세요.txt", readme)
        archive.writestr("파일목록.tsv", index)
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        for record in records:
            archive.write(ROOT / record["path"], record["path"])

    with zipfile.ZipFile(OUTPUT) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(records) + 3
        for record in records:
            assert hashlib.sha256(archive.read(record["path"])).hexdigest() == record["sha256"]

    print(json.dumps({"archive": str(OUTPUT), "files": len(records), "bytes": OUTPUT.stat().st_size}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"snapshot packaging failed: {exc}", file=sys.stderr)
        raise
