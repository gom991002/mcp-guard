"""Render Progress_map_v14: implementation and how the parts work together (2026-11-04).

On top of v13:
- state storage: server trust tiers (D6-54), session taint and new-session counters
  can be shared in DynamoDB (D6-55); the gateway runs as one instance (D6-58), so
  per-instance login and approval state completes that item;
- B classifier measured in Docker and on by default in deployment (D6-53);
- separate track at portfolio scale: Docker sandbox for local servers and
  known-vulnerability holds (D6-56);
- deployment: compose fixed for the private state folder, local Docker demo with an
  end-to-end smoke test (D6-57);
- a band of the integrations actually exercised, apart from unit tests.
Usage: python scripts/render_progress_map_v14.py [--html out.html]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import tempfile
from pathlib import Path

import render_progress_map_v13 as v13

v12, base = v13.v12, v13.base
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Docs" / "Core_images" / "Progress_map_v14.png"
D, P, T = base.D, base.P, base.T
item, box, replace_box = base.item, base.box, v12._replace_box

base.GROUPS["상태 저장"] = [D, D, D, D]
core = base.COL_CORE
core = core.replace("공식 Registry 서버·버전 대조", "공식 Registry 서버·버전·발행자 대조")  # D6-05
core = core.replace("OSV 악성 기록 · 새 릴리스·비슷한 이름 검사", "OSV 악성·취약 기록 · 새 릴리스·비슷한 이름 검사")  # D6-56
core = replace_box(core, "box-3", box("box-3", "3단계 · 응답 처리", [
    item(D, "M4 원격: 원 서버 결과마다 오염 표시·파일/DynamoDB"),
    item(D, "M4 로컬: Claude Code 훅 오염 표시 · 신뢰 등급 반영"),
    item(D, "B 응답 문구 규칙·분류기: 감사 기록 · 오염 불변"),
], extra="two", notes=("Claude는 새 세션 시작 버튼 · Desktop 오염 표시는 범위 밖 (D6-52)",)))
core = replace_box(core, "box-2", box("box-2", "2단계 · 등록 검사", [
    item(D, "M2 보호 이름·유사 도구 이름 검사"),
    item(D, "M2 혼동 문자·형식 검사"),
    item(D, "M3 정의·설명문 변경 감지"),
    item(D, "M3 재승인: 관리자 기본 · 사용자 수락 선택"),
    item(D, "M5 민감 세션 설명문 대체"),
    item(D, "M5 서버 단위 격리·외부 전송 도구 판별"),
    item(D, "B 설명문: 문구·구조·분류기 · LLM은 남은 것만"),
    item(D, "목록 변경·재연결 시 재검사"),
], tag="원격·로컬", extra="two", notes=(
    "MCPTox 분리 시험: 문구+구조 82.1% → +분류기 95.7% 탐지 · 정상 1.18% 보류 (기준 2% 이하)",)))
core = replace_box(core, "box-state", box("box-state", "상태 저장", [
    item(D, "정책·승인·재승인 파일 · 서버 신뢰 등급"),
    item(D, "오염·새 세션 번호: 파일 · DynamoDB(선택)"),
    item(D, "감사 로그: 로컬·CloudWatch 경로"),
    item(D, "사용자별 원 서버 토큰 · 로그인·승인 기록"),
], extra="two", notes=("게이트웨이 1대 운영 (D6-58) · 여러 대 동시 운영은 범위 밖 · DynamoDB는 가짜 서버로만 시험",)))
core = replace_box(core, "box-out", box("box-out", "범위 밖 · 별도 트랙 (포트폴리오 범위)", status="done",
                                        counted=False, lines=(
    "OS 격리: 선택 Docker 샌드박스 (네트워크 없음·읽기 전용·권한 제거)",
    "패치 관리: 알려진 취약 버전은 업데이트·수락 전까지 시작 보류"),
    notes=("포트폴리오 범위(D6-56) 완료 · VM 격리·남의 서버 코드 수정·원격 서버 내부는 범위 밖",)))
base.COL_CORE = core

base.COL_ENTRY = replace_box(base.COL_ENTRY, "deploy", box(
    "deploy", "배포 구성", status="done", counted=False,
    lines=("Docker · Caddy · AWS 구성 · 로컬 Docker 데모 통과",),
    notes=("포트폴리오 범위 완료 · AWS 실배포는 미검증",)))

base.COL_ENTRY = (base.COL_ENTRY
                  .replace("과다 요청 지연·반복 시 429", "과다 요청 지연·반복 시 429 · 공유 대역은 로그인 요청만 예외")
                  .replace("콘텐츠 악성 판정에는 사용하지 않음", "ChatGPT 공개 대역 매일 반영 · 콘텐츠 판정에는 안 씀"))
base.COL_EXT = base.COL_EXT.replace("오염 표시는 Claude Code 훅 기준 · Desktop 없음",
                                    "오염 표시는 Claude Code 훅 기준 · Desktop은 범위 밖")

base.ATTACKS = [
    (n, name, D, "선택 Docker 샌드박스 · 취약 버전 보류", "포트폴리오 범위 · VM 격리·원격 서버 내부는 범위 밖")
    if name == "서버 내부 동작" else (n, name, state, description, note)
    for n, name, state, description, note in base.ATTACKS
]
_MVP = {
    # Checks run in the MVP 2 core; MVP 4/7 keep only the upstream HTTP clients (2026-11-04 cleanup).
    "MVP 4 ": ("MVP 4 · tools/list", "원 서버 목록 조회·검토 CLI", D),
    "MVP 7 ": ("MVP 7 · tools/call", "원 서버 호출 클라이언트", D),
    "MVP 6 ": ("MVP 6 · HTTP 게이트웨이", "원격 진입·승인 페이지·새 세션", D),
    "MVP 9 ": ("MVP 9 · 클라우드 진입", "C1–C3 · DynamoDB 공유 상태", D),
    "MVP 10 ": ("MVP 10 · 로컬 진입", "L1–L4 · 1단계 · 샌드박스", D),
    "MVP 11 ": ("MVP 11 · B 분류기", "배포 기본 켜짐 · 기준값 0.86", D),
}
base.MVPS = [next((v for k, v in _MVP.items() if m[0].startswith(k)), m) for m in base.MVPS]


def build_html() -> str:
    page = v13.build_html().replace("구현 현황 v13", "구현 현황 v14")
    page = page.replace("Progress_map_v13", "Progress_map_v14")
    page = re.sub(
        r'<section class="band"><h2>검증 범위 · 다음 작업</h2>.*?</ul></section>',
        '<section class="band"><h2>상호 연동 검증 · 다음 작업</h2><ul class="checks">'
        '<li><i class="sq done"></i><span>전체 테스트 510개 통과 · 2개 건너뜀</span></li>'
        '<li><i class="sq done"></i><span>Docker 데모 19단계: OAuth 로그인 → 게이트웨이 → 원 서버 → 오염·값 정책·승인 페이지</span></li>'
        '<li><i class="sq done"></i><span>L2 래퍼 ↔ Docker 샌드박스 안 서버 (실제 Docker)</span></li>'
        '<li><i class="sq done"></i><span>B 분류기 Docker 실측: 문장당 16ms · 메모리 약 530MB</span></li>'
        '<li><i class="sq partial"></i><span>DynamoDB 공유 상태: 가짜 DynamoDB로만 시험</span></li>'
        '<li><i class="sq todo"></i><span>실제 LLM 클라이언트·외부 MCP 서버·AWS 배포 미검증</span></li>'
        '<li class="left">다음: 실제 클라이언트 연동 → AWS 배포 → 대화창 승인 카드</li>'
        '</ul></section>', page, count=1, flags=re.S)
    return page


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", type=Path, help="also keep the generated HTML here")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-guard-v14-") as work:
        page = Path(work) / "progress_map_v14.html"
        page.write_text(build_html(), encoding="utf-8")
        if args.html:
            args.html.write_text(page.read_text(encoding="utf-8"), encoding="utf-8")
        profile = str(Path(work) / "profile")
        dom = base.run_edge([f"--window-size={base.WIDTH},1800", "--dump-dom", page.as_uri()], profile)
        height_match = re.search(r'data-height="(\d+)"', dom)
        issues_match = re.search(r'data-issues="([^"]*)"', dom)
        if not height_match or not issues_match:
            raise RuntimeError("Layout metadata was not returned by Edge")
        height = int(height_match.group(1))
        issues = json.loads(html.unescape(issues_match.group(1)))
        if issues:
            raise RuntimeError("Layout issues: " + "; ".join(issues))
        base.run_edge([f"--window-size={base.WIDTH},{height}", "--force-device-scale-factor=2",
                       f"--screenshot={args.output}", page.as_uri()], profile)
    print(f"wrote {args.output} ({base.WIDTH * 2}x{height * 2})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
