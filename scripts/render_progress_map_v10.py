"""Render Progress_map_v10 with the same grid and visual language as v9.

Only the content is condensed and brought up to the 2026-11-03 code snapshot.
Usage: python scripts/render_progress_map_v10.py [--html out.html]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import tempfile
from pathlib import Path

import render_progress_map_v9 as base


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Docs" / "Core_images" / "Progress_map_v10.png"
D, P, T = base.D, base.P, base.T
item, box = base.item, base.box


# Keep v9's 33-item accounting, with current stage 2 states.
base.GROUPS = {
    "0단계": [D] * 7,
    "M1": [D] * 3,
    "1단계": [D, D, D, D, P],
    "2단계": [D, D, D, T, D, D, P, D],
    "3단계": [T, P, P],
    "4단계": [P, P, T],
    "상태 저장": [P, P, D, P],
}


base.COL_ENTRY = "".join([
    box("box-L", "L · 로컬 진입 강제", [
        item(D, "L1 설정 생성 · guard 선택 항목만 변경"),
        item(D, "L2 stdio 래퍼 · 검사 실패 시 실행 차단"),
        item(D, "L3 설정 감시 · 재래핑"),
        item(D, "L4 Claude Code 훅 · 미승인 도구 제한"),
    ], tag="MVP 10", notes=("실제 Claude 클라이언트 연동 미검증",)),
    box("box-C", "C · 클라우드 진입 강제", [
        item(D, "C1 게이트웨이 URL 등록 경로"),
        item(D, "C2 OAuth · CIMD/DCR/PKCE"),
        item(D, "C3 서버·사용자별 토큰 분리"),
    ], tag="MVP 9", notes=("실제 상용 클라이언트·OAuth 공급자 미검증",)),
    box("branch", "guard 사용 분기", status="done", counted=False,
        lines=("사용 yes → 검사 경유 · no → 원 서버 직접 연결",)),
    box("box-S0", "코어 쪽 0단계", [
        item(D, "서버 허용 목록 · 최초 승인 기록"),
        item(D, "게이트웨이 입구 규칙 · HTTP 검사"),
    ], counted=False),
    box("box-ip", "IP 지연", status="aux", counted=False, tag="MVP 5",
        lines=("과다 요청 지연·반복 시 429",),
        notes=("콘텐츠 악성 판정에는 사용하지 않음",)),
    box("deploy", "배포 구성", status="partial", counted=False,
        lines=("Docker · Caddy · AWS 구성 파일",),
        notes=("실제 배포 미검증",)),
    box("direct", "직접 연결 선택 → 원 서버", status="none", counted=False,
        extra="ghost", lines=("0~4단계 검사 우회",)),
])


base.COL_CORE = "".join([
    box("box-M1", "M1 · 중계·감사 기록", [
        item(D, "ASGI/개발용 HTTP · stdio 중계"),
        item(D, "JSON 단일 응답 · 감사 이벤트 저장"),
        item(D, "판정 코드·B 점수·모델 버전 기록"),
    ], notes=("실제 클라이언트·AWS 검증은 배포 단계",)),
    box("box-1", "1단계 · 정상 연동", [
        item(D, "공식 Registry 서버·버전 대조"),
        item(D, "npm/PyPI 배포 파일·의존성 잠금 · Docker 서명 옵션"),
        item(D, "OSV 악성 기록 · 새 릴리스·비슷한 이름 검사"),
        item(D, "Semgrep + 메타데이터 B 점수 · GuardDog 선택 연동"),
        item(P, "악성 코드 유사도는 근거만 · LLM 검토는 판정 불변"),
    ], tag="로컬 패키지 경로", extra="two",
        notes=("원격 1단계 없음 · 실제 Registry/npm/PyPI/Docker 실연동 미검증",)),
    box("box-2", "2단계 · 등록 검사", [
        item(D, "M2 보호 이름·유사 도구 이름 검사"),
        item(D, "M2 혼동 문자·형식 검사"),
        item(D, "M3 정의·설명문 변경 감지"),
        item(T, "M3 재승인 화면·흐름"),
        item(D, "M5 민감 세션 설명문 대체"),
        item(D, "M5 서버 단위 격리·외부 전송 도구 표시"),
        item(P, "B 설명문 규칙·선택형 LLM · LLM 성능 미평가"),
        item(D, "목록 변경·재연결 시 재검사"),
    ], tag="원격·로컬", extra="two"),
    box("box-3", "3단계 · 응답 처리", [
        item(T, "M4 출처 태깅·게이트웨이 세션 오염"),
        item(P, "Claude Code 세션 오염 표시"),
        item(P, "B 응답 점수는 감사 기록만"),
    ], extra="two"),
    box("box-4", "4단계 · 봉쇄", [
        item(P, "Claude Code 오염 세션 Bash·WebFetch 제한"),
        item(P, "3-A4 Claude Code 승인 창"),
        item(T, "원격 MCP 외부 전송 차단·값 정책"),
    ], extra="two"),
    box("box-state", "상태 저장", [
        item(P, "정책·승인 파일 · 신뢰 등급 없음"),
        item(P, "오염 상태: Claude Code 세션만"),
        item(D, "감사 로그: 로컬·CloudWatch 경로"),
        item(P, "사용자별 토큰·클라이언트별 세션"),
    ], extra="two"),
    box("box-out", "범위 밖 · 별도 트랙", status="todo", counted=False,
        lines=("서버 내부 코드 패치 · OS 격리",)),
])


# Keep v9's external column IDs: its flow arrows and layout checker use them.
base.COL_EXT = "".join([
    '<div class="ext" id="ext-local"><h4>로컬 MCP 서버 프로세스</h4>'
    '<div>guard 래퍼 뒤에서 실행</div></div>',
    '<div class="ext" id="ext-registry"><h4>공식 MCP Registry</h4>'
    '<div>서버·버전 조회</div></div>',
    '<div class="ext" id="ext-npm"><h4>npm · PyPI · Docker · OSV</h4>'
    '<div>배포·서명·악성 기록 조회</div></div>',
    '<div class="ext" id="ext-remote"><h4>원격 MCP 서버</h4>'
    '<div id="remote-static">도구 목록·호출 중계</div>'
    '<div class="flow" id="remote-c3">사용자별 원 서버 토큰 분리</div>'
    '<div class="flow" id="remote-note">실제 외부 서버 미검증</div>'
    '<div class="flow ok" id="flow-2">등록: tools/list 실조회 경로</div>'
    '<div class="flow" id="flow-3">응답: B 점수 감사만</div>'
    '<div class="flow" id="flow-4">호출: 원격 봉쇄 미구현</div></div>',
    '<div class="ext danger" id="ext-content"><h4>외부 콘텐츠</h4>'
    '<div>메일 · 이슈 · 웹</div></div>',
    '<div class="ext danger" id="ext-attacker"><h4>공격자</h4>'
    '<div>글 · 서버 · 패키지</div></div>',
])


base.ATTACKS = [
    ("0", "우회", P, "L·C 진입 + 서버 허용 목록", "직접 연결 선택 시 검사 우회"),
    ("①", "신원 위장", P, "1단계 출처·패키지 + M2 이름 검사", "실제 공급 서비스 연동 미검증"),
    ("②", "정의 변조", P, "M3 변경 감지 · M5 설명문 대체", "M3 재승인 흐름 미구현"),
    ("③", "응답 오염", P, "Claude Code 세션 제한 일부", "게이트웨이 M4·원격 봉쇄 미구현"),
    ("범위 밖", "서버 내부 동작", T, "검사 코어 대상 아님", "패치·OS 격리 별도"),
]


base.MVPS = [
    ("MVP 1 · 정책 엔진", "규칙·판정", P),
    ("MVP 2 · 게이트웨이 코어", "M1 중계", D),
    ("MVP 3 · 서버 등록", "0단계 설정", D),
    ("MVP 4 · tools/list", "2단계 검사", D),
    ("MVP 5 · IP 지연", "보조 제어", "aux"),
    ("MVP 6 · HTTP 게이트웨이", "원격 진입", D),
    ("MVP 7 · tools/call", "호출 중계", D),
    ("MVP 8 · 결정 제어", "M5 결합 일부", P),
    ("MVP 9 · 클라우드 진입", "C1–C3", P),
    ("MVP 10 · 로컬 진입", "L1–L4", D),
    ("MVP 11 · B 분류기", "선택 기능", P),
]


# Preserve v9's grid and typography while preventing cards from collapsing.
base.CSS += """
#box-M1{min-height:150px}#box-1{min-height:180px}#box-2{min-height:180px}
#box-3{min-height:125px}#box-4{min-height:125px}#box-state{min-height:115px}
#box-out{min-height:70px}
"""


def build_html() -> str:
    page = base.build_html()
    page = page.replace("구현 현황 v9", "구현 현황 v10")
    page = page.replace("Progress_map_v9", "Progress_map_v10")
    page = page.replace("2026-11-02", "2026-11-03")
    page = page.replace(
        " — 제작된 것과 아직 구현하지 않은 것", " — 아키텍처별 핵심 구현 상태")
    page = re.sub(r'<div class="sub">.*?</div>',
                  '<div class="sub">A-01 · A-02의 경로 위에 현재 코드 상태를 표시 · 네모 1칸 = 설계 항목 1개</div>',
                  page, count=1)
    page = re.sub(
        r'<section class="band"><h2>테스트 · 검증 범위 · 남은 큰 작업</h2>.*?</ul></section>',
        '<section class="band"><h2>검증 범위 · 다음 작업</h2><ul class="checks">'
        '<li><i class="sq done"></i><span>전체 테스트 389개 실행 · 387개 통과 · 2개 건너뜀</span></li>'
        '<li><i class="sq todo"></i><span>실제 LLM 클라이언트·외부 MCP 서버·AWS 배포 미검증</span></li>'
        '<li class="left">다음: M3 재승인 → M4 출처 태깅·원격 봉쇄 → 실연동 검증</li>'
        '</ul></section>', page, count=1, flags=re.S)
    page = re.sub(
        r'<footer>.*?</footer>',
        '<footer>근거: src/mcp_guard · mvp/01–11 · tests · Docs/Core_mds/architecture.md · SECURITY.md. '
        '녹색은 코드·테스트 기준이며 외부 서비스 실연동 검증을 뜻하지 않음.</footer>',
        page, count=1, flags=re.S)
    return page


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", type=Path, help="also keep the generated HTML here")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-guard-v10-") as work:
        page = Path(work) / "progress_map_v10.html"
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
        base.run_edge([
            f"--window-size={base.WIDTH},{height}", "--force-device-scale-factor=2",
            f"--screenshot={args.output}", page.as_uri(),
        ], profile)
    print(f"wrote {args.output} ({base.WIDTH * 2}x{height * 2})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
