"""Render Progress_map_v11 with the v10 layout and visual language.

Only the content changes, brought up to the later 2026-11-03 code snapshot:
M3 re-approval (D6-45), the grid-searched B score with GuardDog on (D6-40,
D6-46, D6-47), the description LLM check result (D6-44), local M4 for MCP
tools in tainted sessions, approval fatigue metrics, and the B rule tests.
Usage: python scripts/render_progress_map_v11.py [--html out.html]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import tempfile
from pathlib import Path

import render_progress_map_v10 as v10

base = v10.base
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Docs" / "Core_images" / "Progress_map_v11.png"
D, P, T = base.D, base.P, base.T
item, box = base.item, base.box


# Same 33-item accounting as v10; M3 re-approval is now done.
base.GROUPS = {
    "0단계": [D] * 7,
    "M1": [D] * 3,
    "1단계": [D, D, D, D, D],
    "2단계": [D, D, D, D, D, D, P, D],
    "3단계": [T, P, P],
    "4단계": [P, P, T],
    "상태 저장": [P, P, D, P],
}


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
        item(D, "B 점수: GBDT · PyPI 별도 기준 · GuardDog 기본 켜짐"),
        item(D, "악성 코드 유사도(근거 전용)·외부 피드 · LLM 검토는 판정 불변"),
    ], tag="로컬 패키지 경로", extra="two",
        notes=("시험 데이터 재현율 0.85 · 정상 보류 13% (PyPI 23%) · 유사도 색인은 D6-36 데이터 · 실연동 미검증",)),
    box("box-2", "2단계 · 등록 검사", [
        item(D, "M2 보호 이름·유사 도구 이름 검사"),
        item(D, "M2 혼동 문자·형식 검사"),
        item(D, "M3 정의·설명문 변경 감지"),
        item(D, "M3 재승인: 관리자 기본 · 사용자 수락 선택"),
        item(D, "M5 민감 세션 설명문 대체"),
        item(D, "M5 서버 단위 격리·외부 전송 도구 판별"),
        item(P, "B 설명문 규칙 42% · LLM 검사는 오탐 12%로 꺼짐"),
        item(D, "목록 변경·재연결 시 재검사"),
    ], tag="원격·로컬", extra="two"),
    box("box-3", "3단계 · 응답 처리", [
        item(T, "M4 출처 태깅·게이트웨이 세션 오염"),
        item(P, "Claude Code 세션 오염 표시"),
        item(P, "B 응답 점수는 감사 기록만"),
    ], extra="two"),
    box("box-4", "4단계 · 봉쇄", [
        item(P, "Claude Code 오염 세션: 내장·외부 전송 MCP 도구 차단"),
        item(P, "3-A4 Claude Code 승인 창 · 승인 피로 지표"),
        item(T, "원격 MCP 외부 전송 차단·값 정책"),
    ], extra="two", notes=("B는 오염 해제·승인 생략 불가 — 테스트로 강제",)),
    box("box-state", "상태 저장", [
        item(P, "정책·승인·재승인 파일 · 신뢰 등급 없음"),
        item(P, "오염 상태: Claude Code 세션만"),
        item(D, "감사 로그: 로컬·CloudWatch 경로"),
        item(P, "사용자별 토큰·세션 · 공유 저장소 없음"),
    ], extra="two"),
    box("box-out", "범위 밖 · 별도 트랙", status="todo", counted=False,
        lines=("서버 내부 코드 패치 · OS 격리",)),
])


base.ATTACKS = [
    ("0", "우회", P, "L·C 진입 + 서버 허용 목록", "직접 연결 선택 시 검사 우회"),
    ("①", "신원 위장", P, "1단계 출처·패키지·B 점수 + M2 이름 검사", "실제 공급 서비스 연동 미검증"),
    ("②", "정의 변조", P, "M3 변경 감지·재승인 · M5 설명문 대체", "정의 밖 서버 동작 변경은 M4 몫"),
    ("③", "응답 오염", P, "Claude Code 오염 세션 외부 전송 차단", "게이트웨이 M4·원격 봉쇄 미구현"),
    ("범위 밖", "서버 내부 동작", T, "검사 코어 대상 아님", "패치·OS 격리 별도"),
]


base.MVPS = [
    ("MVP 1 · 정책 엔진", "규칙·판정", P),
    ("MVP 2 · 게이트웨이 코어", "M1 중계·재승인", D),
    ("MVP 3 · 서버 등록", "0단계 설정", D),
    ("MVP 4 · tools/list", "2단계 검사", D),
    ("MVP 5 · IP 지연", "보조 제어", "aux"),
    ("MVP 6 · HTTP 게이트웨이", "원격 진입·확인 페이지", D),
    ("MVP 7 · tools/call", "호출 중계", D),
    ("MVP 8 · 결정 제어", "M5는 코어로 이동", P),
    ("MVP 9 · 클라우드 진입", "C1–C3", P),
    ("MVP 10 · 로컬 진입", "L1–L4 · 로컬 M4", D),
    ("MVP 11 · B 분류기", "선택 기능 · 설명문 LLM", P),
]


def build_html() -> str:
    page = v10.build_html()
    page = page.replace("구현 현황 v10", "구현 현황 v11")
    page = page.replace("Progress_map_v10", "Progress_map_v11")
    page = re.sub(
        r'<section class="band"><h2>검증 범위 · 다음 작업</h2>.*?</ul></section>',
        '<section class="band"><h2>검증 범위 · 다음 작업</h2><ul class="checks">'
        '<li><i class="sq done"></i><span>전체 테스트 426개 실행 · 425개 통과 · 1개 건너뜀</span></li>'
        '<li><i class="sq todo"></i><span>실제 LLM 클라이언트·외부 MCP 서버·AWS 배포 미검증</span></li>'
        '<li class="left">다음: 원격 M4 오염 표시·봉쇄 → M4 값 정책 → 실연동 검증</li>'
        '</ul></section>', page, count=1, flags=re.S)
    return page


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", type=Path, help="also keep the generated HTML here")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-guard-v11-") as work:
        page = Path(work) / "progress_map_v11.html"
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
