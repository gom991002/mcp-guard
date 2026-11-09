"""Render v13 from the v12 architecture layout after M4 value checks."""

from __future__ import annotations

import argparse
import html
import json
import re
import tempfile
from pathlib import Path

import render_progress_map_v12 as v12

base = v12.base
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Docs" / "Core_images" / "Progress_map_v13.png"
D, P = base.D, base.P

base.GROUPS["2단계"] = [D] * 8
base.GROUPS["3단계"] = [D] * 3
base.GROUPS["4단계"] = [D] * 3
base.COL_CORE = v12._replace_box(base.COL_CORE, "box-2", base.box("box-2", "2단계 · 등록 검사", [
    base.item(D, "M2 보호 이름·유사 도구 이름 검사"),
    base.item(D, "M2 혼동 문자·형식 검사"),
    base.item(D, "M3 정의·설명문 변경 감지"),
    base.item(D, "M3 재승인: 관리자 기본 · 사용자 수락 선택"),
    base.item(D, "M5 민감 세션 설명문 대체"),
    base.item(D, "M5 서버 단위 격리·외부 전송 도구 판별"),
    base.item(D, "B 설명문: 문구·구조 신호 · 단계식 LLM 검사"),
    base.item(D, "목록 변경·재연결 시 재검사"),
], tag="원격·로컬", extra="two", notes=(
    "문구+구조 규칙: 분리 시험 오염 82.1% 탐지 · 실제 설명문 0.47% 보류 · 선택 LLM은 남은 설명문만 검사",
)))
base.COL_CORE = v12._replace_box(base.COL_CORE, "box-3", base.box("box-3", "3단계 · 응답 처리", [
    base.item(D, "M4 원격: 원 서버 결과마다 오염 표시·파일 저장"),
    base.item(D, "M4 로컬: Claude Code 훅 오염 표시·파일 저장"),
    base.item(D, "B 응답 문구 규칙: 양쪽 감사 기록 · 오염 불변"),
], extra="two", notes=(
    "B_RESPONSE_EXFIL_TEXT는 로컬 래퍼·원격에 연결 · 선택 분류기 추론은 별도 검증 · Desktop 오염 표시는 범위 밖",
)))
base.COL_CORE = v12._replace_box(base.COL_CORE, "box-4", base.box("box-4", "4단계 · 봉쇄", [
    base.item(D, "오염 세션 외부 전송 도구 차단: Claude Code·원격"),
    base.item(D, "3-A4 승인: Claude Code 훅·원격 로그인 페이지"),
    base.item(D, "M4 값 정책: 설정 시 받는 사람·bcc·URL·공개 설정 검사"),
], extra="two", notes=("실제 클라이언트 검증은 별도 · Desktop 오염 세션 차단은 범위 밖 · 값 정책 미지정 필드는 보완 필요",)))
base.COL_CORE = base.COL_CORE.replace(
    "오염 상태: Claude Code·원격 파일 · 게이트웨이 한 대 기준",
    "오염·승인 요청 파일 · 게이트웨이 한 대 기준",
)
base.ATTACKS = [
    (n, name, D if n in {"②", "③"} else state,
     "M3 재승인 · M5 대체 · B 설명문 신호 · M4 값 정책" if n == "②" else
     "M4 오염 표시·전송 차단·값 검사 · 3-A4 승인" if n == "③" else description,
     "비민감 설명문은 B 신호만 · 정의 밖 동작 변경 가능" if n == "②" else
     "B 응답은 감사만 · Desktop·직접 콘텐츠 미포착" if n == "③" else note)
    for n, name, state, description, note in base.ATTACKS
]
base.MVPS = [
    ("MVP 8 · 결정 제어", "토큰 발급·사용 분기 · 발행자 검사는 1단계", D)
    if title.startswith("MVP 8 ") else
    ("MVP 11 · B 분류기", "선택 경로 연결 · 실모델 추론 미검증", P)
    if title.startswith("MVP 11 ") else (title, detail, state)
    for title, detail, state in base.MVPS
]


def build_html() -> str:
    page = v12.build_html().replace("구현 현황 v12", "구현 현황 v13")
    page = page.replace("Progress_map_v12", "Progress_map_v13")
    page = page.replace("2026-11-03", "2026-11-04")
    page = re.sub(
        r'<section class="band"><h2>검증 범위 · 다음 작업</h2>.*?</ul></section>',
        '<section class="band"><h2>검증 범위 · 다음 작업</h2><ul class="checks">'
        '<li><i class="sq partial"></i><span>전체 테스트 496개 · Semgrep 환경 실패 2개 · 건너뜀 3개</span></li>'
        '<li><i class="sq done"></i><span>기본 전용 상태 폴더 · 이전 확인 · 상위 폴더 권한 검사</span></li>'
        '<li><i class="sq todo"></i><span>실제 LLM 클라이언트·외부 MCP 서버·AWS 배포 미검증</span></li>'
        '<li class="left">다음: 실제 클라이언트 승인 검증 → 도구별 값 필드 확장 → 단일 게이트웨이 운영 검증</li>'
        '</ul></section>', page, count=1, flags=re.S)
    return page


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-guard-v13-") as work:
        page = Path(work) / "progress_map_v13.html"
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
