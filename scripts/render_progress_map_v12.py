"""Render Progress_map_v12 with the v11 layout and visual language.

Content brought up to the later 2026-11-03 snapshot: remote M4 session taint
(every upstream tool result taints its session, kept in files), removal and
call-time blocking of tools that can send data out in tainted remote sessions,
and the B response rule recorded on both paths.
Usage: python scripts/render_progress_map_v12.py [--html out.html]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import tempfile
from pathlib import Path

import render_progress_map_v11 as v11

base = v11.base
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Docs" / "Core_images" / "Progress_map_v12.png"
D, P, T = base.D, base.P, base.T
item, box = base.item, base.box


base.GROUPS = {
    "0단계": [D] * 7,
    "M1": [D] * 3,
    "1단계": [D, D, D, D, D],
    "2단계": [D, D, D, D, D, D, P, D],
    "3단계": [D, P, P],
    "4단계": [P, P, T],
    "상태 저장": [P, P, D, P],
}


def _replace_box(html_text: str, box_id: str, new_box: str) -> str:
    """Swap one card of v11's core column for its v12 version."""
    start = html_text.index(f'id="{box_id}"')
    start = html_text.rindex("<", 0, start)
    depth, i = 0, start
    while True:
        open_at, close_at = html_text.find("<div", i), html_text.find("</div>", i)
        if open_at != -1 and open_at < close_at:
            depth, i = depth + 1, open_at + 4
        else:
            depth, i = depth - 1, close_at + 6
            if depth == 0:
                return html_text[:start] + new_box + html_text[i:]


core = base.COL_CORE
core = _replace_box(core, "box-3", box("box-3", "3단계 · 응답 처리", [
    item(D, "M4 원격 세션 오염: 원 서버 결과마다 표시·파일 저장"),
    item(P, "로컬 세션 오염: Claude Code만 (Desktop 없음)"),
    item(P, "B 응답 규칙·분류기는 감사 기록만"),
], extra="two", notes=("오염 표시는 해제되지 않음 · 새 세션에서만 초기화",)))
core = _replace_box(core, "box-4", box("box-4", "4단계 · 봉쇄", [
    item(P, "오염 세션 외부 전송 도구 차단: Claude Code·원격"),
    item(P, "3-A4 승인 창: Claude Code만 · 승인 피로 지표"),
    item(T, "M4 값 정책: bcc·외부·공개 목적지"),
], extra="two", notes=("원격은 예외 승인 없음 — 오염되면 외부 전송 도구 전부 차단 · B는 오염 해제·승인 생략 불가",)))
core = _replace_box(core, "box-state", box("box-state", "상태 저장", [
    item(P, "정책·승인·재승인 파일 · 신뢰 등급 없음"),
    item(P, "오염 상태: Claude Code·원격 파일 · 게이트웨이 한 대 기준"),
    item(D, "감사 로그: 로컬·CloudWatch 경로"),
    item(P, "사용자별 토큰·세션 · 공유 저장소 없음"),
], extra="two"))
base.COL_CORE = core

base.COL_EXT = (base.COL_EXT
                .replace('<div class="flow" id="flow-3">응답: B 점수 감사만</div>',
                         '<div class="flow ok" id="flow-3">응답: 세션 오염 표시 · B 감사 기록</div>')
                .replace('<div class="flow" id="flow-4">호출: 원격 봉쇄 미구현</div>',
                         '<div class="flow ok" id="flow-4">호출: 오염 세션 외부 전송 차단</div>')
                # The local path has the same stage 2-4 controls, through the wrapper and the
                # Claude Code hook; say so like the remote card does.
                .replace('<div>guard 래퍼 뒤에서 실행</div></div>',
                         '<div>guard 래퍼 뒤에서 실행</div>'
                         '<div class="flow-ok">목록 검사 · 재승인 대기 · M5 설명문 대체</div>'
                         '<div class="flow-ok">응답·호출: 오염 표시 · 외부 전송 MCP 도구 거부</div>'
                         '<div>오염 표시는 Claude Code 훅 기준 · Desktop 없음</div></div>')
                .replace('<div class="flow" id="remote-c3">사용자별 원 서버 토큰 분리</div>',
                         '<div class="flow" id="remote-c3">사용자별 원 서버 토큰 · 로그인 없으면 시작 전 확인</div>'))
# Response and call paths now work on the remote gateway: draw them solid.
base.JS = (base.JS
           .replace("back('ext-remote','box-3', R('box-3').cy, {dash:true, label:'응답'})",
                    "back('ext-remote','box-3', R('box-3').cy, {label:'응답'})")
           .replace("link('box-4','ext-remote',{dash:true, y2:R('box-4').cy, label:'호출'})",
                    "link('box-4','ext-remote',{y2:R('box-4').cy, label:'호출'})"))

base.ATTACKS = [
    # Same criterion as the cards: done = code and tests. A user's direct connection is an
    # allowed choice outside the checks (architecture.md), and live checks are listed below.
    ("0", "우회", D, "L·C 진입 + 서버 허용 목록 + 설정 감시", "직접 연결은 허용된 선택 (검사 범위 밖)"),
    ("①", "신원 위장", D, "1단계 출처·패키지·B 점수 + M2 이름 검사", "실연동 검증은 별도 (하단)"),
    ("②", "정의 변조", P, "M3 변경 감지·재승인 · M5 설명문 대체", "정의 밖 서버 동작 변경은 M4 몫"),
    ("③", "응답 오염", P, "오염 표시 + 외부 전송 차단 (로컬·원격)", "Desktop·값 정책·원격 예외 승인 없음"),
    ("범위 밖", "서버 내부 동작", T, "검사 코어 대상 아님", "패치·OS 격리 별도"),
]

# First done attack cards: v9 styled only partial and todo ones.
base.CSS += "\n.atk.done{background:#e7fff4;border-color:#39d98a}\n"

# Same criterion as the cards. MVP 1: every rule family is wired or parity-tested (WAF edge,
# Sigma correlation, Semgrep code scan, OPA/YARA parity). MVP 9: C1-C3 are green in the entry
# column; deployment has its own card. MVP 8 stays partial: strict identity is not wired.
_MVP_UPDATES = {
    "MVP 1 ": ("MVP 1 · 정책 엔진", "규칙·판정", D),
    "MVP 2 ": ("MVP 2 · 게이트웨이 코어", "M1 중계·재승인·M4", D),
    "MVP 8 ": ("MVP 8 · 결정 제어", "신원 강화 미연결 · M5는 코어", P),
    "MVP 9 ": ("MVP 9 · 클라우드 진입", "C1–C3", D),
    "MVP 11 ": ("MVP 11 · B 분류기", "선택 기능 · 설명문 LLM 꺼짐", P),
}
base.MVPS = [next((v for k, v in _MVP_UPDATES.items() if m[0].startswith(k)), m) for m in base.MVPS]


def build_html() -> str:
    page = v11.build_html()
    page = page.replace("구현 현황 v11", "구현 현황 v12")
    page = page.replace("Progress_map_v11", "Progress_map_v12")
    page = re.sub(
        r'<section class="band"><h2>검증 범위 · 다음 작업</h2>.*?</ul></section>',
        '<section class="band"><h2>검증 범위 · 다음 작업</h2><ul class="checks">'
        '<li><i class="sq done"></i><span>전체 테스트 430개 실행 · 429개 통과 · 1개 건너뜀</span></li>'
        '<li><i class="sq todo"></i><span>실제 LLM 클라이언트·외부 MCP 서버·AWS 배포 미검증</span></li>'
        '<li class="left">다음: 원격 3-A4 예외 승인 → M4 값 정책 → 공유 상태 저장소 → 실연동 검증</li>'
        '</ul></section>', page, count=1, flags=re.S)
    return page


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", type=Path, help="also keep the generated HTML here")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-guard-v12-") as work:
        page = Path(work) / "progress_map_v12.html"
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
