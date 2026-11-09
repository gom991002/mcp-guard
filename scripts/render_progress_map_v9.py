"""Render Docs/Core_images/Progress_map_v9.png with headless Microsoft Edge.

Reviewed code/test snapshot: 2026-11-02. Keeps the v8 layout. v9 adds the
stage 1 work since v8: the Semgrep code scan (D6-30), dependency locks against
lookalike and hijacked packages (D6-31), the B score trained on labelled
malware (D6-35), and known-malware similarity plus the LLM review aid (D6-36).
Stage 1 grows from 3 to 5 design items. Live third-party interoperability and
the review aid's accuracy remain unverified.

Usage: python scripts/render_progress_map_v9.py [--html out.html]
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Docs" / "Core_images" / "Progress_map_v9.png"
WIDTH = 2000
EDGE_CANDIDATES = (
    os.environ.get("MSEDGE", ""),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)

LABEL = {"done": "구현됨", "partial": "일부 구현", "todo": "미구현", "aux": "보조"}


def esc(text: str) -> str:
    """Escape text and turn `code` spans into <code>."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text))


def item(status: str, text: str) -> tuple[str, str]:
    return status, text


def box(
    box_id: str,
    title: str,
    items: list[tuple[str, str]] = (),
    *,
    status: str = "",
    tag: str = "",
    notes: tuple[str, ...] = (),
    lines: tuple[str, ...] = (),
    counted: bool = True,
    extra: str = "",
) -> str:
    """A component box. Mixed boxes show one square per counted item."""
    statuses = [s for s, _ in items]
    if not status:
        status = statuses[0] if len(set(statuses)) == 1 else "mixed"
    head = f'<span class="pill {status}">{LABEL[status]}</span>' if status in LABEL else ""
    if counted and items and len(set(statuses)) > 1:
        head = "".join(f'<i class="sq {s}"></i>' for s in statuses)
    tag_html = f'<span class="tag">{esc(tag)}</span>' if tag else ""
    body = "".join(f'<div class="line">{esc(t)}</div>' for t in lines)
    if items:
        body += "<ul>" + "".join(
            f'<li class="{s}"><i class="sq {s}"></i><span>{esc(t)}</span></li>' for s, t in items
        ) + "</ul>"
    body += "".join(f'<div class="note">{esc(t)}</div>' for t in notes)
    return (
        f'<div class="box {status} {extra}" id="{box_id}">'
        f'<div class="bh"><h3>{esc(title)}{tag_html}</h3><div class="marks">{head}</div></div>'
        f"{body}</div>"
    )


D, P, T = "done", "partial", "todo"

GROUPS = {
    "0단계": [D, D, D, D, D, D, D],
    "M1": [D, D, D],
    "1단계": [D, D, D, D, P],
    "2단계": [P, P, D, T, P, T, P, D],
    "3단계": [T, P, P],
    "4단계": [P, P, T],
    "상태 저장": [P, P, D, P],
}

COL_ENTRY = "".join([
    box("box-L", "L · 로컬 진입 강제", [
        item(D, "L1 비독점 `.mcp.json` · 훅 설정 생성"),
        item(D, "L2 stdio 래퍼 fail-closed · 목록 필터"),
        item(D, "L3 설정 감시 · 재래핑 · 우회 사본"),
        item(D, "L4 훅: 미승인 도구 · 오염 세션 내장 도구 판정"),
    ], tag="MVP 10", notes=("도구 승인: 서비스 기본, 허용 시 사용자 (D6-18)",
                            "M1 기록은 단말에만 · 6개월 · 래퍼 세션은 프로세스 단위",
                            "실제 Claude Code · Desktop 실행 미검증")),
    box("box-C", "C · 클라우드 진입 강제", [
        item(D, "C1 등록 절차: Claude · ChatGPT · Codex · Gemini Enterprise · Gemini CLI"),
        item(D, "C2 OAuth: CIMD · DCR · PKCE · 사전 등록 클라이언트(secret)"),
        item(D, "C3 서버별 shared · per_user · 토큰은 Secrets Manager"),
    ], tag="MVP 9", notes=("강제는 claude.ai Team · Enterprise만 · ChatGPT · Gemini 강제 방법 미확인",
                           "세션은 LLM 클라이언트별 (ChatGPT는 대화 ID)",
                           "실제 클라이언트 · AWS 연결 미검증")),
    box("branch", "guard 사용 분기", status="done", counted=False,
        lines=("매니페스트 guard yes/no → L1 설정 생성에 결합",),
        notes=("원격 항목은 MVP 8 `decide_activation`",)),
    box("box-S0", "코어 쪽 0단계 보조", [
        item(D, "S0 서버 허용 목록 · 등록 출처 (엔진)"),
        item(D, "`S0_GATEWAY_*` 입구 검사 → HTTP 상태"),
        item(D, "첫 사용 승인 기록 `--enroll` · 신원 고정"),
    ], tag="도면 밖", counted=False, notes=("L · C 경로 통제를 대체하지 않음",)),
    box("box-ip", "IP 딜레이 보조", status="aux", counted=False, tag="MVP 5 갱신",
        lines=("요청 횟수 슬라이딩 창",
               "IP당 60초 100회 · IP+토큰당 60초 60회",
               "10분 내 5회 지연 → 10분 차단(429) · 반복 2배 · 상한 1시간",
               "공유 출발지(Anthropic 대역)는 IP 규칙 제외"),
        notes=("콘텐츠 판정 아님 · ChatGPT 대역은 수동 등록",)),
    box("deploy", "배포: AWS EC2 · Docker · Caddy", status="partial", counted=False, tag="인프라",
        lines=("Secrets Manager(토큰) · CloudWatch Logs(감사)",
               "IAM 템플릿 · 경보 대시보드 · SNS 이메일"),
        notes=("이미지 빌드 · 실제 AWS 배포 미검증",)),
    box("direct", "직접 연결 선택 → 원 서버", status="none", counted=False, extra="ghost",
        lines=("0~4단계 미적용 · 매니페스트에 guard: false로 선언",)),
])

COL_CORE = "".join([
    box("box-M1", "M1 · 중계 · 감사 기록", [
        item(D, "중계: ASGI/개발용 HTTP(원격) · stdio 래퍼(로컬) · JSON 단일 응답 (D6-29)"),
        item(D, "감사 기록: 27종 이벤트 · CloudWatch + 로컬 사본 · 6개월 · 상관 규칙 5분 주기"),
        item(D, "판정 모델 내용 해시 · 선택형 B 점수/임계값 기록 (기본 0.5)"),
    ], notes=("클라이언트 방향 streaming은 범위 제외 · 실제 클라이언트/AWS 검증은 배포 단계", "경보: CloudWatch 대시보드 → SNS 이메일 구성 · 실제 AWS 연결 미검증")),
    box("box-1", "1단계 · 정상 연동", [
        item(D, "공식 MCP Registry: 서버 ID·버전·게시 상태·패키지 대조"),
        item(D, "2-A5: npm/PyPI 배포 해시·설치 트리 고정; Docker 서명 옵션 강제"),
        item(D, "의존성 잠금: 전 패키지 배포 파일 대조 · OSV 악성 · 30일 보류 · 비슷한 이름 (D6-31)"),
        item(D, "B 코드 행동 분석: Semgrep 규칙 9종 · 정답 2,066개로 학습한 패키지 점수 (D6-30 · 35)"),
        item(P, "규칙 + LLM: 알려진 악성 유사도(근거, 보류 악성 19/30 · 정상 0/30) · LLM 도우미(판정 불변) — 무료 7B는 악성·정상 구분 못함 (D6-36)"),
    ], tag="로컬 패키지 경로 (A-02)", notes=("L2 실행 전 검사; 실패 시 서버 미시작 · 실제 Registry/npm/PyPI/Docker 접속은 마지막 단계에서 검증",
                                      "B 판정은 데이터가 고른 규칙(검토 신호 하나라도 → 검토) · 점수는 우선순위 · 시험 재현율 65% · PyPI는 45%이고 정상 약 1/3 보류",
                                      "Docker 이미지 코드는 검사 안 함(서명에 맡김, D6-34) · 원격 경로에는 1단계 없음(D6-32)"), extra="two"),
    box("box-2", "2단계 · 등록 검사", [
        item(P, "M2 이름 바인딩: 보호 이름 정확 일치"),
        item(P, "M2 혼동 문자: skeleton 비교 (보호 이름만)"),
        item(D, "M3 해시 · 설명문 변경 감지 → review"),
        item(T, "M3 재승인 절차 (UI 없음)"),
        item(P, "M5 설명문 대체: MVP 8 단독"),
        item(T, "M5 세션 격리"),
        item(P, "B 설명문: YARA 초안 + 선택형 분류기(SIGNAL)"),
        item(D, "재검사: 캐시 만료 · `list_changed`"),
    ], tag="재연결 · 목록 변경마다", extra="two",
        notes=("원격 게이트웨이와 로컬 래퍼가 같은 검사 · 도면 밖 보조: MCP 이름 권장 위반 → review · 서버 간 비슷한 이름 비교 없음",)),
    box("box-3", "3단계 · 응답 처리", [
        item(T, "M4 출처 태깅"),
        item(P, "M4 세션 오염 표시: Claude Code 세션만 (L4 훅)"),
        item(P, "B 분류기: 응답 점수 감사 기록만 · LLM 미결합"),
    ], notes=("게이트웨이 응답 점수는 선택형 감사 신호; M4 오염 표시·차단 없음",), extra="two"),
    box("box-4", "4단계 · 봉쇄", [
        item(P, "M4 오염 세션 외부 전송 차단: Claude Code 내장 도구만 · 값 정책 없음"),
        item(P, "3-A4 사용자 지정 예외만 승인: Claude Code 승인 창 (원문)"),
        item(T, "최소 권한 · 세션 분리"),
    ], notes=("MCP 외부 전송 도구 정의는 결정 대기 (D6-07) · 3-A4 거절은 기록 안 함 (D6-23)",), extra="two"),
    box("box-state", "상태 저장", [
        item(P, "정책 파일 로딩 (신뢰 등급 없음)"),
        item(P, "오염 상태: 세션별 파일 (Claude Code)"),
        item(D, "감사 로그: CloudWatch + 로컬 사본 (월 회전 · 180일)"),
        item(P, "사용자별 분리: per_user 토큰 · 클라이언트별 세션"),
    ], notes=("JSON 파일: 0단계 승인 · OAuth 클라이언트 · refresh 해시 · 목록 캐시 · IP 카운터 · 차단은 메모리 · 인스턴스 1대 가정",), extra="two"),
    box("box-out", "범위 밖 · 별도 트랙", status="todo", counted=False,
        lines=("서버 내부 동작 → 코드 분석 · 패치 · OS 격리 — 미착수",)),
])

COL_EXT = "".join([
    '<div class="ext" id="ext-local"><h4>로컬 MCP 서버 프로세스</h4>'
    '<div>npm · PyPI 패키지를 단말에서 실행</div><div class="flow-ok">guard 선택 시 L2 래퍼 뒤에서 실행</div></div>',
    '<div class="ext" id="ext-registry"><h4>공식 MCP Registry <small>로컬 실행 전 조회 코드</small></h4></div>',
    '<div class="ext" id="ext-npm"><h4>npm · PyPI · Docker · OSV <small>메타데이터·배포 파일·서명 옵션·악성 기록 조회 코드</small></h4></div>',
    '<div class="ext" id="ext-remote"><h4>원격 MCP 서버</h4><div id="remote-static">서드파티 · 공격자 통제 가능</div>'
    '<div class="flow" id="remote-c3">자격증명은 게이트웨이만 · 사용자별 연결 (C3 · Secrets Manager)</div>'
    '<div class="flow" id="remote-note">실제 외부 서버 미검증 (localhost만)</div>'
    '<div class="flow ok" id="flow-2">← 등록: <code>tools/list</code> 실조회 동작</div>'
    '<div class="flow" id="flow-3">← 응답: 선택형 B 점수 감사만 · M4 처리 없음</div>'
    '<div class="flow" id="flow-4">→ 호출: 4단계 봉쇄 없음</div></div>',
    '<div class="ext danger" id="ext-content"><h4>외부 콘텐츠</h4><div>메일 · 이슈 · 웹 → 정상 서버가 읽어 옴</div></div>',
    '<div class="ext danger" id="ext-attacker"><h4>공격자</h4><div>글 · 서버 · 패키지</div></div>',
])

ATTACKS = [
    ("0", "우회", P, "L1–L4 · C1–C3 진입 경로 + 코어 쪽 허용 목록 · L3 재래핑은 감사 기록",
     "비독점 설정 · 개인은 자유 배포 · ChatGPT · Gemini 강제 미확인"),
    ("①", "신원 위장", P, "로컬 1단계: 출처·버전 · 의존성 배포 파일 대조 · OSV 악성 · 비슷한 이름 · B 코드 분석 + S0 + M2",
     "실제 공급 서비스 연동 미검증 · PyPI B 오탐 높음 · 서버 간 비슷한 이름 비교 없음"),
    ("②", "정의 변조", P, "M3 해시 · 설명문 변경 → review (원격 · 로컬)", "M5 미결합 · 4단계 봉쇄 없음"),
    ("③", "응답 오염", P, "Claude Code: 오염 세션의 Bash · WebFetch 차단", "게이트웨이 응답 검사 · MCP 외부 전송 도구 차단 없음"),
    ("범위 밖", "서버 내부 동작", T, "검사 코어 대상 아님 (A-01)", "코드 분석 · 패치 · OS 격리 미착수"),
]

MVPS = [
    ("MVP 1 · 정책 엔진 · 규칙 초안", "→ 0 · 2단계 판정 · WAF · Semgrep 규칙 결합", P),
    ("MVP 2 · 게이트웨이 코어", "→ M1 중계 · JSON-RPC 처리", D),
    ("MVP 3 · 서버 등록 설정", "→ 0단계 보조 · 2단계 입력", D),
    ("MVP 4 · `tools/list` 중계", "→ 2단계 · 실조회 · 캐시 · C3 헤더", D),
    ("MVP 5 · IP 요청 횟수 딜레이", "→ 보조 · 반복 지연 차단 · MVP 6 연결", "aux"),
    ("MVP 6 · HTTP 게이트웨이 서버", "→ 중계 진입점 · 감사 기록 · 상관 규칙", D),
    ("MVP 7 · `tools/call` 중계", "→ 호출 직전 2단계 재검사 · C3 헤더", D),
    ("MVP 8 · 결정 컨트롤", "→ 토큰 · 분기는 결합 · M5 · strict identity 단독", P),
    ("MVP 9 · 클라우드 진입", "→ C1–C3 · 3개 LLM · Secrets Manager · CloudWatch", P),
    ("MVP 10 · 로컬 진입", "→ L1–L4 · 1단계 검사 · 의존성 잠금 · 코드 검사 · 승인", D),
    ("MVP 11 · 선택형 B 분류기", "→ 2단계 SIGNAL · 3단계 응답 점수 감사 (기본 꺼짐)", P),
]

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{width:%(w)dpx;background:#0e2a43;color:#d9e8f6;font-family:'Noto Sans KR','Malgun Gothic',sans-serif;
 background-image:linear-gradient(#1a3b59 1px,transparent 1px),linear-gradient(90deg,#1a3b59 1px,transparent 1px);
 background-size:40px 40px;padding:34px 50px 26px;position:relative;word-break:keep-all;overflow-wrap:break-word}
code{font-family:Consolas,monospace;font-size:.92em}
header{display:flex;justify-content:space-between;align-items:flex-start}
h1{font-size:44px;font-weight:800;color:#f3f8ff;letter-spacing:-.5px}
.sub{font-size:19px;color:#a9bdd2;margin-top:6px}
.date{text-align:right;font-size:34px;font-weight:800;color:#f3f8ff}.date small{display:block;font-size:17px;color:#a9bdd2;font-weight:400}
.legend{margin-top:22px;border:1.5px solid #3f6180;border-radius:12px;background:rgba(21,59,91,.6);padding:14px 22px;display:flex;flex-direction:column;gap:12px}
.lg{display:flex;gap:34px;align-items:center;font-size:17px;flex-wrap:wrap}
.lg span{display:flex;align-items:center;gap:9px}
.chip{width:30px;height:18px;border-radius:5px;border:2.5px solid}
.chip.done{background:#e7fff4;border-color:#39d98a}.chip.partial{background:#fff8df;border-color:#f6c343}
.chip.todo{background:#f1f5fa;border-color:#9fb3c8;border-style:dashed}.chip.aux{background:#f4ebff;border-color:#9c6bff}
.chip.infra{background:transparent;border-color:#5c7894}
.arrow-key{display:inline-block;width:46px;border-top:3px solid #d8e7f5;position:relative}
.arrow-key.dash{border-top-style:dashed;border-color:#b9cce0}
.summary{display:flex;align-items:center;gap:26px}
.big{font-size:21px;font-weight:800;color:#f3f8ff;white-space:nowrap}
.big b.g{color:#59e3a0}.big b.y{color:#f6c343}.big b.s{color:#b9cce0}
.bar{flex:1;display:flex;height:22px;border-radius:6px;overflow:hidden;border:1.5px solid #5c7894}
.bar div{height:100%%}.bar .done{background:#39d98a}.bar .partial{background:#f6c343}.bar .todo{background:#53708c}
.groups{display:flex;gap:20px;font-size:15px;color:#b9cce0;white-space:nowrap}
.groups i{display:inline-block;width:13px;height:13px;border-radius:3px;margin-left:3px;vertical-align:-1px}
.sq.done{background:#39d98a}.sq.partial{background:#f6c343}.sq.todo{background:#9fb3c8}.sq.aux{background:#9c6bff}
main{display:grid;grid-template-columns:430px 960px 430px;column-gap:40px;margin-top:22px;align-items:start}
.sec{border:2px dashed #5c7894;border-radius:14px;background:rgba(21,59,91,.55);padding:16px 16px 18px;position:relative;min-height:100%%}
.sec.core{border-color:#39d98a;background:rgba(18,70,72,.35)}
.sec>h2{font-size:24px;font-weight:800;color:#e6f1fb;margin-bottom:14px;display:flex;justify-content:space-between;align-items:baseline}
.sec>h2 small{font-size:14px;color:#59e3a0;font-weight:600}
.stack{display:flex;flex-direction:column;gap:14px}
.box{border-radius:11px;border:2.5px solid;padding:12px 14px 11px;color:#334b60}
.box.done{background:#e7fff4;border-color:#39d98a}.box.partial{background:#fff8df;border-color:#f6c343}
.box.todo{background:#e9eef4;border-color:#9fb3c8;border-style:dashed}.box.aux{background:#f4ebff;border-color:#9c6bff}
.box.mixed{background:#f7f9fc;border-color:#c4d2e0}
.box.ghost{background:transparent;border:2px dashed #5c7894;color:#a9bdd2}
.box.ghost h3{color:#d9e8f6}
.bh{display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:6px}
.box h3{font-size:19px;font-weight:800;color:#142333;line-height:1.25}
.tag{font-size:13px;font-weight:500;color:#5b7186;margin-left:8px}
.marks{display:flex;gap:4px;flex-shrink:0;padding-top:3px}
.marks .sq{width:15px;height:15px;border-radius:3px;display:inline-block}
.pill{font-size:13px;font-weight:800;padding:2px 10px;border-radius:20px;white-space:nowrap}
.pill.done{background:#39d98a;color:#0d3322}.pill.partial{background:#f6c343;color:#3b2b00}
.pill.todo{background:#9fb3c8;color:#1d2f40}.pill.aux{background:#9c6bff;color:#fff}
.box ul{list-style:none;display:grid;gap:3px 14px}
.box.two ul{grid-template-columns:1fr 1fr}
.box li{display:flex;gap:8px;font-size:15.5px;line-height:1.4;align-items:flex-start}
.box li .sq{width:12px;height:12px;border-radius:2px;flex-shrink:0;margin-top:5px}
.box li.todo span{color:#6b7f92}
.line{font-size:15.5px;line-height:1.45}
.note{font-size:13.5px;color:#6b7f92;margin-top:6px;line-height:1.4}
.box.ghost .note,.box.ghost .line{color:#a9bdd2}
.col-ext{position:relative}
.ext{position:absolute;left:16px;right:16px;border:2px solid #5c7894;border-radius:11px;background:rgba(23,57,90,.92);padding:11px 14px;font-size:14.5px;line-height:1.45;color:#b9cce0}
.ext h4{font-size:18px;color:#eef6ff;font-weight:800;margin-bottom:3px}.ext h4 small{font-size:13px;color:#a9bdd2;font-weight:500;margin-left:6px}
.ext .warn{color:#f6c343;font-weight:700}.ext .flow-ok{color:#59e3a0;font-weight:700}
.ext.danger{background:rgba(74,36,51,.95);border-color:#ff667c}.ext.danger h4{color:#ffb3bf}
.flow{position:absolute;left:14px;right:10px;font-size:14.5px;color:#b9cce0}
.flow.ok{color:#59e3a0;font-weight:700}
.bands{display:grid;gap:18px;margin-top:22px}
.band{border:2px dashed #5c7894;border-radius:14px;background:rgba(21,59,91,.55);padding:14px 18px 16px}
.band h2{font-size:23px;font-weight:800;color:#e6f1fb;margin-bottom:12px}
.attacks{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}
.atk{border-radius:11px;border:2.5px solid;padding:10px 14px;color:#334b60;font-size:15px;line-height:1.45}
.atk.partial{background:#fff8df;border-color:#f6c343}.atk.todo{background:#e9eef4;border-color:#9fb3c8;border-style:dashed}
.atk h3{font-size:18px;color:#142333;display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
.num{display:inline-block;min-width:28px;padding:0 7px;height:26px;border-radius:13px;background:#24496b;color:#fff;font-size:14px;text-align:center;line-height:26px;margin-right:8px}
.lower{display:grid;grid-template-columns:1.9fr 1fr;gap:18px}
.mvps{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.mvp{border-radius:10px;border:2.5px solid;padding:8px 12px;font-size:14px;color:#334b60;line-height:1.4}
.mvp b{display:block;font-size:15.5px;color:#142333}
.mvp.done{background:#e7fff4;border-color:#39d98a}.mvp.partial{background:#fff8df;border-color:#f6c343}.mvp.aux{background:#f4ebff;border-color:#9c6bff}
.checks{list-style:none;display:grid;gap:7px;font-size:15.5px;color:#d9e8f6}
.checks li{display:flex;gap:10px;align-items:flex-start}.checks li i{width:13px;height:13px;border-radius:3px;flex-shrink:0;margin-top:5px}
.checks .left{color:#f6c343;font-weight:800;margin-top:4px}
footer{margin-top:14px;font-size:13.5px;color:#8fa6bd}
svg#wires{position:absolute;left:0;top:0;pointer-events:none;overflow:visible}
"""

JS = r"""
const page = document.body.getBoundingClientRect();
function R(id){const r=document.getElementById(id).getBoundingClientRect();
 return {l:r.left-page.left,t:r.top-page.top,r:r.right-page.left,b:r.bottom-page.top,cy:(r.top+r.bottom)/2-page.top,h:r.height};}
function place(id, top, height){const el=document.getElementById(id), col=R('col-ext');
 el.style.top=(top-col.t)+'px'; if(height) el.style.minHeight=height+'px';}
const issues=[];
// Align the external column with the stages it talks to.
const m1=R('box-M1'), s1=R('box-1'), s2=R('box-2'), s4=R('box-4'), st=R('box-state'), out=R('box-out');
place('ext-local', m1.t, m1.h);
place('ext-registry', s1.t); place('ext-npm', s1.b - R('ext-npm').h);
place('ext-remote', s2.t, s4.b - s2.t);
place('ext-content', st.t); place('ext-attacker', out.t);
function flow(id, y){const el=document.getElementById(id), box=R('ext-remote'); el.style.top=(y-box.t-10)+'px';}
flow('flow-2', R('box-2').cy); flow('flow-3', R('box-3').cy); flow('flow-4', R('box-4').cy);
flow('remote-note', (R('box-3').cy + R('box-4').cy) / 2);
flow('remote-c3', (R('box-2').cy + R('box-3').cy) / 2);
const order=['ext-local','ext-registry','ext-npm','ext-remote','ext-content','ext-attacker'];
for(let i=1;i<order.length;i++){ if(R(order[i]).t < R(order[i-1]).b+6) issues.push('overlap '+order[i]); }
if(R('flow-2').t < R('remote-static').b+4) issues.push('overlap flow-2');
if(R('remote-note').t < R('flow-3').b+4 || R('remote-note').b > R('flow-4').t-4) issues.push('overlap remote-note');
if(R('remote-c3').t < R('flow-2').b+4 || R('remote-c3').b > R('flow-3').t-4) issues.push('overlap remote-c3');
const NS='http://www.w3.org/2000/svg', svg=document.getElementById('wires');
svg.setAttribute('width', document.body.scrollWidth); svg.setAttribute('height', document.body.scrollHeight);
function wire(points, {dash=false, color='#d8e7f5', both=false, label=''}={}){
 const p=document.createElementNS(NS,'polyline');
 p.setAttribute('points', points.map(q=>q.join(',')).join(' '));
 p.setAttribute('fill','none'); p.setAttribute('stroke',color); p.setAttribute('stroke-width','3');
 if(dash) p.setAttribute('stroke-dasharray','10 8');
 const mk = dash ? 'url(#ah-soft)' : (color==='#ff8a9b' ? 'url(#ah-red)' : 'url(#ah)');
 p.setAttribute('marker-end', mk); if(both) p.setAttribute('marker-start', mk);
 svg.appendChild(p);
 if(label){const t=document.createElementNS(NS,'text'); const a=points[0], b=points[points.length-1];
  t.setAttribute('x',(a[0]+b[0])/2); t.setAttribute('y',Math.min(a[1],b[1])-8); t.setAttribute('text-anchor','middle');
  t.setAttribute('fill','#b9cce0'); t.setAttribute('font-size','14'); t.textContent=label; svg.appendChild(t);}
}
function link(from, to, opt={}){const a=R(from), b=R(to); const y1=opt.y1 ?? a.cy, y2=opt.y2 ?? b.cy;
 const x1=a.r+4, x2=b.l-6, xm=(x1+x2)/2;
 wire(Math.abs(y1-y2)<2 ? [[x1,y1],[x2,y2]] : [[x1,y1],[xm,y1],[xm,y2],[x2,y2]], opt);}
link('box-L','sec-core',{y2:R('box-L').cy});
link('box-C','sec-core',{y2:R('box-C').cy});
link('box-S0','sec-core',{y2:R('box-S0').cy});
link('box-M1','ext-local',{both:true, label:'중계'});
function back(fromExt, toBox, y, opt={}){const a=R(fromExt), b=R(toBox); wire([[a.l-6,y],[b.r+6,y]], opt);}
back('ext-registry','box-1', R('ext-registry').cy, {color:'#59e3a0'});
back('ext-npm','box-1', R('ext-npm').cy, {color:'#59e3a0'});
back('ext-remote','box-2', R('box-2').cy, {label:'등록', color:'#59e3a0'});
back('ext-remote','box-3', R('box-3').cy, {dash:true, label:'응답'});
link('box-4','ext-remote',{dash:true, y2:R('box-4').cy, label:'호출'});
const rc=R('ext-content'), rr=R('ext-remote'), ra=R('ext-attacker'), cx=(rc.l+rc.r)/2;
wire([[cx,rc.t-4],[cx,rr.b+8]], {color:'#ff8a9b'});
wire([[cx,ra.t-4],[cx,rc.b+8]], {color:'#ff8a9b'});
document.querySelectorAll('h3, li span, .line, .note').forEach(el=>{
 if(el.scrollWidth > el.clientWidth+1) issues.push('overflow '+el.textContent.slice(0,40));});
document.body.dataset.height = Math.ceil(document.body.scrollHeight);
document.body.dataset.issues = JSON.stringify(issues);
"""


def build_html() -> str:
    counts = {s: sum(v.count(s) for v in GROUPS.values()) for s in (D, P, T)}
    total = sum(counts.values())
    bar = "".join(
        f'<div class="{s}" style="width:{counts[s] / total * 100:.2f}%"></div>' for s in (D, P, T)
    )
    groups = "".join(
        f"<span>{name}" + "".join(f'<i class="sq {s}"></i>' for s in marks) + "</span>"
        for name, marks in GROUPS.items()
    )
    attacks = "".join(
        f'<div class="atk {s}"><h3><span><span class="num">{esc(n)}</span>{esc(t)}</span>'
        f'<span class="pill {s}">{LABEL[s]}</span></h3><div>{esc(a)}</div><div class="note">{esc(b)}</div></div>'
        for n, t, s, a, b in ATTACKS
    )
    mvps = "".join(
        f'<div class="mvp {s}"><b>{esc(t)}</b>{esc(d)}</div>' for t, d, s in MVPS
    )
    built = counts[D] + counts[P]
    return f"""<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
<title>mcp-guard 구현 현황 v9</title><style>{CSS % {"w": WIDTH}}</style></head><body>
<svg id="wires"><defs>
<marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="#d8e7f5"/></marker>
<marker id="ah-soft" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="#b9cce0"/></marker>
<marker id="ah-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="#ff8a9b"/></marker>
</defs></svg>
<header><div><h1>mcp-guard 구현 현황 v9 — 제작된 것과 아직 구현하지 않은 것</h1>
<div class="sub">도면 v2 · A-01 · A-02의 구성 위에 현재 코드 상태를 겹친 그림 · 네모 1칸 = 설계 항목 1개 (작업량 · 완성률 % 아님)</div></div>
<div class="date">2026-11-02<small>Progress_map_v9</small></div></header>
<section class="legend">
<div class="lg"><span><i class="chip done"></i>구현됨 · 연결 · 테스트</span><span><i class="chip partial"></i>일부 구현 또는 단독 구현 (미결합)</span>
<span><i class="chip todo"></i>미구현</span><span><i class="chip aux"></i>보조 · 주 판정 아님</span><span><i class="chip infra"></i>인프라 · 외부 (셈에서 제외)</span>
<span><i class="arrow-key"></i>동작하는 경로</span><span><i class="arrow-key dash"></i>미구현 경로</span></div>
<div class="summary"><div class="big">설계 항목 {total}개 — 제작됨 <b class="g">{built}</b> (구현 <b class="g">{counts[D]}</b> · 일부 <b class="y">{counts[P]}</b>) · 미구현 <b class="s">{counts[T]}</b></div>
<div class="bar">{bar}</div><div class="groups">{groups}</div></div>
</section>
<main>
<section class="sec"><h2>0단계 · 진입</h2><div class="stack">{COL_ENTRY}</div></section>
<section class="sec core" id="sec-core"><h2>검사 코어 · 로컬 프록시 = 원격 게이트웨이 <small>현재 동작: 원격 (MVP 6+9) · 로컬 (MVP 10 래퍼)</small></h2><div class="stack">{COL_CORE}</div></section>
<section class="sec col-ext" id="col-ext"><h2>MCP 서버 · 외부</h2>{COL_EXT}</section>
</main>
<div class="bands">
<section class="band"><h2>공격 유형별 현재 방어 — A-01 행 기준</h2><div class="attacks">{attacks}</div></section>
<div class="lower">
<section class="band"><h2>MVP 1–11 → 아키텍처 위치</h2><div class="mvps">{mvps}</div></section>
<section class="band"><h2>테스트 · 검증 범위 · 남은 큰 작업</h2><ul class="checks">
<li><i class="sq done"></i><span>344개 테스트 실행 (1개 건너뜀, 실패 없음) · 1단계 B는 정답 데이터(악성 916 · 정상 1,150)로 평가</span></li>
<li><i class="sq todo"></i><span>공식 Registry/npm/PyPI/Docker 실연동 · 실제 LLM 클라이언트 · AWS 배포 미검증</span></li>
<li><i class="sq todo"></i><span>단계별 차단 효과 미측정 · IP 딜레이 기본값은 MCP 트래픽으로 실측 안 함</span></li>
<li class="left">남은 큰 작업: PyPI 오탐 개선 · LLM 도우미 개선(GPU·더 큰 모델·정상 비교 근거) · 외부 전송 도구 정의(D6-07) · 게이트웨이 3 · 4단계 · M5 결합 · 실연동 · 실배포</li>
</ul></section></div></div>
<footer>근거: <code>src/mcp_guard/</code> · <code>mvp/01–11</code> · <code>tests/</code> · <code>Docs/Core_mds/architecture.md</code> (2026-11-02). {total}개 항목은 0~4단계 · M1 · 상태 저장 기준. v8 대비: 1단계 Semgrep 코드 검사(D6-30) · 의존성 잠금(D6-31) · 정답 데이터로 학습한 B 점수(D6-35) · 알려진 악성 유사도와 LLM 검토 도우미(D6-36) 반영, 1단계 설계 항목 3→5개. M1은 JSON 단일 응답으로 개발 범위를 완료하고 클라이언트 방향 streaming은 제외 (D6-29). 녹색은 코드·테스트 기준이며 외부 실서비스 검증을 뜻하지 않음. 범위 밖 트랙 · 도면 밖 보조 통제는 셈에서 제외.</footer>
<script>{JS}</script></body></html>"""


def edge() -> str:
    for candidate in EDGE_CANDIDATES:
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("Microsoft Edge not found; set MSEDGE to msedge.exe")


def run_edge(args: list[str], profile: str) -> str:
    command = [
        edge(), "--headless=new", "--disable-gpu", "--disable-gpu-sandbox",
        "--disable-software-rasterizer", "--no-sandbox", "--hide-scrollbars", "--no-first-run",
        f"--user-data-dir={profile}", "--virtual-time-budget=3000", *args,
    ]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"Edge exited {result.returncode}: {result.stderr[-3000:]}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", type=Path, help="also keep the generated HTML here")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as work:
        page = Path(work) / "progress_map_v8.html"
        page.write_text(build_html(), encoding="utf-8")
        if args.html:
            args.html.write_text(page.read_text(encoding="utf-8"), encoding="utf-8")
        profile = str(Path(work) / "profile")
        dom = run_edge([f"--window-size={WIDTH},1800", "--dump-dom", page.as_uri()], profile)
        height = int(re.search(r'data-height="(\d+)"', dom).group(1))
        issues = json.loads(html.unescape(re.search(r'data-issues="([^"]*)"', dom).group(1)))
        if issues:
            raise SystemExit("layout issues: " + "; ".join(issues))
        run_edge([
            f"--window-size={WIDTH},{height}", "--force-device-scale-factor=2",
            f"--screenshot={args.output}", page.as_uri(),
        ], profile)
    print(f"wrote {args.output} ({WIDTH * 2}x{height * 2})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
