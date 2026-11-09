# Roadmap

순서는 "사용자가 mcp-guard를 선택한 연결을 검사 코어로 보내고, 그 경로의 정상 연동을 확인한 뒤, 유형별 차단을 더한다"는 선택형 설계를 따릅니다. 직접 연결을 선택하면 원 서버에 그대로 연결하며 mcp-guard의 0~4단계 검사는 적용되지 않습니다 (설계 논의). 모듈 ID는 [architecture.md](architecture.md)에 정의돼 있습니다.

## Phase 1: Repository Scaffold

- [x] 문서 구조, 원본 도면 정리
- [x] 등록 검사 정책 엔진 초안 (2단계 일부)
- [x] CLI 샘플 입력 검사
- [x] 단위 테스트 (allow, review, block 경로)
- [x] `configs/example-policy.json`을 실제로 읽도록 연결, 기본값과 일치 검사
- [x] 코드 표기를 도면에 맞추기: B 신호를 `B_*`·SIGNAL로, 도면 ID가 없는 A 검사를 `S<단계>_*`로
- [x] 해시 승인을 `서버:도구` 단위로 묶기 (M2 바인딩)
- [x] 규칙 계열 초안(rule_sets)을 엔진과 같은 판정 체계로 맞추고 동일성 테스트 추가

## Phase 2: 선택한 보호 경로의 0단계 로컬 진입 + 중계

L1–L4는 사용자가 guard를 활성화한 연결의 경로를 다룹니다. 사용자가 직접 연결을 선택한 항목은 재래핑하거나 차단하지 않습니다 (설계 논의).

구현은 [MVP Folder 10](#mvp-folder-10-로컬-진입-l1l4)에 있습니다.

- [x] L1 클라이언트 설정 생성 (guard를 선택한 항목만 래핑, 직접 연결 항목은 그대로). 비독점 `.mcp.json`으로 배포 (D6-10)
- [x] L2 래퍼: 코어를 먼저 불러오고, 불러오지 못하면 서버를 띄우지 않음 (fail-closed)
- [x] L3 guard를 선택한 항목의 설정 감시와 재래핑 (수정 시각 폴링)
- [x] L4 `mcp__*` 훅 2차 판정
- [x] 로컬 MCP 서버 중계 (stdio 래퍼)
- [x] M1 감사 로그: 공통 필드, 단계별 이벤트, 게이트웨이 보안 이벤트를 JSON Lines로 저장 (원격 `--audit-log`, 로컬 매니페스트 `audit_log`, D6-20)
- [x] M1 판정 모델 버전: 엔진 코드·정책·승인 설정의 내용 해시를 이벤트마다 기록 (D6-21)
- [x] M1 선택형 B 분류기 점수 기록: 2단계 설명문·3단계 응답의 임계값 미만 점수도 기록, 모델 카드 기본 임계값 0.5 적용
- [x] 기록 방식 확정: 해시만, 실패 시 경고 후 계속, 반복되는 allow 목록 판정 생략 (D6-20)
- [x] 원격 감사 로그 저장소: CloudWatch Logs + 로컬 사본 (`--audit-cloudwatch-group`, D6-22)
- [x] 3-A4 거절이 기록되지 않는 한계 수용 (D6-23)
- [ ] CloudWatch Logs 실제 연결·IAM 정책 검증
- [x] 감사 로그 보존 6개월(CloudWatch 180일, 로컬 사본 월 단위 회전), IAM 관리자·열람자 정책 (D6-24)
- [x] 상관 규칙 5분 주기·24시간 조회 범위 실행, `correlation_alert` 경보 (D6-25)
- [x] LLM 클라이언트별 세션(ChatGPT 대화 ID), 로컬 래퍼 프로세스 세션 (D6-26)
- [x] 경보 전달: CloudWatch 대시보드(화면) + 지표 필터·알람·SNS 이메일 설정 파일 (D6-27)
- [ ] CloudWatch 대시보드·지표 필터·알람·SNS 실제 설정 검증
- [x] M1 응답 방식 결정: 업스트림 SSE의 최종 결과를 모아 JSON 단일 응답으로 반환. 클라이언트 방향 스트리밍은 이번 서비스 범위에서 제외 (D6-29)

M1 개발 범위의 중계·감사·저장·경보 구성 코드는 완료했습니다. 실제 클라이언트 연결, CloudWatch Logs/IAM/경보 설정과 운영 동작 검증은 배포 단계의 작업입니다. M1 자체는 3단계 응답 오염 판정이나 4단계 차단을 수행하지 않습니다.

## MVP Folder 2: 원격 `/mcp` 게이트웨이 코어

사용자 흐름상 원격 게이트웨이를 먼저 검증하기 위해 [mvp/02-remote-gateway-mcp](../../mvp/02-remote-gateway-mcp/README.md)에 별도 MVP를 둡니다. 이 폴더는 Phase 6의 앞부분을 당겨 만든 실험 구역입니다.

- [x] `S0_GATEWAY_*` 입구 규칙을 게이트웨이 처리에 연결
- [x] JSON-RPC `tools/list`, `tools/call` 단일 요청 처리
- [x] `tools/list`에서 `allow` 도구만 노출
- [x] 호출 직전 등록 검사 재실행
- [x] M1 감사 이벤트 생성
- [x] 실제 HTTP/ASGI 서버 (MVP 6 `--server asgi`)
- [x] OAuth(C2), 원 서버 토큰 보관(C3): MVP 9

## MVP Folder 3: 실제 MCP 서버 등록 설정

[mvp/03-server-registration-config](../../mvp/03-server-registration-config/README.md)는 게이트웨이가 사용할 실제 MCP 서버 등록 설정을 다룹니다.

- [x] `servers.json` 샘플 형식
- [x] 서버 이름, namespace, transport, URL, source, 도구 목록 로딩
- [x] 서버·도구 이름 중복 검사
- [x] 정책의 `registered_servers`와 정합성 검사
- [x] MVP 2 `GatewayConfig`로 변환
- [x] 조회한 원격 도구 목록의 반영: 자동 승인은 하지 않기로 함(D6-45, 바뀐 정의는 관리자 재승인). 검토용 초안(도구 정의·해시)은 MVP 4 `inspect` CLI가 내고, 바뀐 정의는 `/review`·`http_gateway.review`로 승인 (2026-11-04 정리)
- [x] 토큰·OAuth 참조 관리: MVP 9 `credentials.json`의 `env:`·`file:` 참조

## MVP Folder 4: `tools/list` 중계

[mvp/04-tools-list-relay](../../mvp/04-tools-list-relay/README.md)는 upstream `tools/list` 결과를 받아 등록 검사를 거쳐 LLM에 보여줄 도구만 남기는 흐름입니다.

- [x] upstream `tools/list` 클라이언트 인터페이스
- [x] 정적 클라이언트를 이용한 테스트 가능한 중계
- [x] 도구별 등록 검사 재실행
- [x] `allow` 도구만 노출
- [x] `review`/`block` 도구의 숨김 사유와 감사 이벤트 반환
- [x] 실제 Streamable HTTP `tools/list` 호출 (JSON/SSE 응답, 페이지네이션, `--live-tools`)
- [x] `notifications/tools/list_changed` 수신 시 검증 목록 캐시 무효화 (`--live-tools`)

## MVP Folder 5: IP 요청 횟수 딜레이

[mvp/05-indirect-injection-throttle](../../mvp/05-indirect-injection-throttle/README.md)는 IP, 또는 IP와 헤더를 묶은 키마다 일정 시간 안의 요청 횟수를 세고, 한도를 넘으면 접속 딜레이를 산출합니다. 기간과 횟수의 기본값과 허용 범위는 방화벽·WAF 서비스(AWS WAF, Cloudflare, Cloud Armor, nginx, OWASP CRS)에서 가져왔습니다. 이전의 감마-포아송 신호 집계를 대체합니다.

- [x] 키별 임시 저장소 (창이 지나면 만료, 가득 차면 가장 오래 쓰지 않은 키 제거, 헤더는 digest만 보관)
- [x] 슬라이딩 창 요청 집계 (`per-ip`, `per-client` 규칙 동시 적용)
- [x] 한도 초과 시 딜레이 산출 (상한 있음)
- [x] 기본값 근거와 한계를 README에 명시
- [x] 실제 HTTP 미들웨어 연결 (MVP 6 어댑터)
- [x] 딜레이가 계속 걸리는 키 차단: 10분 안에 5회면 10분 차단, 반복 시 2배, 상한 1시간 (fail2ban·OWASP CRS·Cloud Armor), `429` + `Retry-After`
- [x] 공유 출발지(Anthropic 대역 등)에서는 IP만 보는 규칙 건너뜀
- [x] 여러 인스턴스가 함께 쓰는 저장소: 세션 오염·새 세션 번호를 DynamoDB에 (D6-55, 가짜 DynamoDB로만 시험). 승인 요청·재승인·OAuth 상태·IP 지연 카운터는 인스턴스별이고 고정 세션으로도 묶이지 않아 게이트웨이 1대 운영으로 확정(D6-58)
- [ ] 계정·조직 단위 제한과 결합

## Phase 3: 1·2단계 등록 검사

- 1단계: 로컬 경로의 공식 MCP Registry 서버·버전·패키지 대조, npm·PyPI 배포 파일·설치 내용 해시 고정, Docker MCP Toolkit 서명 검증 명령 강제, 개인 서버 파일 고정 구현. B 코드 행동 분석은 Semgrep CE로 고정 코드를 검사하고 수락 전 시작 보류 (D6-30). 의존성 잠금: 모든 설치 패키지의 배포 파일 대조·OSV 악성 기록·30일 새 릴리스·비슷한 이름·설치 스크립트 검사 (D6-31). 원격 1단계 없음(D6-32), 로컬 승인 파일 위조는 한계 수용(D6-33), Docker 이미지 코드 검사 안 함(D6-34). B 점수: 정답 데이터로 학습 (D6-35). 가져올 때 실행 규칙·매니페스트 메타데이터·GuardDog(선택) 특징을 더해 2,495개로 다시 학습, 판정은 모델 기준값(시험 데이터 재현율 0.70, 정상 보류 10.1%), GuardDog 없을 때는 따로 학습한 모델 (D6-37). 알려진 악성 유사도(근거)와 LLM 검토 도우미(판정 불변) 추가. 로컬 Qwen2.5-Coder 7B로 보류 표본 60개를 평가했으나 정상과 악성을 가리지 못했으며 다른 모델 평가는 남음 (D6-36). 설치 스크립트 산출물·바이트코드 출처 증명·실제 서비스 연동 검증은 남음 (설계 논의)
- 2단계 M2: 이름 형식은 MCP 2026-07-28 Tool Names, 보호 이름과의 UTS #39 skeleton 비교, 다른 서버의 승인된 도구와의 비슷한 이름 비교(구분자·대소문자, 단어 순서, 한 글자 편집)는 구현됨 (D6-38). 한 단어를 붙인 이름은 승인 화면의 근거로만 표시
- 2단계 M3: 정의 해시 고정, 변경 시 재승인 상태로 전환. 구현됨 (D6-45): 바뀐 도구는 숨기고 대기열에 올림, 기본은 관리자 재승인(원격 `python -m http_gateway.review`, 로컬 `approve`), 관리자가 켜면 위험이 낮은 변경만 사용자가 본인에게 수락(원격 `/review` 페이지, 로컬 `--as-user`), 관리자 취소(`revoke`)
- 2단계 M5: 세션 격리, 민감 세션의 설명문 대체. 구현됨 (D6-42, D6-43): 외부 전송 도구는 관리자 지정이 결정하고 미지정 도구는 이름·입력 항목으로 판별, 민감 세션에서 설명문·스키마 안 문장·instructions·프롬프트·리소스 설명 대체(원격은 도구만 중계), 다른 서버 도구를 언급하는 설명문은 검토
- 재연결할 때와 도구 목록 변경 알림을 받을 때 2단계 다시 실행 (로컬: 모든 `tools/list` 응답을 검사하고 변경 알림에 허용 목록을 비움. 원격 `--live-tools`: 캐시 만료·변경 알림·변경 구독 재연결 때 다시 조회)
- B 신호: 코드 행동 분석, 설명문 YARA · LLM (위험도 상향만). 설명문 규칙은 구현됨: MCPTox 오염 설명문 42% 탐지, 정상 0.18% 보류 (D6-39). 설명문 LLM 검사는 구현됨(D6-44, 선택). 구조 신호 추가로 문구 규칙+구조 82.1%, 정상 보류 0.47%(시험 절반, D6-51). 단계식 판정 구현, 분류기·LLM과 묶은 측정은 남음

## Phase 4: 3단계 응답 처리

- M4 출처 태깅과 세션 오염 상태 저장. 로컬(Claude Code 훅)과 원격 게이트웨이는 구현됨: 원 서버 도구 결과가 오면 그 세션을 오염으로 표시하고 파일에 저장(재시작 후에도 유지, `--auth oauth`면 사용자별). Claude Desktop은 남음
- B 분류기 + LLM (위험도 상향만). 응답 문구 규칙 `B_RESPONSE_EXFIL_TEXT`를 원격 게이트웨이와 로컬 래퍼의 도구 응답에 연결(감사 기록만, 오염 표시를 바꾸지 않음)
- 금지 규칙을 테스트로 강제: B가 오염을 해제하거나 승인을 생략하지 못하게 함 (구현: `tests/test_stage4_controls.py` — B는 판정을 낮추거나 혼자 차단하지 않음, 오염 저장소에 해제 기능 없음, 예외 도구는 항상 승인 질문, 재승인은 B 발견을 풀지 않음)

## Phase 5: 4단계 봉쇄

3단계 M4 오염 표시가 먼저 있어야 합니다.

- M4 값 정책: `m4_value_policy`를 설정하면 세션 오염 여부와 관계없이 모든 `tools/call`에서 받는 사람·bcc·URL·공개 설정을 검사한다. 원격은 로그인한 사용자의 승인 페이지, 로컬 stdio는 `local_entry.value_approve` 명령으로 원문을 확인하고 같은 인자 1회만 승인한다. Claude Code 내장 도구는 L4 훅의 승인 질문을 사용한다. 필드 이름 자동 탐지와 관리자 지정 경로를 함께 쓴다. 실제 클라이언트 연동과 도구별 필드 범위 검증은 남음
- M4 오염 세션의 외부 전송 능력 제거: `tools/list` 중계(MVP 4)에서 외부 전송 도구를 빼고, `tools/call` 중계(MVP 7)에서 호출 직전에도 차단. 로컬 Claude Code는 구현됨: L4 훅이 오염 세션에서 외부 전송 MCP 도구(D6-42)를 호출 직전에 거부하고, `taint_exceptions`의 `mcp__서버__도구`는 승인 질문으로 보냄. 래퍼는 어느 세션이 목록을 묻는지 몰라 목록에서는 빼지 못함. 원격 게이트웨이도 구현됨: 오염 세션의 `tools/list`에서 외부 전송 도구를 빼고(`_meta.mcp_guard/withheldInTaintedSession`) 호출 직전에도 차단. 원격 사용자 예외는 승인 페이지에서 호출마다 승인 (D6-49)
- 외부 전송 도구의 정의 (M5 민감 세션과 같은 정의, D6-42로 결정·구현)
- 3-A4 사람 승인: 사용자가 세션 밖 설정에서 미리 지정한 예외 도구에만 요구하고, 승인 화면에 인자 원문 표시. 승인은 인자 해시에 묶고 1회용·만료, 거부·만료는 차단. 원격은 D6-49로 결정: 대화창 승인 카드(MCP Apps, 모델이 볼 수 없는 1회용 승인 코드 필요, 클라이언트별 시험 통과 후 켬)가 기본, 대체는 게이트웨이 승인 페이지(Claude Code는 URL 모드 elicitation, 나머지는 오류 속 링크). 지정·승인자·인증·유효 시간(10분)·큰 인자·기록 방식 포함. 1단계 구현됨 (2026-11-04): 예외 저장소, `/approve` 승인 페이지, 오류 속 링크, `--allow-taint-exceptions`, 관리자 `http_gateway.exceptions`. 링크 승인으로 마무리(같은 날 결정). URL 모드 elicitation과 대화창 카드는 실연동 단계로 미룸
- 승인 피로 지표: 승인까지 걸린 시간, 승인율. 구현됨: `python -m mcp_guard.approval_metrics --audit-log <파일>` — 승인자·도구별 승인율, 결정 시간 중앙값, 2초 미만 비율, 하루 최대 요청 수, 하루 안에서 결정이 빨라지는 추세(습관화 연구 근거). 표시 기준값은 검증되지 않은 시작점
- 최소 권한과 세션 분리: 세션마다 토큰 권한 축소

## Phase 6: 클라우드 경로

구현은 [MVP Folder 9](#mvp-folder-9-클라우드-진입-c1c3)에 있습니다.

- [x] C1 guard를 선택한 조직 커넥터에 게이트웨이 URL을 등록하는 절차 문서 (ChatGPT 개발자 모드·Codex 포함, D6-08)
- [x] 원격 게이트웨이 (로컬 프록시와 같은 코어). 원 서버 구간은 2·3·4단계 (A-02). Docker·HTTPS 배포 구성 (이미지 빌드·실배포 미검증)
- [x] 게이트웨이 입구 규칙(`S0_GATEWAY_*`)을 실제 HTTP 처리에 연결 (MVP 6)
- [x] C2: 게이트웨이 자체 OAuth 2.1 인가 서버 (DCR, PKCE S256, refresh 회전)
- [x] C3: 원 서버 자격증명은 게이트웨이만 보관 (원 서버별 공유 자격증명)
- [x] 사용자별 원 서버 OAuth, CIMD (외부 IdP는 고려하지 않음, D6-13)
- [x] 상태 저장을 사용자별로 분리: 원격 오염 세션·예외·재승인 수락·원 서버 토큰·새 세션 번호가 로그인 사용자별 (2026-11-04 확인). 서버 신뢰 등급은 정책에 (D6-54)

## MVP Folder 6: HTTP 게이트웨이 서버

[mvp/06-http-gateway-server](../../mvp/06-http-gateway-server/README.md)는 MVP 2의 원격 게이트웨이 코어를 실제 HTTP 요청 경계에 연결합니다. 새 방어 결정을 만들지 않고, 미확정 항목은 [DECISIONS.md](../../mvp/06-http-gateway-server/DECISIONS.md)에 검토 대기로 둡니다.

- [x] `POST /mcp` HTTP 요청을 `GatewayRequest`로 변환
- [x] `OPTIONS /mcp` CORS preflight 처리
- [x] `S0_GATEWAY_*` 경계 규칙을 실제 HTTP 응답 코드에 연결
- [x] MVP 5 IP 딜레이 보조 수단을 HTTP 어댑터에 연결
- [x] 표준 라이브러리 개발용 HTTP 서버와 localhost 테스트
- [x] 미확정 방어 방식 검토 목록 작성
- [x] production ASGI 배포 어댑터: 표준 라이브러리 ASGI 앱 + uvicorn (`--server asgi`, D6-28)
- [x] C2 OAuth (MVP 9, `--auth oauth`)
- [x] C3 원 서버 토큰 보관 (MVP 9, `--upstream-credentials`)
- [x] 실제 upstream MCP 호출 (`--live-tools`)
- [x] 신뢰한 리버스 프록시의 `X-Forwarded-For`로 클라이언트 IP 결정 (`--trusted-proxy`)

## MVP Folder 7: `tools/call` 업스트림 릴레이

[mvp/07-tools-call-upstream-relay](../../mvp/07-tools-call-upstream-relay/README.md)는 `tools/call` 직전에 정책 검사를 다시 수행하고, 허용된 도구만 upstream MCP 서버로 전달하는 흐름입니다. OAuth와 토큰 보관은 MVP 6의 결정 대기 항목으로 남겨 둡니다.

- [x] 호출 직전 등록 검사 재실행
- [x] `allow` 도구만 upstream 호출
- [x] `review`/`block` 도구 호출 차단
- [x] 정적 upstream 호출 클라이언트
- [x] HTTP JSON-RPC upstream 호출 클라이언트
- [x] localhost upstream 호출 테스트
- [x] MVP 6 HTTP 서버의 `tools/call` 경로에 직접 결합
- [x] C3 인증 헤더 주입 (MVP 9 `header_provider`; 클라이언트 토큰은 넘기지 않음)
- [x] 응답 방식 확정: 업스트림 JSON/SSE의 최종 결과를 JSON으로 반환하고 클라이언트 방향 스트리밍은 제외 (M1, D6-29)

## MVP Folder 8: 결정 반영 컨트롤

[mvp/08-decision-controls](../../mvp/08-decision-controls/README.md)는 사용자가 확정한 보안 결정을 코드로 반영합니다.

- [x] 게이트웨이 토큰 발급·검증 모델
- [x] 외부 secret manager/KMS 참조형 토큰 보관 모델
- [x] 테스트용 메모리 토큰 보관소
- [x] mcp-guard 활성화 yes/no 분기
- [x] 구버전 MCP 미지원 결정을 문서화
- [x] A1/A2식 strict identity 검사
- [x] 민감 세션에서 도구·프롬프트·리소스 설명문 대체
- [x] 게이트웨이 자체 OAuth 인가 서버에서 토큰 발급 (MVP 9, audience 포함)
- [x] ~~외부 OAuth provider(IdP) 연동~~: 하지 않음 (D6-13, 게이트웨이 사용자 목록 유지; 2026-11-04 로드맵 정리)
- [x] 실제 cloud secret manager 연동: MVP 9 `per_user` 토큰을 AWS Secrets Manager에 보관 (SDK 없이 SigV4, D6-19). 실제 AWS 호출은 미검증
- [x] strict identity 정리 (2026-11-04, D6-05): 초안 삭제, 로컬 1단계에 Registry 발행자 허용 목록(`trusted_registry_publishers`)만 추가
- [x] M5를 엔진(`src/mcp_guard/m5.py`)에 두고 로컬 `tools/list`·`prompts/list`·`resources/list`·`initialize`와 원격 `tools/list`에 결합 (D6-43)

## MVP Folder 9: 클라우드 진입 (C1–C3)

[mvp/09-cloud-entry](../../mvp/09-cloud-entry/README.md)는 원격 게이트웨이를 `https://<도메인>/mcp`로 배포하고 OAuth로 보호합니다.

- [x] Protected Resource Metadata, 인가 서버 메타데이터, DCR, 인가 코드 + PKCE S256, refresh 회전, `iss`
- [x] 토큰 없는 `/mcp`에 `401` + `WWW-Authenticate` (resource_metadata, scope)
- [x] 토큰 audience 검증 (RFC 8707)
- [x] 원 서버 자격증명 참조(`env:`·`file:`)와 헤더 주입, 비밀값 없으면 호출 실패 (fail-closed)
- [x] 인증 없이 공개 주소로 열리지 않음
- [x] Dockerfile, Caddy(HTTPS), compose
- [x] C1 커넥터 등록 절차 (claude.ai 조직·개인, Claude Code)
- [x] Docker 이미지 빌드와 로컬 실행: `deploy/demo` compose와 `smoke.py` 19단계 통과 (D6-57, 2026-11-04)
- [ ] 실제 클라우드 배포, claude.ai·ChatGPT·Codex 실제 연결 검증
- [x] CIMD (claude.ai·claude.com 문서만)
- [x] 서버별 원 서버 인증 방식: `shared` 또는 `per_user` (사용자별 원 서버 OAuth, 로그인 때 연결, `403` step-up)
- [x] `per_user` 토큰을 AWS Secrets Manager에 보관 (`--upstream-token-store aws-secrets-manager`, D6-19)
- [ ] AWS Secrets Manager 실제 연결·IAM 정책 검증
- [x] ChatGPT 개발자 모드·Codex: 콜백과 `chatgpt.com` CIMD 허용, 등록 절차 (D6-08)
- [x] Gemini Enterprise: 사전 등록 confidential 클라이언트(`admin add-client`), 등록 절차. Gemini CLI: DCR·loopback (D6-26)
- [ ] Gemini Enterprise·Gemini CLI 실제 연결 검증
- [x] ChatGPT 요청 대역(`chatgpt-connectors.json`)을 공유 출발지로 자동 반영 (2026-11-04, `--shared-egress-feed chatgpt`, 하루 한 번, 실패 시 마지막 정상 목록 유지). 공유 출발지 예외는 로그인한 `/mcp` 요청에만. Claude는 문서의 두 대역을 고정 반영, Gemini는 공개 목록 없음. 실제 배포에서 받기는 미검증
- 외부 IdP·조직 고객은 고려하지 않음 (D6-13)

## MVP Folder 10: 로컬 진입 (L1–L4)

[mvp/10-local-entry](../../mvp/10-local-entry/README.md)는 로컬 stdio 서버를 같은 검사 코어 뒤에 둡니다.

- [x] guard yes/no 매니페스트, 원격 항목은 MVP 8 `decide_activation`으로 분기
- [x] L1 `.mcp.json`·Claude Desktop 설정·Claude Code 훅 설정 생성 (허용 목록·독점 배포는 D6-10으로 제거)
- [x] L2 stdio 래퍼 (fail-closed, `tools/list` 필터, 목록 밖 `tools/call` 차단, `list_changed` 재검사, 검토 대기 정의 기록)
- [x] L3 설정 감시와 재래핑, 우회 사본 처리
- [x] L4 Claude Code `PreToolUse` 훅
- [x] L4 오염 세션 판정: `PostToolUse`로 세션 오염 표시, 오염 세션에서 Bash·PowerShell·WebFetch 거부, 사용자 지정 예외만 승인 창 (D6-17)
- [x] 비독점 설정: 허용 목록·독점 배포 없음, 보안 메커니즘은 유지 (D6-10)
- [x] 로컬 도구 승인: 서비스(관리자)가 승인, 매니페스트가 허용하면 사용자도 승인 (D6-18)
- [ ] 실제 Claude Code·Claude Desktop에서 실행 검증
- [x] Claude Desktop 설정 형식 확인 (MCP 공식 문서, 2026-11-04; 절대 경로 요구를 `render`에 반영)

## Phase 7: 평가

- A 계층을 끄고 켰을 때 비교하는 유형별 평가 세트
- 적응형 공격 평가: 단계별 차단 효과 측정 (현재 미확인)
- 승인 품질 측정: 승인 피로 지표 실측

## 별도 트랙: 범위 밖

검사 코어가 아닌 별도 대응이라 위 단계와 병행합니다.

- 로컬 서버 패키지 코드 분석
- 패치 관리: 남의 서버 코드는 고치지 않고, 알려진 취약 버전은 업데이트·수락 전까지 시작 보류 (D6-56, `S1_DEPENDENCY_VULNERABLE`)
- OS 격리: 포트폴리오 범위로 선택형 Docker 샌드박스 구현 (D6-56, `local_entry/sandbox.py`, 실제 Docker로 시험). VM 수준 격리는 범위 밖

## 결정 대기

다음 항목은 결정해야 해당 단계의 범위가 정해집니다. 자세한 내용은 [threat-model.md](threat-model.md#open-questions)에 있습니다.

- 외부 전송 도구의 정의: D6-42로 결정됨.
- M1: 선택형 B 분류기의 점수 형식은 결정·구현됨. 다른 모델을 붙이면 해당 모델의 임계값은 별도 확인.
