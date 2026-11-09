# 07 Tools Call Upstream Relay

MVP 일곱 번째 작업 구역입니다.

목표는 허용된 `tools/call`을 upstream MCP 서버로 전달하는 HTTP 클라이언트를 만드는 것입니다. 호출 직전 정책 재검사, M4 세션 오염, 외부 전송 차단은 게이트웨이 코어(MVP 2 `RemoteMcpGateway`)가 하고, 원 서버 자격증명은 MVP 9 C3가 `header_provider`로 넣습니다. 처음에 있던 별도 중계 클래스(`ToolsCallRelay`)는 등록 검사만 하고 나머지 통제를 건너뛰어, 게이트웨이 코어로 대체하고 삭제했습니다 (2026-11-04).

## Scope

- HTTP JSON-RPC `tools/call` 클라이언트 (JSON·SSE 응답, 리디렉션 거부)

## Out of Scope

- 클라이언트 방향 streaming 응답과 중간 진행 알림 전달 (M1 D6-29에서 JSON 단일 응답으로 결정하여 의도적으로 제외)
- retry/backoff 정책

## Files

| File | Purpose |
| --- | --- |
| `tools_call_relay/client.py` | upstream HTTP 호출 클라이언트 |

## Run

검사를 거친 호출 중계는 [MVP 6](../06-http-gateway-server/README.md#run)의 `--live-tools`에서 실행합니다. 클라이언트 테스트: `$env:PYTHONPATH = "src"; python -m unittest tests.test_mvp07_tools_call_relay`
