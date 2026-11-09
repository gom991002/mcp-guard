# 04 Tools List Relay

MVP 네 번째 작업 구역입니다.

M2 도구 이름 검사 평가 코드와 결과는 [m2_names/README.md](m2_names/README.md)에 있습니다.

목표는 원격 게이트웨이가 upstream MCP 서버의 `tools/list`를 실제로 조회하는 클라이언트를 만드는 것입니다. 조회한 도구의 검사와 노출 여부는 게이트웨이 코어(MVP 2 `RemoteMcpGateway`)가 정합니다. 처음에 있던 별도 중계 클래스(`ToolsListRelay`)는 등록 검사만 하고 0단계 입구·M3 재승인·M4·M5를 건너뛰어, 게이트웨이 코어로 대체하고 삭제했습니다 (2026-11-04).

## Scope

- 실제 Streamable HTTP `tools/list` 클라이언트: JSON/SSE 응답, 페이지네이션, 응답 크기 제한
- `subscriptions/listen`의 목록 변경 알림 수신과 게이트웨이 캐시 무효화
- 운영자가 실제 정의를 읽는 조회 전용 CLI(`inspect`)

## Out of Scope

- 도구 검사와 노출 결정 (MVP 2 게이트웨이 코어)
- 원 서버 자격증명 (MVP 9 C3가 `header_provider`로 넣음)
- 오래 열린 스트림의 운영용 재연결 관리

## Files

| File | Purpose |
| --- | --- |
| `tools_list_relay/client.py` | 실제 HTTP 목록 조회, 변경 알림 수신 |
| `tools_list_relay/inspect.py` | 운영자가 실제 설명문·스키마·해시를 읽고 승인 설정을 준비하는 조회 전용 CLI |

## Run

검사를 거친 목록 노출은 [MVP 6 데모](../06-http-gateway-server/README.md#run)에서 봅니다. 실제 서버의 정의를 검토하려면 저장소 루트에서 실행합니다. 이 명령은 승인 기록을
쓰지 않으며 결과를 자동 승인하지 않습니다.

```powershell
$env:PYTHONPATH = "src;mvp/01-policy-engine-cleanup;mvp/02-remote-gateway-mcp;mvp/03-server-registration-config;mvp/04-tools-list-relay"
python -m tools_list_relay.inspect --server company-tools
```

출력의 `tools`는 검토 후 `servers.json`에, `approved_schema_hashes`는 정책에
반영합니다. 등록 URL이 예시 주소라면 먼저 실제 서버 URL로 바꿔야 합니다.

