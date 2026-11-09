# 02 Remote Gateway MCP

MVP 두 번째 작업 구역입니다.

목표는 상용 LLM에 등록할 원격 `/mcp` 게이트웨이의 최소 흐름을 코드로 잡는 것입니다. 실제 네트워크 서버를 띄우지는 않고, HTTP 요청을 나타내는 객체를 받아 검사하고 JSON-RPC 응답을 돌려주는 게이트웨이 코어를 만듭니다.

## Scope

- `S0_GATEWAY_*` 입구 규칙 연결
- JSON-RPC 단일 요청 처리
- `tools/list`에서 등록 검사를 통과한 도구만 노출
- `tools/call`에서 호출 직전 등록 검사를 다시 수행
- 선택적으로 실제 원 서버의 검증된 도구 목록을 사용하고 TTL/알림 무효화 캐시를 공유
- M1 감사 이벤트 생성

## Out of Scope

- 실제 HTTP/ASGI 서버
- 코어 자체의 네트워크 I/O (실제 조회·호출 클라이언트는 MVP 4/7에 있으며 MVP 6의 `--live-tools`에서 연결)
- OAuth 중계(C2)
- 원 서버 토큰 보관(C3)
- 4단계 M4 값 정책 (M4 세션 오염 표시와 외부 전송 도구 제거는 `gateway.py`에 구현됨, 원격 3-A4 예외 승인은 D6-49)

## Files

| File | Purpose |
| --- | --- |
| `gateway_mvp/models.py` | Gateway config, upstream server, tool definition, response models |
| `gateway_mvp/jsonrpc.py` | JSON-RPC parsing and response helpers |
| `gateway_mvp/catalog.py` | Sample upstream catalog for demos and tests |
| `gateway_mvp/gateway.py` | Remote gateway core |
| `gateway_mvp/live_catalog.py` | 실제 목록의 bounded TTL 캐시와 변경 무효화 |
| `gateway_mvp/demo.py` | Runnable demo |

## Run

From this folder:

```powershell
$env:PYTHONPATH = "../../src;../01-policy-engine-cleanup"
python -m gateway_mvp.demo
```

From repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests
```

## Design Notes

- The gateway uses the rule drafts in `mvp/01-policy-engine-cleanup/rule_sets/waf_gateway_rules.py`.
- B signals can raise a decision to `review`, but they never create a `block` by themselves.
- `review` tools are not exposed in `tools/list` and cannot be called in this MVP.

