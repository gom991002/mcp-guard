# 03 Server Registration Config

MVP 세 번째 작업 구역입니다.

목표는 실제 MCP 서버를 mcp-guard에 등록하는 설정 형식을 만들고, 그 설정을 원격 게이트웨이 코어가 사용할 수 있는 `GatewayConfig`로 변환하는 것입니다.

## Scope

- `servers.json` 형식 정의
- 서버 이름, namespace, endpoint URL, transport, 도구 목록 로딩
- 서버 이름과 도구 이름 중복 검사. 도구 이름은 LLM에 평평한 목록으로 노출되므로, enabled 서버 전체에서 중복되면 fail-closed로 봅니다.
- 정책 파일의 `registered_servers`와 등록 설정의 정합성 검사
- MVP 2 `GatewayConfig`로 변환

## Out of Scope

- 실제 원격 MCP 서버 접속
- OAuth 토큰 저장
- 서버별 비밀값 관리
- 관리 웹 UI

## Files

| File | Purpose |
| --- | --- |
| `configs/servers.json` | 샘플 MCP 서버 등록 설정 |
| `server_registry/models.py` | 등록 설정 모델 |
| `server_registry/loader.py` | JSON 로더와 `GatewayConfig` 변환 |
| `server_registry/validation.py` | 정합성 검사 |
| `server_registry/demo.py` | 실행 데모 |

## Run

From this folder:

```powershell
$env:PYTHONPATH = "../../src;../02-remote-gateway-mcp"
python -m server_registry.demo
```

