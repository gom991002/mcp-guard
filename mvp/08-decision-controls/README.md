# 08 Decision Controls

MVP 여덟 번째 작업 구역입니다.

목표는 사용자가 확정한 보안 결정을 코드로 반영하는 것입니다.

## Decisions Applied

| Decision | Applied behavior |
| --- | --- |
| C2 OAuth | mcp-guard가 자체 짧은 수명의 게이트웨이 토큰을 발급합니다. 이 발급기를 MVP 9 C2 인가 서버(`cloud_entry/oauth.py`)가 씁니다. 외부 IdP 연동은 하지 않습니다(D6-13). |
| C3 token custody | 보관소 인터페이스(`SecretStore`)만 남깁니다. 실제 보관은 MVP 9의 파일 저장소와 AWS Secrets Manager(D6-19)가 합니다. 초기의 참조 저장 보관소·메모리 보관소·`TokenCustodyService`는 D6-19로 대체되어 삭제했습니다 (2026-11-04). |
| Legacy MCP | 2025-11-25 이전 MCP 방식은 지원하지 않습니다. 기존 `S0_GATEWAY_*` 규칙 유지. |
| ChatGPT/developer mode | 사용자가 mcp-guard 활성화 여부를 yes/no로 결정하는 분기점을 둡니다. |
| A1/A2 strict identity | 초안을 삭제하고 로컬 1단계의 Registry 발행자 허용 목록으로 옮겼습니다 (D6-05, 2026-11-04). 정책 `trusted_registry_publishers`, 코드 `S1_REGISTRY_PUBLISHER_NOT_ALLOWED`. 이름·네임스페이스 대조는 0단계와 1단계가 합니다. |
| M5 description replacement | 코어 `src/mcp_guard/m5.py`로 옮겼습니다(D6-42, D6-43). 이 폴더의 초기 초안 `m5_sanitizer.py`는 삭제했습니다 (2026-11-04). |

## Files

| File | Purpose |
| --- | --- |
| `decision_controls/token_custody.py` | 게이트웨이 토큰 발급·검증, 보관소 인터페이스 |
| `decision_controls/activation.py` | mcp-guard 사용 yes/no 분기 |
| `demo.py` | 실행 데모 |

## Run

```powershell
$env:PYTHONPATH = "../../src"
python -m decision_controls.demo
```

