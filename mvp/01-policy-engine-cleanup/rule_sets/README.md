# Rule Sets

mcp-guard 정책 규칙의 MVP 설계 구역입니다.

- **판정 엔진은 `src/mcp_guard`**입니다. 이 폴더는 규칙 계열별 초안이고, 판정 체계(`Verdict`, `RuleAction`, `Severity`)와 감사 이벤트(`AuditEvent`)는 엔진의 것을 그대로 가져다 씁니다.
- 표기 규칙(`marker`, `stage`, 코드 접두어)과 모듈 정의는 [Docs/Core_mds/architecture.md](../../../Docs/Core_mds/architecture.md)를 따릅니다. 문서끼리 다르면 도면 A-01·A-02를 따릅니다.

## 규칙 계열과 도면 대응

| 파일 | 계열 | marker | stage | 하는 일 |
| --- | --- | --- | --- | --- |
| `opa_decision_rules.py` | OPA 형식 판정 | M2, M3, A | 0, 2 | 등록 정보와 실조회 정의의 A 결정을 모델링합니다. 엔진 검사와 ID·marker·stage·action의 대응을 테스트합니다. B 신호를 함께 넣으면 판정을 `review`까지만 올립니다. |
| `yara_text_rules.py` | YARA 형식 텍스트 | B | 2, 3 | 설명문(2단계 "설명문 YARA · LLM")과 응답(3단계 "분류기 + LLM")에서 의심 문구를 찾습니다. SIGNAL만 냅니다. 규칙 정의는 엔진의 `src/mcp_guard/text_rules.py`에서 가져오고(D6-39), 엔진은 2단계 규칙을 설명문 검사에 씁니다. |
| `semgrep_static_rules.py` | Semgrep 정적 분석 | B | 1 | 1단계 "코드 행동 분석"용 Python·JavaScript·TypeScript 코드 패턴입니다(프로세스 실행, 네트워크, 비밀 파일 읽기, 인코딩 풀어 실행, 동적 실행, 환경 변수 수집). SIGNAL만 냅니다. MVP 10 [`code_scan.py`](../../10-local-entry/local_entry/code_scan.py)가 Semgrep CE에 이 규칙만 넘겨 실행하고(D6-30), 결과는 패키지별 B 점수로 묶입니다(D6-35). 특정 공격자 문자열 규칙은 넣지 않습니다. |
| `sigma_correlation_rules.py` | Sigma 형식 상관 | M1 | audit | 감사 기록에서 의심스러운 순서를 찾아 사후 경보를 냅니다. 오염 규칙은 mcp-guard 세션(`session_id`) 단위로, 서버를 가리지 않고 봅니다. |
| `waf_gateway_rules.py` | WAF 형식 게이트웨이 | A | 0 | 원격 게이트웨이 `/mcp` 입구 검사입니다. 기준은 MCP Streamable HTTP 2026-07-28입니다. 도면에는 없습니다. |

코드 접두어: 도면 ID가 있으면 그 ID(`M2_`, `M3_`, `M1_`), 신호는 `B_`, 도면 ID가 없는 A 결정은 `S<단계>_`입니다.

## 실행 순서 (엔진에 연결할 때)

1. HTTP 요청이 오면 게이트웨이 입구 규칙 (C 경로, 0단계)
2. 등록 정보에 텍스트 규칙(B) 실행
3. 판정 규칙(A)에 B 신호를 넣어 최종 판정
4. 감사 이벤트 기록 (M1)
5. 감사 기록에 상관 규칙 실행 (M1)

아직 없는 것:

- 3단계 M4 출처 태깅·세션 오염 표시(출처 기준 A 결정)
- 4단계 M4 값 정책과 3-A4 승인
- npm 패키지용 정적 규칙

## Downstream Use

[mvp/02-remote-gateway-mcp](../../02-remote-gateway-mcp/README.md)는 이 폴더의 `waf_gateway_rules.py`를 가져와 원격 `/mcp` 게이트웨이 코어에서 사용합니다. 코어는 `GatewayRequest` 객체를 입력으로 받고, 개발용 실제 HTTP 서버는 MVP 6에 있습니다.

## 실행

저장소 루트에서:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests
```

데모는 이 폴더의 상위(`mvp/01-policy-engine-cleanup`)에서 실행합니다:

```powershell
$env:PYTHONPATH = "../../src"
python -m rule_sets.demo
```

## 게이트웨이 규칙의 기준

MCP 2026-07-28 Streamable HTTP 기준으로 다음을 차단합니다.

- POST(와 CORS 사전 요청 OPTIONS) 외의 메서드. GET 스트림과 DELETE 세션 종료는 이 버전에서 없어졌습니다.
- `/mcp`가 아닌 경로
- `application/json`이 아닌 POST 요청
- 허용 목록에 없는 `Origin`
- 배치 요청과 클라이언트가 보낸 응답
- `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` 헤더가 없거나 본문과 다른 요청. `Mcp-Name`이 위조되면 라우팅과 실행이 서로 다른 도구를 보게 되므로 M2와 관련이 있습니다.

2025-11-25 이전 클라이언트는 이 규칙에서 차단됩니다. 이들을 지원할지는 결정 대기입니다 ([threat-model.md](../../../Docs/Core_mds/threat-model.md#open-questions)).
