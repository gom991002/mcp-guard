# 2단계 B 설명문 규칙 평가 (D6-39)

[eval_text_rules.py](eval_text_rules.py)는 엔진의 설명문 규칙(`src/mcp_guard/text_rules.py`)과 기본 정책 문구 목록을 평가합니다.

- **악성:** [MCPTox](https://arxiv.org/abs/2508.14925)(AAAI 2026)의 오염된 도구 설명문 1,348개(실제 MCP 서버 45곳). 라이선스 표기가 없어 내려받은 사본으로 평가만 하고 이 저장소에는 넣지 않습니다.
- **정상:** MCPTox에 들어 있는 같은 서버들의 원래 설명문 362개, Docker MCP 카탈로그(MIT)의 실제 설명문 755개.
- **기준(실행 전에 정함):** 규칙마다 정상 보류 1% 이하, 채택한 규칙 합계 2% 이하. 탐지율은 공격 틀(Template-1·2·3)별로도 봅니다.

| | 정상 보류 | 탐지율 | Template-1 | Template-2 | Template-3 |
| --- | --- | --- | --- | --- | --- |
| 이전 규칙 (정책 무력화·비밀 수집 + 정책 문구) | 0.09% | 5.8% | 7.1% | 7.9% | 3.6% |
| **+ 숨은·다른 도구 지시 (미리 정한 결과)** | **0.18%** | **42.1%** | 48.8% | 42.8% | 39.3% |
| 위 + 관사 버그 수정 (사후, 참고용) | 0.18% | 50.5% | 53.6% | 49.1% | 50.7% |

- 결과 파일: [report_preregistered.json](report_preregistered.json), [report_after_fix.json](report_after_fix.json)
- 정상 보류 2건은 성능 분석 예시 문장(`Performix`)과 DNS 확인 설명(`Okta`)이었습니다.
- 위험 유형 중 자격증명 유출은 77%를 잡지만, 코드 주입·메시지 가로채기는 35% 안팎입니다.
- 오염 설명문의 절반은 문구 규칙으로 잡히지 않습니다. 남은 것은 B 설명문 LLM 검사로 다룰 과제입니다.

```text
python mvp/11-b-classifier/b_text/eval_text_rules.py --mcptox <response_all.json> --docker <mcp-registry>/servers
```

## 구조 신호와 단계식 판정 (D6-51, 2026-11-04)

[eval_structure.py](eval_structure.py)는 문구 규칙에 구조 신호([src/mcp_guard/structure_signals.py](../../../src/mcp_guard/structure_signals.py))를 더해 평가합니다. 구조 신호는 설명문이 **같은 서버의 다른 도구를 어떻게 부르라고 지시하는지**를 봅니다.

| 신호 | 보는 것 |
| --- | --- |
| `B_DESCRIPTION_CROSS_TOOL_DIRECTIVE` | 다른 도구 이름 바로 앞에 호출 동사가 있고 가까이에 강한 지시(must, always, first 등)가 있음. "instead of X", "deprecated" 같은 선호 표현은 제외 |
| `B_DESCRIPTION_ARGUMENT_TAMPERING` | 다른 호출의 입력을 바꾸라는 지시 ("modify the 'path' argument", "replace query with") |
| `B_DESCRIPTION_PRIORITY_CLAIM` | 사용자나 시스템보다 우선한다는 주장 |

- **나눠서 평가:** 서버 이름의 SHA-256이 짝수면 개발, 홀수면 시험입니다(MCPTox 서버 18/27곳, 공격 504/844개). 신호는 개발 절반만 보고 만들었고, 시험 절반은 설계를 고정한 뒤 한 번 돌렸습니다.
- **기준(D6-39와 같음, 미리 정함):** 신호마다 정상 보류 1% 이하, 모두 합쳐 2% 이하.

| | 개발 탐지 | 개발 정상 보류 | **시험 탐지** | **시험 정상 보류** |
| --- | --- | --- | --- | --- |
| 문구 규칙만 | 54.2% | 0.14% (1/695) | 48.3% | 0.24% (1/422) |
| 구조 신호만 | 90.1% | 0.43% (3/695) | 70.1% | 0.24% (1/422) |
| **문구 규칙 + 구조 신호** | 93.9% | 0.58% (4/695) | **82.1%** | **0.47% (2/422)** |

- 시험의 공격 방식별 탐지: Template-1 83.0%, Template-2 81.0%, Template-3 82.6%.
- 개발(93.9%)과 시험(82.1%)의 차이 약 12%p는 개발 절반에 맞춘 과적합으로 봅니다. 다른 도구 지시 신호가 개발 84% → 시험 59%로 가장 많이 떨어졌습니다.
- 다른 도구 이름은 그 서버의 승인된 도구 목록에서 가져옵니다(M5 다른 서버 도구 검사와 같은 출처). 승인 목록에 없는 도구 이름은 보지 못합니다.
- 결과 파일: [report_structure_dev.json](report_structure_dev.json), [report_structure_test.json](report_structure_test.json). 예시 문장은 Docker 카탈로그(MIT)만 남깁니다.
- 2026-11-04에 다시 받은 데이터로 기존 문구 규칙을 재현하면 탐지 50.5%, 정상 보류 0.18%로, 사후 수정 뒤 기록(`report_after_fix.json`)과 같습니다.

**단계식 판정 (구현, 측정 대기):** 정책은 다른 B 신호가 이미 잡은 설명문을 LLM에 보내지 않고, 분류기와 `--description-llm-floor`를 함께 쓰면 그 값보다 점수가 낮은 설명문도 보내지 않습니다. 기준값과 하한은 `eval_structure.py --classifier --llm-url ... --llm-model ...`로 개발 절반에서 고르고 시험 절반으로 보고합니다. 이 PC에서는 분류기(onnxruntime)와 로컬 LLM을 실행할 수 없어 아직 측정하지 못했습니다.

