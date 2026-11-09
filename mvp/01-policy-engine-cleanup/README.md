# 01 Policy Engine Cleanup

MVP 첫 작업 구역입니다.

목표는 판정 엔진을 문서의 방어 모델(도면 A-01·A-02 기준)과 맞추는 것입니다. `allow`, `review`, `block` 판정 기준을 분리하고, `configs/example-policy.json`을 실제 정책 입력으로 연결합니다.

## Scope

- M2: 보호 대상 도구 이름과 신뢰 네임스페이스 검사, 해시 승인을 `서버:도구` 단위로 묶기, 빈 이름 입력 차단
- M3: 스키마 해시 유무와 승인 후 변경 감지
- B: 설명문 의심 문구는 신호(`B_*`, SIGNAL)로만 다룹니다. 판정을 `review`로 올릴 수는 있지만 차단은 하지 않습니다. 이 규칙은 정책 설정으로 바꿀 수 없습니다.
- 0단계 코어 쪽 허용 목록: 등록되지 않은 서버와 신뢰하지 않는 등록 출처를 차단(`S0_*`)
- JSON 정책 로딩, 코드 기본값과 일치
- allow, review, block 경로 테스트

M5(세션 격리·설명문 대체)는 이 작업 구역의 범위가 아닙니다.

## Target Files

- `src/mcp_guard/policy.py`
- `src/mcp_guard/registry.py`
- `src/mcp_guard/models.py`
- `src/mcp_guard/audit.py`
- `configs/example-policy.json`
- `tests/test_policy.py`, `tests/test_rule_sets.py`
- `mvp/01-policy-engine-cleanup/rule_sets/`

## Rule Set Drafts

[rule_sets/](rule_sets/README.md)에는 규칙 계열마다 첫 초안이 있습니다.

| 계열 | 도면상 위치 |
| --- | --- |
| YARA 형식 텍스트 규칙 | B 신호 (2단계 설명문, 3단계 응답) |
| OPA 형식 판정 규칙 | A 결정. 엔진(`src/mcp_guard/policy.py`)의 검사와 같은 ID |
| Sigma 형식 상관 규칙 | M1 감사 기록의 확장 |
| Semgrep 형식 정적 규칙 | 1단계 B 코드 행동 분석 |
| WAF 형식 게이트웨이 규칙 | C 경로 게이트웨이 입구 (도면에 없음) |

## Done When

- [x] 엔진이 설정 파일에서 정책을 읽습니다.
- [x] 판정 규칙이 명시돼 있고 테스트로 확인됩니다.
- [x] `python -m unittest discover -s tests`가 통과합니다 (`PYTHONPATH=src`).
