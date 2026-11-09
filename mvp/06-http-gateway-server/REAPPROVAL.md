# M3 재승인 흐름 설계 (D6-45)

승인된 도구의 정의(입력 스키마 해시나 설명문)가 바뀌었을 때 다시 쓰게 하는 절차입니다. 바뀐 정의를 감지해 숨기는 부분(M3)은 이미 구현돼 있고, 이 문서는 그다음을 다룹니다. 상태: **구현됨 (2026-11-03).** 엔진 `src/mcp_guard/reapproval.py`, 원격 `gateway_mvp/reapproval_store.py`·`http_gateway/review.py`·`http_gateway/review_page.py`, 로컬 `local_entry` (`approve --as-user` 제한, 알림, `revoke`). 테스트 `tests/test_reapproval.py`. 실제 클라이언트·브라우저로는 검증하지 않았습니다.

## 원칙

1. **기본은 관리자 재승인입니다.** 바뀐 도구는 관리자가 다시 승인할 때까지 숨깁니다. 업계에서 흔한 방식이고(API7 AI Gateway의 검토 대기 상태 등, 설계 논의), 사람 한 명의 승인에 방어를 걸지 않는다는 D6-07과도 맞습니다.
2. **사용자 수락은 관리자가 켤 때만 됩니다.** 원격은 `--allow-user-reapproval`, 로컬은 기존 `allow_user_approval`을 씁니다. 둘 다 기본은 꺼짐입니다.
3. **사용자 수락은 본인에게만, 그 정의에만 적용됩니다.** 서버 단위 승인(D6-41)과 다른 사용자는 그대로입니다. 정의가 다시 바뀌면 다시 묻습니다. 만료는 없습니다.
4. **위험한 변경은 사용자가 수락할 수 없습니다.** 아래 "관리자 전용 변경"에 해당하면 사용자 수락이 켜져 있어도 관리자에게 갑니다.
5. **관리자는 사용자 수락을 보고 취소할 수 있습니다.**
6. **이 흐름은 판정을 완화하지 않습니다.** 수락은 M3 변경 하나만 풀고, 다른 A·B 발견이 있으면 그 판정이 그대로 남습니다.

## 관리자 전용 변경

다음 중 하나라도 해당하면 사용자 수락 대상이 아닙니다.

| 조건 | 판단 근거 |
| --- | --- |
| 승인된 설정에 없는 새 도구 | `S2_UNAPPROVED_TOOL` |
| 이름 흉내·보호 이름 | `M2_*` 발견 |
| 설명문 신호 | `B_DESCRIPTION_*`, `B_SUSPICIOUS_DESCRIPTION`, `B_DESCRIPTION_LLM_SIGNAL`, `B_PROMPT_INJECTION_SIGNAL` |
| 다른 서버 도구 언급 | `M5_DESCRIPTION_NAMES_OTHER_SERVER_TOOL` |
| 외부 전송 능력이 새로 생김 | 이전 정의는 `is_external_send`가 거짓, 새 정의는 참 (D6-42) |
| 그 밖의 A 발견 | M3 변경 코드(`M3_SCHEMA_HASH_CHANGED`, `M3_DESCRIPTION_CHANGED`)가 아닌 review·block 발견 |

나머지(입력 항목이 바뀌었지만 위 조건에 해당하지 않는 변경, 설명문만 바뀌었고 신호가 없는 변경)는 사용자 수락이 켜져 있으면 사용자가 판단할 수 있습니다.

## 저장하는 것

검토된 설정 파일(`servers.json`, 정책)은 고치지 않습니다. 승인 기록은 따로 둡니다. 설정 파일은 사람이 검토한 원본으로 남기고, 재승인 기록은 감사할 수 있게 하기 위해서입니다.

| 파일 (원격 기본 위치 `.mcp-guard/`) | 내용 | 누가 씀 |
| --- | --- | --- |
| `pending-definitions.json` | `server:tool`마다 관찰된 정의(해시, 설명문, 입력 스키마), 처음 본 시각, 변경 요약, 분류(사용자 가능 / 관리자 전용)와 그 이유, `per_user` 서버라면 그 정의를 받은 사용자 | 게이트웨이 |
| `definition-approvals.json` | 관리자가 다시 승인한 정의: `server:tool` → 해시, 설명문 SHA-256, 승인자, 시각 | 관리자 명령 |
| `user-acceptances.json` | 사용자 수락: 사용자 → `server:tool` → 해시, 설명문 SHA-256, 시각 | 게이트웨이(확인 페이지) |

- **승인 정의를 정하는 순서:** 관리자 재승인 기록이 있으면 그것, 없으면 `servers.json`입니다. 그 사용자의 수락 기록은 해시와 설명문이 모두 같고 분류가 "사용자 가능"일 때만 씁니다.
- **반영 시점:** 게이트웨이는 요청마다 두 승인 파일의 수정 시각을 확인하고, 바뀌었으면 다시 읽습니다. 재시작이 필요 없습니다.
- **쓰는 방식:** 파일은 임시 파일에 쓴 뒤 교체(원자적 교체)하고, 소유자만 읽고 쓰게 둡니다. 로컬의 pending 파일과 같은 방식입니다.

## 흐름

```text
바뀐 정의 감지 (M3, 구현됨)
  └─ 도구 숨김 + pending-definitions.json 기록 + definition_changed 감사 이벤트
       ├─ 관리자 전용 변경, 또는 사용자 수락 꺼짐
       │    └─ 호출 시 오류: "관리자 재승인 대기"
       │         └─ 관리자: review list / show / approve / reject
       └─ 사용자 가능 변경, 그리고 사용자 수락 켜짐
            └─ 호출 시 오류: "도구가 바뀌었습니다. 확인: <public_url>/review"
                 └─ 사용자: 확인 페이지에서 수락 → 본인 세션에서만 다시 보임
                      └─ 관리자: review acceptances / revoke 로 사후 확인·취소
```

## 사용자에게 알리는 방법

- **`tools/list`:** 숨긴 도구 이름을 `_meta["mcp_guard/pendingReview"]`에 넣습니다. 설명문은 넣지 않습니다.
- **`tools/call`:** 숨긴 도구를 부르면 JSON-RPC 오류로 답합니다. 메시지에는 도구 이름, 대기 이유(관리자 대기 / 사용자 확인 가능), 확인 주소만 넣습니다. 서버가 쓴 문장은 넣지 않습니다. 오류 메시지는 모델에게도 보이기 때문입니다.
- **MCP elicitation(클라이언트가 사용자에게 직접 묻는 기능):** 쓰지 않습니다. 지원하는 클라이언트가 많아지면 다시 검토합니다(D6-45).

## 원격 확인 페이지 (`/review`, 사용자 수락이 켜졌을 때만)

- **로그인:** 기존 게이트웨이 사용자 파일(PBKDF2)로 로그인합니다. 세션 쿠키는 `HttpOnly`, `Secure`, `SameSite=Strict`, 15분 유효입니다. 수락 버튼은 CSRF 토큰을 확인합니다.
- **보이는 항목:** 그 사용자에게 해당하는 변경만 보입니다.
  - `per_user` 서버: 그 사용자가 받은 목록에서 생긴 변경
  - `shared` 서버: 그 서버의 변경 전부
- **보여 주는 내용:** 가드가 정리한 변경 요약을 먼저 보여 줍니다.
  - 추가·삭제된 입력 항목, 형식이 바뀐 입력 항목
  - 외부 전송 판단과 그 이유
  - 설명문 길이 변화와 걸린 규칙
  - 새 설명문 원문은 맨 아래 경계 상자 안에 500자까지만, 글자 그대로(HTML 이스케이프) 보여 줍니다. 링크로 만들지 않습니다.
- **페이지 보안:** `Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'`. 페이지에 스크립트가 없습니다.
- **관리자 전용 변경:** 목록에는 보이지만 수락 버튼이 없고, "관리자 재승인이 필요합니다"와 그 이유를 표시합니다.

## 관리자 명령 (게이트웨이 서버에서)

```text
python -m http_gateway.review list                      # 대기 중인 변경과 분류
python -m http_gateway.review show SERVER:TOOL          # 변경 요약과 새 정의 원문
python -m http_gateway.review approve SERVER:TOOL --schema-hash HASH [--external-send yes|no]
python -m http_gateway.review reject SERVER:TOOL        # 대기열에서 지움, 도구는 계속 숨김
python -m http_gateway.review acceptances [--user U]    # 사용자 수락 목록
python -m http_gateway.review revoke --user U SERVER:TOOL
```

- `approve`는 `show`가 보여 준 해시를 `--schema-hash`로 받아, 그사이 정의가 또 바뀌었으면 거부합니다.
- 관리자 재승인도 M3 변경·미승인 발견만 풉니다. B 신호 같은 다른 발견이 있으면 도구는 여전히 숨겨집니다.
- 원격 대기열과 재승인 기록은 `--live-tools`일 때 켜집니다. `--allow-user-reapproval`은 `--auth oauth`와 `--live-tools`가 필요합니다.
- `--external-send`는 D6-42의 관리자 지정을 같이 기록합니다.

## 로컬 경로와 맞출 것

로컬에는 대기 파일, `approve` 명령, 사용자 승인(`--as-user`, `allow_user_approval`)이 이미 있습니다. 바꿀 것은 다음과 같습니다.

1. `approve --as-user`도 위 "관리자 전용 변경" 규칙을 따릅니다. 분류 기록이 없는 대기 정의(이전 버전이 쓴 것)도 관리자 전용으로 봅니다. D6-18의 사용자 승인 범위가 좁아집니다: 사용자는 새 도구를 승인할 수 없습니다.
2. 숨긴 도구를 부르면, 바뀐 도구인 경우 "도구가 바뀌었습니다. 확인: `mcp-guard pending`, 승인: `approve --as-user`"를 알립니다. 지금은 "허용되지 않은 도구"라고만 답합니다.
3. `revoke --server S --tool T` 명령으로 관리자가 사용자 승인 파일에서 항목을 지웁니다. 로컬 사용자 승인 파일은 한 사람 것이라 `--user`가 없습니다.
4. 로컬 사용자 승인은 기존대로 `definition_approved`(approver `user`)로 기록하고, 취소는 `acceptance_revoked`로 기록합니다.

## 감사 기록 (M1)

| 이벤트 | 언제 |
| --- | --- |
| `definition_changed` | 변경 감지 (있음) |
| `definition_approved` | 관리자 재승인 (로컬에 있음, 원격에 추가) |
| `definition_rejected` | 관리자 거부 (추가) |
| `definition_accepted` | 사용자 수락: 사용자, 해시, 분류 (추가) |
| `acceptance_revoked` | 관리자 취소 (추가) |

새 이벤트 유형은 D6-20의 공통 필드를 따르고, 설명문 원문 대신 SHA-256을 남깁니다.

## 구현 순서 (제안)

1. 엔진: 변경 분류 함수(사용자 가능 / 관리자 전용 + 이유)와 변경 요약 함수. 원격·로컬 공통입니다.
2. 원격: 대기 파일 기록, 관리자 재승인 기록 적용(파일 다시 읽기), 관리자 명령, 호출 오류 메시지.
3. 로컬: `--as-user` 제한, 알림 메시지, `revoke`.
4. 원격 `/review` 페이지와 사용자 수락. 기본 꺼짐이라 마지막에 합니다.

## 남는 위험

- 사용자 수락을 켜면, 공격 대상인 사용자가 판단합니다. 관리자 전용 규칙은 알려진 신호가 있는 변경만 거릅니다. 신호 없이 문장을 바꾼 오염은 사용자 판단에 맡겨집니다.
- 해시는 정의만 고정합니다. 정의는 그대로 두고 서버 쪽 동작만 바꾸는 경우는 이 흐름으로 잡지 못합니다. 3·4단계(M4)가 맡습니다.
- 확인 페이지는 게이트웨이의 공격면을 넓힙니다. 그래서 기본 꺼짐으로 두고, 로그인·CSRF·CSP를 둡니다.
