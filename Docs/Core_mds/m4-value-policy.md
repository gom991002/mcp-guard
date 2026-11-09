# M4 값 정책

관리자는 게이트웨이의 `--policy` 파일과 로컬 매니페스트의 `policy` 파일에 아래 항목을 넣습니다. 도메인과 호스트는 실제 조직 값으로 바꿔야 합니다. 이 항목이 있으면 세션 오염 여부와 관계없이 모든 도구 호출에서 검사합니다. 없으면 기존 동작을 유지합니다.

```json
{
  "m4_value_policy": {
    "internal_domains": ["company.example"],
    "allowed_url_hosts": ["hooks.company.example"],
    "tool_fields": {
      "files:publish": {"visibility": ["share.level"]}
    }
  }
}
```

`internal_domains`는 이메일 받는 사람의 도메인을 정확히 대조합니다. `allowed_url_hosts`는 HTTP(S) URL의 호스트를 정확히 대조합니다. 자동 탐지는 중첩된 입력의 `to`, `cc`, `bcc`, `recipient`, `url`, `webhook`, `visibility`, `access`, `sharing`, `public` 같은 키를 봅니다. `tool_fields`는 `서버:도구`별 JSON 경로를 `recipient`, `bcc`, `url`, `visibility` 종류로 추가합니다. 누락되거나 해석할 수 없는 지정 목적지도 승인 대상으로 잡습니다. 도구가 다른 이름이나 본문 문자열에 목적지를 숨기면 자동 탐지만으로는 잡지 못하므로 해당 도구의 필드를 지정해야 합니다.

원격: `--auth oauth --live-tools --public-url`로 실행해야 값 정책의 사용자 승인이 가능합니다. 위험한 입력은 `/approve`에서 로그인한 사용자가 원문을 확인할 때까지 보내지 않으며, 승인 후 같은 인자로 재시도해야 합니다. 승인은 해당 사용자·세션·도구·인자 해시에 묶이고 한 번만 사용됩니다. 오염 세션의 외부 전송은 지정된 3-A4 예외 도구가 아니면 값 승인과 무관하게 차단됩니다.

로컬 stdio: 래퍼가 호출을 보류하고 요청 ID를 돌려줍니다. 터미널에서 다음 명령으로 전체 입력을 보고 승인한 뒤 같은 입력을 재시도합니다.

```powershell
$env:PYTHONPATH = "src;mvp/01-policy-engine-cleanup;mvp/10-local-entry"
python -m local_entry.value_approve --manifest <매니페스트 경로> list
python -m local_entry.value_approve --manifest <매니페스트 경로> approve <요청 ID>
```

로컬 승인도 같은 서버·도구·인자에 한 번만 적용되고 10분 뒤 만료됩니다. Claude Code의 내장 도구는 L4 훅 승인 질문을 사용합니다. 직접 연결한 MCP 서버와 Claude Desktop의 대화 세션 오염 추적은 범위 밖입니다. 값 정책은 mcp-guard 래퍼를 쓰는 Desktop 서버의 호출에도 적용되지만, 그 승인은 터미널 명령으로 합니다.
