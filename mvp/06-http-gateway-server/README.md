# 06 HTTP Gateway Server

MVP 여섯 번째 작업 구역입니다.

목표는 MVP 2의 인메모리 원격 게이트웨이 코어를 실제 HTTP 요청 경계에 붙이는 것입니다. 새 정책 판단을 만들지 않고, 이미 구현된 `S0_GATEWAY_*` 검사와 등록 검사, MVP 5 IP 딜레이 보조 수단을 HTTP 어댑터에서 실행합니다.

## Scope

- 실제 HTTP 요청을 `GatewayRequest`로 변환
- `POST /mcp`를 기존 `RemoteMcpGateway`로 전달
- `OPTIONS /mcp` CORS preflight 응답
- 잘못된 경로, 메서드, content type, 헤더는 MVP 1 WAF 규칙으로 차단
- IP·헤더 키별 요청 횟수를 MVP 5 딜레이 계산에 연결
- 표준 라이브러리 `http.server` 기반 개발용 서버 제공
- 최초 사용 시 관리자가 등록한 서버 신원 정보를 기록하고, 이후 `tools/list`·`tools/call` 전에 기록 및 정책과 대조
- `--live-tools`에서 원 서버 도구 목록을 조회·검사·캐시하고 허용된 호출만 실제 원 서버에 전달
- `--correlation-interval`(기본 300초)마다 지난 `--correlation-lookback`(기본 24시간)의 감사 이벤트에 상관 규칙을 돌려 새 일치를 `correlation_alert`로 기록(D6-25). 재시작하면 로컬 사본에서 조회 범위만큼 다시 읽습니다
- `--audit-log <경로>`에서 M1 감사 이벤트를 JSON Lines로 저장(`path: remote`, 월 단위 회전, `--audit-retention-days` 기본 180). 게이트웨이 판정 이벤트에 로그인 사용자·OAuth 클라이언트를 붙이고, 입구 거부·IP 지연·차단·자격증명 저장소 장애·운영자 서버 승인도 기록. 형식은 [architecture.md](../../Docs/Core_mds/architecture.md#m1-감사-기록)

- 운영 서버 `--server asgi` (D6-28): 표준 라이브러리로 짠 ASGI 앱([http_gateway/asgi.py](http_gateway/asgi.py))을 uvicorn이 띄웁니다. IP 지연은 `asyncio.sleep`으로 기다려 스레드를 붙잡지 않고, 원 서버 호출·Secrets Manager·파일 쓰기는 스레드 풀에서 돌립니다. 본문은 1 MB + 1바이트까지만 읽고 넘치면 입구 규칙이 413으로 거부합니다. uvicorn은 `proxy_headers=False`로 띄워 클라이언트 주소를 바꾸지 않게 하고, 신뢰할 프록시는 `--trusted-proxy`로만 정합니다. `--asgi-keep-alive`(기본 5초), `--asgi-limit-concurrency`(넘으면 503)를 줄 수 있습니다. 개발용 `--server dev`(기본)는 그대로입니다

## Out of Scope

- 기본 정적 데모 모드에서의 실제 upstream MCP 네트워크 호출
- C2 OAuth 중계
- C3 원 서버 토큰 보관
- 사용자 계정·조직 단위 rate limit
- ChatGPT 개발자 모드 강제 방법
- 서버 URL 뒤 원격 운영 주체 인증, 클라이언트의 게이트웨이 경유 강제, 원 서버의 실시간 정의 검증

## Files

| File | Purpose |
| --- | --- |
| `http_gateway/models.py` | HTTP 요청/응답 모델 |
| `http_gateway/adapter.py` | HTTP 요청을 게이트웨이 코어와 IP 딜레이에 연결 |
| `http_gateway/server.py` | 표준 라이브러리 HTTP 서버 |
| `http_gateway/demo.py` | 실행 데모 |
| `DECISIONS.md` | 사용자 검토가 필요한 미확정 방어 방식 |

## Run

From this folder:

```powershell
$env:PYTHONPATH = "../../src;../01-policy-engine-cleanup;../02-remote-gateway-mcp;../03-server-registration-config;../05-indirect-injection-throttle"
python -m http_gateway.demo
```

Development server:

```powershell
# 저장소 루트에서 정적 데모 실행
$env:PYTHONPATH = "src;mvp/01-policy-engine-cleanup;mvp/02-remote-gateway-mcp;mvp/03-server-registration-config;mvp/05-indirect-injection-throttle;mvp/06-http-gateway-server"
python -m http_gateway.server --host 127.0.0.1 --port 8765 --enroll
```

실제 원 서버를 쓰려면 등록 설정의 URL을 변경하고,
[MVP 4 조회 전용 CLI](../04-tools-list-relay/README.md#run)로 각 도구의 설명문과
`inputSchema`의 SHA-256 해시를 검토해 `servers.json` 및 정책 파일에 기록합니다.
샘플의 `sha256:example` 등은 실제 해시가 아니므로 실조회 모드에서 해당
도구는 `review`로 숨겨집니다. 그 뒤 다음과 같이 실행합니다.

```powershell
$env:PYTHONPATH = "src;mvp/01-policy-engine-cleanup;mvp/02-remote-gateway-mcp;mvp/03-server-registration-config;mvp/04-tools-list-relay;mvp/05-indirect-injection-throttle;mvp/06-http-gateway-server;mvp/07-tools-call-upstream-relay"
python -m http_gateway.server --live-tools --enroll
```

이 예시는 인증 없이 도구 호출을 중계하므로, 시작할 때 확인 창이나 터미널에서 실행 여부를 묻습니다(D6-48).

실조회 모드에서는 최초 목록 조회 후 서버의 `ttlMs` 범위 안에서 최대 60초간
공개 목록을 캐시합니다. 비공개 목록은 사용자 인증 맥락을 구분할 수 없어 캐시하지
않습니다. 변경 알림을 받으면 캐시를 폐기하고 다음 목록/호출 시 다시 조회합니다.
`refresh_before_call_tools`에 지정한 도구는 호출 직전에 새 목록을 받습니다.
알림 미지원 서버는 캐시 만료 시 다시 조회하며, 재조회 실패 시 기존 목록으로
호출하지 않습니다. 서버별 목록 장애는 다른 서버의 도구 목록을 막지 않습니다.

첫 실행은 `--enroll`을 붙입니다. 서버가 처음 사용될 때 등록 설정의 이름,
네임스페이스, 전송 방식, URL, 출처를 정책과 비교하고
전용 상태 폴더의 `stage0-approvals.json`에 기록합니다. 기록 파일은 Git에서 제외되며
운영자가 읽기·쓰기 권한을 통제해야 합니다. 다음 실행부터는 `--enroll` 없이
실행합니다. 기록이 사라지면 기본 실행은 중단되고, 새 서버 또는 URL 변경은
명시적으로 다시 승인하기 전까지 차단됩니다.

```powershell
# 서버 등록 설정을 검토한 뒤, 변경된 서버 한 곳만 재승인
python -m http_gateway.server --approve-server company-tools
```

### 세션 오염과 외부 전송 차단 (M4)

원 서버 도구를 호출해 결과가 돌아오면 그 세션을 오염으로 표시합니다(전용 상태 폴더의 `sessions/`,
재시작 후에도 유지). 오염된 세션에서는 데이터를 밖으로 보낼 수 있는 도구(D6-42)를 `tools/list`에서
빼고, 호출해도 원 서버에 보내지 않습니다. 새 세션에서는 다시 쓸 수 있습니다. ChatGPT는 대화마다 세션이 나뉘지만, Claude·Gemini·Codex는 대화 ID를 보내지 않아 세션이 "그 클라이언트의 사용자"라서 새 대화를 열어도 같은 세션입니다. 그래서 로그인한 사용자는 `/approve` 페이지의 **새 세션 시작** 버튼으로 새 세션을 엽니다(`http_gateway/session_epochs.py`, 감사 이벤트 `session_reset`). 이전 세션의 오염 기록은 그대로 남고, 버튼은 로그인한 브라우저와 폼 토큰이 있어야 눌리므로 대화나 도구 결과가 대신 누를 수 없습니다. 게이트웨이는 어느 대화를 이어 쓰는지 모르므로, 페이지와 차단 메시지는 "새 대화를 먼저 연 다음 누르라"고 안내합니다. `--auth oauth`와 `--live-tools`이면 이 페이지가 열립니다. `--auth oauth`에서는
세션이 로그인한 사용자에 묶이고, 인증 없이 실행하면 클라이언트가 보낸 세션 헤더를 씁니다.
이 경우 새 세션 ID로 오염을 피할 수 있어서, 게이트웨이는 시작 전에 멈추고 경고합니다(D6-48).
화면이 있으면 확인 창, 없으면 터미널에서 묻고, 둘 다 없으면(Docker, CI) `--accept-unbound-sessions`를
줘야 시작합니다. 허용한 기록은 `startup_override` 감사 이벤트로 남습니다.
도구 응답에 외부 전송을 유도하는 문구가 있으면 `response_classified` 감사 기록만 남깁니다(B).

### 오염 세션의 예외 승인 (3-A4, D6-49)

`--allow-taint-exceptions`(`--auth oauth`, `--live-tools` 필요)를 켜면, 관리자가 허용한 외부 전송 도구 가운데
사용자가 고른 것은 오염된 세션에서도 호출마다 본인 승인을 받고 쓸 수 있습니다.

```powershell
python -m http_gateway.exceptions allow mail:send_email   # 사용자가 고를 수 있게 허용
python -m http_gateway.exceptions list                    # 허용 목록과 사용자별 지정
python -m http_gateway.exceptions revoke --user alice mail:send_email
```

- 사용자는 `/approve`에 로그인해 허용된 도구를 본인 예외로 지정합니다. MCP 호출로는 바꿀 수 없습니다.
- 오염된 세션에서 예외 도구를 부르면 원 서버에 보내지 않고, 승인 페이지 링크를 담은 오류로 답합니다. 사용자는
  페이지에서 입력 원문을 보고 승인하고, 대화에서 같은 입력으로 다시 요청합니다.
- 승인은 그 사용자·세션·도구·입력 해시에 묶이고, 10분 안에 한 번만 쓰입니다. 링크만으로는 승인되지 않고, 요청을
  만든 사용자로 로그인해야 합니다. 4,000자를 넘는 입력은 다 보여 줄 수 없어 승인 없이 차단합니다.
- 승인 요청은 다른 상태 파일 옆의 권한 제한 파일 `approval-requests.json`에 원문 입력과 함께 저장되어 게이트웨이 재시작 뒤에도 복구됩니다. 만료된 입력은 다음 보호된 도구 호출에서 정리합니다. 승인·거부·만료는 감사 기록에 남습니다. 이 파일은 게이트웨이 한 대 운영용이며 여러 대가 함께 쓰는 저장소는 아닙니다.
- Windows에서는 새 승인 요청 파일을 쓰기 전에 상속 권한을 제거하고 실행 계정 권한만 부여합니다. 기존 파일도 시작 시 상속 권한을 제거하지만, 이미 별도로 부여된 권한은 남으므로 운영자가 확인해야 합니다. 상태 폴더의 쓰기 권한도 제한해야 다른 계정이 파일을 바꾸는 일을 막을 수 있습니다.

#### 전용 상태 폴더

기본 실행도 전용 상태 폴더를 요구합니다. Windows 기본 위치는 실행 계정의
`%LOCALAPPDATA%\mcp-guard\private-state`이고, Linux/macOS 계열은
`$XDG_STATE_HOME/mcp-guard` 또는 `~/.local/state/mcp-guard`입니다.
게이트웨이를 멈춘 상태에서 기존 `.mcp-guard` 밖에 폴더를 준비합니다.

```powershell
python -m http_gateway.state_storage "$env:LOCALAPPDATA\mcp-guard\private-state" --migrate-from .mcp-guard
python -m http_gateway.server [기존 실행 옵션]
```

처음 설치해 이전 상태가 없으면 `--migrate-from .mcp-guard`를 생략합니다. 기존 상태가 있으면 준비 명령으로 이전한 뒤에만 게이트웨이가 시작됩니다. 준비 명령은 폴더에 실행 계정 권한을 설정하고 기존 파일을 복사합니다. 게이트웨이는 기본 실행에서도 폴더와 바로 위 폴더의 권한을 검사하고, 승인·오염·세션·OAuth 상태를 전용 폴더에 둡니다. `--audit-log`를 사용한다면 로그 경로도 전용 폴더 안에 지정해야 합니다. 관리자용 `http_gateway.exceptions`와 `http_gateway.review`도 같은 기본 위치를 사용합니다. 다른 위치를 쓰려면 세 명령에 동일한 `--state-dir`을 전달합니다. 기존 폴더는 자동 삭제하지 않으므로 새 게이트웨이가 정상 동작하는지 확인한 뒤 별도로 정리합니다.

개별 `--approvals`·`--oauth-state`·`--signing-key`·`--upstream-tokens` 경로를 지정할 때도 전용 폴더 안이어야 합니다. 같은 계정으로 실행되는 프로그램은 이 권한 제한으로 막을 수 없습니다.
- 실제 클라이언트·브라우저로는 확인하지 않았습니다.

### 바뀐 도구 정의의 재승인 (D6-45)

`--live-tools`에서 승인된 도구의 정의가 바뀌거나 새 도구가 나타나면 숨기고
전용 상태 폴더의 `pending-definitions.json`에 올립니다. 관리자는 게이트웨이 서버에서 확인하고
승인합니다. 게이트웨이는 다음 요청에서 반영하므로 재시작이 필요 없습니다.

```powershell
python -m http_gateway.review list
python -m http_gateway.review show company-tools:company.search
python -m http_gateway.review approve company-tools:company.search --schema-hash <show가 보여 준 값>
```

`--allow-user-reapproval`(`--auth oauth` 필요)을 켜면 로그인한 사용자가 `/review`에서 위험이
낮은 변경을 본인에게만 수락할 수 있습니다. 관리자는 `acceptances`와 `revoke`로 확인·취소합니다.
설계와 규칙은 [REAPPROVAL.md](REAPPROVAL.md)에 있습니다.

현재 이 기록은 실제 원격 서버의 소유자 증명이나 코드 무결성 검증이 아닙니다.
`tools/list`/`tools/call`의 도구별 정책 검사는 계속 수행됩니다. 변경된 설정
파일을 반영하려면 게이트웨이를 재시작해야 합니다.

