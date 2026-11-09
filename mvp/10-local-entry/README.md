# 10 Local Entry (L1–L4)

MVP 열 번째 작업 구역입니다. 사용자 컴퓨터에서 도는 로컬(stdio) MCP 서버를 검사 코어 뒤에 두는 0단계 L 경로입니다. 클라우드 게이트웨이(MVP 9)는 원격 서버만 중계할 수 있어서, 로컬 서버는 이 경로가 따로 필요합니다. 두 경로는 같은 검사 코어(`src/mcp_guard`)를 씁니다.

설정은 **비독점**입니다 (D6-10). 사용자는 다른 서버를 자유롭게 추가할 수 있고, 개인 사용자도 그대로 설치해서 씁니다 (D6-11). 보안 메커니즘인 L2 래퍼, L3 재래핑, L4 훅은 그대로 동작합니다.

1단계 관련 자료: [외부 악성 유사도 피드 설정](EXTERNAL_SIMILARITY_FEED.md), [B 점수·유사도·LLM 평가 기록](EVALUATION.md), [B 점수 학습 코드와 결과](b_score/README.md), [인기 패키지 목록 갱신 도구](update_popular_packages.py).

## 구성

| ID | 파일 | 하는 일 |
| --- | --- | --- |
| 사용 분기 | [local_entry/manifest.py](local_entry/manifest.py) | 서버마다 `guard: true/false`를 적는 매니페스트. 원격 서버의 yes/no는 MVP 8 `decide_activation`으로 게이트웨이 URL 또는 원 서버 URL이 됩니다 |
| L1 | [local_entry/client_config.py](local_entry/client_config.py) `render` | 매니페스트에서 Claude Code `.mcp.json`, Claude Desktop 설정, Claude Code 훅 설정을 만듭니다. 서버 허용 목록이나 독점 설정은 만들지 않습니다 |
| L2 | [local_entry/wrapper.py](local_entry/wrapper.py) | stdio 래퍼. 코어를 먼저 불러오고 실패하면 서버를 띄우지 않습니다(종료 코드 78). `tools/list` 응답에서 허용된 도구만 넘기고, 목록에 없는 도구의 `tools/call`은 서버에 보내지 않고 오류로 답합니다. 숨긴 정의는 검토 대기 파일에 적습니다 |
| 1단계 | [STAGE1.md](STAGE1.md) · [src/mcp_guard/stage1.py](../../src/mcp_guard/stage1.py) | 로컬 서버 시작 전에 Registry·패키지 해시 또는 Docker 서명 검증 경로를 검사합니다. 개인 서버는 명시적으로 고정한 로컬 파일 경로를 사용합니다 |
| 1단계 의존성 | `deps` 명령 · [src/mcp_guard/dependencies.py](../../src/mcp_guard/dependencies.py) | npm·PyPI 설치 폴더의 모든 패키지를 공개 배포 파일과 비교하고, OSV 악성 기록·새 릴리스·비슷한 이름·설치 스크립트를 확인해 잠금 파일을 만듭니다(D6-31). 래퍼는 고정된 잠금 파일이 없으면 시작하지 않습니다 |
| 1단계 B | [local_entry/code_scan.py](local_entry/code_scan.py) · `scan` 명령 | 1단계가 고정한 코드(npm·PyPI 설치 폴더, `local`의 고정 파일)를 Semgrep으로 검사합니다(D6-30). 결과는 B 신호라 사람이 수락할 때까지 시작을 보류(`review`)할 뿐 차단하지 않습니다. 기본으로 켜져 있어 래퍼가 보고서를 요구합니다(`code_scan.enabled: false`로 끔) |
| L3 | [local_entry/client_config.py](local_entry/client_config.py) `rewrap` | 설정 파일을 감시해 guard 항목이 풀리면 다시 감쌉니다. 같은 명령을 다른 이름으로 등록한 우회 사본도 감싸고, guard를 선택한 원격 서버를 직접 연결한 항목은 지웁니다 |
| L4 | [local_entry/hook.py](local_entry/hook.py) | Claude Code `PreToolUse`·`PostToolUse` 훅. 아래 두 가지를 판정합니다 |
| 승인 | `approve`·`pending` 명령 | 검토 대기 정의를 승인합니다. 기본은 서비스(관리자)가 승인하고, 매니페스트가 허용하면 사용자도 자기 승인 목록에 승인할 수 있습니다 (D6-18) |

### L4 훅이 판정하는 것

1. **guard 서버의 MCP 호출**: 승인되지 않은 도구는 거부합니다. L2 래퍼를 거치지 않고 도구가 들어온 경우를 막는 두 번째 줄입니다.
2. **오염 세션의 내장 도구** (D6-17): MCP 도구·WebFetch·WebSearch 결과가 들어오면 그 세션을 오염 상태로 표시합니다(`PostToolUse`, M4). 오염된 세션에서는 데이터를 밖으로 보낼 수 있는 내장 도구(기본 Bash·PowerShell·WebFetch)를 거부합니다. 사용자가 매니페스트 `taint_exceptions`에 미리 적은 도구만 Claude Code 승인 창을 띄우고, 승인 창에 입력 원문을 보여줍니다 (D6-07의 3-A4 예외 승인). 오염 표시는 세션 안에서 해제되지 않으므로, 막힌 작업은 새 세션에서 다시 합니다.

오염 상태는 [src/mcp_guard/taint.py](../../src/mcp_guard/taint.py)에 세션마다 파일 하나로 저장합니다(매니페스트 `state_dir`, 기본은 매니페스트 옆 `sessions/`). 설정을 못 읽으면 MCP 호출과 감시 대상 내장 도구를 모두 거부합니다.

래퍼가 막는 서버 측 속임수:
- 대기 중인 `tools/list` id를 재사용한 서버 요청: 응답(`method` 없음)만 목록 응답으로 봅니다
- 요청하지 않은 도구 목록(중복 응답 등): 버립니다
- `notifications/tools/list_changed`: 허용 목록을 비우고, 클라이언트가 다시 목록을 받아 검사할 때까지 호출을 막습니다

## 사용 순서

1. **정책**: `configs/example-policy.json` 형식. 로컬 서버 이름을 `registered_servers`에 넣고, `trusted_sources`에 `local`이 있어야 합니다.
2. **승인 목록**(`approvals`): 처음에는 `{"servers": {}}`로 둡니다. 래퍼가 숨긴 정의는 `pending` 파일에 쌓입니다.
3. **매니페스트**(`guard-manifest.json`): [manifest.py](local_entry/manifest.py) 맨 위 예시 형식. `guard: true` 로컬 서버에는 [1단계 검증 정보](STAGE1.md)를 추가합니다. 기존 `npx -y <패키지>` 예시는 동작 원리 설명용이며 1단계에서 차단됩니다.
4. **1단계 사전 확인**: `python mvp/10-local-entry/mcp_guard_config.py check-stage1 --manifest guard-manifest.json --server <서버 이름>`.
4-0. **의존성 잠금**(npm·PyPI, D6-31): [STAGE1.md](STAGE1.md#의존성-패키지-검사-d6-31)의 순서대로 `deps --manifest guard-manifest.json --server <서버 이름>`을 실행하고, 출력된 `dependency_lock`·`dependency_lock_sha256`을 `stage1`에 넣습니다.
4-2. **LLM 검토 도우미**(선택, 판정 불변, D6-36): 매니페스트에 `review_assist`(OpenAI 호환 주소·모델)를 넣고 `scan ... --explain`으로 보류된 패키지의 요약을 받습니다. [STAGE1.md](STAGE1.md)에 설정 예시가 있습니다.
4-1. **코드 행동 분석**(기본 켜짐, D6-30): `pip install semgrep`(또는 `pip install .[codescan]`)으로 엔진을 설치하고, 필요하면 매니페스트에 `"code_scan": {"semgrep": "<semgrep 실행 파일>"}`로 위치를 적습니다. 끄려면 `"enabled": false`. Docker 서버는 대상이 아닙니다(D6-34). `scan --manifest guard-manifest.json --server <서버 이름>`이 1단계 검사를 다시 통과한 코드만 검사해 `code-scans/<서버>.json` 보고서를 씁니다. 발견 항목이 있으면 래퍼는 서버를 띄우지 않고(`review`), 보고서를 검토한 뒤 `scan ... --accept`로 그 발견 항목을 수락하면 시작합니다. 코드나 규칙이 바뀌면 다시 검사해야 합니다.
5. **설정 만들기**:

   ```powershell
   python mvp/10-local-entry/mcp_guard_config.py render --manifest guard-manifest.json --target claude-code --output .mcp.json
   python mvp/10-local-entry/mcp_guard_config.py render --manifest guard-manifest.json --target claude-code-settings
   python mvp/10-local-entry/mcp_guard_config.py render --manifest guard-manifest.json --target claude-desktop
   ```

   - `.mcp.json`은 프로젝트 또는 사용자 범위에 둡니다. Claude Code `managed-mcp.json`의 독점 배포는 쓰지 않습니다.
   - `claude-code-settings` 출력은 훅만 담고 있어서 `~/.claude/settings.json`의 `hooks`에 합칩니다.
   - Claude Desktop 출력은 `claude_desktop_config.json`의 `mcpServers`에 넣습니다. 원격 서버는 Desktop 설정 파일이 아니라 커넥터(MVP 9 C1)로 연결합니다.
6. **승인**: `pending`으로 대기 정의를 보고, `approve --server files --tool write_file`로 승인합니다. 사용자 승인을 허용하려면 매니페스트에 `"allow_user_approval": true`와 `user_approvals` 경로를 넣고, 사용자는 `approve ... --as-user`를 씁니다. 사용자는 승인된 도구의 위험이 낮은 변경만 승인할 수 있고, 새 도구와 위험한 변경은 관리자만 승인합니다(D6-45). 관리자는 `revoke --manifest ... --server S --tool T`로 사용자 승인을 지웁니다. 사용자 승인은 서비스 승인을 덮어쓰지 못하고, 서버를 다른 네임스페이스에 묶지 못합니다.
7. **감시**(L3): `python mvp/10-local-entry/mcp_guard_config.py rewrap --manifest guard-manifest.json --config <설정 파일> --watch 5`

런처(`mcp_guard_wrap.py`, `mcp_guard_hook.py`, `mcp_guard_config.py`)가 경로를 직접 잡으므로 `PYTHONPATH`가 필요 없습니다.

## OS 격리: 샌드박스 (D6-56, 선택)

매니페스트의 서버 항목에 `sandbox`를 넣으면 래퍼가 1단계 검증을 마친 뒤 서버를 호스트가 아닌 Docker 컨테이너에서 실행합니다([local_entry/sandbox.py](local_entry/sandbox.py)). MCP 메시지는 그대로 래퍼를 거치므로 2·3·4단계 검사는 같습니다.

```json
"sandbox": {"image": "node:22-slim@sha256:<digest>",
            "command": ["node", "/srv/server/index.js"],
            "mounts": [{"source": "C:/mcp/servers/files", "target": "/srv/server"},
                       {"source": "C:/work/shared", "target": "/work", "mode": "rw"}],
            "network": "none", "memory": "512m", "cpus": "1"}
```

- 기본으로 네트워크 없음, 읽기 전용 루트와 작은 `/tmp`, 모든 리눅스 권한 제거, 권한 상승 금지, 프로세스 128개·메모리·CPU 제한, 이름 없는 사용자(65534)로 실행합니다.
- 마운트는 나열한 폴더만, `mode: rw`가 아니면 읽기 전용입니다. 서버 코드 폴더는 1단계가 해시로 고정한 폴더여야 합니다.
- 이미지는 `@sha256:` 다이제스트로 고정하기를 권합니다(감사 기록의 `image_pinned`).
- 컨테이너는 VM이 아니어서 호스트 커널을 함께 씁니다. Docker 자체를 믿어야 하고, 다중 사용자용 강화 샌드박스가 아닙니다.
- 시험: 실제 Docker로 래퍼가 컨테이너 안의 가짜 서버를 띄우고 승인된 도구만 넘기는지 확인합니다(`tests/test_sandbox.py`, Docker가 없으면 건너뜀).

## 신뢰 등급 (D6-54)

정책 파일의 `server_trust`로 서버마다 등급을 줍니다: `trusted_output`(결과에 외부 내용이 없음, 세션을 오염시키지 않음), `standard`(기본), `restricted`(설명문을 항상 대체). 훅은 `trusted_output` 서버의 결과로 세션을 오염시키지 않고, 래퍼는 `restricted` 서버의 설명문을 항상 대체합니다.

## 취약 버전 관리 (D6-56)

의존성 잠금(`deps`)은 OSV의 악성 기록 외에 알려진 취약점(`GHSA-`, `PYSEC-` 등)도 `S1_DEPENDENCY_VULNERABLE`로 기록하고, 업데이트하거나 수락할 때까지 시작을 보류합니다. 승인 뒤 새 취약점이 보고되면 시작할 때 다시 보류하고, 패키지를 올리거나 `deps`를 다시 실행해 수락하라고 안내합니다.

## M1 감사 기록

매니페스트에 `"audit_log": "<경로>.jsonl"`을 넣으면 래퍼·훅·L3·승인 명령이 한 파일에 JSON Lines로 기록합니다(`path: local`). 파일은 월 단위로 돌리고 180일이 지난 달 파일은 지웁니다(D6-24). 단말 로그는 단말에만 남고 어디로도 보내지 않습니다(D6-24). 래퍼 이벤트의 세션은 래퍼 프로세스 하나(`l2:<서버>:<임의값>`)이고, 훅 이벤트에는 Claude Code 세션 ID가 붙습니다(D6-26). 형식과 이벤트 종류는 [architecture.md](../../Docs/Core_mds/architecture.md#m1-감사-기록)에 있습니다. 여러 프로세스가 같은 파일에 쓰므로 한 줄씩 OS 파일 잠금(`<경로>.lock`)을 잡고 씁니다.

| 어디서 | 기록하는 것 |
| --- | --- |
| L2 래퍼 | 1단계 연동 검사, 도구별 목록 판정, 정의 변경(처음 한 번), 호출 허용·차단, 원 서버 결과, 목록 변경 알림, 코어를 못 불러와 서버를 띄우지 않은 경우 |
| L4 훅 | 세션 오염 표시, 오염 세션의 외부 전송 시도(거부·승인 창), 3-A4 승인 요청과 결과, 승인 안 된 MCP 호출 거부 |
| L3 `rewrap` | 바로잡은 설정 항목 하나하나 |
| `approve` | 승인한 정의와 승인 주체(서비스·사용자) |
| `deps` | 의존성 잠금(`dependencies_checked`: 패키지 수, 발견 코드별 개수, 설치 폴더 해시)과 수락(`dependencies_reviewed`) |
| `scan` | 코드 검사 결과(`code_scanned`: 엔진 버전, 규칙 해시, 발견 코드별 개수)와 수락(`code_scan_reviewed`: 승인 주체). 코드 경로와 메시지는 보고서 파일에만 있습니다 |

Claude Code는 승인 창에서 사용자가 무엇을 골랐는지 어떤 훅에도 알려 주지 않습니다(공식 문서 확인). 그래서 승인은 그 도구가 실행됐을 때(`PostToolUse`) 추정으로만 기록하고, 거절은 기록되지 않습니다. 이 추정을 위해 `taint_exceptions`의 도구도 `PostToolUse` 훅 대상에 넣습니다.

## 한계

- 비독점이라 사용자가 guard 서버를 감싸지 않은 채로 다른 설정 파일에 추가하면, L3가 감시하는 파일이 아닌 한 래퍼를 거치지 않습니다. 이때는 L4 훅이 승인되지 않은 도구 호출을 막습니다.
- 로컬 경로의 오염 표시는 Claude Code 세션에서만, 훅이 실행될 때만 됩니다. Claude Desktop 채팅 앱은 훅이 없어 오염 표시와 외부 전송 차단이 **지원 범위 밖**입니다(D6-52). Desktop의 guard 로컬 서버에도 래퍼의 1·2단계 검사는 적용됩니다. 원격 게이트웨이는 자체 오염 표시와 외부 전송 차단이 있습니다([MVP 6](../06-http-gateway-server/README.md#세션-오염과-외부-전송-차단-m4)). MCP 외부 전송 도구는 오염된 Claude Code 세션에서 훅이 호출 직전에 거부합니다(D6-42 정의, `taint_exceptions`에 `mcp__서버__도구`로 넣은 도구는 승인 질문). 래퍼는 어느 세션이 목록을 묻는지 몰라 목록에서 빼지는 못합니다. 직접 연결한 서버는 이 동작이 없습니다. 게이트웨이를 거치는 도구(`mcp__mcp-guard__도구`)도 같은 규칙으로 막습니다(2026-11-04): 게이트웨이는 이 세션이 로컬에서 무엇을 읽었는지 모르기 때문입니다. 판정은 관리자가 로컬 정책에 `mcp-guard:도구`로 표시한 것을 따르고, 표시가 없으면 도구 이름과 호출 입력 이름으로 판단합니다(D6-42 힌트 규칙).
- 기본 설정에서는 MCP 도구를 한 번만 써도 세션이 오염되어 Bash·WebFetch가 막힙니다. 작업 흐름이 자주 끊기면 `taint_sources`를 좁히거나 `taint_exceptions`를 쓰세요.
- 래퍼는 서버 프로세스가 MCP 밖에서 하는 일(파일·네트워크 직접 접근)을 보지 못합니다. 범위 밖 트랙(코드 분석·OS 격리)입니다.
- Semgrep 코드 검사는 Python·JavaScript·TypeScript의 알려진 패턴만 찾습니다. 난독화·동적 `require`·`eval`, 네이티브 모듈(`.node`)·WASM, Docker 이미지 안의 코드는 보지 못합니다. 발견 항목이 없다는 것은 안전하다는 뜻이 아닙니다. 보고서와 수락 기록은 승인 목록처럼 로컬 파일이라, 그 파일을 쓸 수 있는 사람은 수락을 꾸밀 수 있습니다.
- L3는 파일 수정 시각을 주기적으로 확인하는 방식이고, 사용자가 감시 프로세스를 끌 수 있습니다.
- Claude Desktop 설정 형식(`mcpServers`의 `command`·`args`·`env`, `type` 없음, 파일 위치 Windows `%APPDATA%\Claude\claude_desktop_config.json`, 저장 뒤 앱 재시작)은 MCP 공식 문서 [Connect to local MCP servers](https://modelcontextprotocol.io/docs/develop/connect-local-servers)로 확인했습니다(2026-11-04). 같은 문서가 경로는 절대 경로여야 한다고 하므로, Desktop용 `render`는 매니페스트의 정책·승인·대기·감사 파일 경로가 상대 경로면 만들지 않습니다. Claude Code 형식과 훅 입력도 공식 문서로 확인했습니다.
- 실제 Claude Code·Claude Desktop에서 실행해 보지 않았습니다. 테스트는 가짜 stdio 서버와 실제 파이프로 래퍼를 실행합니다.

## 참고 자료

- MCP 2026-07-28 stdio transport: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio
- Claude Code hooks: https://code.claude.com/docs/en/hooks
- Claude Code MCP: https://code.claude.com/docs/en/mcp

## Run

테스트 (저장소 루트): `$env:PYTHONPATH = "src"; python -m unittest tests.test_mvp10_local_entry tests.test_m1_audit`
