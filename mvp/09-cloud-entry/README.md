# 09 Cloud Entry (C1–C3)

MVP 아홉 번째 작업 구역입니다. 원격 게이트웨이를 `https://<도메인>/mcp` 주소로 배포하고, 클라우드 클라이언트(claude.ai·Claude Desktop·모바일·Cowork, ChatGPT 개발자 모드, Gemini Enterprise, Claude Code·Codex·Gemini CLI의 HTTP 연결)가 그 주소로만 들어오게 하는 0단계 C 경로를 만듭니다. 구성은 **프록시 코드 → Docker 컨테이너 → 클라우드 서버 → HTTPS MCP 주소**입니다.

AI 모델은 사용자가 쓰던 클라이언트에 그대로 있고, 이 서버는 MCP 중계와 검사만 합니다. 검사 코어는 로컬 경로(MVP 10)와 같습니다.

## 구성

| ID | 위치 | 구현 |
| --- | --- | --- |
| C1 | 조직 관리 콘솔 | 아래 [커넥터 등록 절차](#c1-커넥터-등록-절차). 코드가 아니라 관리자 절차입니다. MVP 10은 서버 허용 목록을 만들지 않습니다(D6-10, 비독점) |
| C2 | 원격 게이트웨이 | [cloud_entry/oauth.py](cloud_entry/oauth.py): 게이트웨이가 직접 OAuth 2.1 인가 서버 역할을 합니다. 토큰은 MVP 8 게이트웨이 토큰(D6-02 결정)이고, 이 서버(`<도메인>/mcp`)에만 쓰이도록 audience를 묶습니다 |
| C3 | 원격 게이트웨이 | [cloud_entry/upstream_credentials.py](cloud_entry/upstream_credentials.py), [cloud_entry/upstream_oauth.py](cloud_entry/upstream_oauth.py): 원 서버 자격증명은 게이트웨이만 갖습니다. 서버마다 방식을 고릅니다 (D6-12): `shared`(게이트웨이가 가진 자격증명 하나, `env:`·`file:` 참조)와 `per_user`(사용자마다 자기 원 서버 계정을 OAuth로 연결). 개인 데이터를 다루는 서버는 `per_user`로 둡니다. 클라이언트 토큰은 원 서버로 넘기지 않습니다 |

### C2가 지원하는 것

Claude·ChatGPT·Codex의 커넥터 인증 요구사항과 MCP 2026-07-28 인가 규격에 맞춘 최소 구성입니다.

- 토큰 없는 `/mcp` 요청에 `401`과 `WWW-Authenticate: Bearer resource_metadata="…", scope="mcp"` 응답
- Protected Resource Metadata(RFC 9728): `/.well-known/oauth-protected-resource`와 `/.well-known/oauth-protected-resource/mcp`
- 인가 서버 메타데이터(RFC 8414): `/.well-known/oauth-authorization-server`
- Client ID Metadata Document(CIMD, D6-14): `claude.ai`·`claude.com`·`chatgpt.com`(ChatGPT·Codex)에 있는 문서만 받습니다(SSRF 방지). 문서의 `client_id`가 URL과 같아야 하고, redirect URI는 문서에 있으면서 아래 허용 목록에도 있어야 합니다. 문서가 토큰 엔드포인트 인증 방식으로 `none`을 지원해야 합니다: `token_endpoint_auth_methods_supported`가 있으면 그 목록에 `none`이 있어야 하고, 없으면 `token_endpoint_auth_method`가 `none`이어야 합니다(ChatGPT는 `private_key_jwt`를 선호값으로 적지만 목록에 `none`도 있습니다). 로그인 화면에는 문서의 이름이 아니라 URL의 호스트를 보여 줍니다(ChatGPT와 Codex는 둘 다 `chatgpt.com`). 문서는 `Cache-Control max-age`를 따라 1분~1일 캐시합니다
- 사전 등록 클라이언트(D6-26): DCR·CIMD를 쓰지 못하는 클라이언트(Gemini Enterprise)를 관리자가 `cloud_entry.admin add-client`로 등록합니다. secret은 해시로만 저장하고, 토큰 엔드포인트에서 `client_secret_basic`·`client_secret_post`로 확인합니다. PKCE는 이 클라이언트에도 필수입니다
- Dynamic Client Registration(RFC 7591): 공개 클라이언트만. redirect URI는 Claude 콜백(`https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`), ChatGPT 콜백(고정 `https://chatgpt.com/connector_platform_oauth_redirect`, 서버별 `https://chatgpt.com/connector/oauth/<callback_id>`), Claude Code·Codex의 loopback(`http://localhost`·`http://127.0.0.1`, 포트 무관), `--redirect-uri`로 추가한 주소만 허용
- 인가 코드 + PKCE S256 필수, 코드는 60초·1회용, `iss` 응답 파라미터(RFC 9207)
- refresh token 회전(쓴 토큰은 즉시 폐기), 상태 파일에는 refresh token의 해시만 저장
- 로그인 화면: 관리자가 등록한 사용자(PBKDF2-SHA256 비밀번호 해시). 서명된 요청값으로 변조를 막고, 프레임 삽입을 금지합니다
- 사용자별 IP 딜레이: 토큰이 `authorization` 헤더에 실리므로 MVP 5의 `per-client` 규칙이 사용자마다 따로 셉니다

사용자 신원은 게이트웨이의 사용자 목록으로 유지합니다 (D6-13). 외부 IdP(SSO)와 조직 고객은 고려하지 않습니다. 토큰 수명(access 1시간, refresh 30일)은 그대로 둡니다 (D6-15).

### C3 사용자별 원 서버 연결 (`per_user`)

게이트웨이가 원 서버의 OAuth 클라이언트가 됩니다.

1. 사용자가 게이트웨이에 로그인하면, 아직 연결하지 않은 `per_user` 원 서버의 인가 화면으로 차례로 이어집니다. 모두 연결해야 Claude로 돌아갑니다. 하나라도 실패하면 로그인이 끝나지 않습니다(fail-closed).
2. 원 서버 인가 서버는 원 서버의 Protected Resource Metadata로 찾고(RFC 9728), RFC 8414 또는 OpenID 메타데이터를 읽습니다. 클라이언트 등록은 MCP 순서를 따릅니다: 미리 등록한 클라이언트(`client_id`, `client_secret_ref`) → 게이트웨이 자체 CIMD(`/oauth/client-metadata.json`) → DCR.
3. 인가 요청에는 S256 PKCE와 `resource`(원 서버 URL)를 넣고, 응답의 `iss`를 확인합니다(RFC 9207). 콜백은 `/upstream/callback`입니다.
4. 원 서버 토큰은 (게이트웨이 사용자, 서버)마다 저장하고(기본은 `--upstream-tokens` 파일, 운영은 아래 [AWS Secrets Manager](#per_user-토큰-보관-aws-secrets-manager)), 만료 1분 전부터 refresh합니다. refresh가 실패하면 연결을 지웁니다.
5. 연결이 없거나 풀린 사용자가 `tools/list`나 그 서버의 `tools/call`을 부르면 게이트웨이가 `403 insufficient_scope`(scope `mcp upstream:<서버>`)로 답합니다. Claude는 이 응답을 받으면 다시 인가를 받고 같은 호출을 재시도합니다. 그 인가에서 1번이 다시 실행됩니다.
6. 사용자별 목록은 원 서버가 public으로 표시해도 다른 사용자와 나눠 쓰지 않습니다(`PerUserListClient`).

원 서버 인가 서버 주소는 HTTPS이면서 공인 주소여야 합니다(사설·loopback 주소 거부, SSRF 방지).

### per_user 토큰 보관: AWS Secrets Manager

`--upstream-token-store aws-secrets-manager`로 켭니다 (D6-19). [cloud_entry/aws_secrets.py](cloud_entry/aws_secrets.py)가 MVP 8의 `SecretStore`(`put`·`get`)를 AWS Secrets Manager로 구현하고, [cloud_entry/upstream_oauth.py](cloud_entry/upstream_oauth.py)의 `SecretManagerTokenStore`가 그 위에서 토큰을 관리합니다. SDK 없이 표준 라이브러리로 SigV4 서명을 만들어 JSON API를 부릅니다.

- 비밀 하나에 항목 하나: `<prefix>/token/<해시>`(사용자·서버별), `<prefix>/client/<해시>`(원 서버 DCR 등록). 이름은 해시라 사용자 이름이 드러나지 않습니다. prefix는 `--aws-secret-prefix`(기본 `mcp-guard/upstream`)
- refresh token이 있으면 access token은 저장하지 않고 메모리에만 둡니다. 재시작하면 처음 쓸 때 refresh합니다
- 같은 비밀에는 10분에 한 번까지만 씁니다. AWS가 비밀 하나에 PutSecretValue를 10분에 한 번보다 자주 부르지 말라고 하기 때문입니다(24시간 안에 만든 버전은 모두 보관해 버전 한도에 걸림). 그 사이의 새 값은 메모리에서 기다렸다가 간격이 지난 뒤 첫 요청이나 종료 시 씁니다. 그 전에 프로세스가 죽으면 저장된 refresh token이 이미 회전돼 무효일 수 있고, 그 사용자는 원 서버를 다시 연결합니다
- 연결을 지울 때는 비밀을 삭제하지 않고 `{}`로 덮어씁니다. 삭제한 비밀 이름은 복구 기간 동안 다시 만들 수 없기 때문입니다
- 읽기·쓰기에 실패하면 원 서버를 부르지 않습니다(fail-closed). `/mcp`는 `503 upstream_credentials_unavailable`, 로그인은 `503` 화면으로 답하고, 실패한 쓰기는 다음 요청 때 다시 시도합니다
- 새 비밀은 기본 `aws/secretsmanager` 키로 암호화되고, `--aws-kms-key-id`로 고객 관리 키를 지정할 수 있습니다
- 자격증명: `AWS_ACCESS_KEY_ID`·`AWS_SECRET_ACCESS_KEY`(·`AWS_SESSION_TOKEN`) 환경변수, 없으면 EC2 인스턴스 역할(IMDSv2, 만료 5분 전 갱신). Region은 `--aws-region` 또는 `AWS_REGION`

필요한 IAM 권한 예시입니다(실제 AWS에서 확인하지 않음). 고객 관리 KMS 키를 쓰면 그 키의 `kms:GenerateDataKey`·`kms:Decrypt`도 필요합니다.

```json
{"Effect": "Allow",
 "Action": ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:CreateSecret"],
 "Resource": "arn:aws:secretsmanager:<region>:<account>:secret:mcp-guard/upstream/*"}
```

## 배포

`deploy/`에 Dockerfile, Caddy(HTTPS 자동 인증서), compose 파일이 있습니다.

1. 클라우드 서버에 도메인(`mcp.example.com`)을 연결하고 80·443 포트를 엽니다.
2. `deploy/config/`에 실제 설정을 둡니다. 이 폴더의 `*.json`은 git에 올라가지 않습니다(`*.example.json` 제외).
   - `policy.json`, `servers.json`: 저장소의 `configs/example-policy.json`, `mvp/03-server-registration-config/configs/servers.json` 형식
   - `credentials.json`: `credentials.example.json` 형식. 비밀값 자체는 `deploy/.env`에 둡니다(`.env.example` 참고)
   - `users.json`: 아래 명령으로 만듭니다
3. 사용자 등록 (저장소 루트에서):

   ```powershell
   $env:PYTHONPATH = "src;mvp/08-decision-controls;mvp/09-cloud-entry"
   python -m cloud_entry.admin add-user --users mvp/09-cloud-entry/deploy/config/users.json alice
   ```

4. 원 서버 승인(0단계 승인 기록). 서버마다 한 번:

   ```powershell
   cd mvp/09-cloud-entry/deploy
   $env:MCP_GUARD_DOMAIN = "mcp.example.com"
   docker compose run --rm gateway --policy=/config/policy.json --servers=/config/servers.json --state-dir=/data/state --approve-server=company-tools
   ```

5. 실행: `docker compose up -d`. MCP 주소는 `https://mcp.example.com/mcp`입니다.

### 로컬 Docker 데모 (D6-57)

[deploy/demo/](deploy/demo/)는 포트폴리오용 시연입니다. 실제 배포에 쓰지 않습니다(포트는 127.0.0.1에만 열리고, 데모 비밀번호가 평문으로 들어 있습니다).

```powershell
cd mvp/09-cloud-entry/deploy/demo
docker compose up -d --build
python smoke.py
docker compose down -v
```

| 서비스 | 하는 일 |
| --- | --- |
| `gateway` (127.0.0.1:8080) | 로그인 없는 게이트웨이. 세션은 `mcp-guard-session-id` 헤더 |
| `gateway-oauth` (127.0.0.1:8081) | OAuth 2.1 로그인 게이트웨이(사용자 `demo`), `/approve` 승인 페이지, M4 값 정책 |
| `upstream-open`, `upstream-oauth` | 데모 원 서버(메일·문서). 0단계는 loopback이 아니면 HTTPS만 받으므로, 각 게이트웨이와 네트워크를 함께 써서 127.0.0.1로 연결합니다 |

`smoke.py`는 MCP 클라이언트처럼 DCR·PKCE·로그인·토큰 교환을 거친 뒤 19단계를 확인합니다: 승인된 도구 노출, 독이 든 설명문 보류(B 구조 신호), 민감 세션 설명문 대체(M5), 메일 속 지시 뒤 오염과 외부 전송 차단(M4), 외부 받는 사람·숨은 참조(M4 값 정책)와 `/approve`의 1회 승인, 새 세션 시작. 2026-11-04에 모두 통과했습니다. 설정은 `deploy/demo/make_config.py`가 데모 원 서버의 도구 정의에서 만듭니다.

### 여러 게이트웨이 (D6-55)

게이트웨이를 부하 분산 뒤에 여러 대 두면 `--state-backend dynamodb --dynamodb-table mcp-guard-state`로 세션 오염 기록과 새 세션 번호를 DynamoDB 표 하나에서 함께 씁니다. 표는 문자열 파티션 키 `pk` 하나로 만들고, IAM은 [deploy/iam/gateway-instance-role.json](deploy/iam/gateway-instance-role.json)의 `SharedSessionState`입니다. 표를 읽지 못하면 그 세션을 오염으로 보고 외부 전송을 막습니다. 가짜 DynamoDB로만 시험했습니다. 다만 승인 요청, 재승인, OAuth 상태(인가 코드·리프레시 토큰), IP 지연 카운터는 게이트웨이마다 따로이고, 로그인 코드와 승인은 브라우저와 클라이언트 서버가 따로 요청하므로 고정 세션으로도 묶을 수 없습니다. 그래서 **게이트웨이는 1대로 운영합니다(D6-58).** 여러 대 동시 운영은 범위 밖입니다.

### AWS 호스팅 (D6-22)

호스팅은 AWS입니다. EC2 한 대에서 이 compose(게이트웨이 + Caddy HTTPS)를 돌리고, AWS 서비스 두 개를 씁니다.

| 무엇 | 어디에 | 켜는 방법 (`deploy/.env`) |
| --- | --- | --- |
| `per_user` 원 서버 토큰 | AWS Secrets Manager | `MCP_GUARD_TOKEN_STORE=aws-secrets-manager` |
| M1 감사 로그 | CloudWatch Logs가 기본 저장소, `/data/state/audit.jsonl`은 장애 대비 사본 | `MCP_GUARD_AUDIT_LOG_GROUP=/mcp-guard/audit` |

1. **EC2 인스턴스 역할**: 액세스 키를 `.env`에 넣지 말고 인스턴스 역할을 씁니다. 컨테이너 안에서 IMDSv2에 닿으려면 인스턴스 메타데이터의 hop limit을 2 이상으로 올려야 할 수 있습니다 (미확인).
2. **로그 그룹 만들기 (보존 6개월, D6-24)**: 게이트웨이는 로그 스트림만 만듭니다. 배포 담당자가 로그 그룹을 만들고 보존 기간을 **180일**(CloudWatch가 받는 값 중 6개월에 해당)로 한 번 설정하고 삭제 방지를 켭니다. 예: `aws logs create-log-group --log-group-name /mcp-guard/audit`, `aws logs put-retention-policy --log-group-name /mcp-guard/audit --retention-in-days 180` (CLI 명령 형식은 확인하지 않음). 로컬 사본은 게이트웨이가 월 단위로 돌리고 180일이 지난 달 파일을 지웁니다(`--audit-retention-days`, 기본 180).
3. **`AWS_REGION`**을 `.env`에 넣습니다. Secrets Manager와 CloudWatch Logs가 같은 리전을 씁니다.
4. **IAM (D6-24)**: [deploy/iam/](deploy/iam/)의 정책을 씁니다(실제 AWS에서 확인하지 않음).

| 정책 | 누구 | 할 수 있는 것 |
| --- | --- | --- |
| [gateway-instance-role.json](deploy/iam/gateway-instance-role.json) | 게이트웨이 EC2 인스턴스 역할 | `per_user` 토큰 읽기·쓰기, 감사 이벤트 쓰기만 |
| [audit-admin.json](deploy/iam/audit-admin.json) | 관리자 | 감사 로그 열람·검색, 경보(지표 필터·알람) 관리 |
| [audit-reader.json](deploy/iam/audit-reader.json) | 사용자(열람자) | 감사 로그 열람·검색만 |

  두 열람 정책 모두 로그 그룹·스트림 삭제, 보존 기간 변경, 이벤트 쓰기를 명시적으로 거부합니다. CloudWatch는 로그 그룹 단위로 권한을 주므로, **열람자는 다른 사용자의 이벤트도 봅니다.** 자기 이벤트만 보게 하려면 사용자별 로그 그룹이 필요합니다.
5. **상관 규칙 경보 받기 (D6-25, D6-27)**: 게이트웨이가 5분마다 지난 24시간을 검사해 `correlation_alert` 이벤트를 남깁니다. 경보는 **먼저 화면(CloudWatch 대시보드)에 띄우고, 이어서 이메일로 보냅니다.** 설정 파일은 [deploy/alerts/](deploy/alerts/)에 있습니다. `<region>`·`<account>`를 바꿔 쓰세요. 아래 CLI 명령은 이 저장소에서 실행해 보지 않았습니다.

   1. **지표 필터**: `correlation_alert` 이벤트 하나를 지표 `mcp-guard/CorrelationAlerts` 1로 셉니다.
      `aws logs put-metric-filter --cli-input-json file://deploy/alerts/metric-filter.json`
   2. **이메일 주제**: `aws sns create-topic --name mcp-guard-alerts` 후
      `aws sns subscribe --topic-arn <주제 ARN> --protocol email --notification-endpoint <받을 주소>`.
      받는 사람이 SNS가 보낸 메일에서 **Confirm subscription**을 눌러야 받기 시작합니다. 메일 본문은 바꿀 수 없습니다.
   3. **알람**: 5분 동안 `CorrelationAlerts` 합이 1 이상이면 알람 상태가 되고 2번 주제로 보냅니다.
      `aws cloudwatch put-metric-alarm --alarm-name mcp-guard-correlation-alert --namespace mcp-guard --metric-name CorrelationAlerts --statistic Sum --period 300 --evaluation-periods 1 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --treat-missing-data notBreaching --alarm-actions <주제 ARN>`
   4. **화면**: `aws cloudwatch put-dashboard --dashboard-name mcp-guard-alerts --dashboard-body file://deploy/alerts/dashboard.json`.
      대시보드 맨 위에 알람 상태, 그 아래에 최근 경보 표(심각도·규칙·메시지·세션·서버·도구), 규칙별 경보 수, 차단된 판정 수가 보입니다. 관리자·열람자 IAM 정책 모두 이 화면을 볼 수 있습니다.

   이메일에는 "알람이 울렸다"는 것만 담기고, 어떤 규칙의 경보인지는 화면에서 봅니다.

감사 로그 전송 방식:
- 이벤트는 로컬 파일과 CloudWatch 대기열에 함께 들어가고, 백그라운드 스레드가 2초마다 또는 대기열이 찰 때 `PutLogEvents`로 보냅니다. 요청 처리를 붙잡지 않습니다.
- 한 번에 최대 1 MB·10,000건, 시간순, 24시간 범위 안으로 나눠 보냅니다.
- 실패한 묶음은 대기열 앞에 남겨 다시 보냅니다. 대기열(기본 10,000건)이 차면 그 이벤트는 로컬 사본에만 남고 stderr에 경고합니다.
- CloudWatch는 14일보다 오래된 이벤트를 받지 않습니다. 그보다 긴 장애 동안의 기록은 로컬 사본에만 남습니다.
- 종료할 때 남은 이벤트를 보냅니다(`--approve-server` 실행 포함).

로그인 실패, 원 서버 계정 연결·해제, 자격증명 저장소 장애(503)도 감사 로그에 남습니다.

**세션 (D6-26)**: 감사 이벤트의 `session_id`는 LLM 클라이언트마다 나뉩니다. 어떤 클라이언트인지는 OAuth 클라이언트(CIMD 주소, DCR 콜백 주소·이름, 사전 등록 클라이언트의 `family`)로 판별합니다.

| 클라이언트 | 세션 | 이유 |
| --- | --- | --- |
| ChatGPT | `chatgpt:conversation:<해시>` | ChatGPT가 `_meta["openai/session"]`으로 익명화된 대화 ID를 보냅니다 |
| Claude (claude.ai·Claude Code) | `claude:user:<사용자>` | Claude는 대화 ID를 주지 않는다고 문서에 적혀 있습니다 |
| Gemini (Enterprise·CLI) | `gemini:user:<사용자>` | 대화 ID를 보낸다는 문서가 없습니다 |
| Codex | `codex:user:<사용자>` | 같은 이유 |

ChatGPT 대화 ID는 해시로만 남깁니다. 같은 사용자라도 클라이언트가 다르면 세션이 섞이지 않습니다. Claude처럼 대화 ID가 없는 클라이언트는 오염된 뒤 새 대화를 열어도 같은 세션이라, 사용자가 `/approve`의 **새 세션 시작** 버튼을 누릅니다([MVP 6](../06-http-gateway-server/README.md#세션-오염과-외부-전송-차단-m4)).

**Claude 사용 안내 (2026-11-04 결정, D6-52):** Claude는 **브라우저(claude.ai)에서 게이트웨이 커넥터로** 쓰도록 안내합니다. Claude Desktop 채팅 앱에는 훅이 없어서, Desktop에 직접 등록한 로컬 MCP 서버는 오염 표시와 외부 전송 차단을 받지 못합니다. Desktop으로 열어 로컬 서버를 쓰면 이 부분은 막을 수 없습니다. PC에서 도는 서버가 필요하면 Claude Code를 씁니다(훅이 있음). 또 브라우저 claude.ai 자체 웹 검색이나 올린 파일처럼 게이트웨이를 거치지 않고 들어온 내용은 게이트웨이가 볼 수 없어서, 그 뒤 게이트웨이 외부 전송 도구는 막히지 않습니다(SECURITY.md).

게이트웨이는 인증 없이 공개 주소에서 열리지 않습니다. `--auth none`으로 loopback이 아닌 주소에 붙이면 시작을 거부합니다(시험용 `--allow-unauthenticated` 제외). 클라이언트 IP는 `--trusted-proxy`로 지정한 Caddy 네트워크에서 온 `X-Forwarded-For`만 믿습니다.

Claude 호스팅 앱의 요청은 Anthropic의 나가는 대역 `160.79.104.0/21`, `153.61.208.0/20`에서 옵니다([Anthropic IP 주소 문서](https://platform.claude.com/docs/en/api/ip-addresses), 2026-11-04 확인; 기계가 읽는 파일은 없음). compose는 두 대역을 `--shared-egress`로 넣습니다. 방화벽으로 더 좁히려면 이 대역과 사용자의 Claude Code 출발지를 허용하세요.

## C1 커넥터 등록 절차

**claude.ai Team·Enterprise (Owner)**

1. **Organization settings > Connectors**에서 **Add** → **Custom** → 종류를 물으면 **Web**
2. MCP server URL: `https://mcp.example.com/mcp`
3. Authentication: **Sign in now**, OAuth client: **Register automatically** (이 게이트웨이는 DCR과 CIMD를 모두 지원합니다)
4. 구성원은 **Customize > Connectors**에서 **Custom** 표시가 붙은 커넥터를 **Connect**하고 게이트웨이 로그인 화면에서 로그인합니다

Team·Enterprise에서는 Owner(또는 권한 있는 커스텀 역할)가 아닌 구성원은 커스텀 커넥터를 직접 추가할 수 없습니다. 그래서 Owner가 게이트웨이 URL만 등록하면 커스텀 커넥터 경로는 게이트웨이로 모입니다. claude.ai 디렉터리 커넥터는 허용하고, 따로 처리하는 경로는 만들지 않습니다 (D6-09).

**claude.ai Free·Pro·Max (개인)**: **Customize > Connectors > Add custom connector**에서 같은 URL과 설정을 넣습니다. 강제하지 않고 자유롭게 배포합니다 (D6-11).

**Claude Code**: `claude mcp add --transport http mcp-guard https://mcp.example.com/mcp`. MVP 10은 원격 서버를 게이트웨이 URL로 제한하는 관리 설정을 만들지 않습니다(D6-10, 비독점). 조직이 Claude Code 관리 설정으로 직접 제한하는 것은 이 저장소에서 만들거나 확인하지 않았습니다.

**ChatGPT 개발자 모드** (D6-08): OpenAI Apps SDK 문서의 절차입니다. 실제 연결은 검증하지 않았습니다.

1. [ChatGPT Plugins](https://chatgpt.com/plugins)에서 **+** → **Add custom MCP server**
2. 이름과 설명을 넣고, **Connection**에 `https://mcp.example.com/mcp`(`/mcp` 경로 포함)
3. 인증은 OAuth. ChatGPT는 CIMD(`https://chatgpt.com/oauth/client.json`)를 먼저 쓰고, 쓸 수 없으면 DCR로 등록합니다. 게이트웨이가 모든 인가 응답에 `iss`를 넣으므로 고정 콜백 `https://chatgpt.com/connector_platform_oauth_redirect`를 씁니다
4. 위험 경고에서 **I understand and want to continue** → **Create as a plugin** → 발견된 도구 확인

타사 문서에는 먼저 설정에서 Developer mode를 켜야 하고, Business·Enterprise·Edu에서는 관리자가 허용해야 한다고 적혀 있습니다 (미확인). ChatGPT에서 게이트웨이 URL만 쓰도록 강제하는 방법은 확인하지 못했습니다 (미확인).

ChatGPT의 요청은 OpenAI가 공개하는 대역(`https://openai.com/chatgpt-connectors.json`)에서 옵니다. 여러 사용자가 같은 대역을 쓰므로 공유 출발지로 둡니다. `--shared-egress-feed chatgpt`(compose에 들어 있음)는 시작할 때와 하루 한 번 이 파일을 HTTPS로 받아(리디렉션 거부) 반영하고, 마지막 정상 목록을 상태 폴더의 `egress-chatgpt.json`에 둡니다. 받기에 실패하거나 형식이 이상하면 마지막 정상 목록을 유지하고 `shared_egress_updated` 감사 이벤트로 남기며, 7일 동안 정상 목록을 받지 못하면 그 이벤트에 `stale`을 표시합니다. /12보다 넓은 IPv4 대역(IPv6는 /32)이 있으면 파일 전체를 받지 않습니다. 2026-11-04에 받은 파일은 288개 대역이고, 그중 `9.129.0.0/16` 하나가 주소의 약 95%입니다. 그 대역의 소유자는 확인하지 않았습니다. 공유 출발지 예외는 로그인한 `/mcp` 요청에만 적용되므로([MVP 5](../05-indirect-injection-throttle/README.md)), 그 대역에서 오는 로그인 전 요청은 IP 기준으로 셉니다.

**Codex**:

```powershell
codex mcp add mcp-guard --url https://mcp.example.com/mcp
codex mcp login mcp-guard
```

**Gemini Enterprise** (D6-26): Google 문서 기준 절차입니다. 실제 연결은 검증하지 않았습니다. Gemini Enterprise는 DCR·CIMD 없이 관리자가 OAuth 클라이언트를 직접 등록하고 client secret을 씁니다.

1. 게이트웨이에 클라이언트를 등록합니다. secret은 한 번만 출력되고 파일에는 해시만 남습니다.

   ```powershell
   python -m cloud_entry.admin add-client --clients mvp/09-cloud-entry/deploy/config/oauth-clients.json --family gemini --name "Gemini Enterprise" --redirect-uri https://vertexaisearch.cloud.google.com/oauth-redirect gemini-enterprise
   ```

2. `deploy/.env`에 `MCP_GUARD_OAUTH_CLIENTS=/config/oauth-clients.json`을 넣고 다시 시작합니다.
3. Google Cloud 콘솔에서 Custom MCP Server 데이터 저장소를 만들고 다음을 넣습니다: MCP Server URL `https://mcp.example.com/mcp`, Authorization URL `https://mcp.example.com/authorize`, Token URL `https://mcp.example.com/token`, Client ID `gemini-enterprise`와 1번의 secret, Scopes `mcp offline_access`. **Enable PKCE Support를 켜야 합니다.** 이 게이트웨이는 모든 클라이언트에 PKCE를 요구합니다. HTTP Basic 인증(기본값)과 secret을 본문에 넣는 방식 모두 받습니다.

Google 문서에는 Standard·Plus·Pay-as-you-go·Frontline 판이 대상이고, Business 판은 별도 안내로 연결된다고 적혀 있습니다. 소비자용 Gemini 앱에서 원격 MCP 서버를 붙이는 방법은 찾지 못했습니다 (미확인).

Gemini Enterprise는 공개된 나가는 대역 목록이 없습니다. 기본은 Google의 변하는 대역이고, 데이터 저장소를 만들 때 고정 IP를 켜면 콘솔의 데이터 저장소 상세 페이지에 주소가 나옵니다([Google 문서](https://docs.cloud.google.com/gemini/enterprise/docs/connectors/configure-static-ip-egress), 2026-11-04 확인). 그 주소를 `--shared-egress`로 직접 넣습니다.

**Gemini CLI**: `~/.gemini/settings.json`의 `mcpServers`에 `"httpUrl": "https://mcp.example.com/mcp"`를 넣으면 401을 받고 OAuth를 시작합니다. DCR로 등록하고 콜백은 `http://localhost:<임시 포트>/oauth/callback`이라 이미 받아들입니다. 세션 구분은 DCR 클라이언트 이름에 기댑니다(스스로 밝힌 이름이라 판별에만 쓰고 권한에는 쓰지 않음). Gemini CLI 문서에는 무료·Google One 사용자의 경우 2026-06-18에 Antigravity CLI로 바뀌었다고 적혀 있습니다.

Codex는 CIMD(`https://chatgpt.com/oauth/codex/client.json`)로 로그인하고, 콜백은 `http://127.0.0.1:<임시 포트>/callback`입니다. 요청은 사용자 단말에서 나가므로 공유 출발지 설정이 필요 없습니다. Codex에서 원격 서버를 게이트웨이 URL로만 제한하는 관리 설정은 확인하지 못했습니다 (미확인).

## 한계

- `shared` 서버는 모든 사용자가 같은 원 서버 계정을 씁니다. 개인 데이터를 다루는 서버를 `shared`로 두면 사용자끼리 데이터가 섞입니다.
- 기본 파일 저장소(`--upstream-token-store file`)는 `per_user` 원 서버 토큰을 암호화 없이(소유자 전용 권한) 저장합니다.
- CloudWatch Logs 저장소도 가짜 서버로만 시험했습니다. 실제 AWS 호출과 IAM 정책, 비용은 확인하지 않았습니다. CloudWatch Logs 자체는 WORM 저장소가 아니어서, 권한이 있는 사람은 보존 기간을 줄이거나 로그 그룹을 지울 수 있습니다. 위변조 방지는 M1 B-7 결정 뒤 S3 Object Lock 보관으로 보강합니다.
- AWS Secrets Manager 저장소는 가짜 Secrets Manager·IMDS 서버로만 시험했습니다. 실제 AWS 호출, IAM 정책, 오류 응답 형식(`__type`)은 확인하지 않았습니다. 서명은 AWS SigV4 테스트 스위트의 두 예제로 확인했습니다. ECS 작업 역할·SSO 프로필 같은 다른 자격증명 출처는 지원하지 않습니다.
- Secrets Manager도 실행 중인 게이트웨이가 탈취되면 토큰을 지켜 주지 못합니다. 게이트웨이가 그 비밀을 읽을 권한을 갖고 돌기 때문입니다. 막는 것은 디스크·백업 유출과, 권한 회수·CloudTrail 감사입니다.
- 원 서버 인가 서버 주소를 DNS로 확인한 뒤 연결하므로, DNS rebinding까지 막지는 못합니다.
- 실제 원 서버(GitHub·Slack 등)의 OAuth와 연결해 보지 않았습니다. 테스트는 같은 프로세스 안의 가짜 원 서버·인가 서버로 실제 HTTP를 주고받습니다.
- compose는 운영 서버 `--server asgi`(uvicorn, D6-28)로 띄웁니다. IP 지연은 비동기로 기다리지만, 원 서버 호출 같은 막히는 작업은 스레드 풀(기본 크기)에서 돌므로 느린 원 서버가 많으면 풀이 찰 수 있습니다.
- 서버가 하나라는 가정입니다. 상태 파일(OAuth 클라이언트·refresh token, 0단계 승인)과 IP 카운터를 여러 인스턴스가 나눠 쓰지 않습니다.
- `per_user` 서버의 `403 insufficient_scope` 재인가를 ChatGPT·Codex가 처리하는지는 확인하지 못했습니다 (미확인). 첫 로그인 때 모든 원 서버를 연결하므로 재인가는 연결이 풀린 뒤에만 필요합니다.
- Docker 이미지 빌드와 실제 클라우드 배포, claude.ai·ChatGPT·Codex에서의 실제 연결은 이 저장소에서 검증하지 않았습니다. compose 파일 문법(`docker compose config`)과 로컬 서버의 OAuth 응답만 확인했습니다.
- Caddy가 `X-Forwarded-For`를 붙이는 것은 Caddy 기본 동작으로 알고 있으나 이 저장소에서 확인하지 않았습니다 (미확인).

## 참고 자료

- MCP 2026-07-28 Authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- Claude connectors authentication: https://claude.com/docs/connectors/building/authentication.md
- Add a connector that isn't in the directory: https://claude.com/docs/connectors/custom/add-unlisted.md
- Anthropic IP addresses: https://platform.claude.com/docs/en/api/ip-addresses
- OpenAI Apps SDK authentication (ChatGPT 콜백·CIMD): https://developers.openai.com/apps-sdk/build/auth
- OpenAI Apps SDK connect from ChatGPT: https://developers.openai.com/apps-sdk/deploy/connect-chatgpt
- Codex MCP (`codex mcp add`·`login`, CIMD 조건): https://learn.chatgpt.com/docs/extend/mcp?surface=cli
- OpenAI IP egress ranges: https://developers.openai.com/api/docs/guides/ip-addresses
- AWS SigV4 signed requests: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
- Secrets Manager PutSecretValue (10분 간격 권고): https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html
- Secrets Manager CreateSecret: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html
- CloudWatch Logs PutLogEvents: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
- CloudWatch Logs log groups (보존 기간, 삭제 방지): https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html
- S3 Object Lock: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- CloudWatch Logs filter pattern syntax (JSON): https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html
- CloudWatch dashboard body structure (log·alarm 위젯): https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html
- Amazon SNS email subscriptions (구독 확인 필요): https://docs.aws.amazon.com/sns/latest/dg/sns-email-notifications.html
- CloudWatch Logs PutRetentionPolicy (허용 값에 180 포함): https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutRetentionPolicy.html
- Gemini Enterprise custom MCP server: https://docs.cloud.google.com/gemini/enterprise/docs/connectors/custom-mcp-server/set-up-custom-mcp-server
- Gemini CLI MCP servers: https://geminicli.com/docs/tools/mcp-server
- OpenAI Apps SDK reference (`openai/session`): https://developers.openai.com/apps-sdk/reference
- Claude MCP Apps (Claude가 대화 ID를 주지 않음): https://claude.com/docs/connectors/building/mcp-apps/instance-supersession.md
- EC2 instance role credentials (IMDSv2): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html
- SigV4 test suite (botocore): https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite

## Run

테스트 (저장소 루트): `$env:PYTHONPATH = "src"; python -m unittest tests.test_mvp09_cloud_entry tests.test_mvp09_upstream_oauth tests.test_mvp09_aws_secrets tests.test_mvp09_aws_logs`
