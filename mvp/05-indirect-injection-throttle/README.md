# 05 IP Request-Rate Delay

MVP 다섯 번째 작업 구역입니다. 폴더 이름(`indirect-injection-throttle`)과 패키지 이름(`injection_throttle`)은 기존 경로와 맞추려고 그대로 둡니다.

목표는 게이트웨이 보조 수단(AUX)으로, 일정 시간 안에 같은 키(IP, 또는 IP와 헤더)에서 요청이 정해진 횟수를 넘으면 접속 지연을 계산하는 것입니다. `allow`·`review`·`block` 판정은 바꾸지 않습니다.

## 방식

- **임시 저장소** (`SlidingWindowStore`): 키마다 최근 요청 시각만 보관합니다. 키 하나에 최대 `limit + 1`개를 두고, 창(window)이 지나면 키를 지우고, 가득 차면 가장 오래 쓰지 않은 키를 버립니다. nginx `limit_req_zone`이 키마다 고정 크기 상태를 두고 가득 차면 가장 오래 쓰지 않은 상태를 지우는 방식을 따랐습니다.
- **슬라이딩 창**: 현재 시각에서 `window_seconds`만큼 거슬러 올라가 요청을 셉니다. AWS WAF의 평가 창과 같은 방식입니다.
- **지연 시간**: 한도를 넘으면, 창 안의 가장 오래된 요청이 창 밖으로 나갈 때까지의 시간을 지연으로 씁니다. 상한은 `max_delay_seconds`입니다.
- **규칙 두 개를 함께 적용**: `per-ip`는 헤더를 보지 않고 IP만으로 셉니다. `per-client`는 IP와 헤더 값을 묶어 셉니다. 헤더 값을 바꿔 가며 보내도 `per-ip` 한도에 걸립니다. nginx 문서의 IP별·서버별 제한을 동시에 거는 예를 따랐습니다.
- **헤더 보관**: 헤더 원문은 저장하지 않습니다. 프로세스를 시작할 때 만든 키로 HMAC-SHA256 digest를 계산해 그 값만 저장합니다. `Authorization` 토큰이 메모리에 원문으로 남지 않습니다.
- **헤더가 없는 요청**: 빈 값으로 셉니다 (Cloudflare 방식). AWS WAF는 키 구성 요소가 없는 요청을 세지 않지만, 그 방식이면 헤더를 빼기만 해도 규칙을 피할 수 있어 따르지 않았습니다.

## 차단 단계

딜레이가 계속 걸리는 키는 다시 지연하지 않고 거절합니다 (D6-16). 거절은 서버 스레드를 붙잡지 않고 바로 `429 Too Many Requests`와 `Retry-After`로 답합니다.

- 한도를 넘어 지연된 요청마다 그 키에 경고 1회를 셉니다.
- 정해진 시간 안에 경고가 정해진 횟수에 이르면 키를 차단합니다. 차단된 동안의 요청은 세지 않습니다.
- 다시 차단되면 차단 시간이 두 배가 되고, 상한에서 멈춥니다.
- 차단 키는 한도를 넘은 규칙의 키입니다. `per-ip`이면 그 IP, `per-client`이면 그 IP와 토큰 조합입니다.
- **공유 출발지**(`shared_networks`, 서버 옵션 `--shared-egress`): 여러 사용자가 같은 IP로 들어오는 대역에서는 IP만 보는 규칙을 건너뜁니다. claude.ai 요청은 Anthropic의 나가는 대역(`160.79.104.0/21`, `153.61.208.0/20`)에서 오므로, 이 대역을 공유 출발지로 두지 않으면 한 사람 때문에 모든 claude.ai 사용자가 차단됩니다. compose 설정에 두 대역과 ChatGPT 공개 대역 자동 반영(`--shared-egress-feed chatgpt`, MVP 9)이 들어 있습니다.
- **공유 출발지 예외는 로그인한 `/mcp` 요청에만** (2026-11-04): 게이트웨이 토큰이 유효한 `/mcp` 요청만 IP 규칙을 건너뜁니다. 로그인 화면·토큰 발급처럼 로그인 전 요청은 공유 대역에서 와도 IP 기준으로 셉니다. 그 대역의 누구든 헤더 값을 바꿔 보낼 수 있어서, IP 규칙을 빼면 로그인 전 경로에 제한이 없어지기 때문입니다. 인증을 끈 개발 모드(`--auth none`)는 이전처럼 모든 요청에 예외를 둡니다.

| 항목 | 기본값 | 허용 범위 | 근거 |
| --- | --- | --- | --- |
| 경고 횟수 `strikes` | 5 | 1 이상 | fail2ban `maxretry = 5` |
| 경고를 세는 시간 `findtime_seconds` | 600 | 10–3600 | fail2ban `findtime = 10m` |
| 첫 차단 시간 `ban_seconds` | 600 | 60–3600 | fail2ban `bantime = 10m`, OWASP CRS DoS 플러그인 `dos_block_timeout = 600` |
| 반복 차단 | 2배씩 | — | fail2ban `bantime.increment`(1, 2, 4, 8 … 배) |
| 차단 상한 `max_ban_seconds` | 3600 | 첫 차단 이상, 86400 이하 | Google Cloud Armor `ban_duration_sec` 최댓값 3600. 86400은 Cloudflare mitigation timeout 최댓값 |
| 반복으로 세는 기간 `repeat_window_seconds` | 86400 | 상한 이상 | 외부 근거 없음 (설계 논의) |

`429` 응답 코드는 RFC 6585 정의를 따랐습니다 (기억에 의존, 이번에 확인하지 않음).

## 기본값과 근거

| 항목 | 기본값 | 허용 범위 | 근거 |
| --- | --- | --- | --- |
| `window_seconds` | 60 | 10–3600 | AWS WAF 평가 창은 60·120·300·600초(기본 300), Cloudflare period는 10–3600초, Google Cloud Armor interval은 10–3600초, OWASP CRS DoS 플러그인 burst 구간은 60초입니다. 허용 범위는 Cloudflare·Cloud Armor를, 기본값은 네 곳 모두에서 쓸 수 있는 60초를 따랐습니다. |
| `per-ip` 한도 | 60초에 100회 | 1 이상 | OWASP CRS DoS 플러그인 기본값입니다 (정적 파일을 뺀 요청이 60초에 100회를 넘으면 burst). 하한 1은 Cloud Armor throttle의 최소값입니다. AWS WAF의 최소값은 10입니다. |
| `per-client` 한도 | 60초에 60회 | 1 이상 | nginx `limit_req` 문서의 예시 `rate=1r/s`(평균 초당 1회)입니다. 권장값이 아니라 예시값입니다. |
| `per-client` 헤더 | `authorization`, `user-agent` | — | AWS WAF·Cloud Armor·Cloudflare 모두 헤더 값을 집계 키로 쓸 수 있습니다. 어느 헤더를 쓸지는 이 MVP에서 정했습니다 (설계 논의). |
| `max_delay_seconds` | 30 | 0 초과 | 이전 MVP 5 기본값을 유지했습니다. 외부 근거는 없습니다. |
| `max_tracked_keys` | 10,000 | 규칙 수 이상 | 외부 근거는 없습니다 (설계 논의). 참고로 nginx는 1MB에 128바이트 상태를 약 8천 개 담습니다. |

이 값이 MCP 트래픽에 맞는지는 실측하지 않았습니다 (미확인). 에이전트가 짧은 시간에 도구를 많이 부르는 경우 `per-client` 한도에 걸릴 수 있습니다.

## 한계

- **프록시·NAT**: 같은 프록시나 NAT 뒤의 사용자는 한 IP로 보입니다. 서버는 소켓 주소만 쓰고 `X-Forwarded-For`를 믿지 않습니다. AWS WAF 문서도 전달 IP 헤더는 프록시마다 다르게 다뤄지고 위조될 수 있다고 경고합니다.
- **인스턴스별 카운터**: 저장소는 프로세스 메모리 하나입니다. 인스턴스가 여럿이면 인스턴스마다 따로 세고, 재시작하면 초기화됩니다. Azure WAF 문서도 인스턴스별 카운터에 같은 한계를 적고 있습니다.
- **차단 전까지는 대기**: 차단 전의 지연은 서버 스레드에서 `sleep`으로 적용합니다 (`sleep_on_delay`). 차단 단계가 대기 스레드가 쌓이는 시간을 줄이지만, 경고 5회가 쌓이기 전까지는 여전히 요청 스레드가 기다립니다.
- **차단 상태도 메모리**: 경고와 차단 기록은 프로세스 메모리에 있어서 재시작하면 사라집니다.
- **요청 수만 셈**: 이전 버전처럼 B/M1/M4 의심 신호를 세지 않습니다. 그래서 간접 인젝션 시도와 정상적인 대량 호출을 구분하지 않습니다.
- **근사치**: 지연된 요청도 도착 시각으로 기록합니다. AWS WAF·Azure WAF 문서도 한도가 정확히 지켜지지는 않는다고 적고 있습니다.

## 참고 자료

- AWS WAF rate-based rule settings: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-high-level-settings.html
- AWS WAF aggregation options: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-aggregation-options.html
- Cloudflare rate limiting parameters: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/
- Google Cloud Armor rate limiting: https://docs.cloud.google.com/armor/docs/rate-limiting-overview
- Azure WAF rate limiting: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/rate-limiting-overview
- nginx `ngx_http_limit_req_module`: https://nginx.org/en/docs/http/ngx_http_limit_req_module.html
- OWASP CRS DoS protection plugin: https://github.com/coreruleset/dos-protection-plugin

## Run

From this folder:

```powershell
$env:PYTHONPATH = "../../src"
python -m injection_throttle.demo
```
