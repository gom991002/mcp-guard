# 1단계: 로컬 MCP 정상 연동 검사

`guard: true`인 로컬 서버는 L2 래퍼가 자식 프로세스를 시작하기 전에 `stage1`을 검사합니다. 검사가 실패하면 종료 코드 78로 멈추고, 감사 로그를 켠 경우 `integration_checked` 이벤트를 남깁니다. 클라이언트 설정을 만들 때 매니페스트 경로가 래퍼에 자동으로 전달됩니다. `guard: false`인 서버는 이 검사를 받지 않습니다.

## 공급 경로

| `provider` | 검사 내용 | 실행 조건 |
| --- | --- | --- |
| `npm` | 공식 MCP Registry의 정확한 서버 버전·게시 상태·npm 패키지와 npm의 SHA-512 배포 해시, 로컬 배포 파일 SHA-256, 설치 디렉터리 전체 해시 | 절대 경로의 고정 실행 파일만 허용합니다. `npx`로 매번 내려받는 실행은 허용하지 않습니다. |
| `pypi` | 공식 MCP Registry의 정확한 서버 버전·게시 상태·PyPI 패키지와 PyPI의 파일별 SHA-256, 로컬 배포 파일·설치 디렉터리 전체 해시 | 절대 경로의 고정 실행 파일만 허용합니다. `uvx` 등 동적 실행은 허용하지 않습니다. |
| `docker` | 로컬 Docker 카탈로그·Docker CLI 파일 해시, 서버 ID와 실행 명령 | `docker mcp gateway run --verify-signatures`로 실행하여 Docker가 이미지 서명을 검사하게 합니다. |
| `local` | 개인이 직접 승인한 실행 파일과 지정한 코드 파일의 SHA-256 | 공개 Registry에 없는 개인·비공개 서버용입니다. 출처 검증은 제공하지 않습니다. |

`npm`·`pypi`의 매니페스트 항목 예시입니다. 아래 `<...>`는 실제 값으로 바꿔야 합니다. `pypi`는 `provider`, `package_identifier`, 배포 파일 경로를 바꿔 같은 구조를 사용합니다.

```json
{
  "guard": true,
  "namespace": "company",
  "command": "<절대 경로의 설치된 실행 파일>",
  "args": [],
  "stage1": {
    "provider": "npm",
    "registry_name": "<공식 Registry의 전체 서버 이름>",
    "registry_version": "<정확한 서버 버전>",
    "package_identifier": "<Registry에 기록된 패키지 이름>",
    "package_version": "<정확한 패키지 버전>",
    "artifact_path": "<내려받아 보관한 배포 파일의 절대 경로>",
    "artifact_sha256": "<배포 파일 SHA-256>",
    "install_root": "<설치 디렉터리의 절대 경로>",
    "install_tree_sha256": "<설치 디렉터리 전체 해시>",
    "executable_sha256": "<실행 파일 SHA-256>",
    "dependency_lock": "<deps 명령이 만든 잠금 파일의 절대 경로>",
    "dependency_lock_sha256": "<잠금 파일 SHA-256>"
  }
}
```

정책 파일에 `"trusted_registry_publishers": ["io.github.company"]`처럼 공식 Registry 발행자(서버 이름에서 `/` 앞부분)를 적으면, 그 발행자의 npm·PyPI 서버만 1단계를 통과합니다(`S1_REGISTRY_PUBLISHER_NOT_ALLOWED`, D6-05). 목록이 비어 있으면 제한하지 않습니다. Docker와 `local` 서버는 Registry 발행자가 없어 이 검사 대상이 아닙니다. 정책 파일은 그 PC 사용자가 고칠 수 있으므로(D6-33) 실수를 막는 장치이지 사용자의 의도적인 우회를 막지는 못합니다.

Docker 경로는 `command`에 절대 경로의 Docker CLI를 넣고 `args`를 다음 순서로 고정합니다. 카탈로그 파일은 실제로 사용하려는 Docker MCP 카탈로그여야 합니다.

```text
mcp gateway run --catalog <카탈로그 절대 경로> --servers <서버 ID> --verify-signatures --watch=false
```

`stage1`에는 `provider: docker`, `catalog_path`, `catalog_sha256`, `server_id`, `executable_sha256`를 넣습니다. `local` 경로에는 `executable_sha256`와 `files`(절대 파일 경로 → SHA-256 해시)를 넣습니다.

파일·설치 디렉터리 해시는 승인 전에 다음 명령으로 계산합니다. `check-stage1`은 저장된 값과 공식 서비스를 조회해 실행 전 검사를 수행합니다.

```powershell
python mvp/10-local-entry/mcp_guard_config.py fingerprint --path <파일 또는 설치 디렉터리>
python mvp/10-local-entry/mcp_guard_config.py check-stage1 --manifest guard-manifest.json --server <서버 이름>
```

## 의존성 패키지 검사 (D6-31)

MCP Registry와 배포 해시는 서버 패키지 하나만 보증합니다. 설치 폴더에 함께 깔리는 의존성 패키지가 유사 이름(타이포스쿼팅)이나 탈취된 릴리스가 들어오는 길이므로, `npm`·`pypi` 경로는 의존성 잠금 파일을 고정해야 시작합니다.

1. 설치 스크립트 없이, 바이트코드 없이 설치합니다: npm은 `npm ci --ignore-scripts`(lockfile 사용), PyPI는 가상 환경에서 `pip install --no-compile --only-binary :all:`. `--only-binary`는 소스 배포판의 `setup.py`가 설치 중에 실행되지 않게 합니다. 학습 데이터의 PyPI 악성 416개 중 186개는 `setup.py`에서만 신호가 잡혔습니다(D6-35).
2. 설치 폴더 해시를 `install_tree_sha256`에 넣습니다(`fingerprint`).
3. `deps --manifest guard-manifest.json --server <서버 이름>`으로 잠금 파일을 만듭니다(기본 위치 `dependency-locks/<서버>.json`). 출력 끝의 `dependency_lock`·`dependency_lock_sha256`을 `stage1`에 넣습니다.
4. 검토 항목이 있으면 확인한 뒤 `deps ... --accept`로 수락하고, 바뀐 잠금 파일 해시를 다시 넣습니다.

| 승인할 때 보는 것 | 판정 | 코드 |
| --- | --- | --- |
| 설치된 파일이 공개 배포 파일과 다르거나 빠짐 (서버 패키지 자신 포함) | 차단 (A) | `2-A5_DEPENDENCY_TAMPERED` |
| 공개 저장소에 없는 패키지 | 차단 (A) | `S1_DEPENDENCY_NOT_PUBLISHED` |
| OSV 악성 패키지 기록(`MAL-`) | 차단 (A) | `S1_DEPENDENCY_MALICIOUS` |
| 30일이 안 된 릴리스 | 검토 (A) | `S1_DEPENDENCY_TOO_NEW` |
| 배포 파일에 없는 파일, 어느 패키지에도 속하지 않는 파일 (`.pth` 등) | 검토 (A) | `S1_DEPENDENCY_EXTRA_FILE` |
| 소스 빌드 설치 (`setup.py`가 설치 중 실행됨, D6-37). `stage1.allow_source_builds: true`면 검토 | 차단 (A) | `S1_DEPENDENCY_SOURCE_BUILD` |
| 비교할 수 없는 설치 (`.pyc`), 철회된(yanked) wheel | 검토 (A) | `S1_DEPENDENCY_UNVERIFIED`, `S1_DEPENDENCY_YANKED` |
| 인기 패키지와 비슷한 이름 (`crossenv` → `cross-env`, `lodahs` → `lodash`) | 검토 (B) | `B_DEPENDENCY_LOOKALIKE_NAME` |
| npm 설치 스크립트(`preinstall`·`install`·`postinstall`, node-gyp) | 검토 (B) | `B_DEPENDENCY_INSTALL_SCRIPT` |
| 이전 릴리스에 있던 npm 출처 증명(provenance)이 없는 릴리스 | 검토 (B) | `B_DEPENDENCY_PROVENANCE_DROPPED` |

시작할 때마다 잠금 파일 해시, 잠금 파일이 같은 설치 폴더로 만들어졌는지, 서버 패키지가 들어 있는지, 수락 여부를 확인하고 OSV를 다시 조회합니다. 승인 뒤에 악성으로 보고된 버전은 그때 차단됩니다. 비슷한 이름 검사는 [npm-high-impact](https://github.com/wooorm/npm-high-impact)(MIT, `src/mcp_guard/data/NPM-HIGH-IMPACT-LICENSE.txt`)와 [top-pypi-packages](https://hugovk.dev/top-pypi-packages/)의 상위 5,000개 이름을 씁니다. npm 목록은 함께 배포되고, PyPI 목록은 출처에 라이선스 표기가 없어 설치할 때 `python mvp/10-local-entry/update_popular_packages.py --ecosystem pypi`로 직접 받습니다. 목록이 없으면 `B_DEPENDENCY_LOOKALIKE_UNCHECKED`로 검토 보류합니다. OSV에 접속할 수 없으면 시작하지 않습니다(D6-31).

설치 폴더는 서버가 실행 중에 파일을 쓰면 해시가 바뀌어 다음 시작이 막힙니다. 그래서 래퍼는 서버를 `PYTHONDONTWRITEBYTECODE=1`로 실행해 Python 바이트코드(`__pycache__`)를 설치 폴더에 쓰지 않게 합니다. 바이트코드를 다른 폴더로 옮기는 방식(`PYTHONPYCACHEPREFIX`)은 고정되지 않은 위치의 코드를 불러오게 되므로 쓰지 않습니다. 서버를 래퍼 없이 직접 실행했거나 패키지가 실행 중에 캐시를 쓰면, 시작 거부 메시지에 추가·변경·삭제된 파일이 나옵니다.

## B 코드 행동 분석 (D6-30)

해시 확인을 통과한 코드를 Semgrep CE로 검사합니다. npm·PyPI는 `install_root` 전체, `local`은 `files`에 고정한 파일을 검사하고, Docker 이미지는 검사하지 않고 보고서도 요구하지 않습니다(D6-34, 이미지 서명 검증에 맡김). 규칙은 이 저장소의 [Semgrep 규칙](../01-policy-engine-cleanup/rule_sets/semgrep_static_rules.py)만 쓰고 Semgrep Registry 규칙은 쓰지 않습니다.

```powershell
python mvp/10-local-entry/mcp_guard_config.py scan --manifest guard-manifest.json --server <서버 이름>
python mvp/10-local-entry/mcp_guard_config.py scan --manifest guard-manifest.json --server <서버 이름> --accept
```

| 래퍼가 본 상태 | 판정 | 코드 |
| --- | --- | --- |
| 검사를 요구했는데 보고서가 없음 | block (A) | `S1_CODE_SCAN_MISSING` |
| 검사 뒤 1단계 고정값이나 규칙이 바뀜 | block (A) | `S1_CODE_SCAN_STALE` |
| 엔진이 돌지 않았거나 분석하지 못한 코드 파일 (백신이 읽기를 막은 파일 포함) | review (B) | `B_CODE_SCAN_UNAVAILABLE`, `B_CODE_SCAN_INCOMPLETE` |
| 검토 신호가 있는 패키지 (B 점수, 아래) | review (B) | `B_SCORE_HELD` |
| 위 항목 없음, 또는 같은 항목을 수락함 | allow | |

### B 점수 (D6-35, D6-37)

Semgrep 발견 항목을 설치된 패키지별로 나누고, 패키지마다 신호를 [b_score.py](../../src/mcp_guard/b_score.py)로 점수화합니다. 신호는 비슷한 이름, npm 설치 스크립트, `.pth` 파일, Semgrep 규칙 7종, 매니페스트 메타데이터 5종, GuardDog 결과 5종입니다. 모델은 악성·정상 패키지 2,495개로 학습했습니다([학습과 결과](../../mvp/10-local-entry/b_score/README.md)).

- **판정:** 점수가 기준값 이상이면 검토입니다(D6-37). 모델은 그리드서치로 고른 단조 제약 그래디언트 부스팅이고(D6-40), PyPI는 더 낮은 기준값을 씁니다(D6-46). 현재 시험 데이터 수치는 아래 GuardDog 항목에 있습니다. D6-37 당시 로지스틱 모델의 수치(재현율 0.70, 정상 보류 10.1%)는 이전 기록입니다.
- **GuardDog(기본 켜짐, D6-47):** `ghcr.io/datadog/guarddog:3.2.0`을 네트워크 없는 Docker에서 패키지마다 돌립니다. Docker가 필요합니다. GuardDog을 돌리지 못하면(Docker 없음, 이미지 없음, 점검용 표본을 못 잡음) `B_GUARDDOG_UNAVAILABLE` 공백으로 검토 대기가 되고, 점수는 GuardDog 특징 없이 따로 학습한 모델이 매깁니다. Docker를 쓸 수 없는 곳에서는 매니페스트에 `"code_scan": {"guarddog": {"enabled": false}}`를 넣습니다. 시험 데이터에서 GuardDog 켬: 재현율 0.847·정상 보류 13.0%(PyPI 0.843·23.1%), 끔: 0.776·12.7%(PyPI 0.651·20.6%) (D6-40, D6-46).
- **점수:** 보류된 패키지마다 확률과 신호별 기여도(SHAP)를 보고서와 `code_scanned` 감사 기록에 남겨, 무엇을 먼저 볼지와 이유를 보여 줍니다. 확률은 학습 데이터 기준이라 실제 위험 확률이 아닙니다.
- **기록 전용:** `B_CODE_ENV_HARVEST`, `B_CODE_DYNAMIC_EVAL`은 정상 패키지에서 더 흔해 기록만 합니다(예: `debug`).
- 모델이 모르는 신호가 켜지면 검토로 올립니다. 모델 파일이 없으면 모든 신호가 검토입니다.
- 코드 검사가 켜져 있으면 의존성 잠금의 비슷한 이름·설치 스크립트 신호는 잠금에서 따로 수락하지 않고 이 점수에서 다룹니다.

### 알려진 악성 유사도와 LLM 검토 도우미 (D6-36)

- **유사도(근거 전용):** 코드 파일 지문을 [알려진 악성 색인](../../src/mcp_guard/data/known_malware_index.json)과 비교해 일치하면 `B_CODE_KNOWN_MALWARE_SIMILAR`로 기록합니다. 검토로 올리지는 않고, 보류된 패키지의 근거와 검토 도우미 자료에 붙습니다. 인기 패키지(상위 5,000) 자신의 파일은 비교하지 않습니다. 유사 이름 악성이 원본 코드를 베껴 넣기 때문입니다.
- **LLM 검토 도우미(판정 불변, 기본 꺼짐):** 매니페스트에 OpenAI 호환 주소를 넣고 `scan --explain`을 실행하면, 보류된 패키지마다 요약이 `code-scans/<서버>.review.json`에 저장되고 `review_assisted` 감사 이벤트(코드 없음)가 남습니다. 보고서의 상태와 수락은 바뀌지 않습니다.

```json
"review_assist": {"enabled": true, "base_url": "http://127.0.0.1:11434/v1", "model": "<로컬 모델 이름>", "api_key_env": ""}
```

로컬 모델 서버(Ollama 등)는 코드 조각을 설정한 로컬 주소로 보냅니다. 외부 API는 HTTPS 주소와 키를 담은 환경 변수 이름(`api_key_env`)을 넣고, 실행할 때 코드 조각이 그 서비스로 전송된다는 안내가 나옵니다. 모델 주소의 리디렉션은 거부합니다. 응답은 지정된 JSON 필드와 형식을 검사하며, 맞지 않으면 `unclear`로 기록합니다. 검사 대상 코드는 공격자가 쓴 입력이라 무작위 태그와 AI 대상 문구 탐지는 요약을 신뢰해도 된다는 보증이 아닙니다. 문구 탐지는 정규식에 맞는 표현만 표시합니다. 무료 로컬 모델 Qwen2.5-Coder 7B로 평가했을 때는 보류된 악성과 정상을 거의 모두 "suspicious"라고 답해 구분하지 못했습니다([평가](../../mvp/10-local-entry/b_score/README.md)). 알려진 악성 지문 일치도 오탐이 가능하므로 검토 근거로만 씁니다.

Registry와 패키지 서비스에 접속할 수 없거나 게시 상태가 `active`가 아니면 연결을 시작하지 않습니다. 버전·파일 해시·설치 내용이 바뀌면 매니페스트를 검토하고 승인 값을 갱신해야 합니다. 설치 폴더가 배포 파일에서 나왔는지는 의존성 잠금 파일을 만들 때 파일 단위로 비교합니다(D6-31). 설치 스크립트가 만든 파일과 컴파일된 바이트코드는 비교할 수 없어 검토 대상입니다. Docker 서명 검증은 Docker CLI가 시작될 때 이루어지며, 이 코드의 사전 검사는 해당 옵션과 고정 카탈로그를 강제합니다.

공식 MCP Registry: https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md  
npm 패키지 메타데이터: https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md  
PyPI JSON API: https://docs.pypi.org/api/json/  
Docker MCP gateway 옵션: https://docs.docker.com/reference/cli/docker/mcp/gateway/run/
