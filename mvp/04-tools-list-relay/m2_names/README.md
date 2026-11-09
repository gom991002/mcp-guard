# M2 도구 이름 비교 방식 선택 (D6-38)

[eval_lookalike.py](eval_lookalike.py)는 M2의 "비슷한 이름" 비교 방식을 실제 도구 이름으로 평가해 고릅니다. 결과는 [report.json](report.json)입니다.

- **정상 데이터:** [Docker MCP 카탈로그](https://github.com/docker/mcp-registry)(MIT)의 `tools.json`에 있는 실제 도구 이름 755개(서버 28곳). 각 서버의 도구를 다른 모든 서버의 도구와 비교해, 비슷하다고 잡히면 오탐(검토)으로 셉니다. 같은 이름은 MCP 명세가 서버 간에 있을 수 있다고 하므로 비교하지 않습니다.
- **위장 데이터:** 실제 이름마다 위장 변형(ASCII·Unicode 동형 문자, 구분자, 대소문자, 빠짐, 반복, 자리 바꿈, 치환, 단어 순서, 접두·접미어)을 만들었습니다(7,482개). 직접 만든 것이라 탐지율은 실제보다 낙관적입니다.
- **선택 기준(실행 전에 정함):** 정상 보류 2% 이하인 방식 중 탐지율이 가장 높은 것.

| 방식 | 정상 보류 | 탐지율 |
| --- | --- | --- |
| UTS #39 skeleton (표준) | 0% | 26.9% |
| + 구분자·대소문자 | 0% | 36.9% |
| + 단어 순서 | 0% | 46.9% |
| + 한 글자 편집 (5자 이상, 치환은 7자 이상) | 0.53% | 88.3% |
| **+ 한 글자 편집 (길이 제한 없음, 채택)** | **0.53%** | **88.5%** |

정상 보류 4건은 모두 다른 서버의 단수·복수 쌍(`get_node`/`get_nodes`, `get_job`/`get_jobs`)이었습니다. 접두·접미어 추가는 어느 방식도 잡지 못했습니다(0%). 길이 제한 없는 방식은 짧은 이름(`get`/`set`)을 비슷하다고 볼 수 있지만 이 데이터에는 그런 경우가 없었습니다.

```text
git clone --depth 1 https://github.com/docker/mcp-registry.git
python mvp/04-tools-list-relay/m2_names/eval_lookalike.py --servers mcp-registry/servers
```
