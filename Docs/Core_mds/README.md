# Architecture Drawings

이 폴더에는 [전체 아키텍처](architecture.md), [공격 유형별 위협 모델](threat-model.md), [구현 순서](roadmap.md), [M4 값 정책](m4-value-policy.md)을 모았습니다. 현재 구현 현황은 [Progress_map_v13.png](../Core_images/Progress_map_v13.png)와 [SECURITY.md](../../SECURITY.md)에 있습니다.

| 파일 | 도면 | 내용 |
| --- | --- | --- |
| [`Core_images/Architecture.png`](../Core_images/Architecture.png) | v2 | MCP보다 먼저 실행: 실행 순서, 0단계 진입 강제(L·C), 검사 코어 1~4단계. 다른 도면의 기준인 '원본' |
| [`Core_images/Defense_Paths.png`](../Core_images/Defense_Paths.png) | A-01 | 공격 유형별 방어 경로: 유형(행) × 인프라 구역(열), 막는 지점, 남는 구멍 |
| [`Core_images/Deployment_map.png`](../Core_images/Deployment_map.png) | A-02 | 배치도: 로컬 경로와 클라우드 경로가 같은 검사 코어를 지나는 구성 |

세 도면 모두 2026-10-30에 작성됐습니다. A-01과 A-02에서 (해석)·(추론)·(미기재)로 표시된 내용은 원본 v2에 없는 부분입니다.

**A-01과 A-02가 최신 기준입니다.** 문서·코드·v2 도면이 서로 다르면 A-01·A-02를 따릅니다.

이 기준으로 정리한 차이:

- 클라우드 경로: v2는 "1·2단계 후 원 서버 연결", A-02는 원격 게이트웨이 → MCP 서버 구간에 "2·3·4단계"라고 적었습니다. 문서는 A-02를 따릅니다. 1단계는 로컬 패키지 경로에 놓입니다.
