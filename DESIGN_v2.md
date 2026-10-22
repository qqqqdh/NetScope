# NetScope 설계 제안서 v2

> 실시간 네트워크 트래픽 분석기. 패킷을 수집해 프로토콜별 통신량, IP 연결 관계, 이상 트래픽을 실시간으로 시각화한다.

- 작성일: 2026-10-21
- 상태: v2 — 기술 검토(조건부 승인) 반영본. 이전 판은 `DESIGN_v1.md`에 있다.

---

## 0. 리뷰 반영 내역

| # | 리뷰 지적 | 반영 내용 | 문서 위치 |
|---|-----------|-----------|-----------|
| ① | 작은 포트를 먼저 매칭하는 분류는 오분류 위험 | **Flow 기반 분류**로 변경: 연결 시작 방향을 보고 서버 포트를 판단. 결과에 `method`와 `confidence`를 붙이고, UI에서는 `HTTPS (추정)`처럼 표시 | §5.2, §5.3 |
| ② | 메모리 상한이 보장되지 않음 | 모든 상태 테이블에 **명시적 상한**을 둠. 넘친 데이터는 `other`에 합산. 대상 키는 Space-Saving 방식(가장 작은 항목을 축출)으로 관리. 축출과 누락 횟수를 카운터로 공개 | §6 |
| ③ | SYN 플러드를 ACK 개수로 판단하기 어려움 | Flow 상태 전이를 기반으로 **최초 SYN, 재전송, SYN-ACK, 핸드셰이크 완료**를 따로 셈. 캡처가 단방향인지 감지. 경고 문구는 "의심"으로만 표현하고 `confidence`를 붙임 | §5.4 |
| ④ | 시간 기준이 하나뿐임 | 이벤트 시간, 처리 시간, 단조 시간을 분리. 워터마크, 지연 허용, 미래 패킷 처리 정책을 정의 | §4 |
| ⑤ | DNS 플러드와 터널링을 혼동함 | v1은 `dns_flood` ("질의 폭주 의심")만 둠. 터널링 탐지는 DNS 페이로드 파서가 필요하므로 v2로 연기 | §5.4, §11 |
| ⑥ | 캡처 계층과 분석 계층의 결합도가 높음 | **Bounded Queue와 단일 분석 워커**로 분리. 스냅샷은 불변 객체로 발행. 클라이언트마다 송신 큐를 두고, 느린 클라이언트는 연결을 끊음 | §3 |
| 부가 | `ipaddress.is_private`는 RFC1918 사설 대역만 뜻하지 않음 | 내부/외부 판단은 **설정한 로컬 서브넷**으로 함. 주소 종류는 `scope` 속성으로 별도 표현 | §5.5 |
| 부가 | 시나리오 테스트와 탐지 성능 지표 추가 | 시뮬레이터가 **정답 라벨**을 내보내고, 평가기가 Precision, Recall, 탐지 지연을 계산 | §8 |

**리뷰와 다르게 판단한 두 가지**
- **쿨다운의 시간 기준**: 리뷰는 단조 시간을 권했지만, 쿨다운과 탐지 윈도우는 **이벤트 시간**으로 계산한다. PCAP을 최대 속도로 재생하면 10분 분량이 몇 초 만에 처리된다. 이때 단조 시간을 쓰면 쿨다운 30초 안에 공격 전체가 묻히고, 같은 데이터를 다시 돌려도 결과가 달라진다. 단조 시간은 발행 주기와 워치독에만 쓴다.
- **SYN과 ACK의 방향**: 핸드셰이크의 세 번째 ACK는 SYN과 같은 방향(클라이언트 → 서버)으로 간다. 그러니 v1의 문제는 방향이 아니었다. 기존 데이터 연결의 ACK까지 함께 세어 바쁜 서버에서 **탐지를 놓치는 것**이 문제였다. 결론(Flow 상태로 세기)은 리뷰와 같다.

> 참고: 폴더에 있는 기존 부분 코드(`netscope/*.py`, `tests/`)는 v1 기준이다. 1단계에서 이 문서에 맞춰 고친다.

---

## 1. 목표와 범위

### 1.1 목표
| # | 목표 | 성공 기준 |
|---|------|-----------|
| G1 | 패킷 수집 | 실제 NIC 캡처, PCAP 재생, 시뮬레이터를 같은 파이프라인으로 처리 |
| G2 | 프로토콜별 통신량 | 최근 60초 동안 프로토콜별 초당 바이트 시계열과 비율. 분류 신뢰도 표시 |
| G3 | IP 연결 관계 | 노드와 엣지 그래프. 표시 상한을 넘는 데이터는 `other`에 합산해 합계 보존 |
| G4 | 이상 탐지 | 4종 탐지. 시뮬레이터 기준 **Recall ≥ 0.95, Precision ≥ 0.9, 정상 시나리오 오탐 0건** |
| G5 | 실시간성 | 패킷 이벤트부터 대시보드 반영까지 **P95 ≤ 2.5초** (1초 버킷 + 지연 허용 1초) |
| G6 | 자원 상한 | 고유 IP 10만 개/초 부하에서도 **RSS ≤ 400MB**. 패킷 손실은 카운터로 보고 |

> v1의 "1초 이내 반영"은 1초 버킷을 쓰면서 늦게 도착하는 패킷도 받으려면 지킬 수 없는 목표였다. 그래서 G5로 고쳤다.

### 1.2 범위
- **포함**: LiveSource, **PcapSource(1단계에 포함)**, SimulatedSource. 4종 탐지. 로컬 대시보드.
- **제외 (v2 이후)**: 페이로드 검사(TLS/DNS 파싱), DNS 터널링, 장기 저장, 인증과 원격 접속, ML 기반 탐지, 수평 스캔과 ARP 스푸핑 탐지

---

## 2. 결정 사항 (리뷰 권장안 채택)
| 항목 | 결정 |
|------|------|
| 실제 캡처 | 4단계에 추가. 코어는 시뮬레이터와 PCAP으로 먼저 검증 |
| 대상 환경 | 로컬 PC 전용. `127.0.0.1`에만 바인딩하고 인증 없음 |
| 프런트엔드 | 정적 HTML/JS + Chart.js + D3.js (빌드 단계 없음) |
| 추가 탐지 | 2차로 연기 |
| PCAP 재생 | 1차에 포함. 실제 데이터로 재현 테스트 |

---

## 3. 아키텍처

```
 [Capture Thread]                 [Analyzer Worker Thread]                     [asyncio Event Loop]
 Live / Pcap / Sim                 (모든 분석 상태를 단독 소유 → 락 없음)
   │ 정규화 Packet                  ┌───────────────────────────────┐
   ▼                               │ FlowTable → Classifier          │  close_second(s)
 Bounded Packet Queue ───────────▶ │ TrafficAnalyzer (버킷)           │ ───────────────▶ Snapshot Publisher
 maxsize=100,000                   │ AnomalyDetector                 │  불변 스냅샷과       (참조 교체 +
 꽉 차면 tail-drop                 │ Watermark / Clock               │  새 경고            call_soon_threadsafe)
 + drop 카운터                     └───────────────────────────────┘                        │
                                                                                            ▼
                                                                 클라이언트별 송신 큐 → WebSocket / REST
```

| 구성 요소 | 책임 | 동시성 정책 |
|-----------|------|-------------|
| Source | 캡처한 패킷을 `Packet`으로 정규화하고 큐에 넣음 | `put_nowait`. 큐가 꽉 차면 **새 패킷을 버림**(시간 순서 유지). 캡처 스레드는 절대 멈추지 않음 |
| Packet Queue | `queue.Queue(maxsize=100_000)` | 버린 패킷 수를 초 단위로 기록해 스냅샷의 `health.dropped`로 공개 |
| Analyzer Worker | 큐 소비, 집계, 탐지, 초 단위 마감 | 상태를 단독 소유하므로 락이 없음. 큐 대기 timeout 0.2초 (패킷이 없어도 시간이 흐르게 하기 위함) |
| Publisher | 마감된 초마다 스냅샷을 만들고, JSON 직렬화를 **한 번만** 수행 | 이벤트 루프에는 직렬화된 bytes만 전달 |
| WebSocket | 클라이언트마다 `snapshot` 슬롯(최신 값만 유지, 크기 1)과 `alert` 큐(최대 100) | 경고 큐가 넘치거나 전송이 5초 넘게 막히면 close 1013. 클라이언트는 재접속 후 `/api/alerts`로 누락분을 받음 |

**품질 저하 표시**: 최근 60초 안에 패킷 손실, 늦은 패킷 폐기, 상태 축출이 있었으면 스냅샷에 `health.degraded=true`를 표시하고, 대시보드 상단에 배지를 띄운다. 일부 데이터만으로 탐지했다는 사실을 숨기지 않기 위해서다.

---

## 4. 시간 모델

| 시간 | 정의 | 사용처 |
|------|------|--------|
| **이벤트 시간** `Packet.ts` | 패킷에 기록된 캡처 시각 (pcap 헤더나 시뮬레이터 시계) | 버킷 배정, 탐지 윈도우, 쿨다운, 경고 시각 |
| **처리 시간** `Packet.ingest_ts` | 큐에 넣은 벽시계 시각 | 지연(latency) 측정, 미래 패킷 판정 |
| **단조 시간** `time.monotonic()` | 시스템 시계 변경과 무관한 시각 | 발행 주기, 워치독, 전송 timeout |

**워터마크와 초 마감**
- `watermark = max(본 이벤트 시간) − allowed_lateness` (기본 1초. PCAP과 시뮬레이터는 설정 가능)
- 초 `s`는 `watermark ≥ s+1`이 되면 **마감**된다. 마감 시 탐지기를 평가하고 스냅샷을 발행한다.
- 스냅샷은 마감된 초 버킷 60개다. 즉 `[floor(watermark)−60, floor(watermark))` 구간이다. 진행 중인 초는 넣지 않는다.
- **유휴 진행**: Live 모드에서 패킷이 없으면 `벽시계 − lateness`로 워터마크를 전진시켜, 트래픽이 끊긴 시간도 0으로 표시한다. PCAP과 시뮬레이터 모드는 이벤트 시간으로만 전진하고, 입력이 끝나면 남은 초를 모두 마감한다.

**예외 패킷 처리**
| 상황 | 판정 | 처리 |
|------|------|------|
| 순서 뒤바뀜 (아직 마감 안 된 초) | `ts ≥ 마감된 마지막 초 + 1` | 정상 반영 |
| 늦은 패킷 | 이미 마감된 초에 속함 | 폐기하고 `health.late_dropped++` |
| 미래 패킷 (Live만) | `ts > ingest_ts + 5초` (시계 오차) | 폐기하고 `health.future_dropped++` |

---

## 5. 모듈 설계

```
netscope/
├── models.py        # Packet, Classification, Alert, Episode(정답 라벨)
├── clock.py         # Watermark, 마감 로직
├── flows.py         # FlowTable: 5-tuple 상태, 개시자, TCP 상태 전이
├── protocols.py     # 서비스 포트 테이블, Flow 기반 분류, 주소 scope
├── bounded.py       # SpaceSaving(top-K), CappedSet 등 상한이 있는 자료구조
├── analyzer.py      # TrafficAnalyzer: 버킷, 엣지 상한, other 합산
├── anomaly.py       # 4종 탐지기 + Thresholds
├── pipeline.py      # Queue, AnalyzerWorker, Publisher
├── sources/         # live.py, pcap.py, sim.py
├── server.py        # FastAPI, WebSocket 송신 큐
├── evaluate.py      # 정답 라벨 대비 Precision, Recall, 탐지 지연
└── static/
bench/               # 처리량, 지연, 메모리 벤치마크
tests/
```

### 5.1 데이터 모델
```python
Packet(ts, ingest_ts, src, dst, proto, length, sport=None, dport=None, flags="")
Classification(name="HTTPS", method="port+direction", confidence="medium")
#   method: port+direction | port-heuristic | l4     (v2: payload)
#   confidence: high | medium | low
Alert(ts, type, severity, confidence, key, message, details, id)
Episode(type, key, start, end)       # 시뮬레이터가 내보내는 정답 라벨
```

### 5.2 FlowTable (`flows.py`)
- 키: 방향을 무시한 5-tuple `(proto, (ipA, portA), (ipB, portB))`, 정렬해서 만든다.
- 항목: `initiator`, `server_port`, `state`, `first_ts`, `last_ts`, `pkts`, `bytes`, `syn_count`, `bidirectional`, `classification`
- `initiator` 결정: TCP는 순수 SYN을 보낸 쪽이다. UDP는 Flow에서 처음 본 패킷의 출발지다(질의를 보낸 쪽일 가능성이 높음).
- TCP 상태 전이: `SYN_SENT → SYNACK_SEEN → ESTABLISHED → CLOSING/CLOSED`. 같은 4-tuple로 SYN이 다시 오면 **재전송**으로 센다.
- 상태 전이가 일어날 때 탐지기에 이벤트를 보낸다: `new_syn`, `syn_retrans`, `synack`, `handshake_done`. 탐지기는 패킷이 아니라 이 이벤트를 센다.
- 상한: `max_flows = 200_000`. 유휴 timeout은 TCP 120초(완료 후 10초), UDP 30초. 넘치면 가장 오래 쓰지 않은 Flow부터 축출하고 `health.flow_evictions++`. 축출된 Flow도 이미 낸 이벤트는 카운터에 반영되어 있으므로 탐지가 깨지지 않는다.

### 5.3 프로토콜 분류 (`protocols.py`)
Flow 단위로 **한 번** 분류해서 저장해 두고, 같은 Flow의 모든 패킷에 같은 결과를 쓴다.

1. **개시자를 아는 경우** (SYN을 봤거나 UDP 첫 패킷): 응답자 쪽 포트를 서비스 테이블에서 찾는다. → `port+direction`, `medium`
2. **개시자를 모르는 경우** (캡처 시작 전에 열린 연결): 휴리스틱 → `port-heuristic`, `low`
   - 두 포트 중 하나만 테이블에 있으면 그 포트를 쓴다.
   - 둘 다 있으면 에피메럴이 아닌 쪽(< 49152, OS 범위는 설정 가능)을 고른다. 그래도 같으면 처음 본 패킷의 목적지 포트를 고른다.
3. 테이블에 없으면 L4 이름(TCP, UDP, ICMP, ARP)을 쓴다. → `l4`, `high`
- 포트만으로 추정한 결과는 UI에서 `HTTPS (추정)`으로 표시하고, 툴팁에 근거(method)를 보여 준다. 실제 TLS나 DNS 확인(`payload`, `high`)은 v2에서 한다.
- 리뷰 예시인 `192.168.0.2:22 → 8.8.8.8:443`에 적용하면: SYN을 봤을 때는 응답자 포트 443 → **HTTPS (medium)**. SYN을 못 봤을 때는 22와 443이 모두 테이블에 있고 둘 다 에피메럴이 아니므로, 처음 본 패킷의 목적지 포트 443 → **HTTPS (low)**.

### 5.4 이상 탐지 (`anomaly.py`)
모든 윈도우는 **1초 슬롯 링버퍼**로 만든다. 그래서 키 하나당 메모리가 O(윈도우 초 수)로 고정된다. 경고 문구는 모두 "의심"으로 쓰고, 공격이라고 단정하지 않는다.

| 탐지기 | 신호 (집계 키) | 발생 조건 (기본값) | severity / confidence |
|--------|----------------|--------------------|-----------------------|
| **port_scan** | 출발지별 `new_syn`의 서로 다른 목적지 포트 수 (재전송 제외) | 10초 동안 포트 20개 이상 | high / medium |
| **syn_flood** | `(dst_ip, dst_port)`별 `new_syn`, `syn_retrans`, `synack`, `handshake_done`, 서로 다른 출발지 수 | 아래 규칙 참고 | 아래 규칙 참고 |
| **dns_flood** | 출발지별 UDP/53 질의 수 | 10초 동안 80건 이상 **그리고** 10개 슬롯 중 6개 이상이 0이 아님(지속성) | medium / medium |
| **traffic_spike** | 전체 초당 바이트 (EWMA α=0.1) | 학습 10초 후, 평균+4σ 초과 **그리고** 평균의 3배 초과 **그리고** 50KB 이상 | low / medium |

**syn_flood 규칙** (5초 윈도우, 서비스 단위)
1. 전제: `new_syn ≥ 100`이고 `new_syn ≥ 3 × 해당 서비스의 EWMA 기준선`. 갑작스러운 증가만 본다.
2. **재전송 비율** `syn_retrans / new_syn ≥ 0.5`이면 발생하지 않는다. 서버가 응답하지 않을 때 정상 클라이언트들이 재전송하는 상황(장애)이기 때문이다. 위조된 출발지를 쓰는 플러드 도구는 재전송하지 않는다.
3. **양방향이 보이는 캡처**일 때: 반개방 비율 `1 − handshake_done / new_syn ≥ 0.8`이면 경고하고 `confidence=medium`.
4. **단방향만 보이는 캡처**일 때 (최근 Flow 중 양방향 비율이 5% 미만): 1번과 2번만으로 경고하고 `confidence=low`. 메시지에 "단방향 캡처라 완료율 미확인"을 적는다.
5. 서로 다른 출발지가 50곳 이상이면(분산 또는 위조 출발지) severity를 high로, 아니면 medium으로 한다.
- 포트 스캔과의 이중 보고를 막는 방법: 집계 키에 목적지 포트가 들어가므로, 스캔 트래픽은 포트마다 몇 개씩 흩어져 1번 조건에 걸리지 않는다.

**traffic_spike 보완**
- 급증한 초는 기준선에 반영하지 않는다(baseline poisoning 방지).
- 다만 **연속 10초 이상** 급증이 이어지면 새 정상 수준으로 보고 기준선을 다시 잡는다. 정상적인 대용량 다운로드가 경고를 최대 1건만 내고, 쿨다운마다 반복 경고하지 않게 하기 위해서다.
- 의미는 "볼륨 이상"이고 공격 판정이 아니다. 그래서 severity를 low로 한다.

**공통**
- 쿨다운: 같은 `(type, key)`는 이벤트 시간 기준 30초 동안 다시 보내지 않는다.
- 허용 목록(allowlist): 로컬 DNS 리졸버, 스캐너 서버 같은 IP나 CIDR을 탐지기별로 제외할 수 있다.
- 모든 임계값은 `Thresholds`에 모은다. 벤치마크에서 임계값을 바꿔 가며 실험할 때도 이것을 쓴다.

### 5.5 주소 분류
- `local`(bool): `--local-net`으로 지정한 CIDR 목록이 있으면 그것을 쓴다. 지정하지 않으면 캡처 인터페이스의 주소와 넷마스크를 자동 감지하고, 그것도 안 되면 RFC1918(10/8, 172.16/12, 192.168/16)과 ULA(fc00::/7)를 **명시적으로** 쓴다.
- `scope`: `loopback | link_local | rfc1918 | ula | cgnat | multicast | documentation | reserved | public`. `ipaddress.is_private`는 문서용이나 벤치마크용 대역까지 포함하므로 쓰지 않고, 대역을 직접 비교한다.
- 그래프의 노드 색은 `local`로 정하고, 툴팁에 `scope`를 표시한다.

### 5.6 TrafficAnalyzer (`analyzer.py`)
- 1초 버킷에는 프로토콜별 `[pkts, bytes]`(종류 수가 유한하므로 정확히 셈)와 엣지 맵을 둔다.
- 버킷 하나에 엣지는 최대 `max_edges_per_bucket = 5_000`개다. 넘치면 Space-Saving 방식으로 바이트가 가장 작은 엣지를 `other`에 합산하고 축출한다. → `totals`와 `protocols` 합계는 항상 정확하고, 엣지 단위 정보만 근사치가 된다.
- 스냅샷의 그래프는 상위 200개 엣지다. 나머지는 `graph.other = {edges, packets, bytes}`로 합산하고, 화면에는 "기타 N개 연결" 노드로 표시한다.

### 5.7 Sources
- **PcapSource**: `scapy.utils.PcapReader`로 스트리밍한다(전체를 메모리에 올리지 않음). 속도 옵션은 `--speed max | 1x | Nx`이고, 테스트에서는 `max`를 쓴다.
- **LiveSource**: `AsyncSniffer(iface, filter=bpf, store=False, prn=enqueue)`. Npcap과 관리자 권한이 필요하다.
- **SimulatedSource**: 시드로 고정되는 결정적 생성기다. 정상 트래픽에 공격 시나리오를 섞고, 공격마다 **`Episode` 정답 라벨**을 함께 내보낸다. 정상 상황을 재현하는 시나리오(§8.2)도 생성할 수 있다.
- 공통 인터페이스는 `start() / stop() / stats()`이다. 재시작해도 큐와 워커는 그대로 유지된다.

### 5.8 서버와 대시보드
| 엔드포인트 | 설명 |
|------------|------|
| `GET /` | 대시보드 |
| `GET /api/status` | 모드, 소스 상태, PPS, 가동 시간, `health` 카운터 |
| `GET /api/snapshot` | 최신 불변 스냅샷 |
| `GET /api/alerts?since_id=` | 경고 이력 (링버퍼 500건). 재접속한 클라이언트의 누락분 복구용 |
| `POST /api/source/{start,stop}` | 소스 중지와 재시작 |
| `WS /ws` | `snapshot`(최신 값만 전달)과 `alert`(순서 보장, 큐 100) |

대시보드 화면 구성은 v1과 같다: 프로토콜 시계열, 비율 도넛, D3 연결 그래프, 경고 목록, 통신량 상위 호스트. 여기에 다음을 추가한다.
- 상단 **health 배지**: 손실, 지연 폐기, 축출, 단방향 캡처 여부
- 프로토콜 이름의 `(추정)` 표기와 근거 툴팁
- 경고 카드에 confidence 표시
- 그래프의 `기타` 노드

---

## 6. 자원 상한

| 상태 | 상한 | 초과 시 처리 | 카운터 |
|------|------|--------------|--------|
| Packet Queue | 100,000 | 새 패킷 폐기 | `dropped` |
| FlowTable | 200,000 Flow | 가장 오래 쓰지 않은 Flow 축출 | `flow_evictions` |
| 버킷당 엣지 | 5,000 | Space-Saving 축출 후 `other`에 합산 | `edge_evictions` |
| 탐지기 키 (포트 스캔·DNS: 출발지, 플러드: 서비스) | 각 10,000 | Space-Saving (가장 작은 항목 축출) | `detector_evictions` |
| 스캔 대상 포트 집합 | 출발지당 256 | 집합에 더 넣지 않음 ("256+"로 표시) | 없음 |
| 플러드 출발지 집합 | 서비스당 1,024 | 집합에 더 넣지 않음 ("1024+"로 표시) | 없음 |
| 경고 이력 | 500 | 링버퍼 | 없음 |
| 클라이언트 송신 큐 | snapshot 1, alert 100 | 연결 종료 1013 | `ws_slow_disconnects` |

- 축출 대상으로 LRU 대신 Space-Saving을 쓰는 이유: 공격자가 의미 없는 키를 대량으로 만들어 큰 항목(실제 공격자)을 밀어내는 우회 공격에 강하기 때문이다.
- 메모리 계산(대략): Flow 20만 개 × 약 400B ≈ 80MB, 엣지 5천 개 × 60초 × 약 300B ≈ 90MB, 큐 10만 개 × 약 200B ≈ 20MB. 합계 약 200MB이고, G6의 400MB 이내다.

---

## 7. 개발 순서와 완료 기준

| 단계 | 내용 | 완료 기준 |
|------|------|-----------|
| **1. Core Engine** | models, clock, flows, protocols, bounded, analyzer | §8.1 단위 테스트 중 분류, 집계, 시간, 상한 테스트 통과 |
| **2. Detection** | anomaly, sim(정답 라벨 포함), evaluate | 탐지 테스트와 §8.2 시나리오 테스트 통과. 기본 시나리오 Recall ≥ 0.95, Precision ≥ 0.9 |
| **3. Pipeline & Dashboard** | pipeline, server, static | WebSocket 클라이언트 20개, 느린 클라이언트, 재시작 테스트 통과. 대시보드 수동 확인 |
| **4. Real Traffic** | pcap, live | 공개 PCAP 샘플 재생 결과가 `tshark` 통계(패킷 수, 프로토콜 분포)와 ±1% 이내. Live 모드 동작 확인 |
| **5. Benchmark & Docs** | bench/, README, 기술 보고서 | §9 실험 결과 표와 그래프 작성 |

---

## 8. 테스트 전략

### 8.1 단위 테스트 (입력 → 기대 결과)
| 영역 | 입력 | 기대 결과 |
|------|------|-----------|
| 분류 | SYN `a:51000 → b:443` | HTTPS, `port+direction`, medium |
| 분류 | SYN `a:22 → b:443` (리뷰 사례) | HTTPS (SSH 아님) |
| 분류 | SYN 없이 시작된 `a:22 ↔ b:443`, 처음 본 패킷 목적지가 443 | HTTPS, low |
| 분류 | UDP `a:51000 → b:53` 후 응답 `b:53 → a:51000` | 두 패킷 모두 DNS, 같은 Flow |
| 분류 | TCP `54321 → 55555` | TCP, `l4` |
| 주소 | `192.0.2.1` (문서용 대역) | `local=False`, scope=documentation |
| 주소 | `100.64.0.1` | scope=cgnat |
| 집계 | HTTPS 100B×10 + DNS 50B×5 | totals 15개·1250B, 프로토콜별 합계 일치 |
| 그래프 | A→B 300B, B→A 700B | 엣지 하나, 1000B, 2패킷 |
| 시간 | 같은 초 안에서 순서가 뒤바뀐 패킷 | 정상 반영, 합계 일치 |
| 시간 | 마감된 초에 속하는 늦은 패킷 | 반영 안 됨, `late_dropped=1` |
| 시간 | Live 모드, `ts = ingest_ts + 10초` | 폐기, `future_dropped=1` |
| 시간 | 패킷 없이 5초 경과 (Live) | 해당 초들이 0으로 마감되어 스냅샷에 포함 |
| 상한 | 고유 출발지 10만 개의 SYN, 1초 | 엣지 ≤ 5,000, `other`에 합산, **totals는 정확**, `edge_evictions > 0` |
| 상한 | 큐 용량 10, 패킷 100개 투입 (워커 정지 상태) | 큐 10개, `dropped=90` |
| 포트 스캔 | 3초 동안 포트 30개에 new_syn | 경고 1건, 쿨다운으로 중복 없음 |
| 포트 스캔 | 같은 포트로 SYN 재전송 30회 | 경고 없음 |
| SYN 플러드 | 위조 출발지 300곳 → `:80`, 완료 0, 양방향 캡처 | syn_flood, high, medium |
| SYN 플러드 | 단방향 캡처에서 같은 입력 | syn_flood, confidence=low |
| SYN 플러드 | 정상 핸드셰이크 300건 완료 | 경고 없음 |
| SYN 플러드 | 포트 500개 스캔 (한 목적지) | port_scan만 발생, syn_flood 없음 |
| DNS | 지속적인 질의 (4.8초 동안 120건, 슬롯 6개 이상) | dns_flood |
| 급증 | 30초 동안 10KB/s 후 1초 동안 500KB | traffic_spike 1건 |

### 8.2 시나리오 테스트 (시뮬레이터 + 평가기)
| 시나리오 | 검증 목적 | 기대 결과 |
|----------|-----------|-----------|
| 정상 트래픽 120초 | 기본 오탐 | 경고 0건 |
| 정상 대용량 HTTPS 다운로드 (5MB/s, 60초 지속) | 급증 오탐 억제 | traffic_spike 최대 1건(low), 기준선 재설정 후 추가 경고 없음 |
| 정상 DNS 버스트 (페이지 로드: 1초에 60건, 30초 간격) | DNS 오탐 | 경고 0건 (지속성 조건) |
| 서버 장애로 정상 클라이언트 20대가 SYN 재전송 | SYN 플러드 오탐 | syn_flood 0건 |
| NAT 게이트웨이 (한 IP에서 정상 연결 수천 개) | 스캔/플러드 오탐 | 경고 0건 |
| 공격 4종 주입 (20초 간격) | 탐지 성능 | Recall ≥ 0.95, Precision ≥ 0.9, 탐지 지연 P95 ≤ 3초 |
| 순서가 섞인 입력 (±500ms 지터) | 윈도우 정확성 | 지터가 없을 때와 스냅샷 합계 동일 |

평가기(`evaluate.py`) 매칭 규칙: 경고와 Episode는 `type`이 같고, `key`가 같고, `alert.ts ∈ [start, end + 5초]`이면 일치로 본다. 이를 바탕으로 Precision, Recall, 탐지 지연(alert.ts − start)과 정상 시나리오의 시간당 오탐 수를 계산한다.

### 8.3 통합 테스트
| 시나리오 | 기대 결과 |
|----------|-----------|
| WebSocket 클라이언트 20개 동시 접속, 60초 | 모두 초당 스냅샷 1개 ±1 수신, 경고 누락 0 |
| 수신하지 않는 느린 클라이언트 1개 + 정상 클라이언트 5개 | 느린 클라이언트만 1013으로 끊김, 나머지는 영향 없음, 서버 메모리 증가 없음 |
| 소스 stop 후 start | 스레드 누수 없음, 카운터 이어짐, 스냅샷 계속 발행 |
| 서버 종료 (lifespan) | 캡처 스레드와 워커가 2초 안에 종료 |

---

## 9. 벤치마크와 실험 계획 (포트폴리오 핵심)

**연구 질문**: Python 기반 트래픽 분석기가 메모리 상한을 지키면서, 규칙 기반 이상 탐지의 정확성과 실시간성을 어디까지 확보할 수 있는가?

| 실험 | 변수 | 측정값 |
|------|------|--------|
| E1 단계별 처리량 | 파서(Scapy / dpkt) × 분석기 | 단계별 최대 PPS (병목 위치 확인) |
| E2 큐 크기와 손실 | 큐 크기 1k~1M × 입력 PPS | 손실률, 메모리, 지연 |
| E3 지연 분포 | lateness 0.5~3초 | 이벤트에서 화면까지 지연 P50/P95/P99, 늦은 패킷 폐기율 |
| E4 메모리 상한 | 고유 IP/초 1k~1M | RSS 변화 (상한이 있을 때와 없을 때 비교) |
| E5 임계값 민감도 | 탐지기별 임계값 | Precision-Recall 곡선 |
| E6 상한이 정확도에 미치는 영향 | 탐지기 키 상한 1k~100k + 키 대량 생성 우회 공격 | 우회 공격 하의 Recall (LRU와 Space-Saving 비교) |

결과는 `bench/results/`에 CSV와 그래프로 저장하고, README와 기술 보고서에 정리한다.

---

## 10. 한계
- 포트 기반 분류는 추정이다. 비표준 포트나 터널링된 트래픽은 L4로 분류되거나 잘못 분류될 수 있다(confidence로 드러냄).
- 캡처 위치에 따라 양방향 패킷을 다 못 볼 수 있다. 이 경우 SYN 플러드 판정의 신뢰도가 떨어진다(confidence=low로 표시).
- Scapy 파싱이 처리량의 상한이다. E1 결과에 따라 dpkt 교체를 검토한다.
- 인증이 없으므로 로컬 전용이다. 원격으로 노출하는 것은 지원하지 않는다.

---

## 11. 로드맵 (v2 이후)
- 페이로드 메타데이터 파서: TLS SNI, DNS 질의 이름 → 분류 confidence high, 도메인 표시
- DNS 터널링 탐지: 질의 길이, 고유 서브도메인 비율, 엔트로피, TXT 레코드 비율
- 수평 스캔, ARP 스푸핑, 비정상 아웃바운드 포트, 호스트별 대용량 외부 전송 탐지
- 시간대별 기준선, SQLite 이력 저장, 지오IP 지도, 임계값 UI 조정
