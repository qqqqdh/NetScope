# NetScope

[![test](https://github.com/qqqqdh/NetScope/actions/workflows/test.yml/badge.svg)](https://github.com/qqqqdh/NetScope/actions/workflows/test.yml)

실시간 네트워크 트래픽 분석기. 패킷을 수집해 프로토콜별 통신량, IP 연결 관계, 이상 트래픽을 실시간으로 시각화한다.
설계: [DESIGN.md](DESIGN.md) (v3.1)

## 설치

Python 3.11 이상 (검증: 3.12, 3.13 / Windows, Ubuntu).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt      # 검증한 버전 고정
pip install -e . --no-deps           # netscope 명령 등록
```

> Windows에서 PATH의 `python`이 MSYS2 빌드(`C:\msys64\...`)면 pydantic 등의 바이너리 휠이 없어 설치가 실패할 수 있다. python.org의 공식 CPython으로 venv를 만든다.

## 실행

```bash
python -m netscope                                   # 시뮬레이터, http://127.0.0.1:8000
python -m netscope --speed 3 --attack-interval 20    # 빠른 데모
python -m netscope --config netscope.example.toml    # 설정 파일 사용
```

### 프로그램별 통신량과 기록 보기

실제 캡처를 실행한 뒤 `http://127.0.0.1:8000`의 아래쪽 패널을 확인한다.

```powershell
.\.venv\Scripts\python.exe -m netscope --mode live --iface "Wi-Fi"
```

- **프로세스별 통신량(추정)**: 프로그램 이름·PID, 이번 실행에서 대응한 송수신 누적 바이트,
  현재 소켓 수를 보여 준다. 상위 20개를 표시하며 패킷 헤더 길이를 포함한다.
  `psutil`로 OS 연결 표를 1초마다 읽어 패킷의 주소·포트와 대조한다.
  짧은 연결, 권한 제한, 공유 소켓, 다른 장치의 패킷은 대응하지 못할 수 있다.
  대응하지 못한 바이트를 별도 표시하며, 모호한 공유 소켓은 임의로 배정하지 않는다.
  메모리 상한은 프로세스 식별자 512개다. 로컬 양 끝에 프로세스가 있으면 송신 쪽에 배정한다.
  시뮬레이터·PCAP에서는 이 기능을 사용하지 않는다. 일시정지·재개 시 누적값은 유지되고 서버 재시작 시 초기화된다.
- **통계·경고 이력**: 통계는 발행되는 스냅샷에서 약 10초마다, 경고는 발생할 때 저장한다.
  종류·모드별 조회 및 CSV 다운로드를 지원한다. LIVE/SIM/PCAP과 실행 식별자를 함께 저장해
  재시작하거나 모드를 바꿔도 기록을 구분한다. 최근 60초 통신량은 겹치는 구간이므로 여러 행을 합산하지 않는다.
- CLI 실행은 현재 폴더의 `netscope-history.sqlite3`에 기본 저장한다. 패킷 원문과 프로세스별 누적값은 저장하지 않는다.
  기록에는 경고의 IP 등 메타데이터가 포함될 수 있다. 저장 시 최근 7일만 유지하며 통계 10만 건·경고 1만 건으로 제한한다.
  저장 지연으로 큐가 차거나 디스크 오류가 나면 수집은 계속하고 이력 패널에 저장 누락을 표시한다.
  화면은 최신 50건, CSV는 최신 1만 건을 제공한다. `create_app()`을 직접 쓰는 경우 `history="경로"`로 저장을 켠다.

```powershell
# 다른 파일에 저장
.\.venv\Scripts\python.exe -m netscope --mode live --iface "Wi-Fi" --history "my-history.sqlite3"
# 저장 끄기 (PowerShell에서도 확실하게 빈 값 전달)
.\.venv\Scripts\python.exe -m netscope --history=
```

업데이트 후에는 실행 중인 서버를 `Ctrl+C`로 종료하고 다시 실행한다.
의존성 설치는 `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.
API: `/api/processes`, `/api/history?kind=stats&mode=live`,
`/api/history?kind=alerts&format=csv&limit=10000`.

설정 파일(`netscope.example.toml` 참고)로 서버 옵션, 탐지 임계값, 탐지기별 허용 목록(CIDR)을 지정한다.
CLI 인자가 설정 파일보다 우선하고, 알 수 없는 키(오타)는 오류로 알린다.

> **보안**: 인증이 없다. 기본은 `127.0.0.1` 바인딩이고, 루프백이 아닌 주소로 띄우면 경고를 출력한다.

시뮬레이터는 정상 트래픽 위에 포트 스캔 → SYN 플러드 → DNS 폭주 → 트래픽 급증을 `--attack-interval`초(시뮬레이터 시간)마다 돌아가며 주입한다.
대시보드 화면만 확인하려면 `/?mock=1` (서버 데이터 대신 브라우저 내부 가짜 데이터).

### PCAP 재생과 실제 캡처

```bash
python -m netscope --mode pcap --pcap capture.pcap --speed 0   # 대시보드로 재생 (0 = 최대 속도, N = N배속)
python -m netscope --mode live --iface "Wi-Fi" --bpf "ip"         # 실제 캡처 (아래 주의)
```

- pcap과 pcapng를 모두 읽는다. PCAP 재생은 큐가 차면 패킷을 버리지 않고 기다리므로, 기계 속도와 상관없이 결과가 같다.
- live는 Windows 11 + Npcap 1.90 + Wi-Fi에서 검증했다. Windows는 [Npcap](https://npcap.com) 설치가 필요하고
  (설치 시 '관리자 전용' 옵션을 켜지 않으면 관리자 권한 없이 캡처 가능), Linux는 root(또는 CAP_NET_RAW)가 필요하다.
- 캡처 소켓에서 원시 바이트를 받아 빠른 파서로 처리한다(`--live-parser fast`, 기본). 같은 부하에서 NIC 카운터 대비
  캡처율이 빠른 파서 **100%**, Scapy 분해 경로(`--live-parser scapy`) **81.9%** 였다(`bench/results/live_capture.txt`).

### 오프라인 분석

```bash
python -m netscope.replay capture.pcap --alerts-json alerts.json   # 서버 없이 최대 속도로 분석
python -m netscope.replay --generate attacks:100 attacks.pcap      # 시뮬레이터로 테스트용 PCAP 생성
```

출력에는 단계별 처리량이 나온다. 개발 PC 측정치(시뮬레이터 PCAP 3만 패킷): 파싱 약 82,000 pps / 분석 약 29,000~49,000 pps.
분석 처리량은 실행마다 편차가 커서(한 번 측정 29k, 워밍업 후 측정 49k) 한 번 잰 값을 그대로 쓰지 않는다. 분석 단계에는 두드러진 병목이 없고(프로파일상 Flow·집계·탐지에 고르게 분산) 패킷당 약 20µs의 순수 Python 비용이다.
파서는 struct 기반으로 직접 구현했다. Scapy 파서(약 1,100 pps)는 기준 구현으로 남겨 결과가 같은지 테스트로 확인한다.

## 테스트와 평가

```bash
python -m pytest -q
python -m netscope.evaluate --seeds 1-20     # 평가 시드 (튜닝은 100-109)
```

평가 결과(`bench/results/`)는 시뮬레이터 기준이다. 시뮬레이터 공격은 임계값보다 확실히 강한 범위라
실제 환경 성능을 뜻하지 않는다. 공개 PCAP 데이터셋 평가는 4단계에서 추가한다.

## 벤치마크

```bash
python bench/e4_memory.py --pps 100000 --seconds 90 --workload spread   # 최악 부하 메모리
python bench/e5_threshold_sweep.py --seeds 100-109                       # 임계값 민감도 (PR 곡선 데이터)
python bench/latency.py --seconds 40                                     # 지연 지표 3종
```

결과 요약: [bench/results/RESULTS.md](bench/results/RESULTS.md)
— 최악 부하 메모리 306~361MB(상한 400MB), 표본 종단 지연 P95 1.99초, 약한 공격 포함 시 기본 임계값의 Recall 0.43~0.67.

## 라이선스

MIT

## 구조

| 모듈 | 역할 |
|------|------|
| `clock.py` | 이벤트 시간 워터마크, 초 마감, late/future 판정 |
| `flows.py` | Flow 상태 머신, SYN 재전송(ISN), 상태별 만료 |
| `protocols.py` | Flow 기반 프로토콜 분류(신뢰도), 주소 scope |
| `bounded.py` | Space-Saving, HyperLogLog, 정확→HLL 하이브리드 |
| `analyzer.py` | 정확 계층(합계·엣지) / 근사 계층(후보) |
| `engine.py` | 재정렬 버퍼 + 위 모듈을 묶은 결정적 코어 |
| `anomaly.py` | 탐지 4종 + 서비스 연결 장애 구분 |
| `pipeline.py` | 제한 큐 → 분석 워커 → 스냅샷 발행 |
| `server.py` | FastAPI REST + WebSocket(클라이언트별 송신 큐, ack) |
| `sources/sim.py` | 결정적 시뮬레이터 + 정답 라벨 |
| `sources/fastparse.py` | struct 기반 프레임 파서, pcap/pcapng 리더 |
| `sources/pcap.py` | PCAP 읽기·기록, 독립 집계기 |
| `sources/live.py` | 실제 캡처 (Scapy AsyncSniffer) |
| `sources/realtime.py` | 배속 재생 소스 (시뮬레이터·PCAP 공용) |
| `replay.py` | PCAP 오프라인 분석 CLI |
| `evaluate.py` | Precision/Recall, Wilson 신뢰구간 |
| `config.py` | TOML 설정 로딩, 외부 노출 경고 |
| `processes.py` | OS 연결 표와 live 패킷 대조, 프로세스별 통신량 추정 |
| `history.py` | 통계·경고 SQLite 저장, 보관 상한·오류 상태 |
| `static/` | 대시보드 (Chart.js, D3) |
