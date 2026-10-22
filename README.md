# NetScope

실시간 네트워크 트래픽 분석기. 패킷을 수집해 프로토콜별 통신량, IP 연결 관계, 이상 트래픽을 실시간으로 시각화한다.
설계: [DESIGN.md](DESIGN.md) (v3.1)

## 설치

```powershell
C:\Python\Python313\python.exe -m venv .venv     # PATH의 python은 MSYS2 빌드라 쓰지 않는다
.\.venv\Scripts\python.exe -m pip install fastapi "uvicorn[standard]" scapy pytest httpx
```

## 실행

```powershell
.\.venv\Scripts\python.exe -m netscope                       # 시뮬레이터, http://127.0.0.1:8000
.\.venv\Scripts\python.exe -m netscope --speed 3 --attack-interval 20   # 빠른 데모
```

시뮬레이터는 정상 트래픽 위에 포트 스캔 → SYN 플러드 → DNS 폭주 → 트래픽 급증을 `--attack-interval`초(시뮬레이터 시간)마다 돌아가며 주입한다.
대시보드 화면만 확인하려면 `/?mock=1` (서버 데이터 대신 브라우저 내부 가짜 데이터).

실제 캡처(`--mode live`)와 PCAP 재생(`--mode pcap`)은 4단계에서 추가한다.

## 테스트와 평가

```powershell
.\.venv\Scripts\python.exe -m pytest -q                       # 87개, 약 40초
.\.venv\Scripts\python.exe -m netscope.evaluate --seeds 1-20  # 평가 시드 (튜닝은 100-109)
```

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
| `evaluate.py` | Precision/Recall, Wilson 신뢰구간 |
| `static/` | 대시보드 (Chart.js, D3) |
