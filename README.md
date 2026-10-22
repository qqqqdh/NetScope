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

설정 파일(`netscope.example.toml` 참고)로 서버 옵션, 탐지 임계값, 탐지기별 허용 목록(CIDR)을 지정한다.
CLI 인자가 설정 파일보다 우선하고, 알 수 없는 키(오타)는 오류로 알린다.

> **보안**: 인증이 없다. 기본은 `127.0.0.1` 바인딩이고, 루프백이 아닌 주소로 띄우면 경고를 출력한다.

시뮬레이터는 정상 트래픽 위에 포트 스캔 → SYN 플러드 → DNS 폭주 → 트래픽 급증을 `--attack-interval`초(시뮬레이터 시간)마다 돌아가며 주입한다.
대시보드 화면만 확인하려면 `/?mock=1` (서버 데이터 대신 브라우저 내부 가짜 데이터).

실제 캡처(`--mode live`)와 PCAP 재생(`--mode pcap`)은 4단계에서 추가한다.

## 테스트와 평가

```bash
python -m pytest -q                          # 약 40초
python -m netscope.evaluate --seeds 1-20     # 평가 시드 (튜닝은 100-109)
```

평가 결과(`bench/results/`)는 시뮬레이터 기준이다. 시뮬레이터 공격은 임계값보다 확실히 강한 범위라
실제 환경 성능을 뜻하지 않는다. 공개 PCAP 데이터셋 평가는 4단계에서 추가한다.

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
| `evaluate.py` | Precision/Recall, Wilson 신뢰구간 |
| `config.py` | TOML 설정 로딩, 외부 노출 경고 |
| `static/` | 대시보드 (Chart.js, D3) |
