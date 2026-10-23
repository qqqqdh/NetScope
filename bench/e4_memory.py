"""E4: 최악 부하에서 메모리(RSS) 실측 (DESIGN §6.2, §9).

모든 상한 구조를 동시에 넘치게 하는 합성 부하를 CoreEngine + AnomalyDetector에 넣는다.
  - 위조 출발지 SYN → 6,000개 서비스 (SYN 키 상한 5,000 초과, FlowTable 상한 초과)
  - 스캐너 12,000곳이 각자 64개 이상 포트 (스캔 키 상한 10,000 초과)
  - 20,000곳의 DNS 질의 (DNS 키 상한 10,000 초과)
  - 고유 UDP 엣지 (엣지 상한 5,000/버킷 초과)
서버 실행과 같은 조건이 되도록 FastAPI·Scapy를 먼저 import한 뒤의 RSS를 기준선으로 잰다.

    python bench/e4_memory.py --pps 100000 --seconds 90
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fastapi  # noqa: E402,F401  (서버와 같은 기준선)
import scapy.all  # noqa: E402,F401

from netscope.anomaly import AnomalyDetector  # noqa: E402
from netscope.engine import CoreEngine  # noqa: E402
from netscope.memory import rss_bytes  # noqa: E402
from netscope.models import Packet  # noqa: E402


def mb() -> float:
    return rss_bytes() / 1e6


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pps", type=int, default=100_000, help="이벤트 시간 기준 초당 패킷 수")
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--workload", choices=["spread", "concentrated"], default="spread",
                    help="spread: 모든 키 상한 포화 / concentrated: 적은 키에 공격 집중(경고 대량 발생)")
    ap.add_argument("--max-flows", type=int, default=None, help="FlowTable 상한 (기본: 엔진 기본값)")
    ap.add_argument("--keep-alerts", type=int, default=0,
                    help="탐지기 경고 보관 개수 (서버와 같은 0). -1이면 무제한(누수 재현용)")
    ap.add_argument("--tracemalloc", action="store_true", help="끝에 메모리를 많이 쓴 코드 위치 상위 15개 출력 (느려짐)")
    a = ap.parse_args()
    if a.tracemalloc:
        import tracemalloc
        tracemalloc.start()

    rnd = random.Random(a.seed)
    base = mb()
    eng = CoreEngine(**({"max_flows": a.max_flows} if a.max_flows else {}))
    det = AnomalyDetector(eng, keep_alerts=None if a.keep_alerts < 0 else a.keep_alerts)
    fired = 0
    svc_ips = [0x0A000001 + i for i in range(6)]                 # 10.0.0.1~6 × 포트 1,000개 = 6,000 서비스
    scanners = [0x2D000000 + i for i in range(12_000)]          # 45.0.x.x
    dns_src = [0xC0A80000 + i for i in range(20_000)]           # 192.168.x.x
    target, resolver = 0x0A090909, 0x08080808
    peak, t_start, n = base, time.perf_counter(), 0
    # 유형별 독립 카운터: i에서 파생하면 i % 10 조건과 얽혀 일부 키만 나오는 문제가 있었다
    # (초기 실행에서 SYN 키 2,600 / DNS 키 4,000에서 멈춰 상한에 도달하지 못함)
    n_scan = 0
    print(f"기준선(FastAPI·Scapy import 후) RSS {base:.0f} MB, 부하 {a.pps:,} pps × {a.seconds}초 (이벤트 시간)")
    for sec in range(a.seconds):
        t0 = 1_000_000.0 + sec
        for i in range(a.pps):
            ts = t0 + i / a.pps
            k = i % 10
            if a.workload == "concentrated":
                # 초기 버전 부하: i에서 키를 파생해 키 수는 적지만(SYN 2,600 / DNS 4,000 / 스캐너 3,600)
                # 키마다 공격이 집중돼 경고가 대량으로 나온다
                if k < 4:
                    p = Packet(ts, rnd.getrandbits(32) | 0x01000000, svc_ips[i % 6], "TCP", 60,
                               rnd.randint(1024, 65535), 1000 + (i // 6) % 1000, "S", rnd.getrandbits(32))
                elif k < 7:
                    p = Packet(ts, scanners[i % 12_000], target, "TCP", 58, 40000,
                               1 + (i // 12_000 + sec * 7) % 200, "S", i)
                elif k < 9:
                    p = Packet(ts, dns_src[i % 20_000], resolver, "UDP", 80, 1024 + i % 60000, 53)
                else:
                    p = Packet(ts, rnd.getrandbits(32), rnd.getrandbits(32), "UDP", 100, 5000, 6000)
            elif k < 4:                                          # SYN 플러드 (위조 출발지)
                svc = rnd.randrange(6000)
                p = Packet(ts, rnd.getrandbits(32) | 0x01000000, svc_ips[svc % 6], "TCP", 60,
                           rnd.randint(1024, 65535), 1000 + svc // 6, "S", rnd.getrandbits(32))
            elif k < 7:                                          # 스캐너
                s = scanners[n_scan % 12_000]
                p = Packet(ts, s, target, "TCP", 58, 40000, 1 + (n_scan // 12_000) % 200, "S", n_scan)
                n_scan += 1
            elif k < 9:                                          # DNS
                p = Packet(ts, dns_src[rnd.randrange(20_000)], resolver, "UDP", 80, 1024 + i % 60000, 53)
            else:                                                # 고유 UDP 엣지
                p = Packet(ts, rnd.getrandbits(32), rnd.getrandbits(32), "UDP", 100, 5000, 6000)
            eng.ingest(p)
            n += 1
        fired += len(det.drain())
        if sec % 10 == 9 or sec == a.seconds - 1:
            now = mb()
            peak = max(peak, now)
            s = eng.sizes()
            print(f"  {sec + 1:>3}초: RSS {now:6.0f} MB  flows={s['flows']:,} "
                  f"scan_keys={len(det.scan.keys):,} syn_keys={len(det.syn.keys):,} dns_keys={len(det.dns.keys):,} "
                  f"edges/bucket≤{s['max_edges_in_bucket']:,}  ({n / (time.perf_counter() - t_start):,.0f} pps)",
                  flush=True)
    eng.flush()
    peak = max(peak, mb())
    print(f"최대 RSS {peak:.0f} MB (기준선 대비 +{peak - base:.0f} MB), 목표 ≤ 320 MB, 상한 400 MB → "
          f"{'통과' if peak <= 400 else '초과'}")
    print(f"health: {dict(eng.health.totals)}")
    print(f"경고 {fired:,}건 발생, 탐지기 보관 {len(det.alerts):,}건, 쿨다운 테이블 {len(det._last_fired):,}개")
    if a.tracemalloc:
        import tracemalloc
        snap = tracemalloc.take_snapshot().filter_traces(
            [tracemalloc.Filter(True, "*netscope*")])
        total = sum(s.size for s in snap.statistics("filename"))
        print(f"\nnetscope 코드가 할당한 메모리 합계 {total / 1e6:.0f} MB, 상위 15개 위치:")
        for st in snap.statistics("lineno")[:15]:
            fr = st.traceback[0]
            print(f"  {st.size / 1e6:7.1f} MB  {st.count:>9,}개  {Path(fr.filename).name}:{fr.lineno}")


if __name__ == "__main__":
    main()
