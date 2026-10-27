"""E2: 큐 크기 × 입력 속도 → 손실률, 처리량, 큐 대기, 메모리 (DESIGN §9).

실시간 캡처와 같은 조건: 소스 스레드가 벽시계 속도로 offer()하고, 큐가 차면 버린다(queue_drop).
소스 스레드와 분석 워커가 같은 프로세스에서 Python GIL을 나눠 쓴다는 점도 그대로 반영된다.

    python bench/e2_queue.py --seconds 10 --out bench/results/e2_queue.csv
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscope.memory import rss_bytes  # noqa: E402
from netscope.pipeline import Pipeline, percentiles  # noqa: E402
from netscope.sources.realtime import PacedSource  # noqa: E402
from netscope.sources.sim import attack_scenario  # noqa: E402

RATES = (5_000, 10_000, 20_000, 40_000)
QUEUES = (1_000, 10_000, 50_000, 200_000)


def template() -> list:
    sim, dur = attack_scenario(100, repeat=1)            # 정상 + 공격 4종이 섞인 실제적인 패킷 구성
    return list(sim.run(dur))


def stream(tpl: list, rate: int, seconds: float):
    """템플릿을 순환하며 이벤트 시각을 rate pps 간격으로 다시 매긴 새 Packet을 만든다."""
    t0, n = 1_000_000.0, int(rate * seconds)
    for i in range(n):
        yield dataclasses.replace(tpl[i % len(tpl)], ts=t0 + i / rate, ingest_ts=0.0)


def run(tpl, rate: int, qmax: int, seconds: float) -> dict:
    pipe = Pipeline(queue_max=qmax)
    src = PacedSource(stream(tpl, rate, seconds), pipe.offer, speed=1.0, name="netscope-e2")
    peak_q, peak_rss = 0, 0
    pipe.start()
    src.start()
    t0 = time.time()
    while time.time() - t0 < seconds:
        time.sleep(0.1)
        peak_q = max(peak_q, pipe.queue.qsize())
        peak_rss = max(peak_rss, rss_bytes() or 0)
    elapsed = time.time() - t0
    src.stop()
    pipe.stop()
    processed = pipe.engine.processed + len(pipe.engine._buf)      # 재정렬 버퍼에서 대기 중인 것 포함
    qw = percentiles(pipe.queue_wait) or {}
    return {"rate_target": rate, "queue_max": qmax,
            "offered_pps": round(pipe.offered / elapsed), "processed_pps": round(processed / elapsed),
            "drop_rate": round(pipe._drops / max(pipe.offered, 1), 4),
            "queue_wait_p95_s": qw.get("p95"), "peak_queue": peak_q,
            "peak_rss_mb": round(peak_rss / 1e6)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--out", default="bench/results/e2_queue.csv")
    ap.add_argument("--rates", default=",".join(map(str, RATES)))
    ap.add_argument("--queues", default=",".join(map(str, QUEUES)))
    a = ap.parse_args()
    tpl = template()
    rows = []
    for rate in map(int, a.rates.split(",")):
        for q in map(int, a.queues.split(",")):
            r = run(tpl, rate, q, a.seconds)
            rows.append(r)
            print(f"입력 {rate:>6,} pps  큐 {q:>7,}: 실제 입력 {r['offered_pps']:>6,}  처리 {r['processed_pps']:>6,} pps  "
                  f"손실 {r['drop_rate']:6.1%}  큐 대기 P95 {r['queue_wait_p95_s']}s  최대 큐 {r['peak_queue']:,}  "
                  f"RSS {r['peak_rss_mb']}MB", flush=True)
    with Path(a.out).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"저장: {a.out}")


if __name__ == "__main__":
    main()
