"""E3: lateness별 처리 대기 시간과 늦은 패킷 폐기율 (DESIGN §4, §9).

초당 300패킷을 실시간으로 넣되, 각 패킷의 이벤트 시각을 '도착 지연' 모델만큼 앞당긴다.
  지연 모델: 98%는 0~20ms, 2%는 0~2초 (드물게 크게 늦는 패킷)
실제 NIC 한 곳에서의 순서 뒤바뀜은 보통 이보다 훨씬 작다. 결과는 이 모델 기준으로만 해석한다.

    python bench/e3_lateness.py --seconds 20 --out bench/results/e3_lateness.csv
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscope.models import Packet  # noqa: E402
from netscope.pipeline import Pipeline, percentiles  # noqa: E402

LATENESS = (0.25, 0.5, 1.0, 2.0, 3.0)
PPS = 300


def delay(rnd: random.Random) -> float:
    return rnd.uniform(0, 0.02) if rnd.random() < 0.98 else rnd.uniform(0, 2.0)


def run(lateness: float, seconds: float, seed: int = 1) -> dict:
    pipe = Pipeline(live=True, lateness=lateness)
    rnd = random.Random(seed)
    stop = threading.Event()

    def source():
        i = 0
        start = time.time()
        while not stop.is_set():
            now = time.time()
            due = start + i / PPS
            if due > now:
                stop.wait(due - now)
                continue
            d = delay(rnd)
            pipe.offer(Packet(time.time() - d, 0x0A000001 + i % 50, 0x08080808, "UDP", 100,
                              40000 + i % 1000, 53))
            i += 1

    th = threading.Thread(target=source, daemon=True)
    pipe.start()
    th.start()
    time.sleep(seconds)
    stop.set()
    th.join()
    time.sleep(lateness + 1.5)                           # 마지막 초가 마감될 때까지
    pipe.stop()
    eng = pipe.engine
    lat = percentiles(eng.processing_latency) or {}
    return {"lateness_s": lateness, "offered": pipe.offered,
            "late_drop_rate": round(eng.health.totals.get("late_drop", 0) / max(pipe.offered, 1), 5),
            "wait_p50_s": lat.get("p50"), "wait_p95_s": lat.get("p95"), "wait_max_s": lat.get("max")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--out", default="bench/results/e3_lateness.csv")
    a = ap.parse_args()
    rows = []
    for L in LATENESS:
        r = run(L, a.seconds)
        rows.append(r)
        print(f"lateness {L:>4}s: 늦은 패킷 폐기 {r['late_drop_rate']:.3%}  처리 대기 P50 {r['wait_p50_s']}s  "
              f"P95 {r['wait_p95_s']}s  (패킷 {r['offered']:,})", flush=True)
    with Path(a.out).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"저장: {a.out}")


if __name__ == "__main__":
    main()
