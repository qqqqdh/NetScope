"""E5: 임계값 민감도 → Precision-Recall 곡선 데이터 (DESIGN §9).

"hard" 난이도 공격(임계값 아래~위로 넓게 퍼진 강도)에서 탐지기별 핵심 임계값에 배수 m을 곱해 가며
Precision / Recall / 정상 시나리오 오탐 수를 기록한다.

    python bench/e5_threshold_sweep.py --seeds 100-109 --out bench/results/e5_pr.csv

튜닝 시드(100~109)를 쓴다. 임계값 선택용 실험이므로 평가 시드(1~20)는 쓰지 않는다.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscope.anomaly import Thresholds  # noqa: E402
from netscope.evaluate import match, merge, run, summarize  # noqa: E402
from netscope.sources.sim import attack_scenario, benign_scenario  # noqa: E402

MULTIPLIERS = (0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0)
# 탐지기별로 배수를 곱할 핵심 임계값
KNOBS = {
    "port_scan": ("scan_ports",),
    "syn_flood": ("syn_min",),
    "dns_flood": ("dns_queries",),
    "traffic_spike": ("spike_factor", "spike_min_bytes"),
}
BENIGN = ("baseline", "big_download", "dns_burst", "outage", "nat")


def scaled(m: float) -> Thresholds:
    base = Thresholds()
    changes = {}
    for names in KNOBS.values():
        for n in names:
            v = getattr(base, n)
            changes[n] = type(v)(max(1, v * m)) if isinstance(v, int) else v * m
    return dataclasses.replace(base, **changes)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="100-109")
    ap.add_argument("--benign-seeds", default="100-102")
    ap.add_argument("--out", default="bench/results/e5_pr.csv")
    a = ap.parse_args()
    lo, hi = map(int, a.seeds.split("-"))
    blo, bhi = map(int, a.benign_seeds.split("-"))
    rows = []
    t0 = time.time()
    for m in MULTIPLIERS:
        th = scaled(m)
        results = []
        for s in range(lo, hi + 1):
            sim, dur = attack_scenario(s, difficulty="hard")
            res = run(sim, dur, thresholds=th)
            results.append(match(res.alerts, res.episodes))
        summ = summarize(merge(results))
        fp = {t: 0 for t in KNOBS}
        for name in BENIGN:
            for s in range(blo, bhi + 1):
                sim, dur = benign_scenario(name, s)
                for al in run(sim, dur, thresholds=th).alerts:
                    if al.type in fp:
                        fp[al.type] += 1
        for t in KNOBS:
            v = summ.get(t, {})
            rows.append({"multiplier": m, "type": t, "episodes": v.get("episodes", 0),
                         "detected": v.get("detected", 0), "recall": v.get("recall"),
                         "alerts": v.get("alerts", 0), "precision": v.get("precision"),
                         "benign_false_alerts": fp[t]})
        print(f"m={m}: " + "  ".join(f"{t} R={r['recall']} P={r['precision']} FP={r['benign_false_alerts']}"
                                     for t in KNOBS for r in rows[-4:] if r['type'] == t),
              f"({time.time() - t0:.0f}s)", flush=True)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"저장: {out}")


if __name__ == "__main__":
    main()
