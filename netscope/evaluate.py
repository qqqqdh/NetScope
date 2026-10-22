"""정답 라벨 대비 탐지 성능 평가 (DESIGN §8.2).

매칭: type과 key가 같고 alert.ts ∈ [start, end + grace]이면 일치.
Precision = 일치한 경고 / 그 유형의 전체 경고, Recall = 탐지된 에피소드 / 전체 에피소드.

사용법:  python -m netscope.evaluate --seeds 1-20
튜닝 시드(100~109)와 평가 시드(1~20)를 나눠 쓴다. 평가 시드를 보고 임계값을 고치지 않는다.
"""
from __future__ import annotations

import argparse
import math
from collections import defaultdict
from dataclasses import dataclass

from .anomaly import AnomalyDetector, Thresholds
from .engine import CoreEngine
from .models import Alert, Episode
from .sources.sim import ATTACK_TYPES, Simulation, attack_scenario, benign_scenario

TUNING_SEEDS = range(100, 110)
EVAL_SEEDS = range(1, 21)


@dataclass
class RunResult:
    alerts: list[Alert]
    episodes: list[Episode]
    engine: CoreEngine
    detector: AnomalyDetector


def run(sim: Simulation, duration: float, *, lateness: float = 1.0,
        thresholds: Thresholds | None = None, order_jitter: float = 0.0) -> RunResult:
    eng = CoreEngine(lateness=lateness)
    det = AnomalyDetector(eng, thresholds)
    for pkt in sim.run(duration, order_jitter=order_jitter):
        eng.ingest(pkt)
    eng.flush()
    return RunResult(det.alerts, list(sim.episodes), eng, det)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def match(alerts: list[Alert], episodes: list[Episode], grace: float = 5.0) -> dict:
    """유형별 {episodes, detected, alerts, tp_alerts, delays}."""
    out: dict = defaultdict(lambda: {"episodes": 0, "detected": 0, "alerts": 0, "tp_alerts": 0,
                                     "delays": []})
    for ep in episodes:
        hits = [a.ts for a in alerts
                if a.type == ep.type and a.key == ep.key and ep.start <= a.ts <= ep.end + grace]
        row = out[ep.type]
        row["episodes"] += 1
        if hits:
            row["detected"] += 1
            row["delays"].append(min(hits) - ep.start)
    for a in alerts:
        row = out[a.type]
        row["alerts"] += 1
        if any(a.type == ep.type and a.key == ep.key and ep.start <= a.ts <= ep.end + grace
               for ep in episodes):
            row["tp_alerts"] += 1
    return dict(out)


def merge(rows: list[dict]) -> dict:
    total: dict = defaultdict(lambda: {"episodes": 0, "detected": 0, "alerts": 0, "tp_alerts": 0,
                                       "delays": []})
    for r in rows:
        for t, v in r.items():
            for k in ("episodes", "detected", "alerts", "tp_alerts"):
                total[t][k] += v[k]
            total[t]["delays"] += v["delays"]
    return dict(total)


def summarize(m: dict) -> dict:
    out = {}
    for t, v in sorted(m.items()):
        d = sorted(v["delays"])
        p95 = d[min(len(d) - 1, math.ceil(0.95 * len(d)) - 1)] if d else None
        out[t] = {
            "episodes": v["episodes"], "detected": v["detected"],
            "recall": v["detected"] / v["episodes"] if v["episodes"] else None,
            "recall_ci95": wilson(v["detected"], v["episodes"]) if v["episodes"] else None,
            "alerts": v["alerts"], "tp_alerts": v["tp_alerts"],
            "precision": v["tp_alerts"] / v["alerts"] if v["alerts"] else None,
            "precision_ci95": wilson(v["tp_alerts"], v["alerts"]) if v["alerts"] else None,
            "delay_p95": p95,
        }
    return out


def evaluate_attacks(seeds, randomize: bool = True, **kw) -> dict:
    rows = []
    for s in seeds:
        sim, dur = attack_scenario(s, randomize=randomize)
        res = run(sim, dur, **kw)
        rows.append(match(res.alerts, res.episodes))
    return summarize(merge(rows))


def evaluate_benign(seeds, names=("baseline", "big_download", "dns_burst", "outage", "nat")) -> dict:
    out = {}
    for name in names:
        counts: dict = defaultdict(int)
        for s in seeds:
            sim, dur = benign_scenario(name, s)
            for a in run(sim, dur).alerts:
                counts[a.type] += 1
        out[name] = dict(counts)
    return out


def _seeds(text: str):
    lo, _, hi = text.partition("-")
    return range(int(lo), int(hi or lo) + 1)


def main() -> None:
    ap = argparse.ArgumentParser(description="NetScope 탐지 성능 평가")
    ap.add_argument("--seeds", default="1-20", help="예: 1-20 (평가), 100-109 (튜닝)")
    ap.add_argument("--fixed", action="store_true", help="공격 파라미터를 무작위로 바꾸지 않음")
    args = ap.parse_args()
    seeds = _seeds(args.seeds)
    print(f"공격 시나리오 · 시드 {args.seeds} · {'고정' if args.fixed else '변형'} 파라미터")
    print(f"{'유형':<28}{'에피소드':>8}{'Recall':>8}{'95% CI':>16}{'경고':>6}{'Precision':>10}{'95% CI':>16}{'지연P95':>8}")
    for t, v in evaluate_attacks(seeds, randomize=not args.fixed).items():
        rec = f"{v['recall']:.3f}" if v["recall"] is not None else "-"
        rci = f"{v['recall_ci95'][0]:.2f}~{v['recall_ci95'][1]:.2f}" if v["recall_ci95"] else "-"
        pre = f"{v['precision']:.3f}" if v["precision"] is not None else "-"
        pci = f"{v['precision_ci95'][0]:.2f}~{v['precision_ci95'][1]:.2f}" if v["precision_ci95"] else "-"
        dly = f"{v['delay_p95']:.1f}s" if v["delay_p95"] is not None else "-"
        print(f"{t:<28}{v['episodes']:>8}{rec:>8}{rci:>16}{v['alerts']:>6}{pre:>10}{pci:>16}{dly:>8}")
    print("\n정상 시나리오 경고 수 (유형별)")
    for name, counts in evaluate_benign(seeds[:5]).items():
        print(f"  {name:<14} {counts or '경고 없음'}")


if __name__ == "__main__":
    main()
