"""E6: 키 테이블 축출 정책(Space-Saving vs LRU)의 우회 공격 내성 (DESIGN §6.1, §9).

공격자는 느린 포트 스캔(초당 3포트, 20초)을 하면서, 동시에 처음 보는 출발지 IP의 SYN(잡음)을 대량으로
보내 탐지기 키 테이블을 채운다. 잡음이 공격자의 스캔 상태를 밀어내면 탐지를 피한다.

실행 시간을 줄이려고 스캔 키 상한을 1,000으로 줄이고 잡음도 상한 대비 비율로 준다(동작은 비율이 결정).

    python bench/e6_eviction.py --out bench/results/e6_eviction.csv
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscope.anomaly import AnomalyDetector, Thresholds  # noqa: E402
from netscope.engine import CoreEngine  # noqa: E402
from netscope.models import Packet, ip_to_int  # noqa: E402

CAP = 1_000
RATIOS = (0, 0.5, 1, 2, 3, 5, 10)            # 초당 잡음 키 수 / 키 상한
POLICIES = ("space_saving", "lru")
ATTACKER = ip_to_int("45.33.1.1")[0]
TARGET = ip_to_int("10.0.0.10")[0]


def scenario(ratio: float, seed: int) -> list[Packet]:
    rnd = random.Random(f"{seed}:{ratio}")
    t0, pk = 1_000_000.0, []
    noise = int(ratio * CAP)
    for sec in range(40):                    # 0~10초 잡음만, 10~30초 스캔 + 잡음, 30~40초 잡음만
        for k in range(noise):
            pk.append(Packet(t0 + sec + k / max(noise, 1), rnd.getrandbits(32) | 0x01000000,
                             0x0A010000 | rnd.getrandbits(16), "TCP", 60, rnd.randint(1024, 65535),
                             443, "S", rnd.getrandbits(32)))
    ports = rnd.sample(range(1, 65000), 60)
    for i, port in enumerate(ports):          # 초당 3포트 × 20초
        pk.append(Packet(t0 + 10 + i / 3, ATTACKER, TARGET, "TCP", 58, 40000, port, "S", i))
    pk.sort(key=lambda p: p.ts)
    return pk


def detected(policy: str, packets: list[Packet]) -> tuple[bool, int]:
    eng = CoreEngine()
    det = AnomalyDetector(eng, Thresholds(scan_keys=CAP, key_policy=policy))
    for p in packets:
        eng.ingest(p)
    eng.flush()
    hit = any(a.type == "port_scan" and a.key == "45.33.1.1" for a in det.alerts)
    return hit, det.scan.keys.evictions


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--out", default="bench/results/e6_eviction.csv")
    a = ap.parse_args()
    rows = []
    for ratio in RATIOS:
        for seed in range(1, a.seeds + 1):
            pk = scenario(ratio, seed)
            for policy in POLICIES:
                hit, ev = detected(policy, pk)
                rows.append({"noise_keys_per_sec_over_cap": ratio, "seed": seed, "policy": policy,
                             "detected": int(hit), "evictions": ev})
        line = "  ".join(
            f"{p}={sum(r['detected'] for r in rows if r['policy'] == p and r['noise_keys_per_sec_over_cap'] == ratio)}"
            f"/{a.seeds}" for p in POLICIES)
        print(f"잡음 {ratio:>4}×상한/초: {line}", flush=True)
    out = Path(a.out)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"저장: {out}")


if __name__ == "__main__":
    main()
