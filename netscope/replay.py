"""PCAP을 서버 없이 최대 속도로 분석한다.

    python -m netscope.replay capture.pcap [--alerts-json out.json]
    python -m netscope.replay --generate attacks:100 out.pcap     # 시뮬레이터 → PCAP

단계별 처리량(파싱 / 분석)을 따로 재서 병목이 어디인지 보여 준다 (DESIGN §9 E1의 출발점).
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .anomaly import AnomalyDetector
from .engine import CoreEngine
from .sources.pcap import PcapStats, count_pcap, iter_pcap, write_pcap


def analyze(path: str, lateness: float = 1.0) -> dict:
    stats = PcapStats()
    t0 = time.perf_counter()
    packets = list(iter_pcap(path, stats))                 # 파싱 시간만 따로 재기 위해 먼저 읽음
    t1 = time.perf_counter()
    eng = CoreEngine(lateness=lateness)
    det = AnomalyDetector(eng)
    for p in packets:
        eng.ingest(p)
    eng.flush()
    t2 = time.perf_counter()
    snap = eng.snapshot()
    return {
        "file": path,
        "records": stats.records, "parsed": stats.parsed, "skipped_non_ip": stats.skipped,
        "late_drops": eng.health.totals.get("late_drop", 0),
        "bytes": sum(p.length for p in packets),
        "span_seconds": round(packets[-1].ts - packets[0].ts, 3) if packets else 0,
        "parse_pps": round(len(packets) / (t1 - t0)) if t1 > t0 else None,
        "analyze_pps": round(len(packets) / (t2 - t1)) if t2 > t1 else None,
        "protocols_last_window": {k: v["bytes"] for k, v in snap["protocols"].items()},
        "alerts": [a.to_dict() for a in det.alerts],
    }


def _generate(spec: str, out: str) -> int:
    from .sources.sim import attack_scenario, benign_scenario

    name, _, seed = spec.partition(":")
    seed = int(seed or 1)
    sim, dur = attack_scenario(seed, repeat=1) if name == "attacks" else benign_scenario(name, seed)
    return write_pcap(out, sim.run(dur))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="netscope.replay", description="PCAP 오프라인 분석")
    ap.add_argument("pcap", help="입력 PCAP (--generate일 때는 출력 경로)")
    ap.add_argument("--generate", metavar="SCENARIO:SEED",
                    help="시뮬레이터로 PCAP 생성: attacks | baseline | big_download | dns_burst | outage | nat")
    ap.add_argument("--alerts-json", help="경고를 JSON 파일로 저장")
    ap.add_argument("--lateness", type=float, default=1.0)
    args = ap.parse_args(argv)

    if args.generate:
        n = _generate(args.generate, args.pcap)
        print(f"{args.pcap}: {n}개 패킷 기록")
        return
    try:
        r = analyze(args.pcap, args.lateness)
    except (OSError, ValueError) as e:
        sys.exit(f"읽기 실패: {e}")
    print(f"파일 {r['file']}  ·  레코드 {r['records']}  ·  분석 {r['parsed']}  ·  IP 아님 {r['skipped_non_ip']}"
          f"  ·  늦은 패킷 폐기 {r['late_drops']}")
    print(f"총 {r['bytes'] / 1e6:.2f} MB, 캡처 길이 {r['span_seconds']}초")
    print(f"처리량: 파싱 {r['parse_pps']:,} pps  /  분석 {r['analyze_pps']:,} pps")
    try:
        c = count_pcap(args.pcap)
        ok = c["records"] == r["records"]
        print(f"독립 집계기 교차 검증: 레코드 {c['records']} ({'일치' if ok else '불일치'})")
    except ValueError:
        pass                                               # pcapng는 교차 검증 생략
    print(f"경고 {len(r['alerts'])}건")
    for a in r["alerts"]:
        print(f"  [{a['severity']:<6}] {a['type']:<28} {a['key']:<22} {a['message']}")
    if args.alerts_json:
        with open(args.alerts_json, "w", encoding="utf-8") as f:
            json.dump(r["alerts"], f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
