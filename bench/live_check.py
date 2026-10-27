"""실제 캡처(live) 동작 확인: 인터페이스에서 N초 캡처해 파이프라인 전체를 통과시킨다.

패킷 내용은 저장하지 않고 집계 수치만 출력한다.

    python bench/live_check.py --iface Wi-Fi --seconds 20
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscope.pipeline import Pipeline, percentiles  # noqa: E402
from netscope.sources.live import LiveSource  # noqa: E402


def nic_packets(name: str) -> int | None:
    """Windows 어댑터 카운터(송수신 패킷 합). 드라이버 단계에서 버려진 캡처 손실을 추정하는 기준."""
    if sys.platform != "win32":
        return None
    ps = (f"$s = Get-NetAdapterStatistics -Name '{name}'; $s.ReceivedUnicastPackets + $s.ReceivedMulticastPackets"
          f" + $s.ReceivedBroadcastPackets + $s.SentUnicastPackets + $s.SentMulticastPackets + $s.SentBroadcastPackets")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None)
    ap.add_argument("--bpf", default=None)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--parser", choices=["fast", "scapy"], default="fast")
    a = ap.parse_args()

    pipe = Pipeline(live=True)
    src = LiveSource(pipe.offer, iface=a.iface, bpf=a.bpf, parser=a.parser)
    pipe.start()
    src.start()
    time.sleep(0.5)                               # 스니퍼 준비 대기
    nic0, cap0 = nic_packets(a.iface) if a.iface else None, src.captured + src.skipped
    t0 = time.time()
    time.sleep(a.seconds)
    nic1, cap1 = nic_packets(a.iface) if a.iface else None, src.captured + src.skipped
    elapsed = time.time() - t0
    src.stop()
    time.sleep(2.5)                               # 마지막 초 마감 (lateness 1초 + 여유)
    pipe.stop()
    eng = pipe.engine
    snap = eng.snapshot()
    out = {
        "iface": a.iface, "parser": a.parser, "seconds": round(elapsed, 1),
        "captured": src.captured, "skipped_non_ip": src.skipped,
        "capture_pps": round(src.captured / elapsed, 1),
        "queue_drops": pipe._drops, "processed": eng.processed,
        "window_captured": cap1 - cap0,
        "window_nic_packets": (nic1 - nic0) if nic0 is not None and nic1 is not None else None,
        "window_capture_ratio": round((cap1 - cap0) / (nic1 - nic0), 4) if nic0 and nic1 and nic1 > nic0 else None,
        "late_drop": eng.health.totals.get("late_drop", 0),
        "future_drop": eng.health.totals.get("future_drop", 0),
        "flows": len(eng.flows), "tcp_flows": eng.flows.tcp_flows,
        "tcp_bidirectional": eng.flows.tcp_bidir,
        "protocols": {k: v["packets"] for k, v in snap["protocols"].items()},
        "graph": {"nodes": len(snap["graph"]["nodes"]), "edges": len(snap["graph"]["edges"])},
        "visibility": pipe.detector.visibility(),
        "alerts": [(x.type, x.severity) for x in pipe.detector.drain()],
        "packet_processing": percentiles(eng.processing_latency),
        "queue_wait": percentiles(pipe.queue_wait),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
