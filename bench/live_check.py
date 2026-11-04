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
    # Windows 오류 메시지가 현지 코드 페이지로 나오므로 깨져도 실패하지 않게 읽는다 (예: 루프백은 NIC가 아님)
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True,
                       encoding="utf-8", errors="replace")
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
    ap.add_argument("--processes", choices=["worker", "capture"], default=None,
                    help="프로세스 대응을 켬다. worker: 분석 워커에서(서버와 같음), capture: 캡처 스레드에서(이전 방식)")
    ap.add_argument("--slow-ms", type=float, default=0,
                    help="검증용: 패킷마다 일부러 지연을 넣어 드라이버 단계 손실을 일으킨다")
    a = ap.parse_args()

    pipe = Pipeline(live=True)
    offer = pipe.offer
    monitor = None
    if a.processes:
        from netscope.processes import ProcessMonitor

        monitor = ProcessMonitor()
        monitor.start()
        if a.processes == "worker":                  # server.create_app과 같은 경로
            pipe.engine.packet_listeners.append(lambda pkt, flow, m=monitor: m.record(pkt))
        else:
            def offer(p, _o=pipe.offer, _m=monitor):
                accepted = _o(p)
                if accepted:
                    _m.record(p)
                return accepted
    if a.slow_ms:
        def offer(p, _o=pipe.offer, _d=a.slow_ms / 1000):
            time.sleep(_d)
            return _o(p)
    src = LiveSource(offer, iface=a.iface, bpf=a.bpf, parser=a.parser, on_stats=pipe.report_capture_stats)
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
    if monitor is not None:
        monitor.stop()
    eng = pipe.engine
    snap = eng.snapshot()
    out = {
        "iface": a.iface, "parser": a.parser, "seconds": round(elapsed, 1),
        "captured": src.captured, "skipped_non_ip": src.skipped,
        "capture_pps": round(src.captured / elapsed, 1),
        "queue_drops": pipe._drops, "processed": eng.processed,
        "processes": ({k: monitor.snapshot()[k] for k in ("matched_bytes", "unmatched_bytes")}
                      if monitor else None),
        "driver_stats": src.stats, "capture_drop_health": eng.health.totals.get("capture_drop", 0),
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
