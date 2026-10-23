"""지연 지표 3종 측정 (DESIGN §9, G5).

시뮬레이터 1배속(이벤트 시간 ≈ 벽시계)으로 서버를 띄우고, WebSocket 클라이언트가 스냅샷마다
ack를 보내는 동안 /api/status의 지연 지표를 모은다. 지연은 항상 같은 실행의 폐기율과 함께 보고한다.

    python bench/latency.py --seconds 40
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from netscope.server import create_app  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=40)
    ap.add_argument("--lateness", type=float, default=1.0)
    a = ap.parse_args()
    app = create_app(speed=1.0, seed=7, warmup=10, attack_interval=10, lateness=a.lateness)
    with TestClient(app) as c, c.websocket_connect("/ws") as ws:
        end = time.time() + a.seconds
        while time.time() < end:
            msg = ws.receive_json()
            if msg["type"] == "snapshot":
                ws.send_json({"type": "ack", "seq": msg["seq"]})
        st = c.get("/api/status").json()
        snap = c.get("/api/snapshot").json()
    totals = snap["health"]["totals"]
    offered = st["offered"] or 1
    out = {
        "lateness": a.lateness,
        "offered_packets": st["offered"],
        "latency": st["latency"],
        "drop_rates": {k: totals.get(k, 0) / offered for k in ("queue_drop", "late_drop", "future_drop")},
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    lat = st["latency"]
    e2e, fresh = lat.get("sampled_e2e") or {}, lat.get("snapshot_freshness") or {}
    print(f"\nG5: Sampled E2E P95 {e2e.get('p95')}s (목표 ≤ 2.5), Snapshot Freshness P95 {fresh.get('p95')}s "
          f"(목표 ≤ 1.5), late_drop {out['drop_rates']['late_drop']:.4%} (≤ 0.1%)")


if __name__ == "__main__":
    main()
