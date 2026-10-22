"""§8.1 집계·그래프·시간·상한 (CoreEngine 경유)."""
from conftest import tcp, udp
from netscope.engine import CoreEngine
from netscope.models import make_packet


def feed(eng, pkts):
    for pkt in pkts:
        eng.ingest(pkt)
    eng.flush()
    return eng.snapshot()


def test_protocol_totals():
    pk = [tcp(100 + i * 0.1, "192.168.0.2", "8.8.4.4", 50000, 443, "S" if i == 0 else "A") for i in range(10)]
    pk += [udp(100 + i * 0.1, "192.168.0.2", "8.8.8.8", 50001, 53, length=50) for i in range(5)]
    snap = feed(CoreEngine(), pk)
    assert snap["totals"] == {"packets": 15, "bytes": 1250}
    https = snap["protocols"]["HTTPS"]
    assert (https["packets"], https["bytes"], https["estimated"]) == (10, 1000, True)
    assert snap["protocols"]["DNS"]["bytes"] == 250


def test_bidirectional_edge_merges():
    snap = feed(CoreEngine(), [tcp(10, "10.0.0.1", "10.0.0.2", 50000, 443, length=300),
                               tcp(10.1, "10.0.0.2", "10.0.0.1", 443, 50000, length=700)])
    g = snap["graph"]
    assert len(g["edges"]) == 1
    assert (g["edges"][0]["bytes"], g["edges"][0]["packets"]) == (1000, 2)
    assert g["other"] == {"packets": 0, "bytes": 0}


def test_out_of_order_same_totals():
    pk = [tcp(100 + i * 0.01, "10.0.0.1", "10.0.0.2", 1, 443, length=10 + i) for i in range(50)]
    a = feed(CoreEngine(), pk)
    b = feed(CoreEngine(), list(reversed(pk)))
    assert a["totals"] == b["totals"] and a["protocols"] == b["protocols"]


def test_late_packet_dropped_and_reported():
    eng = CoreEngine(lateness=1.0)
    eng.ingest(tcp(100.5, "10.0.0.1", "10.0.0.2", 1, 443))
    eng.ingest(tcp(103.0, "10.0.0.1", "10.0.0.2", 1, 443))   # 100, 101 마감
    eng.ingest(tcp(100.7, "10.0.0.1", "10.0.0.2", 1, 443))   # late
    eng.flush()
    snap = eng.snapshot()
    assert snap["totals"]["packets"] == 2
    assert [r["code"] for r in snap["health"]["reasons"]] == ["late_drop"]
    assert snap["health"]["degraded"]


def test_future_packet_live():
    eng = CoreEngine(live=True)
    eng.ingest(make_packet(110, "10.0.0.1", "10.0.0.2", "UDP", 10, ingest_ts=100))
    assert eng.health.totals["future_drop"] == 1 and eng.ingested == 0


def test_idle_seconds_are_zero_filled():
    eng = CoreEngine(live=True, lateness=1.0)
    eng.ingest(make_packet(100.2, "10.0.0.1", "10.0.0.2", "UDP", 10, sport=1, dport=53, ingest_ts=100.2))
    closed = eng.idle_advance(106.0)
    assert closed == [100, 101, 102, 103, 104]
    ts = eng.snapshot()["timeseries"]
    i = ts["labels"].index(100)
    assert ts["series"]["DNS"][i:i + 5] == [10, 0, 0, 0, 0]


def test_edge_cap_keeps_exact_totals():
    eng = CoreEngine(max_edges=5_000)
    pk = [udp(200 + i / 100_000, f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", "192.168.0.10",
              40000, 53, length=60 + i % 7) for i in range(100_000)]
    snap = feed(eng, pk)
    eng.analyzer.check_invariant()
    assert eng.analyzer.stats()["max_edges_in_bucket"] <= 5_000
    exact_bytes = sum(p.length for p in pk)
    assert snap["totals"] == {"packets": 100_000, "bytes": exact_bytes}
    g = snap["graph"]
    assert g["total"] == {"packets": 100_000, "bytes": exact_bytes}
    shown = sum(e["bytes"] for e in g["edges"])
    assert shown + g["other"]["bytes"] == exact_bytes          # Σ표시 + other == total
    assert g["edges_lower_bound"] and "edge_untracked" in {r["code"] for r in snap["health"]["reasons"]}


def test_tracked_edge_still_exact_after_saturation():
    eng = CoreEngine(max_edges=10)
    pk = [tcp(300, "10.0.0.1", "10.0.0.2", 1, 443, length=1000)]
    pk += [udp(300.1, f"10.1.0.{i}", "10.0.0.9", 1, 53) for i in range(50)]  # 상한 초과
    pk += [tcp(300.5, "10.0.0.1", "10.0.0.2", 1, 443, length=1000)]           # 이미 추적 중
    snap = feed(eng, pk)
    eng.analyzer.check_invariant()
    top = snap["graph"]["edges"][0]
    assert (top["source"], top["target"], top["bytes"]) == ("10.0.0.1", "10.0.0.2", 2000)


def test_sketch_candidates_preadmitted_in_next_bucket():
    eng = CoreEngine(max_edges=5)
    # 버킷 [300, 305): 앞자리를 잡음 5개 → 이후 heavy는 미추적 → 스케치에 잡힘
    pk = [udp(300, f"10.1.0.{i}", "10.0.0.9", 1, 53) for i in range(5)]
    pk += [tcp(301 + i * 0.01, "10.9.9.9", "10.0.0.2", 1, 443, length=1000) for i in range(50)]
    # 다음 버킷 [305, 310): 다시 잡음이 먼저 와도 heavy는 미리 자리를 받음
    pk += [udp(305, f"10.2.0.{i}", "10.0.0.9", 1, 53) for i in range(10)]
    pk += [tcp(306, "10.9.9.9", "10.0.0.2", 1, 443, length=1000)]
    feed(eng, pk)
    eb = eng.analyzer._ebuckets[305]
    heavy = [k for k in eb.edges if eb.edges[k].bytes == 1000]
    assert len(heavy) == 1
    eng.analyzer.check_invariant()


def test_flow_eviction_reported():
    eng = CoreEngine(max_flows=5)
    snap = feed(eng, [tcp(400, "10.0.0.1", "10.0.0.2", 40000 + i, 80, "S", seq=i) for i in range(8)])
    assert snap["flows"]["evictions"] == 3
    assert "flow_eviction" in {r["code"] for r in snap["health"]["reasons"]}
