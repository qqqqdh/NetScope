"""§8.1 탐지 행 (CoreEngine + AnomalyDetector 경유)."""
import random

from conftest import tcp, udp
from netscope.anomaly import AnomalyDetector, Thresholds
from netscope.engine import CoreEngine
from netscope.models import int_to_ip

SVC, PORT = "10.0.0.20", 80


def make(**th):
    eng = CoreEngine()
    return eng, AnomalyDetector(eng, Thresholds(**th))


def feed(eng, pkts):
    for p in sorted(pkts, key=lambda p: p.ts):
        eng.ingest(p)
    eng.flush()


def types(det):
    return [a.type for a in det.alerts]


def handshake(t, c, s, cp, sp, *, synack=True, seq=1):
    out = [tcp(t, c, s, cp, sp, "S", seq=seq)]
    if synack:
        out.append(tcp(t + 0.002, s, c, sp, cp, "SA"))
    out.append(tcp(t + 0.004, c, s, cp, sp, "A"))
    return out


def warmup(t0=1000, n=40, server=SVC, port=PORT, synack=True):
    """서비스 기준선 + 출발지 이력 + 캡처 가시성(양방향/단방향)을 만든다."""
    pk = []
    for i in range(n):
        pk += handshake(t0 + i, f"192.168.0.{2 + i % 20}", server, 50000 + i, port, synack=synack)
    return pk


def spoofed(rnd):
    return f"11.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"


def flood(t0, n=300, dur=3.0, server=SVC, port=PORT, synack=True, retrans=0, seed=1):
    rnd, pk = random.Random(seed), []
    for i in range(n):
        t, src, sp = t0 + dur * i / n, spoofed(rnd), rnd.randint(1024, 65535)
        pk.append(tcp(t, src, server, sp, port, "S", seq=i))
        for k in range(retrans):
            pk.append(tcp(t + 1 + k, src, server, sp, port, "S", seq=i))
        if synack:
            pk.append(tcp(t + 0.001, server, src, port, sp, "SA"))
    return pk


# ---------------------------------------------------------------- port_scan
def test_port_scan_once_with_cooldown():
    eng, det = make()
    pk = [tcp(1000 + p * 0.1, "45.33.32.156", "192.168.0.10", 40000, p, "S", seq=p) for p in range(1, 31)]
    pk += [tcp(1010 + p * 0.1, "45.33.32.156", "192.168.0.10", 40000, 100 + p, "S", seq=p) for p in range(30)]
    feed(eng, pk)
    assert types(det) == ["port_scan"]
    a = det.alerts[0]
    assert (a.key, a.severity) == ("45.33.32.156", "high")
    assert a.ts == 1003                       # 20번째 포트(1002.0초) → 1002초 마감 시점에 탐지


def test_retransmissions_to_one_port_are_not_scan():
    eng, det = make()
    feed(eng, [tcp(1000 + i * 0.1, "45.33.32.156", "192.168.0.10", 40000, 22, "S", seq=7) for i in range(30)])
    assert det.alerts == []


def test_scan_of_500_ports_is_only_port_scan():
    eng, det = make()
    pk = warmup()
    for p in range(1, 501):
        t = 1045 + p / 100
        pk += [tcp(t, "45.33.32.156", SVC, 40000, p, "S", seq=p), tcp(t + 0.001, SVC, "45.33.32.156", p, 40000, "RA")]
    feed(eng, pk)
    assert types(det) == ["port_scan"]


def test_saturated_scan_keys_judge_by_lower_bound():
    eng, det = make(scan_keys=2)
    pk = [tcp(1000 + i * 0.01, "1.1.1.1", "192.168.0.10", 40000 + i, 80, "S", seq=i) for i in range(50)]
    pk += [tcp(1000 + i * 0.01, "2.2.2.2", "192.168.0.10", 40000 + i, 80, "S", seq=i) for i in range(50)]
    pk += [tcp(1001 + i * 0.01, "3.3.3.3", "192.168.0.10", 40000, p, "S", seq=p) for i, p in enumerate((1, 2, 3))]
    feed(eng, pk)
    assert det.scan.keys.error(next(k for k in det.scan.states if int_to_ip(k[1]) == "3.3.3.3")) >= 50
    assert det.alerts == []                   # 물려받은 ε만으로는 경고하지 않음
    assert eng.health.totals["detector_eviction"] >= 1


# ---------------------------------------------------------------- syn
def test_syn_flood_bidirectional():
    eng, det = make()
    feed(eng, warmup() + flood(1045))
    assert types(det) == ["syn_flood"]
    a = det.alerts[0]
    assert (a.key, a.severity, a.confidence) == (f"{SVC}:{PORT}", "high", "high")
    assert a.details["visibility"] == "bidirectional" and not a.details["cold_start"]
    assert a.details["half_open_ratio"] >= 0.8


def test_syn_flood_unidirectional_lowers_confidence():
    eng, det = make()
    feed(eng, warmup(synack=False) + flood(1045, synack=False))
    assert types(det) == ["syn_flood"]
    a = det.alerts[0]
    assert a.details["visibility"] == "unidirectional" and a.confidence == "medium"
    assert "half_open_ratio" not in a.details
    assert eng.health.totals["unidirectional"] > 0


def test_normal_handshakes_are_not_flood():
    eng, det = make()
    pk = warmup()
    for i in range(300):
        pk += handshake(1045 + i / 100, f"10.1.{i // 250}.{i % 250 + 1}", SVC, 40000 + i, PORT)
    feed(eng, pk)
    assert det.alerts == []


def test_retransmitting_flood_still_detected():
    eng, det = make()
    feed(eng, warmup() + flood(1045, retrans=2))
    assert types(det) == ["syn_flood"]
    assert det.alerts[0].details["retrans_ratio"] >= 0.5          # 재전송 지표만 장애 쪽으로 기움


def test_cold_start_flood_on_new_service():
    eng, det = make()
    feed(eng, warmup() + flood(1045, server="10.0.0.30", port=8080))
    assert types(det) == ["syn_flood"]
    a = det.alerts[0]
    assert a.details["cold_start"] and a.confidence == "medium"   # high에서 한 단계 낮음


def test_outage_is_connectivity_issue():
    eng, det = make()
    pk = warmup(server=SVC, port=443)
    rnd = random.Random(3)
    for c in range(20):
        client = f"192.168.0.{2 + c}"
        t = 1041 + rnd.random()
        while t < 1060:
            sp, seq = rnd.randint(40000, 60000), rnd.getrandbits(32)
            pk += [tcp(t + d, client, SVC, sp, 443, "S", seq=seq) for d in (0, 1, 3)]
            t += rnd.expovariate(1.5)
    feed(eng, pk)
    assert "service_connectivity_issue" in types(det) and "syn_flood" not in types(det)
    a = det.alerts[types(det).index("service_connectivity_issue")]
    assert a.severity == "low" and a.details["connectivity_score"] >= 2


def test_cohort_counts_without_waiting_for_expiry():
    eng, det = make()
    rnd = random.Random(5)
    pk = warmup()
    for i in range(100):
        src = spoofed(rnd)
        pk += [tcp(3000 + i / 200, src, "10.0.0.40", 1000 + i, 80, "S", seq=i),
               tcp(3000.05 + i / 200, "10.0.0.40", src, 80, 1000 + i, "SA")]
    pk.append(tcp(3003.5, "192.168.0.2", "8.8.8.8", 1, 443))          # 3001초까지 마감시킴
    for p in sorted(pk, key=lambda p: p.ts):
        eng.ingest(p)
    st = next(v for k, v in det.syn.states.items() if k[2] == 80 and int_to_ip(k[1]) == "10.0.0.40")
    assert det.syn.window(st, 3000)[0][0] == 0        # 유예 시간 전: 집계 대상 아님
    agg, sources = det.syn.window(st, 3001)
    assert agg[:5] == [100, 0, 100, 0, 0]              # 반개방 100 (75초 만료를 기다리지 않음)
    assert 90 <= sources <= 110                         # 64개 초과 → HLL 근사 (§6.1)


def test_cohort_assigns_late_completion_to_syn_second():
    eng, det = make()
    for p in (tcp(4000.9, "192.168.0.2", SVC, 5000, PORT, "S", seq=1),
              tcp(4001.0, SVC, "192.168.0.2", PORT, 5000, "SA"),
              tcp(4001.2, "192.168.0.2", SVC, 5000, PORT, "A")):
        eng.ingest(p)
    eng.flush()                                          # 4005초까지 마감 → 코호트 4000은 아직 창 안
    st = next(iter(det.syn.states.values()))
    assert st.cohorts[4000][:5] == [1, 0, 1, 0, 1] and 4001 not in st.cohorts


# ---------------------------------------------------------------- 장시간 실행 메모리 (E4에서 발견)
def test_server_mode_keeps_no_alerts_and_prunes_cooldowns():
    eng = CoreEngine()
    det = AnomalyDetector(eng, keep_alerts=0)
    delivered = []
    pk = []
    for s in range(40):                                  # 공격자 40명이 1초씩 차례로 스캔
        src = f"45.33.0.{s + 1}"
        pk += [tcp(6000 + s + p * 0.01, src, "192.168.0.10", 40000, p, "S", seq=p) for p in range(1, 31)]
    pk.append(tcp(6200, "192.168.0.2", "8.8.8.8", 1, 443))   # 마지막 공격 후 160초 → 정리 시점 지남
    for p in sorted(pk, key=lambda p: p.ts):
        eng.ingest(p)
        delivered += det.drain()
    eng.flush()
    delivered += det.drain()
    assert len(delivered) == 40 and len(det.alerts) == 0  # 전달은 되지만 보관하지 않음
    assert len(det._last_fired) == 0                      # 쿨다운이 끝난 항목은 정리됨


# ---------------------------------------------------------------- dns / spike
def test_dns_flood_sustained():
    eng, det = make()
    feed(eng, [udp(2000 + i / 15, "192.168.0.50", "8.8.8.8", 40000 + i, 53) for i in range(120)])
    assert types(det) == ["dns_flood"]
    assert det.alerts[0].key == "192.168.0.50" and det.alerts[0].details["active_seconds"] >= 6


def test_dns_burst_is_not_flood():
    eng, det = make()
    feed(eng, [udp(2000 + i / 140, "192.168.0.50", "8.8.8.8", 40000 + i, 53) for i in range(120)])
    assert det.alerts == []


def test_traffic_spike_once():
    eng, det = make()
    rnd = random.Random(2)
    pk = [tcp(5000 + s + rnd.random(), "192.168.0.2", "1.1.1.1", 50000, 443, length=rnd.randint(80, 120))
          for s in range(30) for _ in range(100)]
    pk += [tcp(5030 + rnd.random(), "192.168.0.2", "1.1.1.1", 50000, 443, length=1000) for _ in range(500)]
    feed(eng, pk)
    assert types(det) == ["traffic_spike"]
    assert det.alerts[0].severity == "low"
