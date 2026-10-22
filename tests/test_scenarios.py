"""§8.2 시나리오 (튜닝 시드 100번대만 사용. 평가 시드 1~20은 python -m netscope.evaluate로)."""
from collections import Counter

import pytest

from netscope.evaluate import match, run, summarize, wilson
from netscope.models import Alert, Episode
from netscope.sources.sim import attack_scenario, benign_scenario

SEEDS = (100, 101)


def alert_types(res):
    return Counter(a.type for a in res.alerts)


@pytest.mark.parametrize("seed", SEEDS)
def test_baseline_no_false_positive(seed):
    res = run(*benign_scenario("baseline", seed))
    assert res.alerts == []
    snap = res.engine.snapshot()
    assert snap["totals"]["packets"] > 1000
    assert {"HTTPS", "DNS", "HTTP", "SSH", "QUIC"} <= set(snap["protocols"])
    assert snap["protocols"]["SSH"]["low_confidence_bytes"] > 0      # 캡처 전부터 열린 세션 → 추정(low)
    res.engine.analyzer.check_invariant()


@pytest.mark.parametrize("seed", SEEDS)
def test_big_download_at_most_one_low_spike(seed):
    c = alert_types(run(*benign_scenario("big_download", seed)))
    assert set(c) <= {"traffic_spike"} and c["traffic_spike"] <= 1


@pytest.mark.parametrize("seed", SEEDS)
def test_dns_burst_no_alert(seed):
    assert run(*benign_scenario("dns_burst", seed)).alerts == []


@pytest.mark.parametrize("seed", SEEDS)
def test_outage_is_not_flood(seed):
    c = alert_types(run(*benign_scenario("outage", seed)))
    assert c["service_connectivity_issue"] >= 1 and c["syn_flood"] == 0
    assert set(c) == {"service_connectivity_issue"}


@pytest.mark.parametrize("seed", SEEDS)
def test_nat_surge_no_alert(seed):
    assert run(*benign_scenario("nat", seed)).alerts == []


def test_attacks_all_detected_fixed_params():
    sim, dur = attack_scenario(100, randomize=False)
    res = run(sim, dur)
    s = summarize(match(res.alerts, res.episodes))
    for t in ("port_scan", "syn_flood", "dns_flood", "traffic_spike"):
        assert s[t]["episodes"] == 3 and s[t]["recall"] == 1.0 and s[t]["precision"] == 1.0, (t, s[t])


def test_replay_is_deterministic_across_lateness():
    def sig(lateness):
        sim, dur = attack_scenario(102, repeat=1)
        return [(a.type, a.key, a.ts) for a in run(sim, dur, lateness=lateness).alerts]
    assert sig(1.0) == sig(2.5)


def test_order_jitter_keeps_totals_and_alerts():
    a = run(*benign_scenario("baseline", 103))
    sim, dur = benign_scenario("baseline", 103)
    b = run(sim, dur, order_jitter=0.5)
    sa, sb = a.engine.snapshot(), b.engine.snapshot()
    assert sa["totals"] == sb["totals"] and sa["protocols"] == sb["protocols"]
    assert sa["graph"]["edges"] == sb["graph"]["edges"]
    assert b.engine.health.totals.get("late_drop", 0) == 0


def test_order_jitter_keeps_attack_alerts():
    def sig(jitter):
        sim, dur = attack_scenario(104, repeat=1)
        return [(a.type, a.key, a.ts, a.confidence) for a in run(sim, dur, order_jitter=jitter).alerts]
    assert sig(0.0) == sig(0.5)


def test_match_and_wilson():
    eps = [Episode("port_scan", "1.1.1.1", 100, 105)]
    alerts = [Alert(101, "port_scan", "high", "medium", "1.1.1.1", ""),
              Alert(200, "port_scan", "high", "medium", "1.1.1.1", ""),
              Alert(102, "dns_flood", "medium", "medium", "2.2.2.2", "")]
    s = summarize(match(alerts, eps))
    assert s["port_scan"]["recall"] == 1.0 and s["port_scan"]["precision"] == 0.5
    assert s["port_scan"]["delay_p95"] == 1
    assert s["dns_flood"]["precision"] == 0.0
    lo, hi = wilson(57, 60)
    assert 0.85 < lo < 0.88 and 0.98 < hi < 0.995
