"""§6 상한 자료구조."""
import random

from netscope.bounded import CappedSet, HybridCardinality, HyperLogLog, SpaceSaving


def test_space_saving_inherits_floor_and_lower_bound():
    ss = SpaceSaving(3)
    for k, n in (("a", 5), ("b", 3), ("c", 1)):
        ss.touch(k, n)
    assert ss.touch("d", 1) == "c"          # 최솟값 c(1) 축출
    assert ss.count("d") == 2 and ss.error("d") == 1 and ss.lower_bound("d") == 1
    assert len(ss) == 3 and ss.evictions == 1


def test_space_saving_bounds_hold_and_heavy_hitter_survives_flood():
    rnd = random.Random(1)
    ss, true = SpaceSaving(100), {}
    for i in range(20_000):
        key = "heavy" if i % 10 == 0 else f"u{rnd.randrange(10**9)}"
        true[key] = true.get(key, 0) + 1
        ss.touch(key)
    assert "heavy" in ss
    for key, count, err in ss.items():
        assert count - err <= true[key] <= count
    assert len(ss) == 100


def test_hll_error_within_10_percent():
    for n in (1_000, 10_000, 100_000):
        h = HyperLogLog()
        for x in range(n):
            h.add(x * 2654435761 + 7)
        assert abs(h.count() - n) / n < 0.10, (n, h.count())
    assert len(HyperLogLog().reg) == 256


def test_hybrid_exact_until_64_then_hll():
    for n in (49, 50, 64):
        hc = HybridCardinality()
        for x in range(n):
            hc.add(x)
        assert hc.exact and hc.count() == n
        assert hc.at_least(50) is (n >= 50)
    hc = HybridCardinality()
    for x in range(65):
        hc.add(x)
    assert not hc.exact and hc._set is None and hc.count() >= 65 and hc.at_least(50)


def test_hybrid_large_estimate():
    hc = HybridCardinality()
    for x in range(100_000):
        hc.add(x)
    assert abs(hc.count() - 100_000) / 100_000 < 0.10


def test_capped_set():
    cs = CappedSet(64)
    for p in range(100):
        cs.add(p)
    assert len(cs) == 64 and cs.saturated and cs.label() == "64+"
