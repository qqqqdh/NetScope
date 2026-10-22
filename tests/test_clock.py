"""§4 시간 모델."""
from netscope.clock import Watermark
from netscope.models import make_packet


def p(ts, ingest=None):
    return make_packet(ts, "10.0.0.1", "10.0.0.2", "UDP", 10, ingest_ts=ts if ingest is None else ingest)


def test_close_rule_and_late_packet():
    wm = Watermark(lateness=1.0)
    assert wm.admit(p(100.5)) == "ok"
    assert wm.admit(p(102.6)) == "ok"
    assert list(wm.advance()) == [100]        # watermark 101.6 → 초 100만 마감
    assert wm.admit(p(100.9)) == "late"
    assert wm.admit(p(101.2)) == "ok"         # 101은 아직 열려 있음


def test_out_of_order_before_first_close_is_accepted():
    wm = Watermark(lateness=1.0)
    assert wm.admit(p(100.2)) == "ok"
    assert wm.admit(p(99.5)) == "ok"
    assert list(wm.advance()) == []
    wm.admit(p(102.0))
    assert list(wm.advance()) == [99, 100]


def test_no_premature_close_before_any_second_closes():
    wm = Watermark(lateness=1.0)
    wm.admit(p(100.2))
    assert list(wm.advance()) == []
    assert wm.closed_until is None
    assert wm.admit(p(98.7)) == "ok"          # 아직 아무 초도 마감되지 않았으므로 late가 아님


def test_flush_aligned_to_edge_bucket():
    wm = Watermark(lateness=1.0)
    wm.admit(p(201.3))
    assert list(wm.flush(align=5)) == [201, 202, 203, 204]


def test_future_packet_only_in_live():
    assert Watermark(live=True).admit(p(110, ingest=100)) == "future"
    assert Watermark(live=False).admit(p(110, ingest=100)) == "ok"


def test_idle_advance_live_only():
    wm = Watermark(lateness=1.0, live=True)
    wm.admit(p(100.2))
    assert list(wm.idle_advance(106.0)) == [100, 101, 102, 103, 104]
    assert list(Watermark(live=False).idle_advance(106.0)) == []


def test_flush_closes_last_second():
    wm = Watermark(lateness=1.0)
    wm.admit(p(100.2))
    wm.admit(p(101.7))
    assert list(wm.flush()) == [100, 101]
