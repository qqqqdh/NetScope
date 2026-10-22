"""§5.2 FlowTable 상태 전이·만료·재전송."""
from collections import Counter

from conftest import tcp
from netscope.flows import CLOSED, ESTABLISHED, FlowTable

C, S = "192.168.0.2", "10.0.0.20"


def run(pkts, ft=None):
    ft = ft or FlowTable()
    kinds = Counter()
    flow = None
    for pkt in pkts:
        flow, evs = ft.process(pkt)
        kinds.update(e.kind for e in evs)
    return ft, flow, kinds


def test_handshake_events_and_cohort_timestamp():
    ft = FlowTable()
    evs = []
    for pkt in (tcp(10.0, C, S, 50000, 80, "S", seq=1),
                tcp(10.01, S, C, 80, 50000, "SA", seq=9),
                tcp(10.02, C, S, 50000, 80, "A")):
        flow, e = ft.process(pkt)
        evs += e
    assert [e.kind for e in evs] == ["new_syn", "synack", "handshake_done"]
    assert all(e.syn_ts == 10.0 for e in evs)
    ev = evs[0]
    assert (ev.client, ev.server, ev.server_port) == (flow.ips[flow.init], flow.ips[1 - flow.init], 80)
    assert flow.state == ESTABLISHED and flow.bidirectional


def test_retransmission_same_isn():
    _, _, k = run([tcp(0, C, S, 50000, 80, "S", seq=1), tcp(3, C, S, 50000, 80, "S", seq=1)])
    assert k == {"new_syn": 1, "syn_retrans": 1}


def test_retransmission_without_seq_is_approx():
    ft = FlowTable()
    ft.process(tcp(0, C, S, 50000, 80, "S"))
    _, evs = ft.process(tcp(1, C, S, 50000, 80, "S"))
    assert evs[0].kind == "syn_retrans" and evs[0].approx


def test_different_isn_is_new_connection():
    _, _, k = run([tcp(0, C, S, 50000, 80, "S", seq=1), tcp(3, C, S, 50000, 80, "S", seq=2)])
    assert k["new_syn"] == 2 and k["syn_retrans"] == 0
    assert k["syn_unanswered_expired"] == 1          # 이전 Flow를 미완료로 마감


def test_tuple_reuse_after_rst():
    ft, flow, k = run([tcp(0, C, S, 50000, 80, "S", seq=1),
                       tcp(0.1, S, C, 80, 50000, "SA"),
                       tcp(0.2, C, S, 50000, 80, "A"),
                       tcp(5, C, S, 50000, 80, "R")])
    assert flow.state == CLOSED
    _, _, k2 = run([tcp(20, C, S, 50000, 80, "S", seq=1)], ft)   # 같은 ISN이어도 CLOSED 후엔 새 연결
    assert k2 == {"new_syn": 1}


def test_rst_from_responder():
    _, _, k = run([tcp(0, C, S, 50000, 81, "S", seq=1), tcp(0.01, S, C, 81, 50000, "RA")])
    assert k["rst_from_responder"] == 1


def test_unidirectional_handshake():
    ft = FlowTable()
    ft.process(tcp(0, C, S, 50000, 80, "S", seq=1))
    _, evs = ft.process(tcp(0.05, C, S, 50000, 80, "A"))
    assert evs[0].kind == "handshake_done" and evs[0].unidirectional


def test_syn_sent_expires_after_75s():
    ft = FlowTable()
    ft.process(tcp(0, C, S, 50000, 80, "S", seq=1))
    assert ft.expire(74) == [] and len(ft) == 1
    evs = ft.expire(76)
    assert [e.kind for e in evs] == ["syn_unanswered_expired"] and len(ft) == 0


def test_closing_expires_after_60s():
    ft, _, _ = run([tcp(0, C, S, 50000, 80, "PA"), tcp(1, C, S, 50000, 80, "FA")])
    ft.expire(59)
    assert len(ft) == 1
    ft.expire(62)
    assert len(ft) == 0


def test_capacity_evicts_oldest():
    ft = FlowTable(max_flows=10)
    for i in range(20):
        ft.process(tcp(i, C, S, 40000 + i, 80, "S", seq=i))
    assert len(ft) == 10 and ft.evictions == 10
    assert ft.get(FlowTable.key_of(tcp(0, C, S, 40019, 80))[0]) is not None
    assert ft.get(FlowTable.key_of(tcp(0, C, S, 40000, 80))[0]) is None
