"""§8.1 분류·주소 행."""
import pytest

from conftest import tcp, udp
from netscope.flows import FlowTable
from netscope.models import ip_to_int
from netscope.protocols import LocalNets, scope


def cls_of(*pkts):
    ft = FlowTable()
    flow = None
    for p in pkts:
        flow, _ = ft.process(p)
    return flow.cls


def test_syn_to_443_is_https_by_direction():
    c = cls_of(tcp(0, "10.0.0.1", "8.8.8.8", 51000, 443, "S"))
    assert (c.name, c.method, c.confidence) == ("HTTPS", "port+direction", "medium")


def test_review_case_client_port_22_to_443_is_https():
    assert cls_of(tcp(0, "192.168.0.2", "8.8.8.8", 22, 443, "S")).name == "HTTPS"


def test_midstream_uses_first_seen_dport():
    c = cls_of(tcp(0, "192.168.0.2", "8.8.8.8", 22, 443, "PA"))
    assert (c.name, c.method, c.confidence) == ("HTTPS", "port-heuristic", "low")
    c = cls_of(tcp(0, "8.8.8.8", "192.168.0.2", 443, 22, "PA"))
    assert c.name == "SSH" and c.confidence == "low"


def test_udp_query_and_response_share_flow_and_name():
    ft = FlowTable()
    f1, _ = ft.process(udp(0, "10.0.0.1", "8.8.8.8", 51000, 53))
    f2, _ = ft.process(udp(0.01, "8.8.8.8", "10.0.0.1", 53, 51000))
    assert f1 is f2 and f1.cls.name == "DNS" and f1.cls.confidence == "medium"


def test_udp_response_seen_first_falls_back_to_heuristic():
    c = cls_of(udp(0, "8.8.8.8", "10.0.0.1", 53, 51000))
    assert (c.name, c.confidence) == ("DNS", "low")


def test_unknown_ports_are_l4():
    c = cls_of(tcp(0, "10.0.0.1", "10.0.0.2", 54321, 55555, "S"))
    assert (c.name, c.method) == ("TCP", "l4")


@pytest.mark.parametrize("ip,expected,local", [
    ("192.0.2.1", "documentation", False),
    ("100.64.0.1", "cgnat", False),
    ("10.1.2.3", "rfc1918", True),
    ("8.8.8.8", "public", False),
    ("198.18.0.1", "reserved", False),
    ("127.0.0.1", "loopback", False),
    ("fe80::1", "link_local", False),
    ("fd00::1", "ula", True),
    ("2001:db8::1", "documentation", False),
])
def test_scope_and_local(ip, expected, local):
    n, ver = ip_to_int(ip)
    assert scope(n, ver) == expected
    assert LocalNets().contains(n, ver) is local


def test_custom_local_nets():
    n, ver = ip_to_int("100.64.0.1")
    assert LocalNets(["100.64.0.0/10"]).contains(n, ver)
