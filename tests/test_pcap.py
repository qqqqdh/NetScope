"""4단계: 파서, PCAP 왕복(시뮬레이터 → PCAP → 파서 → 엔진), 독립 집계기, pcap 모드 서버."""
import time

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, CookedLinux, Dot1Q, Ether, Loopback
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, wrpcap

from netscope.evaluate import run
from netscope.models import Packet, int_to_ip
from netscope.server import create_app
from netscope.sources.fastparse import parse_frame
from netscope.sources.parse import to_packet
from netscope.sources.pcap import PcapStats, count_pcap, iter_pcap, iter_pcap_scapy, write_pcap
from netscope.sources.sim import attack_scenario


# ---------------------------------------------------------------- 파서
E = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")     # MAC 생략 시 Windows에서 인터페이스 조회가 일어남


def eth(*layers):
    p = Ether(**E)
    for layer in layers:
        p = p / layer
    return p


def conv(sp, ts=5.0):
    sp = Ether(bytes(sp))
    sp.time = ts
    return to_packet(sp)


def test_parse_tcp_fields():
    p = conv(eth(IP(src="10.0.0.1", dst="8.8.8.8"), TCP(sport=51000, dport=443, flags="SA", seq=7)))
    assert (int_to_ip(p.src), int_to_ip(p.dst), p.proto, p.sport, p.dport, p.flags, p.seq, p.ver) == \
        ("10.0.0.1", "8.8.8.8", "TCP", 51000, 443, "SA", 7, 4)
    assert p.length == 54 and p.ts == 5.0


def test_parse_ipv6_udp_icmp_arp_vlan():
    p = conv(eth(IPv6(src="fd00::1", dst="2001:db8::2"), UDP(sport=5353, dport=53)))
    assert (p.proto, p.ver, int_to_ip(p.src, 6)) == ("UDP", 6, "fd00::1")
    assert conv(eth(IP(src="1.1.1.1", dst="2.2.2.2"), ICMP())).proto == "ICMP"
    a = conv(eth(ARP(psrc="192.168.0.1", pdst="192.168.0.2", hwsrc=E["src"])))
    assert (a.proto, int_to_ip(a.src)) == ("ARP", "192.168.0.1")
    v = conv(eth(Dot1Q(vlan=10), IP(src="10.0.0.1", dst="10.0.0.2"), UDP(sport=1, dport=53)))
    assert (v.proto, v.dport) == ("UDP", 53)


def test_parse_non_ip_returns_none():
    assert conv(Ether(type=0x88CC, **E) / Raw(b"\0" * 40)) is None          # LLDP


def test_parse_uses_wire_length():
    sp = eth(IP(src="1.1.1.1", dst="2.2.2.2"), UDP(), Raw(b"\0" * 10))
    sp.wirelen = 1500                                                   # snaplen으로 잘린 캡처
    sp.time = 1.0
    assert to_packet(sp).length == 1500


# ---------------------------------------------------------------- 왕복
@pytest.fixture(scope="module")
def roundtrip(tmp_path_factory):
    sim, dur = attack_scenario(105, repeat=1)
    pkts = []
    for p in sim.run(dur):                                             # PCAP 해상도(µs)로 맞춤
        p.ts = round(p.ts * 1_000_000) / 1_000_000
        pkts.append(p)
    path = tmp_path_factory.mktemp("pcap") / "attacks.pcap"
    assert write_pcap(path, pkts) == len(pkts)
    return pkts, path


def key(p: Packet):
    # 시뮬레이터 데이터 패킷은 seq=None, 실제 TCP 헤더에는 항상 seq가 있어 0으로 읽힌다
    return (round(p.ts, 6), p.src, p.dst, p.proto, p.length, p.sport, p.dport, p.flags, p.seq or 0)


# ---------------------------------------------------------------- 빠른 파서 ↔ Scapy 교차 검증
V4 = dict(src="10.0.0.1", dst="10.0.0.2")
V6 = dict(src="fd00::1", dst="fd00::2")
FRAMES = [
    eth(IP(**V4), TCP(sport=1, dport=443, flags=f, seq=9)) for f in ("S", "SA", "A", "PA", "FA", "R", "RA", "SEC", "")
] + [
    eth(IP(**V4), UDP(sport=53, dport=5000), Raw(b"x" * 30)),
    eth(IP(**V4), ICMP()),
    eth(IP(**V4, frag=10, proto=6), Raw(b"y" * 20)),                       # 비첫 조각
    eth(IP(**V4, ihl=6, options=b"\x01\x01\x01\x00"), TCP(sport=2, dport=22)),  # IP 옵션
    eth(IP(**V4, proto=47), Raw(b"g" * 8)),                                # GRE → OTHER
    eth(Dot1Q(vlan=5), Dot1Q(vlan=6), IP(**V4), UDP(sport=1, dport=2)),     # QinQ
    eth(IPv6(**V6), TCP(sport=3, dport=80, flags="S", seq=1)),
    eth(IPv6(**V6), IPv6ExtHdrHopByHop(), UDP(sport=4, dport=53)),
    eth(IPv6(**V6), IPv6ExtHdrFragment(offset=0), UDP(sport=5, dport=53)),
    eth(IPv6(**V6), IPv6ExtHdrFragment(offset=8), Raw(b"z" * 16)),
    eth(IPv6(**V6), ICMPv6EchoRequest()),
    eth(ARP(psrc="192.168.0.1", pdst="192.168.0.9", hwsrc=E["src"])),
    Ether(type=0x88CC, **E) / Raw(b"\0" * 40),
]


def fields_of(p):
    return None if p is None else (p.src, p.dst, p.proto, p.length, p.sport, p.dport, p.flags, p.seq, p.ver)


@pytest.mark.parametrize("i", range(len(FRAMES)))
def test_fast_parser_matches_scapy(i):
    raw = bytes(FRAMES[i])
    ref = Ether(raw)
    ref.time = 1.0
    assert fields_of(parse_frame(raw, 1, 1.0, len(raw))) == fields_of(to_packet(ref))


@pytest.mark.parametrize("linktype,pkt", [
    (101, IP(**V4) / TCP(sport=1, dport=443, flags="S")),                 # Raw IP
    (113, CookedLinux(proto=0x0800) / IP(**V4) / UDP(sport=1, dport=53)),  # Linux SLL
    (0, Loopback(type=2) / IP(**V4) / UDP(sport=1, dport=53)),             # BSD loopback
])
def test_linktypes(tmp_path, linktype, pkt):
    pkt.time = 7.5
    path = tmp_path / "lt.pcap"
    wrpcap(str(path), [pkt], linktype=linktype)
    fast, ref = list(iter_pcap(path)), list(iter_pcap_scapy(path))
    assert len(fast) == 1 and [fields_of(p) for p in fast] == [fields_of(p) for p in ref]
    assert fast[0].ts == pytest.approx(7.5)


def test_pcapng_and_nanosecond(tmp_path):
    pkts = [eth(IP(**V4), TCP(sport=1, dport=443, flags="S", seq=i)) for i in range(3)]
    for i, p in enumerate(pkts):
        p.time = 100.123456789 + i
    ng = tmp_path / "a.pcapng"
    with PcapNgWriter(str(ng)) as w:
        for p in pkts:
            w.write(p)
    nano = tmp_path / "n.pcap"
    wrpcap(str(nano), pkts, nano=True)
    for path in (ng, nano):
        fast, ref = list(iter_pcap(path)), list(iter_pcap_scapy(path))
        assert [fields_of(p) for p in fast] == [fields_of(p) for p in ref]
        assert [p.ts for p in fast] == pytest.approx([p.ts for p in ref], abs=1e-6)
    assert list(iter_pcap(nano))[0].ts == pytest.approx(100.123456789, abs=1e-8)


def test_unknown_linktype_falls_back_to_scapy(tmp_path):
    path = tmp_path / "u.pcap"
    wrpcap(str(path), [Raw(b"\0" * 20)], linktype=147)                    # USER0
    stats = PcapStats()
    assert list(iter_pcap(path, stats)) == [] and stats.scapy_fallback == 1 and stats.skipped == 1


def test_roundtrip_packets_identical(roundtrip):
    pkts, path = roundtrip
    back = list(iter_pcap(path))
    assert len(back) == len(pkts)
    assert [key(p) for p in back] == [key(p) for p in pkts]


def test_fast_reader_matches_scapy_on_sim_capture(roundtrip):
    _, path = roundtrip
    import itertools
    fast = list(itertools.islice(iter_pcap(path), 3000))
    ref = list(itertools.islice(iter_pcap_scapy(path), 3000))
    assert [key(p) for p in fast] == [key(p) for p in ref]


def test_independent_counter_agrees(roundtrip):
    pkts, path = roundtrip
    c = count_pcap(path)
    assert c["records"] == len(pkts) and c["bytes"] == sum(p.length for p in pkts)
    assert c["ethertypes"] == {0x0800: len(pkts)}


class _ListSim:
    def __init__(self, pkts, episodes):
        self.pkts, self.episodes = pkts, episodes

    def run(self, duration, order_jitter=0.0):
        return iter(self.pkts)


def test_roundtrip_same_alerts_and_totals(roundtrip):
    pkts, path = roundtrip
    a = run(_ListSim(pkts, []), 0)
    b = run(_ListSim(list(iter_pcap(path)), []), 0)
    sig = lambda r: [(x.type, x.key, x.ts, x.confidence) for x in r.alerts]
    assert sig(a) == sig(b) and len(sig(a)) >= 4
    assert a.engine.snapshot()["totals"] == b.engine.snapshot()["totals"]


# ---------------------------------------------------------------- pcap 모드 서버
def test_pcap_mode_server_matches_offline(roundtrip):
    pkts, path = roundtrip
    offline = run(_ListSim(pkts, []), 0)
    with TestClient(create_app(mode="pcap", pcap=str(path), speed=0, queue_max=1000)) as c:
        end = time.time() + 30
        while time.time() < end:
            st = c.get("/api/status").json()
            if st["source_finished"] and st["queue_size"] == 0:
                time.sleep(0.5)                                         # 마지막 flush·발행 대기
                break
            time.sleep(0.1)
        st = c.get("/api/status").json()
        assert st["source_finished"] and st["queue_drops"] == 0       # 역압: 작은 큐에서도 손실 없음
        got = c.get("/api/alerts?limit=500").json()
        snap = c.get("/api/snapshot").json()
    assert [(x["type"], x["key"], x["ts"]) for x in got] == [(x.type, x.key, x.ts) for x in offline.alerts]
    assert snap["totals"] == offline.engine.snapshot()["totals"]


def test_pcap_mode_requires_existing_file(tmp_path):
    with pytest.raises(ValueError):
        create_app(mode="pcap")
    with pytest.raises(ValueError):
        create_app(mode="pcap", pcap=str(tmp_path / "nope.pcap"))
