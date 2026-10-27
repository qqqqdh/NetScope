"""live 캡처 소스의 수신 루프 (Npcap 없이 가짜 소켓으로 검증)."""
import time

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from netscope.models import int_to_ip
from netscope.sources.live import LiveSource

E = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


class FakePcapFd:
    def datalink(self):
        return 1                                       # Ethernet


class FakeSock:
    def __init__(self, frames):
        self.pcap_fd = FakePcapFd()
        self.frames = list(frames)
        self.closed = False

    def recv_raw(self):
        if self.frames:
            data, ts = self.frames.pop(0)
            return Ether, data, ts
        time.sleep(0.01)
        return None, None, None                        # 타임아웃

    def close(self):
        self.closed = True


def test_fast_loop_parses_raw_frames_and_stops():
    frames = [(bytes(Ether(**E) / IP(src="10.0.0.1", dst="8.8.8.8") / TCP(sport=5, dport=443, flags="S")), 10.5),
              (bytes(Ether(type=0x88CC, **E) / (b"\0" * 40)), 10.6),             # LLDP → 건너뜀
              (bytes(Ether(**E) / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=6, dport=53)), 10.7)]
    got = []
    src = LiveSource(lambda p: got.append(p) or True)
    src._sock = FakeSock(frames)
    src._stop.clear()
    import threading
    src._thread = threading.Thread(target=src._loop, daemon=True)
    src._thread.start()
    deadline = time.time() + 2
    while len(got) < 2 and time.time() < deadline:
        time.sleep(0.01)
    sock = src._sock
    src.stop()
    assert not src.running and sock.closed
    assert [(p.proto, p.dport, p.ts) for p in got] == [("TCP", 443, 10.5), ("UDP", 53, 10.7)]
    assert int_to_ip(got[0].src) == "10.0.0.1" and src.captured == 2 and src.skipped == 1


def test_parser_option_validated():
    with pytest.raises(ValueError):
        LiveSource(lambda p: True, parser="dpkt")
