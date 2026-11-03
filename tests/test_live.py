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


def test_driver_drops_become_health_reason():
    """드라이버 누적 손실의 증가분만 capture_drop으로 기록된다 (queue_drop과 별개)."""
    from netscope.pipeline import Pipeline

    pipe = Pipeline(live=True)
    pipe.report_capture_stats(1000, 0, 0)
    pipe._sync_drops()
    assert pipe.engine.health.totals.get("capture_drop", 0) == 0
    pipe.report_capture_stats(2000, 30, 5)              # 누적값: 드라이버 30 + 인터페이스 5
    pipe._sync_drops()
    pipe.report_capture_stats(2500, 30, 5)              # 증가 없음 → 중복 기록 안 함
    pipe._sync_drops()
    pipe.report_capture_stats(3000, 40, 5)
    pipe._sync_drops()
    assert pipe.engine.health.totals["capture_drop"] == 45
    assert pipe.engine.health.totals.get("queue_drop", 0) == 0
    assert pipe.status()["capture"] == {"recv": 3000, "drop": 40, "ifdrop": 5}


def test_capture_stats_none_without_pcap_handle():
    from netscope.sources.live import _linktype, capture_stats

    assert capture_stats(FakeSock([])) is None          # pcap 핸들 없음 (Linux 네이티브 소켓 등)

    class NativeSock:                                   # Linux: pcap_fd 속성이 없다
        pass
    assert _linktype(NativeSock(), Ether) == 1
    assert _linktype(NativeSock(), object) == -1
    assert _linktype(FakeSock([]), Ether) == 1          # pcap 소켓은 datalink()


def test_unknown_linktype_falls_back_to_scapy_dissection():
    frame = bytes(Ether(**E) / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=6, dport=53))

    class NativeSock(FakeSock):
        def __init__(self, frames):
            super().__init__(frames)
            del self.pcap_fd                            # 링크 타입을 알 수 없는 소켓

        def recv_raw(self):
            if self.frames:
                data, ts = self.frames.pop(0)
                return Ether, data, ts                  # 계층 클래스로 Ethernet 추론 → 빠른 파서
            time.sleep(0.01)
            return None, None, None
    got = []
    src = LiveSource(lambda p: got.append(p) or True)
    src._sock = NativeSock([(frame, 3.0)])
    import threading
    src._thread = threading.Thread(target=src._loop, daemon=True)
    src._thread.start()
    deadline = time.time() + 2
    while not got and time.time() < deadline:
        time.sleep(0.01)
    src.stop()
    assert [(p.proto, p.dport) for p in got] == [("UDP", 53)] and src.scapy_fallback == 0


def test_parser_option_validated():
    with pytest.raises(ValueError):
        LiveSource(lambda p: True, parser="dpkt")
