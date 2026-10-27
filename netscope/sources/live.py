"""실제 NIC 캡처. Windows는 Npcap, Linux는 root(또는 CAP_NET_RAW).

parser="fast"(기본): 캡처 소켓에서 원시 바이트만 받아(recv_raw) fastparse로 처리한다.
    Scapy의 패킷 분해(패킷당 약 1ms)를 건너뛰므로 처리량이 크게 늘어난다.
parser="scapy": AsyncSniffer + Scapy 분해 (기준 구현·대체 경로).
    실측: Wi-Fi 약 1,280 pps 부하에서 초당 약 1,100개에서 막혀 약 8%를 드라이버 단계에서 잃었다.
"""
from __future__ import annotations

import sys
import threading
from typing import Callable

from ..models import Packet
from .fastparse import parse_frame
from .parse import to_packet

HINT = ("Windows: Npcap(https://npcap.com) 설치 후 실행 (설치 시 '관리자 전용' 옵션을 켰다면 관리자 권한 필요). "
        "Linux: sudo로 실행하거나 python에 CAP_NET_RAW 부여.")


class LiveCaptureError(RuntimeError):
    pass


class LiveSource:
    def __init__(self, offer: Callable[[Packet], bool], iface: str | None = None,
                 bpf: str | None = None, parser: str = "fast") -> None:
        if parser not in ("fast", "scapy"):
            raise ValueError("parser는 fast 또는 scapy")
        self.offer, self.iface, self.bpf, self.parser = offer, iface, bpf, parser
        self._sniffer = None
        self._sock = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.captured = 0
        self.skipped = 0
        self.scapy_fallback = 0

    @property
    def running(self) -> bool:
        if self.parser == "scapy":
            return self._sniffer is not None and self._sniffer.running
        return self._thread is not None and self._thread.is_alive()

    def _deliver(self, pkt: Packet | None) -> None:
        if pkt is None:
            self.skipped += 1
            return
        self.captured += 1
        self.offer(pkt)            # 큐가 차면 Pipeline이 버리고 queue_drop으로 센다

    def _on_packet(self, sp) -> None:
        self._deliver(to_packet(sp))

    def start(self) -> None:
        if self.running:
            return
        from scapy.all import conf

        if sys.platform == "win32" and not conf.use_pcap:
            raise LiveCaptureError("패킷 캡처 드라이버(Npcap)를 찾을 수 없습니다. " + HINT)
        try:
            if self.parser == "scapy":
                from scapy.all import AsyncSniffer

                self._sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, store=False,
                                             prn=self._on_packet)
                self._sniffer.start()
                return
            self._sock = conf.L2listen(iface=self.iface or conf.iface, filter=self.bpf)
        except Exception as e:      # 권한 부족, 잘못된 인터페이스·BPF 등
            self._sniffer = self._sock = None
            raise LiveCaptureError(f"캡처를 시작할 수 없습니다: {e}. {HINT}") from e
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netscope-live", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        sock = self._sock
        linktype = sock.pcap_fd.datalink()
        while not self._stop.is_set():
            try:
                cls, data, ts = sock.recv_raw()      # 약 0.1초마다 타임아웃(None) → 정지 신호 확인
            except Exception:
                if self._stop.is_set():
                    break
                raise
            if data is None:
                continue
            pkt = parse_frame(data, linktype, float(ts), len(data))
            if pkt is NotImplemented:                # 빠른 파서가 모르는 링크 타입 → Scapy
                self.scapy_fallback += 1
                sp = cls(data)
                sp.time = ts
                pkt = to_packet(sp)
            self._deliver(pkt)

    def stop(self, timeout: float = 2.0) -> None:
        if self.parser == "scapy":
            if self._sniffer is not None and self._sniffer.running:
                try:
                    self._sniffer.stop(join=True)
                except Exception:
                    pass
            self._sniffer = None
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
