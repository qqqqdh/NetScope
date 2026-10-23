"""실제 NIC 캡처 (Scapy AsyncSniffer). Windows는 Npcap + 관리자 권한, Linux는 root(또는 CAP_NET_RAW)."""
from __future__ import annotations

import sys
from typing import Callable

from ..models import Packet
from .parse import to_packet

HINT = ("Windows: Npcap(https://npcap.com) 설치 후 관리자 권한으로 실행. "
        "Linux: sudo로 실행하거나 python에 CAP_NET_RAW 부여.")


class LiveCaptureError(RuntimeError):
    pass


class LiveSource:
    def __init__(self, offer: Callable[[Packet], bool], iface: str | None = None,
                 bpf: str | None = None) -> None:
        self.offer, self.iface, self.bpf = offer, iface, bpf
        self._sniffer = None
        self.captured = 0
        self.skipped = 0

    @property
    def running(self) -> bool:
        return self._sniffer is not None and self._sniffer.running

    def _on_packet(self, sp) -> None:
        pkt = to_packet(sp)
        if pkt is None:
            self.skipped += 1
            return
        self.captured += 1
        self.offer(pkt)            # 큐가 차면 Pipeline이 버리고 queue_drop으로 센다

    def start(self) -> None:
        if self.running:
            return
        from scapy.all import AsyncSniffer, conf

        if sys.platform == "win32" and not conf.use_pcap:
            raise LiveCaptureError("패킷 캡처 드라이버(Npcap)를 찾을 수 없습니다. " + HINT)
        try:
            self._sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, store=False,
                                         prn=self._on_packet)
            self._sniffer.start()
        except Exception as e:      # 권한 부족, 잘못된 인터페이스·BPF 등
            self._sniffer = None
            raise LiveCaptureError(f"캡처를 시작할 수 없습니다: {e}. {HINT}") from e

    def stop(self, timeout: float = 2.0) -> None:
        if self.running:
            try:
                self._sniffer.stop(join=True)
            except Exception:
                pass
        self._sniffer = None
