"""Scapy 패킷 → 정규화된 Packet (PCAP 재생과 실제 캡처가 함께 쓴다)."""
from __future__ import annotations

import socket
from functools import lru_cache

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from ..models import Packet


@lru_cache(maxsize=65536)
def _v4(text: str) -> int:
    return int.from_bytes(socket.inet_pton(socket.AF_INET, text), "big")


@lru_cache(maxsize=65536)
def _v6(text: str) -> int:
    return int.from_bytes(socket.inet_pton(socket.AF_INET6, text), "big")


def to_packet(sp, ts: float | None = None) -> Packet | None:
    """IP/ARP가 아닌 프레임(LLDP, STP 등)은 None."""
    ts = float(sp.time) if ts is None else ts
    length = getattr(sp, "wirelen", None) or len(sp)      # snaplen으로 잘린 캡처도 원래 길이로
    if IP in sp:
        ip = sp[IP]
        src, dst, ver, l4 = _v4(ip.src), _v4(ip.dst), 4, ip.proto
    elif IPv6 in sp:
        ip = sp[IPv6]
        src, dst, ver, l4 = _v6(ip.src), _v6(ip.dst), 6, ip.nh
    elif ARP in sp:
        a = sp[ARP]
        try:
            return Packet(ts, _v4(a.psrc), _v4(a.pdst), "ARP", length)
        except OSError:
            return None
    else:
        return None
    if TCP in sp:
        t = sp[TCP]
        return Packet(ts, src, dst, "TCP", length, t.sport, t.dport, str(t.flags), t.seq, ver)
    if UDP in sp:
        u = sp[UDP]
        return Packet(ts, src, dst, "UDP", length, u.sport, u.dport, ver=ver)
    if ICMP in sp or l4 in (1, 58):
        return Packet(ts, src, dst, "ICMP", length, ver=ver)
    return Packet(ts, src, dst, "OTHER", length, ver=ver)   # 비첫 조각(fragment), GRE 등
