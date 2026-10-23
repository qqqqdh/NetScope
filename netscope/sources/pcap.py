"""PCAP 읽기(스트리밍)와 빠른 기록기, 그리고 읽기 경로와 독립적인 최소 집계기.

- iter_pcap: fastparse로 한 패킷씩 읽는다(파일 전체를 메모리에 올리지 않음).
  모르는 링크 타입의 프레임만 Scapy로 넘긴다. iter_pcap_scapy는 기준 구현(교차 검증용).
- write_pcap: 시뮬레이터 패킷을 Ethernet/IPv4 프레임으로 직접 기록한다(struct, Scapy보다 수십 배 빠름).
- count_pcap: struct만으로 레코드 수와 원래 길이 합을 센다. 파서 결과를 교차 검증하는 용도.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, Iterator

from ..models import Packet
from .fastparse import parse_frame, read_frames
from .parse import to_packet

LINKTYPE_ETHERNET = 1
_TCP_FLAGS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}
_PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1}
_MAC_A, _MAC_B = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


class PcapStats:
    def __init__(self) -> None:
        self.records = 0
        self.parsed = 0
        self.skipped = 0       # IP/ARP가 아닌 프레임, 시각 없는 레코드
        self.scapy_fallback = 0


def _scapy_frame(data: bytes, linktype: int, ts: float, wirelen: int) -> Packet | None:
    from scapy.config import conf
    from scapy.packet import Raw

    cls = conf.l2types.get(linktype, Raw)
    sp = cls(data)
    sp.wirelen = wirelen
    return to_packet(sp, ts)


def iter_pcap(path: str | Path, stats: PcapStats | None = None) -> Iterator[Packet]:
    stats = stats or PcapStats()
    with open(path, "rb") as f:
        for data, linktype, ts, wirelen in read_frames(f):
            stats.records += 1
            pkt = parse_frame(data, linktype, ts, wirelen) if linktype >= 0 else None
            if pkt is NotImplemented:
                stats.scapy_fallback += 1
                pkt = _scapy_frame(data, linktype, ts, wirelen)
            if pkt is None:
                stats.skipped += 1
                continue
            stats.parsed += 1
            yield pkt


def iter_pcap_scapy(path: str | Path, stats: PcapStats | None = None) -> Iterator[Packet]:
    """Scapy 기준 구현 (느림, 약 1,100 pps). fastparse 교차 검증용."""
    from scapy.utils import PcapReader      # pcap과 pcapng 모두 처리

    stats = stats or PcapStats()
    with PcapReader(str(path)) as reader:
        for sp in reader:
            stats.records += 1
            pkt = to_packet(sp)
            if pkt is None:
                stats.skipped += 1
                continue
            stats.parsed += 1
            yield pkt


def _frame(p: Packet) -> bytes:
    if p.proto == "ARP":
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, _MAC_A, p.src.to_bytes(4, "big"),
                          b"\0" * 6, p.dst.to_bytes(4, "big"))
        return _MAC_B + _MAC_A + b"\x08\x06" + arp
    if p.ver != 4:
        raise ValueError("write_pcap은 IPv4만 지원")
    if p.proto == "TCP":
        flags = sum(_TCP_FLAGS[c] for c in p.flags)
        l4 = struct.pack("!HHIIBBHHH", p.sport, p.dport, (p.seq or 0) & 0xFFFFFFFF, 0, 5 << 4, flags,
                         65535, 0, 0)
    elif p.proto == "UDP":
        l4 = struct.pack("!HHHH", p.sport, p.dport, max(8, p.length - 34), 0)
    elif p.proto == "ICMP":
        l4 = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    else:
        l4 = b""
    payload = b"\0" * max(0, p.length - 34 - len(l4))
    total = 20 + len(l4) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, _PROTO.get(p.proto, 253), 0,
                     p.src.to_bytes(4, "big"), p.dst.to_bytes(4, "big"))
    return _MAC_B + _MAC_A + b"\x08\x00" + ip + l4 + payload


def write_pcap(path: str | Path, packets: Iterable[Packet]) -> int:
    """마이크로초 해상도로 기록한다. 기록한 패킷 수를 돌려준다."""
    n = 0
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for p in packets:
            data = _frame(p)
            us = round(p.ts * 1_000_000)
            f.write(struct.pack("<IIII", us // 1_000_000, us % 1_000_000, len(data), max(p.length, len(data))))
            f.write(data)
            n += 1
    return n


def count_pcap(path: str | Path) -> dict:
    """Scapy 없이 (클래식 pcap) 레코드 수와 원래 길이(wirelen) 합, EtherType별 개수를 센다."""
    out = {"records": 0, "bytes": 0, "ethertypes": {}}
    with open(path, "rb") as f:
        magic = f.read(24)[:4]
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
        if endian is None:
            raise ValueError("클래식 pcap 파일이 아닙니다 (pcapng는 지원하지 않음)")
        rec = struct.Struct(endian + "IIII")
        while hdr := f.read(16):
            _, _, incl, orig = rec.unpack(hdr)
            data = f.read(incl)
            out["records"] += 1
            out["bytes"] += orig
            et = int.from_bytes(data[12:14], "big") if len(data) >= 14 else -1
            out["ethertypes"][et] = out["ethertypes"].get(et, 0) + 1
    return out
