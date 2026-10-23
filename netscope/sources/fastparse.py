"""struct 기반 빠른 프레임 파서와 pcap/pcapng 리더.

Scapy의 범용 분해는 이 PC에서 패킷당 약 1ms(≈1,100 pps)라 PCAP 재생의 병목이었다.
자주 나오는 경로만 직접 파싱하고, 모르는 링크 타입은 None 대신 NotImplemented를 돌려
호출자가 Scapy로 넘기게 한다. 결과는 parse.to_packet(Scapy 기준 구현)과 같아야 한다(테스트로 고정).
"""
from __future__ import annotations

import struct
from typing import BinaryIO, Iterator

from ..models import Packet

# Scapy와 같은 플래그 문자열: 비트 순서 F S R P A U E C
_FLAGS = ["".join(ch for i, ch in enumerate("FSRPAUEC") if b & (1 << i)) for b in range(256)]
_IPV6_EXT = {0, 43, 60, 51}              # hop-by-hop, routing, destination options, AH
DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LOOP, DLT_LINUX_SLL, DLT_LINUX_SLL2 = 0, 1, 101, 108, 113, 276
_RAW_ALIASES = {12, 14, DLT_RAW}


def _l4(data: bytes, off: int, l4: int, ts, src, dst, length, ver) -> Packet:
    n = len(data)
    if l4 == 6 and n >= off + 14:
        sport, dport, seq = struct.unpack_from("!HHI", data, off)
        return Packet(ts, src, dst, "TCP", length, sport, dport, _FLAGS[data[off + 13]], seq, ver)
    if l4 == 17 and n >= off + 4:
        sport, dport = struct.unpack_from("!HH", data, off)
        return Packet(ts, src, dst, "UDP", length, sport, dport, ver=ver)
    if l4 in (1, 58):
        return Packet(ts, src, dst, "ICMP", length, ver=ver)
    return Packet(ts, src, dst, "OTHER", length, ver=ver)


def _ipv4(data: bytes, off: int, ts, length) -> Packet | None:
    if len(data) < off + 20:
        return None
    ihl = (data[off] & 0x0F) * 4
    l4 = data[off + 9]
    src = int.from_bytes(data[off + 12:off + 16], "big")
    dst = int.from_bytes(data[off + 16:off + 20], "big")
    frag = ((data[off + 6] & 0x1F) << 8) | data[off + 7]
    if frag:                                             # 첫 조각이 아니면 L4 헤더가 없음
        return Packet(ts, src, dst, "OTHER", length, ver=4)
    return _l4(data, off + ihl, l4, ts, src, dst, length, 4)


def _ipv6(data: bytes, off: int, ts, length) -> Packet | None:
    if len(data) < off + 40:
        return None
    nh = data[off + 6]
    src = int.from_bytes(data[off + 8:off + 24], "big")
    dst = int.from_bytes(data[off + 24:off + 40], "big")
    p = off + 40
    while True:
        if nh in _IPV6_EXT and len(data) >= p + 2:
            nh, p = data[p], p + (data[p + 1] + 2) * 4 if nh == 51 else p + (data[p + 1] + 1) * 8
        elif nh == 44 and len(data) >= p + 8:            # fragment header
            frag = struct.unpack_from("!H", data, p + 2)[0] >> 3
            if frag:
                return Packet(ts, src, dst, "OTHER", length, ver=6)
            nh, p = data[p], p + 8
        else:
            break
    return _l4(data, p, nh, ts, src, dst, length, 6)


def _arp(data: bytes, off: int, ts, length) -> Packet | None:
    if len(data) < off + 28 or data[off + 5] != 4:      # plen == 4 (IPv4)만
        return None
    return Packet(ts, int.from_bytes(data[off + 14:off + 18], "big"),
                  int.from_bytes(data[off + 24:off + 28], "big"), "ARP", length)


def _by_ethertype(et: int, data: bytes, off: int, ts, length):
    if et == 0x0800:
        return _ipv4(data, off, ts, length)
    if et == 0x86DD:
        return _ipv6(data, off, ts, length)
    if et == 0x0806:
        return _arp(data, off, ts, length)
    return None


def parse_frame(data: bytes, linktype: int, ts: float, length: int):
    """Packet | None(IP/ARP 아님) | NotImplemented(모르는 링크 타입 → Scapy로)."""
    if linktype == DLT_EN10MB:
        if len(data) < 14:
            return None
        off, et = 14, (data[12] << 8) | data[13]
        while et in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:   # VLAN (QinQ 포함)
            et, off = (data[off + 2] << 8) | data[off + 3], off + 4
        return _by_ethertype(et, data, off, ts, length)
    if linktype in _RAW_ALIASES:
        v = data[0] >> 4 if data else 0
        return _ipv4(data, 0, ts, length) if v == 4 else _ipv6(data, 0, ts, length) if v == 6 else None
    if linktype == DLT_LINUX_SLL:
        return _by_ethertype((data[14] << 8) | data[15], data, 16, ts, length) if len(data) >= 16 else None
    if linktype == DLT_LINUX_SLL2:
        return _by_ethertype((data[0] << 8) | data[1], data, 20, ts, length) if len(data) >= 20 else None
    if linktype in (DLT_NULL, DLT_LOOP):
        if len(data) < 4:
            return None
        fam = int.from_bytes(data[:4], "big" if linktype == DLT_LOOP else "little")
        if fam > 0xFFFF:                                 # 다른 바이트 순서로 기록된 파일
            fam = int.from_bytes(data[:4], "little" if linktype == DLT_LOOP else "big")
        if fam == 2:
            return _ipv4(data, 4, ts, length)
        if fam in (10, 23, 24, 28, 30):
            return _ipv6(data, 4, ts, length)
        return None
    return NotImplemented


# ====================================================================== 리더
def read_frames(f: BinaryIO) -> Iterator[tuple[bytes, int, float, int]]:
    """(data, linktype, ts, wirelen)을 내보낸다. 클래식 pcap(µs/ns)과 pcapng를 지원한다."""
    head = f.read(4)
    if head == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(f, head)
        return
    magic = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}.get(head)
    if magic is None:
        raise ValueError("pcap/pcapng 파일이 아닙니다")
    e, unit = magic
    linktype = struct.unpack(e + "HHiIII", f.read(20))[5] & 0x0FFFFFFF
    rec = struct.Struct(e + "IIII")
    while (hdr := f.read(16)) and len(hdr) == 16:
        sec, frac, incl, orig = rec.unpack(hdr)
        yield f.read(incl), linktype, sec + frac * unit, orig


def _pcapng(f: BinaryIO, first: bytes) -> Iterator[tuple[bytes, int, float, int]]:
    e = "<"
    ifaces: list[tuple[int, float]] = []                 # (linktype, 초 단위)
    btype_raw = first
    while True:
        if btype_raw is None:
            btype_raw = f.read(4)
            if len(btype_raw) < 4:
                return
        blen_raw = f.read(4)
        if len(blen_raw) < 4:
            return
        if btype_raw == b"\x0a\x0d\x0d\x0a":             # SHB: 바이트 순서 결정, 인터페이스 초기화
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(e + "I", blen_raw)[0]
            f.read(blen - 12)
            ifaces = []
            btype_raw = None
            continue
        btype = struct.unpack(e + "I", btype_raw)[0]
        blen = struct.unpack(e + "I", blen_raw)[0]
        body = f.read(blen - 8)
        btype_raw = None
        if btype == 1:                                   # IDB
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            unit = 1e-6
            p = 8
            while p + 4 <= len(body) - 4:
                code, olen = struct.unpack_from(e + "HH", body, p)
                if code == 0:
                    break
                if code == 9 and olen >= 1:              # if_tsresol
                    r = body[p + 4]
                    unit = 2.0 ** -(r & 0x7F) if r & 0x80 else 10.0 ** -r
                p += 4 + (olen + 3) // 4 * 4
            ifaces.append((linktype, unit))
        elif btype == 6:                                 # EPB
            iid, hi, lo, incl, orig = struct.unpack_from(e + "IIIII", body, 0)
            linktype, unit = ifaces[iid]
            yield body[20:20 + incl], linktype, ((hi << 32) | lo) * unit, orig
        elif btype == 3:                                 # SPB: 시각이 없어 이벤트 시간 처리 불가
            yield b"", -1, 0.0, 0                        # 호출자가 건너뛴 레코드로 센다
