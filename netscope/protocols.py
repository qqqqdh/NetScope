"""서비스 포트 테이블, Flow 기반 분류, 주소 scope (DESIGN §5.3, §5.5)."""
from __future__ import annotations

import ipaddress
from functools import lru_cache

from .models import Classification

SERVICES = {
    "TCP": {20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAP",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP"},
    "UDP": {53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 137: "NetBIOS", 161: "SNMP",
            443: "QUIC", 1900: "SSDP", 5353: "mDNS"},
}


def classify(proto: str, server_port: int | None, client_port: int | None,
             direction_known: bool, first_dport: int | None = None) -> Classification:
    """Flow 하나를 분류한다.

    direction_known: 개시자를 안다(SYN을 봤거나 UDP 첫 패킷) → server_port를 그대로 믿는다.
    모르면(MIDSTREAM) 두 포트 중 테이블에 있는 쪽, 둘 다 있으면 처음 본 패킷의 목적지 포트.
    """
    table = SERVICES.get(proto)
    if table is None:
        return Classification(proto, "l4", "high")
    if direction_known:
        name = table.get(server_port)
        if name:
            return Classification(name, "port+direction", "medium")
        return Classification(proto, "l4", "high")
    hits = [p for p in (server_port, client_port) if p in table]
    if not hits:
        return Classification(proto, "l4", "high")
    port = hits[0] if len(hits) == 1 else (first_dport if first_dport in hits else min(hits))
    return Classification(table[port], "port-heuristic", "low")


# ---------------------------------------------------------------- 주소 scope
def _nets(*cidrs: str):
    return [ipaddress.ip_network(c) for c in cidrs]


# 순서가 곧 우선순위다 (더 좁은 대역을 먼저)
_SCOPES_V4 = [
    ("loopback", _nets("127.0.0.0/8")),
    ("link_local", _nets("169.254.0.0/16")),
    ("multicast", _nets("224.0.0.0/4")),
    ("documentation", _nets("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")),
    ("rfc1918", _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("cgnat", _nets("100.64.0.0/10")),
    ("reserved", _nets("0.0.0.0/8", "198.18.0.0/15", "240.0.0.0/4", "192.0.0.0/24")),
]
_SCOPES_V6 = [
    ("loopback", _nets("::1/128")),
    ("link_local", _nets("fe80::/10")),
    ("multicast", _nets("ff00::/8")),
    ("documentation", _nets("2001:db8::/32")),
    ("ula", _nets("fc00::/7")),
    ("reserved", _nets("::/128")),
]


def _as_range(net) -> tuple[int, int]:
    return int(net.network_address), int(net.broadcast_address)


_RANGES = {
    4: [(name, [_as_range(n) for n in nets]) for name, nets in _SCOPES_V4],
    6: [(name, [_as_range(n) for n in nets]) for name, nets in _SCOPES_V6],
}


@lru_cache(maxsize=65536)
def scope(ip: int, ver: int = 4) -> str:
    for name, ranges in _RANGES[ver]:
        for lo, hi in ranges:
            if lo <= ip <= hi:
                return name
    return "public"


class LocalNets:
    """'내부' 판단용 CIDR 목록. ipaddress.is_private는 쓰지 않는다 (§5.5)."""

    DEFAULT = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")

    def __init__(self, cidrs=DEFAULT) -> None:
        self._ranges = {4: [], 6: []}
        for c in cidrs:
            net = ipaddress.ip_network(c, strict=False)
            self._ranges[net.version].append(_as_range(net))

    def contains(self, ip: int, ver: int = 4) -> bool:
        return any(lo <= ip <= hi for lo, hi in self._ranges[ver])
