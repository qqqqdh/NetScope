"""정규화된 데이터 모델 (DESIGN §5.1).

IP 주소는 메모리와 해시 비용을 줄이기 위해 내부에서 정수로 다루고(§6.2),
표시할 때만 문자열로 바꾼다.
"""
from __future__ import annotations

import ipaddress
import itertools
from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class Packet:
    ts: float                 # 이벤트 시간 (캡처 시각)
    src: int
    dst: int
    proto: str                # TCP | UDP | ICMP | ARP | OTHER
    length: int
    sport: int | None = None
    dport: int | None = None
    flags: str = ""           # Scapy 표기: "S", "SA", "A", "PA", "FA", "R", "RA" ...
    seq: int | None = None    # TCP 시퀀스 번호 (SYN 재전송 판정에 사용)
    ver: int = 4              # IP 버전 (4 | 6)
    ingest_ts: float = 0.0    # 처리 시간 (큐에 넣은 벽시계 시각)


@dataclass(slots=True, frozen=True)
class Classification:
    name: str                 # HTTPS, DNS, ..., 또는 L4 이름
    method: str               # port+direction | port-heuristic | l4
    confidence: str           # high | medium | low

    @property
    def estimated(self) -> bool:
        return self.method != "l4"


_alert_ids = itertools.count(1)


@dataclass(slots=True)
class Alert:
    ts: float
    type: str                 # port_scan | syn_flood | service_connectivity_issue | dns_flood | traffic_spike
    severity: str             # low | medium | high
    confidence: str           # low | medium | high
    key: str
    message: str
    details: dict = field(default_factory=dict)
    id: int = field(default_factory=lambda: next(_alert_ids))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class Episode:
    """시뮬레이터가 내보내는 정답 라벨."""
    type: str
    key: str
    start: float
    end: float


# ---------------------------------------------------------------- IP 변환
def ip_to_int(text: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(text)
    return int(addr), addr.version


def int_to_ip(value: int, ver: int = 4) -> str:
    return str(ipaddress.IPv4Address(value) if ver == 4 else ipaddress.IPv6Address(value))


def make_packet(ts: float, src: str, dst: str, proto: str, length: int, **kw) -> Packet:
    """문자열 IP로 Packet을 만드는 편의 함수 (테스트·시뮬레이터용)."""
    s, ver = ip_to_int(src)
    d, _ = ip_to_int(dst)
    return Packet(ts=ts, src=s, dst=d, proto=proto, length=length, ver=ver, **kw)
