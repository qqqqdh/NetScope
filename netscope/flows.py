"""FlowTable: 방향 무관 5-tuple 상태, 개시자, TCP 상태 전이 (DESIGN §5.2).

탐지기는 패킷이 아니라 여기서 나오는 FlowEvent를 센다. 모든 이벤트에는
그 Flow의 첫 SYN 시각(syn_ts)이 들어 있어 SYN 코호트(§5.4)에 배정할 수 있다.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from .models import Classification, Packet
from .protocols import classify

SYN_SENT, SYNACK_SEEN, ESTABLISHED = "SYN_SENT", "SYNACK_SEEN", "ESTABLISHED"
CLOSING, CLOSED, MIDSTREAM, UDP, OTHER = "CLOSING", "CLOSED", "MIDSTREAM", "UDP", "OTHER"

TIMEOUTS = {SYN_SENT: 75, SYNACK_SEEN: 75, ESTABLISHED: 300, CLOSING: 60,
            CLOSED: 10, MIDSTREAM: 300, UDP: 30, OTHER: 30}
SYN_RETRANS_WINDOW = 75.0
_PENDING = (SYN_SENT, SYNACK_SEEN)


@dataclass(slots=True)
class FlowEvent:
    kind: str           # new_syn | syn_retrans | synack | rst_from_responder | handshake_done
                        # | syn_unanswered_expired | half_open_expired
    ts: float
    syn_ts: float | None
    client: int         # 개시자 IP
    server: int         # 응답자 IP
    server_port: int | None
    ver: int
    approx: bool = False    # seq 없이 시간만으로 재전송을 판정함
    unidirectional: bool = False


class Flow:
    # 메모리: Flow 15만 개가 상주하므로(E4) proto·ver·ips·ports는 따로 저장하지 않고 key에서 꺼낸다.
    # key = (proto, ver, side0_ip, side0_port, side1_ip, side1_port), side0이 정렬상 작은 쪽
    __slots__ = ("key", "init", "state", "last_ts", "syn_ts", "isn", "pkts", "bytes", "dirs",
                 "fins", "cls", "tclass")

    def __init__(self, key, pkt: Packet) -> None:
        self.key = key
        self.init: int | None = None
        self.state = OTHER
        self.last_ts = pkt.ts
        self.syn_ts: float | None = None
        self.isn: int | None = None
        self.pkts = 0
        self.bytes = 0
        self.dirs = 0           # 비트 0: side0→side1, 비트 1: side1→side0
        self.fins = 0
        self.cls: Classification | None = None
        self.tclass: int | None = None

    @property
    def proto(self) -> str:
        return self.key[0]

    @property
    def ver(self) -> int:
        return self.key[1]

    @property
    def ips(self) -> tuple[int, int]:
        return self.key[2], self.key[4]

    @property
    def ports(self) -> tuple[int, int]:
        return self.key[3], self.key[5]

    @property
    def bidirectional(self) -> bool:
        return self.dirs == 3


class FlowTable:
    def __init__(self, max_flows: int = 100_000) -> None:   # E4 실측으로 15만 → 10만 (DESIGN §6.2)
        self.max_flows = max_flows
        self._flows: dict = {}
        self._classes: dict[int, OrderedDict] = {t: OrderedDict() for t in set(TIMEOUTS.values())}
        self.evictions = 0
        self.tcp_flows = 0
        self.tcp_bidir = 0

    def __len__(self) -> int:
        return len(self._flows)

    def get(self, key):
        return self._flows.get(key)

    # ------------------------------------------------------------ 내부 도우미
    @staticmethod
    def key_of(pkt: Packet):
        a = (pkt.src, pkt.sport or 0)
        b = (pkt.dst, pkt.dport or 0)
        lo, hi = (a, b) if a <= b else (b, a)
        return (pkt.proto, pkt.ver, lo[0], lo[1], hi[0], hi[1]), (0 if a == lo else 1)

    def _event(self, kind: str, flow: Flow, ts: float, **kw) -> FlowEvent:
        c = flow.init if flow.init is not None else 0
        return FlowEvent(kind, ts, flow.syn_ts, flow.ips[c], flow.ips[1 - c],
                         flow.ports[1 - c] or None, flow.ver, **kw)

    def _touch(self, flow: Flow) -> None:
        t = TIMEOUTS[flow.state]
        if flow.tclass != t:
            if flow.tclass is not None:
                del self._classes[flow.tclass][flow.key]
            self._classes[t][flow.key] = flow
            flow.tclass = t
        else:
            self._classes[t].move_to_end(flow.key)

    def _remove(self, flow: Flow) -> None:
        del self._flows[flow.key]
        if flow.tclass is not None:
            self._classes[flow.tclass].pop(flow.key, None)

    def _finish(self, flow: Flow, ts: float, events: list) -> None:
        """Flow를 마감한다(만료 또는 4-tuple 재사용). 미완료 상태면 통계 이벤트를 낸다."""
        if flow.state == SYN_SENT:
            events.append(self._event("syn_unanswered_expired", flow, ts))
        elif flow.state == SYNACK_SEEN:
            events.append(self._event("half_open_expired", flow, ts))
        self._remove(flow)

    def _evict_one(self) -> None:
        oldest = None
        for od in self._classes.values():
            if od:
                f = next(iter(od.values()))
                if oldest is None or f.last_ts < oldest.last_ts:
                    oldest = f
        if oldest is not None:
            self._remove(oldest)
            self.evictions += 1

    def _create(self, key, pkt: Packet, side: int) -> Flow:
        if len(self._flows) >= self.max_flows:
            self._evict_one()
        flow = Flow(key, pkt)
        self._flows[key] = flow
        if pkt.proto == "TCP":
            self.tcp_flows += 1
        return flow

    def _classify(self, flow: Flow, pkt: Packet) -> None:
        if flow.init is not None:
            server_port = flow.ports[1 - flow.init] or None
            client_port = flow.ports[flow.init] or None
            cls = classify(flow.proto, server_port, client_port, True)
            if cls.method == "l4" and flow.proto == "UDP":
                # 응답부터 본 UDP (예: 캡처가 DNS 응답 도중 시작) → 휴리스틱으로 재시도
                cls = classify(flow.proto, server_port, client_port, False, pkt.dport)
            flow.cls = cls
        else:
            flow.cls = classify(flow.proto, pkt.dport, pkt.sport, False, pkt.dport)

    # ------------------------------------------------------------ 공개 API
    def process(self, pkt: Packet) -> tuple[Flow, list[FlowEvent]]:
        key, side = self.key_of(pkt)
        flow = self._flows.get(key)
        events: list[FlowEvent] = []
        if pkt.proto == "TCP":
            flow = self._tcp(pkt, key, side, flow, events)
        elif flow is None:
            flow = self._create(key, pkt, side)
            if pkt.proto == "UDP":
                flow.state, flow.init = UDP, side
            self._classify(flow, pkt)

        flow.pkts += 1
        flow.bytes += pkt.length
        if pkt.ts > flow.last_ts:
            flow.last_ts = pkt.ts
        before = flow.dirs
        flow.dirs |= 1 << side
        if flow.proto == "TCP" and before != 3 and flow.dirs == 3:
            self.tcp_bidir += 1
        self._touch(flow)
        return flow, events

    def _tcp(self, pkt: Packet, key, side: int, flow: Flow | None, events: list) -> Flow:
        f = pkt.flags
        syn, ack, rst, fin = "S" in f, "A" in f, "R" in f, "F" in f

        if syn and not ack:
            if flow is not None:
                if flow.state in _PENDING:
                    if side != flow.init:
                        return flow                         # 동시 개방: 무시
                    same_isn = pkt.seq is None or flow.isn is None or pkt.seq == flow.isn
                    if same_isn and pkt.ts - flow.syn_ts <= SYN_RETRANS_WINDOW:
                        events.append(self._event("syn_retrans", flow, pkt.ts,
                                                  approx=pkt.seq is None or flow.isn is None))
                        return flow
                self._finish(flow, pkt.ts, events)          # 4-tuple 재사용 → 새 연결
            flow = self._create(key, pkt, side)
            flow.state, flow.init = SYN_SENT, side
            flow.syn_ts, flow.isn = pkt.ts, pkt.seq
            self._classify(flow, pkt)
            events.append(self._event("new_syn", flow, pkt.ts))
            return flow

        if flow is None:
            flow = self._create(key, pkt, side)
            if syn and ack:                                 # SYN을 못 본 채 SYN-ACK부터 봄
                flow.state, flow.init, flow.syn_ts = SYNACK_SEEN, 1 - side, pkt.ts
            else:
                flow.state = MIDSTREAM
            self._classify(flow, pkt)
            if rst:
                flow.state = CLOSED
            elif fin:
                flow.fins |= 1 << side
                flow.state = CLOSING
            return flow

        if syn and ack:
            if flow.state == SYN_SENT and side != flow.init:
                flow.state = SYNACK_SEEN
                events.append(self._event("synack", flow, pkt.ts))
            return flow

        if rst:
            if flow.state in _PENDING and flow.init is not None and side != flow.init:
                events.append(self._event("rst_from_responder", flow, pkt.ts))
            flow.state = CLOSED
            return flow

        if ack and flow.state in _PENDING and side == flow.init:
            unidirectional = flow.state == SYN_SENT         # SYN-ACK를 못 봄
            flow.state = ESTABLISHED
            events.append(self._event("handshake_done", flow, pkt.ts, unidirectional=unidirectional))

        if fin:
            flow.fins |= 1 << side
            flow.state = CLOSED if flow.fins == 3 else CLOSING
        return flow

    def expire(self, now: float) -> list[FlowEvent]:
        """마지막 패킷 이후 상태별 timeout이 지난 Flow를 지운다 (이벤트 시간 기준)."""
        events: list[FlowEvent] = []
        for t, od in self._classes.items():
            while od:
                flow = next(iter(od.values()))
                if now - flow.last_ts <= t:
                    break
                self._finish(flow, now, events)
        return events
