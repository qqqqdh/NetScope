"""CoreEngine: 워터마크 → FlowTable → TrafficAnalyzer를 묶은 단일 스레드 결정적 코어.

3단계의 AnalyzerWorker는 이 객체를 큐 소비 루프로 감싸기만 한다 (DESIGN §3).
2단계 탐지기는 on_event / on_second_closed 리스너로 붙는다.
"""
from __future__ import annotations

import heapq
from typing import Callable

from .analyzer import TrafficAnalyzer
from .clock import Watermark
from .flows import FlowEvent, FlowTable
from .health import Health
from .models import Packet
from .protocols import LocalNets


class CoreEngine:
    def __init__(self, *, window: int = 60, lateness: float = 1.0, live: bool = False,
                 max_flows: int = 150_000, max_edges: int = 5_000, edge_bucket: int = 5,
                 local_nets: LocalNets | None = None) -> None:
        self.health = Health(window)
        self.clock = Watermark(lateness=lateness, live=live)
        self.flows = FlowTable(max_flows)
        self.analyzer = TrafficAnalyzer(window=window, edge_bucket=edge_bucket,
                                        max_edges=max_edges, local_nets=local_nets)
        self.event_listeners: list[Callable[[FlowEvent], None]] = []
        self.packet_listeners: list[Callable] = []          # fn(pkt, flow)
        self.close_listeners: list[Callable[[int], None]] = []
        self.ingested = 0
        self._buf: list = []        # 재정렬 버퍼: (ts, seq, pkt)
        self._seq = 0

    def _now(self, pkt: Packet) -> float:
        return self.clock.max_event if self.clock.max_event is not None else pkt.ts

    def _dispatch(self, events: list[FlowEvent]) -> None:
        for ev in events:
            for fn in self.event_listeners:
                fn(ev)

    # ------------------------------------------------------------------ 입력
    def ingest(self, pkt: Packet) -> list[int]:
        """패킷을 받아 재정렬 버퍼에 넣고, 그 결과 새로 마감된 초들을 돌려준다.

        패킷은 초가 마감될 때 이벤트 시간 순서로 처리된다. 그래서 lateness 안에서는
        도착 순서가 달라도 Flow 해석과 탐지 결과가 같다 (DESIGN §4 재정렬 버퍼).
        """
        verdict = self.clock.admit(pkt)
        if verdict != "ok":
            self.health.record(f"{verdict}_drop", self._now(pkt))
            return []
        self.ingested += 1
        self._seq += 1
        heapq.heappush(self._buf, (pkt.ts, self._seq, pkt))
        return self._close(self.clock.advance())

    def _release(self, until: float) -> None:
        buf = self._buf
        while buf and buf[0][0] < until:
            self._process(heapq.heappop(buf)[2])

    def _process(self, pkt: Packet) -> None:
        evictions = self.flows.evictions
        flow, events = self.flows.process(pkt)
        if self.flows.evictions != evictions:
            self.health.record("flow_eviction", pkt.ts, self.flows.evictions - evictions)
        if not self.analyzer.add(pkt, flow.cls):
            self.health.record("edge_untracked", pkt.ts)
        for fn in self.packet_listeners:
            fn(pkt, flow)
        self._dispatch(events)

    def idle_advance(self, wall_now: float) -> list[int]:
        """Live 모드, 큐가 비었을 때만 호출한다."""
        return self._close(self.clock.idle_advance(wall_now))

    def flush(self) -> list[int]:
        return self._close(self.clock.flush(align=self.analyzer.edge_bucket))

    def _close(self, secs: range) -> list[int]:
        for sec in secs:
            self._release(sec + 1)
            self._dispatch(self.flows.expire(sec + 1))
            for fn in self.close_listeners:
                fn(sec)
        if secs:
            self.analyzer.prune(secs[-1] + 1)
        return list(secs)

    # ------------------------------------------------------------------ 출력
    def snapshot(self) -> dict:
        end = self.clock.closed_until or 0
        snap = self.analyzer.snapshot(end)
        reasons = self.health.reasons(end)
        snap["health"] = {"degraded": bool(reasons), "reasons": reasons,
                          "totals": dict(self.health.totals)}
        snap["buffered"] = len(self._buf)
        snap["flows"] = {"active": len(self.flows), "evictions": self.flows.evictions,
                         "tcp_flows": self.flows.tcp_flows, "tcp_bidirectional": self.flows.tcp_bidir}
        return snap
