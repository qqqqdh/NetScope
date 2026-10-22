"""이벤트 시간 워터마크와 초 마감 (DESIGN §4).

- watermark = max(이벤트 시간) − lateness
- 초 s는 watermark ≥ s+1 이면 마감된다. 마감된 초에 속한 패킷은 late.
- Live 모드에서 큐가 비었을 때만 벽시계로 유휴 전진한다 (v3 수정).
"""
from __future__ import annotations

import math

from .models import Packet


class Watermark:
    def __init__(self, lateness: float = 1.0, live: bool = False,
                 future_tolerance: float = 5.0) -> None:
        self.lateness = lateness
        self.live = live
        self.future_tolerance = future_tolerance
        self.max_event: float | None = None
        self.min_event: float | None = None
        self.closed_until: int | None = None   # 이 초 미만은 모두 마감됨

    def admit(self, pkt: Packet) -> str:
        """'ok' | 'late' | 'future'"""
        if self.live and pkt.ts > pkt.ingest_ts + self.future_tolerance:
            return "future"
        if self.closed_until is not None and math.floor(pkt.ts) < self.closed_until:
            return "late"
        if self.max_event is None or pkt.ts > self.max_event:
            self.max_event = pkt.ts
        if self.min_event is None or pkt.ts < self.min_event:
            self.min_event = pkt.ts
        return "ok"

    def _close_to(self, target: int) -> range:
        start = self.closed_until
        if start is None:
            if self.min_event is None:
                return range(0)
            start = math.floor(self.min_event)   # 실제로 마감할 때까지 초기화하지 않는다
        if target <= start:
            return range(0)
        closed = range(start, target)
        self.closed_until = target
        return closed

    def advance(self) -> range:
        """새로 마감된 초들을 돌려준다."""
        if self.max_event is None:
            return range(0)
        return self._close_to(math.floor(self.max_event - self.lateness))

    def idle_advance(self, wall_now: float) -> range:
        """Live 모드 전용. 호출자는 큐가 비어 있음을 보장해야 한다."""
        if not self.live:
            return range(0)
        if self.max_event is None or wall_now > self.max_event:
            self.max_event = wall_now
            if self.min_event is None:
                self.min_event = wall_now - self.lateness
        return self.advance()

    def flush(self, align: int = 1) -> range:
        """입력 끝: 본 마지막 초까지 모두 마감한다 (PCAP·시뮬레이터).

        align: 마감 경계를 이 배수로 올린다 (엣지 버킷을 끝까지 닫기 위함).
        """
        if self.max_event is None:
            return range(0)
        target = math.floor(self.max_event) + 1
        target += -target % align
        return self._close_to(target)
