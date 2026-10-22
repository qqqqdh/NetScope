"""데이터 품질 원인 코드 (DESIGN §3 `health.reasons`)."""
from __future__ import annotations

import math
from collections import defaultdict

HINTS = {
    "queue_drop": "BPF 필터로 수집 범위를 줄이거나 큐 크기를 늘리기",
    "backlog": "분석기가 입력 속도를 따라가지 못함. 필터 적용",
    "late_drop": "--lateness 늘리기",
    "future_drop": "시스템 시계나 캡처 장비 시계 확인",
    "flow_eviction": "분류와 SYN 판정이 일부 불완전함. FlowTable 상한 늘리기",
    "edge_untracked": "그래프 엣지 값은 하한값이고, 나머지는 '기타'에 들어감",
    "detector_eviction": "일부 출발지는 탐지 대상에서 빠졌을 수 있음",
    "unidirectional": "미러 포트나 캡처 위치 확인. SYN 판정 신뢰도가 낮아짐",
    "memory_high": "상한 낮추기 (DESIGN §6)",
}


class Health:
    """원인 코드별 발생 횟수를 초 단위로 기록하고, 최근 window초를 보고한다."""

    def __init__(self, window: int = 60) -> None:
        self.window = window
        self.totals: dict[str, int] = defaultdict(int)
        self._recent: dict[str, dict[int, int]] = defaultdict(dict)

    def record(self, code: str, ts: float, n: int = 1) -> None:
        if code not in HINTS:
            raise ValueError(f"unknown health code: {code}")
        self.totals[code] += n
        sec = math.floor(ts)
        slots = self._recent[code]
        slots[sec] = slots.get(sec, 0) + n

    def reasons(self, now: float) -> list[dict]:
        cutoff = math.floor(now) - self.window
        out = []
        for code, slots in self._recent.items():
            for sec in [s for s in slots if s < cutoff]:
                del slots[sec]
            if slots:
                out.append({"code": code, "count": sum(slots.values()),
                            "first_ts": min(slots), "last_ts": max(slots) + 1,
                            "hint": HINTS[code]})
        return sorted(out, key=lambda r: r["code"])
