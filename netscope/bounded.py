"""상한이 있는 자료구조 (DESIGN §6)."""
from __future__ import annotations

import heapq
import math

_MASK64 = (1 << 64) - 1


def mix64(x: int) -> int:
    """splitmix64 — 정수 키를 고르게 섞는다 (IPv6 128비트도 접어서 처리)."""
    x = (x ^ (x >> 64)) & _MASK64
    x = (x + 0x9E3779B97F4A7C15) & _MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _MASK64
    return x ^ (x >> 31)


class SpaceSaving:
    """Space-Saving top-K. 새 키는 밀려난 키의 최솟값 ε를 물려받는다.

    count(key)는 과대 추정일 수 있다(축출 순위용). 판정에는 lower_bound()를 쓴다.
    최솟값 탐색은 지연 삭제 힙으로 O(log k).
    """

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._counts: dict = {}      # key -> [count, error]
        self._heap: list = []        # (count, seq, key) — 지연 삭제
        self._seq = 0
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._counts)

    def __contains__(self, key) -> bool:
        return key in self._counts

    def _push(self, key, count) -> None:
        self._seq += 1
        heapq.heappush(self._heap, (count, self._seq, key))
        if len(self._heap) > 4 * self.capacity + 64:
            self._heap = [(c, i, k) for i, (k, (c, _)) in enumerate(self._counts.items())]
            heapq.heapify(self._heap)
            self._seq = len(self._heap)

    def _pop_min(self):
        while self._heap:
            count, _, key = heapq.heappop(self._heap)
            cur = self._counts.get(key)
            if cur is not None and cur[0] == count:
                return key, count
        raise RuntimeError("heap out of sync")

    def touch(self, key, inc: int = 1):
        """key를 inc만큼 올린다. 다른 키가 밀려났으면 그 키를 돌려준다."""
        entry = self._counts.get(key)
        evicted = None
        if entry is None:
            if len(self._counts) >= self.capacity:
                evicted, floor = self._pop_min()
                del self._counts[evicted]
                self.evictions += 1
                entry = self._counts[key] = [floor, floor]
            else:
                entry = self._counts[key] = [0, 0]
        entry[0] += inc
        self._push(key, entry[0])
        return evicted

    def count(self, key) -> int:
        e = self._counts.get(key)
        return e[0] if e else 0

    def error(self, key) -> int:
        e = self._counts.get(key)
        return e[1] if e else 0

    def lower_bound(self, key) -> int:
        e = self._counts.get(key)
        return e[0] - e[1] if e else 0

    def items(self):
        """(key, count, error)를 count 내림차순으로."""
        return sorted(((k, c, err) for k, (c, err) in self._counts.items()), key=lambda t: -t[1])

    def remove(self, key) -> None:
        self._counts.pop(key, None)


class LRUKeys:
    """SpaceSaving과 같은 인터페이스의 LRU 키 테이블 (E6 비교 실험용).

    가장 오래 접근하지 않은 키를 축출한다. 물려받는 값이 없으므로 error는 항상 0이다.
    """

    def __init__(self, capacity: int) -> None:
        from collections import OrderedDict

        self.capacity = capacity
        self._counts: "OrderedDict" = OrderedDict()
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._counts)

    def __contains__(self, key) -> bool:
        return key in self._counts

    def touch(self, key, inc: int = 1):
        evicted = None
        if key in self._counts:
            self._counts.move_to_end(key)
        elif len(self._counts) >= self.capacity:
            evicted, _ = self._counts.popitem(last=False)
            self.evictions += 1
        self._counts[key] = self._counts.get(key, 0) + inc
        return evicted

    def count(self, key) -> int:
        return self._counts.get(key, 0)

    def error(self, key) -> int:
        return 0

    def lower_bound(self, key) -> int:
        return self.count(key)

    def items(self):
        return sorted(((k, c, 0) for k, c in self._counts.items()), key=lambda t: -t[1])

    def remove(self, key) -> None:
        self._counts.pop(key, None)


def make_key_table(policy: str, capacity: int):
    if policy == "space_saving":
        return SpaceSaving(capacity)
    if policy == "lru":
        return LRUKeys(capacity)
    raise ValueError(f"알 수 없는 키 정리 정책: {policy!r} (space_saving | lru)")


class HyperLogLog:
    """p=8 → 256 레지스터(256B), 표준 오차 약 1.04/√256 ≈ 6.5%."""

    __slots__ = ("p", "m", "reg")

    def __init__(self, p: int = 8) -> None:
        self.p = p
        self.m = 1 << p
        self.reg = bytearray(self.m)

    def add(self, item: int) -> None:
        h = mix64(item)
        idx = h >> (64 - self.p)
        rest = (h << self.p) & _MASK64
        rank = (64 - self.p + 1) if rest == 0 else (64 - rest.bit_length() + 1)
        if rank > self.reg[idx]:
            self.reg[idx] = rank

    def merge(self, other: "HyperLogLog") -> None:
        """합집합: 레지스터별 최댓값."""
        self.reg = bytearray(max(a, b) for a, b in zip(self.reg, other.reg))

    def count(self) -> int:
        m = self.m
        alpha = 0.7213 / (1 + 1.079 / m)
        est = alpha * m * m / sum(2.0 ** -r for r in self.reg)
        zeros = self.reg.count(0)
        if est <= 2.5 * m and zeros:
            est = m * math.log(m / zeros)   # 작은 범위 보정 (linear counting)
        return round(est)


class HybridCardinality:
    """exact_limit개까지는 정확한 집합, 넘으면 HLL로 전환하고 집합을 해제한다 (§6.1)."""

    __slots__ = ("exact_limit", "p", "_set", "_hll")

    def __init__(self, exact_limit: int = 64, p: int = 8) -> None:
        self.exact_limit = exact_limit
        self.p = p
        self._set: set[int] | None = set()
        self._hll: HyperLogLog | None = None

    def add(self, item: int) -> None:
        if self._set is not None:
            self._set.add(item)
            if len(self._set) > self.exact_limit:
                self._hll = HyperLogLog(self.p)
                for x in self._set:
                    self._hll.add(x)
                self._set = None
        else:
            self._hll.add(item)

    @property
    def exact(self) -> bool:
        return self._set is not None

    def count(self) -> int:
        if self._set is not None:
            return len(self._set)
        # 전환 시점에 이미 exact_limit을 넘었음이 확정되어 있다
        return max(self._hll.count(), self.exact_limit + 1)

    @staticmethod
    def union_count(parts: list["HybridCardinality"], exact_limit: int = 64) -> int:
        """여러 카운터의 합집합 크기. 모두 정확하고 합이 작으면 정확한 값."""
        if all(p.exact for p in parts):
            u: set[int] = set()
            for p in parts:
                u |= p._set
            return len(u)
        hll = HyperLogLog(parts[0].p)
        for p in parts:
            if p.exact:
                for x in p._set:
                    hll.add(x)
            else:
                hll.merge(p._hll)
        biggest_exact = max((len(p._set) for p in parts if p.exact), default=0)
        return max(hll.count(), exact_limit + 1, biggest_exact)

    def at_least(self, n: int) -> bool:
        """n ≤ exact_limit이면 항상 정확한 판정."""
        return (len(self._set) >= n) if self._set is not None else (n <= self.exact_limit + 1 or self._hll.count() >= n)


class CappedSet:
    """limit개까지만 담는다. 넘으면 saturated (예: "64+")."""

    __slots__ = ("limit", "items", "saturated")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.items: set = set()
        self.saturated = False

    def add(self, item) -> None:
        if item in self.items:
            return
        if len(self.items) < self.limit:
            self.items.add(item)
        else:
            self.saturated = True

    def __len__(self) -> int:
        return len(self.items)

    def label(self) -> str:
        return f"{self.limit}+" if self.saturated else str(len(self.items))
