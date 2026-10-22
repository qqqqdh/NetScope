"""TrafficAnalyzer: 정확 계층과 근사 계층 (DESIGN §5.6).

- 정확 / 합계: 1초 버킷의 total과 프로토콜별 [pkts, bytes]
- 정확 / 엣지: 5초 버킷의 엣지 테이블(상한 max_edges). 진입한 엣지는 이후 정확히 센다.
  상한에 도달하면 새 엣지는 진입시키지 않고 other에 정확히 더한다.
- 근사 / 후보: 미추적 패킷만 보는 Space-Saving 스케치. 어떤 합계에도 섞지 않는다.

불변식: 모든 엣지 버킷에서 Σ추적 엣지 + other == total (패킷·바이트).
"""
from __future__ import annotations

import math

from .bounded import SpaceSaving
from .models import Classification, Packet, int_to_ip
from .protocols import LocalNets, scope

PREADMIT = 32   # 다음 버킷에 미리 자리를 잡아 줄 스케치 후보 수


class _Sec:
    __slots__ = ("packets", "bytes", "protocols")

    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.protocols: dict[str, list[int]] = {}   # name -> [pkts, bytes, estimated_bytes, low_conf_bytes]


class _Edge:
    __slots__ = ("packets", "bytes", "protocols")

    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.protocols: dict[str, int] = {}


class _EdgeBucket:
    __slots__ = ("edges", "other_packets", "other_bytes", "total_packets", "total_bytes",
                 "sketch", "saturated")

    def __init__(self, sketch_k: int) -> None:
        self.edges: dict[tuple, _Edge] = {}
        self.other_packets = 0
        self.other_bytes = 0
        self.total_packets = 0
        self.total_bytes = 0
        self.sketch = SpaceSaving(sketch_k)
        self.saturated = False


class TrafficAnalyzer:
    def __init__(self, window: int = 60, edge_bucket: int = 5, max_edges: int = 5_000,
                 sketch_k: int = 256, top_edges: int = 200,
                 local_nets: LocalNets | None = None) -> None:
        if window % edge_bucket:
            raise ValueError("window must be a multiple of edge_bucket")
        self.window = window
        self.edge_bucket = edge_bucket
        self.max_edges = max_edges
        self.sketch_k = sketch_k
        self.top_edges = top_edges
        self.local_nets = local_nets or LocalNets()
        self._secs: dict[int, _Sec] = {}
        self._ebuckets: dict[int, _EdgeBucket] = {}
        self.untracked_packets = 0

    # ------------------------------------------------------------------ 입력
    def add(self, pkt: Packet, cls: Classification) -> bool:
        """패킷을 집계한다. 엣지가 추적되지 않았으면 False."""
        sec = math.floor(pkt.ts)
        s = self._secs.get(sec)
        if s is None:
            s = self._secs[sec] = _Sec()
        s.packets += 1
        s.bytes += pkt.length
        p = s.protocols.get(cls.name)
        if p is None:
            p = s.protocols[cls.name] = [0, 0, 0, 0]
        p[0] += 1
        p[1] += pkt.length
        if cls.estimated:
            p[2] += pkt.length
        if cls.confidence == "low":
            p[3] += pkt.length

        start = sec - sec % self.edge_bucket
        eb = self._ebuckets.get(start)
        if eb is None:
            eb = self._new_edge_bucket(start)
        eb.total_packets += 1
        eb.total_bytes += pkt.length
        key = (pkt.ver, pkt.src, pkt.dst) if pkt.src <= pkt.dst else (pkt.ver, pkt.dst, pkt.src)
        e = eb.edges.get(key)
        if e is None:
            if len(eb.edges) >= self.max_edges:
                eb.other_packets += 1
                eb.other_bytes += pkt.length
                eb.sketch.touch(key, pkt.length)
                eb.saturated = True
                self.untracked_packets += 1
                return False
            e = eb.edges[key] = _Edge()
        e.packets += 1
        e.bytes += pkt.length
        e.protocols[cls.name] = e.protocols.get(cls.name, 0) + pkt.length
        return True

    def _new_edge_bucket(self, start: int) -> _EdgeBucket:
        eb = self._ebuckets[start] = _EdgeBucket(self.sketch_k)
        prev = self._ebuckets.get(start - self.edge_bucket)
        if prev is not None and prev.saturated:
            # 직전 버킷에서 자리를 못 얻은 heavy hitter 후보에게 먼저 자리를 준다
            for key, _, _ in prev.sketch.items()[:PREADMIT]:
                eb.edges[key] = _Edge()
        return eb

    def prune(self, closed_until: int) -> None:
        """윈도우 밖 버킷을 버린다 (closed_until 미만은 마감된 초)."""
        keep_from = closed_until - self.window - self.edge_bucket
        for sec in [s for s in self._secs if s < keep_from]:
            del self._secs[sec]
        for start in [s for s in self._ebuckets if s < keep_from - self.edge_bucket]:
            del self._ebuckets[start]

    # ------------------------------------------------------------------ 스냅샷
    def snapshot(self, end: int) -> dict:
        """마감된 초 [end − window, end)의 스냅샷."""
        labels = list(range(end - self.window, end))
        totals = {"packets": 0, "bytes": 0}
        protocols: dict[str, dict] = {}
        series: dict[str, list[int]] = {}
        for idx, sec in enumerate(labels):
            s = self._secs.get(sec)
            if s is None:
                continue
            totals["packets"] += s.packets
            totals["bytes"] += s.bytes
            for name, (pk, by, est, low) in s.protocols.items():
                agg = protocols.setdefault(name, {"packets": 0, "bytes": 0, "estimated_bytes": 0,
                                                  "low_confidence_bytes": 0})
                agg["packets"] += pk
                agg["bytes"] += by
                agg["estimated_bytes"] += est
                agg["low_confidence_bytes"] += low
                series.setdefault(name, [0] * self.window)[idx] += by
        for agg in protocols.values():
            agg["estimated"] = agg["estimated_bytes"] > 0

        return {
            "end": end,
            "window": self.window,
            "totals": totals,
            "rate": {"bytes_per_sec": sum(v[-1] for v in series.values()) if series else 0},
            "protocols": dict(sorted(protocols.items(), key=lambda kv: -kv[1]["bytes"])),
            "timeseries": {"labels": labels, "series": series},
            "graph": self._graph(end),
        }

    def _graph(self, end: int) -> dict:
        g_end = end - end % self.edge_bucket            # 마감된 5초 버킷만
        g_start = g_end - self.window
        edges: dict[tuple, list] = {}
        total_p = total_b = 0
        lower_bound = False
        approx: dict[tuple, list[int]] = {}
        for start in range(g_start, g_end, self.edge_bucket):
            eb = self._ebuckets.get(start)
            if eb is None:
                continue
            total_p += eb.total_packets
            total_b += eb.total_bytes
            lower_bound |= eb.saturated
            for key, e in eb.edges.items():
                if e.packets == 0:
                    continue
                agg = edges.get(key)
                if agg is None:
                    agg = edges[key] = [0, 0, {}]
                agg[0] += e.packets
                agg[1] += e.bytes
                for name, by in e.protocols.items():
                    agg[2][name] = agg[2].get(name, 0) + by
            for key, est, err in eb.sketch.items():
                a = approx.setdefault(key, [0, 0])
                a[0] += est
                a[1] += err

        top = sorted(edges.items(), key=lambda kv: -kv[1][1])[: self.top_edges]
        shown_p = sum(v[0] for _, v in top)
        shown_b = sum(v[1] for _, v in top)
        nodes: dict[tuple, dict] = {}
        edge_list = []
        for (ver, a, b), (pk, by, protos) in top:
            ids = []
            for ip in (a, b):
                n = nodes.get((ver, ip))
                if n is None:
                    n = nodes[(ver, ip)] = {"id": int_to_ip(ip, ver), "bytes": 0, "packets": 0,
                                            "peers": 0, "local": self.local_nets.contains(ip, ver),
                                            "scope": scope(ip, ver)}
                n["bytes"] += by
                n["packets"] += pk
                n["peers"] += 1
                ids.append(n["id"])
            edge_list.append({"source": ids[0], "target": ids[1], "bytes": by, "packets": pk,
                              "protocols": dict(sorted(protos.items(), key=lambda kv: -kv[1]))})
        heavy = sorted(approx.items(), key=lambda kv: -kv[1][0])[:10]
        return {
            "start": g_start,
            "end": g_end,
            "nodes": list(nodes.values()),
            "edges": edge_list,
            "total": {"packets": total_p, "bytes": total_b},
            # 정확한 값: 화면에 그리지 않은 추적 엣지 + 미추적(other)
            "other": {"packets": total_p - shown_p, "bytes": total_b - shown_b},
            "edges_lower_bound": lower_bound,
            "approx_heavy_hitters": [
                {"source": int_to_ip(a, ver), "target": int_to_ip(b, ver),
                 "est_bytes": est, "error": err}
                for (ver, a, b), (est, err) in heavy],
            "top_talkers": sorted(nodes.values(), key=lambda n: -n["bytes"])[:10],
        }

    def sec_bytes(self, sec: int) -> int:
        s = self._secs.get(sec)
        return s.bytes if s else 0

    # ------------------------------------------------------------------ 검증용
    def check_invariant(self) -> None:
        for start, eb in self._ebuckets.items():
            p = sum(e.packets for e in eb.edges.values()) + eb.other_packets
            b = sum(e.bytes for e in eb.edges.values()) + eb.other_bytes
            if (p, b) != (eb.total_packets, eb.total_bytes):
                raise AssertionError(f"edge bucket {start}: tracked+other={p}/{b} "
                                     f"!= total={eb.total_packets}/{eb.total_bytes}")

    def stats(self) -> dict:
        return {"sec_buckets": len(self._secs), "edge_buckets": len(self._ebuckets),
                "max_edges_in_bucket": max((len(eb.edges) for eb in self._ebuckets.values()), default=0)}
