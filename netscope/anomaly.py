"""이상 탐지 4종 (DESIGN §5.4).

CoreEngine에 리스너로 붙는다. 판정은 초가 마감될 때(close) 이벤트 시간으로 한다.
- port_scan:   출발지별 new_syn의 서로 다른 목적지 포트 수 (재전송 제외)
- syn_flood / service_connectivity_issue: 서비스별 SYN 코호트 + 판별 점수
- dns_flood:   출발지별 DNS 질의 수 + 지속성
- traffic_spike: 초당 총 바이트의 EWMA 기준선 대비
"""
from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass

from .bounded import HybridCardinality, SpaceSaving
from .engine import CoreEngine
from .flows import FlowEvent
from .models import Alert, Packet, int_to_ip
from .protocols import LocalNets

_CONF = ["low", "medium", "high"]


def _lower(conf: str, steps: int = 1) -> str:
    return _CONF[max(0, _CONF.index(conf) - steps)]


@dataclass
class Thresholds:
    cooldown: float = 30.0
    # port_scan
    scan_window: int = 10
    scan_ports: int = 20
    scan_port_cap: int = 64
    scan_keys: int = 10_000
    # syn
    syn_window: int = 5
    syn_grace: int = 1
    syn_min: int = 100
    syn_factor: float = 3.0
    syn_cold_age: float = 30.0
    syn_sources: int = 50
    syn_alpha: float = 0.1
    syn_keys: int = 5_000
    syn_completion_ok: float = 0.5
    syn_half_open: float = 0.8
    syn_unanswered: float = 0.8
    syn_retrans_low: float = 0.2
    syn_retrans_high: float = 0.5
    syn_novel_high: float = 0.8
    syn_novel_low: float = 0.3
    history_size: int = 100_000
    history_ttl: float = 600.0
    # dns
    dns_window: int = 10
    dns_queries: int = 80
    dns_active_slots: int = 6
    dns_keys: int = 10_000
    # spike
    spike_warmup: int = 10
    spike_alpha: float = 0.1
    spike_z: float = 4.0
    spike_factor: float = 3.0
    spike_min_bytes: int = 50_000
    spike_rebaseline: int = 10


def _ip(key) -> str:
    return int_to_ip(key[1], key[0])


# ====================================================================== port_scan
class _ScanState:
    __slots__ = ("ports", "targets", "saturated", "last")

    def __init__(self) -> None:
        self.ports: dict[int, float] = {}
        self.targets: Counter = Counter()
        self.saturated = False
        self.last = 0.0


class PortScanDetector:
    def __init__(self, owner: "AnomalyDetector") -> None:
        self.o, self.t = owner, owner.t
        self.keys = SpaceSaving(self.t.scan_keys)
        self.states: dict = {}
        self.hot: set = set()

    def on_new_syn(self, ev: FlowEvent) -> None:
        if ev.server_port is None:
            return
        src = (ev.ver, ev.client)
        evicted = self.keys.touch(src)
        if evicted is not None:
            self.states.pop(evicted, None)
            self.hot.discard(evicted)
            self.o.engine.health.record("detector_eviction", ev.ts)
        st = self.states.get(src)
        if st is None:
            st = self.states[src] = _ScanState()
        ports = st.ports
        if ev.server_port in ports or len(ports) < self.t.scan_port_cap:
            ports[ev.server_port] = ev.ts
        else:
            cutoff = ev.ts - self.t.scan_window
            for p in [p for p, ts in ports.items() if ts < cutoff]:
                del ports[p]
            if len(ports) < self.t.scan_port_cap:
                ports[ev.server_port] = ev.ts
            else:
                st.saturated = True
        if ev.server in st.targets or len(st.targets) < 16:
            st.targets[ev.server] += 1
        st.last = ev.ts
        if len(ports) >= self.t.scan_ports:
            self.hot.add(src)

    def evaluate(self, now: float) -> list[Alert]:
        out = []
        cutoff = now - self.t.scan_window
        for src in list(self.hot):
            st = self.states.get(src)
            if st is None:
                self.hot.discard(src)
                continue
            for p in [p for p, ts in st.ports.items() if ts < cutoff]:
                del st.ports[p]
            if len(st.ports) < self.t.scan_ports:
                self.hot.discard(src)
                st.saturated = False
                continue
            # 마감된 구간 [now − window, now)만 센다. lateness 때문에 먼저 들어온 미래 이벤트를
            # 세면 결과가 lateness 설정에 따라 달라진다 (재생 결정성 깨짐).
            n = sum(1 for ts in st.ports.values() if ts < now)
            if n < self.t.scan_ports:
                continue
            if not self.o.allowed("port_scan", src):
                continue
            label = f"{n}+" if st.saturated and n >= self.t.scan_port_cap else str(n)
            targets = [int_to_ip(ip, src[0]) for ip, _ in st.targets.most_common(3)]
            out.append(Alert(
                ts=now, type="port_scan", severity="high", confidence="medium", key=_ip(src),
                message=f"{_ip(src)}에서 포트 스캔 의심: {self.t.scan_window}초간 서로 다른 포트 {label}개 "
                        f"(대상 {', '.join(targets)})",
                details={"ports": n, "ports_label": label, "targets": targets,
                         "sample_ports": sorted(st.ports)[:20]}))
        if int(now) % 10 == 0:                                   # 유휴 상태 정리
            for src in [s for s, st in self.states.items() if st.last < cutoff]:
                del self.states[src]
                self.keys.remove(src)
                self.hot.discard(src)
        return out


# ====================================================================== syn
class _Svc:
    __slots__ = ("cohorts", "sources", "first_seen", "mean", "src_mean", "n", "last", "approx_until")

    def __init__(self, ts: float) -> None:
        self.cohorts: dict[int, list[int]] = {}      # sec -> [syn, retrans, answered, rst, completed, novel]
        self.sources: dict[int, HybridCardinality] = {}
        self.first_seen = ts
        self.mean = 0.0
        self.src_mean = 0.0
        self.n = 0
        self.last = ts
        self.approx_until = -1.0


class SynDetector:
    def __init__(self, owner: "AnomalyDetector") -> None:
        self.o, self.t = owner, owner.t
        self.keys = SpaceSaving(self.t.syn_keys)
        self.states: dict = {}
        self.active: set = set()

    def on_event(self, ev: FlowEvent) -> None:
        if ev.server_port is None or ev.syn_ts is None:
            return
        key = (ev.ver, ev.server, ev.server_port)
        sec = math.floor(ev.syn_ts)
        if ev.kind == "new_syn":
            evicted = self.keys.touch(key)
            if evicted is not None:
                self.states.pop(evicted, None)
                self.active.discard(evicted)
                self.o.engine.health.record("detector_eviction", ev.ts)
            st = self.states.get(key)
            if st is None:
                st = self.states[key] = _Svc(ev.ts)
            c = st.cohorts.get(sec)
            if c is None:
                c = st.cohorts[sec] = [0, 0, 0, 0, 0, 0]
                st.sources[sec] = HybridCardinality()
            c[0] += 1
            if not self.o.in_history((ev.ver, ev.client), ev.ts):
                c[5] += 1
            st.sources[sec].add(ev.client)
            st.last = ev.ts
            self.active.add(key)
            return
        st = self.states.get(key)
        if st is None:
            return
        c = st.cohorts.get(sec)
        if c is None:
            return
        kind = ev.kind
        if kind == "syn_retrans":
            c[1] += 1
            if ev.approx:
                st.approx_until = ev.ts + self.t.syn_window + self.t.syn_grace
        elif kind == "synack":
            c[2] += 1
        elif kind == "rst_from_responder":
            c[2] += 1
            c[3] += 1
        elif kind == "handshake_done":
            c[4] += 1

    def evaluate(self, sec: int) -> list[Alert]:
        t = self.t
        now = sec + 1
        lo = sec - t.syn_grace - t.syn_window + 1
        out = []
        for key in list(self.active):
            st = self.states.get(key)
            if st is None:
                self.active.discard(key)
                continue
            for c in [c for c in st.cohorts if c < lo]:
                del st.cohorts[c]
                del st.sources[c]
            if not st.cohorts:
                if st.last < now - 60:
                    self.active.discard(key)
                continue
            agg, sources = self.window(st, sec)
            syn, retrans, answered, rst, completed, novel = agg
            cold = now - st.first_seen < t.syn_cold_age
            if cold:
                triggered = syn >= t.syn_min and sources >= t.syn_sources
            else:
                triggered = syn >= t.syn_min and syn >= t.syn_factor * max(st.mean, 1.0)
            if not triggered or completed / syn >= t.syn_completion_ok:
                self._update_baseline(st, syn, sources)
                continue
            alert = self._judge(key, st, now, syn, retrans, answered, rst, completed, novel, sources, cold)
            if alert is not None:
                out.append(alert)
        return out

    def window(self, st: _Svc, sec: int) -> tuple[list[int], int]:
        """초 sec 마감 시점의 판정 구간: 응답 유예가 지난 코호트 [sec−grace−window+1, sec−grace]."""
        hi = sec - self.t.syn_grace
        lo = hi - self.t.syn_window + 1
        agg = [0] * 6
        parts = []
        for c in range(lo, hi + 1):
            v = st.cohorts.get(c)
            if v is not None:
                for i in range(6):
                    agg[i] += v[i]
                parts.append(st.sources[c])
        return agg, (HybridCardinality.union_count(parts) if parts else 0)

    def _update_baseline(self, st: _Svc, syn: int, sources: int) -> None:
        a = self.t.syn_alpha
        if st.n == 0:
            st.mean, st.src_mean = float(syn), float(sources)
        else:
            st.mean += a * (syn - st.mean)
            st.src_mean += a * (sources - st.src_mean)
        st.n += 1

    def _judge(self, key, st, now, syn, retrans, answered, rst, completed, novel, sources, cold):
        t = self.t
        flood, conn, indicators = 0, 0, {}
        visibility = self.o.visibility()
        half_open = max(0, answered - rst - completed)
        unanswered = max(0, syn - answered)
        if visibility != "unidirectional":
            ho, un = half_open / syn, (unanswered + rst) / syn
            indicators["half_open_ratio"] = round(ho, 3)
            indicators["unanswered_or_rst_ratio"] = round(un, 3)
            if ho >= t.syn_half_open:
                flood += 1
            if un >= t.syn_unanswered:
                conn += 1
        r = retrans / syn
        indicators["retrans_ratio"] = round(r, 3)
        if r < t.syn_retrans_low:
            flood += 1
        elif r >= t.syn_retrans_high:
            conn += 1
        nv = novel / syn
        indicators["novel_source_ratio"] = round(nv, 3)
        if nv >= t.syn_novel_high:
            flood += 1
        elif nv < t.syn_novel_low:
            conn += 1
        indicators["sources"] = sources
        if sources >= t.syn_sources:
            flood += 1
        elif sources < max(10.0, 2 * st.src_mean):
            conn += 1

        if flood >= 2 and flood >= conn:
            kind, score = "syn_flood", flood
        elif conn >= 2 and conn > flood:
            kind, score = "service_connectivity_issue", conn
        else:
            kind, score = "syn_flood", 0                     # 애매함 → 낮은 신뢰도로라도 알림
        conf = "high" if score >= 3 else "medium"
        if score == 0:
            conf = "low"
        steps = (visibility == "unidirectional") + cold + (st.approx_until >= now)
        conf = _lower(conf, steps)
        server = int_to_ip(key[1], key[0])
        service = f"{server}:{key[2]}"
        if not self.o.allowed(kind, (key[0], key[1])):
            return None
        details = {"syn": syn, "retrans": retrans, "answered": answered, "rst": rst,
                   "completed": completed, "novel": novel, "baseline": round(st.mean, 1),
                   "cold_start": cold, "visibility": visibility, "flood_score": flood,
                   "connectivity_score": conn, **indicators}
        if kind == "syn_flood":
            sev = "high" if sources >= t.syn_sources else "medium"
            msg = (f"{service}로 SYN 플러드 의심: {t.syn_window}초간 SYN {syn}개, 완료 {completed}개, "
                   f"출발지 {sources}곳 (점수 플러드 {flood} / 장애 {conn})")
        else:
            sev = "low"
            msg = (f"{service} 서비스 응답 없음 — 장애 또는 차단 의심: SYN {syn}개 중 응답 {answered}개, "
                   f"재전송 비율 {r:.2f} (점수 장애 {conn} / 플러드 {flood})")
        return Alert(ts=now, type=kind, severity=sev, confidence=conf, key=service,
                     message=msg, details=details)


# ====================================================================== dns
class _DnsState:
    __slots__ = ("slots", "last", "resolvers")

    def __init__(self) -> None:
        self.slots: dict[int, int] = {}
        self.last = 0.0
        self.resolvers: set = set()


class DnsFloodDetector:
    def __init__(self, owner: "AnomalyDetector") -> None:
        self.o, self.t = owner, owner.t
        self.keys = SpaceSaving(self.t.dns_keys)
        self.states: dict = {}
        self.hot: set = set()

    def on_packet(self, pkt: Packet) -> None:
        if pkt.proto != "UDP" or pkt.dport != 53:
            return
        src = (pkt.ver, pkt.src)
        evicted = self.keys.touch(src)
        if evicted is not None:
            self.states.pop(evicted, None)
            self.hot.discard(evicted)
            self.o.engine.health.record("detector_eviction", pkt.ts)
        st = self.states.get(src)
        if st is None:
            st = self.states[src] = _DnsState()
        sec = math.floor(pkt.ts)
        st.slots[sec] = st.slots.get(sec, 0) + 1
        st.last = pkt.ts
        if len(st.resolvers) < 5:
            st.resolvers.add(pkt.dst)
        if len(st.slots) > self.t.dns_window + 3:
            for s in sorted(st.slots)[: len(st.slots) - self.t.dns_window - 3]:
                del st.slots[s]
        if sum(st.slots.values()) >= self.t.dns_queries:
            self.hot.add(src)

    def evaluate(self, now: float) -> list[Alert]:
        out = []
        t = self.t
        lo = int(now) - t.dns_window
        for src in list(self.hot):
            st = self.states.get(src)
            if st is None:
                self.hot.discard(src)
                continue
            window = [n for s, n in st.slots.items() if lo <= s < now]
            total, active = sum(window), sum(1 for n in window if n > 0)
            if sum(st.slots.values()) < t.dns_queries:
                self.hot.discard(src)
            if total < t.dns_queries or active < t.dns_active_slots:
                continue
            if not self.o.allowed("dns_flood", src):
                continue
            out.append(Alert(
                ts=now, type="dns_flood", severity="medium", confidence="medium", key=_ip(src),
                message=f"{_ip(src)}에서 DNS 질의 폭주 의심: {t.dns_window}초간 {total}건 "
                        f"({active}개 초에 걸쳐 지속)",
                details={"queries": total, "active_seconds": active,
                         "resolvers": sorted(int_to_ip(r, src[0]) for r in st.resolvers)}))
        if int(now) % 10 == 0:
            for src in [s for s, st in self.states.items() if st.last < lo]:
                del self.states[src]
                self.keys.remove(src)
                self.hot.discard(src)
        return out


# ====================================================================== spike
class TrafficSpikeDetector:
    def __init__(self, owner: "AnomalyDetector") -> None:
        self.o, self.t = owner, owner.t
        self.mean = 0.0
        self.var = 0.0
        self.n = 0
        self.streak = 0

    def evaluate(self, sec: int) -> list[Alert]:
        t = self.t
        x = self.o.engine.analyzer.sec_bytes(sec)
        if self.n == 0:
            self.mean, self.var, self.n = float(x), 0.0, 1
            return []
        std = math.sqrt(self.var)
        spike = (self.n >= t.spike_warmup and x >= t.spike_min_bytes
                 and x > self.mean + t.spike_z * std and x > t.spike_factor * self.mean)
        if spike:
            self.streak += 1
            if self.streak >= t.spike_rebaseline:          # 새 정상 수준으로 재설정
                self.mean, self.var, self.streak = float(x), 0.0, 0
                return []
            if self.streak > 1:
                return []                                  # 이어지는 급증 구간은 첫 초에만 알림
            return [Alert(
                ts=sec + 1, type="traffic_spike", severity="low", confidence="medium", key="global",
                message=f"트래픽 급증: {x / 1024:.0f} KB/s (기준선 {self.mean / 1024:.1f} KB/s의 "
                        f"{x / max(self.mean, 1):.1f}배)",
                details={"bytes": x, "baseline": round(self.mean), "std": round(std), "second": sec})]
        self.streak = 0
        d = x - self.mean
        self.mean += t.spike_alpha * d
        self.var = (1 - t.spike_alpha) * (self.var + t.spike_alpha * d * d)
        self.n += 1
        return []


# ====================================================================== 묶음
class AnomalyDetector:
    def __init__(self, engine: CoreEngine, thresholds: Thresholds | None = None,
                 allowlist: dict[str, list[str]] | None = None) -> None:
        self.engine = engine
        self.t = thresholds or Thresholds()
        self._allow = {k: LocalNets(v) for k, v in (allowlist or {}).items()}
        self._history: OrderedDict = OrderedDict()
        self._handshakes: deque = deque()                  # (ts, unidirectional)
        self._last_fired: dict = {}
        self.alerts: list[Alert] = []
        self._pending: list[Alert] = []
        self.scan = PortScanDetector(self)
        self.syn = SynDetector(self)
        self.dns = DnsFloodDetector(self)
        self.spike = TrafficSpikeDetector(self)
        engine.event_listeners.append(self._on_event)
        engine.packet_listeners.append(self._on_packet)
        engine.close_listeners.append(self._on_close)

    # ------------------------------------------------------------ 공통 상태
    def allowed(self, alert_type: str, key) -> bool:
        nets = self._allow.get(alert_type)
        return nets is None or not nets.contains(key[1], key[0])

    def in_history(self, key, now: float) -> bool:
        ts = self._history.get(key)
        return ts is not None and now - ts <= self.t.history_ttl

    def visibility(self) -> str:
        n = len(self._handshakes)
        if n < 10:
            return "unknown"
        uni = sum(1 for _, u in self._handshakes if u)
        return "unidirectional" if uni / n >= 0.8 else "bidirectional"

    # ------------------------------------------------------------ 리스너
    def _on_event(self, ev: FlowEvent) -> None:
        if ev.kind == "new_syn":
            self.scan.on_new_syn(ev)
        elif ev.kind == "handshake_done":
            key = (ev.ver, ev.client)
            self._history[key] = ev.ts
            self._history.move_to_end(key)
            if len(self._history) > self.t.history_size:
                self._history.popitem(last=False)
            self._handshakes.append((ev.ts, ev.unidirectional))
        self.syn.on_event(ev)

    def _on_packet(self, pkt: Packet, flow) -> None:
        self.dns.on_packet(pkt)

    def _on_close(self, sec: int) -> None:
        now = sec + 1
        while self._handshakes and self._handshakes[0][0] < now - 60:
            self._handshakes.popleft()
        if self.visibility() == "unidirectional":
            self.engine.health.record("unidirectional", sec)
        cands = (self.scan.evaluate(now) + self.syn.evaluate(sec)
                 + self.dns.evaluate(now) + self.spike.evaluate(sec))
        for a in cands:
            k = (a.type, a.key)
            last = self._last_fired.get(k)
            if last is not None and now - last < self.t.cooldown:
                continue
            self._last_fired[k] = now
            self.alerts.append(a)
            self._pending.append(a)

    def drain(self) -> list[Alert]:
        out, self._pending = self._pending, []
        return out
