"""Bounded Queue → AnalyzerWorker → Snapshot Publisher (DESIGN §3).

- 소스 스레드는 offer()로 큐에 넣기만 한다. 큐가 꽉 차면 새 패킷을 버리고 센다(절대 멈추지 않음).
- 워커 스레드 하나가 CoreEngine과 AnomalyDetector를 단독으로 소유한다(락 없음).
- 초가 마감되면 스냅샷을 만들고 JSON 직렬화를 한 번만 해서 on_publish로 넘긴다.
  다른 스레드는 엔진에 직접 접근하지 않고, 발행된 불변 문자열만 읽는다.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from typing import Callable

from .anomaly import AnomalyDetector, Thresholds
from .engine import CoreEngine
from .memory import rss_bytes
from .models import Packet

BACKLOG_SECONDS = 2.0


def percentiles(values) -> dict | None:
    """다른 스레드가 append 중인 deque도 안전하게 복사해 p50/p95/max를 돌려준다."""
    for _ in range(3):
        try:
            v = sorted(values)
            break
        except RuntimeError:                       # deque mutated during iteration
            continue
    else:
        return None
    if not v:
        return None
    pick = lambda q: round(v[min(len(v) - 1, int(q * len(v)))], 4)
    return {"n": len(v), "p50": pick(0.5), "p95": pick(0.95), "max": round(v[-1], 4)}


class Pipeline:
    def __init__(self, *, live: bool = False, queue_max: int = 50_000, lateness: float = 1.0,
                 thresholds: Thresholds | None = None, allowlist: dict[str, list[str]] | None = None,
                 alert_history: int = 500, batch: int = 2_000, memory_budget_mb: float = 400.0) -> None:
        self.live = live
        self.queue: queue.Queue = queue.Queue(maxsize=queue_max)
        self.engine = CoreEngine(live=live, lateness=lateness)
        self.detector = AnomalyDetector(self.engine, thresholds, allowlist, keep_alerts=0)
        self.batch = batch
        self.memory_budget_mb = memory_budget_mb
        self.queue_wait: deque = deque(maxlen=2000)        # 큐에서 꺼낼 때까지 기다린 시간(표본)
        self._cached = {"rss_mb": None, "structures": {}, "latency": {}}
        self.on_publish: Callable[[int, str, list[dict]], None] | None = None
        self.status_provider: Callable[[], dict] = lambda: {}
        self.started_at = time.time()
        self.seq = 0
        self.latest_snapshot: str | None = None      # 스냅샷 JSON
        self.latest_message: str | None = None       # {"type":"snapshot",...} JSON
        self._alerts: deque = deque(maxlen=alert_history)
        self._alerts_lock = threading.Lock()
        self.offered = 0
        self._drops = 0
        self._drops_reported = 0
        self._rate: deque = deque()                  # (wall, offered)
        self._flush = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------ 소스 쪽 (다른 스레드)
    def offer(self, pkt: Packet) -> bool:
        pkt.ingest_ts = time.time()
        self.offered += 1
        try:
            self.queue.put_nowait(pkt)
            return True
        except queue.Full:
            self._drops += 1
            return False

    def try_offer(self, pkt: Packet) -> bool:
        """큐가 차면 버리지 않고 False를 돌려준다 (PCAP 재생의 역압용, 손실로 세지 않음)."""
        pkt.ingest_ts = time.time()
        try:
            self.queue.put_nowait(pkt)
        except queue.Full:
            return False
        self.offered += 1
        return True

    def request_flush(self) -> None:
        """입력 끝(PCAP 등): 큐를 비운 뒤 남은 초를 모두 마감하게 한다."""
        self._flush.set()

    # ------------------------------------------------------------ 수명
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netscope-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    # ------------------------------------------------------------ 워커
    def _loop(self) -> None:
        eng = self.engine
        while not self._stop.is_set():
            closed = False
            try:
                pkt = self.queue.get(timeout=0.2)
            except queue.Empty:
                pkt = None
            if pkt is not None:
                n = 0
                while True:
                    if n % 100 == 0:
                        wait = time.time() - pkt.ingest_ts
                        self.queue_wait.append(wait)
                        if wait > BACKLOG_SECONDS:
                            eng.health.record("backlog", eng.clock.max_event or pkt.ts)
                    if eng.ingest(pkt):
                        closed = True
                    n += 1
                    if n >= self.batch:
                        break
                    try:
                        pkt = self.queue.get_nowait()
                    except queue.Empty:
                        break
            elif self._flush.is_set():
                self._flush.clear()
                closed = bool(eng.flush())
            elif self.live and eng.idle_advance(time.time()):
                closed = True
            self._sync_drops()
            if closed:
                self._publish()

    def _sync_drops(self) -> None:
        d = self._drops - self._drops_reported
        if d:
            self._drops_reported += d
            self.engine.health.record("queue_drop", self.engine.clock.max_event or time.time(), d)

    def _publish(self) -> None:
        new = [a.to_dict() for a in self.detector.drain()]
        if new:
            with self._alerts_lock:
                self._alerts.extend(new)
        eng = self.engine
        rss = rss_bytes()
        if rss is not None and rss > 0.9 * self.memory_budget_mb * 1e6:
            eng.health.record("memory_high", eng.clock.max_event or time.time())
        # 다른 스레드(REST)가 엔진을 직접 읽지 않도록 워커에서 계산해 둘
        self._cached = {
            "rss_mb": round(rss / 1e6, 1) if rss is not None else None,
            "structures": eng.sizes(),
            "latency": {"queue_wait": percentiles(self.queue_wait),
                        "packet_processing": percentiles(eng.processing_latency)},
        }
        end = eng.clock.closed_until or 0
        samples = eng.take_e2e_samples(end)
        snap = eng.snapshot()
        snap["status"] = self.status()
        body = json.dumps(snap, separators=(",", ":"), ensure_ascii=False)
        self.seq += 1
        msg = f'{{"type":"snapshot","seq":{self.seq},"data":{body}}}'
        self.latest_snapshot, self.latest_message = body, msg
        if self.on_publish is not None:
            self.on_publish(self.seq, msg, new, end, samples)

    # ------------------------------------------------------------ 조회 (아무 스레드)
    def pps(self) -> float:
        now = time.time()
        self._rate.append((now, self.offered))
        while len(self._rate) > 2 and self._rate[0][0] < now - 5:
            self._rate.popleft()
        (t0, n0), (t1, n1) = self._rate[0], self._rate[-1]
        return round((n1 - n0) / (t1 - t0), 1) if t1 > t0 else 0.0

    def status(self) -> dict:
        return {"pps": self.pps(), "uptime": round(time.time() - self.started_at, 1),
                "queue_size": self.queue.qsize(), "offered": self.offered,
                "queue_drops": self._drops, "seq": self.seq, "rss_mb": self._cached["rss_mb"],
                "memory_budget_mb": self.memory_budget_mb, "structures": self._cached["structures"],
                "latency": dict(self._cached["latency"]), **self.status_provider()}

    def alerts(self, since_id: int | None = None, limit: int = 50) -> list[dict]:
        with self._alerts_lock:
            items = list(self._alerts)
        if since_id is not None:
            items = [a for a in items if a["id"] > since_id]
        return items[-limit:]
