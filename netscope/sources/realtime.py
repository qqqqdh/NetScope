"""시뮬레이터를 벽시계 속도(speed배)로 재생해 파이프라인에 넣는 소스 스레드."""
from __future__ import annotations

import threading
import time
from typing import Callable

from ..models import Packet
from .sim import Simulation


class SimSource:
    def __init__(self, sim: Simulation, offer: Callable[[Packet], bool], speed: float = 1.0) -> None:
        self.sim = sim
        self.offer = offer
        self.speed = speed
        self._gen = sim.run(duration=10 ** 9)
        self._pending: Packet | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netscope-sim", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _loop(self) -> None:
        # 재시작할 때마다 기준점을 다시 잡는다 (일시정지한 시간만큼 시뮬레이터 시계가 멈춘 것으로 본다)
        anchor_wall = anchor_ts = None
        while not self._stop.is_set():
            pkt = self._pending or next(self._gen)
            self._pending = None
            if anchor_wall is None:
                anchor_wall, anchor_ts = time.monotonic(), pkt.ts
            delay = anchor_wall + (pkt.ts - anchor_ts) / self.speed - time.monotonic()
            if delay > 0:
                self._stop.wait(min(delay, 0.2))
                if delay > 0.2 or self._stop.is_set():
                    self._pending = pkt
                    continue
            self.offer(pkt)
            self.sent += 1
