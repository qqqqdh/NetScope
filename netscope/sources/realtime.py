"""패킷열을 벽시계 속도(speed배)로 재생해 파이프라인에 넣는 소스 스레드.

- speed=0: 최대 속도(대기 없음).
- retry_on_full=True (PCAP): 큐가 차면 버리지 않고 기다렸다 다시 넣는다(역압). 재생 결과가
  기계 속도에 따라 달라지지 않게 하기 위함. Live 캡처는 반대로 버리고 센다(DESIGN §3).
- 입력이 끝나면 on_eof를 한 번 부른다(PCAP → 남은 초 마감).
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Iterator

from ..models import Packet
from .sim import Simulation


class PacedSource:
    def __init__(self, packets: Iterator[Packet], offer: Callable[[Packet], bool], speed: float = 1.0,
                 retry_on_full: bool = False, on_eof: Callable[[], None] | None = None,
                 name: str = "netscope-source") -> None:
        self._it = iter(packets)
        self.offer = offer
        self.speed = speed
        self.retry_on_full = retry_on_full
        self.on_eof = on_eof
        self.name = name
        self._pending: Packet | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0
        self.finished = False

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running or self.finished:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name=self.name, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _loop(self) -> None:
        # 재시작할 때마다 기준점을 다시 잡는다 (일시정지한 시간만큼 재생 시계가 멈춘 것으로 본다)
        anchor_wall = anchor_ts = None
        while not self._stop.is_set():
            pkt = self._pending
            self._pending = None
            if pkt is None:
                try:
                    pkt = next(self._it)
                except StopIteration:
                    self.finished = True
                    if self.on_eof is not None:
                        self.on_eof()
                    return
            if self.speed > 0:
                if anchor_wall is None:
                    anchor_wall, anchor_ts = time.monotonic(), pkt.ts
                delay = anchor_wall + (pkt.ts - anchor_ts) / self.speed - time.monotonic()
                if delay > 0:
                    self._stop.wait(min(delay, 0.2))
                    if delay > 0.2 or self._stop.is_set():
                        self._pending = pkt
                        continue
            if not self.offer(pkt) and self.retry_on_full:
                self._pending = pkt
                self._stop.wait(0.005)
                continue
            self.sent += 1


class SimSource(PacedSource):
    def __init__(self, sim: Simulation, offer: Callable[[Packet], bool], speed: float = 1.0) -> None:
        super().__init__(sim.run(duration=10 ** 9), offer, speed, name="netscope-sim")
