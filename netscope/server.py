"""FastAPI 서버: REST + WebSocket (DESIGN §3, §5.8).

WebSocket 송신 정책 (클라이언트별):
- snapshot: 최신 값 하나만 보관(latest-wins). 느린 클라이언트에게 옛 스냅샷이 쌓이지 않는다.
- alert: 순서 보장 큐(최대 100). 넘치면 연결 종료(1013) → 클라이언트가 재접속 후 since_id로 복구.
- ack: 클라이언트는 스냅샷을 화면에 적용한 뒤 ack를 보낸다. 미확인 스냅샷이 max_unacked를
  넘거나 전송이 send_timeout초 넘게 막히면 그 클라이언트만 1013으로 끊는다.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .anomaly import Thresholds
from .pipeline import Pipeline, percentiles
from .sources.realtime import PacedSource, SimSource
from .sources.sim import live_demo

STATIC = Path(__file__).parent / "static"


class Client:
    def __init__(self, ws: WebSocket) -> None:
        self.ws = ws
        self.snapshot: tuple | None = None    # (seq, msg, end)
        self.pending_samples: list[float] = []  # 아직 보내지 않은 스냅샷들의 E2E 표본 (latest-wins로 덮여도 유지)
        self.alerts: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.wake = asyncio.Event()
        self.sent_seq = 0
        self.outstanding: deque = deque()     # (seq, 보낸 단조 시각, end, samples)
        self.closed = False


class Hub:
    def __init__(self, send_timeout: float = 5.0, max_unacked: int = 5) -> None:
        self.send_timeout = send_timeout
        self.max_unacked = max_unacked
        self.clients: set[Client] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.slow_disconnects = 0
        self.ack_rtts: deque = deque(maxlen=1000)
        self.freshness: deque = deque(maxlen=1000)     # ack 시각 − 스냅샷 최신 마감 초의 끝
        self.e2e: deque = deque(maxlen=2000)           # ack 시각 − 표본 패킷 ingest_ts

    # ------------------------------------------------------------ 워커 스레드에서
    def publish_threadsafe(self, seq: int, msg: str, alerts: list[dict], end: int | None = None,
                           samples: list[float] = ()) -> None:
        if self.loop is not None and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.publish, seq, msg, alerts, end, list(samples))

    # ------------------------------------------------------------ 이벤트 루프에서
    def publish(self, seq: int, msg: str, alerts: list[dict], end: int | None = None,
                samples: list[float] = ()) -> None:
        encoded = [json.dumps({"type": "alert", "data": a}, ensure_ascii=False) for a in alerts]
        for c in list(self.clients):
            if c.closed:
                continue
            c.snapshot = (seq, msg, end)
            if len(c.pending_samples) < 50:
                c.pending_samples.extend(samples)
            for text in encoded:
                try:
                    c.alerts.put_nowait(text)
                except asyncio.QueueFull:
                    self.kick(c, "alert queue overflow")
                    break
            c.wake.set()

    def kick(self, c: Client, reason: str) -> None:
        if c.closed:
            return
        c.closed = True
        c.wake.set()
        self.slow_disconnects += 1
        asyncio.ensure_future(self._close(c, reason))

    async def _close(self, c: Client, reason: str) -> None:
        try:
            await asyncio.wait_for(c.ws.close(code=1013, reason=reason), timeout=1.0)
        except Exception:
            pass

    async def _send(self, c: Client, text: str) -> bool:
        try:
            await asyncio.wait_for(c.ws.send_text(text), timeout=self.send_timeout)
            return True
        except asyncio.TimeoutError:
            self.kick(c, "send timeout")
        except Exception:
            c.closed = True
        return False

    async def sender(self, c: Client) -> None:
        while not c.closed:
            await c.wake.wait()
            c.wake.clear()
            while not c.closed and not c.alerts.empty():
                if not await self._send(c, c.alerts.get_nowait()):
                    return
            snap = c.snapshot
            if c.closed or snap is None or snap[0] <= c.sent_seq:
                continue
            if len(c.outstanding) >= self.max_unacked:
                self.kick(c, "too many unacked snapshots")
                return
            if not await self._send(c, snap[1]):
                return
            c.sent_seq = snap[0]
            samples, c.pending_samples = c.pending_samples, []
            c.outstanding.append((snap[0], time.monotonic(), snap[2], samples))

    def on_ack(self, c: Client, seq: int) -> None:
        """브라우저는 화면에 적용한 뒤 ack를 보낸다 → ack 시각 = 화면 반영 시각 (§9)."""
        mono, wall = time.monotonic(), time.time()
        while c.outstanding and c.outstanding[0][0] <= seq:
            s, sent, end, samples = c.outstanding.popleft()
            for ingest in samples:                  # 이 초들은 acked 스냅샷 이전에 포함됐다
                self.e2e.append(wall - ingest)
            if s == seq:
                self.ack_rtts.append(mono - sent)
                if end:
                    self.freshness.append(wall - end)

    async def serve(self, ws: WebSocket, hello: dict, latest: tuple | None) -> None:
        await ws.accept()
        c = Client(ws)
        self.clients.add(c)
        task = None
        try:
            await ws.send_text(json.dumps({"type": "hello", "data": hello}, ensure_ascii=False))
            if latest is not None:
                c.snapshot = latest
                c.wake.set()
            task = asyncio.create_task(self.sender(c))
            while not c.closed:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("type") == "ack":
                    self.on_ack(c, int(msg.get("seq", 0)))
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            c.closed = True
            c.wake.set()
            self.clients.discard(c)
            if task is not None:
                task.cancel()


def create_app(*, mode: str = "sim", seed: int = 1, speed: float = 1.0, attack_interval: float = 45.0,
               warmup: float = 40.0, queue_max: int = 50_000, lateness: float = 1.0,
               send_timeout: float = 5.0, max_unacked: int = 5,
               thresholds: Thresholds | None = None,
               allowlist: dict[str, list[str]] | None = None,
               pcap: str | None = None, iface: str | None = None, bpf: str | None = None,
               live_parser: str = "fast",
               memory_budget_mb: float = 400.0) -> FastAPI:
    if mode not in ("sim", "pcap", "live"):
        raise ValueError(f"알 수 없는 mode: {mode!r} (sim | pcap | live)")
    if mode == "pcap":
        if not pcap:
            raise ValueError("pcap 모드에는 --pcap 파일 경로가 필요합니다")
        if not Path(pcap).is_file():
            raise ValueError(f"PCAP 파일을 찾을 수 없습니다: {pcap}")
    hub = Hub(send_timeout=send_timeout, max_unacked=max_unacked)

    def make_source(pipe: Pipeline):
        if mode == "sim":
            return SimSource(live_demo(seed, start=time.time(), interval=attack_interval, warmup=warmup),
                             pipe.offer, speed=speed)
        if mode == "pcap":
            from .sources.pcap import iter_pcap
            return PacedSource(iter_pcap(pcap), pipe.try_offer, speed=speed, retry_on_full=True,
                               on_eof=pipe.request_flush, name="netscope-pcap")
        from .sources.live import LiveSource
        return LiveSource(pipe.offer, iface=iface, bpf=bpf, parser=live_parser)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        hub.loop = asyncio.get_running_loop()
        pipe = Pipeline(live=(mode == "live"), queue_max=queue_max, lateness=lateness,
                        thresholds=thresholds, allowlist=allowlist, memory_budget_mb=memory_budget_mb)
        source = make_source(pipe)
        pipe.status_provider = lambda: {"mode": mode, "source_running": source.running,
                                        "source_finished": getattr(source, "finished", False),
                                        "clients": len(hub.clients),
                                        "ws_slow_disconnects": hub.slow_disconnects}
        pipe.on_publish = hub.publish_threadsafe
        app.state.pipe, app.state.source, app.state.hub = pipe, source, hub
        pipe.start()
        try:
            source.start()
        except Exception:
            pipe.stop()
            raise
        try:
            yield
        finally:
            source.stop()
            pipe.stop()
            for c in list(hub.clients):
                c.closed = True
                c.wake.set()

    app = FastAPI(title="NetScope", lifespan=lifespan)
    if STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index():
        page = STATIC / "index.html"
        if not page.exists():
            return Response("대시보드 파일이 없습니다 (netscope/static/index.html)", status_code=503)
        return FileResponse(page)

    @app.get("/api/status")
    def status():
        # sync 핸들러는 스레드 풀에서 돌므로, 이벤트 루프가 append 중인 deque를 안전하게 복사한다
        st = app.state.pipe.status()
        rtt = percentiles(hub.ack_rtts)
        st["ws_ack_rtt_p95"] = rtt["p95"] if rtt else None
        st["latency"].update({"snapshot_freshness": percentiles(hub.freshness),
                              "sampled_e2e": percentiles(hub.e2e), "ws_ack_rtt": rtt})
        return st

    @app.get("/api/snapshot")
    def snapshot():
        body = app.state.pipe.latest_snapshot
        if body is None:
            return JSONResponse({"detail": "아직 마감된 초가 없습니다"}, status_code=503)
        return Response(body, media_type="application/json")

    @app.get("/api/alerts")
    def alerts(since_id: int | None = None, limit: int = 50):
        return app.state.pipe.alerts(since_id, min(max(limit, 1), 500))

    @app.post("/api/source/stop")
    def source_stop():
        app.state.source.stop()
        return {"source_running": app.state.source.running}

    @app.post("/api/source/start")
    def source_start():
        app.state.source.start()
        return {"source_running": app.state.source.running}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        pipe = app.state.pipe
        latest = (pipe.seq, pipe.latest_message, None) if pipe.latest_message else None
        hello = {"status": pipe.status(), "alerts": pipe.alerts(limit=50)}
        await hub.serve(ws, hello, latest)

    return app
