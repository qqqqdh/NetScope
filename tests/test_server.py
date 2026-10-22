"""§8.3 통합 테스트: REST, WebSocket 송신 정책, 소스 재시작, 종료."""
import asyncio
import contextlib
import threading
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from netscope.server import Client, Hub, create_app


def app(**kw):
    opts = dict(seed=100, speed=20.0, warmup=5.0, attack_interval=8.0)
    opts.update(kw)
    return create_app(**opts)


def wait_for(fn, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.05)
    raise AssertionError("timeout")


def netscope_threads():
    return sorted(t.name for t in threading.enumerate() if t.name.startswith("netscope-"))


def next_snapshot(ws, ack=True):
    while True:
        msg = ws.receive_json()
        if msg["type"] == "snapshot":
            if ack:
                ws.send_json({"type": "ack", "seq": msg["seq"]})
            return msg


def test_rest_endpoints():
    with TestClient(app()) as c:
        st = c.get("/api/status").json()
        assert st["mode"] == "sim" and st["source_running"]
        snap = wait_for(lambda: c.get("/api/snapshot").status_code == 200 and c.get("/api/snapshot").json())
        assert {"totals", "protocols", "timeseries", "graph", "health", "flows", "status"} <= set(snap)
        alerts = wait_for(lambda: c.get("/api/alerts").json(), timeout=15)
        first = alerts[0]["id"]
        assert all(a["id"] > first for a in c.get(f"/api/alerts?since_id={first}").json())


def test_ws_hello_then_snapshots_with_increasing_seq():
    with TestClient(app()) as c, c.websocket_connect("/ws") as ws:
        assert ws.receive_json()["type"] == "hello"
        seqs = [next_snapshot(ws)["seq"] for _ in range(5)]
        assert seqs == sorted(seqs) and len(set(seqs)) == 5


def test_twenty_clients_all_receive():
    with TestClient(app(speed=4.0)) as c, contextlib.ExitStack() as stack:
        socks = [stack.enter_context(c.websocket_connect("/ws")) for _ in range(20)]
        for ws in socks:
            assert ws.receive_json()["type"] == "hello"
        got = {i: [] for i in range(20)}
        for _ in range(4):                                      # 라운드 로빈으로 받고 바로 ack
            for i, ws in enumerate(socks):
                got[i].append(next_snapshot(ws)["seq"])
        assert all(len(v) == 4 and v == sorted(v) for v in got.values())
        assert c.get("/api/status").json()["ws_slow_disconnects"] == 0


def test_client_without_ack_is_kicked_others_unaffected():
    with TestClient(app(speed=20.0)) as c:
        with c.websocket_connect("/ws") as good, c.websocket_connect("/ws") as bad:
            good.receive_json()
            bad.receive_json()
            code = None
            for _ in range(40):
                next_snapshot(good)
                try:
                    msg = bad.receive_json()                    # 받기만 하고 ack하지 않음
                except WebSocketDisconnect as e:
                    code = e.code
                    break
            assert code == 1013
            for _ in range(3):
                next_snapshot(good)                             # 정상 클라이언트는 계속 받음
        assert c.get("/api/status").json()["ws_slow_disconnects"] >= 1


def test_blocked_send_times_out():
    class StuckWS:
        closed_with = None

        async def send_text(self, text):
            await asyncio.Event().wait()                        # TCP 버퍼가 가득 찬 상황

        async def close(self, code=1000, reason=""):
            StuckWS.closed_with = code

    async def scenario():
        hub = Hub(send_timeout=0.2)
        hub.loop = asyncio.get_running_loop()
        cl = Client(StuckWS())
        hub.clients.add(cl)
        task = asyncio.create_task(hub.sender(cl))
        hub.publish(1, '{"type":"snapshot"}', [])
        await asyncio.wait_for(task, timeout=2)
        await asyncio.sleep(0.05)
        return cl.closed, hub.slow_disconnects

    closed, kicks = asyncio.run(scenario())
    assert closed and kicks == 1 and StuckWS.closed_with == 1013


def test_source_stop_start_no_thread_leak():
    with TestClient(app()) as c:
        before = netscope_threads()
        for _ in range(3):
            assert c.post("/api/source/stop").json() == {"source_running": False}
            assert c.post("/api/source/start").json() == {"source_running": True}
        assert netscope_threads() == before
        seq = c.get("/api/status").json()["seq"]
        wait_for(lambda: c.get("/api/status").json()["seq"] > seq)  # 재개 후에도 스냅샷 계속 발행


def test_shutdown_within_two_seconds():
    tc = TestClient(app())
    tc.__enter__()
    wait_for(lambda: tc.get("/api/status").json()["seq"] > 0)
    t0 = time.time()
    tc.__exit__(None, None, None)
    assert time.time() - t0 < 2.0
    wait_for(lambda: netscope_threads() == [], timeout=1.0)


def test_unsupported_mode_rejected():
    with pytest.raises(ValueError):
        create_app(mode="live")
