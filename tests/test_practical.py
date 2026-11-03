import csv
import io
import socket
import time
from collections import namedtuple

import psutil
import pytest
from fastapi.testclient import TestClient

from netscope.history import HistoryStore
from netscope.models import make_packet
from netscope.processes import ProcessMonitor
from netscope.server import create_app


Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "pid family type laddr raddr")


def connection(pid=42, proto=socket.SOCK_STREAM, local="10.0.0.1", remote="8.8.8.8"):
    return Conn(pid, socket.AF_INET, proto, Addr(local, 5000), Addr(remote, 443) if remote else ())


def fake_processes(monkeypatch, connections):
    monkeypatch.setattr(psutil, "net_connections", lambda **kw: connections)
    class Process:
        def __init__(self, pid): self.pid = pid
        def name(self): return "browser.exe"
        def create_time(self): return 1234.0
    monkeypatch.setattr(psutil, "Process", Process)


def test_process_attribution_directions_and_unmatched(monkeypatch):
    fake_processes(monkeypatch, [connection()])
    monitor = ProcessMonitor()
    monitor.refresh()
    monitor.record(make_packet(1, "10.0.0.1", "8.8.8.8", "TCP", 100, sport=5000, dport=443))
    monitor.record(make_packet(2, "8.8.8.8", "10.0.0.1", "TCP", 200, sport=443, dport=5000))
    monitor.record(make_packet(3, "10.0.0.2", "8.8.8.8", "TCP", 30, sport=5000, dport=443))
    snap = monitor.snapshot()
    assert snap["matched_bytes"] == 300 and snap["unmatched_bytes"] == 30
    assert snap["items"] == [dict(pid=42, name="browser.exe", sent_bytes=100,
                                  received_bytes=200, bytes=300, connections=1)]


def test_udp_wildcard_and_shared_socket_is_not_guessed(monkeypatch):
    conns = [connection(proto=socket.SOCK_DGRAM, local="0.0.0.0", remote=None)]
    fake_processes(monkeypatch, conns)
    monitor = ProcessMonitor()
    monitor.refresh()
    packet = make_packet(1, "10.0.0.1", "8.8.8.8", "UDP", 70, sport=5000, dport=53)
    monitor.record(packet)
    assert monitor.snapshot()["matched_bytes"] == 70
    conns.append(connection(pid=43, proto=socket.SOCK_DGRAM, local="0.0.0.0", remote=None))
    monitor.refresh()
    monitor.record(packet)
    assert monitor.snapshot()["unmatched_bytes"] == 70


def test_process_permission_failure_discards_stale_mapping(monkeypatch):
    fake_processes(monkeypatch, [connection()])
    monitor = ProcessMonitor()
    monitor.refresh()
    def denied(**kw): raise psutil.AccessDenied()
    monkeypatch.setattr(psutil, "net_connections", denied)
    monitor.refresh()
    monitor.record(make_packet(1, "10.0.0.1", "8.8.8.8", "TCP", 100, sport=5000, dport=443))
    snap = monitor.snapshot()
    assert snap["error"] and not snap["items"] and snap["unmatched_bytes"] == 100


def sample():
    return {"end": 100, "totals": {"bytes": 1000, "packets": 10}, "rate": {"bytes_per_sec": 20},
            "status": {"pps": 2, "queue_drops": 0}, "flows": {"active": 3}, "health": {"degraded": False}}


def alert():
    return dict(id=1, ts=99, type="traffic_spike", severity="low", confidence="medium", key="global",
                message="=危険,한글", details={})


def test_history_persists_and_separates_sessions_and_modes(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path, "live")
    store.record(sample(), [alert()])
    store.record(sample(), [])              # 10초 안의 요약은 다시 저장하지 않는다.
    store.stop()
    assert len(store.read("stats")) == 1
    old = store.session
    store = HistoryStore(path, "sim")
    store.record(sample(), [alert()])       # 경고 id가 재사용돼도 세션으로 구별한다.
    store.stop()
    assert len(store.read("alerts")) == 2
    assert len(store.read("alerts", mode="live")) == 1
    assert {r["session"] for r in store.read("alerts")} == {old, store.session}
    assert len({r["record_id"] for r in store.read("alerts")}) == 2


def test_history_retention_and_disk_failure_reported(tmp_path):
    import sqlite3
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path, "sim")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO history VALUES (1,0,'old','sim','stats','{}')")
        db.execute("CREATE TRIGGER broken BEFORE INSERT ON history BEGIN SELECT RAISE(FAIL,'disk'); END")
    store.record(sample(), [])
    store._queue.join()
    assert store.status()["error"] and store.dropped == 1
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER broken")
    store.record(sample(), [alert()])
    store.stop()
    assert not store.status()["error"] and not store.read("stats")


def test_history_api_export_validation_and_disabled(tmp_path):
    path = str(tmp_path / "history.sqlite3")
    with TestClient(create_app(history=path)) as client:
        store = client.app.state.history
        store.record(sample(), [alert()])
        store._queue.join()
        data = client.get("/api/history?kind=alerts&mode=sim").json()
        assert data["items"][0]["message"] == alert()["message"]
        response = client.get("/api/history?kind=alerts&format=csv")
        assert "attachment" in response.headers["content-disposition"]
        rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
        assert rows[0]["message"] == "'" + alert()["message"]
        assert client.get("/api/history?kind=wrong").status_code == 422
        assert client.get("/api/history?limit=10001").status_code == 422
        assert not client.get("/api/processes").json()["enabled"]
        assert client.get("/api/status").json()["history"]["enabled"]
        page = client.get("/").text
        assert 'id="historyRows"' in page and 'id="processRows"' in page
        assert client.get("/static/practical.js").status_code == 200
    with TestClient(create_app()) as client:
        assert client.get("/api/history").status_code == 409
    with TestClient(create_app(history=path)) as client:
        assert client.get("/api/history?kind=alerts").json()["items"]


def test_live_source_feeds_process_monitor(monkeypatch):
    from netscope.sources import live
    fake_processes(monkeypatch, [connection()])
    class Source:
        running = False
        def __init__(self, offer, **kw): self.offer = offer
        def start(self):
            self.running = True
            self.offer(make_packet(time.time(), "10.0.0.1", "8.8.8.8", "TCP", 100, sport=5000, dport=443))
        def stop(self): self.running = False
    monkeypatch.setattr(live, "LiveSource", Source)
    with TestClient(create_app(mode="live")) as client:
        snap = client.get("/api/processes").json()
        assert snap["enabled"] and snap["items"][0]["sent_bytes"] == 100


def test_history_config_and_cli(tmp_path):
    from netscope.__main__ import resolve
    path = tmp_path / "config.toml"
    path.write_text('[storage]\nhistory = "custom.sqlite3"', encoding="utf-8")
    assert resolve(["--config", str(path)]).history == "custom.sqlite3"
    assert resolve(["--config", str(path), "--history", ""]).history == ""
