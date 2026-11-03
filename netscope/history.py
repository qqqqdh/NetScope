"""요약 통계와 경고를 별도 워커에서 SQLite에 보관한다 (패킷 원문 제외)."""
from __future__ import annotations

import json
import queue
import sqlite3
import threading
import time
import uuid
from contextlib import closing


class HistoryStore:
    def __init__(self, path, mode):
        self.path, self.mode = str(path), mode
        self.session = uuid.uuid4().hex
        self._queue = queue.Queue(maxsize=128)
        self._stop = threading.Event()
        self._last_sample = float("-inf")
        self.dropped = 0
        self.error = None
        with closing(self._connect()) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, "
                       "recorded_at REAL NOT NULL, session TEXT NOT NULL, mode TEXT NOT NULL, "
                       "kind TEXT NOT NULL, data TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS history_kind_id ON history(kind, id)")
        self._thread = threading.Thread(target=self._loop, name="netscope-history", daemon=True)
        self._thread.start()

    def _connect(self):
        return sqlite3.connect(self.path, timeout=2)

    def record(self, snapshot, alerts):
        now = time.time()
        items = [(now, self.session, self.mode, "alerts", json.dumps(a, ensure_ascii=False)) for a in alerts]
        if now - self._last_sample >= 10:
            self._last_sample = now
            data = {"event_time": snapshot["end"], "window_bytes": snapshot["totals"]["bytes"],
                    "window_packets": snapshot["totals"]["packets"],
                    "bytes_per_sec": snapshot["rate"]["bytes_per_sec"],
                    "pps": snapshot["status"]["pps"], "active_flows": snapshot["flows"]["active"],
                    "queue_drops": snapshot["status"]["queue_drops"],
                    "degraded": snapshot["health"]["degraded"]}
            items.append((now, self.session, self.mode, "stats", json.dumps(data)))
        if items:
            try:
                self._queue.put_nowait(items)
            except queue.Full:
                self.dropped += len(items)

    def _loop(self):
        with closing(self._connect()) as db:
            while not self._stop.is_set() or not self._queue.empty():
                try:
                    items = self._queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                try:
                    with db:
                        db.executemany("INSERT INTO history(recorded_at,session,mode,kind,data) VALUES (?,?,?,?,?)", items)
                        db.execute("DELETE FROM history WHERE recorded_at < ?", (time.time() - 7 * 86400,))
                        # 보관 기간 안에서도 과도한 경고가 디스크를 무한히 채우지 않게 제한한다.
                        for kind, cap in (("stats", 100000), ("alerts", 10000)):
                            db.execute("DELETE FROM history WHERE kind=? AND id <= "
                                       "(SELECT id FROM history WHERE kind=? ORDER BY id DESC LIMIT 1 OFFSET ?)",
                                       (kind, kind, cap))
                    self.error = None
                except sqlite3.Error as e:
                    self.error = f"이력 저장 실패 ({type(e).__name__})"
                    self.dropped += len(items)
                finally:
                    self._queue.task_done()

    def read(self, kind, limit=50, mode=None):
        if kind not in ("stats", "alerts"):
            raise ValueError("kind는 stats 또는 alerts")
        query = "SELECT id,recorded_at,session,mode,data FROM history WHERE kind=?"
        params = [kind]
        if mode:
            query += " AND mode=?"
            params.append(mode)
        params.append(min(max(limit, 1), 10000))
        with closing(self._connect()) as db:
            rows = db.execute(query + " ORDER BY id DESC LIMIT ?", params).fetchall()
        return [dict(json.loads(r[4]), record_id=r[0], recorded_at=r[1], session=r[2], mode=r[3]) for r in rows]

    def status(self):
        return {"enabled": True, "error": self.error, "dropped": self.dropped}

    def stop(self):
        self._stop.set()
        self._thread.join(5)
