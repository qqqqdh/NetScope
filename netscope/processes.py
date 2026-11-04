"""OS 연결 표를 주기적으로 읽어 live 패킷을 로컬 프로세스에 대응한다."""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections import Counter

from .models import Packet


def address(text):
    return int(ipaddress.ip_address(text.split("%")[0]))


class ProcessMonitor:
    """캡처 스레드의 부담을 줄이려고 record()는 연결 키별 바이트만 잠금 없이 누적한다.

    소유자 대응은 refresh()·snapshot() 때 고유 키마다 한 번만 한다. 루프백 20k pps 실측에서 패킷마다
    잠금·조회를 하던 방식은 캡처율을 61.7% → 40.3%로 떨어뜨렸다 (bench/results/live_loopback.csv).
    """

    def __init__(self):
        self._owners = {}
        self._rows = {}
        self._pending = {}          # (proto, ver, src, sport, dst, dport) -> 바이트 (캡처 스레드만 씀)
        # PID → (pid, create_time, name). 프로세스마다 매초 다시 조회하면 refresh()가 약 200ms(프로세스 55개)가 걸려
        # 매초 20%의 시간을 차지했다 → 캡처율 약 20% 하락. 새 PID만 조회하고, PID 재사용에 대비해 60초마다 비운다.
        self._identities = {}
        self._identities_at = 0.0
        self.identity_ttl = 60.0
        self._connections = Counter()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.error = None
        self.matched = self.unmatched = 0

    def refresh(self):
        import psutil

        self._drain()               # 직전 연결 표로 먼저 대응 (그동안 끝난 연결도 놓치지 않게)
        now = time.monotonic()
        if now - self._identities_at > self.identity_ttl:
            self._identities, self._identities_at = {}, now
        owners, identities, counts = {}, self._identities, Counter()
        try:
            connections = psutil.net_connections(kind="inet")
            for c in connections:
                if not c.pid or not c.laddr:
                    continue
                if c.pid not in identities:
                    try:
                        p = psutil.Process(c.pid)
                        identities[c.pid] = (c.pid, p.create_time(), p.name())
                    except psutil.Error:
                        identities[c.pid] = None
                owner = identities[c.pid]
                if owner is None:
                    continue
                ver = 6 if c.family == socket.AF_INET6 else 4
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                remote = (address(c.raddr.ip), c.raddr.port) if c.raddr else (None, None)
                key = (proto, ver, address(c.laddr.ip), c.laddr.port, *remote)
                # 공유 포트의 소유자가 여럿이면 임의의 프로세스에 배정하지 않는다.
                owners[key] = owner if key not in owners or owners[key] == owner else None
                counts[owner] += 1
        except (psutil.Error, OSError) as e:
            with self._lock:
                self._owners = {}
                self._connections = Counter()
                self.error = f"연결 정보를 읽지 못했습니다 ({type(e).__name__}). 권한을 확인하세요."
            return
        with self._lock:
            self._owners, self._connections, self.error = owners, counts, None

    def _owner(self, proto, ver, local, port, remote, rport):
        exact = (proto, ver, local, port, remote, rport)
        if exact in self._owners:
            return self._owners[exact]
        if proto == "UDP":
            for key in ((proto, ver, local, port, None, None), (proto, ver, 0, port, None, None)):
                if key in self._owners:
                    return self._owners[key]
        return None

    def record(self, packet: Packet):
        """캡처 스레드에서 호출. 잠금·조회 없이 dict 덧셈만 한다."""
        key = (packet.proto, packet.ver, packet.src, packet.sport, packet.dst, packet.dport)
        pending = self._pending
        pending[key] = pending.get(key, 0) + packet.length

    def _drain(self):
        # 참조 교체는 GIL 아래에서 원자적이다. 교체 직전에 옛 dict에 쓰인 몇 바이트는 다음 차례에 읽히지 않을 수 있다.
        pending, self._pending = self._pending, {}
        if not pending:
            return
        with self._lock:
            for (proto, ver, src, sport, dst, dport), n in pending.items():
                owner = self._owner(proto, ver, src, sport, dst, dport)
                direction = "sent_bytes"
                if owner is None:
                    owner = self._owner(proto, ver, dst, dport, src, sport)
                    direction = "received_bytes"
                if owner is None or (owner not in self._rows and len(self._rows) >= 512):
                    self.unmatched += n
                    continue
                self.matched += n
                row = self._rows.setdefault(owner, {"pid": owner[0], "name": owner[2],
                                                    "sent_bytes": 0, "received_bytes": 0})
                row[direction] += n

    def snapshot(self):
        self._drain()
        with self._lock:
            rows = [dict(row, bytes=row["sent_bytes"] + row["received_bytes"],
                         connections=self._connections[owner]) for owner, row in self._rows.items()]
            return {"enabled": True, "estimated": True, "error": self.error,
                    "matched_bytes": self.matched, "unmatched_bytes": self.unmatched,
                    "items": sorted(rows, key=lambda r: -r["bytes"])[:20]}

    def start(self):
        self.refresh()
        self._thread = threading.Thread(target=self._loop, name="netscope-processes", daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.wait(1):
            self.refresh()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(3)
