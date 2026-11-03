"""OS 연결 표를 주기적으로 읽어 live 패킷을 로컬 프로세스에 대응한다."""
from __future__ import annotations

import ipaddress
import socket
import threading
from collections import Counter

from .models import Packet


def address(text):
    return int(ipaddress.ip_address(text.split("%")[0]))


class ProcessMonitor:
    def __init__(self):
        self._owners = {}
        self._rows = {}
        self._connections = Counter()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.error = None
        self.matched = self.unmatched = 0

    def refresh(self):
        import psutil

        owners, identities, counts = {}, {}, Counter()
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
        with self._lock:
            owner = self._owner(packet.proto, packet.ver, packet.src, packet.sport, packet.dst, packet.dport)
            direction = "sent_bytes"
            if owner is None:
                owner = self._owner(packet.proto, packet.ver, packet.dst, packet.dport, packet.src, packet.sport)
                direction = "received_bytes"
            if owner is None or (owner not in self._rows and len(self._rows) >= 512):
                self.unmatched += packet.length
                return
            self.matched += packet.length
            row = self._rows.setdefault(owner, {"pid": owner[0], "name": owner[2],
                                                "sent_bytes": 0, "received_bytes": 0})
            row[direction] += packet.length

    def snapshot(self):
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
