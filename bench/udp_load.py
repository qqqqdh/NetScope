"""루프백 UDP 부하 생성기: 127.0.0.1:port로 정해진 속도만큼 보낸다 (live 캡처 벤치마크용).

인터넷 속도에 좌우되지 않는 재현 가능한 부하를 만든다. 수신 소켓을 같은 프로세스에 열어 둬서
(ICMP 포트 도달 불가가 생기지 않게) 프로세스 대응 기능도 확인할 수 있다.

    python bench/udp_load.py --pps 20000 --seconds 15 --port 9999
"""
from __future__ import annotations

import argparse
import json
import socket
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pps", type=int, default=20_000)
    ap.add_argument("--seconds", type=float, default=15)
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--delay", type=float, default=1.0, help="시작 전 대기(캡처 준비용)")
    a = ap.parse_args()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", a.port))
    rx.setblocking(False)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"x" * 64
    time.sleep(a.delay)
    sent, start = 0, time.perf_counter()
    end = start + a.seconds
    while (now := time.perf_counter()) < end:
        due = int((now - start) * a.pps)
        while sent < due:
            tx.sendto(payload, ("127.0.0.1", a.port))
            sent += 1
        try:
            while True:
                rx.recv(2048)
        except BlockingIOError:
            pass
        time.sleep(0.0005)
    print(json.dumps({"sent": sent, "seconds": round(time.perf_counter() - start, 2),
                      "pps": round(sent / (time.perf_counter() - start))}))


if __name__ == "__main__":
    main()
