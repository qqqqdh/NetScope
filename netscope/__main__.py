"""python -m netscope [--speed 1] [--port 8000]"""
from __future__ import annotations

import argparse


def main() -> None:
    ap = argparse.ArgumentParser(prog="netscope", description="NetScope 실시간 네트워크 트래픽 분석기")
    ap.add_argument("--mode", default="sim", choices=["sim"], help="sim (live/pcap은 4단계에서 추가)")
    ap.add_argument("--host", default="127.0.0.1", help="인증이 없으므로 기본은 로컬 전용")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--speed", type=float, default=1.0, help="시뮬레이터 재생 배속")
    ap.add_argument("--attack-interval", type=float, default=45.0, help="데모 공격 주입 간격(시뮬레이터 초)")
    ap.add_argument("--lateness", type=float, default=1.0)
    args = ap.parse_args()

    import uvicorn

    from .server import create_app

    app = create_app(mode=args.mode, seed=args.seed, speed=args.speed,
                     attack_interval=args.attack_interval, lateness=args.lateness)
    print(f"NetScope → http://{args.host}:{args.port}  (모드: {args.mode}, 배속 {args.speed}x)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
