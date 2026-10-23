"""python -m netscope [--config netscope.toml] [--speed 1] [--port 8000]"""
from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    # 기본값은 None: 지정하지 않은 인자는 설정 파일 값(또는 Config 기본값)을 쓴다
    ap = argparse.ArgumentParser(prog="netscope", description="NetScope 실시간 네트워크 트래픽 분석기")
    ap.add_argument("--config", help="TOML 설정 파일 (예: netscope.example.toml)")
    ap.add_argument("--mode", choices=["sim", "pcap", "live"],
                    help="sim: 시뮬레이터, pcap: 파일 재생, live: 실제 캡처(Npcap/root 필요)")
    ap.add_argument("--pcap", help="pcap 모드의 입력 파일 (pcap/pcapng)")
    ap.add_argument("--iface", help="live 모드의 네트워크 인터페이스 (생략 시 기본)")
    ap.add_argument("--bpf", help='live 모드의 BPF 필터 (예: "ip and not port 22")')
    ap.add_argument("--host", help="기본 127.0.0.1. 인증이 없으므로 로컬 전용 권장")
    ap.add_argument("--port", type=int)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--speed", type=float, help="재생 배속 (sim/pcap). pcap에서 0이면 최대 속도")
    ap.add_argument("--attack-interval", type=float, help="데모 공격 주입 간격(시뮬레이터 초)")
    ap.add_argument("--lateness", type=float)
    return ap


def resolve(argv=None):
    from .config import load_config

    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    for key in ("mode", "host", "port", "seed", "speed", "attack_interval", "lateness",
                "pcap", "iface", "bpf"):
        value = getattr(args, key)
        if value is not None:
            setattr(cfg, key, value)
    return cfg


def main(argv=None) -> None:
    from .config import EXPOSURE_WARNING, is_loopback_host

    try:
        cfg = resolve(argv)
    except (OSError, ValueError) as e:
        sys.exit(f"설정 오류: {e}")

    import uvicorn

    from .server import create_app

    if not is_loopback_host(cfg.host):
        print(EXPOSURE_WARNING.format(host=cfg.host), file=sys.stderr)
    app = create_app(mode=cfg.mode, seed=cfg.seed, speed=cfg.speed, attack_interval=cfg.attack_interval,
                     lateness=cfg.lateness, queue_max=cfg.queue_max, thresholds=cfg.thresholds,
                     allowlist=cfg.allowlist, pcap=cfg.pcap or None, iface=cfg.iface or None,
                     bpf=cfg.bpf or None)
    print(f"NetScope → http://{cfg.host}:{cfg.port}  (모드: {cfg.mode}, 배속 {cfg.speed}x)")
    try:
        uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="warning")
    except Exception as e:          # 예: live 캡처 드라이버 없음
        sys.exit(f"시작 실패: {e}")


if __name__ == "__main__":
    main()
