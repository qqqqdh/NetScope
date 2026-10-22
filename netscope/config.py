"""설정 파일 (TOML) 로딩. 예시: netscope.example.toml

우선순위: CLI 인자 > 설정 파일 > 기본값.
알 수 없는 키는 오타일 가능성이 높으므로 조용히 무시하지 않고 오류로 알린다.
"""
from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

from .anomaly import Thresholds

ALERT_TYPES = ("port_scan", "syn_flood", "service_connectivity_issue", "dns_flood", "traffic_spike")


@dataclass
class Config:
    mode: str = "sim"
    host: str = "127.0.0.1"
    port: int = 8000
    seed: int = 1
    speed: float = 1.0
    attack_interval: float = 45.0
    lateness: float = 1.0
    queue_max: int = 50_000
    thresholds: Thresholds = field(default_factory=Thresholds)
    allowlist: dict[str, list[str]] = field(default_factory=dict)


# TOML 섹션 → Config 필드
_SECTIONS = {
    "server": ("mode", "host", "port"),
    "simulator": ("seed", "speed", "attack_interval"),
    "engine": ("lateness", "queue_max"),
}


def _check_keys(section: str, given: dict, allowed) -> None:
    unknown = set(given) - set(allowed)
    if unknown:
        raise ValueError(f"[{section}] 알 수 없는 키: {', '.join(sorted(unknown))} "
                         f"(허용: {', '.join(sorted(allowed))})")


def load_config(path: str | Path | None = None) -> Config:
    cfg = Config()
    if path is None:
        return cfg
    # utf-8-sig: Windows 메모장·PowerShell 5가 붙이는 BOM을 허용한다 (tomllib은 BOM을 거부함)
    data = tomllib.loads(Path(path).read_text(encoding="utf-8-sig"))
    _check_keys("최상위", data, list(_SECTIONS) + ["thresholds", "allowlist"])
    for section, keys in _SECTIONS.items():
        values = data.get(section, {})
        _check_keys(section, values, keys)
        for k, v in values.items():
            setattr(cfg, k, type(getattr(cfg, k))(v))
    th = data.get("thresholds", {})
    _check_keys("thresholds", th, [f.name for f in fields(Thresholds)])
    cfg.thresholds = Thresholds(**{k: type(getattr(Thresholds, k))(v) for k, v in th.items()})
    allow = data.get("allowlist", {})
    _check_keys("allowlist", allow, ALERT_TYPES)
    for kind, cidrs in allow.items():
        if not isinstance(cidrs, list):
            raise ValueError(f"[allowlist] {kind}는 CIDR 문자열 목록이어야 합니다")
        for c in cidrs:
            ipaddress.ip_network(c, strict=False)        # 잘못된 CIDR이면 ValueError
    cfg.allowlist = {k: list(v) for k, v in allow.items()}
    return cfg


def is_loopback_host(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


EXPOSURE_WARNING = ("경고: NetScope에는 인증이 없습니다. --host {host}로 띄우면 같은 네트워크의 누구나 "
                    "트래픽 정보를 보고 수집을 멈출 수 있습니다. 로컬 전용(127.0.0.1)을 권장합니다.")
