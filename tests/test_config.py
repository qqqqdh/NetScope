"""설정 파일, CLI 우선순위, 외부 노출 경고."""
from pathlib import Path

import pytest

from conftest import udp
from netscope.__main__ import resolve
from netscope.anomaly import AnomalyDetector
from netscope.config import is_loopback_host, load_config
from netscope.engine import CoreEngine

ROOT = Path(__file__).resolve().parent.parent


def write(tmp_path, text):
    p = tmp_path / "netscope.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_example_config_loads():
    cfg = load_config(ROOT / "netscope.example.toml")
    assert cfg.port == 8000 and cfg.thresholds.scan_ports == 20
    assert cfg.allowlist["dns_flood"] == ["192.168.0.1/32"]


def test_defaults_without_file():
    cfg = load_config(None)
    assert (cfg.host, cfg.mode, cfg.thresholds.dns_queries) == ("127.0.0.1", "sim", 80)


def test_cli_overrides_file(tmp_path):
    p = write(tmp_path, "[server]\nport = 9000\n[simulator]\nspeed = 2.0\n")
    cfg = resolve(["--config", str(p), "--port", "9100"])
    assert cfg.port == 9100 and cfg.speed == 2.0


@pytest.mark.parametrize("text,needle", [
    ("[server]\nprot = 1\n", "prot"),                       # 오타
    ("[thresholds]\nscan_port = 5\n", "scan_port"),
    ("[allowlist]\nport_scna = []\n", "port_scna"),
    ("[serverr]\n", "serverr"),
])
def test_unknown_keys_rejected(tmp_path, text, needle):
    with pytest.raises(ValueError, match=needle):
        load_config(write(tmp_path, text))


def test_utf8_bom_accepted(tmp_path):
    p = tmp_path / "bom.toml"
    p.write_bytes("﻿[server]\nport = 9001\n".encode("utf-8"))
    assert load_config(p).port == 9001


def test_bad_cidr_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_config(write(tmp_path, '[allowlist]\ndns_flood = ["192.168.0.300/32"]\n'))


def test_allowlist_suppresses_detection(tmp_path):
    cfg = load_config(write(tmp_path, '[allowlist]\ndns_flood = ["192.168.0.50/32"]\n'))
    pk = [udp(2000 + i / 15, "192.168.0.50", "8.8.8.8", 40000 + i, 53) for i in range(120)]
    pk += [udp(2000 + i / 15, "192.168.0.51", "8.8.8.8", 40000 + i, 53) for i in range(120)]
    eng = CoreEngine()
    det = AnomalyDetector(eng, cfg.thresholds, cfg.allowlist)
    for p in sorted(pk, key=lambda p: p.ts):
        eng.ingest(p)
    eng.flush()
    assert [a.key for a in det.alerts] == ["192.168.0.51"]


@pytest.mark.parametrize("host,loop", [
    ("127.0.0.1", True), ("localhost", True), ("::1", True),
    ("0.0.0.0", False), ("192.168.0.5", False), ("example.com", False),
])
def test_loopback_detection(host, loop):
    assert is_loopback_host(host) is loop
