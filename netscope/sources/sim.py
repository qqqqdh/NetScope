"""결정적 트래픽 시뮬레이터 (DESIGN §5.7, §8.2).

액터들이 1초 단위로 미래 패킷을 힙에 넣고, Simulation이 시간 순으로 내보낸다.
같은 seed면 항상 같은 패킷열이 나온다(액터마다 이름으로 파생한 난수 생성기 사용).
공격 액터는 정답 라벨(Episode)을 함께 남긴다.
"""
from __future__ import annotations

import heapq
import math
import random
from functools import lru_cache
from typing import Iterator

from ..models import Episode, Packet, ip_to_int
from ..protocols import scope

MTU = 1460


@lru_cache(maxsize=4096)
def ip(text: str) -> int:
    return ip_to_int(text)[0]


class Simulation:
    def __init__(self, seed: int, start: float = 10_000.0) -> None:
        self.seed = seed
        self.start = start
        self.actors: list[Actor] = []
        self.episodes: list[Episode] = []
        self.down: set[tuple[int, int]] = set()        # 응답하지 않는 서비스 (장애 시나리오)
        self._heap: list = []
        self._n = 0

    def rng(self, name: str) -> random.Random:
        return random.Random(f"{self.seed}:{name}")

    def add(self, actor: "Actor") -> "Simulation":
        actor.bind(self)
        self.actors.append(actor)
        return self

    def push(self, pkt: Packet) -> None:
        self._n += 1
        heapq.heappush(self._heap, (pkt.ts, self._n, pkt))

    def run(self, duration: float, order_jitter: float = 0.0) -> Iterator[Packet]:
        """[start, start+duration) 구간의 패킷을 시간 순으로 내보낸다.

        order_jitter > 0이면 ts는 그대로 두고 '도착 순서'만 ±order_jitter초 범위에서 섞는다.
        """
        end = self.start + duration
        jr = self.rng("jitter")
        t = self.start
        while t < end:
            nxt = min(t + 1.0, end)
            for a in self.actors:
                a.step(t, nxt)
            chunk = []
            while self._heap and self._heap[0][0] < nxt:
                chunk.append(heapq.heappop(self._heap)[2])
            if order_jitter:
                chunk.sort(key=lambda p: p.ts + jr.uniform(-order_jitter, order_jitter))
            yield from chunk
            t = nxt


class Actor:
    name = "actor"

    def bind(self, sim: Simulation) -> None:
        self.sim = sim
        self.rnd = sim.rng(f"{self.name}:{len(sim.actors)}")

    def step(self, a: float, b: float) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------ 패킷 도우미
    def tcp(self, ts, s, d, sp, dp, flags, length=60, seq=None):
        self.sim.push(Packet(ts, s, d, "TCP", length, sp, dp, flags, seq))

    def udp(self, ts, s, d, sp, dp, length):
        self.sim.push(Packet(ts, s, d, "UDP", length, sp, dp))

    def conn(self, t, c, cp, s, sp, *, data=10, dur=1.0, rtt=0.03, up=0.25,
             answer=True, retrans=(), down_size=(400, MTU), up_size=(60, 400)):
        """TCP 연결 하나: 핸드셰이크 → 데이터 → FIN. answer=False면 SYN(과 재전송)만."""
        r = self.rnd
        isn = r.getrandbits(32)
        self.tcp(t, c, s, cp, sp, "S", 66, isn)
        if not answer:
            for dt in retrans:
                self.tcp(t + dt, c, s, cp, sp, "S", 66, isn)
            return
        self.tcp(t + rtt, s, c, sp, cp, "SA", 66, r.getrandbits(32))
        t0 = t + rtt + 0.001
        self.tcp(t0, c, s, cp, sp, "A", 54)
        for i in range(data):
            ts = t0 + dur * (i + 1) / (data + 1)
            if r.random() < up:
                self.tcp(ts, c, s, cp, sp, "PA", r.randint(*up_size))
            else:
                self.tcp(ts, s, c, sp, cp, "PA", r.randint(*down_size))
        te = t0 + dur + 0.01
        self.tcp(te, c, s, cp, sp, "FA", 54)
        self.tcp(te + rtt, s, c, sp, cp, "FA", 54)
        self.tcp(te + rtt + 0.001, c, s, cp, sp, "A", 54)

    def dns(self, t, c, cp, resolver, answer=True, rtt=0.02):
        r = self.rnd
        self.udp(t, c, resolver, cp, 53, r.randint(60, 110))
        if answer:
            self.udp(t + rtt, resolver, c, 53, cp, r.randint(90, 300))


class _Ports:
    """클라이언트별 에피메럴 포트 (4-tuple 재사용을 피하려고 순환)."""

    def __init__(self, rnd: random.Random) -> None:
        self.next: dict[int, int] = {}
        self.rnd = rnd

    def take(self, client: int) -> int:
        p = self.next.get(client) or self.rnd.randint(49152, 60000)
        self.next[client] = 49152 if p >= 65535 else p + 1
        return p


def _arrivals(rnd, rate, a, b):
    t = a + rnd.expovariate(rate)
    while t < b:
        yield t
        t += rnd.expovariate(rate)


# ====================================================================== 정상 트래픽
CLIENTS = [f"192.168.0.{i}" for i in range(2, 22)]            # 20대
RESOLVER = "192.168.0.1"
WEB_SERVERS = ["142.250.0.10", "151.101.1.69", "104.16.0.1", "13.107.42.14", "31.13.82.36",
               "52.95.110.1", "172.217.1.1", "185.199.108.153", "140.82.112.3", "151.101.65.69"]
APP_SERVER = "192.168.0.20"


class Baseline(Actor):
    """웹(HTTPS/HTTP), DNS, 내부 앱(.20:443/.20:80), SSH, QUIC, NTP, mDNS, ICMP. 약 150~200 pps."""
    name = "baseline"

    def __init__(self, web_rate=6.0, app_rate=1.5, dns_rate=1.0) -> None:
        self.web_rate, self.app_rate, self.dns_rate = web_rate, app_rate, dns_rate

    def bind(self, sim):
        super().bind(sim)
        self.ports = _Ports(self.rnd)
        self.clients = [ip(c) for c in CLIENTS]
        self.servers = [ip(s) for s in WEB_SERVERS]
        self.resolver = ip(RESOLVER)
        self.app = ip(APP_SERVER)
        self.ssh = (ip("192.168.0.5"), ip("192.168.0.10"), self.ports.take(ip("192.168.0.5")))

    def step(self, a, b):
        r = self.rnd
        for t in _arrivals(r, self.web_rate, a, b):
            c = r.choice(self.clients)
            s = r.choice(self.servers)
            if r.random() < 0.3:
                self.dns(t - 0.03, c, self.ports.take(c), self.resolver)
            self.conn(t, c, self.ports.take(c), s, 443 if r.random() < 0.85 else 80,
                      data=r.randint(4, 30), dur=r.uniform(0.2, 3.0), rtt=r.uniform(0.01, 0.08))
        for t in _arrivals(r, self.app_rate, a, b):
            c = r.choice(self.clients)
            port = 443 if r.random() < 0.75 else 80
            if (self.app, port) in self.sim.down:
                self.conn(t, c, self.ports.take(c), self.app, port, answer=False, retrans=(1.0, 3.0))
            else:
                self.conn(t, c, self.ports.take(c), self.app, port, data=r.randint(2, 8),
                          dur=r.uniform(0.05, 0.5), rtt=0.002)
        for t in _arrivals(r, self.dns_rate, a, b):
            c = r.choice(self.clients)
            self.dns(t, c, self.ports.take(c), self.resolver)
        sc, ss, sp = self.ssh                                   # 캡처 전부터 열린 SSH 세션
        for t in _arrivals(r, 4.0, a, b):
            if r.random() < 0.5:
                self.tcp(t, sc, ss, sp, 22, "PA", r.randint(80, 120))
            else:
                self.tcp(t, ss, sc, 22, sp, "PA", r.randint(80, 600))
        for t in _arrivals(r, 10.0, a, b):                      # QUIC
            c = self.clients[3]
            if r.random() < 0.3:
                self.udp(t, c, self.servers[0], 55000, 443, r.randint(60, 300))
            else:
                self.udp(t, self.servers[0], c, 443, 55000, r.randint(600, 1350))
        for t in _arrivals(r, 1.0, a, b):                       # ICMP ping
            self.sim.push(Packet(t, self.clients[1], ip("8.8.8.8"), "ICMP", 98))
            self.sim.push(Packet(t + 0.01, ip("8.8.8.8"), self.clients[1], "ICMP", 98))
        for t in _arrivals(r, 0.2, a, b):                       # mDNS
            self.udp(t, r.choice(self.clients), ip("224.0.0.251"), 5353, 5353, r.randint(80, 300))
        for t in _arrivals(r, 0.05, a, b):                      # NTP
            c = r.choice(self.clients)
            self.udp(t, c, ip("162.159.200.1"), 123, 123, 90)
            self.udp(t + 0.02, ip("162.159.200.1"), c, 123, 123, 90)


# ====================================================================== 공격 (Episode 남김)
class _Episodic(Actor):
    episode_type = ""

    def __init__(self, start: float, duration: float) -> None:
        self.t_start, self.duration = start, duration

    def bind(self, sim):
        super().bind(sim)
        self.t_start += sim.start
        self.t_end = self.t_start + self.duration
        key = self.key()
        if key is not None:
            sim.episodes.append(Episode(self.episode_type, key, self.t_start, self.t_end))

    def key(self) -> str | None:
        return None

    def window(self, a, b):
        return max(a, self.t_start), min(b, self.t_end)


def _public_ip(rnd) -> int:
    while True:
        v = rnd.getrandbits(32)
        if scope(v, 4) == "public" and not 0xE0000000 <= v:
            return v


class PortScan(_Episodic):
    name, episode_type = "portscan", "port_scan"

    def __init__(self, start, duration=5.0, rate=60.0, attacker="45.33.32.156", target="192.168.0.10"):
        super().__init__(start, duration)
        self.rate, self.attacker, self.target = rate, attacker, target

    def key(self):
        return self.attacker

    def bind(self, sim):
        super().bind(sim)
        self.ports = self.rnd.sample(range(1, 10_000), 2000)
        self.i = 0
        self.atk, self.tgt = ip(self.attacker), ip(self.target)

    def step(self, a, b):
        a, b = self.window(a, b)
        if a >= b:
            return
        n = int(round((b - a) * self.rate))
        for k in range(n):
            t = a + (b - a) * k / max(n, 1)
            port = self.ports[self.i % len(self.ports)]
            self.i += 1
            self.tcp(t, self.atk, self.tgt, 40123, port, "S", 58, self.rnd.getrandbits(32))
            if port in (22, 80, 443):
                self.tcp(t + 0.002, self.tgt, self.atk, port, 40123, "SA", 58)
                self.tcp(t + 0.004, self.atk, self.tgt, 40123, port, "R", 54)
            else:
                self.tcp(t + 0.002, self.tgt, self.atk, port, 40123, "RA", 54)


class SynFlood(_Episodic):
    name, episode_type = "synflood", "syn_flood"

    def __init__(self, start, duration=5.0, rate=400.0, target=APP_SERVER, port=80,
                 synack_ratio=0.6, retransmit=False):
        super().__init__(start, duration)
        self.rate, self.target, self.port = rate, target, port
        self.synack_ratio, self.retransmit = synack_ratio, retransmit

    def key(self):
        return f"{self.target}:{self.port}"

    def bind(self, sim):
        super().bind(sim)
        self.tgt = ip(self.target)

    def step(self, a, b):
        a, b = self.window(a, b)
        r = self.rnd
        for t in _arrivals(r, self.rate, a, b) if a < b else ():
            src, sp, isn = _public_ip(r), r.randint(1024, 65535), r.getrandbits(32)
            self.tcp(t, src, self.tgt, sp, self.port, "S", 60, isn)
            if self.retransmit:                            # 회피 시도: 위조 SYN을 2회 재전송
                self.tcp(t + 1.0, src, self.tgt, sp, self.port, "S", 60, isn)
                self.tcp(t + 2.0, src, self.tgt, sp, self.port, "S", 60, isn)
            if r.random() < self.synack_ratio:
                self.tcp(t + 0.001, self.tgt, src, self.port, sp, "SA", 60)


class DnsFlood(_Episodic):
    name, episode_type = "dnsflood", "dns_flood"

    def __init__(self, start, duration=8.0, rate=40.0, host="192.168.0.66", resolver="8.8.8.8"):
        super().__init__(start, duration)
        self.rate, self.host, self.resolver = rate, host, resolver

    def key(self):
        return self.host

    def bind(self, sim):
        super().bind(sim)
        self.h, self.res = ip(self.host), ip(self.resolver)
        self.ports = _Ports(self.rnd)

    def step(self, a, b):
        a, b = self.window(a, b)
        n = int(round((b - a) * self.rate)) if a < b else 0
        for k in range(n):
            self.dns(a + (b - a) * k / n, self.h, self.ports.take(self.h), self.res,
                     answer=self.rnd.random() < 0.9)


class Spike(_Episodic):
    """대용량 전송 (공격 시나리오에서는 traffic_spike 정답, 정상 시나리오에서는 큰 다운로드)."""
    name, episode_type = "spike", "traffic_spike"

    def __init__(self, start, duration=3.0, pps=600.0, host="192.168.0.15", server="151.101.1.1",
                 label=True):
        super().__init__(start, duration)
        self.pps, self.host, self.server, self.label = pps, host, server, label

    def key(self):
        return "global" if self.label else None

    def bind(self, sim):
        super().bind(sim)
        self.h, self.s = ip(self.host), ip(self.server)
        self.sp = 50999

    def step(self, a, b):
        a, b = self.window(a, b)
        n = int(round((b - a) * self.pps)) if a < b else 0
        for k in range(n):
            t = a + (b - a) * k / n
            self.tcp(t, self.s, self.h, 443, self.sp, "PA", MTU)
            if k % 10 == 0:
                self.tcp(t + 0.0005, self.h, self.s, self.sp, 443, "A", 54)


# ====================================================================== 정상 스트레스 시나리오
class DnsBurst(Actor):
    """페이지 로드형 DNS 버스트: interval초마다 1초 안에 burst건."""
    name = "dnsburst"

    def __init__(self, host="192.168.0.99", burst=100, interval=30.0, first=20.0):
        self.host, self.burst, self.interval, self.first = host, burst, interval, first

    def bind(self, sim):
        super().bind(sim)
        self.h, self.res = ip(self.host), ip(RESOLVER)
        self.ports = _Ports(self.rnd)
        self.next = sim.start + self.first

    def step(self, a, b):
        while a <= self.next < b:
            for k in range(self.burst):
                self.dns(self.next + k / self.burst * 0.9, self.h, self.ports.take(self.h), self.res)
            self.next += self.interval


class Outage(Actor):
    """서비스 장애: 이력이 있는 정상 클라이언트들이 계속 접속을 시도하고 재전송한다."""
    name = "outage"

    def __init__(self, start=60.0, duration=30.0, rate_per_client=1.5, target=APP_SERVER, port=443):
        self.start, self.duration, self.rate = start, duration, rate_per_client
        self.target, self.port = target, port

    def bind(self, sim):
        super().bind(sim)
        self.t0, self.t1 = sim.start + self.start, sim.start + self.start + self.duration
        self.tgt = ip(self.target)
        self.clients = [ip(c) for c in CLIENTS]
        self.ports = _Ports(self.rnd)

    def step(self, a, b):
        key = (self.tgt, self.port)
        if self.t0 <= a < self.t1:
            self.sim.down.add(key)
            for c in self.clients:
                for t in _arrivals(self.rnd, self.rate, a, b):
                    self.conn(t, c, self.ports.take(c), self.tgt, self.port, answer=False,
                              retrans=(1.0, 3.0))
        else:
            self.sim.down.discard(key)


class NatSurge(Actor):
    """NAT 게이트웨이 뒤 다수 사용자: 한 IP가 정상 연결을 대량으로 맺는다 (인기 서버에 집중)."""
    name = "nat"

    def __init__(self, start=60.0, rate=50.0, gateway="192.168.0.250", popular_share=0.4):
        self.start, self.rate, self.gateway, self.share = start, rate, gateway, popular_share

    def bind(self, sim):
        super().bind(sim)
        self.gw = ip(self.gateway)
        self.popular = ip(WEB_SERVERS[0])
        self.pool = [_public_ip(self.rnd) for _ in range(200)]
        self.ports = _Ports(self.rnd)
        self.t0 = sim.start + self.start

    def step(self, a, b):
        a = max(a, self.t0)
        if a >= b:
            return
        r = self.rnd
        for t in _arrivals(r, self.rate, a, b):
            s = self.popular if r.random() < self.share else r.choice(self.pool)
            self.conn(t, self.gw, self.ports.take(self.gw), s, 443 if r.random() < 0.9 else 80,
                      data=r.randint(2, 6), dur=r.uniform(0.1, 0.5), rtt=0.02,
                      down_size=(200, 800))


# ====================================================================== 시나리오
ATTACK_TYPES = ("port_scan", "syn_flood", "dns_flood", "traffic_spike")


#: 공격 강도 범위. "normal"은 임계값보다 확실히 강한 범위(기본 평가, 균등 분포).
#: "hard"는 기본 임계값에 해당하는 강도의 약 0.1~10배를 로그 균등 분포로 뽑는다(E5용).
#: 임계값 해당 강도: 스캔 2포트/s(20/10초), 플러드 20 SYN/s(100/5초), DNS 8건/s(80/10초),
#: 급증 약 200 pps × 1460B(≈ 기준선 100KB/s의 3배). 선형 균등 분포로 뽑으면 대부분이 임계값보다
#: 강해 약한 공격이 거의 없었다(초기 E5 실행에서 발견).
DIFFICULTY = {
    "normal": {"log": False, "scan_rate": (30, 100), "flood_rate": (200, 800), "dns_rate": (15, 50),
               "spike_pps": (400, 900)},
    "hard": {"log": True, "scan_rate": (0.2, 20), "flood_rate": (2, 200), "dns_rate": (0.8, 80),
             "spike_pps": (20, 2000)},
}


def attack_scenario(seed: int, repeat: int = 3, interval: float = 20.0, warmup: float = 40.0,
                    randomize: bool = True, difficulty: str = "normal") -> tuple[Simulation, float]:
    """공격 4종을 interval초 간격으로 repeat번씩 주입. (sim, 권장 실행 시간)을 돌려준다."""
    sim = Simulation(seed).add(Baseline())
    r = random.Random(f"{seed}:schedule")
    rng = DIFFICULTY[difficulty]
    t = warmup
    for i in range(repeat):
        for kind in ATTACK_TYPES:
            u = (lambda lo, hi: r.uniform(lo, hi)) if randomize else (lambda lo, hi: (lo + hi) / 2)
            if rng["log"] and randomize:
                u_rate = lambda lo, hi: math.exp(r.uniform(math.log(lo), math.log(hi)))
            else:
                u_rate = u
            if kind == "port_scan":
                attacker = f"45.33.{r.randint(1, 250)}.{r.randint(1, 250)}"
                sim.add(PortScan(t, duration=u(3, 8), rate=u_rate(*rng["scan_rate"]), attacker=attacker))
            elif kind == "syn_flood":
                sim.add(SynFlood(t, duration=u(4, 8), rate=u_rate(*rng["flood_rate"]),
                                 synack_ratio=u(0.3, 0.9)))
            elif kind == "dns_flood":
                host = f"192.168.0.{r.randint(60, 90)}"
                sim.add(DnsFlood(t, duration=u(8, 12), rate=u_rate(*rng["dns_rate"]), host=host))
            else:
                sim.add(Spike(t, duration=u(2, 4), pps=u_rate(*rng["spike_pps"]),
                              host=f"192.168.0.{r.randint(2, 21)}"))
            t += interval
    return sim, t + 10


class AttackCycle(Actor):
    """실시간 데모용: warmup 이후 interval초마다 공격 4종을 돌아가며 끝없이 주입한다."""
    name = "cycle"

    def __init__(self, interval: float = 45.0, warmup: float = 40.0) -> None:
        self.interval, self.warmup = interval, warmup

    def bind(self, sim):
        super().bind(sim)
        self.next = sim.start + self.warmup
        self.i = 0

    def step(self, a, b):
        while self.next < b:
            r, rel = self.rnd, self.next - self.sim.start
            kind = ATTACK_TYPES[self.i % len(ATTACK_TYPES)]
            if kind == "port_scan":
                actor = PortScan(rel, duration=r.uniform(3, 8), rate=r.uniform(30, 100),
                                 attacker=f"45.33.{r.randint(1, 250)}.{r.randint(1, 250)}")
            elif kind == "syn_flood":
                actor = SynFlood(rel, duration=r.uniform(4, 8), rate=r.uniform(200, 800))
            elif kind == "dns_flood":
                actor = DnsFlood(rel, duration=r.uniform(8, 12), rate=r.uniform(15, 50),
                                 host=f"192.168.0.{r.randint(60, 90)}")
            else:
                actor = Spike(rel, duration=r.uniform(2, 4), pps=r.uniform(400, 900),
                              host=f"192.168.0.{r.randint(2, 21)}")
            self.sim.add(actor)
            if len(self.sim.episodes) > 1000:
                del self.sim.episodes[:500]
            self.i += 1
            self.next += self.interval


def live_demo(seed: int, start: float, interval: float = 45.0, warmup: float = 40.0) -> Simulation:
    sim = Simulation(seed, start=start).add(Baseline())
    return sim.add(AttackCycle(interval, warmup))


def benign_scenario(name: str, seed: int) -> tuple[Simulation, float]:
    sim = Simulation(seed).add(Baseline())
    if name == "baseline":
        return sim, 120
    if name == "big_download":
        return sim.add(Spike(40, duration=60, pps=3500, host="192.168.0.16",
                             server="151.101.2.2", label=False)), 120
    if name == "dns_burst":
        return sim.add(DnsBurst()), 120
    if name == "outage":
        return sim.add(Outage()), 120
    if name == "nat":
        return sim.add(NatSurge()), 120
    raise ValueError(name)
