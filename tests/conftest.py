from netscope.models import make_packet


def tcp(ts, src, dst, sport, dport, flags="A", length=100, seq=None):
    return make_packet(ts, src, dst, "TCP", length, sport=sport, dport=dport, flags=flags, seq=seq)


def udp(ts, src, dst, sport, dport, length=80):
    return make_packet(ts, src, dst, "UDP", length, sport=sport, dport=dport)
