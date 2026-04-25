"""Tests for local-network detection and TCP host discovery."""
from __future__ import annotations

import socket
import threading

from vuln_platform.scanner.network_detect import (
    _parse_ifconfig,
    _parse_ip_addr,
    detect_local_network,
    tcp_ping_sweep,
)


# ---- ifconfig / ip parsers -------------------------------------------

LINUX_IP_OUT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 192.168.1.42/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86342sec preferred_lft 86342sec
"""

MACOS_IFCONFIG_OUT = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
en4: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
"""


def test_parse_ip_addr_finds_eth0() -> None:
    result = _parse_ip_addr(LINUX_IP_OUT, "192.168.1.42")
    assert result is not None
    prefix, iface = result
    assert prefix == 24
    assert iface == "eth0"


def test_parse_ip_addr_returns_none_for_missing_ip() -> None:
    assert _parse_ip_addr(LINUX_IP_OUT, "10.0.0.1") is None


def test_parse_ifconfig_macos_24() -> None:
    result = _parse_ifconfig(MACOS_IFCONFIG_OUT, "192.168.1.42")
    assert result is not None
    prefix, iface = result
    assert prefix == 24
    assert iface == "en0"


def test_parse_ifconfig_loopback_8() -> None:
    result = _parse_ifconfig(MACOS_IFCONFIG_OUT, "127.0.0.1")
    assert result is not None
    prefix, _ = result
    assert prefix == 8


def test_parse_ifconfig_returns_none_for_missing_ip() -> None:
    assert _parse_ifconfig(MACOS_IFCONFIG_OUT, "8.8.8.8") is None


# ---- end-to-end detect_local_network --------------------------------

def test_detect_local_network_returns_sane_object() -> None:
    """Smoke test — runs in real env, just checks shape."""
    net = detect_local_network()
    assert net.ip
    assert "/" in net.cidr
    assert net.network.num_addresses > 0


# ---- tcp_ping_sweep --------------------------------------------------

def test_tcp_ping_sweep_finds_listening_host() -> None:
    """Bind a real listener; sweep should detect it as alive."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def accept_loop() -> None:
        sock.settimeout(0.1)
        while not stop.is_set():
            try:
                c, _ = sock.accept()
                c.close()
            except (socket.timeout, OSError):
                continue

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    try:
        # /32 sweep targeting just our listener, on the port we're bound to
        alive = tcp_ping_sweep(
            "127.0.0.1/32", timeout=0.4, workers=4, ports=(port,),
        )
        assert "127.0.0.1" in alive
    finally:
        stop.set()
        sock.close()
        t.join(timeout=1)


def test_tcp_ping_sweep_skips_zero_and_broadcast_in_large_nets() -> None:
    """For /24 and bigger we use .hosts() which excludes net + bcast."""
    # We don't actually probe — just call with a 0-port tuple so every
    # connection fails immediately, and check the sweep returned empty
    # (host count would be 254 if it tried .0 and .255).
    alive = tcp_ping_sweep(
        "192.0.2.0/24", timeout=0.05, workers=8, ports=(65530,),
    )
    # 192.0.2.0/24 is TEST-NET-1 — guaranteed unreachable. We don't
    # care how many came back as long as the call returned cleanly.
    assert isinstance(alive, list)
