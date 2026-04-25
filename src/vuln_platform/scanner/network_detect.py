"""Detect the local network the operator is currently attached to.

Pure-stdlib, cross-platform best-effort. Used by the `discover` and
`init-scope` CLI commands to suggest a CIDR for a home/lab scan.

Security note: detecting your network does NOT authorize you to scan
it. The scope-file + signed-attestation requirement still applies —
this helper only fills in the CIDR for you so you don't have to type
it. Authorization is the user's responsibility.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LocalNetwork:
    """The network the host appears to be sitting on."""

    ip: str                              # local IP, e.g. 192.168.1.42
    cidr: str                            # network in CIDR form, e.g. 192.168.1.0/24
    network: ipaddress.IPv4Network       # parsed
    interface: str | None                # best-effort interface name
    detection_method: str                # "ip", "ifconfig", "fallback /24"


def detect_local_network() -> LocalNetwork:
    """Return information about the network this host is currently on.

    Uses a UDP "connect" to a non-routable address to learn which
    interface would be used for outbound traffic, then asks the OS
    for the netmask of that IP. Falls back to /24 if the netmask
    can't be determined.
    """
    ip = _outbound_ip()
    method, prefix, iface = _prefix_and_interface_for_ip(ip)
    if prefix is None:
        # /24 is the overwhelming default for home networks. Worst case
        # we suggest a slightly-too-narrow scope, which the user can
        # widen by editing the generated scope file.
        prefix = 24
        method = "fallback /24"
    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return LocalNetwork(
        ip=ip,
        cidr=str(network),
        network=network,
        interface=iface,
        detection_method=method,
    )


def _outbound_ip() -> str:
    """Find the local address the OS would use to reach the internet.

    The UDP "connect" doesn't actually send anything; it just makes the
    kernel pick a source address. Standard portable trick.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Any non-routable destination works; we just need the kernel
        # to do the routing-table lookup.
        sock.connect(("10.255.255.255", 1))
        ip: str = sock.getsockname()[0]
    finally:
        sock.close()
    if ip == "0.0.0.0":
        # No default route. Fall back to hostname resolution.
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = "127.0.0.1"
    return ip


def _prefix_and_interface_for_ip(
    ip: str,
) -> tuple[str, int | None, str | None]:
    """Parse `ip -4 addr` (Linux) or `ifconfig` (BSD/macOS) output.

    Returns (method, prefix_length, interface_name). If detection
    fails, returns (method, None, None).
    """
    # Linux: `ip -4 addr show`
    out = _run(["ip", "-4", "addr", "show"])
    if out:
        result = _parse_ip_addr(out, ip)
        if result is not None:
            prefix, iface = result
            return ("ip", prefix, iface)

    # macOS / BSD: `ifconfig`
    out = _run(["ifconfig"])
    if out:
        result = _parse_ifconfig(out, ip)
        if result is not None:
            prefix, iface = result
            return ("ifconfig", prefix, iface)

    return ("none", None, None)


def _run(cmd: list[str]) -> str | None:
    try:
        return subprocess.check_output(
            cmd, text=True, timeout=2, stderr=subprocess.DEVNULL,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
        logger.debug("network_detect: %s failed: %s", cmd[0], e)
        return None


# -- parsers -----------------------------------------------------------

# Linux `ip -4 addr show` output:
#   2: eth0: <BROADCAST,...> ... state UP ...
#       inet 192.168.1.42/24 brd 192.168.1.255 scope global dynamic eth0
_IP_INTERFACE_RE = re.compile(r"^\d+:\s+(?P<iface>[^\s:]+):", re.MULTILINE)


def _parse_ip_addr(out: str, ip: str) -> tuple[int, str] | None:
    pattern = re.compile(
        rf"\s+inet\s+{re.escape(ip)}/(?P<prefix>\d+)\b",
    )
    match = pattern.search(out)
    if not match:
        return None
    prefix = int(match.group("prefix"))
    # Walk backwards from the match to find the interface header line.
    iface = None
    head = out[: match.start()]
    for m in _IP_INTERFACE_RE.finditer(head):
        iface = m.group("iface")
    return prefix, iface


# macOS / BSD `ifconfig` output:
#   en0: flags=8863<...> mtu 1500
#       inet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
_IFCONFIG_HEADER_RE = re.compile(r"^(?P<iface>[A-Za-z0-9]+):\s+flags=", re.MULTILINE)


def _parse_ifconfig(out: str, ip: str) -> tuple[int, str] | None:
    pattern = re.compile(
        rf"\s+inet\s+{re.escape(ip)}\s+netmask\s+0x(?P<mask>[0-9a-fA-F]+)\b",
    )
    match = pattern.search(out)
    if not match:
        return None
    mask_int = int(match.group("mask"), 16)
    prefix = bin(mask_int).count("1")
    iface = None
    head = out[: match.start()]
    for m in _IFCONFIG_HEADER_RE.finditer(head):
        iface = m.group("iface")
    return prefix, iface


# -- TCP-based host discovery (no raw sockets needed) -----------------

# A small set of common ports that are usually answered (or RST'd) on
# any live host, used for unprivileged host discovery.
_SWEEP_PORTS = (80, 443, 22, 445, 3389, 8080)


def tcp_ping_sweep(
    cidr: str,
    *,
    timeout: float = 0.4,
    workers: int = 64,
    ports: tuple[int, ...] = _SWEEP_PORTS,
) -> list[str]:
    """TCP-based host discovery: alive if any common port answers/RSTs.

    A drop-in for ICMP ping_scan() that works without raw-socket
    privileges. We try a few common ports and call a host alive if
    any TCP three-way handshake succeeds OR is actively refused
    (RST), since both prove the host's TCP stack responded.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    network = ipaddress.ip_network(cidr, strict=False)
    # Skip network/broadcast addresses on networks larger than /31.
    if network.num_addresses > 2:
        candidates = [str(h) for h in network.hosts()]
    else:
        candidates = [str(h) for h in network]

    logger.info(
        "tcp_ping_sweep: probing %d hosts in %s on %d ports",
        len(candidates), cidr, len(ports),
    )

    def is_alive(host: str) -> str | None:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                rc = sock.connect_ex((host, port))
            except OSError:
                rc = 1
            finally:
                sock.close()
            # 0 = open (connected), ECONNREFUSED = port closed but host alive.
            if rc == 0 or rc == 111 or rc == 61:  # 111 Linux, 61 macOS
                return host
        return None

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(is_alive, h) for h in candidates]
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                alive.append(result)
    return sorted(alive, key=lambda x: ipaddress.ip_address(x))
