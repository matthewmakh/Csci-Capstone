"""ICMP host discovery via scapy.

Derived from the classmate's original ping_scan() — now with type hints,
proper logging, and the scapy import quarantined so tests don't need
raw-socket privileges.
"""
from __future__ import annotations

import logging


logger = logging.getLogger(__name__)


def ping_scan(ip_range: str, timeout: float = 1.0) -> list[str]:
    """ICMP echo sweep across an address or CIDR. Returns live source IPs.

    Requires raw socket privileges (root on Linux, or CAP_NET_RAW).
    """
    # Import scapy lazily so importing this module doesn't crash on systems
    # without scapy installed, and so unit tests can mock without touching
    # the network stack.
    from scapy.all import ICMP, IP, sr  # type: ignore[import-untyped]

    logger.info("ping_scan: probing %s (timeout=%.1fs)", ip_range, timeout)
    answered, _ = sr(
        IP(dst=ip_range) / ICMP(), timeout=timeout, verbose=False
    )

    alive: list[str] = []
    seen: set[str] = set()
    for _sent, received in answered:
        src = received.src
        if src not in seen:
            alive.append(src)
            seen.add(src)
            logger.info("ping_scan: host alive - %s", src)
    return sorted(alive)
