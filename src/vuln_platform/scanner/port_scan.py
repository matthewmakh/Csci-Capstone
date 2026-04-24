"""Concurrent TCP SYN port scan.

The original code scanned ports sequentially with sr1() + 0.1s timeout
per port, which is painfully slow. This version uses a
ThreadPoolExecutor to issue SYN probes concurrently. Classification
logic (SYN-ACK == 0x12 open, RST-ACK == 0x14 closed, no response ==
filtered) matches the original.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable


logger = logging.getLogger(__name__)

_SYN_ACK = 0x12  # TCP flags: SYN + ACK -> port is open
_RST_ACK = 0x14  # TCP flags: RST + ACK -> port is closed


def port_scan(
    host: str,
    ports: Iterable[int],
    *,
    timeout: float = 0.5,
    workers: int = 100,
) -> list[int]:
    """Issue TCP SYN probes concurrently. Returns sorted list of open ports."""
    from scapy.all import IP, TCP, send, sr1  # type: ignore[import-untyped]

    port_list = sorted(set(ports))
    logger.info(
        "port_scan: %s, %d ports, %d workers, %.2fs timeout",
        host, len(port_list), workers, timeout,
    )

    def probe(port: int) -> int | None:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp is None or not resp.haslayer(TCP):
            return None
        flags = int(resp.getlayer(TCP).flags)
        if flags == _SYN_ACK:
            # Send RST to tear down the half-open connection politely.
            send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=False)
            logger.info("port_scan: %s:%d OPEN", host, port)
            return port
        return None

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe, p): p for p in port_list}
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)
