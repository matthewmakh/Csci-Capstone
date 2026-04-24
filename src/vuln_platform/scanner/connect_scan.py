"""Userland TCP connect scan — no raw sockets, no privileges required.

Slower and noisier than the SYN scan (it completes the three-way handshake
and shows up in application logs), but works on macOS and unprivileged
containers where scapy's raw-socket SYN scan fails silently.
"""
from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable


logger = logging.getLogger(__name__)


def connect_scan(
    host: str,
    ports: Iterable[int],
    *,
    timeout: float = 0.5,
    workers: int = 100,
) -> list[int]:
    """TCP connect-scan. Returns sorted list of open ports."""
    port_list = sorted(set(ports))
    logger.info(
        "connect_scan: %s, %d ports, %d workers, %.2fs timeout",
        host, len(port_list), workers, timeout,
    )

    def probe(port: int) -> int | None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((host, port))
            except OSError:
                return None
        if result == 0:
            logger.info("connect_scan: %s:%d OPEN", host, port)
            return port
        return None

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, p) for p in port_list]
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)
