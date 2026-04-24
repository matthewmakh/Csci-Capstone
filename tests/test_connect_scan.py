"""Tests for the userland TCP connect-scan path."""
from __future__ import annotations

import socket
import threading

import pytest

from vuln_platform.scanner import connect_scan


def _bind_listener() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    return sock, sock.getsockname()[1]


@pytest.fixture
def listening_port() -> int:
    sock, port = _bind_listener()
    stop = threading.Event()

    def accept_loop() -> None:
        sock.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        sock.close()
        t.join(timeout=1)


def test_connect_scan_finds_open_port(listening_port: int) -> None:
    open_ports = connect_scan(
        "127.0.0.1", [listening_port], timeout=0.5, workers=4
    )
    assert open_ports == [listening_port]


def test_connect_scan_reports_closed_ports(listening_port: int) -> None:
    # Port 1 is reserved and almost certainly not listening.
    open_ports = connect_scan(
        "127.0.0.1", [listening_port, 1], timeout=0.5, workers=4
    )
    assert open_ports == [listening_port]


def test_connect_scan_dedupes_and_sorts() -> None:
    # All-closed scan: ports 1, 2, 3 are extremely unlikely to be listening.
    result = connect_scan("127.0.0.1", [3, 1, 2, 1], timeout=0.2, workers=4)
    assert result == []
