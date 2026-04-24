"""Local fake HTTP service that advertises a deliberately old banner.

Used by `vuln-platform demo` as a stand-in for a vulnerable target so
the pipeline can run end-to-end without needing a real lab VM. The
banner mimics a known-vulnerable Apache httpd version so the
Enrichment Agent's NVD lookup actually finds CVEs.

This is a userland TCP socket — no raw-socket privileges needed.
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading


BANNER = (
    b"HTTP/1.0 200 OK\r\n"
    b"Server: Apache/2.4.49 (Unix)\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 55\r\n"
    b"\r\n"
    b"Deliberately-vulnerable demo target. DO NOT DEPLOY.\r\n"
)


def handle(conn: socket.socket) -> None:
    try:
        conn.settimeout(2.0)
        try:
            conn.recv(4096)
        except OSError:
            pass
        try:
            conn.sendall(BANNER)
        except OSError:
            pass
    finally:
        conn.close()


def serve(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(8)
        print(f"fake_service: listening on {host}:{port}", file=sys.stderr)
        while True:
            try:
                conn, _ = sock.accept()
            except KeyboardInterrupt:
                return
            thread = threading.Thread(target=handle, args=(conn,), daemon=True)
            thread.start()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
