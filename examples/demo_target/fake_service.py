"""Multi-service fake target for the demo.

Hosts several deliberately-old service banners on different localhost
ports so the pipeline produces a varied report:

    Port    Service         Pretends to be              Famous CVE
    -----   -------------   --------------------------  --------------------------
    18080   HTTP            Apache 2.4.49               CVE-2021-41773 (path trav)
    12222   SSH             OpenSSH 7.2p2               CVE-2018-15473 (user enum)
    12121   FTP             vsftpd 2.3.4                CVE-2011-2523 (backdoor)
    16379   Redis           Redis 4.0.10                CVE-2022-0543 (Lua escape)
    12525   SMTP            Exim 4.87                   CVE-2019-15846 (root RCE)

Every port is bound on 127.0.0.1 only and serves nothing more than the
banner — there is no actual vulnerability behind any of them. This is
purely a banner-grabbing target so we can demo the full pipeline.
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
from dataclasses import dataclass
from typing import Callable


# ---- banners ---------------------------------------------------------

APACHE_BANNER = (
    b"HTTP/1.0 200 OK\r\n"
    b"Server: Apache/2.4.49 (Unix)\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 55\r\n"
    b"\r\n"
    b"Deliberately-vulnerable demo target. DO NOT DEPLOY.\r\n"
)

SSH_BANNER = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n"

FTP_BANNER = b"220 (vsFTPd 2.3.4)\r\n"

REDIS_INFO_RESPONSE = (
    b"$200\r\n"
    b"# Server\r\n"
    b"redis_version:4.0.10\r\n"
    b"redis_git_sha1:00000000\r\n"
    b"redis_mode:standalone\r\n"
    b"os:Linux\r\n"
    b"arch_bits:64\r\n"
    b"\r\n"
)

SMTP_GREETING = b"220 mail.example.com ESMTP Exim 4.87 Ready\r\n"
SMTP_EHLO_RESPONSE = (
    b"250-mail.example.com Hello scanner.local\r\n"
    b"250-PIPELINING\r\n"
    b"250-SIZE 52428800\r\n"
    b"250-STARTTLS\r\n"
    b"250 HELP\r\n"
)


# ---- per-protocol handlers ------------------------------------------

Handler = Callable[[socket.socket], None]


def _http(conn: socket.socket) -> None:
    """HTTP: client sends GET, we reply with the banner."""
    try:
        conn.recv(4096)
    except OSError:
        return
    try:
        conn.sendall(APACHE_BANNER)
    except OSError:
        pass


def _ssh(conn: socket.socket) -> None:
    """SSH: server greets first, then we let the client hang up."""
    try:
        conn.sendall(SSH_BANNER)
        conn.recv(64)  # consume any client banner so the connection stays clean
    except OSError:
        pass


def _ftp(conn: socket.socket) -> None:
    """FTP: 220 greeting then we close on QUIT or any input."""
    try:
        conn.sendall(FTP_BANNER)
        conn.recv(64)
    except OSError:
        pass


def _redis(conn: socket.socket) -> None:
    """Redis: wait for INFO command, reply with a bulk string."""
    try:
        conn.recv(1024)
    except OSError:
        return
    try:
        conn.sendall(REDIS_INFO_RESPONSE)
    except OSError:
        pass


def _smtp(conn: socket.socket) -> None:
    """SMTP: 220 greeting, accept EHLO, respond with extended capabilities."""
    try:
        conn.sendall(SMTP_GREETING)
        data = conn.recv(1024)
        if data and data.upper().startswith(b"EHLO"):
            conn.sendall(SMTP_EHLO_RESPONSE)
        conn.recv(64)
    except OSError:
        pass


@dataclass(frozen=True)
class ServiceProfile:
    port: int
    label: str  # human-readable, for logging
    handler: Handler


PROFILES: tuple[ServiceProfile, ...] = (
    ServiceProfile(18080, "Apache 2.4.49 (HTTP)", _http),
    ServiceProfile(12222, "OpenSSH 7.2p2 (SSH)", _ssh),
    ServiceProfile(12121, "vsftpd 2.3.4 (FTP)", _ftp),
    ServiceProfile(16379, "Redis 4.0.10",       _redis),
    ServiceProfile(12525, "Exim 4.87 (SMTP)",   _smtp),
)


def serve(profile: ServiceProfile, host: str, stop: threading.Event) -> None:
    """Listen on one port; spawn a thread per accepted connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, profile.port))
    except OSError as e:
        print(f"fake_service: skipping {profile.label} on :{profile.port} ({e})",
              file=sys.stderr)
        sock.close()
        return
    sock.listen(8)
    sock.settimeout(0.25)
    print(f"fake_service: listening on {host}:{profile.port} as {profile.label}",
          file=sys.stderr)
    try:
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=_safe_handle, args=(profile.handler, conn), daemon=True
            )
            t.start()
    finally:
        sock.close()


def _safe_handle(handler: Handler, conn: socket.socket) -> None:
    try:
        conn.settimeout(2.0)
        handler(conn)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_all(host: str = "127.0.0.1") -> threading.Event:
    """Spawn a listener thread for every profile. Returns the stop Event."""
    stop = threading.Event()
    for profile in PROFILES:
        t = threading.Thread(
            target=serve, args=(profile, host, stop), daemon=True
        )
        t.start()
    return stop


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    # --port retained for backward compatibility with older demo launchers.
    # When supplied, only the matching profile is served.
    parser.add_argument(
        "--port", type=int, default=None,
        help="If set, only serve the profile bound to this port.",
    )
    args = parser.parse_args()

    profiles = PROFILES
    if args.port is not None:
        profiles = tuple(p for p in PROFILES if p.port == args.port)
        if not profiles:
            print(f"fake_service: no profile registered for port {args.port}",
                  file=sys.stderr)
            return 2

    stop = threading.Event()
    threads: list[threading.Thread] = []
    for profile in profiles:
        t = threading.Thread(
            target=serve, args=(profile, args.host, stop), daemon=True
        )
        t.start()
        threads.append(t)
    try:
        # Idle until interrupted.
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
