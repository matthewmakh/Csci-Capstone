"""TCP banner grabbing + naive service/version parsing.

Uses plain userland TCP sockets (not scapy), so this step does not
require raw-socket privileges. Each well-known port has its own probe
function: HTTP servers need a `GET /`, SMTP wants an `EHLO` after the
greeting, Redis answers an `INFO` command, while SSH/FTP/POP3/IMAP
greet first so we just read.

Service parsing is intentionally best-effort. Nmap-grade fingerprinting
is a semester's worth of work on its own; the goal is to give the
Enrichment Agent a reasonable service+version string for NVD queries.
"""
from __future__ import annotations

import logging
import re
import socket
from typing import Callable

from ..models import Service


logger = logging.getLogger(__name__)

# Protocol probes — each takes a connected socket, sends/receives, and
# returns the raw banner bytes. They are wrapped in OSError-tolerant
# logic in `grab_banner`, so they can sendall/recv freely.
ProbeFn = Callable[[socket.socket], bytes]


def _read_max(sock: socket.socket, limit: int = 4096) -> bytes:
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(limit - len(data))
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data


def _passive_probe(sock: socket.socket) -> bytes:
    """Read whatever the server volunteers (SSH, FTP, POP3, IMAP)."""
    return _read_max(sock, 1024)


def _http_probe(sock: socket.socket) -> bytes:
    sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
    return _read_max(sock, 4096)


def _smtp_probe(sock: socket.socket) -> bytes:
    """Read 220 greeting, send EHLO, read multi-line 250 response."""
    greeting = _read_max(sock, 1024)
    try:
        sock.sendall(b"EHLO scanner.local\r\n")
    except OSError:
        return greeting
    ext = _read_max(sock, 4096)
    return greeting + b"\n" + ext


def _redis_probe(sock: socket.socket) -> bytes:
    """INFO returns a bulk string with redis_version: among other fields."""
    try:
        sock.sendall(b"INFO\r\n")
    except OSError:
        return b""
    return _read_max(sock, 4096)


_PROBES: dict[int, ProbeFn] = {
    # HTTP family
    80: _http_probe,
    443: _http_probe,
    8000: _http_probe,
    8080: _http_probe,
    8443: _http_probe,
    18080: _http_probe,  # demo target default
    # SMTP family
    25: _smtp_probe,
    465: _smtp_probe,
    587: _smtp_probe,
    2525: _smtp_probe,
    # Redis
    6379: _redis_probe,
    # SSH / FTP / POP3 / IMAP all greet first
    22: _passive_probe,
    21: _passive_probe,
    110: _passive_probe,
    143: _passive_probe,
    995: _passive_probe,
    993: _passive_probe,
    23: _passive_probe,  # telnet
}

# Default service names by well-known port. Fallback when the banner
# doesn't identify the service on its own.
_WELL_KNOWN: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp-submission",
    993: "imaps", 995: "pop3s", 2525: "smtp-alt",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 18080: "http-alt",
}


def grab_banner(host: str, port: int, *, timeout: float = 2.0) -> str | None:
    """Open a TCP connection, run the right probe, return decoded banner."""
    probe = _PROBES.get(port, _passive_probe)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = probe(sock)
    except OSError as e:
        logger.debug("grab_banner: %s:%d failed: %s", host, port, e)
        return None
    if not data:
        return None
    return data.decode("utf-8", errors="replace").strip() or None


# Version pattern shared by most parsers — e.g. 9.6p1, 7.0.5, 3.0.3
_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3}[a-zA-Z0-9\-_.]*)")


def parse_service(port: int, banner: str | None) -> Service:
    """Extract a service name and (best-effort) version from a banner.

    Returns a Service whose .name is normalized to lowercase so the
    Enrichment Agent's keyword cache keys match deterministically.
    """
    fallback_name = _WELL_KNOWN.get(port, f"unknown-{port}")
    if not banner:
        return Service(name=fallback_name, version=None, banner=None)

    for parser in _PARSERS:
        result = parser(port, banner, fallback_name)
        if result is not None:
            return result
    return Service(
        name=fallback_name,
        version=_extract_version(banner.splitlines()[0]),
        banner=banner,
    )


# Each parser returns a Service or None (meaning "not my protocol").
ServiceParser = Callable[[int, str, str], "Service | None"]


def _parse_ssh(port: int, banner: str, fallback: str) -> Service | None:
    # "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    m = re.match(r"SSH-\d\.\d-(?P<sw>[^\s\r\n]+)", banner)
    if not m:
        return None
    sw = m.group("sw")
    name, _, version_part = sw.partition("_")
    name = (name or "ssh").lower()
    version = _extract_version(version_part) or _extract_version(sw)
    return Service(name=name, version=version, banner=banner)


def _parse_http(port: int, banner: str, fallback: str) -> Service | None:
    m = re.search(r"^Server:\s*(?P<sw>[^\r\n]+)", banner, re.IGNORECASE | re.MULTILINE)
    if not m:
        return None
    raw = m.group("sw").strip()
    # "Apache/2.4.49 (Unix)" -> name=apache, version=2.4.49
    name = raw.split("/", 1)[0].lower() or "http"
    version = _extract_version(raw)
    return Service(name=name, version=version, banner=banner)


def _parse_smtp(port: int, banner: str, fallback: str) -> Service | None:
    is_smtp_port = port in (25, 465, 587, 2525)
    looks_like_smtp = bool(re.search(r"\b(?:E?SMTP)\b", banner))
    if not is_smtp_port and not looks_like_smtp:
        return None
    name = "smtp"
    for mta in ("Postfix", "Exim", "Sendmail", "Microsoft ESMTP", "OpenSMTPD"):
        if mta.lower() in banner.lower():
            name = mta.split()[0].lower()
            break
    head = "\n".join(banner.splitlines()[:5])
    version = _extract_version(head)
    return Service(name=name, version=version, banner=banner)


def _parse_redis(port: int, banner: str, fallback: str) -> Service | None:
    if port != 6379 and "redis_version" not in banner:
        return None
    m = re.search(r"redis_version:(?P<v>[^\r\n]+)", banner)
    version = m.group("v").strip() if m else None
    return Service(name="redis", version=version, banner=banner)


def _parse_ftp(port: int, banner: str, fallback: str) -> Service | None:
    if port != 21 and not banner.lstrip().startswith("220"):
        return None
    if port != 21 and "ftp" not in banner.lower():
        return None
    # "220 (vsFTPd 3.0.3)" / "220 ProFTPD 1.3.7 Server..."
    m = re.search(r"(vsFTPd|ProFTPD|FileZilla|Pure-FTPd|wu-ftpd)", banner, re.IGNORECASE)
    name = m.group(1).lower() if m else "ftp"
    version = _extract_version(banner.splitlines()[0])
    return Service(name=name, version=version, banner=banner)


def _parse_pop3(port: int, banner: str, fallback: str) -> Service | None:
    if port not in (110, 995) and not banner.lstrip().startswith("+OK"):
        return None
    name = "dovecot" if "dovecot" in banner.lower() else "pop3"
    version = _extract_version(banner.splitlines()[0])
    return Service(name=name, version=version, banner=banner)


def _parse_imap(port: int, banner: str, fallback: str) -> Service | None:
    if port not in (143, 993) and not banner.lstrip().startswith("* OK"):
        return None
    name = "dovecot" if "dovecot" in banner.lower() else "imap"
    version = _extract_version(banner.splitlines()[0])
    return Service(name=name, version=version, banner=banner)


_PARSERS: tuple[ServiceParser, ...] = (
    _parse_ssh,
    _parse_http,
    _parse_smtp,
    _parse_redis,
    _parse_ftp,
    _parse_pop3,
    _parse_imap,
)


def _extract_version(s: str) -> str | None:
    match = _VERSION_RE.search(s)
    return match.group(1) if match else None
