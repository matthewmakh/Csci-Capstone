"""TCP banner grabbing + naive service/version parsing.

Uses plain userland TCP sockets (not scapy), so this step does not
require raw-socket privileges. For well-known services we send a
minimal protocol nudge (GET / for HTTP) so the server coughs up a
useful banner; otherwise we just read whatever the server sends
unprompted.

Service parsing is intentionally best-effort. Nmap-grade
fingerprinting is a semester's worth of work on its own; the goal
here is to give the Enrichment Agent a reasonable service+version
string to query NVD with, and to flag unknowns so the LLM can reason
about them.
"""
from __future__ import annotations

import logging
import re
import socket

from ..models import Service


logger = logging.getLogger(__name__)

_HTTP_PROBE = b"GET / HTTP/1.0\r\n\r\n"
# Minimal protocol nudges keyed by port.
_PROBES: dict[int, bytes] = {
    80: _HTTP_PROBE,
    443: _HTTP_PROBE,
    8000: _HTTP_PROBE,
    8080: _HTTP_PROBE,
    8443: _HTTP_PROBE,
    18080: _HTTP_PROBE,  # demo target default
}

# Default service names by well-known port. These are only used as a
# fallback when the banner doesn't identify the service on its own.
_WELL_KNOWN: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 18080: "http-alt",
}


def grab_banner(host: str, port: int, *, timeout: float = 2.0) -> str | None:
    """Open a TCP connection, nudge if appropriate, return decoded banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            probe = _PROBES.get(port)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    return None
            data = b""
            try:
                while len(data) < 1024:
                    chunk = sock.recv(1024 - len(data))
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
    except OSError as e:
        logger.debug("grab_banner: %s:%d failed: %s", host, port, e)
        return None
    if not data:
        return None
    return data.decode("utf-8", errors="replace").strip() or None


# Regexes ordered roughly most-specific-first.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssh", re.compile(r"SSH-\d\.\d-(?P<name>[^\s]+)")),
    ("http", re.compile(r"Server:\s*(?P<name>[^\r\n]+)", re.IGNORECASE)),
    ("smtp", re.compile(r"^220[- ].*?(?P<name>[A-Za-z][\w\-\.]*)\b", re.DOTALL)),
    ("ftp", re.compile(r"^220[- ].*?(?P<name>[A-Za-z][\w\-\.]*)\b", re.DOTALL)),
)

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3}[a-zA-Z0-9\-_.]*)")


def parse_service(port: int, banner: str | None) -> Service:
    """Extract a service name and (best-effort) version from a banner."""
    fallback_name = _WELL_KNOWN.get(port, f"unknown-{port}")
    if not banner:
        return Service(name=fallback_name, version=None, banner=None)

    name = fallback_name
    first_line = banner.splitlines()[0] if banner else ""

    # SSH banners are the easiest — "SSH-2.0-OpenSSH_9.6p1" etc.
    ssh_match = _PATTERNS[0][1].match(first_line)
    if ssh_match:
        raw = ssh_match.group("name")
        name = raw.split("_", 1)[0].lower() or "ssh"
        version = _extract_version(raw)
        return Service(name=name, version=version, banner=banner)

    # HTTP server header if we triggered one with GET /.
    http_match = _PATTERNS[1][1].search(banner)
    if http_match:
        raw = http_match.group("name").strip()
        name = raw.split("/", 1)[0].lower() or "http"
        version = _extract_version(raw)
        return Service(name=name, version=version, banner=banner)

    # SMTP / FTP 220-style greetings.
    for proto in ("smtp", "ftp"):
        if port in (25, 21) or banner.startswith("220"):
            match = re.match(r"^220[- ](?P<rest>.+)", first_line)
            if match:
                rest = match.group("rest")
                name = proto if port in (25, 21) else fallback_name
                version = _extract_version(rest)
                return Service(name=name, version=version, banner=banner)

    # Last resort: pull any version-looking token out of the first line.
    return Service(name=fallback_name, version=_extract_version(first_line), banner=banner)


def _extract_version(s: str) -> str | None:
    match = _VERSION_RE.search(s)
    return match.group(1) if match else None
