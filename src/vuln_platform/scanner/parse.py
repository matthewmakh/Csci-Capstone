"""Port range parsing, extracted so it's testable in isolation."""
from __future__ import annotations


def parse_ports(spec: str) -> list[int]:
    """Parse a port-range spec like '20-25,80,443' into a sorted unique list.

    Raises ValueError on malformed input or out-of-range ports.
    """
    if not spec or not spec.strip():
        raise ValueError("empty port spec")

    ports: set[int] = set()
    for piece in spec.split(","):
        piece = piece.strip()
        if not piece:
            raise ValueError(f"empty range in spec: {spec!r}")
        if "-" in piece:
            start_s, _, end_s = piece.partition("-")
            if not start_s or not end_s:
                raise ValueError(f"malformed range: {piece!r}")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError as e:
                raise ValueError(f"non-integer in range: {piece!r}") from e
            if start > end:
                raise ValueError(f"range start > end: {piece!r}")
            _require_port(start)
            _require_port(end)
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(piece)
            except ValueError as e:
                raise ValueError(f"non-integer port: {piece!r}") from e
            _require_port(port)
            ports.add(port)
    return sorted(ports)


def _require_port(p: int) -> None:
    if not 1 <= p <= 65535:
        raise ValueError(f"port out of range (1-65535): {p}")
