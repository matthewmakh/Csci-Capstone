"""Authorization / scope enforcement.

Every scan requires a scope file that enumerates authorized CIDR ranges
and carries a signed attestation. Targets are cross-checked against the
scope BEFORE any packet is sent. Refuses to run on scope files that are
missing required fields.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope."""


class InvalidScopeFile(Exception):
    """Raised when the scope file is missing required fields."""


Classification = Literal["lab", "authorized_engagement"]


@dataclass(frozen=True)
class Attestation:
    authorized_by: str
    date: str
    statement: str


@dataclass(frozen=True)
class Scope:
    classification: Classification
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    attestation: Attestation

    def contains(self, target: str) -> bool:
        """Return True if every IP in `target` (address or CIDR) is in scope."""
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        return any(net.subnet_of(auth) for auth in self.cidrs if net.version == auth.version)


def load_scope(path: str | Path) -> Scope:
    """Load and validate a YAML scope file."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise InvalidScopeFile("scope file must be a YAML mapping")

    classification = data.get("classification")
    if classification not in ("lab", "authorized_engagement"):
        raise InvalidScopeFile(
            "classification must be 'lab' or 'authorized_engagement'"
        )

    raw_cidrs = data.get("authorized_cidrs")
    if not isinstance(raw_cidrs, list) or not raw_cidrs:
        raise InvalidScopeFile("authorized_cidrs must be a non-empty list")
    try:
        cidrs = tuple(ipaddress.ip_network(c, strict=False) for c in raw_cidrs)
    except ValueError as e:
        raise InvalidScopeFile(f"invalid CIDR in authorized_cidrs: {e}") from e

    raw_att = data.get("attestation")
    if not isinstance(raw_att, dict):
        raise InvalidScopeFile("attestation section is required")
    for key in ("authorized_by", "date", "statement"):
        if not raw_att.get(key):
            raise InvalidScopeFile(f"attestation.{key} is required")
    attestation = Attestation(
        authorized_by=str(raw_att["authorized_by"]),
        date=str(raw_att["date"]),
        statement=str(raw_att["statement"]),
    )

    return Scope(classification=classification, cidrs=cidrs, attestation=attestation)


def enforce_in_scope(scope: Scope, target: str) -> None:
    """Raise ScopeViolation if target is not covered by scope."""
    if not scope.contains(target):
        raise ScopeViolation(
            f"target {target!r} is not within the authorized scope "
            f"({', '.join(str(c) for c in scope.cidrs)})"
        )
