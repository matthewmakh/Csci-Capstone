"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from vuln_platform.audit import AuditLogger
from vuln_platform.ethics import Attestation, Scope
from vuln_platform.storage import Store

import ipaddress


@pytest.fixture
def tmp_store(tmp_path: Path) -> Store:
    return Store(tmp_path / "test.db")


@pytest.fixture
def tmp_audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(tmp_path / "audit.jsonl")


@pytest.fixture
def lab_scope() -> Scope:
    """A minimal in-scope-for-loopback scope suitable for unit tests."""
    return Scope(
        classification="lab",
        cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        attestation=Attestation(
            authorized_by="Test",
            date="2026-04-24",
            statement="Test attestation.",
        ),
    )


@pytest.fixture
def scope_yaml_path(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "scope.yaml"
    path.write_text(
        """
classification: lab
authorized_cidrs:
  - 127.0.0.0/8
  - 192.168.56.0/24
attestation:
  authorized_by: Test Authority
  date: 2026-04-24
  statement: Test attestation for unit tests.
""",
        encoding="utf-8",
    )
    yield path
