"""Tests for authorization / scope enforcement."""
from __future__ import annotations

from pathlib import Path

import pytest

from vuln_platform.ethics import (
    InvalidScopeFile,
    Scope,
    ScopeViolation,
    enforce_in_scope,
    load_scope,
)


def test_load_valid_scope(scope_yaml_path: Path) -> None:
    scope = load_scope(scope_yaml_path)
    assert scope.classification == "lab"
    assert scope.attestation.authorized_by == "Test Authority"
    assert scope.contains("127.0.0.1")
    assert scope.contains("192.168.56.10")


def test_rejects_missing_classification(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "authorized_cidrs: [127.0.0.0/8]\n"
        "attestation: {authorized_by: X, date: Y, statement: Z}\n",
        encoding="utf-8",
    )
    with pytest.raises(InvalidScopeFile):
        load_scope(path)


def test_rejects_invalid_classification(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "classification: random\n"
        "authorized_cidrs: [127.0.0.0/8]\n"
        "attestation: {authorized_by: X, date: Y, statement: Z}\n",
        encoding="utf-8",
    )
    with pytest.raises(InvalidScopeFile):
        load_scope(path)


def test_rejects_empty_cidrs(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "classification: lab\n"
        "authorized_cidrs: []\n"
        "attestation: {authorized_by: X, date: Y, statement: Z}\n",
        encoding="utf-8",
    )
    with pytest.raises(InvalidScopeFile):
        load_scope(path)


def test_rejects_missing_attestation_field(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "classification: lab\n"
        "authorized_cidrs: [127.0.0.0/8]\n"
        "attestation: {authorized_by: X, date: Y}\n",  # no statement
        encoding="utf-8",
    )
    with pytest.raises(InvalidScopeFile):
        load_scope(path)


def test_in_scope_passes(lab_scope: Scope) -> None:
    enforce_in_scope(lab_scope, "127.0.0.1")


def test_out_of_scope_raises(lab_scope: Scope) -> None:
    with pytest.raises(ScopeViolation):
        enforce_in_scope(lab_scope, "8.8.8.8")


def test_out_of_scope_cidr_raises(lab_scope: Scope) -> None:
    with pytest.raises(ScopeViolation):
        enforce_in_scope(lab_scope, "10.0.0.0/24")


def test_malformed_target_is_out_of_scope(lab_scope: Scope) -> None:
    with pytest.raises(ScopeViolation):
        enforce_in_scope(lab_scope, "not-an-ip")
