"""Tests for port-range parsing."""
from __future__ import annotations

import pytest

from vuln_platform.scanner import parse_ports


def test_single_port() -> None:
    assert parse_ports("80") == [80]


def test_comma_list() -> None:
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_range() -> None:
    assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]


def test_mixed_range_and_list() -> None:
    assert parse_ports("20-25,80,443") == [20, 21, 22, 23, 24, 25, 80, 443]


def test_dedupes_and_sorts() -> None:
    assert parse_ports("1-3,2-4") == [1, 2, 3, 4]
    assert parse_ports("443,22,80") == [22, 80, 443]


def test_empty_raises() -> None:
    with pytest.raises(ValueError):
        parse_ports("")
    with pytest.raises(ValueError):
        parse_ports("   ")


def test_non_integer_raises() -> None:
    with pytest.raises(ValueError):
        parse_ports("abc")
    with pytest.raises(ValueError):
        parse_ports("1-abc")


def test_malformed_range_raises() -> None:
    with pytest.raises(ValueError):
        parse_ports("10-")
    with pytest.raises(ValueError):
        parse_ports("-10")


def test_reverse_range_raises() -> None:
    with pytest.raises(ValueError):
        parse_ports("25-20")


def test_out_of_range_raises() -> None:
    with pytest.raises(ValueError):
        parse_ports("0")
    with pytest.raises(ValueError):
        parse_ports("65536")
    with pytest.raises(ValueError):
        parse_ports("1-70000")
