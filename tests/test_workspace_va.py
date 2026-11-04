"""Tests for rebrew.workspace.va."""

from __future__ import annotations

from rebrew.workspace.va import VA_MAX, parse_va_candidates


def test_hex_prefixed() -> None:
    assert parse_va_candidates("0x10") == [16]
    assert parse_va_candidates("0X10") == [16]


def test_all_digits_decimal_first_with_hex_fallback() -> None:
    assert parse_va_candidates("10") == [10, 16]


def test_single_digit_deduped() -> None:
    assert parse_va_candidates("9") == [9]


def test_bare_hex_letters() -> None:
    assert parse_va_candidates("abc") == [0xABC]
    assert parse_va_candidates("1a") == [26]


def test_negative_kept() -> None:
    assert parse_va_candidates("-0x10") == [-16]
    assert parse_va_candidates("-10") == [-10, -16]


def test_overflow_dropped() -> None:
    assert parse_va_candidates(str(1 << 63)) == []
    assert parse_va_candidates("0x" + format(1 << 63, "x")) == []


def test_negative_overflow_dropped() -> None:
    assert parse_va_candidates("-9223372036854775809") == []
    assert parse_va_candidates("-0x8000000000000001") == []


def test_underscores_rejected() -> None:
    assert parse_va_candidates("1_0") == []
    assert parse_va_candidates("0x1_0") == []


def test_max_kept() -> None:
    assert parse_va_candidates(str(VA_MAX)) == [VA_MAX]


def test_empty_and_unparseable() -> None:
    assert parse_va_candidates("") == []
    assert parse_va_candidates("zzz") == []


def test_non_ascii_digits_rejected() -> None:
    assert parse_va_candidates("١٢") == []
    assert parse_va_candidates("１２") == []
    assert parse_va_candidates("0x١٢") == []
