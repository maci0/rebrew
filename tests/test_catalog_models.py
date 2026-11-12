"""Tests for catalog/models.py — FunctionEntry / GhidraDataLabel parsing."""

import re

import pytest

from rebrew.catalog.models import FunctionEntry, GhidraDataLabel, _parse_int


class TestParseInt:
    def test_int_passthrough(self) -> None:
        assert _parse_int(0x1000) == 0x1000

    def test_hex_string(self) -> None:
        assert _parse_int("0x1000") == 0x1000

    def test_decimal_string(self) -> None:
        assert _parse_int("4096") == 4096

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot parse integer"):
            _parse_int("not-a-number")

    def test_underscores_rejected(self) -> None:
        with pytest.raises(ValueError, match="Cannot parse integer"):
            _parse_int("1_0")

    def test_non_ascii_digits_rejected(self) -> None:
        with pytest.raises(ValueError, match="Cannot parse integer"):
            _parse_int("١٢")


class TestFunctionEntryFromDict:
    def test_hex_string_va(self) -> None:
        e = FunctionEntry.from_dict({"va": "0x10001000", "size": 64, "name": "a"})
        assert e.va == 0x10001000
        assert e.size == 64
        assert e.name == "a"

    @pytest.mark.parametrize("field", ["va", "size"])
    @pytest.mark.parametrize("value", [-1, -1.0, "-0x1"])
    def test_negative_extent_is_rejected(self, field: str, value: float | str) -> None:
        row = {"va": 1, "size": 4, field: value}
        with pytest.raises(ValueError, match="non-negative"):
            FunctionEntry.from_dict(row)

    def test_zero_extent_remains_representable(self) -> None:
        entry = FunctionEntry.from_dict({"va": 0, "size": 0})
        assert (entry.va, entry.size) == (0, 0)

    def test_missing_keys_raise(self) -> None:
        with pytest.raises(
            ValueError, match=re.escape("must contain 'va' and 'size': got ['name', 'va']")
        ):
            FunctionEntry.from_dict({"va": 1, "name": "f"})

    def test_name_fallbacks(self) -> None:
        e = FunctionEntry.from_dict({"va": 1, "size": 2, "ghidra_name": "g"})
        assert e.name == "g"
        assert e.tool_name == "g"
        e2 = FunctionEntry.from_dict({"va": 1, "size": 2, "tool_name": "t"})
        assert e2.name == "t"

    def test_empty_dict_raises(self) -> None:
        with pytest.raises(ValueError):
            FunctionEntry.from_dict({})


class TestGhidraDataLabelFromDict:
    def test_full(self) -> None:
        g = GhidraDataLabel.from_dict({"va": 0x1000, "size": 4, "label": "x", "state": "thunk"})
        assert g.va == 0x1000
        assert g.label == "x"
        assert g.state == "thunk"

    def test_defaults(self) -> None:
        g = GhidraDataLabel.from_dict({})
        assert g.va == 0
        assert g.size == 0
        assert g.label == ""
        assert g.state == "data"
