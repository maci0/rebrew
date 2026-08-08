"""Tests for catalog/models.py — FunctionEntry / GhidraDataLabel parsing."""

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


class TestFunctionEntryFromDict:
    def test_hex_string_va(self) -> None:
        e = FunctionEntry.from_dict({"va": "0x10001000", "size": 64, "name": "a"})
        assert e.va == 0x10001000
        assert e.size == 64
        assert e.name == "a"

    def test_missing_keys_raise(self) -> None:
        with pytest.raises(ValueError, match="must contain 'va' and 'size'"):
            FunctionEntry.from_dict({"va": 1})

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
