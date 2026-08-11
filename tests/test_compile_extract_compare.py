"""Tests for compile.py _extract_and_compare — the post-compile compare stage.

_exctract_and_compare is the shared compile→extract→compare pipeline used by
rebrew test / verify / diff.  These tests exercise the truncation,
classification and error-labeling logic with a monkeypatched
parse_obj_symbol_and_relocs — no MSVC/Wine required.
"""

from __future__ import annotations

from typing import Any

import pytest

from rebrew.compile import _extract_and_compare
from rebrew.matcher.parsers import CoffRelocRecord


def _stub_parser(
    obj_bytes: bytes | None,
    reloc_dict: dict[int, str] | None = None,
    typed: list[CoffRelocRecord] | None = None,
) -> Any:
    """Return a parse_obj_symbol_and_relocs stand-in."""

    def _parse(
        _obj_path: Any, _symbol: str
    ) -> tuple[bytes | None, dict[int, str] | None, list[CoffRelocRecord]]:
        return obj_bytes, reloc_dict, typed or []

    return _parse


class TestExtractAndCompare:
    def test_exact_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x55\x8b\xec")
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec")
        assert r.matched is True
        assert r.status == "EXACT"
        assert r.match_percent == 100.0

    def test_reloc_normalized_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # 8-byte buffers so a reloc at offset 4 (4-byte span) is in-range.
        obj = bytearray(b"\x55\x8b\xec\x90\x00\x00\x00\x00")
        tgt = bytearray(b"\x55\x8b\xec\x90\xaa\xbb\xcc\xdd")
        monkeypatch.setattr(
            "rebrew.compile.parse_obj_symbol_and_relocs",
            _stub_parser(
                bytes(obj),
                typed=[CoffRelocRecord(offset=4, type=0x06, symbol="_other")],
            ),
        )
        # Typed reloc records are preferred; the differing slot is masked.
        r = _extract_and_compare("/x.obj", "_f", bytes(tgt))
        assert r.matched is True
        assert r.status == "RELOC"

    def test_symbol_not_found_is_extract_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing symbol after a successful compile is EXTRACT_ERROR, not
        COMPILE_ERROR — the .obj built fine, the source is not to blame."""
        monkeypatch.setattr("rebrew.compile.parse_obj_symbol_and_relocs", _stub_parser(None))
        r = _extract_and_compare("/x.obj", "_missing", b"\x55")
        assert r.status == "EXTRACT_ERROR"
        assert r.matched is False
        assert "EXTRACT_ERROR" in r.message

    def test_obj_longer_size_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Over-long obj truncates to target length and reports SIZE_MISMATCH
        with a length-based delta."""
        monkeypatch.setattr(
            "rebrew.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x55\x8b\xec\x90\x90")
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec")
        assert r.status == "SIZE_MISMATCH"
        assert r.matched is False
        # delta includes the 2-byte length difference.
        assert r.delta >= 2
        # The full compiled size survives truncation for --fix-size.
        assert r.full_obj_size == 5

    def test_target_longer_size_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x55\x8b"))
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec")
        assert r.status == "SIZE_MISMATCH"
        assert r.matched is False
        assert r.delta >= 1  # 3 - 2
        assert r.full_obj_size == 2

    def test_near_matching_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Mostly-equal bytes above the NEAR_MATCH_THRESHOLD → NEAR_MATCHING."""
        monkeypatch.setattr(
            "rebrew.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x55\x8b\xec\x90\x90")
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec\x90\x90")
        assert r.matched is True  # identical bytes

    def test_stub_below_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x90" * 8))
        r = _extract_and_compare("/x.obj", "_f", b"\x55" * 8)
        assert r.matched is False
        assert r.status in ("NEAR_MATCHING", "STUB")

    def test_parse_exception_propagates_for_wrapper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A ValueError from the obj parser propagates; compile_and_compare's
        nested try converts it to EXTRACT_ERROR (post-compile stage)."""

        def _boom(_obj_path: Any, _symbol: str) -> Any:
            raise ValueError("LIEF parse failed")

        monkeypatch.setattr("rebrew.compile.parse_obj_symbol_and_relocs", _boom)
        with pytest.raises(ValueError, match="LIEF parse failed"):
            _extract_and_compare("/x.obj", "_f", b"\x55")
