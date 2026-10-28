"""Tests for compiler/compile.py _extract_and_compare — the post-compile compare stage.

_exctract_and_compare is the shared compile→extract→compare pipeline used by
rebrew test / verify / diff.  These tests exercise the truncation,
classification and error-labeling logic with a monkeypatched
parse_obj_symbol_and_relocs — no MSVC/Wine required.
"""

from __future__ import annotations

from typing import Any

import pytest

from rebrew.compiler.compile import _extract_and_compare
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


def test_decorated_symbol_falls_back_to_the_undecorated_spelling(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stored stdcall spelling must not turn a cdecl/naked body into EXTRACT_ERROR.

    The store can keep ``_fcn_005ef2e0@20`` from an old linker error while the
    reconstructed definition compiles as ``_fcn_005ef2e0``. Verify reported
    EXTRACT_ERROR for eight such rows even though the body bytes matched.
    """
    from rebrew.compiler.compile import _extract_and_compare

    body = b"\x55\x8b\xec\xc3"
    seen: list[str] = []

    def _parse(
        _obj_path: Any, symbol: str
    ) -> tuple[bytes | None, dict[int, str] | None, list[Any]]:
        seen.append(symbol)
        return (body if symbol == "_fcn_005ef2e0" else None), None, []

    monkeypatch.setattr("rebrew.compiler.compile.parse_obj_symbol_and_relocs", _parse)
    result = _extract_and_compare("f.obj", "_fcn_005ef2e0@20", body, check_known_bindings=False)
    assert result.matched, result.message
    assert seen[0] == "_fcn_005ef2e0@20"
    assert "_fcn_005ef2e0" in seen


def test_stored_symbol_can_differ_in_decoration_family(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fastcall body (``@foo@4``) must compare when the store says ``_foo``.

    ``fcn_005efd86`` is a __fastcall body while the stored symbol is the cdecl
    spelling; verify reported EXTRACT_ERROR instead of EXACT.
    """
    from rebrew.compiler.compile import _extract_and_compare

    body = b"\x8b\xc1\xc3"
    seen: list[str] = []

    def _parse(
        _obj_path: Any, symbol: str
    ) -> tuple[bytes | None, dict[int, str] | None, list[Any]]:
        seen.append(symbol)
        return (body if symbol == "@fcn_005efd86@4" else None), None, []

    monkeypatch.setattr("rebrew.compiler.compile.parse_obj_symbol_and_relocs", _parse)
    monkeypatch.setattr(
        "rebrew.matcher.parsers.list_obj_symbols",
        lambda _path: ["@fcn_005efd86@4", "_other"],
    )
    result = _extract_and_compare("f.obj", "_fcn_005efd86", body, check_known_bindings=False)
    assert result.matched, result.message
    assert "@fcn_005efd86@4" in seen


class TestExtractAndCompare:
    @pytest.mark.parametrize("checked", [False, True])
    def test_public_compare_applies_the_targets_binding_policy(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch, checked: bool
    ) -> None:
        from types import SimpleNamespace

        from rebrew.compiler.compile import CompareResult, compile_and_compare
        from rebrew.test import build_result_dict_from_compare

        obj = b"\x90" * 4 + (4).to_bytes(4, "little")
        native = b"\x90" * 4 + (0x1204).to_bytes(4, "little")
        object_path = tmp_path / "f.obj"
        object_path.write_bytes(b"precompiled")
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs",
            _stub_parser(
                obj,
                typed=[CoffRelocRecord(4, 6, "_array")],
            ),
        )
        monkeypatch.setattr("rebrew.compiler.compile.build_iat_region", lambda _cfg: frozenset())
        cfg = SimpleNamespace(check_known_bindings=checked)
        result = compile_and_compare(
            cfg,
            tmp_path / "f.c",
            "_f",
            native,
            "",
            name_to_va={"_array": 0x2200},
            section_va=0x1000,
            _precompiled_obj=str(object_path),
        )
        assert result.matched is not checked
        if checked:
            assert result.relocation_bindings is not None
            assert result.relocation_bindings[0]["status"] == "CONFLICT"
            assert result.relocation_bindings[0]["expected_value"] == 0x2204
            assert result.relocation_bindings[0]["native_value"] == 0x1204
            assert "_array" in result.message
            assert (
                CompareResult.from_dict(result.to_dict()).relocation_bindings
                == result.relocation_bindings
            )
            payload = build_result_dict_from_compare("f.c", "_f", "0x1000", 8, result, native)
            assert payload["relocation_bindings"] == result.relocation_bindings
        else:
            assert "relocation_bindings" not in result.to_dict()

    def test_exact_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x55\x8b\xec")
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec")
        assert r.matched is True
        assert r.status == "EXACT"
        assert r.match_percent == 100.0

    def test_reloc_normalized_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # 8-byte buffers so a reloc at offset 4 (4-byte span) is in-range.
        # The symbol resolves in the VA map, so DIR32 validation passes and
        # the differing slot is masked.
        obj = bytearray(b"\x55\x8b\xec\x90\x00\x00\x00\x00")
        tgt = bytearray(b"\x55\x8b\xec\x90\xaa\xbb\xcc\xdd")
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs",
            _stub_parser(
                bytes(obj),
                typed=[CoffRelocRecord(offset=4, type=0x06, symbol="_other")],
            ),
        )
        monkeypatch.setattr(
            "rebrew.compiler.compile.build_iat_region",
            lambda cfg: set(),
        )
        import struct

        from rebrew.coff_reloc import smart_reloc_compare

        matched, _, _, valid, invalid = smart_reloc_compare(
            bytes(obj),
            bytes(tgt),
            [CoffRelocRecord(offset=4, type=0x06, symbol="_other")],
            name_to_va={"_other": struct.unpack("<I", bytes(tgt[4:8]))[0]},
        )
        assert matched is True
        assert valid == [4]
        assert invalid == []
        # Typed reloc records are preferred; the differing slot is masked.
        r = _extract_and_compare(
            "/x.obj",
            "_f",
            bytes(tgt),
            name_to_va={"_other": struct.unpack("<I", bytes(tgt[4:8]))[0]},
        )
        assert r.matched is True
        assert r.status == "RELOC"

    def test_symbol_not_found_is_extract_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing symbol after a successful compile is EXTRACT_ERROR, not
        COMPILE_ERROR — the .obj built fine, the source is not to blame."""
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs", _stub_parser(None)
        )
        r = _extract_and_compare("/x.obj", "_missing", b"\x55")
        assert r.status == "EXTRACT_ERROR"
        assert r.matched is False
        assert "EXTRACT_ERROR" in r.message

    def test_obj_longer_size_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Over-long obj truncates to target length and reports SIZE_MISMATCH
        with a length-based delta."""
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs",
            _stub_parser(b"\x55\x8b\xec\x90\x90"),
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec")
        assert r.status == "SIZE_MISMATCH"
        assert r.matched is False
        # delta is the 2-byte length difference, nothing else.
        assert r.delta == 2
        # The full compiled size survives truncation for --fix-sizes.
        assert r.full_obj_size == 5

    def test_target_longer_size_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x55\x8b")
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec")
        assert r.status == "SIZE_MISMATCH"
        assert r.matched is False
        assert r.delta == 1  # 3 - 2
        assert r.full_obj_size == 2

    @pytest.mark.parametrize(
        ("target_bytes", "obj_bytes"),
        [(b"\x55\x8b\xec", b""), (b"", b"\x55\x8b\xec")],
    )
    def test_empty_common_prefix_preserves_size_delta(
        self, monkeypatch: pytest.MonkeyPatch, target_bytes: bytes, obj_bytes: bytes
    ) -> None:
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs", _stub_parser(obj_bytes)
        )
        result = _extract_and_compare("/x.obj", "_f", target_bytes)
        assert result.status == "SIZE_MISMATCH"
        assert result.matched is False
        assert result.delta == 3
        assert result.match_percent == 0.0
        assert result.full_obj_size == len(obj_bytes)

    def test_near_matching_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Mostly-equal bytes above the NEAR_MATCH_THRESHOLD → NEAR_MATCHING."""
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs",
            _stub_parser(b"\x55\x8b\xec\x90\x41"),
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55\x8b\xec\x90\x90")
        assert r.matched is False
        assert r.match_percent == 80.0
        assert r.status == "NEAR_MATCHING"

    def test_stub_below_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs", _stub_parser(b"\x90" * 8)
        )
        r = _extract_and_compare("/x.obj", "_f", b"\x55" * 8)
        assert r.matched is False
        assert r.match_percent == 0.0
        assert r.status == "STUB"

    def test_parse_exception_propagates_for_wrapper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A ValueError from the obj parser propagates; compile_and_compare's
        nested try converts it to EXTRACT_ERROR (post-compile stage)."""

        def _boom(_obj_path: Any, _symbol: str) -> Any:
            raise ValueError("LIEF parse failed")

        monkeypatch.setattr("rebrew.compiler.compile.parse_obj_symbol_and_relocs", _boom)
        with pytest.raises(ValueError, match="LIEF parse failed"):
            _extract_and_compare("/x.obj", "_f", b"\x55")
