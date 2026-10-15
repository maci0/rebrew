"""Tests for rebrew guardrails and data consistency improvements.

Covers: parser consolidation, CFLAGS validation, safe file write-back,
        name sanitization, and duplicate VA detection.
"""

import re
from pathlib import Path

import pytest
from source_util import SourceFixture, write_source

from rebrew.metadata.bindings import (
    make_function_binding,
    read_function_fields,
    read_source_bindings,
)
from rebrew.metadata.functions import get_entry, update_source_status
from rebrew.naming import sanitize_name
from rebrew.test import smart_reloc_compare

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_HEADER = SourceFixture(
    "/* ADDRESS: SERVER 0x10008880 */\n\n\n\n\n\nint __cdecl bit_reverse(int x)\n{\n    return x;\n}\n",
    {"SERVER.0x10008880": {"kind": "FUNCTION", "size": 31, "cflags": "/O2 /Gd", "status": "STUB"}},
)

STUB_HEADER = SourceFixture(
    "/* ADDRESS: SERVER 0x10008880 */\n\n\n\n\n\n\nint __cdecl bit_reverse(int x)\n{\n    return 0;\n}\n",
    {
        "SERVER.0x10008880": {
            "kind": "FUNCTION",
            "blocker": "initial decompilation",
            "size": 31,
            "cflags": "/O2 /Gd",
            "status": "STUB",
        }
    },
)


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    write_source(p, content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# 1. Parser consolidation
# ---------------------------------------------------------------------------


class TestParserConsolidation:
    """Verify read_function_fields delegates to read_source_bindings."""

    def test_status_matches(self, tmp_path: Path) -> None:
        # Volatile keys are metadata-owned: inline STATUS is ignored (STUB default).
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = read_function_fields(str(p), metadata_dir=tmp_path)
        assert meta["STATUS"] == "STUB"

    def test_cflags_matches(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = read_function_fields(str(p), metadata_dir=tmp_path)
        assert meta["CFLAGS"] == "/O2 /Gd"

    def test_symbol_not_in_meta(self, tmp_path: Path) -> None:
        """SYMBOL is no longer emitted — it's derived from C definitions."""
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = read_function_fields(str(p), metadata_dir=tmp_path)
        assert "SYMBOL" not in meta

    def test_size_is_string(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = read_function_fields(str(p), metadata_dir=tmp_path)
        assert meta["SIZE"] == "31"

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "empty.c", "")
        meta = read_function_fields(str(p), metadata_dir=tmp_path)
        assert meta == {}

    def test_kind_present(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = read_function_fields(str(p), metadata_dir=tmp_path)
        assert "FUNCTION" in meta

    def test_blocker_present(self, tmp_path: Path) -> None:
        # Legacy BLOCKER is co-read for migration; a stored value overrides it.
        p = _write_c(tmp_path, "stub.c", STUB_HEADER)
        meta = read_function_fields(str(p), metadata_dir=tmp_path)
        assert meta["BLOCKER"] == "initial decompilation"


# ---------------------------------------------------------------------------
# 2. CFLAGS format validation
# ---------------------------------------------------------------------------


class TestCflagsValidation:
    """Verify CFLAGS format checks in SourceBinding.validate()."""

    def test_valid_cflags_no_warning(self) -> None:
        a = make_function_binding(
            va=0x10001000,
            kind="FUNCTION",
            status="STUB",
            size=32,
            cflags="/O2 /Gd",
            symbol="_foo",
            blocker="test",
            name="foo",
            filepath="foo.c",
        )
        _, warnings = a.validate()
        cflags_warnings = [w for w in warnings if "CFLAGS" in w]
        assert cflags_warnings == []

    def test_missing_slash_warns(self) -> None:
        a = make_function_binding(
            va=0x10001000,
            kind="FUNCTION",
            status="STUB",
            size=32,
            cflags="O2 Gd",
            symbol="_foo",
            blocker="test",
            name="foo",
            filepath="foo.c",
        )
        _, warnings = a.validate()
        assert any("doesn't start with '/'" in w for w in warnings)

    def test_glued_flags_warns(self) -> None:
        a = make_function_binding(
            va=0x10001000,
            kind="FUNCTION",
            status="STUB",
            size=32,
            cflags="/O2/Gd",
            symbol="_foo",
            blocker="test",
            name="foo",
            filepath="foo.c",
        )
        _, warnings = a.validate()
        assert any("glued together" in w for w in warnings)


# ---------------------------------------------------------------------------
# 3. Safe file write-back
# ---------------------------------------------------------------------------


class TestSafeWriteBack:
    """Verify update_source_status writes to metadata and leaves .c untouched."""

    def test_status_updated(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        update_source_status(tmp_path, "RELOC", "SERVER", 0x10008880)
        # .c file must be untouched
        assert "STATUS:" not in p.read_text(encoding="utf-8")
        assert get_entry(tmp_path, 0x10008880, "SERVER")["status"] == "RELOC"
        # Metadata has new status
        entry = get_entry(tmp_path, 0x10008880, module="SERVER")
        assert entry["status"] == "RELOC"

    def test_backup_created(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "func.c", VALID_HEADER)
        update_source_status(tmp_path, "RELOC", "SERVER", 0x10008880)
        # No .bak file created — status lives in metadata, not file
        bak = tmp_path / "func.c.bak"
        assert not bak.exists()

    def test_reparseable_after_update(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        update_source_status(tmp_path, "RELOC", "SERVER", 0x10008880)
        # Read with metadata_dir to see new status
        anns = read_source_bindings(p, metadata_dir=tmp_path)
        assert anns
        assert anns[0].status == "RELOC"

    def test_blocker_removed(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "stub.c", STUB_HEADER)
        # Pre-populate metadata with BLOCKER
        from rebrew.metadata.functions import update_field

        update_field(tmp_path, 0x10008880, "blocker", "initial decompilation", module="SERVER")
        update_source_status(tmp_path, "RELOC", "SERVER", 0x10008880, clear_blockers=True)
        # Blocker gone from metadata
        entry = get_entry(tmp_path, 0x10008880, module="SERVER")
        assert not entry.get("blocker")
        # .c file still has the inline BLOCKER comment (not touched)
        assert "BLOCKER:" not in p.read_text(encoding="utf-8")

    def test_target_va_updates_only_matching_block(self, tmp_path: Path) -> None:
        """Multi-function file: target_va should only update that block's metadata entry."""
        multi = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\n\nvoid _func_a(void) {}\n\n/* ADDRESS: SERVER 0x10002000 */\n\nvoid _func_b(void) {}\n",
            {
                "SERVER.0x10001000": {"kind": "FUNCTION", "symbol": "_func_a"},
                "SERVER.0x10002000": {"kind": "FUNCTION", "symbol": "_func_b"},
            },
        )
        p = _write_c(tmp_path, "multi.c", multi)
        update_source_status(tmp_path, "RELOC", "SERVER", 0x10001000)
        # First VA updated in metadata
        entry1 = get_entry(tmp_path, 0x10001000, module="SERVER")
        assert entry1["status"] == "RELOC"
        # Second VA NOT in metadata (untouched)
        entry2 = get_entry(tmp_path, 0x10002000, module="SERVER")
        assert entry2["status"] == "STUB"
        # .c file untouched
        assert p.read_text(encoding="utf-8") == multi

    def test_target_va_none_updates_all(self, tmp_path: Path) -> None:
        """Without target_va, the first annotation block's VA is used."""
        multi = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\n\nvoid _func_a(void) {}\n\n/* ADDRESS: SERVER 0x10002000 */\n\nvoid _func_b(void) {}\n",
            {
                "SERVER.0x10001000": {"kind": "FUNCTION", "symbol": "_func_a"},
                "SERVER.0x10002000": {"kind": "FUNCTION", "symbol": "_func_b"},
            },
        )
        _write_c(tmp_path, "multi.c", multi)
        update_source_status(tmp_path, "EXACT", "SERVER", 0x10001000)
        # Only first VA updated (update_source_status resolves first VA when target_va=None)
        entry1 = get_entry(tmp_path, 0x10001000, module="SERVER")
        assert entry1["status"] == "EXACT"


# ---------------------------------------------------------------------------
# 3b. smart_reloc_compare
# ---------------------------------------------------------------------------


class TestSmartRelocCompare:
    """Tests for the relocation-aware byte comparison."""

    def test_identical_bytes(self) -> None:
        data = b"\x55\x8b\xec\x83\xec\x10"
        match, count, maxlen, relocs, _ = smart_reloc_compare(data, data)
        assert match is True
        assert count == len(data)
        assert maxlen == len(data)
        assert relocs == []

    def test_different_bytes_no_reloc(self) -> None:
        obj = b"\x55\x8b\xec\x83\xec\x10"
        tgt = b"\x55\x8b\xec\x83\xec\x20"
        match, count, maxlen, mismatches, _ = smart_reloc_compare(obj, tgt)
        assert match is False
        assert count == 5  # 5 matching, 1 mismatch

    def test_zero_span_detected_as_reloc(self) -> None:
        """Fallback: aligned 4-byte zero span in obj that differs in target → reloc."""
        obj = b"\x55\x90\x90\x90\x00\x00\x00\x00\xc3"
        tgt = b"\x55\x90\x90\x90\x78\x56\x34\x12\xc3"
        match, count, maxlen, relocs, _ = smart_reloc_compare(obj, tgt)
        assert match is True  # relocs mask the difference
        assert len(relocs) == 1
        assert relocs[0] == 4

    def test_zero_span_unaligned_not_masked(self) -> None:
        """An unaligned zero dword is coincidental data, not a reloc slot."""
        obj = b"\x55\x00\x00\x00\x00\xc3"
        tgt = b"\x55\x78\x56\x34\x12\xc3"
        match, count, maxlen, relocs, _ = smart_reloc_compare(obj, tgt)
        assert match is False
        assert relocs == []

    def test_explicit_coff_relocs(self) -> None:
        """When COFF relocs are provided, use them instead of zero-span."""
        obj = b"\xe8\xab\xcd\xef\x01\xc3"
        tgt = b"\xe8\x12\x34\x56\x78\xc3"
        match, count, maxlen, relocs, _ = smart_reloc_compare(obj, tgt, coff_relocs=[1])
        assert match is True
        assert 1 in relocs

    def test_length_mismatch(self) -> None:
        obj = b"\x55\x8b\xec"
        tgt = b"\x55\x8b\xec\x83"
        match, count, maxlen, _, _ = smart_reloc_compare(obj, tgt)
        assert match is False  # different lengths
        assert maxlen == 4

    def test_coff_reloc_beyond_min_len_ignored(self) -> None:
        """COFF relocs past the shorter buffer should be filtered out."""
        obj = b"\x55\x8b"
        tgt = b"\x55\x8b\xec\x83"
        _, _, _, relocs, _ = smart_reloc_compare(obj, tgt, coff_relocs=[10])
        assert relocs == []


# ---------------------------------------------------------------------------
# 4. Skeleton name sanitization
# ---------------------------------------------------------------------------


class TestSanitizeName:
    """Verify sanitize_name produces valid C identifiers."""

    def test_fun_prefix_stripped(self) -> None:
        assert sanitize_name("FUN_10003da0") == "func_10003da0"

    def test_special_chars_cleaned(self) -> None:
        result = sanitize_name("game::init_player")
        assert re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", result)

    def test_no_leading_digit(self) -> None:
        result = sanitize_name("3DOBJ_init")
        assert not result[0].isdigit()

    def test_consecutive_underscores_collapsed(self) -> None:
        result = sanitize_name("foo__bar___baz")
        assert "__" not in result

    def test_max_length_64(self) -> None:
        result = sanitize_name("a" * 100)
        assert result == "a" * 64

    def test_empty_name_returns_unnamed(self) -> None:
        result = sanitize_name("!!!")
        assert result == "unnamed"


# ---------------------------------------------------------------------------
# 5. Duplicate VA detection (integration-style)
# ---------------------------------------------------------------------------


class TestDuplicateVADetection:
    """Verify find_all_stubs detects duplicate VAs."""

    def test_duplicate_va_rejected(self, tmp_path: Path) -> None:
        # Create two STUB files with the same VA
        for name in ("func_a.c", "func_b.c"):
            write_source(tmp_path / name, STUB_HEADER, encoding="utf-8")

        from rebrew.match_batch import find_all_stubs

        with pytest.raises(ValueError, match="address anchor conflicts"):
            find_all_stubs(tmp_path)

    def test_different_vas_both_kept(self, tmp_path: Path) -> None:
        header_a = STUB_HEADER
        header_b = STUB_HEADER.replace("0x10008880", "0x10009990")

        write_source(tmp_path / "func_a.c", header_a, encoding="utf-8")
        write_source(tmp_path / "func_b.c", header_b, encoding="utf-8")

        from rebrew.match_batch import find_all_stubs

        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 2
