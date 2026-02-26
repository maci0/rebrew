"""Tests for rebrew guardrails and data consistency improvements.

Covers: parser consolidation, CFLAGS validation, safe file write-back,
        name sanitization, and duplicate VA detection.
"""

import re
from pathlib import Path

from rebrew.annotation import make_func_entry, parse_c_file, parse_source_metadata
from rebrew.naming import sanitize_name
from rebrew.test import smart_reloc_compare, update_source_status

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_HEADER = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _bit_reverse

int __cdecl bit_reverse(int x)
{
    return x;
}
"""

STUB_HEADER = """\
// FUNCTION: SERVER 0x10008880
// STATUS: STUB
// BLOCKER: initial decompilation
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _bit_reverse

int __cdecl bit_reverse(int x)
{
    return 0;
}
"""


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# 1. Parser consolidation
# ---------------------------------------------------------------------------


class TestParserConsolidation:
    """Verify parse_source_metadata delegates to parse_c_file."""

    def test_status_matches(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = parse_source_metadata(str(p))
        assert meta["STATUS"] == "EXACT"

    def test_cflags_matches(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = parse_source_metadata(str(p))
        assert meta["CFLAGS"] == "/O2 /Gd"

    def test_symbol_matches(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = parse_source_metadata(str(p))
        assert meta["SYMBOL"] == "_bit_reverse"

    def test_size_is_string(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = parse_source_metadata(str(p))
        assert meta["SIZE"] == "31"

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "empty.c", "")
        meta = parse_source_metadata(str(p))
        assert meta == {}

    def test_marker_type_present(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        meta = parse_source_metadata(str(p))
        assert "FUNCTION" in meta

    def test_blocker_present(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "stub.c", STUB_HEADER)
        meta = parse_source_metadata(str(p))
        assert "BLOCKER" in meta
        assert "initial" in meta["BLOCKER"]


# ---------------------------------------------------------------------------
# 2. CFLAGS format validation
# ---------------------------------------------------------------------------


class TestCflagsValidation:
    """Verify CFLAGS format checks in Annotation.validate()."""

    def test_valid_cflags_no_warning(self) -> None:
        a = make_func_entry(
            va=0x10001000,
            marker_type="FUNCTION",
            status="STUB",
            origin="GAME",
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
        a = make_func_entry(
            va=0x10001000,
            marker_type="FUNCTION",
            status="STUB",
            origin="GAME",
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
        a = make_func_entry(
            va=0x10001000,
            marker_type="FUNCTION",
            status="STUB",
            origin="GAME",
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
    """Verify update_source_status creates backup and validates."""

    def test_status_updated(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        update_source_status(str(p), "RELOC")
        text = p.read_text(encoding="utf-8")
        assert "STATUS: RELOC" in text

    def test_backup_created(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        update_source_status(str(p), "RELOC")
        bak = tmp_path / "func.c.bak"
        assert bak.exists()
        # Backup should contain original status
        assert "STATUS: EXACT" in bak.read_text(encoding="utf-8")

    def test_reparseable_after_update(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        update_source_status(str(p), "RELOC")
        anno = parse_c_file(p)
        assert anno is not None
        assert anno.status == "RELOC"

    def test_blocker_removed(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "stub.c", STUB_HEADER)
        update_source_status(str(p), "RELOC", blockers_to_remove=True)
        text = p.read_text(encoding="utf-8")
        assert "BLOCKER" not in text

    def test_target_va_updates_only_matching_block(self, tmp_path: Path) -> None:
        """Multi-function file: target_va should only update that block's STATUS."""
        multi = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// BLOCKER: initial decompilation\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 32\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_a\n"
            "void _func_a(void) {}\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: STUB\n"
            "// BLOCKER: dependency\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_b\n"
            "void _func_b(void) {}\n"
        )
        p = _write_c(tmp_path, "multi.c", multi)
        update_source_status(str(p), "RELOC", target_va=0x10001000)
        text = p.read_text(encoding="utf-8")
        # First block should be updated
        assert "// STATUS: RELOC" in text
        # Second block should remain STUB
        lines = text.splitlines()
        second_status = [line for line in lines if "STATUS:" in line][1]
        assert "STUB" in second_status
        # Only the first blocker should be removed
        assert "BLOCKER: dependency" in text

    def test_target_va_none_updates_all(self, tmp_path: Path) -> None:
        """Without target_va, all STATUS lines should be updated."""
        multi = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 32\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_a\n"
            "void _func_a(void) {}\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_b\n"
            "void _func_b(void) {}\n"
        )
        p = _write_c(tmp_path, "multi.c", multi)
        update_source_status(str(p), "EXACT")
        text = p.read_text(encoding="utf-8")
        status_lines = [line for line in text.splitlines() if "STATUS:" in line]
        assert all("EXACT" in s for s in status_lines)


# ---------------------------------------------------------------------------
# 3b. smart_reloc_compare
# ---------------------------------------------------------------------------


class TestSmartRelocCompare:
    """Tests for the relocation-aware byte comparison."""

    def test_identical_bytes(self) -> None:
        data = b"\x55\x8b\xec\x83\xec\x10"
        match, count, maxlen, relocs = smart_reloc_compare(data, data)
        assert match is True
        assert count == len(data)
        assert maxlen == len(data)
        assert relocs == []

    def test_different_bytes_no_reloc(self) -> None:
        obj = b"\x55\x8b\xec\x83\xec\x10"
        tgt = b"\x55\x8b\xec\x83\xec\x20"
        match, count, maxlen, mismatches = smart_reloc_compare(obj, tgt)
        assert match is False
        assert count == 5  # 5 matching, 1 mismatch

    def test_zero_span_detected_as_reloc(self) -> None:
        """Fallback: 4-byte zero span in obj that differs in target → reloc."""
        obj = b"\x55\x00\x00\x00\x00\xc3"
        tgt = b"\x55\x78\x56\x34\x12\xc3"
        match, count, maxlen, relocs = smart_reloc_compare(obj, tgt)
        assert match is True  # relocs mask the difference
        assert len(relocs) == 1
        assert relocs[0] == 1

    def test_explicit_coff_relocs(self) -> None:
        """When COFF relocs are provided, use them instead of zero-span."""
        obj = b"\xe8\xab\xcd\xef\x01\xc3"
        tgt = b"\xe8\x12\x34\x56\x78\xc3"
        match, count, maxlen, relocs = smart_reloc_compare(obj, tgt, coff_relocs=[1])
        assert match is True
        assert 1 in relocs

    def test_length_mismatch(self) -> None:
        obj = b"\x55\x8b\xec"
        tgt = b"\x55\x8b\xec\x83"
        match, count, maxlen, _ = smart_reloc_compare(obj, tgt)
        assert match is False  # different lengths
        assert maxlen == 4

    def test_coff_reloc_beyond_min_len_ignored(self) -> None:
        """COFF relocs past the shorter buffer should be filtered out."""
        obj = b"\x55\x8b"
        tgt = b"\x55\x8b\xec\x83"
        _, _, _, relocs = smart_reloc_compare(obj, tgt, coff_relocs=[10])
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
        long_name = "a" * 100
        result = sanitize_name(long_name)
        assert len(result) <= 64

    def test_empty_name_returns_unnamed(self) -> None:
        result = sanitize_name("!!!")
        assert result == "unnamed"


# ---------------------------------------------------------------------------
# 5. Duplicate VA detection (integration-style)
# ---------------------------------------------------------------------------


class TestDuplicateVADetection:
    """Verify find_all_stubs detects duplicate VAs."""

    def test_duplicate_va_deduped(self, tmp_path: Path, capsys) -> None:
        # Create two STUB files with the same VA
        for name in ("func_a.c", "func_b.c"):
            (tmp_path / name).write_text(STUB_HEADER, encoding="utf-8")

        from rebrew.ga import find_all_stubs

        stubs = find_all_stubs(tmp_path)
        # Should only keep one
        assert len(stubs) == 1

        captured = capsys.readouterr()
        assert "Duplicate VA" in captured.out

    def test_different_vas_both_kept(self, tmp_path: Path) -> None:
        header_a = STUB_HEADER
        header_b = STUB_HEADER.replace("0x10008880", "0x10009990")

        (tmp_path / "func_a.c").write_text(header_a, encoding="utf-8")
        (tmp_path / "func_b.c").write_text(header_b, encoding="utf-8")

        from rebrew.ga import find_all_stubs

        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 2
