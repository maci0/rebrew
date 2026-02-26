"""Tests for the rebrew nasm module -- pure-function helpers."""

from pathlib import Path

import pytest

from rebrew.nasm import (
    _build_nasm_lines,
    _parse_annotations,
    capstone_to_nasm,
    extract_from_bin,
    verify_roundtrip,
)

# ---------------------------------------------------------------------------
# capstone_to_nasm
# ---------------------------------------------------------------------------


class TestCapstoneToNasm:
    """Tests for capstone_to_nasm() syntax conversion."""

    def test_strips_ptr(self) -> None:
        """Removes 'ptr ' from operand strings."""
        result = capstone_to_nasm("mov", "dword ptr [eax]")
        assert "ptr" not in result
        assert "dword" in result
        assert "[eax]" in result

    def test_mnemonic_only(self) -> None:
        """Instructions with no operands return just the mnemonic."""
        result = capstone_to_nasm("ret", "")
        assert result == "ret"

    def test_preserves_registers(self) -> None:
        """Register-only operands pass through."""
        result = capstone_to_nasm("mov", "eax, ebx")
        assert result == "mov eax, ebx"

    def test_immediate_operand(self) -> None:
        result = capstone_to_nasm("push", "0x42")
        assert result == "push 0x42"

    def test_byte_ptr_stripped(self) -> None:
        result = capstone_to_nasm("mov", "byte ptr [ecx]")
        assert result == "mov byte [ecx]"


# ---------------------------------------------------------------------------
# extract_from_bin
# ---------------------------------------------------------------------------


class TestExtractFromBin:
    """Tests for extract_from_bin() file reading."""

    def test_reads_file(self, tmp_path: Path) -> None:
        """Reads raw bytes from a .bin file."""
        bin_file = tmp_path / "test.bin"
        bin_file.write_bytes(b"\x55\x8b\xec\xc3")
        result = extract_from_bin(bin_file)
        assert result == b"\x55\x8b\xec\xc3"

    def test_empty_file(self, tmp_path: Path) -> None:
        """Empty file returns empty bytes."""
        bin_file = tmp_path / "empty.bin"
        bin_file.write_bytes(b"")
        result = extract_from_bin(bin_file)
        assert result == b""


# ---------------------------------------------------------------------------
# _build_nasm_lines
# ---------------------------------------------------------------------------


class TestBuildNasmLines:
    """Tests for _build_nasm_lines() NASM source generation."""

    def test_basic_output(self) -> None:
        """Produces bits 32, org, and instruction lines."""
        insn_data = [
            {"addr": 0x1000, "raw": b"\xc3", "nasm": "ret", "offset": 0, "size": 1},
        ]
        lines = _build_nasm_lines(insn_data, 0x1000, None, b"", set())
        text = "\n".join(lines)
        assert "bits 32" in text
        assert "org 0x00001000" in text
        assert "ret" in text

    def test_with_label(self) -> None:
        """When safe_label is provided, it appears as a label line."""
        insn_data = [
            {"addr": 0x1000, "raw": b"\xc3", "nasm": "ret", "offset": 0, "size": 1},
        ]
        lines = _build_nasm_lines(insn_data, 0x1000, "my_func", b"", set())
        text = "\n".join(lines)
        assert "my_func:" in text

    def test_db_fallback(self) -> None:
        """Instructions in db_indices use db directive."""
        insn_data = [
            {"addr": 0x1000, "raw": b"\x8b\xec", "nasm": "mov ebp, esp", "offset": 0, "size": 2},
        ]
        lines = _build_nasm_lines(insn_data, 0x1000, None, b"", {0})
        text = "\n".join(lines)
        assert "db 0x8B, 0xEC" in text

    def test_trailing_data(self) -> None:
        """Trailing bytes after instructions are emitted as db."""
        insn_data = [
            {"addr": 0x1000, "raw": b"\xc3", "nasm": "ret", "offset": 0, "size": 1},
        ]
        lines = _build_nasm_lines(insn_data, 0x1000, None, b"\xcc\xcc", set())
        text = "\n".join(lines)
        assert "trailing data" in text
        assert "0xCC" in text

    def test_no_trailing(self) -> None:
        """No trailing data means no trailing db line."""
        insn_data = [
            {"addr": 0x1000, "raw": b"\xc3", "nasm": "ret", "offset": 0, "size": 1},
        ]
        lines = _build_nasm_lines(insn_data, 0x1000, None, b"", set())
        text = "\n".join(lines)
        assert "trailing" not in text

    def test_empty_insn_data(self) -> None:
        """Empty instruction data still produces header."""
        lines = _build_nasm_lines([], 0x1000, None, b"", set())
        text = "\n".join(lines)
        assert "bits 32" in text
        assert "org" in text


# ---------------------------------------------------------------------------
# _parse_annotations
# ---------------------------------------------------------------------------


class TestParseAnnotations:
    """Tests for _parse_annotations() file parser."""

    def test_parses_valid_file(self, tmp_path: Path) -> None:
        """Parses a well-formed annotated .c file."""
        src = tmp_path / "func.c"
        src.write_text(
            """\
// FUNCTION: SERVER 0x10003da0
// STATUS: RELOC
// ORIGIN: GAME
// SIZE: 77
// CFLAGS: /O2 /Gd
// SYMBOL: _my_func

int my_func(void) { return 0; }
""",
            encoding="utf-8",
        )
        result = _parse_annotations(src)
        assert result is not None
        assert result["va"] == 0x10003DA0
        assert result["size"] == 77
        assert result["symbol"] == "_my_func"
        assert result["status"] == "RELOC"

    def test_returns_none_for_no_annotations(self, tmp_path: Path) -> None:
        """Returns None for a file without annotations."""
        src = tmp_path / "plain.c"
        src.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        result = _parse_annotations(src)
        assert result is None

    def test_returns_none_for_invalid_status(self, tmp_path: Path) -> None:
        """Returns None for files with unrecognized STATUS."""
        src = tmp_path / "bad.c"
        src.write_text(
            """\
// FUNCTION: SERVER 0x10003da0
// STATUS: INVALID_STATUS
// ORIGIN: GAME
// SIZE: 77
// CFLAGS: /O2
// SYMBOL: _f

int f(void) { return 0; }
""",
            encoding="utf-8",
        )
        result = _parse_annotations(src)
        assert result is None

    def test_returns_none_for_missing_size(self, tmp_path: Path) -> None:
        """Returns None when SIZE is missing (0)."""
        src = tmp_path / "nosize.c"
        src.write_text(
            """\
// FUNCTION: SERVER 0x10003da0
// STATUS: STUB
// ORIGIN: GAME
// CFLAGS: /O2
// SYMBOL: _f

int f(void) { return 0; }
""",
            encoding="utf-8",
        )
        result = _parse_annotations(src)
        assert result is None


# ---------------------------------------------------------------------------
# verify_roundtrip (requires nasm binary -- skip if unavailable)
# ---------------------------------------------------------------------------


def _nasm_available() -> bool:
    """Check if nasm is available on PATH."""
    import shutil

    return shutil.which("nasm") is not None


@pytest.mark.skipif(not _nasm_available(), reason="nasm not installed")
class TestVerifyRoundtrip:
    """Tests for verify_roundtrip() -- requires nasm binary."""

    def test_matching_roundtrip(self) -> None:
        """Simple ret instruction round-trips correctly."""
        nasm_src = "bits 32\norg 0x00001000\n\nret\n"
        original = b"\xc3"
        ok, msg = verify_roundtrip(nasm_src, original)
        assert ok is True
        assert "PASS" in msg

    def test_size_mismatch(self) -> None:
        """Size mismatch is detected."""
        nasm_src = "bits 32\norg 0x00001000\n\nnop\nret\n"
        original = b"\xc3"  # just ret, no nop
        ok, msg = verify_roundtrip(nasm_src, original)
        assert ok is False

    def test_invalid_nasm(self) -> None:
        """Invalid NASM source returns failure."""
        ok, msg = verify_roundtrip("this is not valid nasm", b"\xc3")
        assert ok is False
        assert "failed" in msg.lower() or "FAIL" in msg
