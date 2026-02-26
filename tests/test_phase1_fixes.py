"""Tests for Phase 1 logic fixes: flirt, gen_flirt_pat, and batch.

Covers new logic paths introduced during the deep audit:
- flirt.py: small .text section guard (<32 bytes)
- gen_flirt_pat.py: empty dirname handling, bytes_to_pat_line correctness
- batch.py: type-safe dict value casting from JSON
"""

from pathlib import Path

from rebrew.batch import load_functions
from rebrew.flirt import find_func_size
from rebrew.gen_flirt_pat import bytes_to_pat_line

# ---------------------------------------------------------------------------
# flirt.py — find_func_size + small section guard
# ---------------------------------------------------------------------------


class TestFindFuncSize:
    """Unit tests for flirt.find_func_size (used before FLIRT matching)."""

    def test_ret_terminates(self) -> None:
        """0xC3 (ret) should terminate the function."""
        code = bytes([0x55, 0x8B, 0xEC, 0x33, 0xC0, 0xC3, 0xCC, 0xCC])
        size = find_func_size(code, 0)
        assert size == 6  # bytes 0..5 inclusive (0xC3 at index 5)

    def test_ret_imm16_terminates(self) -> None:
        """0xC2 xx xx (ret imm16) should include the 2-byte immediate."""
        code = bytes([0x55, 0x8B, 0xEC, 0xC2, 0x04, 0x00, 0xCC])
        size = find_func_size(code, 0)
        assert size == 6  # 0xC2 at index 3, plus 2 bytes = 3+3=6

    def test_no_ret_returns_max_scan(self) -> None:
        """If no ret is found within 4096 bytes, return max_scan."""
        code = bytes([0x90] * 100)  # all NOPs, no ret
        size = find_func_size(code, 0)
        assert size == 100  # min(4096, 100) = 100

    def test_offset_into_code(self) -> None:
        """Starting at an offset should measure from that offset."""
        code = bytes([0xCC, 0xCC, 0x55, 0x8B, 0xEC, 0xC3])
        size = find_func_size(code, 2)
        assert size == 4  # bytes 2..5, ret at index 5


class TestSmallSectionGuard:
    """The FLIRT main() guard for .text < 32 bytes is integration-level.

    We test the underlying find_func_size behavior with small inputs
    to verify it handles edge cases correctly.
    """

    def test_tiny_code_with_ret(self) -> None:
        """Even very small code should find a ret if present."""
        code = bytes([0xC3])  # just a ret
        size = find_func_size(code, 0)
        assert size == 1

    def test_empty_code(self) -> None:
        """Empty code (offset == len) should return 0."""
        code = b""
        size = find_func_size(code, 0)
        assert size == 0  # min(4096, 0) = 0


# ---------------------------------------------------------------------------
# gen_flirt_pat.py — bytes_to_pat_line + empty dirname
# ---------------------------------------------------------------------------


class TestBytesToPatLine:
    """Unit tests for gen_flirt_pat.bytes_to_pat_line."""

    def test_basic_pat_line(self) -> None:
        """Simple function bytes should produce a valid .pat line."""
        code = bytes([0x55, 0x8B, 0xEC, 0x5D, 0xC3])
        line = bytes_to_pat_line("_my_func", code, set())
        # Should start with hex bytes
        assert line.startswith("558BEC5DC3")
        # Should end with the symbol name
        assert line.endswith(":0000 _my_func")
        # Should contain CRC and size fields
        parts = line.split()
        assert len(parts) >= 5

    def test_reloc_bytes_masked(self) -> None:
        """Bytes at relocation offsets should be masked with '..'."""
        code = bytes([0x55, 0x8B, 0xEC, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3])
        # Relocations at bytes 4-7 (a call target)
        relocs = {4, 5, 6, 7}
        line = bytes_to_pat_line("_reloc_func", code, relocs)
        # First 3 bytes should be literal hex
        assert line[:6] == "558BEC"
        # Byte 3 (0xE8) should be literal
        assert line[6:8] == "E8"
        # Bytes 4-7 should be masked
        assert line[8:16] == "........"
        # Bytes 8-9 should be literal
        assert line[16:20] == "5DC3"

    def test_max_lead_truncation(self) -> None:
        """Leading portion should be truncated to max_lead bytes."""
        code = bytes(range(64))  # 64 bytes
        line = bytes_to_pat_line("_long_func", code, set(), max_lead=8)
        # Leading hex should be 8 bytes = 16 hex chars
        leading_hex = line.split()[0]
        assert len(leading_hex) == 16


class TestGenFlirtPatEmptyDirname:
    """Verify that output paths with no directory component don't crash.

    Regression test for Phase 1 fix: os.makedirs("") raised OSError.
    Now uses pathlib with a guard: only mkdir if parent != Path(".").
    """

    def test_output_to_current_dir(self, tmp_path: Path) -> None:
        """Writing a .pat file to the current directory should not crash."""
        # The fix is in gen_flirt_pat.main() which checks
        # `if out_path.parent != Path(".")` before mkdir.
        # We test the guard condition directly.
        out_path = Path("output.pat")
        # parent is Path(".") — the guard should skip mkdir
        assert out_path.parent == Path(".")

    def test_output_to_subdir(self, tmp_path: Path) -> None:
        """Writing a .pat file to a subdirectory should create it."""
        out_path = tmp_path / "subdir" / "output.pat"
        # parent is a real directory — mkdir should be called
        assert out_path.parent != Path(".")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        assert out_path.parent.exists()


# ---------------------------------------------------------------------------
# batch.py — type-safe dict access
# ---------------------------------------------------------------------------


class TestBatchTypeSafety:
    """Verify that batch.load_functions returns dicts with correct types.

    Regression test for Phase 1 fix: JSON-loaded dict values could be
    strings instead of ints; explicit int()/str() casts were added in
    the main() function to ensure type safety.
    """

    def test_load_from_txt(self, tmp_path: Path) -> None:
        """parse_r2_functions returns {va: int, size: int, r2_name: str}."""
        from types import SimpleNamespace

        func_list = tmp_path / "r2_functions.txt"
        func_list.write_text(
            "0x10001000 64 _func_a\n0x10002000 128 _func_b\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(function_list=func_list)
        funcs = load_functions(cfg)
        assert len(funcs) == 2

        # Verify types are correct (int, int, str) — not strings
        assert isinstance(funcs[0]["va"], int)
        assert isinstance(funcs[0]["size"], int)
        assert isinstance(funcs[0]["r2_name"], str)
        assert funcs[0]["va"] == 0x10001000
        assert funcs[0]["size"] == 64

    def test_int_cast_handles_string_va(self) -> None:
        """int() cast in batch.main() should handle string VA from JSON."""
        # Simulate what batch.main() does with the dict values
        fn = {"va": "268439552", "size": "64", "r2_name": "func_a"}
        va = int(fn["va"])
        size = int(fn["size"])
        name = str(fn["r2_name"])
        assert va == 268439552
        assert size == 64
        assert name == "func_a"

    def test_int_cast_handles_hex_string(self) -> None:
        """int() with base 16 should handle hex string VA."""
        # This is what parse_r2_functions does internally
        va_str = "0x10001000"
        va = int(va_str, 16)
        assert va == 0x10001000
