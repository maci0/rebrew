"""Tests for rebrew.decompiler backend dispatch and helpers."""

from pathlib import Path
from unittest.mock import patch

from rebrew.decompiler import (
    _BACKEND_MAP,
    BACKENDS,
    _clean_output,
    _strip_ansi,
    fetch_decompilation,
    fetch_ghidra,
    fetch_r2dec,
    fetch_r2ghidra,
)


class TestStripAnsi:
    def test_basic_escape(self) -> None:
        assert _strip_ansi("\x1b[31mhello\x1b[0m") == "hello"

    def test_no_escape(self) -> None:
        assert _strip_ansi("plain text") == "plain text"

    def test_multiple_escapes(self) -> None:
        assert _strip_ansi("\x1b[1m\x1b[32mint\x1b[0m x;") == "int x;"


class TestCleanOutput:
    def test_strips_and_trims(self) -> None:
        text = "\n\n\x1b[32mint main() {\x1b[0m\n  return 0;\n}\n\n"
        assert _clean_output(text) == "int main() {\n  return 0;\n}"

    def test_empty_input(self) -> None:
        assert _clean_output("") is None

    def test_only_whitespace(self) -> None:
        assert _clean_output("\n  \n  \n") is None


class TestBackendDispatch:
    def test_backends_list(self) -> None:
        assert "r2ghidra" in BACKENDS
        assert "r2dec" in BACKENDS
        # ghidra backend excluded from auto-probe (not yet implemented)
        assert "ghidra" not in BACKENDS
        assert "ghidra" in _BACKEND_MAP  # still registered for explicit use

    @patch("rebrew.decompiler.shutil.which", return_value=None)
    def test_r2ghidra_no_r2(self, mock_which) -> None:
        result = fetch_r2ghidra(Path("/fake/binary"), 0x1000, Path("/fake"))
        assert result is None

    @patch("rebrew.decompiler.shutil.which", return_value=None)
    def test_r2dec_no_r2(self, mock_which) -> None:
        result = fetch_r2dec(Path("/fake/binary"), 0x1000, Path("/fake"))
        assert result is None

    def test_ghidra_stub(self, capsys) -> None:
        result = fetch_ghidra(Path("/fake/binary"), 0x1000, Path("/fake"))
        assert result is None
        captured = capsys.readouterr()
        assert "not yet implemented" in captured.err

    def test_unknown_backend(self, capsys) -> None:
        code, name = fetch_decompilation("nonexistent", Path("/f"), 0x1000, Path("/f"))
        assert code is None
        assert name == "nonexistent"
        captured = capsys.readouterr()
        assert "unknown backend" in captured.err


class TestAutoFallback:
    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: None, "r2dec": lambda *a: None, "ghidra": lambda *a: None},
    )
    def test_all_fail(self) -> None:
        code, name = fetch_decompilation("auto", Path("/f"), 0x1000, Path("/f"))
        assert code is None
        assert name == "auto"

    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: None, "r2dec": lambda *a: "int x;", "ghidra": lambda *a: None},
    )
    def test_r2dec_fallback(self) -> None:
        code, name = fetch_decompilation("auto", Path("/f"), 0x1000, Path("/f"))
        assert code == "int x;"
        assert name == "r2dec"

    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: "void f() {}", "r2dec": lambda *a: None, "ghidra": lambda *a: None},
    )
    def test_r2ghidra_first(self) -> None:
        code, name = fetch_decompilation("auto", Path("/f"), 0x1000, Path("/f"))
        assert code == "void f() {}"
        assert name == "r2ghidra"

    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: "void f() {}"},
    )
    def test_explicit_backend(self) -> None:
        code, name = fetch_decompilation("r2ghidra", Path("/f"), 0x1000, Path("/f"))
        assert code == "void f() {}"
        assert name == "r2ghidra"


class TestGenerateSkeletonWithDecomp:
    """Test that generate_skeleton embeds decompilation correctly."""

    def test_no_decomp_default(self) -> None:
        """Without decomp_code, skeleton has TODO placeholder."""
        from rebrew.skeleton import generate_skeleton

        class FakeCfg:
            marker = "SERVER"
            cflags_presets = {"GAME": "/O2 /Gd"}
            root = Path("/fake")
            target_binary = Path("/fake/bin")
            library_origins = []
            origin_todos = {}
            origin_comments = {}

        result = generate_skeleton(FakeCfg(), 0x10001000, 100, "FUN_10001000", "GAME")
        assert "/* TODO:" in result
        assert "Decompilation" not in result

    def test_with_decomp_code(self) -> None:
        """With decomp_code, skeleton embeds the decompilation block."""
        from rebrew.skeleton import generate_skeleton

        class FakeCfg:
            marker = "SERVER"
            cflags_presets = {"GAME": "/O2 /Gd"}
            root = Path("/fake")
            target_binary = Path("/fake/bin")
            library_origins = []
            origin_todos = {}
            origin_comments = {}

        result = generate_skeleton(
            FakeCfg(),
            0x10001000,
            100,
            "FUN_10001000",
            "GAME",
            decomp_code="int foo() { return 42; }",
            decomp_backend="r2ghidra",
        )
        assert "/* === Decompilation (r2ghidra) === */" in result
        assert "int foo() { return 42; }" in result
        assert "/* === End decompilation === */" in result
        # No TODO placeholder when decomp is present
        assert "/* TODO:" not in result.split("/* === End decompilation === */")[-1]

    def test_msvcrt_with_decomp(self) -> None:
        """MSVCRT origin also embeds decompilation."""
        from rebrew.skeleton import generate_skeleton

        class FakeCfg:
            marker = "SERVER"
            cflags_presets = {"MSVCRT": "/O1"}
            root = Path("/fake")
            target_binary = Path("/fake/bin")
            library_origins = []
            origin_todos = {}
            origin_comments = {}

        result = generate_skeleton(
            FakeCfg(),
            0x1001E000,
            50,
            "crt_init",
            "MSVCRT",
            decomp_code="void crt_init() {}",
            decomp_backend="r2dec",
        )
        assert "CRT function" in result
        assert "/* === Decompilation (r2dec) === */" in result
        assert "void crt_init() {}" in result
