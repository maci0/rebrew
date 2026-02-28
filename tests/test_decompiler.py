"""Tests for rebrew.decompiler backend dispatch and helpers."""

import subprocess
from pathlib import Path
from unittest.mock import patch

from rebrew.config import ProjectConfig
from rebrew.decompiler import (
    _BACKEND_MAP,
    BACKENDS,
    _clean_output,
    _find_re_tool,
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
    def test_r2ghidra_no_tool(self, mock_which) -> None:
        result = fetch_r2ghidra(Path("/fake/binary"), 0x1000, Path("/fake"))
        assert result is None

    @patch("rebrew.decompiler.shutil.which", return_value=None)
    def test_r2dec_no_tool(self, mock_which) -> None:
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

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/r2" if x == "r2" else None
    )
    @patch("rebrew.decompiler.subprocess.run")
    def test_r2ghidra_uses_r2(self, mock_run, _mock_which, tmp_path: Path) -> None:
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="int foo() {\n  return 1;\n}\n",
            stderr="",
        )

        result = fetch_r2ghidra(binary, 0x1000, tmp_path)

        assert result == "int foo() {\n  return 1;\n}"
        args, kwargs = mock_run.call_args
        assert args[0][:4] == ["r2", "-q", "-c", "aaa; s 0x00001000; af; pdg"]
        assert args[0][4] == str(binary)
        assert kwargs["cwd"] == tmp_path
        assert kwargs["timeout"] == 120

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/rz" if x == "rz" else None
    )
    @patch("rebrew.decompiler.subprocess.run")
    def test_r2ghidra_uses_rz(self, mock_run, _mock_which, tmp_path: Path) -> None:
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="int bar() {\n  return 2;\n}\n",
            stderr="",
        )

        result = fetch_r2ghidra(binary, 0x1000, tmp_path)

        assert result == "int bar() {\n  return 2;\n}"
        args, _kwargs = mock_run.call_args
        assert args[0][0] == "rz"


class TestFindReTool:
    @patch("rebrew.decompiler.shutil.which", return_value=None)
    def test_neither_installed(self, _mock_which) -> None:
        assert _find_re_tool() is None

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/r2" if x == "r2" else None
    )
    def test_only_r2(self, _mock_which) -> None:
        assert _find_re_tool() == "r2"

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/rz" if x == "rz" else None
    )
    def test_only_rz(self, _mock_which) -> None:
        assert _find_re_tool() == "rz"

    @patch(
        "rebrew.decompiler.shutil.which",
        side_effect=lambda x: f"/usr/bin/{x}" if x in ("rz", "r2") else None,
    )
    def test_both_prefers_rz(self, _mock_which) -> None:
        assert _find_re_tool() == "rz"


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

        cfg = ProjectConfig(root=Path("/fake"))
        cfg.cflags_presets = {"GAME": "/O2 /Gd"}
        cfg.target_binary = Path("/fake/bin")

        result = generate_skeleton(cfg, 0x10001000, 100, "FUN_10001000", "GAME")
        assert "/* TODO:" in result
        assert "Decompilation" not in result

    def test_with_decomp_code(self) -> None:
        """With decomp_code, skeleton embeds the decompilation block."""
        from rebrew.skeleton import generate_skeleton

        cfg = ProjectConfig(root=Path("/fake"))
        cfg.cflags_presets = {"GAME": "/O2 /Gd"}
        cfg.target_binary = Path("/fake/bin")

        result = generate_skeleton(
            cfg,
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

        cfg = ProjectConfig(root=Path("/fake"))
        cfg.cflags_presets = {"MSVCRT": "/O1"}
        cfg.target_binary = Path("/fake/bin")

        result = generate_skeleton(
            cfg,
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
