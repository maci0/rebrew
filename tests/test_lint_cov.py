"""Tests for rebrew.lint — lint_file and LintResult."""

from pathlib import Path

from rebrew.config import ProjectConfig
from rebrew.lint import LintResult, lint_file

# -------------------------------------------------------------------------
# LintResult
# -------------------------------------------------------------------------


class TestLintResult:
    def test_empty_passes(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        assert r.passed is True

    def test_error_fails(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.error(1, "E001", "bad thing")
        assert r.passed is False
        assert len(r.errors) == 1

    def test_warning_still_passes(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.warning(1, "W001", "minor thing")
        assert r.passed is True
        assert len(r.warnings) == 1

    def test_to_dict(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.error(1, "E001", "msg")
        r.warning(2, "W001", "msg2")
        d = r.to_dict()
        assert d["file"] == "test.c"
        assert len(d["errors"]) == 1
        assert len(d["warnings"]) == 1

    def test_display_no_crash(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.error(1, "E001", "err")
        r.warning(2, "W001", "warn")
        assert not r.passed
        assert len(r.errors) == 1
        assert len(r.warnings) == 1
        assert r.errors[0][1] == "E001"
        assert r.warnings[0][1] == "W001"
        r.display()  # ensure no exception
        r.display(quiet=True)


# -------------------------------------------------------------------------
# lint_file
# -------------------------------------------------------------------------


def _make_c_file(tmp_path, name="my_func.c", content=None) -> Path:
    if content is None:
        content = (
            "// STUB: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _my_func\n"
            "void __cdecl _my_func(void) {\n"
            "    // stub\n"
            "}\n"
        )
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


class TestLintFile:
    def test_valid_file(self, tmp_path) -> None:
        f = _make_c_file(tmp_path)
        result = lint_file(f)
        assert result.passed is True

    def test_missing_function_annotation(self, tmp_path) -> None:
        f = _make_c_file(tmp_path, content="void f() {}\n")
        result = lint_file(f)
        assert result.passed is False

    def test_invalid_status(self, tmp_path) -> None:
        f = _make_c_file(
            tmp_path,
            content=(
                "// FUNCTION: SERVER 0x10001000\n"
                "// STATUS: INVALID_STATUS\n"
                "// ORIGIN: GAME\n"
                "// SIZE: 64\n"
                "// CFLAGS: /O2 /Gd\n"
                "// SYMBOL: _my_func\n"
                "void __cdecl _my_func(void) {}\n"
            ),
        )
        result = lint_file(f)
        # Invalid status should produce E004
        assert not result.passed
        assert any(c == "E004" for _, c, _ in result.errors)

    def test_missing_symbol(self, tmp_path) -> None:
        f = _make_c_file(
            tmp_path,
            content=(
                "// FUNCTION: SERVER 0x10001000\n"
                "// STATUS: STUB\n"
                "// ORIGIN: GAME\n"
                "// SIZE: 64\n"
                "// CFLAGS: /O2 /Gd\n"
                "void __cdecl _my_func(void) {}\n"
            ),
        )
        result = lint_file(f)
        # Missing SYMBOL should produce W001
        assert any(c == "W001" for _, c, _ in result.warnings)

    def test_missing_size(self, tmp_path) -> None:
        f = _make_c_file(
            tmp_path,
            content=(
                "// FUNCTION: SERVER 0x10001000\n"
                "// STATUS: STUB\n"
                "// ORIGIN: GAME\n"
                "// CFLAGS: /O2 /Gd\n"
                "// SYMBOL: _my_func\n"
                "void __cdecl _my_func(void) {}\n"
            ),
        )
        result = lint_file(f)
        assert not result.passed

    def test_duplicate_va_detection(self, tmp_path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _make_c_file(tmp_path, name="func1.c")
        f2 = _make_c_file(tmp_path, name="func2.c")  # same VA!
        lint_file(f1, seen_vas=seen_vas)
        result2 = lint_file(f2, seen_vas=seen_vas)
        # Second file should get E013 for duplicate VA
        assert any(c == "E013" for _, c, _ in result2.errors)

    def test_with_config(self, tmp_path) -> None:
        cfg = ProjectConfig(
            root=Path("/tmp"),
            origins=["GAME", "MSVCRT"],
            cflags_presets={"GAME": "/O2 /Gd"},
            marker="SERVER",
        )
        f = _make_c_file(tmp_path)
        result = lint_file(f, cfg=cfg)
        assert result.passed

    def test_multiple_functions_in_file(self, tmp_path) -> None:
        f = _make_c_file(
            tmp_path,
            content=(
                "// FUNCTION: SERVER 0x10001000\n"
                "// STATUS: STUB\n"
                "// ORIGIN: GAME\n"
                "// SIZE: 64\n"
                "// CFLAGS: /O2 /Gd\n"
                "// SYMBOL: _func_a\n"
                "void __cdecl _func_a(void) {}\n"
                "\n"
                "// FUNCTION: SERVER 0x10002000\n"
                "// STATUS: STUB\n"
                "// ORIGIN: GAME\n"
                "// SIZE: 128\n"
                "// CFLAGS: /O2 /Gd\n"
                "// SYMBOL: _func_b\n"
                "void __cdecl _func_b(void) {}\n"
            ),
        )
        result = lint_file(f)
        # Multi-function file should parse both annotations without crash
        assert isinstance(result, LintResult)

    def test_empty_file(self, tmp_path) -> None:
        f = _make_c_file(tmp_path, content="")
        result = lint_file(f)
        assert not result.passed

    def test_bad_cflags(self, tmp_path) -> None:
        f = _make_c_file(
            tmp_path,
            content=(
                "// FUNCTION: SERVER 0x10001000\n"
                "// STATUS: STUB\n"
                "// ORIGIN: GAME\n"
                "// SIZE: 64\n"
                "// CFLAGS: \n"
                "// SYMBOL: _my_func\n"
                "void __cdecl _my_func(void) {}\n"
            ),
        )
        result = lint_file(f)
        # Empty CFLAGS value still parses; file fails for other reasons (E015, E016)
        assert not result.passed
