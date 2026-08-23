"""Tests for the rebrew annotation linter."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.config import ProjectConfig
from rebrew.lint import LintResult, lint_file


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    """Create a .c file in tmp_path and return its Path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _make_cfg(
    marker: str = "SERVER",
    base_cflags: str = "/nologo /c /MT",
    library_modules: set | None = None,
    reversed_dir: Path | None = None,
    cflags: str = "",
) -> SimpleNamespace:
    """Create a minimal config-like namespace for config-aware lint tests."""
    return ProjectConfig(
        root=Path("/tmp"),
        marker=marker,
        base_cflags=base_cflags,
        library_modules=library_modules or set(),
        reversed_dir=reversed_dir or Path("."),
        cflags=cflags,
    )


VALID_HEADER = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n\nint __cdecl bit_reverse(int x)\n{\n    return x;\n}\n"
VALID_LIBRARY_HEADER = "// STUB: SERVER 0x10023714\n// STATUS: STUB\n\n#include <stdlib.h>\nint stub(void) { return 0; }\n"


class TestValidAnnotations:
    def test_valid_function_no_errors(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert result.passed
        assert len(result.errors) == 0

    def test_valid_function_no_warnings(self, tmp_path: Path) -> None:
        """With a config providing default cflags, a clean file has no warnings."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        cfg = _make_cfg(cflags="/O2")
        result = lint_file(f, cfg=cfg)
        assert result.passed, f"Expected lint to pass, errors: {result.errors}"
        non_w019 = [w for w in result.warnings if w[1] != "W019"]
        assert non_w019 == [], f"Unexpected warnings: {non_w019}"

    def test_valid_library_no_errors(self, tmp_path: Path) -> None:
        cfg = _make_cfg()
        f = _write_c(tmp_path, "copy_environ.c", VALID_LIBRARY_HEADER)
        result = lint_file(f, cfg=cfg)
        assert result.passed, f"Expected lint to pass, errors: {result.errors}"
        assert result.errors == [], f"Unexpected errors: {result.errors}"


class TestMissingAnnotation:
    def test_empty_file(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "empty.c", "")
        result = lint_file(f)
        assert not result.passed
        assert any((c == "E001" for _, c, _ in result.errors))

    def test_no_annotation(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "noannot.c", "#include <stdio.h>\nint main() {}\n")
        result = lint_file(f)
        assert not result.passed
        assert any((c == "E001" for _, c, _ in result.errors))

    def test_invalid_marker_type(self, tmp_path: Path) -> None:
        content = "// BADTYPE: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2 /Gd\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E001" for _, c, _ in result.errors))


class TestInvalidVA:
    def test_va_too_small(self, tmp_path: Path) -> None:
        content = "// FUNCTION: SERVER 0x00000001\n// STATUS: EXACT\n// SIZE: 10\n// CFLAGS: /O2 /Gd\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E002" for _, c, _ in result.errors))


class TestMissingFields:
    def test_missing_origin_no_error_when_module_present(self, tmp_path: Path) -> None:
        """ORIGIN is optional when FUNCTION: MODULE field is present — no E005 error."""
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E005" for _, c, _ in result.errors))

    def test_missing_size_no_error(self, tmp_path: Path) -> None:
        """Missing SIZE in source should not cause lint errors — SIZE lives in metadata."""
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// CFLAGS: /O2\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E007" for _, c, _ in result.errors))

    def test_missing_cflags_no_config(self, tmp_path: Path) -> None:
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W018" for _, c, _ in result.warnings))

    def test_missing_cflags_with_config_default(self, tmp_path: Path) -> None:
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        cfg = _make_cfg(cflags="/O2")
        result = lint_file(f, cfg=cfg)
        assert not any((c == "W018" for _, c, _ in result.warnings))


class TestUnknownKeys:
    def test_unknown_annotation_key(self, tmp_path: Path) -> None:
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2\n// FLAVOR: vanilla\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W010" for _, c, _ in result.warnings))


class TestConfigMarkerValidation:
    def test_wrong_module_raises_no_error_without_cfg(self, tmp_path: Path) -> None:
        """Without cfg, module is not validated against marker."""
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E006" for _, c, _ in result.errors))

    def test_valid_function_with_cfg_no_errors(self, tmp_path: Path) -> None:
        cfg = _make_cfg()
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "E006" for _, c, _ in result.errors))


class TestConfigMarker:
    def test_wrong_module_name(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="SERVER")
        content = "// FUNCTION: CLIENT 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any((c == "E012" for _, c, _ in result.errors))

    def test_correct_module_name(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="SERVER")
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "E012" for _, c, _ in result.errors))


class TestDuplicateVA:
    def test_duplicate_va_detected(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _write_c(tmp_path, "first.c", VALID_HEADER)
        f2 = _write_c(tmp_path, "second.c", VALID_HEADER)
        r1 = lint_file(f1, seen_vas=seen_vas)
        r2 = lint_file(f2, seen_vas=seen_vas)
        assert not any((c == "E013" for _, c, _ in r1.errors))
        assert any((c == "E013" for _, c, _ in r2.errors))

    def test_different_vas_no_duplicate(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        content2 = VALID_HEADER.replace("0x10008880", "0x10009999")
        f1 = _write_c(tmp_path, "first.c", VALID_HEADER)
        f2 = _write_c(tmp_path, "second.c", content2)
        r1 = lint_file(f1, seen_vas=seen_vas)
        r2 = lint_file(f2, seen_vas=seen_vas)
        assert not any((c == "E013" for _, c, _ in r1.errors))
        assert not any((c == "E013" for _, c, _ in r2.errors))


class TestWarnings:
    def test_w001_missing_symbol(self, tmp_path: Path) -> None:
        """SYMBOL is derived from C function definitions — W001 should not fire."""
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2 /Gd\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "W001" for _, c, _ in result.warnings))

    def test_w003_no_code(self, tmp_path: Path) -> None:
        content = (
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2 /Gd\n"
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W003" for _, c, _ in result.warnings))

    def test_e015_marker_origin_mismatch(self, tmp_path: Path) -> None:
        """FUNCTION marker with library module should trigger E015 (should be LIBRARY)."""
        cfg = _make_cfg(library_modules={"SERVER"})
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any((c == "E015" for _, c, _ in result.errors))

    def test_w005_stub_without_blocker(self, tmp_path: Path) -> None:
        content = "// STUB: SERVER 0x10008880\n// STATUS: STUB\n// SIZE: 31\n// CFLAGS: /O2\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W005" for _, c, _ in result.warnings))

    def test_w006_library_without_source(self, tmp_path: Path) -> None:
        """Library module without SOURCE annotation should trigger W006."""
        cfg = _make_cfg(library_modules={"SERVER"})
        content = "// LIBRARY: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O1\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "crt_foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any((c == "W006" for _, c, _ in result.warnings))

    def test_e017_contradictory_matching_stub(self, tmp_path: Path) -> None:
        content = "// STUB: SERVER 0x10008880\n// STATUS: NEAR_MATCHING\n// SIZE: 31\n// CFLAGS: /O2\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E017" for _, c, _ in result.errors))

    def test_e017_contradictory_exact_stub_marker(self, tmp_path: Path) -> None:
        """A byte-matched function must not carry a STUB marker (stale marker
        from stub generation; regression: 3 smygb functions were silently
        mislabeled this way)."""
        content = "// STUB: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E017" for _, c, _ in result.errors))

    def test_e017_ok_function_marker_exact(self, tmp_path: Path) -> None:
        """FUNCTION marker + EXACT status is the healthy state — no E017."""
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E017" for _, c, _ in result.errors))


class TestCflagsPreset:
    def test_invalid_annotation_key_no_error_for_valid(self, tmp_path: Path) -> None:
        """Valid annotations should not produce unknown-key warnings."""
        cfg = _make_cfg()
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "W010" for _, c, _ in result.warnings))


class TestJsonOutput:
    def test_to_dict_structure(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        d = result.to_dict()
        assert "file" in d
        assert "path" in d
        assert "errors" in d
        assert "warnings" in d
        assert "passed" in d
        assert d["passed"] is True

    def test_to_dict_errors(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "empty.c", "")
        result = lint_file(f)
        d = result.to_dict()
        assert d["passed"] is False
        assert len(d["errors"]) > 0
        err = d["errors"][0]
        assert "line" in err
        assert "code" in err
        assert "message" in err


class TestNoConfig:
    def test_lint_without_config(self, tmp_path: Path) -> None:
        """Config-aware checks should not fire when cfg is None."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=None)
        assert result.passed
        assert not any((c in ("E011", "E012") for _, c, _ in result.errors))

    def test_fix_without_config_warns_instead_of_silent_noop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--fix outside a project must explain that nothing can migrate
        (functionality-review: previously a silent no-op — the user saw zero
        effect with no message)."""
        from typer.testing import CliRunner

        from rebrew.lint import app

        f = _write_c(
            tmp_path,
            "fcn.c",
            "// FUNCTION: SERVER 0x00401000\n// STATUS: EXACT\n// SIZE: 16\n"
            "int __cdecl f(void) { return 0; }\n",
        )
        monkeypatch.chdir(tmp_path)  # no rebrew-project.toml here
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0
        assert "needs a rebrew-project.toml" in result.output
        # The inline keys must remain untouched.
        assert "// STATUS:" in f.read_text()
        assert "// SIZE:" in f.read_text()


class TestVAHexCase:
    def test_w015_mixed_case_va(self, tmp_path: Path) -> None:
        content = "// FUNCTION: SERVER 0x1000AbCd\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2 /Gd\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W015" for _, c, _ in result.warnings))

    def test_w015_consistent_lowercase(self, tmp_path: Path) -> None:
        """All-lowercase VA should not warn."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert not any((c == "W015" for _, c, _ in result.warnings))

    def test_w015_consistent_uppercase(self, tmp_path: Path) -> None:
        """All-uppercase VA should not warn."""
        content = VALID_HEADER.replace("0x10008880", "0x10008ABF")
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert not any((c == "W015" for _, c, _ in result.warnings))


class TestW016Section:
    def test_w016_global_missing_section(self, tmp_path: Path) -> None:
        """GLOBAL without SECTION in metadata fires W016."""
        metadata_toml = tmp_path / "rebrew-function.toml"
        metadata_toml.write_text('["SERVER.0x10050000"]\nsize = 4\n', encoding="utf-8")
        content = "// GLOBAL: SERVER 0x10050000\nint g_foo;\n"
        f = _write_c(tmp_path, "g_foo.c", content)
        result = lint_file(f)
        assert any((c == "W016" for _, c, _ in result.warnings))

    def test_w016_data_missing_section(self, tmp_path: Path) -> None:
        """DATA without SECTION in metadata fires W016."""
        metadata_toml = tmp_path / "rebrew-function.toml"
        metadata_toml.write_text('["SERVER.0x10050000"]\nsize = 10\n', encoding="utf-8")
        content = '// DATA: SERVER 0x10050000\nchar s_hello[] = "hello";\n'
        f = _write_c(tmp_path, "s_hello.c", content)
        result = lint_file(f)
        assert any((c == "W016" for _, c, _ in result.warnings))

    def test_w016_global_with_section_no_warning(self, tmp_path: Path) -> None:
        """SECTION from the metadata should suppress W016 without inline SECTION."""
        metadata_toml = tmp_path / "rebrew-function.toml"
        metadata_toml.write_text(
            '["SERVER.0x10050000"]\nsize = 4\nsection = ".bss"\n', encoding="utf-8"
        )
        content = "// GLOBAL: SERVER 0x10050000\nint g_foo;\n"
        f = _write_c(tmp_path, "g_foo.c", content)
        result = lint_file(f)
        assert not any((c == "W016" for _, c, _ in result.warnings))
        assert not any(("SECTION" in m for _, c, m in result.warnings if c == "W019"))

    def test_w016_function_no_warning(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert not any((c == "W016" for _, c, _ in result.warnings))


class TestPrintSummary:
    def test_summary_counters_populated(self, tmp_path: Path) -> None:
        """LintResult should have status/marker counters populated after lint."""
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n\nint __cdecl bit_reverse(int x) { return x; }\n"
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert result._status_counts["EXACT"] == 1
        assert result._marker_counts["FUNCTION"] == 1

    def test_summary_counters_multi_block(self, tmp_path: Path) -> None:
        """Multi-block file should accumulate counters across blocks."""
        content = "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n\nint func1() { return 1; }\n\n// STUB: SERVER 0x10009990\n// STATUS: STUB\n\nint func2() { return 0; }\n"
        f = _write_c(tmp_path, "multi.c", content)
        result = lint_file(f)
        assert result._status_counts["EXACT"] == 1
        assert result._status_counts["STUB"] == 1
        assert result._marker_counts["FUNCTION"] == 1
        assert result._marker_counts["STUB"] == 1


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

    def test_display_no_crash(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.error(1, "E001", "err")
        r.warning(2, "W001", "warn")
        # Both display modes must run without raising; quiet must produce
        # less (or equal) output than the default mode.
        r.display()
        full = capsys.readouterr()
        r.display(quiet=True)
        quiet = capsys.readouterr()
        assert len(quiet.out) + len(quiet.err) <= len(full.out) + len(full.err)


def _make_c_file(tmp_path: Path, name: str = "my_func.c", content: str | None = None) -> Path:
    if content is None:
        content = "// STUB: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _my_func\nvoid __cdecl _my_func(void) {\n    // stub\n}\n"
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


class TestLintFile:
    def test_valid_file(self, tmp_path: Path) -> None:
        f = _make_c_file(tmp_path)
        result = lint_file(f)
        assert result.passed is True

    def test_missing_function_annotation(self, tmp_path: Path) -> None:
        f = _make_c_file(tmp_path, content="void f() {}\n")
        result = lint_file(f)
        assert result.passed is False

    def test_missing_symbol(self, tmp_path: Path) -> None:
        """SYMBOL is derived from C function definitions — W001 should not fire."""
        f = _make_c_file(
            tmp_path,
            content="// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\nvoid __cdecl _my_func(void) {}\n",
        )
        result = lint_file(f)
        assert not any((c == "W001" for _, c, _ in result.warnings))

    def test_missing_size(self, tmp_path: Path) -> None:
        """SIZE lives in metadata — a FUNCTION+STUB file without inline SIZE
        is valid (no error); only the metadata-migration warning fires."""
        f = _make_c_file(
            tmp_path,
            content="// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// CFLAGS: /O2 /Gd\n// SYMBOL: _my_func\nvoid __cdecl _my_func(void) {}\n",
        )
        result = lint_file(f)
        assert result.passed
        assert result.errors == []

    def test_duplicate_va_detection(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _make_c_file(tmp_path, name="func1.c")
        f2 = _make_c_file(tmp_path, name="func2.c")
        lint_file(f1, seen_vas=seen_vas)
        result2 = lint_file(f2, seen_vas=seen_vas)
        assert any((c == "E013" for _, c, _ in result2.errors))

    def test_with_config(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=Path("/tmp"), marker="SERVER")
        f = _make_c_file(tmp_path)
        result = lint_file(f, cfg=cfg)
        assert result.passed

    def test_multiple_functions_in_file(self, tmp_path: Path) -> None:
        f = _make_c_file(
            tmp_path,
            content="// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _func_a\nvoid __cdecl _func_a(void) {}\n\n// FUNCTION: SERVER 0x10002000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 128\n// CFLAGS: /O2 /Gd\n// SYMBOL: _func_b\nvoid __cdecl _func_b(void) {}\n",
        )
        result = lint_file(f)
        # Both function blocks should be detected (warnings expected for inline metadata)
        assert result._marker_counts["FUNCTION"] == 2

    def test_empty_file(self, tmp_path: Path) -> None:
        f = _make_c_file(tmp_path, content="")
        result = lint_file(f)
        assert not result.passed

    def test_bad_cflags(self, tmp_path: Path) -> None:
        f = _make_c_file(
            tmp_path,
            content="// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: \n// SYMBOL: _my_func\nvoid __cdecl _my_func(void) {}\n",
        )
        result = lint_file(f)
        # FUNCTION+STUB is a valid marker combination (status lives in
        # metadata); the real issue is the empty inline CFLAGS.
        assert result.passed
        # Empty CFLAGS should produce W018 (missing CFLAGS with no config fallback)
        assert any(c == "W018" for _, c, _ in result.warnings)
        assert any("CFLAGS" in m for _, c, m in result.warnings if c == "W018")


class TestLintFileBranches:
    def test_w019_after_bare_name_hint_line(self, tmp_path: Path) -> None:
        """A bare '// FuncName' comment line must not orphan later inline keys.

        Regression: the header parser used to treat any non-KV comment line as
        "code", so ``// SIZE:``/``// CFLAGS:`` after a name-hint line were
        buffered as pending and never attached to the block — W019 (and --fix)
        never saw them.
        """
        from rebrew.lint import lint_file

        f = _write_c(
            tmp_path,
            "foo.c",
            "// FUNCTION: SERVER 0x1000\n"
            "// FooBar\n"
            "// SIZE: 42\n"
            "// CFLAGS: /O2 /Gd\n"
            "int FooBar(void) { return 0; }\n",
        )
        result = lint_file(f)
        w019 = [m for _, c, m in result.warnings if c == "W019"]
        assert any("'// SIZE:'" in m for m in w019), w019
        assert any("'// CFLAGS:'" in m for m in w019), w019

    def test_w019_silent_for_source_naked_marker(self, tmp_path: Path) -> None:
        """`// SOURCE: naked` (rebrew asm --inline-c skeletons) is the
        file-borne naked-reconstruction marker — exempt from W019 like the
        naked-guard CFLAGS convention, while other inline SOURCE values warn."""
        from rebrew.lint import lint_file

        f = _write_c(
            tmp_path,
            "naked.c",
            "// FUNCTION: SERVER 0x1000\n// SIZE: 42\n// SOURCE: naked\n"
            "#ifdef REBREW_ALLOW_NAKED\n__declspec(naked) void f(void){}\n"
            "#else\nvoid f(void){}\n#endif\n",
        )
        result = lint_file(f)
        # SIZE is legitimately metadata-owned and may still warn — the
        # exemption is SOURCE: naked specifically.
        assert not any("'// SOURCE:'" in m for _, c, m in result.warnings if c == "W019"), (
            result.warnings
        )

        g = _write_c(
            tmp_path,
            "other.c",
            "// FUNCTION: SERVER 0x2000\n// SIZE: 42\n// SOURCE: zlib\nint g(void){return 0;}\n",
        )
        result2 = lint_file(g)
        assert any("'// SOURCE:'" in m for _, c, m in result2.warnings if c == "W019"), (
            result2.warnings
        )

    def test_w019_silent_for_metadata_backed_after_name_hint(self, tmp_path: Path) -> None:
        """SIZE after a name-hint line that metadata already owns stays silent."""
        from rebrew.lint import lint_file
        from rebrew.metadata import set_field

        src = tmp_path / "src"
        src.mkdir()
        (src / "foo.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// FooBar\n// SIZE: 42\nint FooBar(void) { return 0; }\n",
            encoding="utf-8",
        )
        set_field(tmp_path, 0x1000, "size", 42, module="SERVER")
        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            marker="SERVER",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=[],
        )
        result = lint_file(src / "foo.c", cfg=cfg)  # type: ignore[arg-type]
        w019 = [m for _, c, m in result.warnings if c == "W019"]
        assert w019 == []  # metadata-sourced keys must not fire W019

    def test_preloaded_data_metadata_overlay(self, tmp_path: Path) -> None:
        """DATA markers pull size/section/note from rebrew-data.toml without W019."""
        from rebrew.data_metadata import set_data_field
        from rebrew.lint import lint_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "globals.c").write_text("// DATA: SERVER 0x1000\nint g_x;\n", encoding="utf-8")
        set_data_field(tmp_path, 0x1000, "size", 16, "SERVER")
        set_data_field(tmp_path, 0x1000, "section", ".data", "SERVER")
        set_data_field(tmp_path, 0x1000, "note", "counter", "SERVER")
        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            marker="SERVER",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=[],
        )
        result = lint_file(src / "globals.c", cfg=cfg)  # type: ignore[arg-type]
        w019 = [e for e in result.errors + result.warnings if e[1] == "W019"]
        assert w019 == []  # metadata-sourced keys must not fire W019

    def test_bad_hex_va_metadata_lookup_skipped(self, tmp_path: Path) -> None:
        """An unparseable VA in the marker does not crash the metadata overlay."""
        from rebrew.lint import lint_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(
            "// FUNCTION: SERVER 0xZZZZ\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        result = lint_file(src / "f.c")  # no cfg → metadata_dir = filepath.parent
        # The unparseable marker is not recognized → E001 (missing marker),
        # but the metadata overlay must not crash.
        assert any(e[1] == "E001" for e in result.errors)

    def test_invalid_va_reports_e002(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(
            "// FUNCTION: SERVER 0x123\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        result = lint_file(src / "f.c")
        assert any(e[1] == "E002" for e in result.errors)


class TestLintCli:
    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]) -> object:
        from typer.testing import CliRunner

        from rebrew.lint import app

        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=["GAME", "SERVER"],
        )
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        return CliRunner().invoke(app, args)

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        src = tmp_path / "src"
        src.mkdir()
        (src / "ok.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = self._invoke(tmp_path, monkeypatch, ["--json", str(src / "ok.c")])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["files"][0]["path"] == str(src / "ok.c")

    def test_errors_exit_nonzero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.c").write_text("not a c file\n", encoding="utf-8")
        result = self._invoke(tmp_path, monkeypatch, ["--json", str(src / "bad.c")])
        assert result.exit_code != 0

    def test_summary_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "ok.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = self._invoke(tmp_path, monkeypatch, ["--summary", str(src / "ok.c")])
        assert result.exit_code == 0
        assert "EXACT" in result.output or "Summary" in result.output


class TestLintFix:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=["GAME", "SERVER"],
        )

    def _write_inline(self, tmp_path: Path) -> Path:
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// STATUS: EXACT\n// SIZE: 42\n"
            "int f(void) { return 0; }\n",
            encoding="utf-8",
        )
        return f

    def test_fix_dry_run_previews(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app

        cfg = self._cfg(tmp_path)
        f = self._write_inline(tmp_path)
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", "--dry-run", str(f)])
        assert result.exit_code == 0
        assert "Would migrate" in result.output
        # Nothing changed.
        assert "// STATUS: EXACT" in f.read_text(encoding="utf-8")

    def test_fix_migrates_to_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app
        from rebrew.metadata import get_entry

        cfg = self._cfg(tmp_path)
        f = self._write_inline(tmp_path)
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0
        text = f.read_text(encoding="utf-8")
        assert "// STATUS:" not in text
        assert "// SIZE:" not in text
        entry = get_entry(tmp_path, 0x1000, "SERVER")
        assert entry.get("status") == "EXACT"
        assert entry.get("size") == 42  # coerced to int

    def test_fix_metadata_sourced_status_not_migrated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """STATUS already in metadata is metadata-sourced → not listed for migration."""
        from typer.testing import CliRunner

        from rebrew.lint import app
        from rebrew.metadata import update_source_status

        cfg = self._cfg(tmp_path)
        f = self._write_inline(tmp_path)
        update_source_status(tmp_path, "EXACT", "SERVER", 0x1000)
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", "--dry-run", str(f)])
        assert result.exit_code == 0
        assert "STATUS" not in result.output  # overlay marks it metadata-sourced
        assert "SIZE" in result.output  # only the inline SIZE is migrated

    def test_fix_duplicate_va_second_file_already_migrated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cross-file duplicate VA: the second file's inline keys are already
        in metadata mid-loop (migrated by the first file) — the inline copies
        must still be stripped, and nothing may be double-written."""
        from typer.testing import CliRunner

        from rebrew.lint import app
        from rebrew.metadata import get_entry

        cfg = self._cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        body = "// FUNCTION: SERVER 0x1000\n// STATUS: EXACT\n// SIZE: 42\n"
        a = src / "a.c"
        a.write_text(body + "int a(void) { return 0; }\n", encoding="utf-8")
        b = src / "b.c"
        b.write_text(body + "int b(void) { return 0; }\n", encoding="utf-8")

        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", str(a), str(b)])
        assert result.exit_code == 1  # E013 duplicate VA is an error
        assert "E013" in result.output
        # Both inline copies stripped; metadata owns the fields exactly once.
        for f in (a, b):
            text = f.read_text(encoding="utf-8")
            assert "// STATUS:" not in text
            assert "// SIZE:" not in text
        entry = get_entry(tmp_path, 0x1000, "SERVER")
        assert entry.get("status") == "EXACT"
        assert entry.get("size") == 42


class TestLintFixConvergence:
    def test_fix_then_relint_no_w019(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app, lint_file
        from rebrew.metadata import get_entry

        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=["GAME", "SERVER"],
        )
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// STATUS: EXACT\n// SIZE: 42\n"
            "int f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0

        # Re-linting the migrated file: no W019, and metadata owns the fields.
        again = lint_file(f, cfg=cfg)
        assert not any(e[1] == "W019" for e in again.warnings + again.errors)
        entry = get_entry(tmp_path, 0x1000, "SERVER")
        assert entry.get("status") == "EXACT"
        assert entry.get("size") == 42


class TestW020AsmDump:
    """Asm-dump placeholders (__emit / __asm blocks) must be flagged as W020."""

    def _lint(self, tmp_path: Path, body: str) -> LintResult:
        content = (
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2 /Gd\n"
            + body
        )
        f = _write_c(tmp_path, "foo.c", content)
        return lint_file(f)

    def test_emit_byte_dump_warns(self, tmp_path: Path) -> None:
        # Whole-function __declspec(naked) + __asm/__emit is now E023 (error),
        # not W020. Only 1-2 nop/0x90/0xCC padding bytes are allowed as naked.
        body = "__declspec(naked) int f(void) {\n    __asm {\n        _emit 0x55\n        _emit 0x8b\n    }\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "E023" for _, c, _ in result.errors), (
            f"expected E023, got errors={result.errors} warnings={result.warnings}"
        )
        assert not any(c == "W020" for _, c, _ in result.warnings)  # naked dumps are E023, not W020
        msg = next(m for _, c, m in result.errors if c == "E023")
        assert "naked" in msg.lower()

    def test_inline_asm_block_warns(self, tmp_path: Path) -> None:
        body = "int f(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "W020" for _, c, _ in result.warnings)

    def test_plain_c_does_not_warn(self, tmp_path: Path) -> None:
        body = "int f(void) { return 42; }\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "W020" for _, c, _ in result.warnings)

    def test_asm_in_comment_does_not_warn(self, tmp_path: Path) -> None:
        # "// __asm" in a comment is not an implementation.
        body = "// __asm notes about the original\nint f(void) { return 0; }\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "W020" for _, c, _ in result.warnings)

    def test_stub_asm_dump_is_documented_placeholder(self, tmp_path: Path) -> None:
        """STUB + asm dump is an expected placeholder — base message, no escalation."""
        content = (
            "// FUNCTION: SERVER 0x10008880\n// STATUS: STUB\n// SIZE: 31\n"
            "// CFLAGS: /O2 /Gd\n"
            "int f(void) {\n    __asm { _emit 0x55 }\n}\n"
        )
        result = lint_file(_write_c(tmp_path, "stub.c", content))
        msg = next(m for _, c, m in result.warnings if c == "W020")
        assert "cannot be a byte-match" not in msg  # STUB is fine — not escalated
        assert "asm" in msg.lower()

    def test_exact_claim_on_asm_dump_escalates(self, tmp_path: Path) -> None:
        """EXACT + asm dump is a metadata contradiction — W020 escalates."""
        content = (
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n"
            "// CFLAGS: /O2 /Gd\n"
            "int f(void) {\n    __asm { _emit 0x55 }\n}\n"
        )
        result = lint_file(_write_c(tmp_path, "claimed.c", content))
        msg = next(m for _, c, m in result.warnings if c == "W020")
        assert "EXACT" in msg
        assert "cannot be a byte-match" in msg


class TestE023NakedAsm:
    """E023: whole-function __declspec(naked)+__asm is an error; minor padding (1-2 nops) is allowed."""

    def _lint(self, tmp_path: Path, body: str) -> LintResult:
        content = (
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2 /Gd\n"
            + body
        )
        f = _write_c(tmp_path, "foo.c", content)
        return lint_file(f)

    def test_whole_function_naked_asm_is_error(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm { push ebp }\n    __asm { mov eax, 1 }\n    __asm { ret }\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "E023" for _, c, _ in result.errors)
        assert not result.passed
        msg = next(m for _, c, m in result.errors if c == "E023")
        assert "naked" in msg.lower()

    def test_whole_function_naked_emit_is_error(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm {\n        _emit 0x55\n        _emit 0x8b\n        _emit 0xc3\n    }\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "E023" for _, c, _ in result.errors)

    def test_naked_minor_padding_one_nop_allowed(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm nop\n}\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)

    def test_naked_minor_padding_two_emit_padding_allowed(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm { _emit 0x90 }\n    __asm { _emit 0x90 }\n}\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)

    def test_non_naked_asm_still_W020_not_E023(self, tmp_path: Path) -> None:
        body = "int f(void) {\n    __asm { mov eax, 1 }\n    __asm { mov ebx, 2 }\n    __asm { ret }\n}\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)
        assert any(c == "W020" for _, c, _ in result.warnings)

    def test_naked_without_asm_no_error(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) { return 0; }\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)

    def test_metadata_cflags_rebrew_allow_naked_skips_e023(self, tmp_path: Path) -> None:
        """REBREW_ALLOW_NAKED in rebrew-function.toml (not source) suppresses E023."""
        metadata_toml = tmp_path / "rebrew-function.toml"
        metadata_toml.write_text(
            '["SERVER.0x10008880"]\ncflags = "/O2 /Gd /DREBREW_ALLOW_NAKED"\n',
            encoding="utf-8",
        )
        content = (
            "// FUNCTION: SERVER 0x10008880\n"
            "__declspec(naked) int f(void) {\n"
            "    __asm { push ebp }\n"
            "    __asm { mov eax, 1 }\n"
            "    __asm { ret }\n"
            "}\n"
        )
        f = _write_c(tmp_path, "naked.c", content)
        result = lint_file(f)
        assert not any(c == "E023" for _, c, _ in result.errors), (
            f"E023 must not fire when metadata cflags carry /DREBREW_ALLOW_NAKED, "
            f"got errors={result.errors}"
        )

    def test_metadata_cflags_without_guard_keeps_e023(self, tmp_path: Path) -> None:
        """Metadata cflags that lack REBREW_ALLOW_NAKED must not suppress E023."""
        metadata_toml = tmp_path / "rebrew-function.toml"
        metadata_toml.write_text('["SERVER.0x10008880"]\ncflags = "/O2 /Gd"\n', encoding="utf-8")
        content = (
            "// FUNCTION: SERVER 0x10008880\n"
            "__declspec(naked) int f(void) {\n"
            "    __asm { push ebp }\n"
            "    __asm { mov eax, 1 }\n"
            "    __asm { ret }\n"
            "}\n"
        )
        f = _write_c(tmp_path, "naked2.c", content)
        result = lint_file(f)
        assert any(c == "E023" for _, c, _ in result.errors)


class TestW021W022:
    """Duplicate-global (W021) and zero-init .bss (W022) checks."""

    def test_duplicate_global_across_files(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        def _write(name: str, symbol: str, va: int) -> Path:
            content = f"// DATA: SERVER 0x{va:08x}\nextern int {symbol};\n"
            f = _write_c(tmp_path, name, content)
            return f

        f1 = _write("one.c", "g_counter", 0x10001000)
        seen: dict[str, str] = {}
        r1 = lint_file(f1, seen_globals=seen)
        assert not any(c == "W021" for _, c, _ in r1.warnings)

        f2 = _write("two.c", "g_counter", 0x10002000)
        r2 = lint_file(f2, seen_globals=seen)
        assert any(c == "W021" for _, c, _ in r2.warnings)
        msg = next(m for _, c, m in r2.warnings if c == "W021")
        assert "g_counter" in msg

    def test_unique_globals_no_warning(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        seen: dict[str, str] = {}
        for i, name in enumerate(("g_a", "g_b", "g_c")):
            f = _write_c(
                tmp_path, f"f{i}.c", f"// DATA: SERVER 0x1000{i:03x}\nextern int {name};\n"
            )
            r = lint_file(f, seen_globals=seen)
            assert not any(c == "W021" for _, c, _ in r.warnings)

    def test_zero_init_global_warns(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        content = "// FUNCTION: SERVER 0x1000\nint g_buf[256] = {0};\nvoid f(void) {}\n"
        f = _write_c(tmp_path, "z.c", content)
        result = lint_file(f)
        assert any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_inside_function_no_warning(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        content = (
            "// FUNCTION: SERVER 0x1000\n"
            "void f(void) {\n    int local[4] = {0};\n    (void)local;\n}\n"
        )
        f = _write_c(tmp_path, "l.c", content)
        result = lint_file(f)
        assert not any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_in_comment_no_warning(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        # A commented-out zero-init at file scope must not warn, and a
        # string literal that looks like one must not either.
        content = (
            "// FUNCTION: SERVER 0x1000\n"
            "// int g_buf[4] = {0};  // old layout\n"
            'const char *kMsg = "= 0";\n'
            "void f(void) {}\n"
        )
        f = _write_c(tmp_path, "c.c", content)
        result = lint_file(f)
        assert not any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_after_multiline_comment_warns(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        # The file-scope preamble spans lines; the declaration after it must
        # still be seen (block-comment state must not leak).
        content = (
            "/*\n"
            " * preamble\n"
            " */\n"
            "// FUNCTION: SERVER 0x1000\n"
            "int g_buf[4] = {0};\n"
            "void f(void) {}\n"
        )
        f = _write_c(tmp_path, "m.c", content)
        result = lint_file(f)
        assert any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_data_section_name_no_warning(self, tmp_path: Path) -> None:
        """A zero-init global annotated section='.data' in rebrew-data.toml
        is exempt — the original stored the zero-init data in .data."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        data_toml.write_text(
            '["SERVER.0x10034628"]\nname = "g_stat1"\nsection = ".data"\n', encoding="utf-8"
        )
        content = "// FUNCTION: SERVER 0x1000\nint g_stat1 = 0;\nvoid f(void) {}\n"
        f = _write_c(tmp_path, "d.c", content)
        result = lint_file(f)
        assert not any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_bss_section_name_still_warns(self, tmp_path: Path) -> None:
        """section='.bss' metadata does NOT exempt a zero-init global."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        data_toml.write_text(
            '["SERVER.0x1004a000"]\nname = "g_buf"\nsection = ".bss"\n', encoding="utf-8"
        )
        content = "// FUNCTION: SERVER 0x1000\nint g_buf[4] = {0};\nvoid f(void) {}\n"
        f = _write_c(tmp_path, "b.c", content)
        result = lint_file(f)
        assert any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_different_name_still_warns(self, tmp_path: Path) -> None:
        """A .data exemption for another symbol does not suppress this global."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        data_toml.write_text(
            '["SERVER.0x10034628"]\nname = "g_other"\nsection = ".data"\n', encoding="utf-8"
        )
        content = "// FUNCTION: SERVER 0x1000\nint g_buf = 0;\nvoid f(void) {}\n"
        f = _write_c(tmp_path, "n.c", content)
        result = lint_file(f)
        assert any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_exempt_and_warn_in_same_file(self, tmp_path: Path) -> None:
        """Exempt .data globals are skipped; a later non-exempt zero-init warns."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        data_toml.write_text(
            '["SERVER.0x10034628"]\nname = "g_stat1"\nsection = ".data"\n', encoding="utf-8"
        )
        content = (
            "// FUNCTION: SERVER 0x1000\nint g_stat1 = 0;\nint g_bss_var = 0;\nvoid f(void) {}\n"
        )
        f = _write_c(tmp_path, "mx.c", content)
        result = lint_file(f)
        w022 = [(line, m) for line, c, m in result.warnings if c == "W022"]
        assert len(w022) == 1
        assert w022[0][0] == 3


class TestDuplicateVAMultiBlock:
    """E013 must flag a duplicate VA in a LATER block of a multi-function file
    (round-4: the old i == 0 guard only checked the first block)."""

    def test_duplicate_in_later_block_flagged(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\nint first(void) { return 0; }\n\n"
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\nint second(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = lint_file(f)
        assert any((c == "E013" for _, c, _ in result.errors))

    def test_same_va_different_module_allowed(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\nint first(void) { return 0; }\n\n"
            "// FUNCTION: CLIENT 0x10008880\n// STATUS: EXACT\nint second(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = lint_file(f)
        assert not any((c == "E013" for _, c, _ in result.errors))


class TestAnnotationStaleness:
    """W028 — FUNCTION/STUB marker VAs must match a function start in the
    current function list (moved from `rebrew doctor`; corpus-content
    checks belong to lint, environment checks to doctor)."""

    # (starts, spans) as built by _build_function_index from a funcs.txt
    # with func_a@0x1000 (256B) and func_b@0x2000 (128B).
    INDEX = (
        {0x1000, 0x2000},
        [(0x1000, 0x1100, "func_a"), (0x2000, 0x2080, "func_b")],
    )

    @staticmethod
    def _w028(result: LintResult) -> list[tuple[int, str]]:
        return [(line, m) for line, c, m in result.warnings if c == "W028"]

    def test_matching_start_silent(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "a.c", "// FUNCTION: SERVER 0x1000\nint a(void) { return 0; }\n")
        result = lint_file(f, cfg=_make_cfg(), function_index=self.INDEX)
        assert self._w028(result) == []

    def test_dangling_va_warns(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "a.c", "// FUNCTION: SERVER 0x3000\nint a(void) { return 0; }\n")
        result = lint_file(f, cfg=_make_cfg(), function_index=self.INDEX)
        w028 = self._w028(result)
        assert len(w028) == 1
        assert w028[0][0] == 1
        assert "0x3000 has no function" in w028[0][1]
        assert "re-annotate" in w028[0][1]

    def test_va_inside_span_warns(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "a.c", "// FUNCTION: SERVER 0x1050\nint a(void) { return 0; }\n")
        result = lint_file(f, cfg=_make_cfg(), function_index=self.INDEX)
        w028 = self._w028(result)
        assert len(w028) == 1
        assert "points inside function 'func_a'" in w028[0][1]

    def test_library_marker_ignored(self, tmp_path: Path) -> None:
        # LIBRARY markers may point at import stubs the parser filters out.
        f = _write_c(tmp_path, "l.c", "// LIBRARY: SERVER 0x3000\nint l(void) { return 0; }\n")
        result = lint_file(f, cfg=_make_cfg(), function_index=self.INDEX)
        assert self._w028(result) == []

    def test_data_marker_ignored(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "d.c", "// DATA: SERVER 0x3000\n// SECTION: .rdata\nint d = 1;\n")
        result = lint_file(f, cfg=_make_cfg(), function_index=self.INDEX)
        assert self._w028(result) == []

    def test_other_target_marker_filtered(self, tmp_path: Path) -> None:
        # A shared source carrying a marker for a different target must not
        # be cross-checked against this target's function list.
        f = _write_c(tmp_path, "s.c", "// FUNCTION: CLIENT 0x3000\nint s(void) { return 0; }\n")
        result = lint_file(f, cfg=_make_cfg(marker="SERVER"), function_index=self.INDEX)
        assert self._w028(result) == []

    def test_no_index_silent(self, tmp_path: Path) -> None:
        # No function list (or cfg=None): the check is silent, matching the
        # old doctor SKIP-on-missing-list behavior.
        f = _write_c(tmp_path, "a.c", "// FUNCTION: SERVER 0x3000\nint a(void) { return 0; }\n")
        result = lint_file(f, cfg=_make_cfg())
        assert self._w028(result) == []

    def test_build_function_index(self, tmp_path: Path) -> None:
        from rebrew.lint import _build_function_index

        funcs = tmp_path / "funcs.txt"
        funcs.write_text("0x1000 256 func_a\n0x2000 128 func_b\n", encoding="utf-8")
        cfg = _make_cfg()
        cfg.function_list = funcs
        index = _build_function_index(cfg)
        assert index == self.INDEX

    def test_build_function_index_empty_list(self, tmp_path: Path) -> None:
        from rebrew.lint import _build_function_index

        cfg = _make_cfg()
        cfg.function_list = tmp_path / "missing.txt"
        assert _build_function_index(cfg) is None
