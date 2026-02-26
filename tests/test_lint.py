"""Tests for the rebrew annotation linter."""

from pathlib import Path
from types import SimpleNamespace

from rebrew.lint import lint_file

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    """Create a .c file in tmp_path and return its Path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _make_cfg(
    marker: str = "SERVER",
    origins: list[str] | None = None,
    cflags_presets: dict[str, str] | None = None,
    library_origins: set[str] | None = None,
) -> SimpleNamespace:
    """Create a minimal config-like namespace for config-aware lint tests."""
    return SimpleNamespace(
        marker=marker,
        origins=origins or ["GAME", "MSVCRT", "ZLIB"],
        cflags_presets=cflags_presets or {},
        library_origins=library_origins or {"MSVCRT", "ZLIB"},
    )


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

VALID_LIBRARY_HEADER = """\
// STUB: SERVER 0x10023714
// STATUS: STUB
// ORIGIN: MSVCRT
// SIZE: 103
// CFLAGS: /O1
// SYMBOL: __copy_environ
// BLOCKER: missing CRT internals
// SOURCE: ENVIRON.C

#include <stdlib.h>
int stub(void) { return 0; }
"""


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestValidAnnotations:
    def test_valid_function_no_errors(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert result.passed
        assert len(result.errors) == 0

    def test_valid_function_no_warnings(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert len(result.warnings) == 0

    def test_valid_library_no_errors(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "copy_environ.c", VALID_LIBRARY_HEADER)
        result = lint_file(f)
        assert result.passed


# ---------------------------------------------------------------------------
# E001: Missing annotation
# ---------------------------------------------------------------------------


class TestMissingAnnotation:
    def test_empty_file(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "empty.c", "")
        result = lint_file(f)
        assert not result.passed
        assert any(c == "E001" for _, c, _ in result.errors)

    def test_no_annotation(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "noannot.c", "#include <stdio.h>\nint main() {}\n")
        result = lint_file(f)
        assert not result.passed
        assert any(c == "E001" for _, c, _ in result.errors)

    def test_invalid_marker_type(self, tmp_path: Path) -> None:
        content = """\
// BADTYPE: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E001" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# E002: Invalid VA
# ---------------------------------------------------------------------------


class TestInvalidVA:
    def test_va_too_small(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x00000001
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E002" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# E003-E009: Missing/invalid fields
# ---------------------------------------------------------------------------


class TestMissingFields:
    def test_missing_status(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E003" for _, c, _ in result.errors)

    def test_invalid_status(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: PERFECT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E004" for _, c, _ in result.errors)

    def test_missing_origin(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E005" for _, c, _ in result.errors)

    def test_invalid_origin(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: OPENSSL
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E006" for _, c, _ in result.errors)

    def test_missing_size(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E007" for _, c, _ in result.errors)

    def test_invalid_size(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: -5
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E008" for _, c, _ in result.errors)

    def test_missing_cflags(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E009" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# E010: Unknown keys
# ---------------------------------------------------------------------------


class TestUnknownKeys:
    def test_unknown_annotation_key(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2
// FLAVOR: vanilla
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E010" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# E011: ORIGIN not in config.origins
# ---------------------------------------------------------------------------


class TestConfigOrigin:
    def test_origin_not_in_config(self, tmp_path: Path) -> None:
        cfg = _make_cfg(origins=["GAME"])
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: MSVCRT
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        # E006 fires because cfg.origins is set and MSVCRT is not in it
        assert any(c == "E006" for _, c, _ in result.errors)

    def test_origin_in_config_is_ok(self, tmp_path: Path) -> None:
        cfg = _make_cfg(origins=["GAME", "MSVCRT"])
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any(c == "E006" for _, c, _ in result.errors)

    def test_empty_origins_no_warning(self, tmp_path: Path) -> None:
        """Fresh project with no origins configured should not warn."""
        cfg = _make_cfg(origins=[])
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any(c == "E006" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# E012: Module name doesn't match config.marker
# ---------------------------------------------------------------------------


class TestConfigMarker:
    def test_wrong_module_name(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="SERVER")
        content = """\
// FUNCTION: CLIENT 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any(c == "E012" for _, c, _ in result.errors)

    def test_correct_module_name(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="SERVER")
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any(c == "E012" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# E013: Duplicate VA detection
# ---------------------------------------------------------------------------


class TestDuplicateVA:
    def test_duplicate_va_detected(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _write_c(tmp_path, "first.c", VALID_HEADER)
        f2 = _write_c(tmp_path, "second.c", VALID_HEADER)

        r1 = lint_file(f1, seen_vas=seen_vas)
        r2 = lint_file(f2, seen_vas=seen_vas)

        # First file: no duplicate
        assert not any(c == "E013" for _, c, _ in r1.errors)
        # Second file: duplicate detected
        assert any(c == "E013" for _, c, _ in r2.errors)

    def test_different_vas_no_duplicate(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        content2 = VALID_HEADER.replace("0x10008880", "0x10009999")
        f1 = _write_c(tmp_path, "first.c", VALID_HEADER)
        f2 = _write_c(tmp_path, "second.c", content2)

        r1 = lint_file(f1, seen_vas=seen_vas)
        r2 = lint_file(f2, seen_vas=seen_vas)

        assert not any(c == "E013" for _, c, _ in r1.errors)
        assert not any(c == "E013" for _, c, _ in r2.errors)


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------


class TestWarnings:
    def test_w001_missing_symbol(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W001" for _, c, _ in result.warnings)

    def test_w002_old_format(self, tmp_path: Path) -> None:
        content = "/* func @ 0x10001000 (100B) - /O2 - EXACT [GAME] */\nint x;\n"
        f = _write_c(tmp_path, "func.c", content)
        result = lint_file(f)
        assert any(c == "W002" for _, c, _ in result.warnings)

    def test_w003_no_code(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _foo
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W003" for _, c, _ in result.warnings)

    def test_e015_marker_origin_mismatch(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: MSVCRT
// SIZE: 31
// CFLAGS: /O2
// SYMBOL: _foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E015" for _, c, _ in result.errors)

    def test_w005_stub_without_blocker(self, tmp_path: Path) -> None:
        content = """\
// STUB: SERVER 0x10008880
// STATUS: STUB
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2
// SYMBOL: _foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W005" for _, c, _ in result.warnings)

    def test_w006_library_without_source(self, tmp_path: Path) -> None:
        content = """\
// LIBRARY: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: MSVCRT
// SIZE: 31
// CFLAGS: /O1
// SYMBOL: _crt_foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "crt_foo.c", content)
        result = lint_file(f)
        assert any(c == "W006" for _, c, _ in result.warnings)

    def test_e016_filename_mismatch(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "wrong_name.c", VALID_HEADER)
        result = lint_file(f)
        assert any(c == "E016" for _, c, _ in result.errors)

    def test_e017_contradictory_matching_stub(self, tmp_path: Path) -> None:
        content = """\
// STUB: SERVER 0x10008880
// STATUS: MATCHING
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2
// SYMBOL: _foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E017" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# W008: CFLAGS preset mismatch
# ---------------------------------------------------------------------------


class TestCflagsPreset:
    def test_w008_cflags_mismatch(self, tmp_path: Path) -> None:
        cfg = _make_cfg(cflags_presets={"GAME": "/O2 /Gd"})
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O1
// SYMBOL: _foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any(c == "W008" for _, c, _ in result.warnings)

    def test_w008_cflags_matching_no_warning(self, tmp_path: Path) -> None:
        cfg = _make_cfg(cflags_presets={"GAME": "/O2 /Gd"})
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any(c == "W008" for _, c, _ in result.warnings)


# ---------------------------------------------------------------------------
# LintResult.to_dict (JSON output)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# No-config graceful fallback
# ---------------------------------------------------------------------------


class TestNoConfig:
    def test_lint_without_config(self, tmp_path: Path) -> None:
        """Config-aware checks should not fire when cfg is None."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=None)
        assert result.passed
        assert not any(c in ("E011", "E012") for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# W012: Block-comment format
# ---------------------------------------------------------------------------


class TestBlockCommentFormat:
    def test_w012_block_comment_detected(self, tmp_path: Path) -> None:
        content = """\
/* FUNCTION: SERVER 0x10003260 */
/* STATUS: MATCHING */
/* ORIGIN: GAME */
/* SIZE: 183 */
/* CFLAGS: /O2 /Gd */
/* SYMBOL: _AnalyzeInstruction */
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "_AnalyzeInstruction.c", content)
        result = lint_file(f)
        assert any(c == "W012" for _, c, _ in result.warnings)

    def test_block_comment_validates_keys(self, tmp_path: Path) -> None:
        """Block-comment format should still validate fields."""
        content = """\
/* FUNCTION: SERVER 0x10003260 */
/* STATUS: BOGUS */
/* ORIGIN: GAME */
/* SIZE: 183 */
/* CFLAGS: /O2 /Gd */
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E004" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# W013: Javadoc format
# ---------------------------------------------------------------------------


class TestJavadocFormat:
    def test_w013_javadoc_detected(self, tmp_path: Path) -> None:
        content = """\
/**
 * @brief Core logging function
 * @address 0x10003640
 * @size 132
 * @cflags /O2 /Gd
 * @symbol _LogMessageInternal
 * @origin GAME
 * @status RELOC
 */

int LogMessageInternal(void) { return 0; }
"""
        f = _write_c(tmp_path, "_LogMessageInternal.c", content)
        result = lint_file(f)
        assert any(c == "W013" for _, c, _ in result.warnings)

    def test_javadoc_validates_fields(self, tmp_path: Path) -> None:
        """Javadoc format should still report missing required fields."""
        content = """\
/**
 * @address 0x10003640
 * @origin GAME
 */

int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # STATUS should default to RELOC but SIZE and CFLAGS should be missing
        assert any(c == "E007" for _, c, _ in result.errors)  # missing SIZE
        assert any(c == "E009" for _, c, _ in result.errors)  # missing CFLAGS


# ---------------------------------------------------------------------------
# E014: Corrupted annotation values
# ---------------------------------------------------------------------------


class TestCorruptedAnnotation:
    def test_e014_literal_backslash_n(self, tmp_path: Path) -> None:
        content = (
            "// LIBRARY: SERVER 0x1001cd57\n"
            "// STATUS: EXACT\\n// ORIGIN: MSVCRT\n"
            "// SIZE: 40\n"
            "// CFLAGS: /O1\n"
            "// SYMBOL: _format_digits\n"
            "int foo(void) { return 0; }\n"
        )
        f = _write_c(tmp_path, "format_digits.c", content)
        result = lint_file(f)
        assert any(c == "E014" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# W014: Filename/ORIGIN prefix mismatch
# ---------------------------------------------------------------------------


class TestOriginPrefix:
    def test_w014_crt_prefix_game_origin(self, tmp_path: Path) -> None:
        """File named `crt_foo.c` with ORIGIN: GAME should warn."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _crt_foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "crt_foo.c", content)
        result = lint_file(f)
        assert any(c == "W014" for _, c, _ in result.warnings)

    def test_w014_crt_prefix_msvcrt_ok(self, tmp_path: Path) -> None:
        """File named `crt_foo.c` with ORIGIN: MSVCRT should not warn."""
        content = """\
// LIBRARY: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: MSVCRT
// SIZE: 31
// CFLAGS: /O1
// SYMBOL: _crt_foo
// SOURCE: foo.c
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "crt_foo.c", content)
        result = lint_file(f)
        assert not any(c == "W014" for _, c, _ in result.warnings)

    def test_w014_zlib_prefix_game_origin(self, tmp_path: Path) -> None:
        """File named `zlib_foo.c` with ORIGIN: GAME should warn."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _zlib_foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "zlib_foo.c", content)
        result = lint_file(f)
        assert any(c == "W014" for _, c, _ in result.warnings)


# ---------------------------------------------------------------------------
# W015: VA hex case
# ---------------------------------------------------------------------------


class TestVAHexCase:
    def test_w015_mixed_case_va(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x1000AbCd
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _foo
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W015" for _, c, _ in result.warnings)

    def test_w015_consistent_lowercase(self, tmp_path: Path) -> None:
        """All-lowercase VA should not warn."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert not any(c == "W015" for _, c, _ in result.warnings)

    def test_w015_consistent_uppercase(self, tmp_path: Path) -> None:
        """All-uppercase VA should not warn."""
        content = VALID_HEADER.replace("0x10008880", "0x10008ABF")
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert not any(c == "W015" for _, c, _ in result.warnings)


# ---------------------------------------------------------------------------
# SKIP key should not fire E010
# ---------------------------------------------------------------------------


class TestSkipKey:
    def test_skip_key_not_unknown(self, tmp_path: Path) -> None:
        content = """\
// LIBRARY: SERVER 0x1001b8a5
// STATUS: MATCHING
// SKIP: xor edi,edi after call
// ORIGIN: MSVCRT
// SIZE: 11
// CFLAGS: /O1
// SYMBOL: _foo
// SOURCE: foo.c
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any(c == "E010" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# fix_file: block-comment and javadoc
# ---------------------------------------------------------------------------


class TestFixFile:
    def test_fix_block_comment(self, tmp_path: Path) -> None:
        from rebrew.lint import fix_file

        cfg = _make_cfg()
        content = """\
/* FUNCTION: SERVER 0x10003260 */
/* STATUS: MATCHING */
/* ORIGIN: GAME */
/* SIZE: 183 */
/* CFLAGS: /O2 /Gd */
/* SYMBOL: _AnalyzeInstruction */
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "test.c", content)
        assert fix_file(cfg, f)

        fixed_text = f.read_text(encoding="utf-8")
        assert fixed_text.startswith("// FUNCTION: SERVER")
        assert "// STATUS: MATCHING" in fixed_text
        assert "int foo(void)" in fixed_text

    def test_fix_javadoc(self, tmp_path: Path) -> None:
        from rebrew.lint import fix_file

        cfg = _make_cfg()
        content = """\
/**
 * @brief Core logging function
 * @address 0x10003640
 * @size 132
 * @cflags /O2 /Gd
 * @symbol _LogMessageInternal
 * @origin GAME
 * @status RELOC
 */

int LogMessageInternal(void) { return 0; }
"""
        f = _write_c(tmp_path, "test.c", content)
        assert fix_file(cfg, f)

        fixed_text = f.read_text(encoding="utf-8")
        assert fixed_text.startswith("// FUNCTION: SERVER")
        assert "// STATUS: RELOC" in fixed_text
        assert "int LogMessageInternal" in fixed_text
