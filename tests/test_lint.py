"""Tests for the rebrew annotation linter."""

from pathlib import Path
from types import SimpleNamespace

from rebrew.config import ProjectConfig
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
    base_cflags: str = "/nologo /c /MT",
    library_modules: set | None = None,
) -> SimpleNamespace:
    """Create a minimal config-like namespace for config-aware lint tests."""
    return ProjectConfig(
        root=Path("/tmp"),
        marker=marker,
        base_cflags=base_cflags,
        library_modules=library_modules or set(),
    )


VALID_HEADER = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT

int __cdecl bit_reverse(int x)
{
    return x;
}
"""

VALID_LIBRARY_HEADER = """\
// STUB: SERVER 0x10023714
// STATUS: STUB

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
        """With a config providing base_cflags, a clean file has no warnings."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        cfg = _make_cfg()  # base_cflags is set — no W018, and no inline rebrew keys
        result = lint_file(f, cfg=cfg)
        # W019: CFLAGS inline is expected since VALID_HEADER still has inline CFLAGS;
        # this test ensures no OTHER warnings besides W019.
        non_w019 = [w for w in result.warnings if w[1] != "W019"]
        assert non_w019 == []

    def test_valid_library_no_errors(self, tmp_path: Path) -> None:
        cfg = _make_cfg()
        f = _write_c(tmp_path, "copy_environ.c", VALID_LIBRARY_HEADER)
        result = lint_file(f, cfg=cfg)
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
// SIZE: 10
// CFLAGS: /O2 /Gd
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E002" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# E003-E008: Missing/invalid fields
# ---------------------------------------------------------------------------


class TestMissingFields:
    def test_missing_status(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
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
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E004" for _, c, _ in result.errors)

    def test_missing_origin_no_error_when_module_present(self, tmp_path: Path) -> None:
        """ORIGIN is optional when FUNCTION: MODULE field is present — no E005 error."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # ORIGIN is derivable from MODULE (SERVER) — no error
        assert not any(c == "E005" for _, c, _ in result.errors)
        # (W019 fires for the inline CFLAGS — that's expected)

    def test_invalid_status_broken_value(self, tmp_path: Path) -> None:
        """An unknown STATUS value (BROKEN) should produce an error."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: BROKEN
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c in ("E003", "E004") for _, c, _ in result.errors)

    def test_missing_size_no_error(self, tmp_path: Path) -> None:
        """// SIZE: is no longer required in source — SIZE lives in the sidecar."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # No E007 error — SIZE is sidecar-only, not required in source
        assert not any(c == "E007" for _, c, _ in result.errors)

    def test_invalid_size_in_source_no_error(self, tmp_path: Path) -> None:
        """A // SIZE: -5 in source no longer triggers E008 (SIZE is sidecar-only)."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: -5
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # No E008 error — the lint no longer validates inline SIZE values
        assert not any(c == "E008" for _, c, _ in result.errors)

    def test_missing_cflags_no_config(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # No cfg and no annotation CFLAGS → W018 warning
        assert any(c == "W018" for _, c, _ in result.warnings)

    def test_missing_cflags_with_config_default(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        cfg = _make_cfg()  # base_cflags defaults to "/nologo /c /MT"
        result = lint_file(f, cfg=cfg)
        # Config has default cflags → no W018
        assert not any(c == "W018" for _, c, _ in result.warnings)


# ---------------------------------------------------------------------------
# W010: Unknown keys (downgraded from E010)
# ---------------------------------------------------------------------------


class TestUnknownKeys:
    def test_unknown_annotation_key(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2
// FLAVOR: vanilla
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W010" for _, c, _ in result.warnings)


# ---------------------------------------------------------------------------
# E011: ORIGIN not in config.origins
# ---------------------------------------------------------------------------


class TestConfigMarkerValidation:
    def test_wrong_module_raises_no_error_without_cfg(self, tmp_path: Path) -> None:
        """Without cfg, module is not validated against marker."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any(c == "E006" for _, c, _ in result.errors)

    def test_valid_function_with_cfg_no_errors(self, tmp_path: Path) -> None:
        cfg = _make_cfg()
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
        """W001 is no longer emitted — SYMBOL is derived from C function definitions."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2 /Gd
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # W001 was removed: symbol is now derived from C function definitions
        assert not any(c == "W001" for _, c, _ in result.warnings)

    def test_w002_old_format(self, tmp_path: Path) -> None:
        content = "/* func @ 0x10001000 (100B) - /O2 - EXACT [GAME] */\nint x;\n"
        f = _write_c(tmp_path, "func.c", content)
        result = lint_file(f)
        assert any(c == "W002" for _, c, _ in result.warnings)

    def test_w003_no_code(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2 /Gd
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W003" for _, c, _ in result.warnings)

    def test_e015_marker_origin_mismatch(self, tmp_path: Path) -> None:
        """FUNCTION marker with library module should trigger E015 (should be LIBRARY)."""
        cfg = _make_cfg(library_modules={"SERVER"})
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any(c == "E015" for _, c, _ in result.errors)

    def test_w005_stub_without_blocker(self, tmp_path: Path) -> None:
        content = """\
// STUB: SERVER 0x10008880
// STATUS: STUB
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W005" for _, c, _ in result.warnings)

    def test_w006_library_without_source(self, tmp_path: Path) -> None:
        """Library module without SOURCE annotation should trigger W006."""
        cfg = _make_cfg(library_modules={"SERVER"})
        content = """\
// LIBRARY: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O1
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "crt_foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any(c == "W006" for _, c, _ in result.warnings)

    def test_e017_contradictory_matching_stub(self, tmp_path: Path) -> None:
        content = """\
// STUB: SERVER 0x10008880
// STATUS: MATCHING
// SIZE: 31
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E017" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# W008: CFLAGS preset mismatch
# ---------------------------------------------------------------------------


class TestCflagsPreset:
    def test_invalid_annotation_key_no_error_for_valid(self, tmp_path: Path) -> None:
        """Valid annotations should not produce unknown-key warnings."""
        cfg = _make_cfg()
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any(c == "W010" for _, c, _ in result.warnings)

    def test_annotation_with_cflags_fires_w019(self, tmp_path: Path) -> None:
        """Inline // CFLAGS: fires W019 since CFLAGS is a sidecar-only key."""
        cfg = _make_cfg()
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// CFLAGS: /O1
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        # CFLAGS is a sidecar key; inline occurrence fires W019
        assert any(c == "W019" for _, c, _ in result.warnings)
        # But no W010 (it is still a known key)
        assert not any(c == "W010" for _, c, _ in result.warnings)


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
        # STATUS defaults to RELOC — no error. SIZE is sidecar-only, no E007.
        assert not any(c == "E007" for _, c, _ in result.errors)
        # CFLAGS is optional — handled by W018 warning, not an error


# ---------------------------------------------------------------------------
# E014: Corrupted annotation values
# ---------------------------------------------------------------------------


class TestCorruptedAnnotation:
    def test_e014_literal_backslash_n(self, tmp_path: Path) -> None:
        content = (
            "// LIBRARY: SERVER 0x1001cd57\n"
            "// STATUS: EXACT\\n"
            "// SIZE: 40\n"
            "// CFLAGS: /O1\n"
            "// SYMBOL: _format_digits\n"
            "int foo(void) { return 0; }\n"
        )
        f = _write_c(tmp_path, "format_digits.c", content)
        result = lint_file(f)
        assert any(c == "E014" for _, c, _ in result.errors)


# ---------------------------------------------------------------------------
# W015: VA hex case
# ---------------------------------------------------------------------------


class TestVAHexCase:
    def test_w015_mixed_case_va(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x1000AbCd
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2 /Gd
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
# SKIP key should not fire W010
# ---------------------------------------------------------------------------


class TestSkipKey:
    def test_skip_key_fires_w019(self, tmp_path: Path) -> None:
        """Inline // SKIP: is a sidecar key and now fires W019 (not W010)."""
        content = """\
// LIBRARY: SERVER 0x1001b8a5
// STATUS: MATCHING
// SKIP: xor edi,edi after call
// CFLAGS: /O1
// SOURCE: foo.c
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # W010 (unknown key) should NOT fire — SKIP/SOURCE/CFLAGS are known keys
        assert not any(c == "W010" for _, c, _ in result.warnings)
        # W019 SHOULD fire for each inline sidecar key
        w019 = [msg for _, c, msg in result.warnings if c == "W019"]
        assert any("SKIP" in m for m in w019)
        assert any("CFLAGS" in m for m in w019)
        assert any("SOURCE" in m for m in w019)


# ---------------------------------------------------------------------------
# W016: DATA/GLOBAL missing SECTION
# ---------------------------------------------------------------------------


class TestW016Section:
    def test_w016_global_missing_section(self, tmp_path: Path) -> None:
        content = """\
// GLOBAL: SERVER 0x10050000
// SIZE: 4
int g_foo;
"""
        f = _write_c(tmp_path, "g_foo.c", content)
        result = lint_file(f)
        assert any(c == "W016" for _, c, _ in result.warnings)

    def test_w016_data_missing_section(self, tmp_path: Path) -> None:
        content = """\
// DATA: SERVER 0x10050000
// SIZE: 10
char s_hello[] = "hello";
"""
        f = _write_c(tmp_path, "s_hello.c", content)
        result = lint_file(f)
        assert any(c == "W016" for _, c, _ in result.warnings)

    def test_w016_global_with_section_no_warning(self, tmp_path: Path) -> None:
        """SECTION from the sidecar should suppress W016 without inline SECTION."""
        content = """\
// GLOBAL: SERVER 0x10050000
// SIZE: 4
int g_foo;
"""
        # Write the sidecar with SECTION set using the canonical TOML key format
        sidecar = tmp_path / "rebrew-functions.toml"
        sidecar.write_text(
            '["SERVER.0x10050000"]\nsection = ".bss"\n',
            encoding="utf-8",
        )
        f = _write_c(tmp_path, "g_foo.c", content)
        result = lint_file(f)
        assert not any(c == "W016" for _, c, _ in result.warnings)
        # Also: no inline SECTION key → no W019 for SECTION
        assert not any("SECTION" in m for _, c, m in result.warnings if c == "W019")

    def test_w016_function_no_warning(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert not any(c == "W016" for _, c, _ in result.warnings)


# ---------------------------------------------------------------------------
# W017: NOTE starts with [rebrew]
# ---------------------------------------------------------------------------


class TestW017NoteRebrew:
    def test_w017_rebrew_prefix_in_note(self, tmp_path: Path) -> None:
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2 /Gd
// NOTE: [rebrew] FUNCTION: EXACT

int __cdecl bit_reverse(int x)
{
    return x;
}
"""
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert any(c == "W017" for _, c, _ in result.warnings)

    def test_w017_normal_note_no_warning(self, tmp_path: Path) -> None:
        """A normal NOTE inline fires W019 but not W017."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// NOTE: This handles player initialization

int __cdecl bit_reverse(int x)
{
    return x;
}
"""
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert not any(c == "W017" for _, c, _ in result.warnings)
        # NOTE is a sidecar key; it fires W019 since it's inline
        assert any(c == "W019" and "NOTE" in m for _, c, m in result.warnings)

    def test_w017_no_note_no_warning(self, tmp_path: Path) -> None:
        """A file with no NOTE inline and no W019 for NOTE."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT

int __cdecl bit_reverse(int x)
{
    return x;
}
"""
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert not any(c == "W017" for _, c, _ in result.warnings)
        assert not any("NOTE" in m for _, c, m in result.warnings if c == "W019")


# ---------------------------------------------------------------------------
# W019: Inline sidecar key
# ---------------------------------------------------------------------------


class TestW019InlineSidecarKeys:
    def test_w019_inline_cflags(self, tmp_path: Path) -> None:
        """Inline // CFLAGS: fires W019."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// CFLAGS: /O2
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W019" and "CFLAGS" in m for _, c, m in result.warnings)

    def test_w019_inline_skip(self, tmp_path: Path) -> None:
        """Inline // SKIP: fires W019."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SKIP: not matchable
int foo(void) { return 0; }
"""
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "W019" and "SKIP" in m for _, c, m in result.warnings)

    def test_w019_not_for_sidecar_sourced_key(self, tmp_path: Path) -> None:
        """A CFLAGS value from the sidecar should NOT fire W019."""
        content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
int foo(void) { return 0; }
"""
        # Write a sidecar with CFLAGS for this VA
        sidecar = tmp_path / "rebrew-functions.toml"
        sidecar.write_text(
            '[SERVER."0x10008880"]\ncflags = "/O2"\n',
            encoding="utf-8",
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        # No W019 since CFLAGS came from sidecar, not inline
        assert not any(c == "W019" and "CFLAGS" in m for _, c, m in result.warnings)


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
