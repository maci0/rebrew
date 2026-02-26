"""Deep tests for rebrew.lint — exercising edge cases in lint_file and LintResult."""

from pathlib import Path

from rebrew.config import ProjectConfig
from rebrew.lint import lint_file


def _write(tmp_path, name, content) -> Path:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


# -------------------------------------------------------------------------
# Edge cases for lint_file
# -------------------------------------------------------------------------


class TestLintFileEdgeCases:
    def test_unreadable_file(self, tmp_path) -> None:
        f = tmp_path / "unreadable.c"
        f.write_text("data", encoding="utf-8")
        f.chmod(0o000)
        result = lint_file(f)
        assert not result.passed
        f.chmod(0o644)  # cleanup

    def test_old_format_header(self, tmp_path) -> None:
        # Old single-line format: /* name @ 0xVA (NB) - /flags - STATUS [ORIGIN] */
        f = _write(
            tmp_path,
            "old.c",
            "/* my_func @ 10001000 (64) - /O2 /Gd - matching [GAME] */\nvoid my_func() {}\n",
        )
        result = lint_file(f)
        # Should detect old format as W002 or reject as E001
        has_old_warning = any(code == "W002" for _, code, _ in result.warnings)
        has_missing_error = any(code == "E001" for _, code, _ in result.errors)
        assert has_old_warning or has_missing_error

    def test_block_comment_format(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "block.c",
            "/* FUNCTION: SERVER 0x10001000 */\n"
            "/* STATUS: STUB */\n"
            "/* ORIGIN: GAME */\n"
            "/* SIZE: 64 */\n"
            "/* CFLAGS: /O2 /Gd */\n"
            "/* SYMBOL: _my_func */\n"
            "void __cdecl _my_func(void) {}\n",
        )
        result = lint_file(f)
        # Should detect block-comment format (W012)
        assert any(code == "W012" for _, code, _ in result.warnings)

    def test_javadoc_format(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "javadoc.c",
            "/**\n"
            " * @address 0x10001000\n"
            " * @status STUB\n"
            " * @origin GAME\n"
            " * @size 64\n"
            " * @cflags /O2 /Gd\n"
            " * @symbol _my_func\n"
            " */\n"
            "void __cdecl _my_func(void) {}\n",
        )
        result = lint_file(f)
        # Should detect javadoc format (W013)
        assert any(code == "W013" for _, code, _ in result.warnings)

    def test_invalid_va(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "bad_va.c",
            "// FUNCTION: SERVER BADADDR\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert not result.passed

    def test_suspicious_va(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "sus_va.c",
            "// FUNCTION: SERVER 0x0001\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        # VA 0x0001 is below 0x1000 = suspicious
        assert any(code == "E002" for _, code, _ in result.errors)

    def test_missing_status(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "no_status.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert any(code == "E003" for _, code, _ in result.errors)

    def test_missing_origin(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "no_origin.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert any(code == "E005" for _, code, _ in result.errors)

    def test_invalid_origin(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "bad_origin.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: INVALID\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert any(code == "E006" for _, code, _ in result.errors)

    def test_invalid_size_negative(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "neg_size.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: -1\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert any(code == "E008" for _, code, _ in result.errors)

    def test_invalid_size_text(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "text_size.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: notanumber\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert any(code == "E008" for _, code, _ in result.errors)

    def test_missing_cflags(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "no_cflags.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert any(code == "E009" for _, code, _ in result.errors)

    def test_unknown_annotation_key(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "unk_key.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "// BADKEY: some value\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        # Unknown annotation key should produce E010
        assert any(code == "E010" for _, code, _ in result.errors)

    def test_duplicate_va_tracking(self, tmp_path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _write(
            tmp_path,
            "f1.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f1\n"
            "void _f1() {}\n",
        )
        f2 = _write(
            tmp_path,
            "f2.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f2\n"
            "void _f2() {}\n",
        )
        lint_file(f1, seen_vas=seen_vas)
        result2 = lint_file(f2, seen_vas=seen_vas)
        assert any(code == "E013" for _, code, _ in result2.errors)

    def test_struct_without_size(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "struct.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "typedef struct {\n"
            "    int x;\n"
            "} MyStruct;\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        # W007: struct without SIZE annotation
        assert any(code == "W007" for _, code, _ in result.warnings)

    def test_stub_without_blocker(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "stub.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        assert any(code == "W005" for _, code, _ in result.warnings)

    def test_crt_without_source(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "crt.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: MSVCRT\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        # W006: MSVCRT without SOURCE
        assert any(code == "W006" for _, code, _ in result.warnings)

    def test_file_with_no_code(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "header_only.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n",
        )
        result = lint_file(f)
        # W003: File has no function implementation
        assert any(code == "W003" for _, code, _ in result.warnings)

    def test_config_module_mismatch(self, tmp_path) -> None:
        cfg = ProjectConfig(
            root=Path("/tmp"),
            origins=["GAME", "MSVCRT"],
            cflags_presets={"GAME": "/O2 /Gd"},
            marker="GAME_DLL",
        )
        f = _write(
            tmp_path,
            "mismatch.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f, cfg=cfg)
        # E012: module mismatch
        assert any(code == "E012" for _, code, _ in result.errors)

    def test_config_cflags_mismatch(self, tmp_path) -> None:
        cfg = ProjectConfig(
            root=Path("/tmp"),
            origins=["GAME"],
            cflags_presets={"GAME": "/O2 /Gd"},
            marker="SERVER",
        )
        f = _write(
            tmp_path,
            "cflags_diff.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O1\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f, cfg=cfg)
        # W008: CFLAGS mismatch
        assert any(code == "W008" for _, code, _ in result.warnings)

    def test_corrupted_status_newline(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "corrupted.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\\nGARBAGE\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        # E014 or E004: corrupted status
        assert not result.passed

    def test_to_dict_roundtrip(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "f.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _f\n"
            "void _f() {}\n",
        )
        result = lint_file(f)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["passed"] is True
        assert len(d["errors"]) == 0
