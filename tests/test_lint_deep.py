"""Deep tests for rebrew.lint — exercising edge cases in lint_file and LintResult."""

from pathlib import Path

from rebrew.config import ProjectConfig
from rebrew.lint import lint_file


def _write(tmp_path, name, content) -> Path:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


class TestLintFileEdgeCases:
    def test_unreadable_file(self, tmp_path) -> None:
        f = tmp_path / "unreadable.c"
        f.write_text("data", encoding="utf-8")
        f.chmod(0)
        result = lint_file(f)
        assert not result.passed
        f.chmod(420)

    def test_old_format_header(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "old.c",
            "/* my_func @ 10001000 (64) - /O2 /Gd - matching [GAME] */\nvoid my_func() {}\n",
        )
        result = lint_file(f)
        has_old_warning = any((code == "W002" for _, code, _ in result.warnings))
        has_missing_error = any((code == "E001" for _, code, _ in result.errors))
        assert has_old_warning or has_missing_error

    def test_invalid_va(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "bad_va.c",
            "// FUNCTION: SERVER BADADDR\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert not result.passed

    def test_suspicious_va(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "sus_va.c",
            "// FUNCTION: SERVER 0x0001\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert any((code == "E002" for _, code, _ in result.errors))

    def test_missing_origin(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "no_origin.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// SIZE: 64\n// CFLAGS: /O2\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert not any((code == "E005" for _, code, _ in result.errors))

    def test_invalid_origin(self, tmp_path) -> None:
        """ORIGIN is metadata-only — triggers W019 (inline metadata); SYMBOL triggers W010."""
        f = _write(
            tmp_path,
            "bad_origin.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: INVALID\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert any((code == "W010" for _, code, _ in result.warnings))

    def test_invalid_size_negative(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "neg_size.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: -1\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert not any((code == "E008" for _, code, _ in result.errors))

    def test_invalid_size_text(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "text_size.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: notanumber\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert not any((code == "E008" for _, code, _ in result.errors))

    def test_missing_cflags(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "no_cflags.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert any((code == "W018" for _, code, _ in result.warnings))

    def test_unknown_annotation_key(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "unk_key.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\n// BADKEY: some value\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert any((code == "W010" for _, code, _ in result.warnings))

    def test_duplicate_va_tracking(self, tmp_path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _write(
            tmp_path,
            "f1.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f1\nvoid _f1() {}\n",
        )
        f2 = _write(
            tmp_path,
            "f2.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f2\nvoid _f2() {}\n",
        )
        lint_file(f1, seen_vas=seen_vas)
        result2 = lint_file(f2, seen_vas=seen_vas)
        assert any((code == "E013" for _, code, _ in result2.errors))

    def test_struct_without_size(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "struct.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\ntypedef struct {\n    int x;\n} MyStruct;\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert any((code == "W007" for _, code, _ in result.warnings))

    def test_stub_without_blocker(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "stub.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert any((code == "W005" for _, code, _ in result.warnings))

    def test_crt_without_source(self, tmp_path) -> None:
        """Library module without SOURCE triggers W006 when cfg identifies it as library."""
        cfg = ProjectConfig(root=Path("/tmp"), library_modules={"SERVER"})
        f = _write(
            tmp_path,
            "crt.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f, cfg=cfg)
        assert any((code == "W006" for _, code, _ in result.warnings))

    def test_file_with_no_code(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "header_only.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\n",
        )
        result = lint_file(f)
        assert any((code == "W003" for _, code, _ in result.warnings))

    def test_config_module_mismatch(self, tmp_path) -> None:
        cfg = ProjectConfig(root=Path("/tmp"), marker="GAME_DLL")
        f = _write(
            tmp_path,
            "mismatch.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f, cfg=cfg)
        assert any((code == "E012" for _, code, _ in result.errors))

    def test_config_marker_match(self, tmp_path) -> None:
        """Matching module to cfg.marker produces no E012 error."""
        cfg = ProjectConfig(root=Path("/tmp"), marker="SERVER")
        f = _write(
            tmp_path,
            "cflags_diff.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 64\n// CFLAGS: /O1\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f, cfg=cfg)
        assert not any((code == "E012" for _, code, _ in result.errors))

    def test_to_dict_roundtrip(self, tmp_path) -> None:
        f = _write(
            tmp_path,
            "f.c",
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2 /Gd\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["passed"] is True
        assert len(d["errors"]) == 0
