"""Deep tests for rebrew.lint — exercising edge cases in lint_file and LintResult."""

from pathlib import Path

import pytest
from source_util import SourceFixture, write_source

from rebrew.config import ProjectConfig
from rebrew.lint import lint_file


def _write(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    write_source(f, content, encoding="utf-8")
    return f


class TestLintFileEdgeCases:
    def test_unreadable_file(self, tmp_path: Path) -> None:
        """An unreadable file reports E000, not the E001 a plain missing
        annotation header would give. A directory named `unreadable.c` raises
        the read error on every runner; chmod 0 does not, because root
        bypasses the permission bits."""
        f = tmp_path / "unreadable.c"
        f.mkdir()
        result = lint_file(f)
        assert not result.passed
        assert [code for _line, code, _msg in result.errors] == ["E000"], result.errors
        assert "Cannot read file" in result.errors[0][2]

    def test_old_format_header(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "old.c",
            "/* my_func @ 10001000 (64) - /O2 /Gd - matching [GAME] */\nvoid my_func() {}\n",
        )
        result = lint_file(f)
        # The legacy block header is not a recognized annotation form.
        assert [code for _, code, _ in result.errors] == ["E001"]
        assert result.warnings == []

    def test_invalid_va(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "bad_va.c",
            "// FUNCTION: SERVER BADADDR\n// STATUS: STUB\n// ORIGIN: GAME\n// SIZE: 64\n// CFLAGS: /O2\n// SYMBOL: _f\nvoid _f() {}\n",
        )
        result = lint_file(f)
        assert not result.passed

    def test_suspicious_va(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "sus_va.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x0001 */\n\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x0001": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2",
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert any((code == "E002" for _, code, _ in result.errors))

    def test_missing_origin(self, tmp_path: Path) -> None:
        # Verifies missing ORIGIN is not flagged as an error
        f = _write(
            tmp_path,
            "no_origin.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2",
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert not any((code == "E005" for _, code, _ in result.errors))

    def test_invalid_size_text(self, tmp_path: Path) -> None:
        # Verifies text SIZE does not trigger this specific error
        f = _write(
            tmp_path,
            "text_size.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert not any((code == "E008" for _, code, _ in result.errors))

    def test_missing_cflags(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "no_cflags.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert any((code == "W018" for _, code, _ in result.warnings))

    def test_unknown_annotation_key(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "unk_key.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\n// BADKEY: some value\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert not any((code == "W010" for _, code, _ in result.warnings))

    def test_duplicate_va_tracking(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _write(
            tmp_path,
            "f1.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid _f1() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f1",
                        "status": "EXACT",
                    }
                },
            ),
        )
        f2 = _write(
            tmp_path,
            "f2.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid _f2() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f2",
                        "status": "EXACT",
                    }
                },
            ),
        )
        lint_file(f1, seen_vas=seen_vas)
        result2 = lint_file(f2, seen_vas=seen_vas)
        assert any((code == "E013" for _, code, _ in result2.errors))

    def test_struct_without_size_comment(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "struct.c",
            SourceFixture(
                "\n\n\n\n\n\ntypedef struct {\n    int x;\n} MyStruct;\n/* ADDRESS: SERVER 0x10001000 */\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert not any((code == "W007" for _, code, _ in result.warnings))

    def test_stub_without_blocker(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "stub.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert any((code == "W005" for _, code, _ in result.warnings))

    def test_crt_without_source(self, tmp_path: Path) -> None:
        """Library module without SOURCE triggers W006 when cfg identifies it as library."""
        cfg = ProjectConfig(root=tmp_path, library_modules={"SERVER"})
        f = _write(
            tmp_path,
            "crt.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "EXACT",
                    }
                },
            ),
        )
        result = lint_file(f, cfg=cfg)
        assert any((code == "W006" for _, code, _ in result.warnings))

    def test_file_with_no_code(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "header_only.c",
            SourceFixture(
                "\n\n\n\n\n\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert any((code == "W003" for _, code, _ in result.warnings))

    def test_config_module_mismatch(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, marker="GAME_DLL")
        f = _write(
            tmp_path,
            "mismatch.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "EXACT",
                    }
                },
            ),
        )
        result = lint_file(f, cfg=cfg)
        assert any((code == "E012" for _, code, _ in result.errors))

    def test_config_marker_match(self, tmp_path: Path) -> None:
        """Matching module to cfg.marker produces no E012 error."""
        cfg = ProjectConfig(root=tmp_path, marker="SERVER")
        f = _write(
            tmp_path,
            "cflags_diff.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O1",
                        "symbol": "_f",
                        "status": "EXACT",
                    }
                },
            ),
        )
        result = lint_file(f, cfg=cfg)
        assert not any((code == "E012" for _, code, _ in result.errors))

    def test_to_dict_roundtrip(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "f.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid _f() {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_f",
                        "status": "EXACT",
                    }
                },
            ),
        )
        result = lint_file(f)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["passed"] is True
        assert len(d["errors"]) == 0


class TestBodyRulesFirstLine:
    @pytest.mark.parametrize("has_size", [False, True])
    def test_pure_c_struct_size_comment_is_optional(self, has_size: bool) -> None:
        from rebrew.lint import LintResult, _check_body_rules

        lines = ["typedef struct { int value; } RECORD;"]
        if has_size:
            lines.insert(0, "// SIZE 0x4")
        result = LintResult(Path("record.c"))
        _check_body_rules(result, lines, False)
        warnings = [(line, code) for line, code, _message in result.warnings]
        assert warnings == []
