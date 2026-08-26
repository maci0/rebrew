"""Tests for fixup.py — compilability fixup for raw decompiler output."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.fixup import app, fixup_source, sanitize_tokens


class TestSanitizeTokens:
    def test_pseudo_types(self) -> None:
        out, changes = sanitize_tokens("undefined4 a;\nundefined1 b;\nbyte c;\nqword d;\n")
        assert "int a;" in out
        assert "char b;" in out
        assert "unsigned char c;" in out
        assert "unsigned long long d;" in out
        assert len(changes) == 4

    def test_pseudo_type_in_cast(self) -> None:
        out, _ = sanitize_tokens("x = *(undefined4 *)ptr;")
        assert "*(int *)ptr" in out

    def test_qualified_symbols(self) -> None:
        out, changes = sanitize_tokens('printf("%s", GLIBC_2.2.5::stderr);')
        assert "GLIBC_2.2.5::stderr" not in out
        assert "stderr" in out
        assert changes  # the qualification change was recorded

    def test_junk_specifiers(self) -> None:
        out, _ = sanitize_tokens("__unaligned int *p;\n__ptr32 int *q;")
        assert "__unaligned" not in out
        assert "__ptr32" not in out

    def test_unchanged_source(self) -> None:
        out, changes = sanitize_tokens("int main(void) { return 0; }\n")
        assert out == "int main(void) { return 0; }\n"
        assert changes == []

    def test_never_raises_on_garbage(self) -> None:
        out, _ = sanitize_tokens("#### not c at all\n")
        assert isinstance(out, str)


class TestFixupSource:
    def test_inject_undeclared_type(self) -> None:
        src = "void f(void) { mytype x; x = 1; }\n"
        result = fixup_source(src, compile_errors="error: unknown type name 'mytype'")
        assert "typedef int mytype;" in result.source
        assert result.injected == ["typedef int mytype;"]

    def test_inject_implicit_function(self) -> None:
        src = "void f(void) { foo(); }\n"
        result = fixup_source(src, compile_errors="warning: implicit declaration of function 'foo'")
        assert "int foo();" in result.source

    def test_no_redefinition_of_declared_symbol(self) -> None:
        src = "int foo(void);\nvoid f(void) { foo(); }\n"
        result = fixup_source(src, compile_errors="implicit declaration of function 'foo'")
        assert "int foo();" not in result.source
        assert result.injected == []

    def test_sanitize_and_inject_compose(self) -> None:
        src = "void f(void) { undefined4 x; bar(x); }\n"
        result = fixup_source(
            src,
            compile_errors="implicit declaration of function 'bar'; unknown type name 'mytype'",
        )
        assert "int x;" in result.source  # sanitized
        assert "int bar();" in result.source  # injected

    def test_no_errors_skips_injection(self) -> None:
        result = fixup_source("int f(void) { return 0; }\n", compile_errors=None)
        assert result.injected == []
        assert result.iterations == 1


class TestFixupCli:
    def _write(self, tmp_path: Path, src: str) -> Path:
        p = tmp_path / "out.c"
        p.write_text(src, encoding="utf-8")
        return p

    def test_writes_fixed_file(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "undefined4 x;\n")
        result = CliRunner().invoke(app, [str(p)])
        assert result.exit_code == 0
        fixed = tmp_path / "out.c.fixed.c"
        assert fixed.exists()
        assert "int x;" in fixed.read_text(encoding="utf-8")

    def test_dry_run_prints_source(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "undefined4 x;\n")
        result = CliRunner().invoke(app, ["--dry-run", str(p)])
        assert result.exit_code == 0
        assert "int x;" in result.output
        assert not (tmp_path / "out.c.fixed.c").exists()

    def test_json_output(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "undefined4 x;\n")
        result = CliRunner().invoke(app, ["--json", str(p)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["changed"] is True
        assert any("undefined4" in c for c in data["changes"])
        assert "wrote" in data

    def test_compile_check_passed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--compile-check compiles the fixed source; success writes and
        reports the green pass."""
        import rebrew.fixup as fixup

        p = self._write(tmp_path, "undefined4 x;\n")
        monkeypatch.setattr(
            fixup, "require_config", lambda target=None, json_mode=False: SimpleNamespace()
        )
        monkeypatch.setattr(fixup, "_compile_check", lambda cfg, text, hint: None)
        result = CliRunner().invoke(app, ["--compile-check", str(p)])
        assert result.exit_code == 0
        assert "compile check passed" in result.output

    def test_compile_check_failure_banners_and_exits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fix that still does not compile must never be shipped silently:
        the decisive error is banner-commented into the output and the exit
        code is nonzero."""
        import rebrew.fixup as fixup

        p = self._write(tmp_path, "undefined4 x;\n")
        monkeypatch.setattr(
            fixup, "require_config", lambda target=None, json_mode=False: SimpleNamespace()
        )
        monkeypatch.setattr(
            fixup, "_compile_check", lambda cfg, text, hint: "syntax error before ';'\nline 3"
        )
        result = CliRunner().invoke(app, ["--compile-check", str(p)])
        assert result.exit_code == 2
        assert "still does not compile" in result.output
        fixed = tmp_path / "out.c.fixed.c"
        text = fixed.read_text(encoding="utf-8")
        assert "first error: syntax error before ';'" in text

    def test_compile_check_failure_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.fixup as fixup

        p = self._write(tmp_path, "undefined4 x;\n")
        monkeypatch.setattr(
            fixup, "require_config", lambda target=None, json_mode=False: SimpleNamespace()
        )
        monkeypatch.setattr(
            fixup, "_compile_check", lambda cfg, text, hint: "error C2065: 'x': undeclared"
        )
        result = CliRunner().invoke(app, ["--compile-check", "--json", str(p)])
        assert result.exit_code == 2
        data = json.loads(result.output)
        assert data["compile_check"] is True
        assert data["compile_error"] == "error C2065: 'x': undeclared"

    def test_missing_file_errors(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(app, [str(tmp_path / "nope.c")])
        assert result.exit_code == 2
        assert "not found" in result.output
