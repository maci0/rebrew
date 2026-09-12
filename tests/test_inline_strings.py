"""Tests for rebrew inline-strings (string-literal global materialization)."""

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.inline_strings import c_literal, inline_string_uses


class TestCLiteral:
    def test_plain(self) -> None:
        assert c_literal(b"hello") == '"hello"'

    def test_escapes(self) -> None:
        assert c_literal(b'a"b\\c') == '"a\\"b\\\\c"'

    def test_octal_fixed_width(self) -> None:
        assert c_literal(b"\x01\xff") == '"\\001\\377"'


SRC = "// FUNCTION: TEST 0x1000\nint f(void) { return s_foo_10027000[0]; }\n"


def _token_re() -> re.Pattern[str]:
    return re.compile(r"\bs_[A-Za-z0-9_]+_([0-9a-fA-F]{6,8})\b")


class TestInlineUses:
    def test_inlines_string(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text(SRC, encoding="utf-8")
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 1
        assert 'return "hello"[0];' in f.read_text()

    def test_dry_run(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text(SRC, encoding="utf-8")
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=True)
        assert n == 1
        assert "s_foo_10027000" in f.read_text()

    def test_skips_asm_and_extern(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text(
            "// FUNCTION: TEST 0x1000\n"
            "extern char s_foo_10027000[];\n"
            "int f(void) {\n"
            "    __asm { push offset s_foo_10027000 }\n"
            "    return 0;\n"
            "}\n",
            encoding="utf-8",
        )
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 0  # asm + extern only — nothing inlinable
        assert "s_foo_10027000" in f.read_text()

    def test_token_inside_string_literal_not_rewritten(self, tmp_path: Path) -> None:
        """A token inside a C string literal is not a replaceable use: inlining
        it nested quotes and produced invalid C."""
        f = tmp_path / "a.c"
        f.write_text(
            '// FUNCTION: TEST 0x1000\nchar *m = "use s_foo_10027000 here";\n',
            encoding="utf-8",
        )
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 0
        assert "s_foo_10027000" in f.read_text()

    def test_real_use_after_string_with_slashes_is_inlined(self, tmp_path: Path) -> None:
        """A `//` inside a string literal used to start a comment mask, hiding a
        real token use later on the same line."""
        f = tmp_path / "a.c"
        f.write_text(
            '// FUNCTION: TEST 0x1000\nchar *u = "http://x"; int g = s_foo_10027000[0];\n',
            encoding="utf-8",
        )
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 1
        text = f.read_text()
        assert '"http://x"' in text  # the literal is untouched
        assert 'int g = "hello"[0];' in text

    def test_unknown_addr_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text(SRC.replace("10027000", "10028000"), encoding="utf-8")
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 0


class TestDefineRemaining:
    def test_owner_chosen_by_real_uses_not_extern_or_comments(self, tmp_path: Path) -> None:
        """The owner is the file with the most non-extern uses: extern lines and
        comment mentions must not outvote the single real use."""
        from rebrew.inline_strings import define_remaining_strings

        a = tmp_path / "a.c"
        a.write_text(
            "// FUNCTION: TEST 0x1000\n"
            "extern char s_msg_10027000[];\n"
            "// mentions s_msg_10027000 twice: s_msg_10027000\n"
            "int a(void) { return 0; }\n",
            encoding="utf-8",
        )
        b = tmp_path / "b.c"
        b.write_text(
            "// FUNCTION: TEST 0x2000\n"
            "extern char s_msg_10027000[];\n"
            "int b(void) { return s_msg_10027000[0]; }\n",
            encoding="utf-8",
        )
        n = define_remaining_strings([a, b], b"hi\x00", 0x10027000, _token_re(), dry_run=False)
        assert n == 1
        assert 'char s_msg_10027000[3] = "hi";' in b.read_text()
        assert "char s_msg_10027000[3]" not in a.read_text()

    def _cfg(self, tmp_path: Path) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src",
            target_binary=tmp_path / "original" / "x.dll",
            marker="TEST",
        )

    def test_defines_asm_referenced_string(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.inline_strings import app

        (tmp_path / "src").mkdir(parents=True)
        src = tmp_path / "src" / "a.c"
        src.write_text(
            "// FUNCTION: TEST 0x1000\n"
            "extern char s_msg_10027000[];\n"
            "int f(void) {\n"
            "    __asm { push offset s_msg_10027000 }\n"
            "    return 0;\n"
            "}\n",
            encoding="utf-8",
        )
        # reference binary: .data raw "hi\x00" at data_base 0x10027000

        from test_data_layout import _make_pe, _write_layout

        raw = b"hi\x00"
        (tmp_path / "original").mkdir()
        binp = tmp_path / "original" / "x.dll"
        binp.write_bytes(_make_pe(raw, image_base=0x10000000, data_va=0x18000))
        _write_layout(tmp_path, 0x10027000, len(raw), len(raw))
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 0, result.output
        text = src.read_text()
        assert 'char s_msg_10027000[3] = "hi";' in text


if __name__ == "__main__":
    pass


class TestEncodingSafety:
    def test_inline_uses_preserves_source_encoding(self, tmp_path: Path) -> None:
        """A legacy-encoded source must not be rewritten as UTF-8."""
        f = tmp_path / "a.c"
        # 0xA9 is a valid Shift-JIS/cp1252 byte but not valid UTF-8.
        f.write_bytes(
            "// FUNCTION: TEST 0x1000\n// \xa9 note\n"
            "int f(void) { return s_foo_10027000[0]; }\n".encode("latin-1")
        )
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 1
        raw = f.read_bytes()
        assert b"\xa9" in raw
        assert b'"hello"' in raw
