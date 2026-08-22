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

    def test_unknown_addr_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text(SRC.replace("10027000", "10028000"), encoding="utf-8")
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 0


class TestDefineRemaining:
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
