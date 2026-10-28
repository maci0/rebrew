"""Tests for rebrew source inline-strings (string-literal global materialization)."""

import re
from pathlib import Path

import pytest
from cli_json import cli_payload
from source_util import SourceFixture, write_source
from typer.testing import CliRunner

from rebrew.inline_strings import c_literal, inline_string_uses


class TestCLiteral:
    def test_plain(self) -> None:
        assert c_literal(b"hello") == '"hello"'

    def test_escapes(self) -> None:
        assert c_literal(b'a"b\\c') == '"a\\"b\\\\c"'

    def test_octal_fixed_width(self) -> None:
        assert c_literal(b"\x01\xff") == '"\\001\\377"'


SRC = SourceFixture(
    "/* ADDRESS: TEST 0x1000 */\nint f(void) { return s_foo_10027000[0]; }\n",
    {"TEST.0x1000": {"kind": "FUNCTION"}},
)


def _token_re() -> re.Pattern[str]:
    return re.compile(r"\bs_[A-Za-z0-9_]+_([0-9a-fA-F]{6,8})\b")


class TestInlineUses:
    def test_inlines_string(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        write_source(f, SRC, encoding="utf-8")
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 1
        assert 'return "hello"[0];' in f.read_text()

    def test_dry_run(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        write_source(f, SRC, encoding="utf-8")
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=True)
        assert n == 1
        assert "s_foo_10027000" in f.read_text()

    def test_skips_asm_and_extern(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        write_source(
            f,
            "\nextern char s_foo_10027000[];\n/* ADDRESS: TEST 0x1000 */\nint f(void) {\n    __asm { push offset s_foo_10027000 }\n    return 0;\n}\n",
            encoding="utf-8",
            metadata_fields={"TEST.0x1000": {"kind": "FUNCTION"}},
        )
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 0  # asm + extern only — nothing inlinable
        assert "s_foo_10027000" in f.read_text()

    def test_token_inside_string_literal_not_rewritten(self, tmp_path: Path) -> None:
        """A token inside a C string literal is not a replaceable use: inlining
        it nested quotes and produced invalid C."""
        f = tmp_path / "a.c"
        write_source(
            f,
            '/* ADDRESS: TEST 0x1000 */\nchar *m = "use s_foo_10027000 here";\n',
            encoding="utf-8",
            metadata_fields={"TEST.0x1000": {"kind": "FUNCTION"}},
        )
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 0
        assert "s_foo_10027000" in f.read_text()

    def test_real_use_after_string_with_slashes_is_inlined(self, tmp_path: Path) -> None:
        """A `//` inside a string literal used to start a comment mask, hiding a
        real token use later on the same line."""
        f = tmp_path / "a.c"
        write_source(
            f,
            'char *u = "http://x"; int g = s_foo_10027000[0];\n',
            encoding="utf-8",
            metadata_fields={"TEST.0x1000": {"kind": "FUNCTION"}},
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
        write_source(
            a,
            "\nextern char s_msg_10027000[];\n// mentions s_msg_10027000 twice: s_msg_10027000\n/* ADDRESS: TEST 0x1000 */\nint a(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"TEST.0x1000": {"kind": "FUNCTION"}},
        )
        b = tmp_path / "b.c"
        write_source(
            b,
            "\nextern char s_msg_10027000[];\n/* ADDRESS: TEST 0x2000 */\nint b(void) { return s_msg_10027000[0]; }\n",
            encoding="utf-8",
            metadata_fields={"TEST.0x2000": {"kind": "FUNCTION"}},
        )
        n = define_remaining_strings([a, b], b"hi\x00", 0x10027000, _token_re(), dry_run=False)
        assert n == 1
        assert 'char s_msg_10027000[3] = "hi";' in b.read_text()
        assert "char s_msg_10027000[3]" not in a.read_text()

    def test_owner_tie_uses_first_referencing_file(self, tmp_path: Path) -> None:
        from rebrew.inline_strings import define_remaining_strings

        files = [tmp_path / f"{name}.c" for name in ("unrelated", "first", "second")]
        files[0].write_text("int unrelated;\n", encoding="utf-8")
        for path in files[1:]:
            path.write_text(
                "extern char s_msg_10027000[];\nint x = s_msg_10027000[0];\n",
                encoding="utf-8",
            )
        assert define_remaining_strings(files, b"hi\0", 0x10027000, _token_re(), False) == 1
        assert 'char s_msg_10027000[3] = "hi";' in files[1].read_text()
        assert "extern char" in files[2].read_text()

    def _cfg(self, tmp_path: Path) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src",
            target_binary=tmp_path / "original" / "x.dll",
            module="TEST",
        )

    def test_defines_asm_referenced_string(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.inline_strings import app

        (tmp_path / "src").mkdir(parents=True)
        src = tmp_path / "src" / "a.c"
        write_source(
            src,
            "\nextern char s_msg_10027000[];\n/* ADDRESS: TEST 0x1000 */\nint f(void) {\n    __asm { push offset s_msg_10027000 }\n    return 0;\n}\n",
            encoding="utf-8",
            metadata_fields={"TEST.0x1000": {"kind": "FUNCTION"}},
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


class TestEncodingSafety:
    def test_inline_uses_preserves_source_encoding(self, tmp_path: Path) -> None:
        """A legacy-encoded source must not be rewritten as UTF-8."""
        f = tmp_path / "a.c"
        # 0xA9 is a valid Shift-JIS/cp1252 byte but not valid UTF-8.
        f.write_bytes(
            SourceFixture(
                "/* ADDRESS: TEST 0x1000 */\n// © note\nint f(void) { return s_foo_10027000[0]; }\n",
                {"TEST.0x1000": {"kind": "FUNCTION"}},
            ).encode("latin-1")
        )
        n = inline_string_uses(f, b"hello\x00", 0x10027000, _token_re(), {}, dry_run=False)
        assert n == 1
        raw = f.read_bytes()
        assert b"\xa9" in raw
        assert b'"hello"' in raw

    def test_define_keeps_nel_inside_string_literal(self, tmp_path: Path) -> None:
        """0x85 decodes as NEL in a Latin-1 source; it must not become a newline."""
        from rebrew.inline_strings import define_remaining_strings

        f = tmp_path / "a.c"
        f.write_bytes(
            SourceFixture(
                '\nchar *note = "café \x85 end";\n/* ADDRESS: TEST 0x1000 */\nextern char s_msg_10027000[];\nint f(void) {\n    __asm { push offset s_msg_10027000 }\n    return 0;\n}\n',
                {"TEST.0x1000": {"kind": "FUNCTION"}},
            ).encode("latin-1")
        )
        assert (
            define_remaining_strings(
                [f],
                b"hi\x00",
                0x10027000,
                re.compile(r"\bs_[A-Za-z0-9_]+_([0-9a-fA-F]{6,8})\b"),
                dry_run=False,
            )
            == 1
        )
        raw = f.read_bytes()
        assert b"caf\xe9 \x85 end" in raw
        assert b'char s_msg_10027000[3] = "hi";' in raw

    def test_define_keeps_missing_trailing_newline_missing(self, tmp_path: Path) -> None:
        from rebrew.inline_strings import define_remaining_strings

        f = tmp_path / "a.c"
        write_source(
            f,
            "\nextern char s_msg_10027000[];\n/* ADDRESS: TEST 0x1000 */\nint f(void) { __asm { push offset s_msg_10027000 } return 0; }",
            encoding="utf-8",
            metadata_fields={"TEST.0x1000": {"kind": "FUNCTION"}},
        )
        define_remaining_strings(
            [f],
            b"hi\x00",
            0x10027000,
            re.compile(r"\bs_[A-Za-z0-9_]+_([0-9a-fA-F]{6,8})\b"),
            dry_run=False,
        )
        assert not f.read_bytes().endswith(b"\n")


class TestNamedMode:
    """``--named`` inlines same-file ``char s_x[] = "...";`` definitions."""

    def _project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        from test_data_layout import _write_layout

        _write_layout(tmp_path, 0x10027000, 1, 1)  # named mode reads no binary
        src = tmp_path / "src"
        src.mkdir()
        monkeypatch.chdir(tmp_path)
        return src

    def _run(self, *args: str) -> dict[str, object]:

        from rebrew.inline_strings import app

        result = CliRunner().invoke(app, ["--named", "--json", *args])
        assert result.exit_code == 0, result.output
        payload = cli_payload(result)
        assert isinstance(payload, dict)
        return payload

    def test_inlines_escapes_and_drops_externs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = self._project(tmp_path, monkeypatch)
        a = src / "a.c"
        a.write_text(
            "#include <stdio.h>\n"
            "\n"
            'char s_quote[] = "say \\"hi\\"\\n\\001";\n'
            "\n"
            'static char s_tab[] = "a\\tb" "\\\\c";\n'
            "\n"
            "extern char s_quote[];\n"
            "int f(void)\n"
            "{\n"
            "    extern char s_quote[];\n"
            "    /* s_quote stays in this comment */\n"
            '    puts("s_quote");\n'
            "    return s_quote[0] + sizeof(s_tab) + (int)s_tab;\n"
            "}\n",
            encoding="utf-8",
        )
        payload = self._run()
        assert payload["named"] == 2
        assert payload["inlined"] == 3
        assert a.read_text(encoding="utf-8") == (
            "#include <stdio.h>\n"
            "\n"
            "int f(void)\n"
            "{\n"
            "    /* s_quote stays in this comment */\n"
            '    puts("s_quote");\n'
            '    return "say \\"hi\\"\\n\\001"[0] + sizeof("a\\tb" "\\\\c") + (int)"a\\tb" "\\\\c";\n'
            "}\n"
        )

    def test_name_used_from_another_file_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = self._project(tmp_path, monkeypatch)
        a = src / "a.c"
        a_text = 'char s_shared[] = "x";\nint f(void) { return s_shared[0]; }\n'
        write_source(a, a_text, encoding="utf-8")
        (src / "b.c").write_text(
            "extern char s_shared[];\nint g(void) { return s_shared[0]; }\n", encoding="utf-8"
        )
        payload = self._run("--files", "a.c")
        assert payload["named"] == 0
        files = payload["files"]
        assert isinstance(files, list)
        assert files[0]["skipped"] == {"s_shared": f"used from {src / 'b.c'}"}
        assert a.read_text(encoding="utf-8") == a_text

    def test_definition_used_only_elsewhere_names_the_user(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = self._project(tmp_path, monkeypatch)
        (src / "a.c").write_text('char s_err[] = "x";\n', encoding="utf-8")
        (src / "b.h").write_text("#define ERR s_err\n", encoding="utf-8")
        payload = self._run()
        files = payload["files"]
        assert isinstance(files, list)
        assert files[0]["skipped"] == {"s_err": f"used from {src / 'b.h'}"}

    def test_asm_use_is_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = self._project(tmp_path, monkeypatch)
        a = src / "a.c"
        a_text = (
            'char s_asm[] = "x";\n'
            "int f(void) {\n"
            "    __asm { push offset s_asm }\n"
            "    return s_asm[0];\n"
            "}\n"
        )
        write_source(a, a_text, encoding="utf-8")
        payload = self._run()
        assert payload["named"] == 0
        files = payload["files"]
        assert isinstance(files, list)
        assert files[0]["skipped"] == {"s_asm": "line 3: used in __asm or unparsed code"}
        assert a.read_text(encoding="utf-8") == a_text

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = self._project(tmp_path, monkeypatch)
        a = src / "a.c"
        a_text = 'char s_x[] = "x";\nchar *p(void) { return s_x; }\n'
        write_source(a, a_text, encoding="utf-8")
        payload = self._run("--dry-run")
        assert payload["named"] == 1
        assert a.read_text(encoding="utf-8") == a_text

    def test_data_row_marked_literal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.metadata.data import load_data_metadata, set_data_fields_batch

        src = self._project(tmp_path, monkeypatch)
        (src / "a.c").write_text(
            'char s_x[] = "x";\nchar *p(void) { return s_x; }\n', encoding="utf-8"
        )
        set_data_fields_batch(
            tmp_path,
            [
                {
                    "module": "game.dll",
                    "va": 0x10027000,
                    "fields": {"file": "src/a.c", "name": "s_x", "type": "char[2]"},
                }
            ],
        )
        payload = self._run()
        assert payload["data_rows"] == 1
        row = load_data_metadata(tmp_path)[("game.dll", 0x10027000)]
        assert row["storage_kind"] == "literal"
        assert row["updated_by"] == "inline-strings"


class TestNamedScanBudget:
    def test_other_source_parsed_once_and_next_call_sees_edits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import Mock

        from rebrew import inline_strings

        source = tmp_path / "owner.c"
        source.write_text(
            'char s_a[] = "a"; char s_b[] = "b";\nint f(void) { return s_a[0] + s_b[0]; }\n'
        )
        other = tmp_path / "other.c"
        other.write_text("/* s_a and s_b are only mentioned in this comment. */\n")
        parse = Mock(wraps=inline_strings._parse_source)
        monkeypatch.setattr(inline_strings, "_parse_source", parse)
        result = inline_strings.inline_named_strings(source, "s_", [other], True)
        assert result.inlined == {"s_a": 1, "s_b": 1}
        assert parse.call_count == 2  # Owner and other source, independent of string count.
        other.write_text("#define EXTERNAL s_b\n")
        result = inline_strings.inline_named_strings(source, "s_", [other], True)
        assert "s_b" in result.skipped
        assert result.inlined == {"s_a": 1}

    def test_edit_during_scan_does_not_reuse_old_parse(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import inline_strings

        source = tmp_path / "owner.c"
        source.write_text(
            'char s_a[] = "a"; char s_b[] = "b";\nint f(void) { return s_a[0] + s_b[0]; }\n'
        )
        other = tmp_path / "other.c"
        from rebrew.utils import read_source_text

        read = read_source_text
        calls = 0

        def changing_read(path: Path) -> tuple[str, str]:
            nonlocal calls
            if path == other:
                calls += 1
                return ("/* s_a s_b */" if calls == 1 else "#define EXTERNAL s_b\n", "utf-8")
            return read(path)

        monkeypatch.setattr(inline_strings, "read_source_text", changing_read)
        result = inline_strings.inline_named_strings(source, "s_", [other], True)
        assert result.inlined == {"s_a": 1}
        assert result.skipped == {"s_b": f"used from {other}"}


class TestOccurrenceIndex:
    def test_literals_comments_and_identifier_boundaries_stay_distinct(self) -> None:
        from rebrew.inline_strings import _code_occurrences, _parse_source

        source = (
            '/* s_value */ char *example = "s_value";\n'
            "// s_value\nint s_value_extra;\n"
            "int f(void) { return s_value[0] + s_value[1]; }\n"
        )
        _, parsed = _parse_source(source, "s_")
        assert _code_occurrences(parsed, "s_value") == 2
        assert _code_occurrences(parsed, "missing") == 0

    def test_index_matches_byte_regex_on_unicode_macros_and_malformed_code(self) -> None:
        import re
        from bisect import bisect_right

        from rebrew.inline_strings import _code_occurrences, _parse_source

        text = (
            '/* s_a */ char *literal = "s_a s_b";\n'
            "#define M(x) s_a + x + s_b\n"
            "int s_a_extra, s_a1;\n"
            "int f( { s_a + é s_aé + é_s_a + $s_b;\n"
        )
        _, parsed = _parse_source(text, "s_")
        for name in ("s_a", "s_b", "s_a", "s_b", "s_a_extra", "s_a1", "a-b"):
            pattern = re.compile(rb"\b" + re.escape(name.encode()) + rb"\b")
            expected = 0
            for match in pattern.finditer(parsed.data):
                i = bisect_right(parsed.non_code, match.start(), key=lambda span: span[0]) - 1
                if i < 0 or match.start() >= parsed.non_code[i][1]:
                    expected += 1
            assert _code_occurrences(parsed, name) == expected
        assert parsed.code_counts is not None

    def test_single_query_does_not_build_index(self) -> None:
        from rebrew.inline_strings import _code_occurrences, _parse_source

        _, parsed = _parse_source("int s_one; int another;", "s_")
        assert _code_occurrences(parsed, "s_one") == 1
        assert parsed.code_counts is None

    def test_edit_after_index_build_uses_new_source_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import inline_strings
        from rebrew.utils import read_source_text

        source = tmp_path / "owner.c"
        source.write_text(
            "".join(
                f'char s_{i}[] = "x";\nint f{i}(void) {{ return s_{i}[0]; }}\n' for i in range(4)
            )
        )
        other = tmp_path / "other.c"
        reads = 0

        def changing_read(path: Path) -> tuple[str, str]:
            nonlocal reads
            if path == other:
                reads += 1
                return ("/* s_0 s_1 s_2 s_3 */" if reads < 4 else "#define X s_3\n", "utf-8")
            return read_source_text(path)

        monkeypatch.setattr(inline_strings, "read_source_text", changing_read)
        result = inline_strings.inline_named_strings(source, "s_", [other], True)
        assert result.inlined == {"s_0": 1, "s_1": 1, "s_2": 1}
        assert result.skipped == {"s_3": f"used from {other}"}
