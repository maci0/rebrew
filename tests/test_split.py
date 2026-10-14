"""Tests for the rebrew source split command."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from source_util import SourceFixture, write_source
from typer.testing import CliRunner

from rebrew.split import app

runner = CliRunner()


def _make_cfg(tmp_path: Path, marker: str = "SERVER") -> Any:
    return SimpleNamespace(
        marker=marker, source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_source(path, content, encoding="utf-8")
    return path


def test_cdecl_function_declaration_is_not_storage() -> None:
    """`__cdecl` between the type and the name is still a function declaration."""
    from rebrew.split import source_layout

    raw, spans = source_layout(
        "void __cdecl gm_KillSpieler(unsigned int, int);\n"
        "int __cdecl amt_ValidateCommand(char*);\n"
        "void* __cdecl gm_Lookup(int);\n"
        "int value;\n"
    )
    kinds = {(span.kind, span.name) for span in spans}
    assert ("storage", "gm_KillSpieler") not in kinds
    assert ("storage", "amt_ValidateCommand") not in kinds
    assert ("storage", "gm_Lookup") not in kinds
    assert ("storage", "value") in kinds


def test_cdecl_definition_with_a_typedef_return_type_is_a_function() -> None:
    """`Record* __cdecl f(...) {...}` parsed as an error and the function was lost."""
    from rebrew.split import source_layout

    _raw, spans = source_layout(
        "typedef struct Record Record;\n"
        "Record* __cdecl gm_FindRecordById(int id)\n{\n\treturn 0;\n}\n"
        "int __stdcall plain(void)\n{\n\treturn 1;\n}\n"
        "Record* proto_only(int);\n"
    )
    functions = [span.name for span in spans if span.kind == "function"]
    assert functions == ["gm_FindRecordById", "plain"]
    assert ("storage", "proto_only") not in {(span.kind, span.name) for span in spans}


def test_inline_asm_does_not_hide_a_function() -> None:
    """MSVC `__asm` bodies are not C; the function around them is still a function."""
    from rebrew.split import source_layout

    _raw, spans = source_layout(
        "int __cdecl with_block(int a)\n{\n\t__asm {\n\t\tmov eax, a\n\t\tL1:\n\t\tjmp L1\n\t}\n\treturn a;\n}\n"
        "int __cdecl one_line(int a)\n{\n\t__asm mov eax, a\n\treturn a;\n}\n"
        "int after(void)\n{\n\treturn 0;\n}\n"
    )
    assert [span.name for span in spans if span.kind == "function"] == [
        "with_block",
        "one_line",
        "after",
    ]


def test_preamble_struct_keeps_its_semicolon() -> None:
    """`struct t {...};` is a bare specifier plus a `;` token the named walk never visits."""
    from rebrew.split import shared_preamble, source_layout

    raw, spans = source_layout(
        "struct t {\n\tint a;\n};\n#pragma pack(push, 1)\nstruct u {\n\tint b;\n};\n"
        "#pragma pack(pop)\n\nint f(void)\n{\n\treturn 0;\n}\n"
    )
    text = shared_preamble(raw, spans, [])
    assert "};\n#pragma pack(pop)" in text
    assert "}\n#pragma" not in text
    assert text.count("};") == 2


def _multi_two() -> str:
    return SourceFixture(
        "#include <stdio.h>\n\n/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\n\nint func_a(void) { return 0; }\n\n/* ADDRESS: SERVER 0x10002000 */\n\n\n\n\n\n\nint func_b(void) { return 1; }\n",
        {
            "SERVER.0x10001000": {
                "kind": "FUNCTION",
                "size": 42,
                "cflags": "/O2",
                "symbol": "_func_a",
                "status": "EXACT",
            },
            "SERVER.0x10002000": {
                "kind": "FUNCTION",
                "size": 84,
                "cflags": "/O2",
                "symbol": "_func_b",
                "status": "NEAR_MATCHING",
            },
        },
    )


def _invoke(
    tmp_path: Path, monkeypatch: Any, *args: str, name: str = "multi.c"
) -> tuple[Any, Path]:
    """Run the split CLI, returning (result, source path)."""
    src = tmp_path / name
    monkeypatch.setattr(
        "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
    )
    result = runner.invoke(app, [*args, str(src)])
    return result, src


class TestSplitExtensionHandling:
    def test_multi_ext_config_writes_one_extension(self, tmp_path: Path, monkeypatch: Any) -> None:
        """`source_ext = ".c,.cpp"` must not become part of the filename."""
        src = tmp_path / "multi.cpp"
        _write(src, _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                marker="SERVER", source_ext=".c,.cpp", reversed_dir=tmp_path, metadata_dir=tmp_path
            ),
        )
        result = runner.invoke(app, ["--force", str(src)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "func_a.cpp").exists()
        assert not (tmp_path / "func_a.c,.cpp").exists()

    def test_uppercase_extension_accepted(self, tmp_path: Path, monkeypatch: Any) -> None:
        """iter_sources matches FOO.C as .c; the explicit-file check must too."""
        src = tmp_path / "MULTI.C"
        _write(src, _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                marker="SERVER", source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path
            ),
        )
        result = runner.invoke(app, ["--force", str(src)])
        assert result.exit_code == 0, result.output
        # Input suffix is preserved (.C stays .C); acceptance is the contract.
        assert (tmp_path / "func_a.C").exists()
        assert (tmp_path / "func_b.C").exists()
        assert "Split 2 function(s)" in result.output


class TestSplitBasic:
    def test_splits_two_functions(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0
        assert (tmp_path / "func_a.c").exists()
        assert (tmp_path / "func_b.c").exists()

    def test_includes_shared_preamble_in_each_output(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        content = SourceFixture(
            "#include <stdio.h>\n#define MAGIC 7\n\n/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\n\nint a(void) { return MAGIC; }\n\n/* ADDRESS: SERVER 0x10002000 */\n\n\n\n\n\n\nint b(void) { return MAGIC; }\n",
            {
                "SERVER.0x10001000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_a",
                    "status": "EXACT",
                },
                "SERVER.0x10002000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_b",
                    "status": "EXACT",
                },
            },
        )
        _write(tmp_path / "multi.c", content)

        result, src = _invoke(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0
        a_text = (tmp_path / "a.c").read_text(encoding="utf-8")
        b_text = (tmp_path / "b.c").read_text(encoding="utf-8")
        assert "#include <stdio.h>" in a_text
        assert "#define MAGIC 7" in a_text
        assert "#include <stdio.h>" in b_text
        assert "#define MAGIC 7" in b_text

    def test_uses_symbol_for_filename(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0
        assert (tmp_path / "func_a.c").exists()
        assert (tmp_path / "func_b.c").exists()

    def test_derives_name_from_c_definition_without_symbol_annotation(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Function name should come from C definition even without // SYMBOL:."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x1000ABCD */\n\n\n\n\n\nint first(void) { return 0; }\n\n/* ADDRESS: SERVER 0x10002000 */\n\n\n\n\n\n\nint named(void) { return 0; }\n",
            {
                "SERVER.0x1000ABCD": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "status": "EXACT",
                },
                "SERVER.0x10002000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_named",
                    "status": "EXACT",
                },
            },
        )
        _write(tmp_path / "multi.c", content)

        result, src = _invoke(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0
        # Name derived from C definition, not VA fallback
        assert (tmp_path / "first.c").exists()
        assert (tmp_path / "named.c").exists()

    def test_dry_run_does_not_create_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--dry-run")
        assert result.exit_code == 0
        assert not (tmp_path / "func_a.c").exists()
        assert not (tmp_path / "func_b.c").exists()

    def test_errors_when_input_has_only_one_function(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\n\nint only(void) { return 0; }\n",
            {
                "SERVER.0x10001000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_only",
                    "status": "EXACT",
                }
            },
        )
        _write(tmp_path / "single.c", content)

        result, src = _invoke(tmp_path, monkeypatch, "--force", name="single.c")
        assert result.exit_code != 0
        assert "at least two function definitions" in result.output

    def test_errors_when_output_exists_without_force(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _write(tmp_path / "multi.c", _multi_two())
        _write(tmp_path / "func_a.c", "stale\n")

        result, src = _invoke(tmp_path, monkeypatch)
        assert result.exit_code != 0
        assert "Output file already exists" in result.output

    def test_conflict_aborts_before_writing_any_block(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A mid-batch conflict must not leave earlier blocks written: the old
        interleaved check-then-write aborted after writing blocks 1..N-1, and
        every re-run then failed on block 1's now-existing output (the split
        could never complete without --force).  Two-phase validation writes
        NOTHING on any conflict."""
        _write(tmp_path / "multi.c", _multi_two())
        # func_a is the FIRST block; func_b the second.  Conflict on the
        # SECOND path must still prevent the first from being written.
        _write(tmp_path / "func_b.c", "stale\n")

        result, src = _invoke(tmp_path, monkeypatch)
        assert result.exit_code != 0
        assert "Output file already exists" in result.output
        assert not (tmp_path / "func_a.c").exists()

    def test_force_overwrites_existing_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())
        existing = _write(tmp_path / "func_a.c", "stale\n")

        result, src = _invoke(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0
        assert SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */", {"SERVER.0x10001000": {"kind": "FUNCTION"}}
        ) in existing.read_text(encoding="utf-8")

    def test_json_output_structure(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.split.json_print", lambda data: payloads.append(data))

        result, src = _invoke(tmp_path, monkeypatch, "--force", "--json")
        assert result.exit_code == 0
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload["count"] == 2
        assert payload["dry_run"] is False
        assert "files" in payload
        assert len(payload["files"]) == 2

    def test_filters_blocks_to_selected_target(self, tmp_path: Path, monkeypatch: Any) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\n\nint server_a(void) { return 0; }\n\n/* ADDRESS: CLIENT 0x20001000 */\n\n\n\n\n\n\nint client_a(void) { return 0; }\n\n/* ADDRESS: SERVER 0x10002000 */\n\n\n\n\n\n\nint server_b(void) { return 0; }\n",
            {
                "SERVER.0x10001000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_server_a",
                    "status": "EXACT",
                },
                "CLIENT.0x20001000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_client_a",
                    "status": "EXACT",
                },
                "SERVER.0x10002000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_server_b",
                    "status": "EXACT",
                },
            },
        )
        _write(tmp_path / "multi.c", content)

        result, src = _invoke(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0
        assert (tmp_path / "server_a.c").exists()
        assert (tmp_path / "server_b.c").exists()
        assert not (tmp_path / "client_a.c").exists()


class TestSplitExtractVA:
    """Tests for --va single-function extraction mode."""

    def test_extracts_single_function_with_preamble(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0
        out = tmp_path / "multi_c" / "func_a.c"
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "#include <stdio.h>" in content
        assert (
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */", {"SERVER.0x10001000": {"kind": "FUNCTION"}}
            )
            in content
        )
        assert "int func_a(void)" in content

    def test_removes_extracted_block_from_source(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0
        remaining = src.read_text(encoding="utf-8")
        assert "0x10001000" not in remaining
        assert (
            SourceFixture(
                "/* ADDRESS: SERVER 0x10002000 */", {"SERVER.0x10002000": {"kind": "FUNCTION"}}
            )
            in remaining
        )
        assert "#include <stdio.h>" in remaining

    def test_dry_run_does_not_modify_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())
        original = (tmp_path / "multi.c").read_text(encoding="utf-8")

        result, src = _invoke(tmp_path, monkeypatch, "--dry-run", "--va", "0x10001000")
        assert result.exit_code == 0
        assert not (tmp_path / "multi_c" / "func_a.c").exists()
        assert src.read_text(encoding="utf-8") == original

    def test_errors_on_unknown_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--force", "--va", "0xDEADBEEF")
        assert result.exit_code != 0
        assert "No function row" in result.output

    def test_errors_on_invalid_hex_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Non-hex --va should produce a clear error, not a traceback."""
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--force", "--va", "not_hex")
        assert result.exit_code != 0
        assert "Invalid VA" in result.output

    def test_va_force_overwrites(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va --force should overwrite an existing extracted file."""
        _write(tmp_path / "multi.c", _multi_two())
        out_dir = tmp_path / "multi_c"
        out_dir.mkdir()
        _write(out_dir / "func_a.c", "stale\n")

        result, src = _invoke(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0
        content = (out_dir / "func_a.c").read_text(encoding="utf-8")
        assert (
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */", {"SERVER.0x10001000": {"kind": "FUNCTION"}}
            )
            in content
        )

    def test_va_extracts_last_block_deletes_source(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Extracting the only remaining block should delete the source file."""
        content = SourceFixture(
            "#include <stdio.h>\n\n/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\n\nint only(void) { return 0; }\n",
            {
                "SERVER.0x10001000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_only",
                    "status": "EXACT",
                }
            },
        )
        _write(tmp_path / "single.c", content)

        result, src = _invoke(
            tmp_path, monkeypatch, "--va", "0x10001000", "--force", name="single.c"
        )
        assert result.exit_code == 0
        assert (tmp_path / "single_c" / "only.c").exists()
        assert not src.exists()  # source deleted when no blocks remain
        bak = tmp_path / "single.c.bak"
        assert bak.exists()
        assert "int only(void)" in bak.read_text(encoding="utf-8")

    def test_va_extract_preserves_existing_bak(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A second last-block extract must not overwrite an existing .bak."""
        original = SourceFixture(
            "#include <stdio.h>\n\n/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\n\nint only(void) { return 0; }\n",
            {
                "SERVER.0x10001000": {
                    "kind": "FUNCTION",
                    "size": 1,
                    "cflags": "/O2",
                    "symbol": "_only",
                    "status": "EXACT",
                }
            },
        )
        bak = tmp_path / "single.c.bak"
        bak.write_text("ORIGINAL BACKUP\n", encoding="utf-8")
        _write(tmp_path / "single.c", original)

        result, src = _invoke(
            tmp_path, monkeypatch, "--va", "0x10001000", "--force", name="single.c"
        )
        assert result.exit_code == 0
        assert not src.exists()
        assert bak.read_text(encoding="utf-8") == "ORIGINAL BACKUP\n"

    def test_va_json_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va --json should produce correct structured output."""
        _write(tmp_path / "multi.c", _multi_two())
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.split.json_print", lambda data: payloads.append(data))

        result, src = _invoke(tmp_path, monkeypatch, "--json", "--va", "0x10001000", "--force")
        assert result.exit_code == 0
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload["count"] == 1
        assert len(payload["files"]) == 1
        assert payload["files"][0]["va"] == "0x10001000"
        # output_dir should be the va_out_dir, not the parent
        assert "multi_c" in payload["output_dir"]

    def test_va_json_requires_force_for_destructive_extract(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """--va --json should not wait for an interactive destructive prompt."""
        _write(tmp_path / "multi.c", _multi_two())

        result, src = _invoke(tmp_path, monkeypatch, "--json", "--va", "0x10001000")
        assert result.exit_code != 0
        assert "Pass --force" in result.output
        assert "0x10001000" in src.read_text(encoding="utf-8")
        assert not (tmp_path / "multi_c" / "func_a.c").exists()

    def test_va_with_output_dir_override(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va with --output-dir should use the override directory."""
        _write(tmp_path / "multi.c", _multi_two())
        custom_dir = tmp_path / "custom_out"

        result, src = _invoke(
            tmp_path, monkeypatch, "--va", "0x10001000", "--force", "--output", str(custom_dir)
        )
        assert result.exit_code == 0
        assert (custom_dir / "func_a.c").exists()
        assert not (tmp_path / "multi_c").exists()  # default dir not created


class TestSplitHelpers:
    def test_output_name_from_symbol(self) -> None:
        from rebrew.split import _build_output_name

        assert _build_output_name("_my_func", 0x1000, ".c") == "_my_func.c"

    def test_c_name_keeps_its_leading_underscore(self) -> None:
        """A C function ``_foo`` is ``_foo.c``. ``__foo`` is ``__foo.c``.

        ``lstrip("_")`` stored both as ``foo.c``, the same file as ``foo``.
        """
        from rebrew.split import _build_output_name

        assert _build_output_name("_foo", 0x1000, ".c") == "_foo.c"
        assert _build_output_name("__foo", 0x2000, ".c") == "__foo.c"
        assert _build_output_name("foo", 0x3000, ".c") == "foo.c"

    def test_output_name_non_ascii_symbol_is_ascii(self) -> None:
        from rebrew.split import _build_output_name

        # NFC and NFD spellings must not yield two different filenames.
        nfc = _build_output_name("Stra\u00dfe_caf\u00e9", 0x1000, ".c")
        nfd = _build_output_name("Stra\u00dfe_cafe\u0301", 0x1000, ".c")
        assert nfc.isascii() and nfd.isascii()
        assert nfc == nfd == "Stra_e_caf_.c"

    def test_output_name_fallback_va(self) -> None:
        from rebrew.split import _build_output_name

        assert _build_output_name("", 0x1000, ".c") == "func_00001000.c"


class TestSplitCliErrors:
    def test_missing_source_argument(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        result = runner.invoke(app, [])
        assert result.exit_code == 2
        assert "Missing argument" in result.output
        assert "source" in result.output.lower()

    def test_source_not_found(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        result = runner.invoke(app, ["nope.c"])
        assert result.exit_code != 0
        assert "Source file not found" in result.output

    def test_extension_mismatch(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        _write(tmp_path / "multi.txt", "int x;\n")
        result = runner.invoke(app, [str(tmp_path / "multi.txt")])
        assert result.exit_code != 0
        assert "must match configured extension" in result.output

    def test_split_requires_two_matching_blocks(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Two FUNCTION blocks, but only one matches the configured marker."""
        monkeypatch.setattr(
            "rebrew.split.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path, marker="SERVER"),
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nint a(void) { return 0; }\n/* ADDRESS: OTHER 0x10002000 */\nint b(void) { return 1; }\n",
            {"SERVER.0x10001000": {"kind": "FUNCTION"}, "OTHER.0x10002000": {"kind": "FUNCTION"}},
        )
        _write(tmp_path / "multi.c", content)
        result = runner.invoke(app, [str(tmp_path / "multi.c")])
        assert result.exit_code != 0
        # read_source_bindings filters the OTHER block for target SERVER → < 2.
        assert "at least two function definitions" in result.output

    def test_va_json_requires_force(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va in --json mode refuses destructive extraction without --force."""
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        _write(tmp_path / "multi.c", _multi_two())
        result = runner.invoke(app, ["--va", "0x10001000", "--json", str(tmp_path / "multi.c")])
        assert result.exit_code != 0
        assert "Pass --force" in result.output

    def test_va_json_force_extracts(self, tmp_path: Path, monkeypatch: Any) -> None:
        import json

        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        _write(tmp_path / "multi.c", _multi_two())
        result = runner.invoke(
            app, ["--va", "0x10001000", "--json", "--force", str(tmp_path / "multi.c")]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["count"] == 1
        assert data["files"][0]["va"] == "0x10001000"


class TestPreambleStripping:
    def test_strips_comment_blocks_keeps_code(self) -> None:
        from rebrew.utils import strip_comment_blocks

        preamble = (
            "/* Ghidra decompilation reference:\n"
            " * Symbol: _a\n"
            " */\n"
            "typedef unsigned long DWORD;\n"
            "\n"
            "/* another block */\n"
            "extern int g_x;\n"
        )
        stripped = strip_comment_blocks(preamble)
        assert "typedef unsigned long DWORD;" in stripped
        assert "extern int g_x;" in stripped
        assert "Ghidra" not in stripped
        assert "another block" not in stripped

    def test_strips_orphaned_comment_lines(self) -> None:
        from rebrew.utils import strip_comment_blocks

        # Merged preambles can have malformed /* */ nesting (line-union) that
        # leaves orphaned `*` continuation lines — those must go too.
        preamble = "*    Size: 26B\n*    Symbol: _a\nint code(void);\n"
        stripped = strip_comment_blocks(preamble)
        assert "Size:" not in stripped
        assert "code(void)" in stripped

    def test_code_only_preamble_unchanged(self) -> None:
        from rebrew.utils import strip_comment_blocks

        preamble = "#include <stdio.h>\n#define MAGIC 7\n"
        assert strip_comment_blocks(preamble) == "#include <stdio.h>\n#define MAGIC 7"


class TestSplitCrlfSource:
    """A CRLF source keeps CRLF in what the split writes (no mixed endings)."""

    def test_split_outputs_keep_crlf(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two().replace("\n", "\r\n"))

        result, src = _invoke(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0
        raw = (tmp_path / "func_a.c").read_bytes()
        assert b"\r\n" in raw
        assert raw.replace(b"\r\n", b"").count(b"\n") == 0

    def test_va_extract_output_keeps_crlf(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "multi.c", _multi_two().replace("\n", "\r\n"))

        result, src = _invoke(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0
        raw = (tmp_path / "multi_c" / "func_a.c").read_bytes()
        assert b"\r\n" in raw
        assert raw.replace(b"\r\n", b"").count(b"\n") == 0


class TestSplitStackedMarkers:
    """--va on a shared file matches any stacked marker, not just the first."""

    def _stacked(self) -> str:
        return SourceFixture(
            "/* ADDRESS: V2 0x501000 */\n\n/* ADDRESS: V1 0x401000 */\n\nint common(void) { return 1; }\n",
            {
                "V2.0x501000": {"kind": "FUNCTION", "size": 11},
                "V1.0x401000": {"kind": "FUNCTION", "size": 11},
            },
        )

    def _invoke_marker(self, tmp_path: Path, monkeypatch: Any, marker: str, *args: str) -> Any:
        src = _write(tmp_path / "common.c", self._stacked())
        monkeypatch.setattr(
            "rebrew.split.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path, marker),
        )
        return runner.invoke(app, [*args, str(src)])

    def test_va_matches_non_first_marker(self, tmp_path: Path, monkeypatch: Any) -> None:
        result = self._invoke_marker(tmp_path, monkeypatch, "V1", "--va", "0x401000", "--force")
        assert result.exit_code == 0, result.output
        out = tmp_path / "common_c" / "common.c"
        assert out.exists()
        assert SourceFixture(
            "/* ADDRESS: V1 0x401000 */", {"V1.0x401000": {"kind": "FUNCTION"}}
        ) in out.read_text(encoding="utf-8")

    def test_va_matches_first_marker(self, tmp_path: Path, monkeypatch: Any) -> None:
        result = self._invoke_marker(tmp_path, monkeypatch, "V2", "--va", "0x501000", "--force")
        assert result.exit_code == 0, result.output
        out = tmp_path / "common_c" / "common.c"
        assert SourceFixture(
            "/* ADDRESS: V2 0x501000 */", {"V2.0x501000": {"kind": "FUNCTION"}}
        ) in out.read_text(encoding="utf-8")

    def test_va_wrong_target_still_misses(self, tmp_path: Path, monkeypatch: Any) -> None:
        result = self._invoke_marker(tmp_path, monkeypatch, "V3", "--va", "0x401000", "--force")
        assert result.exit_code != 0
        assert "No function row" in result.output


def _meta_cfg(tmp_path: Path, marker: str = "SERVER") -> Any:
    return SimpleNamespace(
        marker=marker, source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path
    )


def _seed(tmp_path: Path, rows: list[tuple[str, int, str]], file: str = "multi.c") -> None:
    from rebrew.metadata.functions import record_function_identity

    for module, va, symbol in rows:
        record_function_identity(
            tmp_path,
            module=module,
            va=va,
            file=file,
            kind="FUNCTION",
            symbol=symbol,
            name=symbol[1:] if symbol.startswith("_") else symbol,
        )


def _invoke_meta(
    tmp_path: Path, monkeypatch: Any, *args: str, name: str = "multi.c"
) -> tuple[Any, Path]:
    src = tmp_path / name
    monkeypatch.setattr(
        "rebrew.split.require_config",
        lambda target=None, json_mode=False: _meta_cfg(tmp_path),
    )
    return runner.invoke(app, [*args, str(src)]), src


class TestMarkerlessSplit:
    """A migrated file is split from its function rows, not from a marker line."""

    def test_extraction_after_conditional_braces_preserves_other_body_and_storage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = (
            "int counter = 3;\nextern int left, right;\n"
            "void first(int x) {\n#ifdef FIRST\nif (left) {\n#else\nif (right) {\n"
            "#endif\nx++;\n}\n}\n"
            "int second(int n, ...) { return counter + n; }\n"
        )
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_first"), ("SERVER", 0x10002000, "_second")])
        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10002000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "second.c").read_text(encoding="utf-8")
        assert "int second(int n, ...) { return counter + n; }" in out
        assert "extern int counter;" in out
        assert "void first" not in out
        assert "int counter = 3;" not in out
        remaining = src.read_text(encoding="utf-8")
        assert "int counter = 3;" in remaining
        assert "void first" in remaining
        assert "int second" not in remaining

    def test_extraction_rebases_local_and_nested_quoted_headers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(tmp_path / "local.h", "int external(void);\n")
        (tmp_path / "include").mkdir()
        _write(tmp_path / "include" / "nested.h", "int nested(void);\n")
        source = (
            '#include "local.h"\n#ifdef VERSION\n#include "include/nested.h"\n#endif\n'
            '#include "missing.h"\n#include <stdio.h>\n'
            "int func_a(void) { return external(); }\nint func_b(void) { return 1; }\n"
        )
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])
        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_a.c").read_text(encoding="utf-8")
        assert '#include "../local.h"' in out
        assert '#include "../include/nested.h"' in out
        assert '#include "missing.h"' in out
        assert "#include <stdio.h>" in out
        assert '#include "local.h"' in src.read_text(encoding="utf-8")

    @pytest.mark.parametrize("calls_sibling", [False, True])
    def test_unrelated_dispatch_initializer_does_not_block_extraction(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, calls_sibling: bool
    ) -> None:
        source = (
            "int func_b(void);\n"
            "int (*dispatch[])(void) = {func_b};\n\n"
            f"int func_a(void) {{ return {'func_b()' if calls_sibling else '0'}; }}\n\n"
            "int func_b(void) { return 1; }\n"
        )
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])
        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_a.c").read_text(encoding="utf-8")
        assert "dispatch" not in out
        assert "int (*dispatch[])(void) = {func_b};" in src.read_text(encoding="utf-8")
        assert "int func_b(void) { return 1; }" not in out
        if calls_sibling:
            assert "int func_b(void);" in out

    def test_static_dependency_also_used_by_an_initializer_is_still_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = (
            "static int hidden = 1;\nint *view = &hidden;\n\n"
            "int func_a(void) { return hidden; }\n\nint func_b(void) { return 0; }\n"
        )
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])
        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code != 0
        assert "depends on hidden" in result.output
        assert src.read_text(encoding="utf-8") == source
        assert not (tmp_path / "multi_c").exists()

    def test_used_callback_table_is_declared_without_copying_storage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(
            tmp_path / "multi.c",
            "int func_b(void);\nint (*dispatch[])(void) = {func_b};\n\n"
            "int func_a(void) { return dispatch[0](); }\n\nint func_b(void) { return 1; }\n",
        )
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])
        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_a.c").read_text(encoding="utf-8")
        assert "extern int (*dispatch[])(void);" in out
        assert "= {func_b}" not in out
        assert "int (*dispatch[])(void) = {func_b};" in src.read_text(encoding="utf-8")

    def test_va_extracts_the_definition_and_retargets_siblings(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew.metadata.functions import load_metadata, update_field, update_source_status

        _write(
            tmp_path / "multi.c",
            "#include <stdio.h>\n\nint func_a(void) { return 0; }\n\nint func_b(void) { return 1; }\n",
        )
        _seed(
            tmp_path,
            [
                ("SERVER", 0x10001000, "_func_a"),
                ("GOLD", 0x20001000, "_func_a"),
                ("SERVER", 0x10002000, "_func_b"),
            ],
        )
        update_source_status(
            tmp_path,
            "EXACT",
            "SERVER",
            0x10001000,
            updated_by="verify",
            verification={"status": "EXACT", "writer": "verify", "input_hash": "a" * 64},
        )
        update_field(tmp_path, 0x10001000, "note", "keep", "SERVER")
        from rebrew.metadata.data import load_data_metadata, record_data_rows

        record_data_rows(
            tmp_path,
            [
                {
                    "module": "SERVER",
                    "va": 0x10025000,
                    "identity": {"file": "multi.c", "kind": "DATA", "name": "g_table"},
                }
            ],
        )

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_a.c").read_text(encoding="utf-8")
        assert "#include <stdio.h>" in out
        assert "int func_a(void) { return 0; }" in out
        assert "func_b" not in out
        assert "// FUNCTION:" not in out
        original = src.read_text(encoding="utf-8")
        assert "func_a" not in original
        assert "int func_b(void) { return 1; }" in original
        rows = load_metadata(tmp_path)
        assert rows[("SERVER", 0x10001000)]["file"] == "multi_c/func_a.c"
        assert rows[("GOLD", 0x20001000)]["file"] == "multi_c/func_a.c"
        assert rows[("SERVER", 0x10002000)]["file"] == "multi.c"
        kept = rows[("SERVER", 0x10001000)]
        assert kept["status"] == "EXACT"
        assert kept["note"] == "keep"
        assert kept["updated_by"] == "verify"
        assert kept["verification"]["input_hash"] == "a" * 64
        assert load_data_metadata(tmp_path)[("SERVER", 0x10025000)]["file"] == "multi.c"

    def test_storage_stays_and_a_use_becomes_an_extern(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _write(
            tmp_path / "multi.c",
            "#include <stdio.h>\n\n"
            "int g_table[4] = {1, 2, 3, 4};\n\n"
            "int func_a(void) { return 0; }\n\n"
            "int func_b(void) { return g_table[0]; }\n",
        )
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10002000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_b.c").read_text(encoding="utf-8")
        assert "extern int g_table[4];" in out
        assert "{1, 2, 3, 4}" not in out
        assert "int func_b(void) { return g_table[0]; }" in out
        original = src.read_text(encoding="utf-8")
        assert "int g_table[4] = {1, 2, 3, 4};" in original
        assert "func_a" in original
        assert "func_b" not in original

    def test_static_dependency_writes_nothing(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = (
            "static int hidden = 1;\n\n"
            "int func_a(void) { return hidden; }\n\n"
            "int func_b(void) { return 0; }\n"
        )
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code != 0
        assert "hidden" in result.output
        assert src.read_text(encoding="utf-8") == source
        assert not (tmp_path / "multi_c").exists()

    def test_static_function_is_refused(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = (
            "static int helper(void) { return 1; }\n\n"
            "int func_a(void) { return helper(); }\n\n"
            "int func_b(void) { return 0; }\n"
        )
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code != 0
        assert "static helper" in result.output
        assert src.read_text(encoding="utf-8") == source

    def test_sibling_call_gets_a_prototype(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(
            tmp_path / "multi.c",
            "int func_b(void) { return 1; }\n\nint func_a(void) { return func_b(); }\n",
        )
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, _src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_a.c").read_text(encoding="utf-8")
        assert "int func_b(void);" in out
        assert "return 1" not in out

    def test_ambiguous_and_missing_definitions_write_nothing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        source = "int func_a(void) { return 0; }\n\nint func_b(void) { return 1; }\n"
        _write(tmp_path / "multi.c", source)
        from rebrew.metadata.functions import record_function_identity

        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10001000,
            file="multi.c",
            kind="FUNCTION",
            symbol="_func_a",
            name="func_b",
        )
        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code != 0
        assert "Ambiguous" in result.output
        assert src.read_text(encoding="utf-8") == source

        _write(tmp_path / "other.c", source)
        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10003000,
            file="other.c",
            kind="FUNCTION",
            symbol="_missing",
            name="missing",
        )
        result, other = _invoke_meta(
            tmp_path, monkeypatch, "--va", "0x10003000", "--force", name="other.c"
        )
        assert result.exit_code != 0
        assert "No C definition" in result.output
        assert other.read_text(encoding="utf-8") == source

    def test_dry_run_is_immutable(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = "int func_a(void) { return 0; }\n\nint func_b(void) { return 1; }\n"
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])
        before = (tmp_path / "rebrew-functions.toml").read_bytes()

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--dry-run")
        assert result.exit_code == 0, result.output
        assert src.read_text(encoding="utf-8") == source
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == before
        assert not (tmp_path / "multi_c").exists()

    def test_metadata_failure_restores_the_source(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = "int func_a(void) { return 0; }\n\nint func_b(void) { return 1; }\n"
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])
        before = (tmp_path / "rebrew-functions.toml").read_bytes()

        def _boom(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("disk full")

        monkeypatch.setattr("rebrew.split.record_function_rows", _boom)
        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code != 0
        assert "restored" in result.output
        assert src.read_text(encoding="utf-8") == source
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == before
        assert not (tmp_path / "multi_c" / "func_a.c").exists()

    def test_crlf_and_non_ascii_comment_round_trip(self, tmp_path: Path, monkeypatch: Any) -> None:
        text = "#include <stdio.h>\r\n\r\n/* café */\r\nint func_a(void) { return 0; }\r\n\r\nint func_b(void) { return 1; }\r\n"
        (tmp_path / "multi.c").write_bytes(text.encode("utf-8"))
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_a.c").read_bytes()
        assert "café".encode() in out
        assert b"\n" not in out.replace(b"\r\n", b"")
        original = src.read_bytes()
        assert "café".encode() not in original
        assert b"\n" not in original.replace(b"\r\n", b"")

    def test_preprocessor_conditional_is_refused(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = "#if 1\nint func_a(void) { return 0; }\n#endif\nint func_b(void) { return 1; }\n"
        _write(tmp_path / "multi.c", source)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code != 0
        assert "preprocessor" in result.output
        assert src.read_text(encoding="utf-8") == source

    def test_full_split_keeps_the_storage_owner(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.metadata.functions import load_metadata

        _write(
            tmp_path / "multi.c",
            "#include <stdio.h>\n\n"
            "int g_table[4] = {1, 2, 3, 4};\n\n"
            "int func_a(void) { return 0; }\n\n"
            "int func_b(void) { return 1; }\n",
        )
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, src = _invoke_meta(tmp_path, monkeypatch, "--force")
        assert result.exit_code == 0, result.output
        for name in ("func_a.c", "func_b.c"):
            body = (tmp_path / name).read_text(encoding="utf-8")
            assert "#include <stdio.h>" in body
            assert "g_table" not in body
            assert "// FUNCTION:" not in body
        original = src.read_text(encoding="utf-8")
        assert "int g_table[4] = {1, 2, 3, 4};" in original
        assert "func_a" not in original
        assert "func_b" not in original
        rows = load_metadata(tmp_path)
        assert rows[("SERVER", 0x10001000)]["file"] == "func_a.c"
        assert rows[("SERVER", 0x10002000)]["file"] == "func_b.c"

    def test_file_level_naked_fence_stays_with_the_original(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _write(
            tmp_path / "multi.c",
            "#include <stdio.h>\n\nint func_a(void) { return 0; }\n\nint func_b(void) { return 1; }\n",
        )
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10002000, "_func_b")])

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10001000", "--force")
        assert result.exit_code == 0, result.output
        out = (tmp_path / "multi_c" / "func_a.c").read_text(encoding="utf-8")
        assert "SOURCE: naked" not in out
        assert "SOURCE: naked" not in src.read_text(encoding="utf-8")

    def test_decorated_row_matches_the_c_definition(self, tmp_path: Path, monkeypatch: Any) -> None:
        """``hook@@12`` extracts ``hook``. ``__foo`` extracts ``_foo``, not ``foo``."""
        from rebrew.metadata.functions import record_function_identity

        _write(
            tmp_path / "multi.c",
            "int other(void) { return 0; }\n\n"
            "int hook(void) { return 1; }\n\n"
            "int _foo(void) { return 2; }\n\n"
            "int foo(void) { return 3; }\n",
        )
        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10002000,
            file="multi.c",
            kind="FUNCTION",
            symbol="hook@@12",
        )
        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10003000,
            file="multi.c",
            kind="FUNCTION",
            symbol="__foo",
            name="_foo",
        )
        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10004000,
            file="multi.c",
            kind="FUNCTION",
            symbol="_foo",
            name="foo",
        )

        result, _src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10002000", "--force")
        assert result.exit_code == 0, result.output
        hook = (tmp_path / "multi_c" / "hook.c").read_text(encoding="utf-8")
        assert "int hook(void) { return 1; }" in hook
        assert "int _foo" not in hook

        result, src = _invoke_meta(tmp_path, monkeypatch, "--va", "0x10003000", "--force")
        assert result.exit_code == 0, result.output
        body = (tmp_path / "multi_c" / "_foo.c").read_text(encoding="utf-8")
        assert "int _foo(void) { return 2; }" in body
        assert "int foo(void)" not in body
        assert "int foo(void) { return 3; }" in src.read_text(encoding="utf-8")
