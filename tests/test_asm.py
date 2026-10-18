"""Tests for rebrew.asm — build_function_lookup helper."""

import json
from pathlib import Path

import pytest
from source_util import SourceFixture, write_source, write_store_fixture

from rebrew.asm import build_function_lookup
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# build_function_lookup
# ---------------------------------------------------------------------------


class TestBuildFunctionLookup:
    """Tests for build_function_lookup()."""

    def test_empty_dir(self, tmp_path: Path) -> None:
        """Empty reversed_dir with no ghidra JSON returns empty lookup."""
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result == {}

    def test_ghidra_json_loaded(self, tmp_path: Path) -> None:
        """Ghidra functions are loaded into the lookup."""
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(
            json.dumps(
                [
                    {"va": 0x10001000, "ghidra_name": "my_func", "size": 64},
                    {"va": 0x10002000, "ghidra_name": "other_func", "size": 128},
                ]
            ),
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert 0x10001000 in result
        assert result[0x10001000] == ("my_func", "")
        assert 0x10002000 in result
        assert result[0x10002000] == ("other_func", "")

    def test_source_files_override_ghidra(self, tmp_path: Path) -> None:
        """Source file annotations override Ghidra names."""
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(
            json.dumps([{"va": 0x10001000, "ghidra_name": "FUN_10001000", "size": 64}]),
            encoding="utf-8",
        )
        src = tmp_path / "game_func.c"
        write_source(
            src,
            "/* ADDRESS: SERVER 0x10001000 */\n\n\nvoid game_func(void) {}\n",
            encoding="utf-8",
            metadata_fields={
                "SERVER.0x10001000": {"kind": "FUNCTION", "size": 64, "cflags": "/O2 /Gd"}
            },
        )
        # STATUS lives in metadata, not inline.
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 3\n["SERVER.0x10001000"]\nstatus = "RELOC"\n',
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path / "src")
        (tmp_path / "src").mkdir()
        src.rename(tmp_path / "src" / "game_func.c")
        ghidra_json.rename(tmp_path / "src" / "function_structure.json")
        result = build_function_lookup(cfg)
        # Source file overrides Ghidra
        assert result[0x10001000] == ("game_func", "RELOC")

    def test_source_status_preserved(self, tmp_path: Path) -> None:
        """Status from source annotations is preserved in lookup."""
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        src = tmp_path / "stub_func.c"
        write_source(
            src,
            "/* ADDRESS: SERVER 0x10003000 */\n\n\n\n\n\n\nvoid stub_func(void) {}\n",
            encoding="utf-8",
            metadata_fields={
                "SERVER.0x10003000": {
                    "kind": "STUB",
                    "size": 32,
                    "cflags": "/O2 /Gd",
                    "blocker": "unknown",
                    "symbol": "_stub_func",
                }
            },
        )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result[0x10003000] == ("stub_func", "STUB")

    def test_symbol_leading_underscore_stripped(self, tmp_path: Path) -> None:
        """Leading underscore in symbol is stripped for display name."""
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        src = tmp_path / "my_func.c"
        write_source(
            src,
            "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid my_func(void) {}\n",
            encoding="utf-8",
            metadata_fields={
                "SERVER.0x10001000": {
                    "kind": "FUNCTION",
                    "size": 16,
                    "cflags": "/O2 /Gd",
                    "symbol": "_my_func",
                }
            },
        )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        name, _ = result[0x10001000]
        assert name == "my_func"
        assert not name.startswith("_")

    def test_decorated_symbol_uses_the_c_name(self, tmp_path: Path) -> None:
        """A decorated symbol is not the VA-map name.

        The map used ``lstrip("_")`` on the linker symbol and ignored the
        C name. ``hook@@12`` and ``@keeps@4`` stayed decorated, and the
        symbol of ``_foo`` (``__foo``) became ``foo``. ``foo`` stays
        ``foo``.
        """
        (tmp_path / "function_structure.json").write_text("[]", encoding="utf-8")
        sources = {
            "hook.c": (
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\nint __vectorcall hook(int a, int b, int c) { return 0; }\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 16}},
                )
            ),
            "keeps.c": (
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10002000 */\n\nint __fastcall keeps(int a) { return a; }\n",
                    {"SERVER.0x10002000": {"kind": "FUNCTION", "size": 16}},
                )
            ),
            "sleepish.c": (
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10003000 */\n\nint __stdcall sleepish(int a) { return a; }\n",
                    {"SERVER.0x10003000": {"kind": "FUNCTION", "size": 16}},
                )
            ),
            "under.c": (
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10004000 */\n\nint _foo(void) { return 0; }\n",
                    {"SERVER.0x10004000": {"kind": "FUNCTION", "size": 16}},
                )
            ),
            "plain.c": (
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10005000 */\n\nint foo(void) { return 0; }\n",
                    {"SERVER.0x10005000": {"kind": "FUNCTION", "size": 16}},
                )
            ),
        }
        for filename, text in sources.items():
            write_source(tmp_path / filename, text, encoding="utf-8")
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result[0x10001000][0] == "hook"
        assert result[0x10002000][0] == "keeps"
        assert result[0x10003000][0] == "sleepish"
        assert result[0x10004000][0] == "_foo"
        assert result[0x10005000][0] == "foo"

    def test_ghidra_entry_without_name_skipped(self, tmp_path: Path) -> None:
        """Ghidra entries with empty name are skipped."""
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(
            json.dumps([{"va": 0x10001000, "ghidra_name": "", "size": 64}]),
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert 0x10001000 not in result

    def test_ghidra_entry_without_va_skipped(self, tmp_path: Path) -> None:
        """Ghidra entries without VA raise ValueError on load."""
        import pytest

        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(
            json.dumps([{"ghidra_name": "orphan_func", "size": 64}]),
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        with pytest.raises(ValueError, match="must contain 'va' and 'size'"):
            build_function_lookup(cfg)

    def test_nonexistent_reversed_dir(self, tmp_path: Path) -> None:
        """Non-existent reversed_dir returns only Ghidra data."""
        nonexistent = tmp_path / "nonexistent"
        # No ghidra JSON either — directory doesn't exist
        cfg = ProjectConfig(root=tmp_path, reversed_dir=nonexistent)
        result = build_function_lookup(cfg)
        assert result == {}

    def test_bad_source_file_skipped(self, tmp_path: Path) -> None:
        """Malformed .c files are silently skipped."""
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        bad = tmp_path / "bad.c"
        bad.write_text("this is not a valid annotation header\n", encoding="utf-8")
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result == {}

    def test_multiple_source_files(self, tmp_path: Path) -> None:
        """Multiple source files all contribute to lookup."""
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        for i, va in enumerate([0x10001000, 0x10002000, 0x10003000]):
            src = tmp_path / f"func_{i}.c"
            write_source(
                src,
                f"/* ADDRESS: SERVER 0x{va:08x} */\n\nvoid func_{i}(void) {{}}\n",
                encoding="utf-8",
                metadata_fields={
                    f"SERVER.0x{va:08x}": {"kind": "FUNCTION", "size": 32, "cflags": "/O2 /Gd"}
                },
            )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert len(result) == 3
        assert 0x10001000 in result
        assert 0x10002000 in result
        assert 0x10003000 in result


# ---------------------------------------------------------------------------
# Flag validation
# ---------------------------------------------------------------------------


class TestFlagValidation:
    """Flag values are checked before the project is loaded.

    In a directory with no rebrew-project.toml, ``require_config`` would
    exit 2 with a config error, so a passing test here proves the flag check
    runs first.
    """

    def test_bad_format_names_the_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.asm import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["show", "--format", "bogus", "0x1000"])
        assert result.exit_code == 2
        assert "--format" in result.output

    def test_bad_size_names_the_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from rebrew.asm import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["show", "--size", "0", "0x1000"])
        assert result.exit_code == 2
        assert "--size" in result.output

    def test_bad_format_is_a_parser_error_even_with_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.asm import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["show", "--format", "bogus", "--json", "0x1000"])
        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Invalid value" in result.stderr
        assert "--format" in result.stderr
