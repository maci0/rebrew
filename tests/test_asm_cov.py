"""Tests for rebrew.asm — build_function_lookup helper."""

import json
from pathlib import Path

from rebrew.asm import build_function_lookup
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# build_function_lookup
# ---------------------------------------------------------------------------


class TestBuildFunctionLookup:
    """Tests for build_function_lookup()."""

    def test_empty_dir(self, tmp_path: Path) -> None:
        """Empty reversed_dir with no ghidra JSON returns empty lookup."""
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result == {}

    def test_ghidra_json_loaded(self, tmp_path: Path) -> None:
        """Ghidra functions are loaded into the lookup."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(
            json.dumps(
                [
                    {"va": 0x10001000, "ghidra_name": "my_func", "size": 64},
                    {"va": 0x10002000, "ghidra_name": "other_func", "size": 128},
                ]
            ),
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert 0x10001000 in result
        assert result[0x10001000] == ("my_func", "")
        assert 0x10002000 in result
        assert result[0x10002000] == ("other_func", "")

    def test_source_files_override_ghidra(self, tmp_path: Path) -> None:
        """Source file annotations override Ghidra names."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(
            json.dumps([{"va": 0x10001000, "ghidra_name": "FUN_10001000", "size": 64}]),
            encoding="utf-8",
        )
        src = tmp_path / "game_func.c"
        src.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: RELOC\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _game_func\n"
            "void game_func(void) {}\n",
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        # Source file overrides Ghidra
        assert result[0x10001000] == ("game_func", "RELOC")

    def test_source_status_preserved(self, tmp_path: Path) -> None:
        """Status from source annotations is preserved in lookup."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        src = tmp_path / "stub_func.c"
        src.write_text(
            "// STUB: SERVER 0x10003000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 32\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _stub_func\n"
            "// BLOCKER: unknown\n"
            "void stub_func(void) {}\n",
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result[0x10003000] == ("stub_func", "STUB")

    def test_symbol_leading_underscore_stripped(self, tmp_path: Path) -> None:
        """Leading underscore in symbol is stripped for display name."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        src = tmp_path / "my_func.c"
        src.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 16\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _my_func\n"
            "void my_func(void) {}\n",
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        name, _ = result[0x10001000]
        assert name == "my_func"
        assert not name.startswith("_")

    def test_ghidra_entry_without_name_skipped(self, tmp_path: Path) -> None:
        """Ghidra entries with empty name are skipped."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(
            json.dumps([{"va": 0x10001000, "ghidra_name": "", "size": 64}]),
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert 0x10001000 not in result

    def test_ghidra_entry_without_va_skipped(self, tmp_path: Path) -> None:
        """Ghidra entries without VA are skipped."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(
            json.dumps([{"ghidra_name": "orphan_func", "size": 64}]),
            encoding="utf-8",
        )
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result == {}

    def test_nonexistent_reversed_dir(self, tmp_path: Path) -> None:
        """Non-existent reversed_dir returns only Ghidra data."""
        nonexistent = tmp_path / "nonexistent"
        # No ghidra JSON either — directory doesn't exist
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=nonexistent)
        result = build_function_lookup(cfg)
        assert result == {}

    def test_bad_source_file_skipped(self, tmp_path: Path) -> None:
        """Malformed .c files are silently skipped."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        bad = tmp_path / "bad.c"
        bad.write_text("this is not a valid annotation header\n", encoding="utf-8")
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert result == {}

    def test_multiple_source_files(self, tmp_path: Path) -> None:
        """Multiple source files all contribute to lookup."""
        ghidra_json = tmp_path / "ghidra_functions.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")
        for i, va in enumerate([0x10001000, 0x10002000, 0x10003000]):
            src = tmp_path / f"func_{i}.c"
            src.write_text(
                f"// FUNCTION: SERVER 0x{va:08x}\n"
                f"// STATUS: RELOC\n"
                f"// ORIGIN: GAME\n"
                f"// SIZE: 32\n"
                f"// CFLAGS: /O2 /Gd\n"
                f"// SYMBOL: _func_{i}\n"
                f"void func_{i}(void) {{}}\n",
                encoding="utf-8",
            )
        cfg = ProjectConfig(root=Path("/tmp"), reversed_dir=tmp_path)
        result = build_function_lookup(cfg)
        assert len(result) == 3
        assert 0x10001000 in result
        assert 0x10002000 in result
        assert 0x10003000 in result
