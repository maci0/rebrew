"""Tests for rename.py — cross-reference rename with dry-run and file renaming."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.rename import rename_function_everywhere


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path)


def _src(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


def _patch_sources(monkeypatch: pytest.MonkeyPatch, files: list[Path]) -> None:
    monkeypatch.setattr("rebrew.rename.iter_sources", lambda _d, _c: files)


class TestRenameFunctionEverywhere:
    def test_dry_run_counts_without_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        b = _src(tmp_path, "other.c", "extern int func_a(void);\n")
        _patch_sources(monkeypatch, [a, b])
        count = rename_function_everywhere(
            _cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn", dry_run=True
        )
        assert count == 2  # both files reference func_a
        # Nothing written.
        assert "func_a" in a.read_text()
        assert "func_a" in b.read_text()

    def test_renames_primary_and_cross_refs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return func_a(); }\n")
        b = _src(tmp_path, "other.c", "extern int func_a(void);\n")
        _patch_sources(monkeypatch, [a, b])
        count = rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        assert count == 2
        renamed = tmp_path / "renamed_fn.c"  # file auto-renamed to match
        assert "renamed_fn" in renamed.read_text()
        assert "func_a" not in renamed.read_text()
        assert "renamed_fn" in b.read_text()

    def test_underscore_symbol_stripped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _patch_sources(monkeypatch, [a])
        # old_sym "_func_a" → matches "func_a" via underscore stripping.
        count = rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        assert count == 1
        renamed = tmp_path / "renamed_fn.c"
        assert "renamed_fn" in renamed.read_text()

    def test_file_renamed_when_stem_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _patch_sources(monkeypatch, [a])
        rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        assert (tmp_path / "renamed_fn.c").exists()
        assert not a.exists()

    def test_new_filename_suffix_added(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _patch_sources(monkeypatch, [a])
        rename_function_everywhere(
            _cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn", new_filename="custom"
        )
        assert (tmp_path / "custom.c").exists()

    def test_target_exists_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _src(tmp_path, "renamed_fn.c", "int renamed_fn(void) { return 2; }\n")
        _patch_sources(monkeypatch, [a])
        with pytest.raises(FileExistsError, match="already exists"):
            rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")

    def test_multi_function_file_not_auto_renamed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(
            tmp_path,
            "func_a.c",
            "// FUNCTION: SERVER 0x10001000\nint func_a(void) { return 1; }\n"
            "// FUNCTION: SERVER 0x10002000\nint func_b(void) { return 2; }\n",
        )
        _patch_sources(monkeypatch, [a])
        rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        # File not renamed (multi-function), content still updated.
        assert a.exists()
        assert "renamed_fn" in a.read_text()


class TestRenameEdgeCases:
    def test_dry_run_unreadable_file_skipped(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.rename import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.c").mkdir()  # directory matching *.c → read raises OSError
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        result = rename_function_everywhere(
            cfg, src / "bad.c", "old_fn", "_old_fn", "new_fn", dry_run=True
        )
        assert result == 0

    def test_primary_file_oserror_warns(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.rename import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        # Missing primary file → OSError logged, no crash, other files scanned.
        result = rename_function_everywhere(cfg, src / "missing.c", "old_fn", "_old_fn", "new_fn")
        assert result == 0

    def test_extern_oserror_skipped(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.rename import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        primary = src / "f.c"
        primary.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        (src / "bad.c").mkdir()  # extern scan hits OSError → skipped
        (src / "e.c").write_text("extern int old_fn(void);\n", encoding="utf-8")
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        result = rename_function_everywhere(cfg, primary, "old_fn", "_old_fn", "new_fn")
        assert result == 2  # primary + extern file
        assert "new_fn" in (src / "e.c").read_text(encoding="utf-8")

    def test_new_filename_absolute_path(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.rename import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        primary = src / "old_fn.c"
        primary.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        (src / "sub").mkdir()  # nested target dir must exist for Path.rename
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        rename_function_everywhere(
            cfg, primary, "old_fn", "_old_fn", "new_fn", new_filename="sub/new_file"
        )
        assert (src / "sub" / "new_file.c").exists()

    def test_stem_not_matching_keeps_file(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.rename import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        primary = src / "unrelated.c"
        primary.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        rename_function_everywhere(cfg, primary, "old_fn", "_old_fn", "new_fn")
        assert (src / "unrelated.c").exists()  # stem != old name → no rename


class TestRenameCli:
    def _invoke(self, tmp_path: Path, monkeypatch: Any, *args: str) -> Any:
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: [
                SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="old_fn.c", va=0x1000)
            ],
        )
        return CliRunner().invoke(app, list(args))

    def test_json_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        import json

        f = tmp_path / "src" / "SERVER" / "old_fn.c"
        f.parent.mkdir(parents=True)
        f.write_text(
            "// FUNCTION: SERVER 0x1000\nint old_fn(void) { return 0; }\n", encoding="utf-8"
        )
        result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", "new_fn")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["new_name"] == "new_fn"
        assert data["files_updated"] >= 1

    def test_not_found_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        result = self._invoke(tmp_path, monkeypatch, "--json", "nope", "new_fn")
        assert result.exit_code != 0
        assert "Could not find function" in result.output

    def test_multiple_matches_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: [
                SimpleNamespace(name="dup", symbol="_dup", filepath="a.c", va=0x1000),
                SimpleNamespace(name="dup", symbol="_dup", filepath="b.c", va=0x2000),
            ],
        )
        result = CliRunner().invoke(app, ["--json", "dup", "new_fn"])
        assert result.exit_code != 0
        assert "Be more specific" in result.output

    def test_rename_onto_existing_symbol_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Renaming onto an existing function's symbol must be rejected —
        otherwise two functions share one name (duplicate definition)."""
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: [
                SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="old_fn.c", va=0x1000),
                SimpleNamespace(name="taken", symbol="_taken", filepath="taken.c", va=0x2000),
            ],
        )
        result = CliRunner().invoke(app, ["--json", "old_fn", "taken"])
        assert result.exit_code != 0
        assert "duplicate symbol" in result.output

    def test_rename_onto_stdcall_decorated_symbol_errors(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A __stdcall collision carries a decorated suffix (_foo@8) — the
        plain-name check must not miss it."""
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: [
                SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="old_fn.c", va=0x1000),
                SimpleNamespace(name="taken2", symbol="_taken2@8", filepath="taken2.c", va=0x2000),
            ],
        )
        result = CliRunner().invoke(app, ["--json", "old_fn", "taken2"])
        assert result.exit_code != 0
        assert "duplicate symbol" in result.output

    def test_invalid_identifier_rejected(self, tmp_path: Path, monkeypatch: Any) -> None:
        # C keyword and non-identifier names must fail before any rename.
        result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", "int")
        assert result.exit_code != 0
        assert "not a valid C identifier" in result.output

        result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", "bad name")
        assert result.exit_code != 0
        assert "not a valid C identifier" in result.output

    def test_rename_by_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        import json

        f = tmp_path / "src" / "SERVER" / "old_fn.c"
        f.parent.mkdir(parents=True)
        f.write_text(
            "// FUNCTION: SERVER 0x1000\nint old_fn(void) { return 0; }\n", encoding="utf-8"
        )
        result = self._invoke(tmp_path, monkeypatch, "--json", "0x1000", "new_fn")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["new_name"] == "new_fn"

    def test_json_dry_run_flag(self, tmp_path: Path, monkeypatch: Any) -> None:
        import json

        f = tmp_path / "src" / "SERVER" / "old_fn.c"
        f.parent.mkdir(parents=True)
        f.write_text(
            "// FUNCTION: SERVER 0x1000\nint old_fn(void) { return 0; }\n", encoding="utf-8"
        )
        result = self._invoke(tmp_path, monkeypatch, "--json", "--dry-run", "old_fn", "new_fn")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["dry_run"] is True
        assert data["files_updated"] >= 0
        # Dry run must not have rewritten the file.
        assert "new_fn" not in f.read_text(encoding="utf-8")


class TestCollectMatchingFiles:
    def test_lists_primary_and_referencing_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import re

        from rebrew.rename import _collect_matching_files

        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        b = _src(tmp_path, "other.c", "extern int func_a(void);\n")
        c = _src(tmp_path, "unrelated.c", "int other(void) { return 0; }\n")
        _patch_sources(monkeypatch, [a, b, c])
        pattern = re.compile(r"\bfunc_a\b")
        matched = _collect_matching_files(_cfg(tmp_path), a, pattern)
        assert set(matched) == {a, b}
