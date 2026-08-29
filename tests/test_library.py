"""Tests for per-library toolchain/flags overrides (rebrew-libraries.toml)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.cli import resolve_compile_overrides
from rebrew.library import app
from rebrew.metadata import (
    LIBRARY_METADATA_FILE,
    apply_library_presets,
    find_library_override,
    parse_library_metadata,
)


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A project root with a nested library and a function dir under it."""
    proj = tmp_path / "proj"
    lib = proj / "refs" / "zlib"
    fn = lib / "f"
    for d in (proj, lib, fn):
        d.mkdir(parents=True)
    return proj, lib, fn


class TestLibraryMetadata:
    def test_absent_file_returns_empty(self, tmp_path: Path) -> None:
        assert parse_library_metadata(tmp_path / LIBRARY_METADATA_FILE) == {}

    def test_malformed_toml_raises(self, tmp_path: Path) -> None:
        from rebrew.metadata import LibraryOverrideError

        bad = tmp_path / LIBRARY_METADATA_FILE
        bad.write_text("toolchain = [unclosed\n", encoding="utf-8")
        with pytest.raises(LibraryOverrideError):
            parse_library_metadata(bad)

    def test_walk_up_finds_nearest(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (proj / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc6"\n', encoding="utf-8")
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc600sp6"\n', encoding="utf-8")
        ovr = find_library_override(fn, proj)
        assert ovr is not None and ovr.path == lib / LIBRARY_METADATA_FILE
        assert ovr.toolchain == "msvc600sp6"  # nearest wins

    def test_no_override_returns_none(self, tmp_path: Path) -> None:
        proj, _, fn = _tree(tmp_path)
        assert find_library_override(fn, proj) is None

    def test_presets_fill_missing_fields(self) -> None:
        merged, presets = apply_library_presets({"library": "msvcrt-static"})
        assert presets == ("msvcrt-static",)
        assert merged["toolchain"] == "msvc6"
        assert merged["cflags"] == "/O2 /Gd /MT"

    def test_explicit_fields_win_over_presets(self) -> None:
        merged, _ = apply_library_presets(
            {"library": "msvcrt-static", "toolchain": "msvc600sp6", "cflags": "/O1"}
        )
        assert merged["toolchain"] == "msvc600sp6"
        assert merged["cflags"] == "/O1"

    def test_unknown_preset_no_merge(self) -> None:
        merged, presets = apply_library_presets({"library": "nope"})
        assert presets == ()
        assert "toolchain" not in merged


class TestResolveCompileOverrides:
    def _cfg(self, tmp_path: Path, **over: object) -> SimpleNamespace:
        base: dict[str, object] = {
            "root": tmp_path,
            "cflags_presets": {},
            "cflags": "",
            "cflags_explicit": False,
        }
        base.update(over)
        return SimpleNamespace(**base)

    def test_per_function_beats_library(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "msvc6"\ncflags = "/O2 /Gd"\n', encoding="utf-8"
        )
        tc, cf = resolve_compile_overrides(
            self._cfg(tmp_path, root=proj),
            fn,
            "msvc5",
            "/O1",
        )
        assert tc == "msvc5"  # per-function wins
        assert cf == "/O1"

    def test_library_beats_default(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "msvc600sp6"\ncflags = "/O2 /Gd /MT"\n', encoding="utf-8"
        )
        tc, cf = resolve_compile_overrides(self._cfg(tmp_path, root=proj), fn, None, None)
        assert tc == "msvc600sp6"
        assert cf == "/O2 /Gd /MT"

    def test_default_fallback(self, tmp_path: Path) -> None:
        proj, _, fn = _tree(tmp_path)
        tc, cf = resolve_compile_overrides(self._cfg(tmp_path, root=proj), fn, None, None)
        assert tc is None  # project default profile
        assert cf == "/O2 /Gd"  # resolve_cflags default

    def test_preset_drives_library(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text('library = "msvcrt-static"\n', encoding="utf-8")
        tc, cf = resolve_compile_overrides(self._cfg(tmp_path, root=proj), fn, None, None)
        assert tc == "msvc6"
        assert cf == "/O2 /Gd /MT"


class TestLibraryCli:
    def _invoke(self, *args: str) -> object:
        from typer.testing import CliRunner

        return CliRunner().invoke(app, list(args))

    def test_list_finds_all_overrides(self, tmp_path: Path) -> None:
        proj, lib, _ = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc6"\n', encoding="utf-8")
        res = self._invoke("list", str(proj), "--json")
        assert res.exit_code == 0, res.output
        import json

        payload = json.loads(res.output)
        assert len(payload["libraries"]) == 1
        assert payload["libraries"][0]["toolchain"] == "msvc6"

    def test_set_show_rm_roundtrip(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--toolchain", "msvc6", "--cflags", "/O2 /Gd")
        assert res.exit_code == 0, res.output
        assert (lib / LIBRARY_METADATA_FILE).exists()
        shown = self._invoke("show", str(lib), "--json")
        assert shown.exit_code == 0
        assert '"toolchain": "msvc6"' in shown.output
        removed = self._invoke("rm", str(lib))
        assert removed.exit_code == 0
        assert not (lib / LIBRARY_METADATA_FILE).exists()

    def test_set_preset_merges_explicit(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke(
            "set", str(lib), "--preset", "msvcrt-static", "--toolchain", "msvc600sp6"
        )
        assert res.exit_code == 0, res.output
        text = (lib / LIBRARY_METADATA_FILE).read_text(encoding="utf-8")
        assert "msvcrt-static" in text
        assert "msvc600sp6" in text
        # the preset's cflags still fill in
        ovr = find_library_override(lib, tmp_path)
        assert ovr is not None and ovr.cflags == "/O2 /Gd /MT"

    def test_unknown_toolchain_fails(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--toolchain", "bogus-nope")
        assert res.exit_code == 2
        assert "unknown toolchain" in res.output
        assert not (lib / LIBRARY_METADATA_FILE).exists()

    def test_known_toolchain_accepts_all_profiles(self, tmp_path: Path) -> None:
        """Every registry profile is settable (docker-backed and native)."""
        from rebrew.toolchain import TOOLCHAINS

        for name in sorted(TOOLCHAINS):
            lib = tmp_path / name
            lib.mkdir()
            res = self._invoke("set", str(lib), "--toolchain", name)
            assert res.exit_code == 0, f"{name}: {res.output}"

    def test_unknown_preset_fails(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--preset", "nope")
        assert res.exit_code == 2
