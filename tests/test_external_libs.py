"""`targets.<name>.external_libs` — one flag for external .lib code.

External library code ("not our work" — CRT, DirectX, import libs) is
flagged per target as ``module = "link-spec"``.  The flag drives three
things: progress accounting excludes the modules, `rebrew lib-match`
ingests the archives by default, and `rebrew cmake-sources` emits the
specs as ``REBREW_EXTERNAL_LIBS`` so the build links the stock archive
at build time ("link it at the right place" — config order is link
order).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.config import load_config
from rebrew.lib_match import external_archive_args
from rebrew.naming import external_vas

PROJECT_TOML = """\
[project]
name = "t"
default_target = "game"

[targets.game]
binary = "bin/game.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
marker = "GAME"

[targets.game.external_libs]
KERNEL32 = "KERNEL32.lib"
D3DX8 = "references/libs/d3dx8.lib"
MSVCRT = ""

[compiler]
profile = "gcc-14.2.0"
command = "gcc"
includes = ""
libs = ""
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")
    (tmp_path / "src").mkdir(exist_ok=True)
    return tmp_path


class TestConfig:
    def test_parsed_and_uppercased(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        cfg = load_config(root=root)
        assert cfg.external_libs == {
            "KERNEL32": "KERNEL32.lib",
            "D3DX8": "references/libs/d3dx8.lib",
            "MSVCRT": "",
        }

    def test_missing_map_is_empty(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            PROJECT_TOML.split("[targets.game.external_libs]", maxsplit=1)[0]
            + '[compiler]\nprofile = "gcc-14.2.0"\ncommand = "gcc"\nincludes = ""\nlibs = ""\n',
            encoding="utf-8",
        )
        (tmp_path / "src").mkdir(exist_ok=True)
        cfg = load_config(root=tmp_path)
        assert cfg.external_libs == {}


class TestExternalVas:
    def test_library_rows_and_flagged_modules(self) -> None:
        existing = {
            0x1000: {"marker_type": "FUNCTION", "module": "GAME", "status": "EXACT"},
            0x2000: {"marker_type": "LIBRARY", "module": "GAME", "status": "EXACT"},
            0x3000: {"marker_type": "FUNCTION", "module": "D3DX8", "status": "RELOC"},
            0x4000: {"marker_type": "FUNCTION", "module": "OTHER", "status": "STUB"},
        }
        got = external_vas(existing, {"KERNEL32": "KERNEL32.lib", "D3DX8": "x.lib"})
        assert got == {0x2000, 0x3000}


class TestCmakeSources:
    def test_emits_external_libs_in_config_order(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.cmake_sources import app as cs_app

        root = _project(tmp_path)
        monkeypatch.chdir(root)
        result = CliRunner().invoke(cs_app, ["--json", "--dry-run"])
        assert result.exit_code == 0
        doc = json.loads(result.stdout)
        # Config order preserved (link order: KERNEL32 before D3DX8);
        # empty specs contribute no archive.
        assert doc["external_libs"] == ["KERNEL32.lib", "references/libs/d3dx8.lib"]


class TestLibMatchDefaults:
    def test_path_specs_are_libs_bare_specs_are_stock(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        cfg = load_config(root=root)
        libs, stock = external_archive_args(cfg)
        assert libs == [Path("references/libs/d3dx8.lib")]
        assert stock == ["KERNEL32.lib"]

    def test_identified_only_module_contributes_nothing(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        cfg = load_config(root=root)
        libs, stock = external_archive_args(cfg)
        assert all("MSVCRT" not in s for s in stock)


class TestDoctor:
    def test_warns_on_missing_archive(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_external_libs

        root = _project(tmp_path)
        cfg = load_config(root=root)
        result = check_external_libs(cfg)
        assert result.name == "External libraries"
        assert result.status == "warn"
        assert "D3DX8" in result.message

    def test_passes_when_archives_exist(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_external_libs

        root = _project(tmp_path)
        (root / "references/libs").mkdir(parents=True)
        (root / "references/libs/d3dx8.lib").write_bytes(b"!")
        cfg = load_config(root=root)
        result = check_external_libs(cfg)
        assert result.status == "pass"

    def test_skips_when_nothing_flagged(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_external_libs

        (tmp_path / "rebrew-project.toml").write_text(
            PROJECT_TOML.split("[targets.game.external_libs]", maxsplit=1)[0]
            + '[compiler]\nprofile = "gcc-14.2.0"\ncommand = "gcc"\nincludes = ""\nlibs = ""\n',
            encoding="utf-8",
        )
        (tmp_path / "src").mkdir(exist_ok=True)
        cfg = load_config(root=tmp_path)
        assert check_external_libs(cfg).status == "skip"
