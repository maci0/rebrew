"""Tests for ``rebrew binary relocs``: base relocation sites of the reference vs a build.

Both images are real PEs: ``bin_util.make_pe`` lays out ``.text`` and LIEF adds
the base relocation table, so the command reads the same tables a linker writes.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import lief
import pytest
from bin_util import make_pe
from typer.testing import CliRunner

from rebrew.app.main import app

_BASE = 0x400000
_TEXT = _BASE + 0x1000

_TOML = """\
[project]
default_target = "game"

[targets.game]
binary = "game.exe"
marker = "GAME"
reversed_dir = "src"
[compiler]
profile = "msvc-6.0"
command = "cl"
cflags = "/O2"
"""

_DATA = """\
["GAME.0x00401014"]
name = "g_table"
section = ".text"
size = 4
"""

_MAP = """\
  Address         Publics by Value              Rva+Base     Lib:Object

 0001:00000000       _alpha                     00401000 f   a.obj
 0001:00000010       _beta_table                00401010     a.obj
 0001:00000018       _gamma                     00401018     b.obj
"""


def _image(path: Path, operands: list[int], relocated: list[int]) -> None:
    """A PE whose .text holds *operands* as dwords, with HIGHLOW fixups at *relocated* offsets."""
    code = b"".join(struct.pack("<I", v) for v in operands) + b"\x90" * 16
    raw = path.with_suffix(".raw")
    raw.write_bytes(make_pe(code, image_base=_BASE))
    binary = lief.PE.parse(str(raw))
    assert binary is not None
    block = lief.PE.Relocation()
    block.virtual_address = 0x1000
    for offset in relocated:
        block.add_entry(lief.PE.RelocationEntry(offset, lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW))
    binary.add_relocation(block)
    binary.write(str(path))
    raw.unlink()


def _project(tmp_path: Path, *, link_map: bool = True) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
    (tmp_path / "rebrew-data.toml").write_text(_DATA, encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "build").mkdir()
    # Reference: sites at +0 and +4.  Build: +0 (displaced target) and +8.
    _image(tmp_path / "game.exe", [_TEXT + 0x10, _TEXT + 0x14, _TEXT + 0x18], [0, 4])
    _image(tmp_path / "build" / "game", [_TEXT + 0x11, _TEXT + 0x14, _TEXT + 0x18], [0, 8])
    if link_map:
        (tmp_path / "build" / "game.map").write_text(_MAP, encoding="utf-8")
    return tmp_path


def _run(args: list[str]) -> tuple[int, dict]:
    result = CliRunner().invoke(app, ["binary", "relocs", *args, "--json"])
    return result.exit_code, json.loads(result.stdout)


class TestRelocsCommand:
    def test_missing_and_extra_sites_with_names(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(_project(tmp_path))
        code, out = _run([])
        assert code == 1
        assert (out["reference_sites"], out["built_sites"], out["common_sites"]) == (2, 2, 1)
        assert out["missing_by_section"] == {".text": 1}
        assert out["extra_by_section"] == {".text": 1}
        assert out["missing_sites"] == [
            {
                "site": "0x00401004",
                "type": "HIGHLOW",
                "section": ".text",
                "symbol": "_alpha+0x4",
                "target": "0x00401014",
                "target_section": ".text",
                "target_symbol": "_beta_table+0x4",
                "target_data": "g_table",
            }
        ]
        assert out["extra_sites"][0]["site"] == "0x00401008"
        assert out["extra_sites"][0]["target"] == "0x00401018"
        assert out["extra_sites"][0]["target_symbol"] == "_gamma"
        assert out["extra_sites"][0]["target_data"] is None
        assert out["link_map"].endswith("game.map")
        assert "pairs" not in out

    def test_pairs_show_displaced_targets_in_range(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(_project(tmp_path))
        _, out = _run(["--pairs", "0x401010:0x401014"])
        assert out["pairs"] == [
            {
                "reference": "0x00401010",
                "built": "0x00401011",
                "delta": 1,
                "sites": 1,
                "reference_data": None,
                "built_symbol": "_beta_table+0x1",
            }
        ]

    def test_without_link_map_symbols_are_null(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(_project(tmp_path, link_map=False))
        _, out = _run([])
        assert out["link_map"] is None
        assert out["missing_sites"][0]["symbol"] is None
        assert out["missing_sites"][0]["target_data"] == "g_table"

    def test_identical_tables_exit_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        monkeypatch.chdir(root)
        code, out = _run(["--built", "game.exe"])
        assert code == 0
        assert (out["missing"], out["extra"]) == (0, 0)

    @pytest.mark.parametrize(
        ("args", "message"),
        [
            (["--pairs", "0x10"], "START:END"),
            (["--pairs", "0x20:0x10"], "above START"),
            (["--built", "build/none.exe"], "not found"),
            (["--link-map", "build/none.map"], "link map not found"),
        ],
    )
    def test_bad_input_exits_with_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str], message: str
    ) -> None:
        monkeypatch.chdir(_project(tmp_path))
        result = CliRunner().invoke(app, ["binary", "relocs", *args, "--json"])
        assert result.exit_code == 2
        assert message in result.output

    def test_help_mounts(self) -> None:
        result = CliRunner().invoke(app, ["binary", "relocs", "--help"])
        assert result.exit_code == 0
        assert "--pairs" in result.output
