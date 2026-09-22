"""`coff_reloc.build_name_to_va` — what enters the reloc-validation catalog.

LIBRARY rows are identifications (FLIRT/Ghidra attributions) and were
seen with swapped names (`_fclose` vs `__fflush_lk`), so validating call
relocations against them false-fails the byte compare — `rebrew test`
(source-only catalog) said RELOC while `rebrew verify` (annotation
catalog) said NEAR on identical bytes.  They must stay out of the map;
everything else (data rows, exports, FUNCTION names) must stay in.
"""

from __future__ import annotations

from pathlib import Path

from rebrew.coff_reloc import build_name_to_va
from rebrew.config import load_config

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

[compiler]
profile = "gcc-14.2.0"
command = "gcc"
includes = ""
libs = ""
"""


class _FakeAnn:
    def __init__(self, name: str, va: int, marker_type: str) -> None:
        self.name = name
        self.va = va
        self.marker_type = marker_type
        self.module = "GAME"


def test_library_rows_stay_out_of_the_catalog(tmp_path: Path) -> None:
    (tmp_path / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")
    (tmp_path / "src").mkdir()
    cfg = load_config(root=tmp_path)

    anns = [
        _FakeAnn("game_fn", 0x1000, "FUNCTION"),
        _FakeAnn("fclose", 0x2000, "LIBRARY"),  # swapped attribution (guild case)
        _FakeAnn("global_thing", 0x3000, "GLOBAL"),
    ]
    m = build_name_to_va(cfg, annotations=anns)  # type: ignore[arg-type]
    assert m.get("game_fn") == 0x1000
    assert m.get("global_thing") == 0x3000
    assert "fclose" not in m
