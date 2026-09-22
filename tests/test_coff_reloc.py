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


def test_function_catalog_scan_is_marker_scoped(tmp_path: Path, monkeypatch) -> None:
    """Only the active target's markers may feed the name→VA map.

    A shared file carries one ``// FUNCTION:`` marker per target and the same
    symbol name sits at a different VA in each binary.  Unfiltered, the last
    marker parsed won the name, so a correct call in the other target's compare
    false-failed REL32 validation (guild-rebrew round 1290: `gm_RandomFloat01`
    resolved to the SERVER VA inside a GOLDTL compare → NEAR_MATCHING on bytes
    that only differed by a relocation).
    """
    from types import SimpleNamespace

    import rebrew.annotation as annotation_mod
    import rebrew.coff_reloc as cr
    import rebrew.data as data_mod
    import rebrew.data_metadata as dm_mod

    src = tmp_path / "src"
    src.mkdir()
    shared = src / "shared.c"
    shared.write_text(
        "// FUNCTION: GAME 0x1000\nvoid shared_fn(void) {}\n"
        "// FUNCTION: OTHER 0x5000\nvoid shared_fn(void) {}\n",
        encoding="utf-8",
    )

    seen: list[str | None] = []
    real_parse = annotation_mod.parse_c_file_multi

    def spy(path, target_name=None, *args, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(target_name)
        return real_parse(path, target_name, *args, **kwargs)

    monkeypatch.setattr(cr, "iter_sources", lambda _dir, _cfg: [shared])
    monkeypatch.setattr(annotation_mod, "parse_c_file_multi", spy)
    monkeypatch.setattr(
        data_mod,
        "scan_globals",
        lambda _dir, _cfg: SimpleNamespace(data_annotations=[], globals={}),
    )
    monkeypatch.setattr(dm_mod, "load_data_metadata", lambda _dir: {})

    cfg = SimpleNamespace(
        reversed_dir=src,
        metadata_dir=tmp_path,
        dll_exports={},
        marker="GAME",
        target_name="game",
    )
    m = cr.build_name_to_va(cfg)  # type: ignore[arg-type]

    assert seen == ["GAME"], "scan must ask for the active target's marker only"
    assert m["shared_fn"] == 0x1000
