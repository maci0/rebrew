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
from typing import Any

import pytest

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
    m = build_name_to_va(cfg, annotations=anns)
    assert m.get("game_fn") == 0x1000
    assert m.get("global_thing") == 0x3000
    assert "fclose" not in m


@pytest.mark.parametrize("provided_annotations", [False, True])
@pytest.mark.parametrize("native_symbol", ["_current_year", "??_C@format@"])
def test_verified_native_data_symbol_enters_marker_scoped_catalog(
    tmp_path: Path, provided_annotations: bool, native_symbol: str
) -> None:
    from rebrew.coff_reloc import build_symbol_resolver, smart_reloc_compare
    from rebrew.data_metadata import set_data_fields_batch

    (tmp_path / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")
    (tmp_path / "src").mkdir()
    set_data_fields_batch(
        tmp_path,
        [
            {
                "module": "GAME",
                "va": 0x401000,
                "fields": {"name": "analysis_label", "link_symbol": native_symbol},
            },
            {
                "module": "OTHER",
                "va": 0x501000,
                "fields": {"name": "other_label", "link_symbol": native_symbol},
            },
            {"module": "GAME", "va": 0x401004, "fields": {"name": "wrong_target"}},
        ],
    )
    names = build_name_to_va(
        load_config(root=tmp_path), annotations=[] if provided_annotations else None
    )
    assert names["analysis_label"] == names[native_symbol] == 0x401000
    assert "other_label" not in names
    assert build_symbol_resolver({}, names)(native_symbol) == 0x401000
    reference = (0x401000).to_bytes(4, "little")
    assert smart_reloc_compare(bytes(4), reference, {0: native_symbol}, name_to_va=names)[0]
    wrong = (0x401004).to_bytes(4, "little")
    assert not smart_reloc_compare(bytes(4), wrong, {0: native_symbol}, name_to_va=names)[0]


def test_name_map_does_not_walk_variable_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reloc validation reads names and VAs, not use sets.

    ``find_variable_roles`` walks every statement of every source. The name
    map must not call it. The counter is the call, and the annotated global
    still lands in the map.
    """
    import rebrew.c_parser as c_parser

    (tmp_path / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "g.c").write_text(
        "// GLOBAL: GAME 0x401000\n"
        "int shared_value;\n"
        "// FUNCTION: GAME 0x1000\n"
        "int f(void) { return shared_value; }\n",
        encoding="utf-8",
    )
    cfg = load_config(root=tmp_path)
    calls = {"n": 0}
    real = c_parser.find_variable_roles

    def _counting(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(c_parser, "find_variable_roles", _counting)
    names = build_name_to_va(cfg, annotations=[])
    assert calls["n"] == 0
    assert names.get("shared_value") == 0x401000


def test_function_catalog_scan_is_marker_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    import rebrew.data_metadata as dm_mod
    import rebrew.data_scan as data_mod

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
        lambda _dir, _cfg, *, record_roles: SimpleNamespace(data_annotations=[], globals={}),
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


class TestStrictOperandProof:
    @pytest.mark.parametrize("typed", [False, True])
    @pytest.mark.parametrize(
        "bound,actual,expected", [(0x1200, 0x1204, True), (0x2200, 0x1204, False)]
    )
    def test_mapped_dir32_requires_the_actual_address(
        self, typed: bool, bound: int, actual: int, expected: bool
    ) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        obj = (4).to_bytes(4, "little")
        native = actual.to_bytes(4, "little")
        records = [CoffRelocRecord(0, 6, "_table")] if typed else {0: "_table"}
        catalog = {"_table": bound}
        assert smart_reloc_compare(obj, native, records, catalog)[0]
        result = smart_reloc_compare(obj, native, records, catalog, strict=True)
        assert result[0] is expected
        assert result[4] == ([] if expected else [0])

    @pytest.mark.parametrize("typed", [False, True])
    @pytest.mark.parametrize("catalog", [{}, {"_unrelated": 0x9000}])
    def test_unbound_dir32_cannot_claim_a_proof(self, typed: bool, catalog: dict[str, int]) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        records = [CoffRelocRecord(0, 6, "_table")] if typed else {0: "_table"}
        result = smart_reloc_compare(bytes(4), bytes(4), records, catalog, strict=True)
        assert not result[0]
        assert result[4] == [0]

    def test_wrong_array_end_addend_is_not_masked(self) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        obj = bytes(4) + (768 * 16).to_bytes(4, "little")
        native = (0x930600).to_bytes(4, "little") + (0x930600 + 32 * 16).to_bytes(4, "little")
        records = [CoffRelocRecord(0, 6, "_rows"), CoffRelocRecord(4, 6, "_rows")]
        catalog = {"_rows": 0x770B80}
        assert smart_reloc_compare(obj, native, records, catalog)[0]
        result = smart_reloc_compare(obj, native, records, catalog, strict=True)
        assert not result[0] and result[4] == [0, 4]

    def test_local_switch_targets_reject_each_wrong_binding(self) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        catalog = {"$L_map": 0x102C, "$L_table": 0x1024, "$L_zero": 0x1019, "$L_two": 0x101C}
        records = [CoffRelocRecord(i * 4, 6, name) for i, name in enumerate(catalog)]
        obj = bytes(16)
        native = b"".join(va.to_bytes(4, "little") for va in catalog.values())
        assert smart_reloc_compare(obj, native, records, catalog, strict=True)[0]
        for i, name in enumerate(catalog):
            wrong = dict(catalog)
            wrong[name] += 4
            result = smart_reloc_compare(obj, native, records, wrong, strict=True)
            assert not result[0] and result[4] == [i * 4]

    def test_explicit_iat_region_keeps_its_policy(self) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        records = [CoffRelocRecord(0, 6, "__imp_api")]
        native = (0x1200).to_bytes(4, "little")
        catalog = {"__imp_api": 0x2200}
        assert smart_reloc_compare(
            bytes(4), native, records, catalog, iat_region=frozenset({0x1200}), strict=True
        )[0]
        assert not smart_reloc_compare(bytes(4), native, records, catalog, strict=True)[0]

    @pytest.mark.parametrize(
        "kind,section_va,catalog",
        [
            (20, None, {"_callee": 0x1020}),
            (20, 0x1000, {"_unrelated": 0x1020}),
            (255, 0x1000, {"_callee": 0x1020}),
        ],
    )
    def test_unprovable_typed_slots_fail_even_when_raw_bytes_agree(
        self, kind: int, section_va: int | None, catalog: dict[str, int]
    ) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        records = [CoffRelocRecord(0, kind, "_callee")]
        assert smart_reloc_compare(bytes(4), bytes(4), records, catalog, section_va=section_va)[0]
        result = smart_reloc_compare(
            bytes(4), bytes(4), records, catalog, section_va=section_va, strict=True
        )
        assert not result[0] and result[4] == [0]

    def test_strict_rel32_uses_pc_and_addend(self) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        records = [CoffRelocRecord(0, 20, "_callee")]
        obj = (4).to_bytes(4, "little")
        native = (0x100).to_bytes(4, "little")
        assert smart_reloc_compare(
            obj, native, records, {"_callee": 0x1100}, section_va=0x1000, strict=True
        )[0]
        assert not smart_reloc_compare(
            obj, native, records, {"_callee": 0x1104}, section_va=0x1000, strict=True
        )[0]

    def test_plain_masks_and_implicit_zero_slots_are_not_a_proof(self) -> None:
        from rebrew.coff_reloc import smart_reloc_compare

        assert smart_reloc_compare(bytes(4), bytes(4), [0])[0]
        result = smart_reloc_compare(bytes(4), bytes(4), [0], strict=True)
        assert not result[0] and result[4] == [0]
        native = (0x1234).to_bytes(4, "little")
        assert smart_reloc_compare(bytes(4), native)[0]
        assert not smart_reloc_compare(bytes(4), native, strict=True)[0]
        assert smart_reloc_compare(bytes(4), bytes(4), strict=True)[0]

    @pytest.mark.parametrize("shape", ["typed", "dict", "offsets"])
    @pytest.mark.parametrize("offset", [-1, 1, 4])
    def test_out_of_extent_claims_fail_strict_proof(self, shape: str, offset: int) -> None:
        from rebrew.coff_reloc import CoffRelocRecord, smart_reloc_compare

        records_by_shape: dict[str, list[CoffRelocRecord] | dict[int, str] | list[int]] = {
            "typed": [CoffRelocRecord(offset, 6, "_table")],
            "dict": {offset: "_table"},
            "offsets": [offset],
        }
        records = records_by_shape[shape]
        assert smart_reloc_compare(bytes(4), bytes(4), records, {"_table": 0})[0]
        result = smart_reloc_compare(bytes(4), bytes(4), records, {"_table": 0}, strict=True)
        assert not result[0] and result[4] == [offset]
