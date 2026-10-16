"""Single-file ``rebrew test`` reuses a target-scoped name map.

The shipped preamble (``_lint_preamble``) must resolve a symbol defined in
another file without parsing a large reversed tree on every call, must not
borrow another target's VA, and must still fail closed when the scan cannot
build a map. The speed gate counts C parses and global scans. Those counts
do not move when the machine is busy.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from source_util import write_source

from rebrew.coff_reloc import relocation_binding_evidence, smart_reloc_compare
from rebrew.config import load_config
from rebrew.test import _lint_preamble

_PROJECT_TOML = """\
[project]
name = "t"
default_target = "game"
shared_dir = ""

[targets.game]
binary = "bin/game.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
module = "GAME"

[targets.other]
binary = "bin/other.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
module = "OTHER"

[compiler]
profile = "gcc-14.2.0"
command = "gcc"
includes = ""
libs = ""
"""

_FILLER_COUNT = 2000
_HELPER_VA = 0x2000
_OTHER_HELPER_VA = 0x6000
_ONLY_OTHER_VA = 0x5000
_ADDED_VA = 0x2100


def _project(root: Path, *, fillers: int = 0) -> None:
    (root / "rebrew-project.toml").write_text(_PROJECT_TOML, encoding="utf-8")
    src = root / "src"
    src.mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "bin" / "game.exe").write_bytes(b"game")
    (root / "bin" / "other.exe").write_bytes(b"other")
    write_source(
        src / "helper.c",
        "/* ADDRESS: GAME 0x2000 */\nvoid helper(void) {}\n",
        metadata_fields={"GAME.0x2000": {"kind": "FUNCTION", "size": 4}},
    )
    write_source(
        src / "caller.c",
        "/* ADDRESS: GAME 0x1000 */\nvoid caller(void) { helper(); }\n",
        metadata_fields={"GAME.0x1000": {"kind": "FUNCTION", "size": 4}},
    )
    write_source(
        src / "foreign.c",
        "/* ADDRESS: OTHER 0x5000 */\nvoid only_other(void) {}\n"
        "/* ADDRESS: OTHER 0x6000 */\nvoid helper(void) {}\n",
        metadata_fields={
            "OTHER.0x5000": {"kind": "FUNCTION", "size": 4},
            "OTHER.0x6000": {"kind": "FUNCTION", "size": 4},
        },
    )
    if fillers:
        fill = src / "fill"
        fill.mkdir()
        for index in range(fillers):
            (fill / f"filler_{index}.c").write_text(
                f"void filler_{index}(void) {{}}\n",
                encoding="utf-8",
            )


def _binding(name_to_va: dict[str, int], symbol: str, native_va: int) -> dict[str, object]:
    rows = relocation_binding_evidence(
        b"\x00\x00\x00\x00",
        native_va.to_bytes(4, "little"),
        {0: symbol},
        name_to_va,
    )
    assert len(rows) == 1
    return rows[0]


def _preamble(root: Path, source: str, *, target: str | None = None) -> dict[str, int]:
    cfg = load_config(root, target=target)
    _annotations, name_to_va = _lint_preamble(
        cfg,
        str(root / "src" / source),
        size=None,
        json_output=True,
    )
    return name_to_va


def _measured_preamble(
    monkeypatch: pytest.MonkeyPatch,
    cfg: Any,
    source: str,
) -> tuple[dict[str, int], int, int]:
    """Run the shipped preamble and count C parses and global scans."""
    import rebrew.c_parser as c_parser
    import rebrew.data_scan as data_scan

    parses = 0
    scans = 0
    real_parse = c_parser.parse_c_source
    real_scan = data_scan.scan_globals

    def _parse(text: str | bytes) -> tuple[Any, bytes]:
        nonlocal parses
        parses += 1
        return real_parse(text)

    def _scan(*args: Any, **kwargs: Any) -> Any:
        nonlocal scans
        scans += 1
        return real_scan(*args, **kwargs)

    monkeypatch.setattr(c_parser, "parse_c_source", _parse)
    monkeypatch.setattr(data_scan, "scan_globals", _scan)
    try:
        _annotations, name_to_va = _lint_preamble(cfg, source, size=None, json_output=True)
    finally:
        monkeypatch.setattr(c_parser, "parse_c_source", real_parse)
        monkeypatch.setattr(data_scan, "scan_globals", real_scan)
    return name_to_va, parses, scans


class TestSingleFileNameMap:
    def test_large_tree_matches_small_project_parse_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        small = tmp_path / "small"
        large = tmp_path / "large"
        small.mkdir()
        large.mkdir()
        _project(small)
        _project(large, fillers=_FILLER_COUNT)
        fillers = list((large / "src" / "fill").glob("filler_*.c"))
        assert len(fillers) >= _FILLER_COUNT
        caller = (large / "src" / "caller.c").read_text(encoding="utf-8")
        helper = (large / "src" / "helper.c").read_text(encoding="utf-8")
        assert "0x2000" not in caller
        assert "helper" in helper

        small_cfg = load_config(small)
        large_cfg = load_config(large)
        small_source = str(small / "src" / "caller.c")
        large_source = str(large / "src" / "caller.c")
        cold_map, cold_parses, cold_scans = _measured_preamble(monkeypatch, large_cfg, large_source)
        assert cold_scans == 1
        assert cold_parses > _FILLER_COUNT
        warm_map, warm_parses, warm_scans = _measured_preamble(monkeypatch, large_cfg, large_source)
        import rebrew.test as test_mod

        test_mod._name_map_cache.clear()
        disk_map, disk_parses, disk_scans = _measured_preamble(monkeypatch, large_cfg, large_source)
        _measured_preamble(monkeypatch, small_cfg, small_source)
        small_map, small_parses, small_scans = _measured_preamble(
            monkeypatch, small_cfg, small_source
        )
        assert warm_scans == disk_scans == small_scans == 0
        assert warm_parses == disk_parses == small_parses
        assert warm_parses < _FILLER_COUNT
        assert disk_map["_helper"] == warm_map["_helper"] == cold_map["_helper"] == _HELPER_VA

        large_map = warm_map
        small_helper = _binding(small_map, "_helper", _HELPER_VA)
        large_helper = _binding(large_map, "_helper", _HELPER_VA)
        small_foreign = _binding(small_map, "_only_other", _ONLY_OTHER_VA)
        large_foreign = _binding(large_map, "_only_other", _ONLY_OTHER_VA)
        assert large_helper == small_helper
        assert large_foreign == small_foreign
        assert large_helper["status"] == "VALIDATED"
        assert large_helper["bound_va"] == _HELPER_VA
        assert large_foreign["status"] == "UNRESOLVED"
        assert large_foreign["bound_va"] is None
        assert large_map["helper"] == large_map["_helper"] == _HELPER_VA
        assert "only_other" not in large_map
        assert "_only_other" not in large_map
        assert _OTHER_HELPER_VA not in large_map.values()
        assert _ONLY_OTHER_VA not in large_map.values()
        assert "filler_0" not in large_map
        assert "_filler_0" not in large_map

    def test_other_target_keeps_its_own_va(self, tmp_path: Path) -> None:
        _project(tmp_path)
        game = _preamble(tmp_path, "caller.c", target="game")
        other = _preamble(tmp_path, "foreign.c", target="other")
        assert game["helper"] == _HELPER_VA
        assert "only_other" not in game
        assert _ONLY_OTHER_VA not in game.values()
        assert other["only_other"] == other["_only_other"] == _ONLY_OTHER_VA
        assert other["helper"] == other["_helper"] == _OTHER_HELPER_VA
        game_row = _binding(game, "_helper", _HELPER_VA)
        other_row = _binding(other, "_only_other", _ONLY_OTHER_VA)
        stolen = _binding(game, "_only_other", _ONLY_OTHER_VA)
        assert game_row["status"] == "VALIDATED"
        assert game_row["bound_va"] == _HELPER_VA
        assert other_row["status"] == "VALIDATED"
        assert other_row["bound_va"] == _ONLY_OTHER_VA
        assert stolen["status"] == "UNRESOLVED"
        assert stolen["bound_va"] is None

    def test_disk_hit_does_not_rebuild(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.test as test_mod

        _project(tmp_path)
        first = _preamble(tmp_path, "caller.c")
        assert first["_helper"] == _HELPER_VA
        cache = tmp_path / ".rebrew" / "name_to_va_cache.json"
        assert cache.is_file()
        test_mod._name_map_cache.clear()

        def _boom(*_args: object, **_kwargs: object) -> dict[str, int]:
            raise AssertionError("name map was rebuilt")

        monkeypatch.setattr(test_mod, "build_name_to_va", _boom)
        second = _preamble(tmp_path, "caller.c")
        assert second["_helper"] == _HELPER_VA
        assert second is not first

    def test_other_target_cache_is_not_reused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.test as test_mod

        _project(tmp_path)
        other = _preamble(tmp_path, "foreign.c", target="other")
        assert other["helper"] == _OTHER_HELPER_VA
        test_mod._name_map_cache.clear()
        calls = {"n": 0}
        real = test_mod.build_name_to_va

        def _counting(cfg: object, **kwargs: object) -> dict[str, int]:
            calls["n"] += 1
            return real(cfg, **kwargs)

        monkeypatch.setattr(test_mod, "build_name_to_va", _counting)
        game = _preamble(tmp_path, "caller.c", target="game")
        assert calls["n"] == 1
        assert game["helper"] == _HELPER_VA
        assert "only_other" not in game

    def test_new_source_invalidates_the_cached_map(self, tmp_path: Path) -> None:
        _project(tmp_path)
        before = _preamble(tmp_path, "caller.c")
        assert "added" not in before
        write_source(
            tmp_path / "src" / "extra.c",
            "/* ADDRESS: GAME 0x2100 */\nvoid added(void) {}\n",
            metadata_fields={"GAME.0x2100": {"kind": "FUNCTION", "size": 4}},
        )
        after = _preamble(tmp_path, "caller.c")
        assert after["added"] == after["_added"] == _ADDED_VA
        assert after["helper"] == _HELPER_VA
        added = _binding(after, "_added", _ADDED_VA)
        assert added["status"] == "VALIDATED"
        assert added["bound_va"] == _ADDED_VA

    def test_bool_va_in_the_disk_cache_is_rebuilt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.test as test_mod

        _project(tmp_path)
        _preamble(tmp_path, "caller.c")
        cache = tmp_path / ".rebrew" / "name_to_va_cache.json"
        payload = json.loads(cache.read_text(encoding="utf-8"))
        payload["map"]["_helper"] = True
        cache.write_text(json.dumps(payload), encoding="utf-8")
        test_mod._name_map_cache.clear()
        calls = {"n": 0}
        real = test_mod.build_name_to_va

        def _counting(cfg: object, **kwargs: object) -> dict[str, int]:
            calls["n"] += 1
            return real(cfg, **kwargs)

        monkeypatch.setattr(test_mod, "build_name_to_va", _counting)
        name_to_va = _preamble(tmp_path, "caller.c")
        assert calls["n"] == 1
        assert name_to_va["_helper"] == _HELPER_VA
        assert isinstance(name_to_va["_helper"], int)
        assert not isinstance(name_to_va["_helper"], bool)

    def test_scan_failure_does_not_validate(self) -> None:
        with pytest.raises(typer.Exit) as first:
            _lint_preamble(SimpleNamespace(), "missing.c", size=None, json_output=True)
        with pytest.raises(typer.Exit) as second:
            _lint_preamble(SimpleNamespace(), "missing.c", size=None, json_output=True)
        assert first.value.exit_code == 2
        assert second.value.exit_code == 2
        obj = b"\x00\x00\x00\x00"
        target = _ONLY_OTHER_VA.to_bytes(4, "little")
        rows = relocation_binding_evidence(obj, target, {0: "_only_other"}, {})
        assert rows[0]["status"] == "UNRESOLVED"
        assert rows[0]["bound_va"] is None
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj, target, {0: "_only_other"}, name_to_va={}
        )
        assert matched is False
        assert valid == []
        assert invalid == [0]
