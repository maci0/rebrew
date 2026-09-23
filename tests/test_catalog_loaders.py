"""Tests for catalog/loaders.py — Ghidra JSON, function lists, data labels, bytes."""

import json
import warnings
from pathlib import Path
from typing import Any

import pytest

from rebrew.catalog.loaders import (
    _classify_ghidra_label,
    load_function_structure,
    load_ghidra_data_labels,
)


class TestLoadFunctionStructure:
    def test_missing_returns_empty(self, tmp_path: Path) -> None:
        assert load_function_structure(tmp_path / "nope.json") == []

    def test_valid(self, tmp_path: Path) -> None:
        p = tmp_path / "function_structure.json"
        p.write_text(json.dumps([{"va": "0x10001000", "size": 64, "name": "a"}]), encoding="utf-8")
        entries = load_function_structure(p)
        assert len(entries) == 1
        assert entries[0].va == 0x10001000
        assert entries[0].size == 64

    def test_non_list_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "function_structure.json"
        p.write_text(json.dumps({"va": 1}), encoding="utf-8")
        with pytest.raises(ValueError, match="Expected a JSON array"):
            load_function_structure(p)

    def test_corrupt_json_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "function_structure.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValueError, match="Corrupt structure JSON"):
            load_function_structure(p)


class TestClassifyGhidraLabel:
    def test_thunk(self) -> None:
        assert _classify_ghidra_label("thunk_FUN_1000") == "thunk"

    def test_data(self) -> None:
        assert _classify_ghidra_label("switchdataD_1000") == "data"
        assert _classify_ghidra_label("") == "data"


class TestLoadGhidraDataLabels:
    def test_missing_returns_empty(self, tmp_path: Path) -> None:
        assert load_ghidra_data_labels(tmp_path) == {}

    def test_none_src_dir(self) -> None:
        assert load_ghidra_data_labels(None) == {}

    def test_new_format_with_thunk_classification(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_data_labels.json").write_text(
            json.dumps(
                [
                    {"va": 0x10002000, "size": 4, "label": "g_thing"},
                    {"va": 0x10003000, "size": 6, "label": "thunk_FUN_3000"},
                ]
            ),
            encoding="utf-8",
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert labels[0x10002000].state == "data"
        assert labels[0x10003000].state == "thunk"

    def test_legacy_fallback(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_switchdata.json").write_text(
            json.dumps([{"va": 0x10001000, "size": 8}]),
            encoding="utf-8",
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert 0x10001000 in labels
        assert labels[0x10001000].size == 8

    def test_corrupt_warns_and_empty(self, tmp_path: Path) -> None:
        # Only the legacy file exists and it is corrupt → warn + empty.
        (tmp_path / "ghidra_switchdata.json").write_text("{oops", encoding="utf-8")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            out = load_ghidra_data_labels(tmp_path)
        assert out == {}
        assert any("corrupt" in str(x.message).lower() for x in w)

    def test_non_dict_entries_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_data_labels.json").write_text(
            json.dumps([42, {"va": 0x10001000, "size": 4, "label": "x"}]),
            encoding="utf-8",
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert list(labels) == [0x10001000]


class TestLoadGhidraDataLabelsMore:
    def test_non_list_entries_warns(self, tmp_path: Path) -> None:
        import json

        from rebrew.catalog.loaders import load_ghidra_data_labels

        (tmp_path / "ghidra_data_labels.json").write_text(json.dumps({"va": 1}), encoding="utf-8")
        with pytest.warns(UserWarning, match="expected JSON array"):
            assert load_ghidra_data_labels(tmp_path) == {}

    def test_legacy_format_fallback(self, tmp_path: Path) -> None:
        import json

        from rebrew.catalog.loaders import load_ghidra_data_labels

        (tmp_path / "ghidra_switchdata.json").write_text(
            json.dumps([{"va": 0x1000, "size": 8}]), encoding="utf-8"
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert 0x1000 in labels

    def test_corrupt_json_warns(self, tmp_path: Path) -> None:
        from rebrew.catalog.loaders import load_ghidra_data_labels

        (tmp_path / "ghidra_data_labels.json").write_text("{broken", encoding="utf-8")
        with pytest.warns(UserWarning, match="corrupt"):
            assert load_ghidra_data_labels(tmp_path) == {}


class TestScanReversedDirLibraryHeaders:
    def test_library_header_markers_included(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.catalog.loaders import scan_reversed_dir

        src = tmp_path / "src"
        src.mkdir()
        (src / "library_msvc.h").write_text(
            "// LIBRARY: SERVER 0x1000\n// _fflush\n", encoding="utf-8"
        )
        cfg = SimpleNamespace(metadata_dir=tmp_path, marker="SERVER", source_ext=".c")
        entries = scan_reversed_dir(src, cfg=cfg)
        assert any(e.va == 0x1000 and e.marker_type == "LIBRARY" for e in entries)

    def test_library_header_merges_metadata_status(self, tmp_path: Path) -> None:
        """verify/test STATUS in TOML must win over the EXACT library default."""
        from types import SimpleNamespace

        from rebrew.catalog.loaders import scan_reversed_dir
        from rebrew.metadata import save_metadata

        src = tmp_path / "src"
        src.mkdir()
        (src / "library_msvc.h").write_text(
            "// LIBRARY: SERVER 0x1000\n// _fflush\n", encoding="utf-8"
        )
        save_metadata(
            tmp_path,
            {("SERVER", 0x1000): {"status": "NEAR_MATCHING", "blocker": "1B diff"}},
        )
        cfg = SimpleNamespace(metadata_dir=tmp_path, marker="SERVER", source_ext=".c")
        entries = scan_reversed_dir(src, cfg=cfg)
        lib = next(e for e in entries if e.va == 0x1000)
        assert lib.status == "NEAR_MATCHING"
        assert lib.blocker == "1B diff"


class TestParseRizinAfl:
    """Shared rizin ``afl`` parser (discover + intake used to hand-roll
    two subtly different copies of this)."""

    def test_three_column(self) -> None:
        from rebrew.catalog.loaders import parse_rizin_afl

        out = parse_rizin_afl("0x1000 16 func_a\n0x2000 32 func_b\n")
        assert out == [(0x1000, 16, "func_a"), (0x2000, 32, "func_b")]

    def test_four_column(self) -> None:
        from rebrew.catalog.loaders import parse_rizin_afl

        out = parse_rizin_afl("0x1000 0x1000 16 func_a\n")
        assert out == [(0x1000, 16, "func_a")]

    def test_non_decimal_digit_column_does_not_crash(self) -> None:
        from rebrew.catalog.loaders import parse_rizin_afl

        # "\u00b2".isdigit() is True but int() rejects it.
        out = parse_rizin_afl("0x1000 16 \u00b2 func_a\n")
        assert out == [(0x1000, 16, "\u00b2")]

    def test_hex_sizes_tolerated(self) -> None:
        from rebrew.catalog.loaders import parse_rizin_afl

        # Some rizin versions print sizes as 0x-prefixed hex (int(x, 0)).
        out = parse_rizin_afl("0x1000 0x10 func_a\n")
        assert out == [(0x1000, 16, "func_a")]

    def test_name_normalization(self) -> None:
        from rebrew.catalog.loaders import parse_rizin_afl

        out = parse_rizin_afl("0x1000 16 ->\n0x2000 16 loc\n0x3000 16 sub.foo\n")
        assert out == [
            (0x1000, 16, "fcn.00001000"),
            (0x2000, 16, "fcn.00002000"),
            (0x3000, 16, "fcn.00003000"),
        ]

    def test_garbage_lines_skipped(self) -> None:
        from rebrew.catalog.loaders import parse_rizin_afl

        out = parse_rizin_afl("nope 1 2\n0x1000 16 func_a\n\n")
        assert out == [(0x1000, 16, "func_a")]


class TestCachedFunctionList:
    """Path-keyed inventory cache: mtime in the value, bounded growth."""

    def test_rewrite_replaces_slot_not_orphan_keys(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os
        from types import SimpleNamespace

        from rebrew.catalog import loaders as loaders_mod
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        monkeypatch.setattr(loaders_mod, "_function_list_cache", {})
        inv = tmp_path / FUNCTION_STRUCTURE_JSON
        inv.write_text(
            json.dumps([{"va": "0x1000", "size": 8, "name": "a"}]),
            encoding="utf-8",
        )
        cfg = SimpleNamespace(reversed_dir=str(tmp_path))
        first = loaders_mod.cached_function_list(cfg)
        assert first == [{"va": 0x1000, "size": 8, "name": "a"}]
        assert len(loaders_mod._function_list_cache) == 1

        previous_stat = inv.stat()
        inv.write_text(
            json.dumps([{"va": "0x2000", "size": 16, "name": "b"}]),
            encoding="utf-8",
        )
        os.utime(inv, ns=(previous_stat.st_atime_ns, previous_stat.st_mtime_ns + 2_000_000_000))
        second = loaders_mod.cached_function_list(cfg)
        assert second == [{"va": 0x2000, "size": 16, "name": "b"}]
        # Same path key — no orphaned path:mtime entries.
        assert len(loaders_mod._function_list_cache) == 1

    def test_same_mtime_size_change_invalidates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rewrite that preserves mtime but changes size must not hit stale data."""
        import os
        from types import SimpleNamespace

        from rebrew.catalog import loaders as loaders_mod
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        monkeypatch.setattr(loaders_mod, "_function_list_cache", {})
        inv = tmp_path / FUNCTION_STRUCTURE_JSON
        inv.write_text(
            json.dumps([{"va": "0x1000", "size": 8, "name": "a"}]),
            encoding="utf-8",
        )
        cfg = SimpleNamespace(reversed_dir=str(tmp_path))
        assert loaders_mod.cached_function_list(cfg) == [{"va": 0x1000, "size": 8, "name": "a"}]
        previous_stat = inv.stat()
        inv.write_text(
            json.dumps([{"va": "0x2000", "size": 16, "name": "b"}, {"va": "0x3000", "size": 4}]),
            encoding="utf-8",
        )
        # Preserve mtime (cp -p / coarse FS same-ns rewrite); size still changes.
        os.utime(inv, ns=(previous_stat.st_atime_ns, previous_stat.st_mtime_ns))
        assert inv.stat().st_mtime_ns == previous_stat.st_mtime_ns
        assert inv.stat().st_size != previous_stat.st_size
        assert loaders_mod.cached_function_list(cfg) == [
            {"va": 0x2000, "size": 16, "name": "b"},
            {"va": 0x3000, "size": 4, "name": ""},
        ]

    def test_failed_load_is_not_memoized(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A transient read error must not pin [] under an unchanged mtime/size."""
        from types import SimpleNamespace

        from rebrew.catalog import loaders as loaders_mod
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        monkeypatch.setattr(loaders_mod, "_function_list_cache", {})
        (tmp_path / FUNCTION_STRUCTURE_JSON).write_text(
            json.dumps([{"va": "0x1000", "size": 8, "name": "a"}]),
            encoding="utf-8",
        )
        cfg = SimpleNamespace(reversed_dir=str(tmp_path))
        real_load = loaders_mod.load_function_structure

        def _failing_load(_path: Path) -> list[Any]:
            raise OSError("transient")

        monkeypatch.setattr(loaders_mod, "load_function_structure", _failing_load)
        assert loaders_mod.cached_function_list(cfg) == []
        assert loaders_mod._function_list_cache == {}
        monkeypatch.setattr(loaders_mod, "load_function_structure", real_load)
        assert loaders_mod.cached_function_list(cfg) == [{"va": 0x1000, "size": 8, "name": "a"}]

    def test_evicts_when_full(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from types import SimpleNamespace

        from rebrew.catalog import loaders as loaders_mod
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        monkeypatch.setattr(loaders_mod, "_FUNCTION_LIST_CACHE_MAX", 2)
        monkeypatch.setattr(loaders_mod, "_function_list_cache", {})
        for i in range(3):
            d = tmp_path / f"p{i}"
            d.mkdir()
            (d / FUNCTION_STRUCTURE_JSON).write_text(
                json.dumps([{"va": hex(0x1000 + i), "size": 4, "name": f"f{i}"}]),
                encoding="utf-8",
            )
            assert loaders_mod.cached_function_list(SimpleNamespace(reversed_dir=str(d))) == [
                {"va": 0x1000 + i, "size": 4, "name": f"f{i}"}
            ]
            assert len(loaders_mod._function_list_cache) == min(i + 1, 2)
        assert set(loaders_mod._function_list_cache) == {
            str(tmp_path / "p1" / FUNCTION_STRUCTURE_JSON),
            str(tmp_path / "p2" / FUNCTION_STRUCTURE_JSON),
        }

    def test_vas_survive_rewrite_during_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rewrite between the VA lookup's stat and the reload must not yield an empty set."""
        from types import SimpleNamespace

        from rebrew.catalog import loaders as loaders_mod
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        monkeypatch.setattr(loaders_mod, "_function_list_cache", {})
        monkeypatch.setattr(loaders_mod, "_function_vas_cache", {})
        (tmp_path / FUNCTION_STRUCTURE_JSON).write_text(
            json.dumps([{"va": "0x1000", "size": 8, "name": "a"}]),
            encoding="utf-8",
        )
        # Each stat sees a newer fingerprint, as if another process rewrote the file.
        stamps = iter(["1:1", "2:1"])
        monkeypatch.setattr(loaders_mod, "_inventory_fingerprint", lambda _p: next(stamps))
        cfg = SimpleNamespace(reversed_dir=str(tmp_path))
        assert loaders_mod.cached_function_vas(cfg) == frozenset({0x1000})
