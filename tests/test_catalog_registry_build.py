"""Tests for catalog/registry.build_function_registry — merging + size resolution."""

import json
from pathlib import Path
from types import SimpleNamespace

from rebrew.catalog.registry import build_function_registry


def _cfg(**overrides: object) -> SimpleNamespace:
    defaults: dict = {"dll_exports": {}, "r2_bogus_vas": set(), "iat_thunks": set()}
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestBuildFunctionRegistry:
    def test_merges_list_and_ghidra(self, tmp_path: Path) -> None:
        funcs = [{"va": 0x1000, "size": 100, "name": "fn_a"}]
        ghidra_path = tmp_path / "function_structure.json"
        ghidra_path.write_text(
            json.dumps([{"va": "0x1000", "size": 200, "tool_name": "FUN_10001000"}]),
            encoding="utf-8",
        )
        registry = build_function_registry(funcs, _cfg(), ghidra_path=ghidra_path)
        entry = registry[0x1000]
        assert "list" in entry["detected_by"]
        assert "ghidra" in entry["detected_by"]
        assert entry["size_by_tool"] == {"list": 100, "ghidra": 200}
        # ghidra larger → canonical = ghidra
        assert entry["canonical_size"] == 200
        assert entry["size_reason"] == "ghidra (larger or equal)"

    def test_exports_marked(self, tmp_path: Path) -> None:
        funcs = [{"va": 0x1000, "size": 100, "name": "fn_a"}]
        cfg = _cfg(dll_exports={0x2000: "ExportFn"})
        registry = build_function_registry(funcs, cfg)
        assert registry[0x2000]["is_export"] is True
        assert "exports" in registry[0x2000]["detected_by"]
        assert registry[0x2000]["canonical_size"] == 0  # no size known

    def test_r2_bogus_vas_skipped(self, tmp_path: Path) -> None:
        funcs = [
            {"va": 0x1000, "size": 100, "name": "fn_a"},
            {"va": 0x2000, "size": 64, "name": "bogus_fn"},
        ]
        cfg = _cfg(r2_bogus_vas={0x2000})
        registry = build_function_registry(funcs, cfg)
        assert "list" in registry[0x2000]["detected_by"]
        assert "list" not in registry[0x2000]["size_by_tool"]

    def test_no_ghidra_path(self, tmp_path: Path) -> None:
        funcs = [{"va": 0x1000, "size": 100, "name": "fn_a"}]
        registry = build_function_registry(funcs, _cfg(), ghidra_path=None)
        assert registry[0x1000]["canonical_size"] == 100
        assert registry[0x1000]["size_reason"] == "list (only source)"

    def test_missing_binary_falls_back(self, tmp_path: Path) -> None:
        """No binary → text_data None → list>ghidra resolves to ghidra size."""
        funcs = [{"va": 0x1000, "size": 100, "name": "fn_a"}]
        ghidra_path = tmp_path / "function_structure.json"
        ghidra_path.write_text(
            json.dumps([{"va": "0x1000", "size": 50, "tool_name": "g"}]),
            encoding="utf-8",
        )
        registry = build_function_registry(
            funcs, _cfg(), ghidra_path=ghidra_path, bin_path=tmp_path / "missing.dll"
        )
        entry = registry[0x1000]
        assert entry["canonical_size"] == 50
        assert entry["size_reason"] == "ghidra (no binary data to verify)"

    def test_binary_text_section_used(self, tmp_path: Path, monkeypatch: object) -> None:

        funcs = [{"va": 0x1000, "size": 100, "name": "fn_a"}]
        ghidra_path = tmp_path / "function_structure.json"
        ghidra_path.write_text(
            json.dumps([{"va": 0x1000, "size": 50, "tool_name": "g"}]),
            encoding="utf-8",
        )
        bin_path = tmp_path / "x.dll"
        bin_path.write_bytes(b"MZ" + b"\x00" * 200)
        info = SimpleNamespace(
            image_base=0x1000,
            text_raw_offset=0,
            data=b"\x90" * 0x200,
            sections={".text": SimpleNamespace(va=0x1000, size=0x200, file_offset=0)},
        )
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda p: info)
        registry = build_function_registry(
            funcs, _cfg(), ghidra_path=ghidra_path, bin_path=bin_path
        )
        # extra bytes are all 0x90 padding → list size wins
        assert registry[0x1000]["canonical_size"] == 100
        assert "tail padding" in registry[0x1000]["size_reason"]


class TestIatSlotFilter:
    """build_function_registry must drop VAs inside the PE import address
    table — MSVC places the IAT at the start of .text, so linear-sweep
    discovery emits a fake function per slot."""

    def test_iat_slots_dropped_from_list(self, tmp_path: Path) -> None:
        # Copy the real mini-PE fixture so LIEF can parse it.  Its IAT slot
        # is at 0x40104C (imagebase 0x400000 + RVA 0x104C).
        import shutil

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        bin_path = tmp_path / "x.exe"
        shutil.copy(fixture, bin_path)
        funcs = [
            {"va": 0x40104C, "size": 12, "name": "sym.imp.DLL.func"},
            {"va": 0x402000, "size": 64, "name": "real_fn"},
        ]
        registry = build_function_registry(funcs, _cfg(), bin_path=bin_path)
        assert 0x402000 in registry
        assert 0x40104C not in registry

    def test_non_iat_entry_kept(self, tmp_path: Path) -> None:
        import shutil

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        bin_path = tmp_path / "x.exe"
        shutil.copy(fixture, bin_path)
        funcs = [{"va": 0x5000, "size": 64, "name": "main"}]
        registry = build_function_registry(funcs, _cfg(), bin_path=bin_path)
        assert 0x5000 in registry

    def test_missing_binary_no_filter(self, tmp_path: Path) -> None:
        funcs = [{"va": 0x1000, "size": 12, "name": "anything"}]
        registry = build_function_registry(funcs, _cfg(), bin_path=None)
        assert 0x1000 in registry
