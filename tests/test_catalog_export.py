"""Tests for catalog/export.py — CATALOG.md and reccmp CSV generation."""

from types import SimpleNamespace

from rebrew.annotation import Annotation
from rebrew.catalog.export import (
    _reccmp_type,
    generate_catalog,
    generate_reccmp_csv,
)


def _ann(
    va: int,
    name: str,
    status: str,
    *,
    marker_type: str = "FUNCTION",
    size: int = 64,
    symbol: str | None = None,
    module: str = "GAME",
    cflags: str = "/O2",
) -> Annotation:
    return Annotation(
        va=va,
        name=name,
        symbol=symbol or f"_{name}",
        module=module,
        status=status,
        size=size,
        cflags=cflags,
        marker_type=marker_type,
        filepath=f"{name}.c",
    )


class TestGenerateCatalog:
    def test_basic(self) -> None:
        entries = [
            _ann(0x1000, "fn_a", "EXACT"),
            _ann(0x2000, "fn_b", "RELOC"),
            _ann(0x3000, "fn_c", "STUB"),
            _ann(0x4000, "g_x", "EXACT", marker_type="GLOBAL"),  # excluded
        ]
        funcs = [
            {"va": 0x1000, "size": 64, "name": "fn_a"},
            {"va": 0x5000, "size": 32, "name": "unmatched_fn"},
        ]
        out = generate_catalog(entries, funcs, text_size=1000)
        assert "# Reversed Functions Catalog" in out
        assert "3/2 functions cataloged" in out  # 3 cataloged, 2 total funcs
        assert "1 exact" in out
        assert "## GAME (3 functions)" in out
        assert "fn_a" in out
        assert "g_x" not in out
        assert "## Unmatched Functions (1 remaining)" in out
        assert "unmatched_fn" in out

    def test_stub_with_near_matching_not_stub(self) -> None:
        entries = [
            _ann(0x1000, "fn_a", "STUB"),
            _ann(0x2000, "fn_b", "STUB"),
        ]
        # Both STUB entries: one also has a NEAR_MATCHING annotation at the
        # same VA via a second entry.
        entries.append(_ann(0x2000, "fn_b", "NEAR_MATCHING"))
        out = generate_catalog(entries, [], text_size=100)
        assert "1 stubs" in out
        # NEAR_MATCHING is its own bucket, not silently dropped.
        assert "1 near-matching" in out

    def test_empty(self) -> None:
        out = generate_catalog([], [], text_size=0)
        assert "0/0 functions cataloged" in out
        assert "Coverage: 0.0%" in out

    def test_covered_bytes_fallback(self) -> None:
        entries = [_ann(0x1000, "fn_a", "EXACT", size=42)]
        out = generate_catalog(entries, [], text_size=100)
        assert "42/100 bytes" in out


class TestReccmpType:
    def test_mapping(self) -> None:
        assert _reccmp_type(_ann(0x1000, "f", "STUB", marker_type="STUB")) == "stub"
        assert _reccmp_type(_ann(0x1000, "f", "EXACT", marker_type="LIBRARY")) == "library"
        assert _reccmp_type(_ann(0x1000, "f", "EXACT")) == "function"


class TestGenerateReccmpCsv:
    def test_matched_with_registry_size(self) -> None:
        entries = [_ann(0x1000, "fn_a", "EXACT", size=64)]
        registry = {0x1000: {"canonical_size": 128, "is_thunk": False}}
        out = generate_reccmp_csv(entries, [], registry=registry)
        lines = out.strip().splitlines()
        assert lines[0].startswith("# reccmp")
        assert "address|name|symbol|type|size" in out
        assert "0x00001000|fn_a|_fn_a|function|128" in out  # registry size wins

    def test_matched_without_registry(self) -> None:
        entries = [_ann(0x1000, "fn_a", "STUB", marker_type="STUB", size=64)]
        out = generate_reccmp_csv(entries, [])
        assert "0x00001000|fn_a|_fn_a|stub|64" in out

    def test_unmatched_ghidra_name(self) -> None:
        registry = {
            0x1000: {
                "canonical_size": 32,
                "is_thunk": False,
                "ghidra_name": "real_name",
            }
        }
        out = generate_reccmp_csv([], [], registry=registry)
        assert "0x00001000|real_name|_real_name|function|32" in out

    def test_unmatched_generic_ghidra_name_ignored(self) -> None:
        registry = {
            0x1000: {"canonical_size": 32, "is_thunk": False, "ghidra_name": "FUN_10001000"}
        }
        funcs = [{"va": 0x1000, "size": 32, "name": "list_fn"}]
        out = generate_reccmp_csv([], funcs, registry=registry)
        assert "list_fn" in out
        assert "FUN_10001000" not in out

    def test_unmatched_no_name(self) -> None:
        registry = {0x1000: {"canonical_size": 0, "is_thunk": False}}
        out = generate_reccmp_csv([], [], registry=registry)
        assert "0x00001000|||function|" in out

    def test_thunk_type(self) -> None:
        registry = {0x1000: {"canonical_size": 5, "is_thunk": True}}
        out = generate_reccmp_csv([], [], registry=registry)
        assert "0x00001000|||stub|5" in out

    def test_iat_thunk_via_cfg(self) -> None:
        registry = {0x1000: {"canonical_size": 5, "is_thunk": False}}
        cfg = SimpleNamespace(iat_thunks={0x1000})
        out = generate_reccmp_csv([], [], registry=registry, cfg=cfg)  # type: ignore[arg-type]
        assert "|stub|" in out

    def test_size_from_funcs_fallback(self) -> None:
        funcs = [{"va": 0x1000, "size": 40, "name": "only_list"}]
        out = generate_reccmp_csv([], funcs)
        assert "0x00001000|only_list|_only_list|function|40" in out
