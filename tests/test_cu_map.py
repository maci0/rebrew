"""Tests for rebrew.cu_map — compilation unit boundary inference."""

import struct
from types import SimpleNamespace
from typing import Any

from rebrew.cu_map import (
    TUCluster,
    _call_graph_boost,
    _classify_gap,
    _cluster_to_dict,
    _contiguity_score,
    _invert_call_map,
    _scan_call_targets,
    cluster_functions,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(
    va: int,
    size: int,
    name: str = "",
    is_thunk: bool = False,
) -> dict[str, Any]:
    return {
        "va": va,
        "canonical_size": size,
        "list_name": name,
        "ghidra_name": "",
        "is_thunk": is_thunk,
        "is_export": False,
        "detected_by": ["list"],
        "size_by_tool": {"list": size},
    }


def _make_binary_info(
    text_va: int,
    text_size: int,
    data: bytes,
) -> SimpleNamespace:
    """Create a minimal BinaryInfo-like object for testing."""
    section = SimpleNamespace(
        name=".text",
        va=text_va,
        size=text_size,
        file_offset=0,
        raw_size=len(data),
    )
    return SimpleNamespace(
        path=None,
        format="pe",
        image_base=text_va,
        text_va=text_va,
        text_size=text_size,
        text_raw_offset=0,
        sections={".text": section},
        data=data,
        _data=data,
    )


# ---------------------------------------------------------------------------
# TestClassifyGap
# ---------------------------------------------------------------------------


class TestClassifyGap:
    def test_all_padding_cc(self) -> None:
        data = bytes([0xCC] * 8)
        assert _classify_gap(data, 0x10000000, 0x10000) == "padding"

    def test_all_padding_nop(self) -> None:
        data = bytes([0x90] * 4)
        assert _classify_gap(data, 0x10000000, 0x10000) == "padding"

    def test_mixed_padding(self) -> None:
        data = bytes([0xCC, 0x90, 0xCC, 0x90])
        assert _classify_gap(data, 0x10000000, 0x10000) == "padding"

    def test_empty_gap(self) -> None:
        assert _classify_gap(b"", 0x10000000, 0x10000) == "padding"

    def test_jump_table(self) -> None:
        """A gap with valid .text pointers is a jump table."""
        text_va = 0x10001000
        text_size = 0x10000
        # Build 3 valid pointers within .text
        ptrs = struct.pack("<III", text_va + 0x100, text_va + 0x200, text_va + 0x300)
        assert _classify_gap(ptrs, text_va, text_size) == "jump_table"

    def test_small_nonpadding(self) -> None:
        data = bytes([0x55, 0x8B, 0xEC] * 5)  # 15 bytes of non-padding
        assert _classify_gap(data, 0x10000000, 0x10000) == "small_nonpadding"

    def test_large_nonpadding(self) -> None:
        data = bytes(range(256)) * 2  # 512 bytes > 64 threshold
        # Make sure it's not detected as padding or jump table
        assert _classify_gap(data, 0x10000000, 0x10000) == "large_nonpadding"

    def test_custom_padding_bytes(self) -> None:
        data = bytes([0x00] * 8)
        assert _classify_gap(data, 0x10000000, 0x10000, padding_bytes=(0x00,)) == "padding"
        # Without 0x00 in padding set, should be small_nonpadding
        assert _classify_gap(data, 0x10000000, 0x10000, padding_bytes=(0xCC,)) == "small_nonpadding"


# ---------------------------------------------------------------------------
# TestContiguityScore
# ---------------------------------------------------------------------------


class TestContiguityScore:
    def test_empty_gaps_single_function(self) -> None:
        score, evidence = _contiguity_score([])
        assert score == 1.0
        assert "single function" in evidence[0]

    def test_all_padding(self) -> None:
        score, evidence = _contiguity_score(["padding", "padding", "padding"])
        assert score == 1.0
        assert "all gaps are padding" in evidence[0]

    def test_with_jump_tables(self) -> None:
        score, _ = _contiguity_score(["padding", "jump_table"])
        assert score == 0.95

    def test_with_small_nonpadding(self) -> None:
        score, _ = _contiguity_score(["padding", "small_nonpadding"])
        assert score == 0.90

    def test_multiple_penalties(self) -> None:
        score, _ = _contiguity_score(["jump_table", "jump_table", "small_nonpadding"])
        assert score == 0.80

    def test_floor_at_040(self) -> None:
        """Score should never go below 0.40."""
        gaps = ["small_nonpadding"] * 20  # 20 × -0.10 = -2.0 → clamped
        score, _ = _contiguity_score(gaps)
        assert score == 0.40

    def test_evidence_breakdown(self) -> None:
        _, evidence = _contiguity_score(["padding", "jump_table", "small_nonpadding"])
        assert any("1 padding" in e for e in evidence)
        assert any("1 jump table" in e for e in evidence)
        assert any("1 small non-padding" in e for e in evidence)


# ---------------------------------------------------------------------------
# TestScanCallTargets
# ---------------------------------------------------------------------------


class TestScanCallTargets:
    def test_extracts_call_targets(self) -> None:
        """Synthetic x86 bytes with E8 rel32 CALL instruction."""
        # Function at VA 0x1000, size 10
        # E8 rel32: call 0x100A (target = 0x1000 + 5 + rel32)
        # We want target = 0x100A, so rel32 = 0x100A - (0x1000 + 5) = 5
        code = b"\xe8\x05\x00\x00\x00"  # call +5 (relative to next insn)
        code += b"\xc3"  # ret
        # Target function at 0x100A
        target_code = b"\xc3\x90\x90\x90"  # ret + padding

        full_data = code + target_code
        text_va = 0x1000
        info = _make_binary_info(text_va, len(full_data), full_data)

        registry = {
            0x1000: _make_entry(0x1000, 6, "caller"),
            0x100A: _make_entry(0x100A, 1, "callee"),
        }

        cfg = SimpleNamespace(
            capstone_arch=None,
            capstone_mode=None,
            padding_bytes=[0xCC, 0x90],
        )

        # Need capstone for this test
        try:
            from capstone import CS_ARCH_X86, CS_MODE_32

            cfg.capstone_arch = CS_ARCH_X86
            cfg.capstone_mode = CS_MODE_32
        except ImportError:
            return  # Skip if capstone not available

        result = _scan_call_targets(info, registry, cfg)  # type: ignore[arg-type]
        # 0x1000 should call 0x100A
        # E8 05000000 at VA 0x1000: target = 0x1000 + 5 + 5 = 0x100A
        assert 0x1000 in result
        assert 0x100A in result[0x1000]

    def test_no_capstone_returns_empty(self) -> None:
        """When capstone unavailable, should return empty dict gracefully."""
        # This test verifies the function signature works even if
        # capstone isn't importable (can't easily mock, so just verify the call works)
        info = _make_binary_info(0x1000, 0, b"")
        registry: dict[int, dict[str, Any]] = {}
        result = _scan_call_targets(info, registry, None)  # type: ignore[arg-type]
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# TestCallGraphBoost
# ---------------------------------------------------------------------------


class TestCallGraphBoost:
    def test_internal_only_callee_boost(self) -> None:
        """Function called only within the cluster → boost."""
        cluster_vas = {0x1000, 0x1010, 0x1020}
        call_map = {0x1000: {0x1010}}  # 0x1000 calls 0x1010
        caller_map = _invert_call_map(call_map)
        # 0x1010 is only called by 0x1000, both in cluster
        boost, evidence = _call_graph_boost(cluster_vas, call_map, caller_map)
        assert boost == 0.05
        assert len(evidence) == 1
        assert "static-function signal" in evidence[0]

    def test_external_callee_no_boost(self) -> None:
        """Function called from outside the cluster → no boost."""
        cluster_vas = {0x1000, 0x1010}
        call_map = {0x2000: {0x1010}}  # external caller
        caller_map = _invert_call_map(call_map)
        boost, evidence = _call_graph_boost(cluster_vas, call_map, caller_map)
        assert boost == 0.0
        assert evidence == []

    def test_boost_cap_at_010(self) -> None:
        """Boost should not exceed 0.10 even with many static signals."""
        cluster_vas = {0x1000, 0x1010, 0x1020, 0x1030, 0x1040}
        # 0x1000 calls all others, all only called internally
        call_map = {0x1000: {0x1010, 0x1020, 0x1030, 0x1040}}
        caller_map = _invert_call_map(call_map)
        boost, _ = _call_graph_boost(cluster_vas, call_map, caller_map)
        assert boost == 0.10

    def test_no_calls_no_boost(self) -> None:
        cluster_vas = {0x1000, 0x1010}
        boost, evidence = _call_graph_boost(cluster_vas, {}, {})
        assert boost == 0.0
        assert evidence == []


# ---------------------------------------------------------------------------
# TestClusterFunctions
# ---------------------------------------------------------------------------


class TestClusterFunctions:
    def test_padding_gap_one_cluster(self) -> None:
        """Functions separated by padding → single cluster."""
        text_va = 0x1000
        # Func A: 4 bytes at 0x1000, then 4 bytes CC padding, then func B at 0x1008
        func_a = b"\x55\x8b\xec\xc3"  # push ebp; mov ebp,esp; ret
        padding = b"\xcc" * 4
        func_b = b"\x55\x8b\xec\xc3"
        data = func_a + padding + func_b

        info = _make_binary_info(text_va, len(data), data)
        registry = {
            0x1000: _make_entry(0x1000, 4, "FuncA"),
            0x1008: _make_entry(0x1008, 4, "FuncB"),
        }

        clusters = cluster_functions(registry, info, None)  # type: ignore[arg-type]
        assert len(clusters) == 1
        assert clusters[0].functions == [0x1000, 0x1008]

    def test_large_gap_two_clusters(self) -> None:
        """Functions separated by >64 bytes of non-padding → two clusters."""
        text_va = 0x1000
        func_a = b"\x55\x8b\xec\xc3"
        gap = bytes(range(256)) * 2  # 512 bytes non-padding (but not pointers)
        func_b = b"\x55\x8b\xec\xc3"
        data = func_a + gap + func_b
        text_size = len(data)

        info = _make_binary_info(text_va, text_size, data)
        registry = {
            0x1000: _make_entry(0x1000, 4, "FuncA"),
            0x1000 + 4 + 512: _make_entry(0x1000 + 4 + 512, 4, "FuncB"),
        }

        clusters = cluster_functions(registry, info, None)  # type: ignore[arg-type]
        assert len(clusters) == 2
        assert clusters[0].functions == [0x1000]
        assert clusters[1].functions == [0x1000 + 4 + 512]

    def test_thunks_excluded(self) -> None:
        """Thunk functions should be excluded from clustering."""
        text_va = 0x1000
        data = b"\xc3" * 16
        info = _make_binary_info(text_va, len(data), data)
        registry = {
            0x1000: _make_entry(0x1000, 4, "FuncA"),
            0x1004: _make_entry(0x1004, 4, "ThunkB", is_thunk=True),
            0x1008: _make_entry(0x1008, 4, "FuncC"),
        }

        clusters = cluster_functions(registry, info, None)  # type: ignore[arg-type]
        # ThunkB excluded, FuncA and FuncC in same cluster (gap is padding)
        all_vas = [va for c in clusters for va in c.functions]
        assert 0x1004 not in all_vas
        assert 0x1000 in all_vas
        assert 0x1008 in all_vas

    def test_zero_size_excluded(self) -> None:
        """Zero-size functions should be excluded from clustering."""
        text_va = 0x1000
        data = b"\xc3" * 16
        info = _make_binary_info(text_va, len(data), data)
        registry = {
            0x1000: _make_entry(0x1000, 4, "FuncA"),
            0x1004: _make_entry(0x1004, 0, "FuncB"),  # zero size
        }

        clusters = cluster_functions(registry, info, None)  # type: ignore[arg-type]
        all_vas = [va for c in clusters for va in c.functions]
        assert 0x1004 not in all_vas

    def test_outside_text_excluded(self) -> None:
        """Functions outside .text should be excluded."""
        text_va = 0x1000
        data = b"\xc3" * 16
        info = _make_binary_info(text_va, 8, data)  # text_size=8
        registry = {
            0x1000: _make_entry(0x1000, 4, "InText"),
            0x2000: _make_entry(0x2000, 4, "OutsideText"),  # beyond .text
        }

        clusters = cluster_functions(registry, info, None)  # type: ignore[arg-type]
        all_vas = [va for c in clusters for va in c.functions]
        assert 0x1000 in all_vas
        assert 0x2000 not in all_vas

    def test_empty_registry(self) -> None:
        info = _make_binary_info(0x1000, 0x100, b"\x00" * 0x100)
        clusters = cluster_functions({}, info, None)  # type: ignore[arg-type]
        assert clusters == []


# ---------------------------------------------------------------------------
# TestClusterToDict
# ---------------------------------------------------------------------------


class TestClusterToDict:
    def test_json_schema_keys(self) -> None:
        registry = {
            0x1000: _make_entry(0x1000, 128, "FuncA"),
            0x1080: _make_entry(0x1080, 64, "FuncB"),
        }
        cluster = TUCluster(
            cluster_id=0,
            functions=[0x1000, 0x1080],
            gap_classes=["padding"],
            confidence=0.92,
            evidence=["all gaps are padding"],
        )

        d = _cluster_to_dict(cluster, registry)

        assert d["cluster_id"] == 0
        assert d["va_start"] == "0x00001000"
        assert d["va_end"] == "0x000010C0"  # 0x1080 + 64
        assert d["function_count"] == 2
        assert d["confidence"] == 0.92
        assert "all gaps are padding" in d["evidence"]
        assert len(d["functions"]) == 2

    def test_va_hex_format(self) -> None:
        registry = {0x10001000: _make_entry(0x10001000, 128, "Func")}
        cluster = TUCluster(
            cluster_id=5,
            functions=[0x10001000],
            gap_classes=[],
            confidence=1.0,
            evidence=["single function"],
        )

        d = _cluster_to_dict(cluster, registry)
        assert d["va_start"] == "0x10001000"
        assert d["functions"][0]["va"] == "0x10001000"

    def test_gap_after_null_for_last(self) -> None:
        registry = {
            0x1000: _make_entry(0x1000, 8, "A"),
            0x1010: _make_entry(0x1010, 8, "B"),
        }
        cluster = TUCluster(
            cluster_id=0,
            functions=[0x1000, 0x1010],
            gap_classes=["padding"],
            confidence=1.0,
            evidence=[],
        )

        d = _cluster_to_dict(cluster, registry)
        assert d["functions"][0]["gap_after"] == "padding"
        assert d["functions"][1]["gap_after"] is None

    def test_function_fields(self) -> None:
        registry = {0x1000: _make_entry(0x1000, 42, "MyFunc")}
        cluster = TUCluster(
            cluster_id=0,
            functions=[0x1000],
            gap_classes=[],
            confidence=0.80,
            evidence=[],
        )

        d = _cluster_to_dict(cluster, registry)
        func = d["functions"][0]
        assert func["name"] == "MyFunc"
        assert func["size"] == 42
        assert func["gap_after"] is None


# ---------------------------------------------------------------------------
# TestInvertCallMap
# ---------------------------------------------------------------------------


class TestInvertCallMap:
    def test_basic_inversion(self) -> None:
        call_map = {0x1000: {0x2000, 0x3000}, 0x2000: {0x3000}}
        inv = _invert_call_map(call_map)
        assert inv[0x2000] == {0x1000}
        assert inv[0x3000] == {0x1000, 0x2000}

    def test_empty_map(self) -> None:
        assert _invert_call_map({}) == {}
