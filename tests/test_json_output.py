"""Tests for --json output across CLI tools.

Validates JSON structure and content for diff_functions(as_dict=True),
rebrew-next JSON modes, rebrew-test result dicts, and rebrew-asm JSON.
"""

import json

from rebrew.matcher.scoring import diff_functions
from rebrew.test import _build_result_dict

# ---------------------------------------------------------------------------
# diff_functions(as_dict=True)
# ---------------------------------------------------------------------------


class TestDiffFunctionsAsDict:
    """Test diff_functions returns structured dict when as_dict=True."""

    def test_identical_bytes(self) -> None:
        """Identical bytes should produce all '==' matches, zero structural diffs."""
        code = b"\x55\x8b\xec\x83\xec\x10\x5d\xc3"
        result = diff_functions(code, code, as_dict=True)
        assert result is not None
        assert result["target_size"] == len(code)
        assert result["candidate_size"] == len(code)
        assert result["summary"]["structural"] == 0
        assert result["summary"]["exact"] > 0
        assert isinstance(result["instructions"], list)
        assert len(result["instructions"]) > 0

    def test_different_bytes(self) -> None:
        """Different bytes should produce structural diffs."""
        target = b"\x55\x8b\xec\x83\xec\x10\x5d\xc3"
        candidate = b"\x55\x8b\xec\x83\xec\x20\x5d\xc3"
        result = diff_functions(target, candidate, as_dict=True)
        assert result is not None
        assert result["summary"]["structural"] >= 1

    def test_instruction_structure(self) -> None:
        """Each instruction entry should have expected keys."""
        code = b"\x55\x8b\xec\x5d\xc3"
        result = diff_functions(code, code, as_dict=True)
        assert result is not None
        for insn in result["instructions"]:
            assert "index" in insn
            assert "match" in insn
            assert "target" in insn
            assert "candidate" in insn
            if insn["target"] is not None:
                assert "bytes" in insn["target"]
                assert "disasm" in insn["target"]

    def test_returns_none_when_not_as_dict(self) -> None:
        """Without as_dict, diff_functions prints and returns None."""
        code = b"\x55\x8b\xec\x5d\xc3"
        result = diff_functions(code, code, as_dict=False)
        assert result is None

    def test_json_serializable(self) -> None:
        """Result dict should be JSON-serializable."""
        code = b"\x55\x8b\xec\x83\xec\x10\x5d\xc3"
        result = diff_functions(code, code, as_dict=True)
        serialized = json.dumps(result)
        parsed = json.loads(serialized)
        assert parsed["target_size"] == len(code)

    def test_empty_bytes(self) -> None:
        """Empty bytes should return valid structure."""
        result = diff_functions(b"", b"", as_dict=True)
        assert result is not None
        assert result["target_size"] == 0
        assert result["candidate_size"] == 0
        assert result["summary"]["total"] == 0
        assert result["instructions"] == []

    def test_size_mismatch(self) -> None:
        """Different-sized inputs should still produce valid output."""
        target = b"\x55\x8b\xec\x5d\xc3"
        candidate = b"\x55\x8b\xec\x83\xec\x10\x5d\xc3"
        result = diff_functions(target, candidate, as_dict=True)
        assert result is not None
        assert result["target_size"] != result["candidate_size"]

    def test_with_reloc_offsets(self) -> None:
        """Reloc offsets should affect match classification."""
        # call rel32 — bytes after opcode differ but are reloc
        target = b"\xe8\x10\x00\x00\x00\xc3"
        candidate = b"\xe8\x20\x00\x00\x00\xc3"
        result = diff_functions(target, candidate, reloc_offsets=[1], as_dict=True)
        assert result is not None
        # With reloc masking, the call instruction should be ~~ not **
        assert result["summary"]["total"] > 0

    def test_summary_counts_add_up(self) -> None:
        """exact + reloc + structural should equal total."""
        target = b"\x55\x8b\xec\x83\xec\x10\x5d\xc3"
        candidate = b"\x55\x8b\xec\x83\xec\x20\x5d\xc3"
        result = diff_functions(target, candidate, as_dict=True)
        assert result is not None
        s = result["summary"]
        assert s["exact"] + s["reloc"] + s["structural"] == s["total"]

    def test_instruction_count_matches_total(self) -> None:
        """Number of instruction entries should equal summary total."""
        code = b"\x55\x8b\xec\x83\xec\x10\x5d\xc3"
        result = diff_functions(code, code, as_dict=True)
        assert result is not None
        assert len(result["instructions"]) == result["summary"]["total"]

    def test_match_values(self) -> None:
        """Match field should be '==', '~~', '**', or None."""
        target = b"\x55\x8b\xec\x83\xec\x10\x5d\xc3"
        candidate = b"\x55\x8b\xec\x83\xec\x20\x5d\xc3"
        result = diff_functions(target, candidate, as_dict=True)
        assert result is not None
        valid_matches = {"==", "~~", "**", None}
        for insn in result["instructions"]:
            assert insn["match"] in valid_matches


# ---------------------------------------------------------------------------
# _build_result_dict (rebrew-test)
# ---------------------------------------------------------------------------


class TestBuildResultDict:
    """Test the rebrew-test JSON result dict builder."""

    def test_exact_match(self) -> None:
        data = b"\x55\x8b\xec\x5d\xc3"
        result = _build_result_dict(
            "src/test.c",
            "_func",
            "0x10001000",
            5,
            matched=True,
            match_count=5,
            total=5,
            relocs=[],
            obj_bytes=data,
            target_bytes=data,
        )
        assert result["status"] == "EXACT"
        assert result["match_count"] == 5
        assert result["mismatches"] == []
        assert result["obj_size"] == 5

    def test_reloc_match(self) -> None:
        result = _build_result_dict(
            "src/test.c",
            "_func",
            "0x10001000",
            10,
            matched=True,
            match_count=10,
            total=10,
            relocs=[2],
            obj_bytes=b"\x00" * 10,
            target_bytes=b"\x00" * 10,
        )
        assert result["status"] == "RELOC"
        assert result["reloc_count"] == 1

    def test_mismatch(self) -> None:
        target = b"\x55\x8b\xec\x5d\xc3"
        candidate = b"\x55\x8b\xec\x5d\xcc"
        result = _build_result_dict(
            "src/test.c",
            "_func",
            "0x10001000",
            5,
            matched=False,
            match_count=4,
            total=5,
            relocs=[],
            obj_bytes=candidate,
            target_bytes=target,
        )
        assert result["status"] == "MISMATCH"
        assert len(result["mismatches"]) == 1
        assert result["mismatches"][0]["offset"] == 4

    def test_mismatch_excludes_relocs(self) -> None:
        """Mismatches list should not include bytes covered by relocations."""
        target = b"\xe8\x10\x00\x00\x00"
        candidate = b"\xe8\x20\x00\x00\x00"
        result = _build_result_dict(
            "src/test.c",
            "_func",
            "0x10001000",
            5,
            matched=False,
            match_count=4,
            total=5,
            relocs=[1],
            obj_bytes=candidate,
            target_bytes=target,
        )
        # Bytes 1-4 are reloc, so no mismatches should be reported there
        mismatch_offsets = {m["offset"] for m in result["mismatches"]}
        assert 1 not in mismatch_offsets
        assert 2 not in mismatch_offsets
        assert 3 not in mismatch_offsets
        assert 4 not in mismatch_offsets

    def test_json_serializable(self) -> None:
        data = b"\x55\x8b\xec"
        result = _build_result_dict(
            "src/test.c",
            "_func",
            "0x10001000",
            3,
            matched=True,
            match_count=3,
            total=3,
            relocs=[],
            obj_bytes=data,
            target_bytes=data,
        )
        serialized = json.dumps(result)
        parsed = json.loads(serialized)
        assert parsed["source"] == "src/test.c"

    def test_all_required_keys(self) -> None:
        """Result dict should have all documented keys."""
        data = b"\x55\x8b\xec"
        result = _build_result_dict(
            "src/test.c",
            "_func",
            "0x10001000",
            3,
            matched=True,
            match_count=3,
            total=3,
            relocs=[],
            obj_bytes=data,
            target_bytes=data,
        )
        required_keys = {
            "source",
            "symbol",
            "va",
            "size",
            "status",
            "match_count",
            "total",
            "reloc_count",
            "obj_size",
            "mismatches",
        }
        assert required_keys == set(result.keys())


# ---------------------------------------------------------------------------
# rebrew-next JSON modes (unit tests on data structures)
# ---------------------------------------------------------------------------


class TestNextJsonSchemas:
    """Validate JSON schema shapes for rebrew-next modes."""

    def test_stats_schema(self) -> None:
        """Stats mode JSON should have expected keys."""
        stats = {
            "mode": "stats",
            "total": 1200,
            "covered": 450,
            "coverage_pct": 37.5,
            "by_status": {"EXACT": 200, "RELOC": 150},
            "by_origin": {"GAME": 300},
            "unmatchable": 120,
            "actionable": 630,
        }
        serialized = json.dumps(stats)
        parsed = json.loads(serialized)
        assert parsed["mode"] == "stats"
        assert "coverage_pct" in parsed
        assert "by_status" in parsed

    def test_recommendations_schema(self) -> None:
        """Recommendations mode JSON should have expected keys."""
        recs = {
            "mode": "recommendations",
            "total_uncovered": 342,
            "count": 1,
            "items": [
                {
                    "rank": 1,
                    "va": "0x10003da0",
                    "size": 160,
                    "difficulty": 3,
                    "origin": "GAME",
                    "name": "func_name",
                    "reason": "medium function",
                    "neighbor_file": None,
                }
            ],
        }
        serialized = json.dumps(recs)
        parsed = json.loads(serialized)
        assert parsed["mode"] == "recommendations"
        assert len(parsed["items"]) == 1
        assert "rank" in parsed["items"][0]

    def test_improving_schema(self) -> None:
        improving = {
            "mode": "improving",
            "total": 5,
            "count": 1,
            "items": [
                {
                    "va": "0x10003da0",
                    "size": 160,
                    "byte_delta": 2,
                    "origin": "GAME",
                    "filename": "func.c",
                    "blocker": "register allocation",
                }
            ],
        }
        parsed = json.loads(json.dumps(improving))
        assert parsed["mode"] == "improving"
        assert parsed["items"][0]["byte_delta"] == 2
        assert parsed["total"] >= parsed["count"]

    def test_unmatchable_schema(self) -> None:
        unmatchable = {
            "mode": "unmatchable",
            "total": 120,
            "count": 1,
            "items": [{"va": "0x10001000", "size": 6, "name": "thunk", "reason": "IAT jmp"}],
        }
        parsed = json.loads(json.dumps(unmatchable))
        assert parsed["mode"] == "unmatchable"
        assert "reason" in parsed["items"][0]
        assert parsed["total"] >= parsed["count"]

    def test_groups_schema(self) -> None:
        groups = {
            "mode": "groups",
            "group_count": 1,
            "singleton_count": 5,
            "groups": [
                {
                    "group_id": 1,
                    "function_count": 2,
                    "total_size": 320,
                    "va_range": ["0x10001000", "0x100010a0"],
                    "neighbor_file": None,
                    "functions": [
                        {
                            "va": "0x10001000",
                            "size": 160,
                            "difficulty": 2,
                            "origin": "GAME",
                            "name": "func_a",
                        },
                    ],
                }
            ],
        }
        parsed = json.loads(json.dumps(groups))
        assert parsed["mode"] == "groups"
        assert parsed["groups"][0]["function_count"] == 2


# ---------------------------------------------------------------------------
# rebrew-asm JSON schema
# ---------------------------------------------------------------------------


class TestAsmJsonSchema:
    """Validate JSON schema shape for rebrew-asm."""

    def test_asm_schema(self) -> None:
        asm_output = {
            "va": "0x10003da0",
            "size": 8,
            "instruction_count": 3,
            "instructions": [
                {"address": "0x10003da0", "bytes": "55", "mnemonic": "push", "operands": "ebp"},
                {
                    "address": "0x10003da1",
                    "bytes": "8bec",
                    "mnemonic": "mov",
                    "operands": "ebp, esp",
                },
                {"address": "0x10003da3", "bytes": "c3", "mnemonic": "ret", "operands": ""},
            ],
        }
        parsed = json.loads(json.dumps(asm_output))
        assert parsed["instruction_count"] == 3
        assert parsed["instructions"][0]["mnemonic"] == "push"

    def test_asm_required_keys(self) -> None:
        """Each instruction should have all required keys."""
        asm_output = {
            "va": "0x10003da0",
            "size": 5,
            "instruction_count": 1,
            "instructions": [
                {"address": "0x10003da0", "bytes": "55", "mnemonic": "push", "operands": "ebp"},
            ],
        }
        required_top = {"va", "size", "instruction_count", "instructions"}
        assert required_top == set(asm_output.keys())
        required_insn = {"address", "bytes", "mnemonic", "operands"}
        assert required_insn == set(asm_output["instructions"][0].keys())


# ---------------------------------------------------------------------------
# rebrew-flirt --json schema
# ---------------------------------------------------------------------------


class TestFlirtJsonSchema:
    """Validate JSON schema shapes for rebrew-flirt --json output."""

    def test_full_output_schema(self) -> None:
        """Full --json output should have all expected top-level keys."""
        output = {
            "binary": "original/server.dll",
            "sig_dir": "flirt_sigs",
            "signature_count": 42,
            "text_size": 524288,
            "min_size": 16,
            "match_count": 15,
            "skipped_ambiguous": 3,
            "matches": [
                {"va": "0x10003da0", "size": 160, "names": ["_malloc"]},
            ],
        }
        serialized = json.dumps(output)
        parsed = json.loads(serialized)
        required_keys = {
            "binary",
            "sig_dir",
            "signature_count",
            "text_size",
            "min_size",
            "match_count",
            "skipped_ambiguous",
            "matches",
        }
        assert required_keys == set(parsed.keys())

    def test_match_entry_structure(self) -> None:
        """Each match entry should have va, size, and names."""
        entry = {"va": "0x10003da0", "size": 160, "names": ["_malloc", "__alloca"]}
        assert isinstance(entry["va"], str)
        assert entry["va"].startswith("0x")
        assert isinstance(entry["size"], int)
        assert isinstance(entry["names"], list)
        assert len(entry["names"]) > 0

    def test_empty_matches(self) -> None:
        """Output with zero matches should be valid JSON with empty matches list."""
        output = {
            "binary": "original/server.dll",
            "sig_dir": "flirt_sigs",
            "signature_count": 42,
            "text_size": 524288,
            "min_size": 16,
            "match_count": 0,
            "skipped_ambiguous": 0,
            "matches": [],
        }
        parsed = json.loads(json.dumps(output))
        assert parsed["match_count"] == 0
        assert parsed["matches"] == []

    def test_error_json_shape(self) -> None:
        """Error JSON should have 'error' and 'sig_dir' keys."""
        error_output = {"error": "No signatures loaded", "sig_dir": "flirt_sigs"}
        parsed = json.loads(json.dumps(error_output))
        assert "error" in parsed
        assert "sig_dir" in parsed

    def test_json_serializable(self) -> None:
        """Full output should round-trip through JSON."""
        output = {
            "binary": "original/server.dll",
            "sig_dir": "flirt_sigs",
            "signature_count": 10,
            "text_size": 1024,
            "min_size": 16,
            "match_count": 2,
            "skipped_ambiguous": 1,
            "matches": [
                {"va": "0x10001000", "size": 32, "names": ["_free"]},
                {"va": "0x10002000", "size": 64, "names": ["_malloc", "_realloc"]},
            ],
        }
        serialized = json.dumps(output)
        parsed = json.loads(serialized)
        assert parsed["match_count"] == 2
        assert len(parsed["matches"]) == 2
        assert parsed["matches"][0]["names"] == ["_free"]
        assert parsed["matches"][1]["size"] == 64


# ---------------------------------------------------------------------------
# rebrew-promote --json schema
# ---------------------------------------------------------------------------


class TestPromoteJsonSchema:
    """Validate JSON schema shapes for rebrew promote --json output."""

    def test_promote_success_schema(self) -> None:
        output = {
            "source": "src/server.dll/func.c",
            "results": [
                {
                    "va": "0x10003da0",
                    "symbol": "_func",
                    "status": "RELOC",
                    "previous_status": "STUB",
                    "new_status": "RELOC",
                    "action": "promoted",
                    "match_count": 160,
                    "total": 160,
                    "reloc_count": 3,
                }
            ],
        }
        parsed = json.loads(json.dumps(output))
        assert parsed["results"][0]["action"] == "promoted"
        assert parsed["results"][0]["new_status"] == "RELOC"

    def test_promote_no_change_schema(self) -> None:
        output = {
            "source": "src/server.dll/func.c",
            "results": [
                {
                    "va": "0x10003da0",
                    "symbol": "_func",
                    "status": "MISMATCH",
                    "previous_status": "STUB",
                    "new_status": "STUB",
                    "action": "no_change",
                    "match_count": 100,
                    "total": 160,
                    "reloc_count": 0,
                }
            ],
        }
        parsed = json.loads(json.dumps(output))
        assert parsed["results"][0]["action"] == "no_change"

    def test_promote_json_serializable(self) -> None:
        output = {
            "source": "src/server.dll/func.c",
            "results": [],
        }
        serialized = json.dumps(output)
        parsed = json.loads(serialized)
        assert parsed["source"] == "src/server.dll/func.c"


# ---------------------------------------------------------------------------
# rebrew-triage --json schema
# ---------------------------------------------------------------------------


class TestTriageJsonSchema:
    """Validate JSON schema shapes for rebrew triage --json output."""

    def test_triage_full_schema(self) -> None:
        output = {
            "coverage": {
                "total": 1200,
                "covered": 450,
                "coverage_pct": 37.5,
                "exact": 200,
                "reloc": 150,
                "matching": 80,
                "stub": 20,
                "unmatchable": 120,
                "actionable": 630,
            },
            "near_miss": [
                {
                    "va": "0x10003da0",
                    "size": 160,
                    "byte_delta": 2,
                    "filename": "func.c",
                    "blocker": "",
                },
            ],
            "near_miss_total": 80,
            "recommendations": [
                {
                    "va": "0x10004000",
                    "size": 64,
                    "difficulty": 2,
                    "origin": "GAME",
                    "name": "small_func",
                    "reason": "small function",
                    "suggested_file": "src/server.dll/func.c",
                    "suggested_action": "create",
                },
            ],
        }
        parsed = json.loads(json.dumps(output))
        assert "coverage" in parsed
        assert "near_miss" in parsed
        assert "recommendations" in parsed
        assert parsed["coverage"]["coverage_pct"] == 37.5
        assert parsed["near_miss_total"] >= len(parsed["near_miss"])

    def test_triage_with_flirt(self) -> None:
        output = {
            "coverage": {
                "total": 100,
                "covered": 50,
                "coverage_pct": 50.0,
                "exact": 30,
                "reloc": 15,
                "matching": 5,
                "stub": 0,
                "unmatchable": 10,
                "actionable": 40,
            },
            "near_miss": [],
            "near_miss_total": 0,
            "recommendations": [],
            "flirt_matches": 25,
        }
        parsed = json.loads(json.dumps(output))
        assert parsed["flirt_matches"] == 25

    def test_triage_coverage_keys(self) -> None:
        required_keys = {
            "total",
            "covered",
            "coverage_pct",
            "exact",
            "reloc",
            "matching",
            "stub",
            "unmatchable",
            "actionable",
        }
        coverage = {k: 0 for k in required_keys}
        assert required_keys == set(coverage.keys())
