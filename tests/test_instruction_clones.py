"""Tests for rebrew.instruction_clones: common instruction runs and identical groups."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.main
import rebrew.similar as similar_mod
from rebrew.instruction_clones import (
    MAX_SUBMATCH_INSTRUCTIONS,
    NormalizedInsn,
    cluster_units,
    find_common_runs,
    normalize_operands,
    normalized_instructions,
)

runner = CliRunner()

# push ebp ; mov ebp, esp ; sub esp, 4
PROLOGUE = b"\x55\x8b\xec\x83\xec\x04"
# leave ; ret
EPILOGUE = b"\xc9\xc3"
# mov eax, 1 ; mov ebx, 2 ; xor ecx, ecx ; ret
UNRELATED = b"\xb8\x01\x00\x00\x00\xbb\x02\x00\x00\x00\x31\xc9\xc3"


def _insns(code: bytes) -> list[NormalizedInsn]:
    return normalized_instructions(code, 0x1000)


class TestNormalization:
    def test_registers_and_immediates_masked(self) -> None:
        assert normalize_operands("eax, ebx") == "R, R"
        assert normalize_operands("esp, 4") == "R, IMM"
        assert normalize_operands("eax, [ebp + 0x10]") == normalize_operands("eax, [ebp + 8]")

    def test_sequences_differing_only_in_immediate_match(self) -> None:
        a = _insns(PROLOGUE + b"\xc3")  # sub esp, 4
        b = _insns(b"\x55\x8b\xec\x83\xec\x08\xc3")  # sub esp, 8
        assert [i.key for i in a] == [i.key for i in b]


class TestFindCommonRuns:
    def test_one_common_run(self) -> None:
        left = _insns(PROLOGUE + EPILOGUE)
        right = _insns(b"\xb8\x01\x00\x00\x00" + PROLOGUE + EPILOGUE)
        runs = find_common_runs(left, right)
        assert len(runs) == 1
        assert runs[0].length == 5
        assert runs[0].left_va == 0x1000
        assert runs[0].right_va == 0x1000 + 5  # after `mov eax, 1`
        assert runs[0].instructions[0] == "push ebp"

    def test_no_common_run(self) -> None:
        left = _insns(PROLOGUE + EPILOGUE)
        right = _insns(UNRELATED)
        assert find_common_runs(left, right) == []

    def test_run_below_minimum_is_dropped(self) -> None:
        left = _insns(PROLOGUE + EPILOGUE)
        right = _insns(EPILOGUE + b"\xb8\x01\x00\x00\x00")
        assert find_common_runs(left, right, min_run=4) == []
        short = find_common_runs(left, right, min_run=2)
        assert len(short) == 1
        assert short[0].length == 2

    def test_empty_side_yields_no_runs(self) -> None:
        assert find_common_runs([], _insns(EPILOGUE)) == []

    def test_oversized_pair_is_refused(self) -> None:
        big = [
            NormalizedInsn(va=0x1000 + i, size=1, text="nop", key=f"nop{i}")
            for i in range(MAX_SUBMATCH_INSTRUCTIONS + 1)
        ]
        with pytest.raises(ValueError, match="quadratic"):
            find_common_runs(big, _insns(EPILOGUE))


def _unit(va: int, code: bytes, name: str = "") -> SimpleNamespace:
    from rebrew.instruction_clones import FunctionUnit

    return FunctionUnit(va=va, size=len(code), name=name, instructions=_insns(code))


class TestClusterUnits:
    def test_three_identical_plus_one_distinct(self) -> None:
        units = [
            _unit(0x1000, PROLOGUE + EPILOGUE, "twin_a"),
            _unit(0x1100, PROLOGUE + EPILOGUE, "twin_b"),
            _unit(0x1200, PROLOGUE + EPILOGUE, "twin_c"),
            _unit(0x1300, UNRELATED, "other"),
        ]
        clusters = cluster_units(units)
        assert len(clusters) == 1
        assert clusters[0].size == 3
        assert clusters[0].members == [0x1000, 0x1100, 0x1200]
        assert clusters[0].names == ["twin_a", "twin_b", "twin_c"]
        assert clusters[0].instruction_count == 5

    def test_min_size_filters_and_validates(self) -> None:
        units = [
            _unit(0x1000, PROLOGUE + EPILOGUE),
            _unit(0x1100, PROLOGUE + EPILOGUE),
        ]
        assert cluster_units(units, min_size=2)[0].size == 2
        assert cluster_units(units, min_size=3) == []
        with pytest.raises(ValueError, match="min_size"):
            cluster_units(units, min_size=1)

    def test_largest_group_first(self) -> None:
        units = [
            _unit(0x1000, PROLOGUE + EPILOGUE),
            _unit(0x1100, PROLOGUE + EPILOGUE),
            _unit(0x1200, PROLOGUE + EPILOGUE),
            _unit(0x1300, UNRELATED),
            _unit(0x1400, UNRELATED),
        ]
        clusters = cluster_units(units)
        assert [c.size for c in clusters] == [3, 2]
        assert clusters[1].members == [0x1300, 0x1400]

    def test_units_without_instructions_are_ignored(self) -> None:
        clusters = cluster_units([_unit(0x1000, b""), _unit(0x1100, b"")])
        assert clusters == []


class TestDeltaOverResembl:
    """These two functions are the delta over ``resembl``; do not reimplement either there.

    ``resembl`` (the sibling project, consumed through the optional
    ``similarity`` extra) is the similarity engine: MinHash + LSH over a
    persisted cross-project corpus, fragment queries, a hybrid
    Jaccard/Levenshtein score, and a snippet key that is already the SHA256 of
    its normalized code, so identical snippets collide in its index.  What it
    cannot report is the two properties pinned here:

    - ``find_common_runs`` reports WHERE in each function the shared
      instructions are, as ``(left_va, right_va, length)``.  A resemblance
      score is a single number with no offsets, so "these two functions are
      82 % alike" cannot say which part of one corresponds to which part of
      the other.
    - ``cluster_units`` reports WHICH functions of one target are identical
      after normalization, as group membership.  resembl answers "which stored
      snippets resemble this query" against its database, not "which of these
      forty functions are the same thunk" within the target in hand.

    A future change that adds an index, persistence, or an approximate
    near-neighbour search here would be a second answer to a question resembl
    already owns.
    """

    def test_runs_carry_offsets_and_groups_carry_membership(self) -> None:
        # Same instruction stream in both functions, shifted by a five-byte
        # `mov eax, 1` on the right: one run, with the right-hand offset
        # pointing PAST that instruction (a score cannot express this).
        left = _insns(PROLOGUE + EPILOGUE)
        right = _insns(b"\xb8\x01\x00\x00\x00" + PROLOGUE + EPILOGUE)
        runs = find_common_runs(left, right)
        assert [(r.left_va, r.right_va, r.length) for r in runs] == [(0x1000, 0x1005, 5)]

        # Group membership, not a ranking: three identical units and one
        # distinct means one group of exactly three members, and the distinct
        # unit appears in no group at all.
        units = [
            _unit(0x2000, PROLOGUE + EPILOGUE),
            _unit(0x2100, PROLOGUE + EPILOGUE),
            _unit(0x2200, PROLOGUE + EPILOGUE),
            _unit(0x2300, UNRELATED),
        ]
        clusters = cluster_units(units)
        assert [c.members for c in clusters] == [[0x2000, 0x2100, 0x2200]]
        assert all(0x2300 not in c.members for c in clusters)


class TestSubmatchCli:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, report: dict) -> None:
        monkeypatch.setattr(
            similar_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(),
        )
        monkeypatch.setattr(similar_mod, "submatch_report", lambda cfg, a, b, min_run: report)

    def test_json_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(
            monkeypatch,
            {
                "left_va": "0x00001000",
                "right_va": "0x00002000",
                "left_name": "a",
                "right_name": "b",
                "left_instructions": 9,
                "right_instructions": 11,
                "min_run": 4,
                "runs": [
                    {
                        "left_va": "0x00001000",
                        "right_va": "0x00002005",
                        "length": 5,
                        "instructions": ["push ebp", "mov ebp, esp"],
                    }
                ],
            },
        )
        result = runner.invoke(
            rebrew.main.app, ["similar", "0x1000", "--submatch", "--other", "0x2000", "--json"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["runs"][0]["length"] == 5
        assert payload["runs"][0]["right_va"] == "0x00002005"

    def test_missing_other_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            similar_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(),
        )
        result = runner.invoke(rebrew.main.app, ["similar", "0x1000", "--submatch", "--json"])
        assert result.exit_code == 2
        assert "--other" in json.loads(result.stdout)["error"]

    def test_render_without_runs_is_not_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(
            monkeypatch,
            {
                "left_va": "0x00001000",
                "right_va": "0x00002000",
                "left_name": "",
                "right_name": "",
                "left_instructions": 3,
                "right_instructions": 4,
                "min_run": 4,
                "runs": [],
            },
        )
        result = runner.invoke(
            rebrew.main.app, ["similar", "0x1000", "--submatch", "--other", "0x2000"]
        )
        assert result.exit_code == 0
        assert "No common run" in result.output


class TestClusterCli:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, report: dict) -> None:
        monkeypatch.setattr(
            similar_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(),
        )
        monkeypatch.setattr(
            similar_mod, "cluster_report", lambda cfg, min_size, query_va=None: report
        )

    def test_json_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(
            monkeypatch,
            {
                "total_functions": 40,
                "skipped": 0,
                "min_size": 2,
                "duplicate_groups": 1,
                "duplicate_functions": 40,
                "query_group": 0,
                "clusters": [
                    {
                        "size": 40,
                        "signature": "abcd1234",
                        "instructions": 3,
                        "members": [{"va": "0x00001000", "name": "thunk", "size": 6}],
                    }
                ],
            },
        )
        result = runner.invoke(rebrew.main.app, ["similar", "--cluster", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["duplicate_groups"] == 1
        assert payload["clusters"][0]["size"] == 40
        assert payload["clusters"][0]["members"][0]["va"] == "0x00001000"

    def test_requires_va_or_cluster(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            similar_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(),
        )
        result = runner.invoke(rebrew.main.app, ["similar", "--json"])
        assert result.exit_code == 2
        assert "--cluster" in json.loads(result.stdout)["error"]
