"""Tests for binary_similarity.py — whole-binary structural similarity."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.binary_similarity import aggregate_similarity, app, score_matrix


def _sig(hist: dict[str, int], calls: int = 0, branches: int = 0) -> dict:
    return {"histogram": hist, "calls": calls, "branches": branches}


def _fn(va: int, size: int, name: str, hist: dict[str, int], calls=0, branches=0) -> dict:
    return {"va": va, "size": size, "name": name, "signature": _sig(hist, calls, branches)}


MOV_RET = {"mov": 2, "ret": 1}
XOR_RET = {"xor": 1, "ret": 1}
PUSH_POP = {"push": 2, "pop": 2, "ret": 1}
# Fully disjoint from MOV_RET/XOR_RET (no shared mnemonics) — a clean non-match.
_SYSENTER = {"sysenter": 1, "loop": 1}


class TestScoreMatrix:
    def test_identical_scores_100(self) -> None:
        s = _sig(MOV_RET, calls=1, branches=2)
        m = score_matrix([s], [s])
        assert m[0][0] == 100.0

    def test_disjoint_histograms_low(self) -> None:
        m = score_matrix([_sig(MOV_RET)], [_sig(PUSH_POP)])
        assert m[0][0] < 60.0

    def test_call_agreement_weighting(self) -> None:
        # Same histogram, call count 1 vs 10 → ratio 0.1 → 20% of 10 points lost.
        a = _sig(MOV_RET, calls=1, branches=2)
        b = _sig(MOV_RET, calls=10, branches=2)
        m = score_matrix([a], [b])
        assert m[0][0] == 0.6 * 100.0 + 0.2 * (1 / 10) * 100.0 + 0.2 * 100.0

    def test_empty_side(self) -> None:
        assert score_matrix([], [_sig(MOV_RET)]).shape == (0, 1)


class TestAggregateSimilarity:
    def test_identical_binaries_near_100(self) -> None:
        a = [_fn(0x1000, 100, "f1", MOV_RET, calls=1, branches=2)]
        b = [_fn(0x2000, 100, "f1", MOV_RET, calls=1, branches=2)]
        r = aggregate_similarity(a, b)
        assert r["overall"] == 100.0
        assert r["functions_a"] == 1 and r["functions_b"] == 1

    def test_byte_weighted_overall(self) -> None:
        # f1 (100B) matches g1 exactly; f2 (10B) is fully disjoint from g2 —
        # the byte-weighted score must be dominated by the big match.
        a = [_fn(0x1000, 100, "f1", MOV_RET, calls=1), _fn(0x1100, 10, "f2", XOR_RET)]
        b = [_fn(0x2000, 100, "g1", MOV_RET, calls=1), _fn(0x2100, 10, "g2", _SYSENTER)]
        r = aggregate_similarity(a, b)
        assert r["overall"] > r["mean"]  # weighting favours the 100B exact match
        assert r["overall"] > 90.0

    def test_buckets_byte_shares(self) -> None:
        a = [_fn(0x1000, 100, "f1", MOV_RET), _fn(0x1100, 100, "f2", XOR_RET)]
        b = [_fn(0x2000, 100, "g1", MOV_RET), _fn(0x2100, 100, "g2", _SYSENTER)]
        r = aggregate_similarity(a, b)
        buckets = {bk["label"]: bk for bk in r["buckets"]}
        near = buckets[">= 95 (near-identical)"]
        diverged = buckets["< 60 (diverged)"]
        assert near["count"] == 1
        assert diverged["count"] == 1

    def test_low_list_reports_matches(self) -> None:
        a = [_fn(0x1000, 10, "f1", MOV_RET), _fn(0x1100, 10, "f2", XOR_RET)]
        b = [_fn(0x2000, 10, "g1", MOV_RET), _fn(0x2100, 10, "g2", _SYSENTER)]
        r = aggregate_similarity(a, b, low_count=1)
        assert len(r["low"]) == 1
        # The diverged function is the lowest.
        assert r["low"][0]["score"] < 60.0
        assert r["low"][0]["matches"]["va"]

    def test_undecodable_skipped(self) -> None:
        a = [
            _fn(0x1000, 100, "f1", MOV_RET),
            {"va": 0x1100, "size": 10, "name": "bad", "signature": None},
        ]
        b = [_fn(0x2000, 100, "g1", MOV_RET)]
        r = aggregate_similarity(a, b)
        assert r["functions_a"] == 1  # the None-signature function is dropped
        assert r["overall"] == 100.0


class TestCli:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
        import rebrew.binary_similarity as bs

        target = tmp_path / "a.dll"
        target.write_bytes(b"MZfake")
        other = tmp_path / "b.dll"
        other.write_bytes(b"MZfake")
        other_list = tmp_path / "b.txt"
        other_list.write_text("0x2000 100 g1\n", encoding="utf-8")
        cfg = SimpleNamespace(target_binary=target, function_list=tmp_path / "a.txt")
        monkeypatch.setattr("rebrew.binary_similarity.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            bs,
            "_load_side",
            lambda binary, func_list, arch, mode: [_fn(0x1000, 100, "f1", MOV_RET, calls=1)],
        )
        return other, other_list

    def test_runs_and_exits_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        other, other_list = self._patch(monkeypatch, tmp_path)
        # Options before the positional (Typer callback convention).
        result = CliRunner().invoke(app, ["--other-list", str(other_list), str(other)])
        assert result.exit_code == 0
        assert "overall" in result.stderr.lower()

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        other, other_list = self._patch(monkeypatch, tmp_path)
        result = CliRunner().invoke(app, ["--json", "--other-list", str(other_list), str(other)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["overall"] == 100.0
        assert data["binary_a"].endswith("a.dll")

    def test_other_binary_missing_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.cli import EXIT_ERROR

        cfg = SimpleNamespace(target_binary=tmp_path / "a.dll")
        monkeypatch.setattr("rebrew.binary_similarity.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(
            app, [str(tmp_path / "nope.dll"), "--other-list", str(tmp_path / "x.txt")]
        )
        assert result.exit_code == EXIT_ERROR

    def test_missing_other_list_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.cli import EXIT_ERROR

        target = tmp_path / "a.dll"
        target.write_bytes(b"MZfake")
        other = tmp_path / "b.dll"
        other.write_bytes(b"MZfake")
        cfg = SimpleNamespace(target_binary=target)
        monkeypatch.setattr("rebrew.binary_similarity.require_config", lambda **kw: cfg)
        # No --other-list and no --other-target → explicit error.
        result = CliRunner().invoke(app, [str(other)])
        assert result.exit_code == EXIT_ERROR
        assert "function list" in result.output
