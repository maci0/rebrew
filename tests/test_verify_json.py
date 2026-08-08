"""Tests for verify.py diff_reports function."""

import pytest

from rebrew.verify import diff_reports


class TestVerifyDiff:
    def test_diff_no_changes(self) -> None:
        previous = {
            "results": [
                {"va": "0x10001000", "name": "func_a", "status": "EXACT", "delta": 0},
                {"va": "0x10002000", "name": "func_b", "status": "STUB", "delta": 3},
            ]
        }
        current = {
            "results": [
                {"va": "0x10001000", "name": "func_a", "status": "EXACT", "delta": 0},
                {"va": "0x10002000", "name": "func_b", "status": "STUB", "delta": 3},
            ]
        }

        diff = diff_reports(previous, current)
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert diff["new"] == []
        assert diff["removed"] == []
        assert diff["unchanged_count"] == 2

    def test_diff_regression(self) -> None:
        previous = {
            "results": [{"va": "0x10001000", "name": "func_a", "status": "EXACT", "delta": 0}]
        }
        current = {
            "results": [{"va": "0x10001000", "name": "func_a", "status": "STUB", "delta": 4}]
        }

        diff = diff_reports(previous, current)
        assert len(diff["regressions"]) == 1
        assert diff["regressions"][0]["previous_status"] == "EXACT"
        assert diff["regressions"][0]["current_status"] == "STUB"
        assert diff["regressions"][0]["delta"] == 4
        assert diff["improvements"] == []

    def test_diff_improvement(self) -> None:
        previous = {
            "results": [{"va": "0x10001000", "name": "func_a", "status": "STUB", "delta": 6}]
        }
        current = {
            "results": [{"va": "0x10001000", "name": "func_a", "status": "EXACT", "delta": 0}]
        }

        diff = diff_reports(previous, current)
        assert len(diff["improvements"]) == 1
        assert diff["improvements"][0]["previous_status"] == "STUB"
        assert diff["improvements"][0]["current_status"] == "EXACT"
        assert diff["regressions"] == []

    def test_diff_new_function(self) -> None:
        previous = {"results": []}
        current = {
            "results": [{"va": "0x10003000", "name": "func_new", "status": "RELOC", "delta": 0}]
        }

        diff = diff_reports(previous, current)
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert len(diff["new"]) == 1
        assert diff["new"][0]["va"] == "0x10003000"
        assert diff["new"][0]["status"] == "RELOC"

    def test_diff_removed_function(self) -> None:
        previous = {
            "results": [
                {"va": "0x10004000", "name": "func_old", "status": "COMPILE_ERROR", "delta": 0}
            ]
        }
        current = {"results": []}

        diff = diff_reports(previous, current)
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert len(diff["removed"]) == 1
        assert diff["removed"][0]["va"] == "0x10004000"
        assert diff["removed"][0]["status"] == "COMPILE_ERROR"

    def test_diff_mixed(self) -> None:
        previous = {
            "results": [
                {"va": "0x10001000", "name": "regress", "status": "EXACT", "delta": 0},
                {"va": "0x10002000", "name": "improve", "status": "STUB", "delta": 8},
                {"va": "0x10003000", "name": "same", "status": "RELOC", "delta": 0},
                {"va": "0x10004000", "name": "removed", "status": "FAIL", "delta": 0},
            ]
        }
        current = {
            "results": [
                {"va": "0x10001000", "name": "regress", "status": "COMPILE_ERROR", "delta": 2},
                {"va": "0x10002000", "name": "improve", "status": "EXACT", "delta": 0},
                {"va": "0x10003000", "name": "same", "status": "RELOC", "delta": 0},
                {"va": "0x10005000", "name": "new", "status": "MISSING_FILE", "delta": 0},
            ]
        }

        diff = diff_reports(previous, current)
        assert len(diff["regressions"]) == 1
        assert len(diff["improvements"]) == 1
        assert len(diff["new"]) == 1
        assert len(diff["removed"]) == 1
        assert diff["unchanged_count"] == 1

    def test_diff_same_status_unchanged(self) -> None:
        previous = {
            "results": [{"va": "0x10006000", "name": "func_same", "status": "STUB", "delta": 1}]
        }
        current = {
            "results": [{"va": "0x10006000", "name": "func_same", "status": "STUB", "delta": 12}]
        }

        diff = diff_reports(previous, current)
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert diff["unchanged_count"] == 1

    def test_diff_reloc_to_exact_is_improvement(self) -> None:
        previous = {
            "results": [{"va": "0x10007000", "name": "func_reloc", "status": "RELOC", "delta": 0}]
        }
        current = {
            "results": [{"va": "0x10007000", "name": "func_reloc", "status": "EXACT", "delta": 0}]
        }

        diff = diff_reports(previous, current)
        assert len(diff["improvements"]) == 1
        assert diff["improvements"][0]["previous_status"] == "RELOC"
        assert diff["improvements"][0]["current_status"] == "EXACT"
        assert diff["regressions"] == []

    def test_diff_near_matching_to_proven_is_improvement(self) -> None:
        """PROVEN must rank as a success tier — not as unknown/FAIL."""
        previous = {
            "results": [
                {"va": "0x10007010", "name": "func_near", "status": "NEAR_MATCHING", "delta": 4}
            ]
        }
        current = {
            "results": [{"va": "0x10007010", "name": "func_near", "status": "PROVEN", "delta": 4}]
        }

        diff = diff_reports(previous, current)
        assert len(diff["improvements"]) == 1
        assert diff["improvements"][0]["previous_status"] == "NEAR_MATCHING"
        assert diff["improvements"][0]["current_status"] == "PROVEN"
        assert diff["regressions"] == []

    def test_diff_proven_not_regression_vs_reloc(self) -> None:
        previous = {
            "results": [{"va": "0x10007020", "name": "func_p", "status": "PROVEN", "delta": 2}]
        }
        current = {
            "results": [{"va": "0x10007020", "name": "func_p", "status": "RELOC", "delta": 0}]
        }

        diff = diff_reports(previous, current)
        # Same rank tier — neither regression nor improvement by status alone.
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert diff["unchanged_count"] == 1

    def test_diff_matching_alias(self) -> None:
        """NEAR_MATCHING → STUB is a same-rank DEGRADATION — the fine-grained
        status order must report it as a regression (was: unchanged)."""
        previous = {
            "results": [
                {"va": "0x10008000", "name": "func_alias", "status": "NEAR_MATCHING", "delta": 3}
            ]
        }
        current = {
            "results": [{"va": "0x10008000", "name": "func_alias", "status": "STUB", "delta": 5}]
        }

        diff = diff_reports(previous, current)
        assert len(diff["regressions"]) == 1
        assert diff["regressions"][0]["previous_status"] == "NEAR_MATCHING"
        assert diff["regressions"][0]["current_status"] == "STUB"
        assert diff["improvements"] == []
        assert diff["unchanged_count"] == 0


class TestApplyOrPreviewStatus:
    """rebrew verify --dry-run must not write STATUS metadata."""

    def _entry(self) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(module="game", va=0x10001000, status="STUB")

    def test_dry_run_skips_writes(self, monkeypatch: object) -> None:
        from rebrew.verify import _apply_or_preview_status

        calls: list[object] = []
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda fixes, cfg: calls.append(fixes),
        )
        _apply_or_preview_status([(self._entry(), "EXACT", 0)], object(), dry_run=True)
        assert calls == []

    def test_apply_writes(self, monkeypatch: object) -> None:
        from rebrew.verify import _apply_or_preview_status

        calls: list[object] = []
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda fixes, cfg: calls.append(fixes),
        )
        _apply_or_preview_status([(self._entry(), "EXACT", 0)], object(), dry_run=False)
        assert len(calls) == 1

    def test_dry_run_preview_skips_refused_updates(self, capsys: pytest.CaptureFixture) -> None:
        """The preview must only claim updates a real run would write.

        PROVEN is sticky (never demoted) and a STUB's placeholder
        size-mismatch keeps the user's classification — neither would be
        written, so --dry-run must not claim them.
        """
        from types import SimpleNamespace

        from rebrew.verify import _apply_or_preview_status

        proven = SimpleNamespace(module="game", va=0x10001000, status="PROVEN")
        stub_mm = SimpleNamespace(module="game", va=0x10002000, status="STUB")
        promotable = SimpleNamespace(module="game", va=0x10003000, status="NEAR_MATCHING")

        # STUB -> SIZE_MISMATCH is refused; PROVEN -> NEAR_MATCHING is refused.
        _apply_or_preview_status(
            [(stub_mm, "SIZE_MISMATCH", 0), (proven, "NEAR_MATCHING", 0)], object(), dry_run=True
        )
        out = capsys.readouterr()
        assert "would update" not in out.err
        assert "would update" not in out.out

        # A genuine promotion is still previewed.
        _apply_or_preview_status([(promotable, "EXACT", 0)], object(), dry_run=True)
        out = capsys.readouterr()
        assert "would update STATUS → EXACT for 0x10003000 (game)" in out.err
