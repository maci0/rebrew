"""Tests for verify.py diff_reports function."""

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

    def test_diff_matching_alias(self) -> None:
        previous = {
            "results": [
                {"va": "0x10008000", "name": "func_alias", "status": "NEAR_MATCHING", "delta": 3}
            ]
        }
        current = {
            "results": [{"va": "0x10008000", "name": "func_alias", "status": "STUB", "delta": 5}]
        }

        diff = diff_reports(previous, current)
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert diff["unchanged_count"] == 1
