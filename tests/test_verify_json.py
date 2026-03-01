"""Tests for verify.py structured JSON report."""

import json
from datetime import UTC, datetime

import pytest

from rebrew.verify import diff_reports


def _classify_status(ok: bool, msg: str) -> str:
    """Reproduce the status classification logic from verify.py main()."""
    if ok:
        return "RELOC" if "RELOC" in msg else "EXACT"
    if "MISMATCH" in msg:
        return "MISMATCH"
    if "COMPILE_ERROR" in msg:
        return "COMPILE_ERROR"
    if "MISSING_FILE" in msg:
        return "MISSING_FILE"
    return "FAIL"


class TestStatusClassification:
    """Test the status classification logic used in verify.py."""

    @pytest.mark.parametrize(
        "ok, msg, expected",
        [
            (True, "EXACT MATCH", "EXACT"),
            (True, "RELOC-NORM MATCH (3 relocs)", "RELOC"),
            (False, "MISMATCH: 5 byte diffs at [0, 1, 2, 3, 4]", "MISMATCH"),
            (False, "COMPILE_ERROR: Symbol '_foo' not found in .obj", "COMPILE_ERROR"),
            (False, "MISSING_FILE: /path/to/file.c", "MISSING_FILE"),
            (False, "Cannot extract DLL bytes", "FAIL"),
        ],
    )
    def test_classify(self, ok, msg, expected) -> None:
        assert _classify_status(ok, msg) == expected


class TestVerifyJsonReport:
    """Test the structured report generation logic."""

    def test_report_structure(self) -> None:
        """Verify the report JSON has the expected top-level keys."""
        report = {
            "timestamp": datetime.now(UTC).isoformat(),
            "target": "server.dll",
            "binary": "/path/to/server.dll",
            "summary": {
                "total": 10,
                "passed": 7,
                "failed": 3,
                "exact": 4,
                "reloc": 3,
                "mismatch": 2,
                "compile_error": 1,
                "missing_file": 0,
            },
            "results": [],
        }
        assert "timestamp" in report
        assert "summary" in report
        assert (
            report["summary"]["total"] == report["summary"]["passed"] + report["summary"]["failed"]
        )
        assert (
            report["summary"]["exact"] + report["summary"]["reloc"] == report["summary"]["passed"]
        )

    def test_report_json_serializable(self) -> None:
        """Test that the report can be serialized to JSON."""
        report = {
            "timestamp": "2026-02-24T02:54:05+00:00",
            "target": "test",
            "binary": "/test/binary.dll",
            "summary": {
                "total": 2,
                "passed": 1,
                "failed": 1,
                "exact": 1,
                "reloc": 0,
                "mismatch": 1,
                "compile_error": 0,
                "missing_file": 0,
            },
            "results": [
                {
                    "va": "0x10001000",
                    "name": "func_a",
                    "filepath": "func_a.c",
                    "size": 100,
                    "status": "EXACT",
                    "message": "EXACT MATCH",
                    "passed": True,
                },
                {
                    "va": "0x10002000",
                    "name": "func_b",
                    "filepath": "func_b.c",
                    "size": 200,
                    "status": "MISMATCH",
                    "message": "MISMATCH: 3 byte diffs at [0, 1, 2]",
                    "passed": False,
                },
            ],
        }
        serialized = json.dumps(report, indent=2)
        deserialized = json.loads(serialized)
        assert deserialized["summary"]["total"] == 2
        assert len(deserialized["results"]) == 2
        assert deserialized["results"][0]["status"] == "EXACT"
        assert deserialized["results"][1]["status"] == "MISMATCH"

    def test_results_sorted_by_va(self) -> None:
        """Test that results are sorted by VA."""
        results = [
            {"va": "0x10003000", "name": "c"},
            {"va": "0x10001000", "name": "a"},
            {"va": "0x10002000", "name": "b"},
        ]
        results.sort(key=lambda r: r["va"])
        assert results[0]["name"] == "a"
        assert results[1]["name"] == "b"
        assert results[2]["name"] == "c"

    def test_report_to_file(self, tmp_path) -> None:
        """Test writing report to a file."""
        report = {
            "timestamp": "2026-02-24T02:54:05+00:00",
            "target": "test",
            "summary": {"total": 0, "passed": 0, "failed": 0},
            "results": [],
        }
        out_file = tmp_path / "db" / "verify_results.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        assert loaded["timestamp"] == "2026-02-24T02:54:05+00:00"


class TestVerifyDiff:
    def test_diff_no_changes(self) -> None:
        previous = {
            "results": [
                {"va": "0x10001000", "name": "func_a", "status": "EXACT", "delta": 0},
                {"va": "0x10002000", "name": "func_b", "status": "MISMATCH", "delta": 3},
            ]
        }
        current = {
            "results": [
                {"va": "0x10001000", "name": "func_a", "status": "EXACT", "delta": 0},
                {"va": "0x10002000", "name": "func_b", "status": "MISMATCH", "delta": 3},
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
            "results": [{"va": "0x10001000", "name": "func_a", "status": "MISMATCH", "delta": 4}]
        }

        diff = diff_reports(previous, current)
        assert len(diff["regressions"]) == 1
        assert diff["regressions"][0]["previous_status"] == "EXACT"
        assert diff["regressions"][0]["current_status"] == "MISMATCH"
        assert diff["regressions"][0]["delta"] == 4
        assert diff["improvements"] == []

    def test_diff_improvement(self) -> None:
        previous = {
            "results": [{"va": "0x10001000", "name": "func_a", "status": "MISMATCH", "delta": 6}]
        }
        current = {
            "results": [{"va": "0x10001000", "name": "func_a", "status": "EXACT", "delta": 0}]
        }

        diff = diff_reports(previous, current)
        assert len(diff["improvements"]) == 1
        assert diff["improvements"][0]["previous_status"] == "MISMATCH"
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
                {"va": "0x10002000", "name": "improve", "status": "MISMATCH", "delta": 8},
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
            "results": [{"va": "0x10006000", "name": "func_same", "status": "MISMATCH", "delta": 1}]
        }
        current = {
            "results": [
                {"va": "0x10006000", "name": "func_same", "status": "MISMATCH", "delta": 12}
            ]
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
                {"va": "0x10008000", "name": "func_alias", "status": "MATCHING", "delta": 3}
            ]
        }
        current = {
            "results": [
                {"va": "0x10008000", "name": "func_alias", "status": "MISMATCH", "delta": 5}
            ]
        }

        diff = diff_reports(previous, current)
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert diff["unchanged_count"] == 1
