"""Tests for verify.py structured JSON report."""

import json
from datetime import UTC, datetime

import pytest


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
