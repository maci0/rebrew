"""Tests for tools/verify_baseline.py — the committed-baseline gate."""

from __future__ import annotations

import json
from pathlib import Path

from tools.verify_baseline import main, snapshot


def _write_report(root: Path, byte_matched: int, exact: int = 0, reloc: int = 0) -> Path:
    (root / "db").mkdir(parents=True, exist_ok=True)
    path = root / "db" / "verify_results.json"
    path.write_text(
        json.dumps(
            {
                "target": "T",
                "byte_matched": byte_matched,
                "exact": exact,
                "reloc": reloc,
                "total": exact + reloc,
            }
        ),
        encoding="utf-8",
    )
    return path


class TestSnapshot:
    def test_reduces_report(self) -> None:
        assert snapshot(
            {"byte_matched": 10, "exact": 6, "reloc": 4, "total": 10, "target": "T"}
        ) == {
            "byte_matched": 10,
            "exact": 6,
            "reloc": 4,
            "total": 10,
            "target": "T",
        }


class TestGate:
    def test_snapshot_then_check_passes(self, tmp_path: Path, capsys) -> None:
        _write_report(tmp_path, byte_matched=42)
        base = tmp_path / "baseline.json"
        assert main(["--snapshot", str(base), "--root", str(tmp_path)]) == 0
        assert json.loads(base.read_text())["byte_matched"] == 42
        # Same report → at baseline.
        assert main(["--check", str(base), "--root", str(tmp_path)]) == 0

    def test_regression_fails(self, tmp_path: Path, capsys) -> None:
        _write_report(tmp_path, byte_matched=42)
        base = tmp_path / "baseline.json"
        main(["--snapshot", str(base), "--root", str(tmp_path)])
        # Matched bytes drop → gate fails.
        _write_report(tmp_path, byte_matched=30)
        assert main(["--check", str(base), "--root", str(tmp_path)]) == 1
        assert "REGRESSION" in capsys.readouterr().out

    def test_improvement_passes(self, tmp_path: Path, capsys) -> None:
        _write_report(tmp_path, byte_matched=42)
        base = tmp_path / "baseline.json"
        main(["--snapshot", str(base), "--root", str(tmp_path)])
        _write_report(tmp_path, byte_matched=50)
        assert main(["--check", str(base), "--root", str(tmp_path)]) == 0

    def test_missing_report_errors(self, tmp_path: Path, capsys) -> None:
        assert main(["--snapshot", str(tmp_path / "b.json"), "--root", str(tmp_path)]) == 2

    def test_missing_baseline_errors(self, tmp_path: Path, capsys) -> None:
        _write_report(tmp_path, byte_matched=1)
        assert main(["--check", str(tmp_path / "nope.json"), "--root", str(tmp_path)]) == 2
