"""CPU clocks and comparable, machine-readable microbenchmark reports."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tools import bench_hotpaths as bench


class TestMeasurement:
    def test_descheduled_time_is_separate_from_cpu_work(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cpu = iter([0, 10, 10, 40, 40, 60])
        wall = iter([0, 1000, 1000, 5000, 5000, 7000])
        monkeypatch.setattr("tools.bench_hotpaths.time.process_time_ns", lambda: next(cpu))
        monkeypatch.setattr("tools.bench_hotpaths.time.perf_counter_ns", lambda: next(wall))
        calls = []
        result = bench.measure(lambda: calls.append(1), repeat=3)
        assert len(calls) == 4  # Untimed warmup plus three samples.
        assert result["cpu_samples"] == [10 / 1e9, 30 / 1e9, 20 / 1e9]
        assert result["cpu_seconds"] == 20 / 1e9
        assert result["wall_seconds"] == 2000 / 1e9

    def test_json_is_a_complete_report_and_can_be_compared(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def workload() -> dict[str, Any]:
            return {"ops": 10, "cpu_seconds": 2.0, "wall_seconds": 4.0}

        monkeypatch.setattr(bench, "_BENCHES", {"unit": workload})
        report = tmp_path / "before.json"
        monkeypatch.setattr(sys, "argv", ["bench", "--json", "--output", str(report)])
        assert bench.main() == 0
        first = json.loads(capsys.readouterr().out)
        assert first == json.loads(report.read_text())
        assert first["clock"] == "process_time_ns"
        assert first["benchmarks"]["unit"]["ops_per_cpu_second"] == 5
        monkeypatch.setattr(sys, "argv", ["bench", "--json", "--compare", str(report)])
        assert bench.main() == 0
        assert json.loads(capsys.readouterr().out)["benchmarks"]["unit"]["speedup"] == 1

    def test_rejects_unrelated_wall_time_baselines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        report = tmp_path / "old.json"
        report.write_text('{"annotation_parsing": 0.004}')
        monkeypatch.setattr(sys, "argv", ["bench", "--compare", str(report)])
        with pytest.raises(SystemExit) as exc:
            bench.main()
        assert exc.value.code == 2
