"""Tests for tools/check_idempotency — the CLI determinism checker."""

import os
from pathlib import Path

import pytest

from tools.check_idempotency import _normalize, outputs_identical


class TestNormalize:
    def test_drops_timestamp_recursively(self) -> None:
        data = {
            "timestamp": "2026-08-07T00:00:00+00:00",
            "summary": {"passed": 1, "timestamp": "x"},
            "results": [{"va": "0x1", "timestamp": "y"}],
        }
        assert _normalize(data) == {
            "summary": {"passed": 1},
            "results": [{"va": "0x1"}],
        }

    def test_leaves_other_keys(self) -> None:
        assert _normalize({"a": 1, "b": [1, 2]}) == {"a": 1, "b": [1, 2]}


class TestOutputsIdentical:
    def _install_rebrew(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str) -> None:
        """Install a fake `rebrew` on PATH that runs *script*."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        script_path = bin_dir / "rebrew"
        script_path.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
        script_path.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")

    def test_identical_outputs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install_rebrew(tmp_path, monkeypatch, 'echo \'{"timestamp": "t", "a": 1}\'')
        assert outputs_identical("status --json", tmp_path)

    def test_differing_outputs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install_rebrew(
            tmp_path,
            monkeypatch,
            'echo "{\\"a\\": $(date +%s%N)}"',
        )
        # A different nanosecond value → not identical.
        assert not outputs_identical("status --json", tmp_path)

    def test_differing_exit_codes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # First invocation exits 0, second exits 1 (count via a marker file
        # in the sandbox — $HOME is unreliable in the test subprocess).
        marker = tmp_path / "count"
        self._install_rebrew(
            tmp_path,
            monkeypatch,
            f"if [ -f {marker} ]; then exit 1; fi; touch {marker}; echo '{{\"a\": 1}}'",
        )
        assert not outputs_identical("status --json", tmp_path)

    def test_non_json_output_compared_verbatim(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_rebrew(tmp_path, monkeypatch, 'echo "plain text"')
        assert outputs_identical("status --json", tmp_path)


class TestCliArgEdgeCases:
    def test_cwd_without_value_errors(self, capsys) -> None:
        from tools.check_idempotency import main

        assert main(["--cwd"]) == 2
        out = capsys.readouterr().out
        assert "--cwd requires a directory" in out


class TestFixtureProject:
    def test_write_fixture_project_assembles_project(self, tmp_path: Path) -> None:
        from tools.check_idempotency import write_fixture_project

        project = write_fixture_project(tmp_path / "proj")
        assert (project / "rebrew-project.toml").is_file()
        assert (project / "original" / "mini_pe.exe").is_file()
        assert (project / "src" / "SERVER" / "fcn.c").is_file()
        assert "mini_pe.exe" in (project / "rebrew-project.toml").read_text(encoding="utf-8")

    def test_fixture_dir_without_value_errors(self, capsys) -> None:
        from tools.check_idempotency import main

        assert main(["--fixture-dir"]) == 2
        assert "--fixture-dir requires a directory" in capsys.readouterr().out

    def test_fixture_dir_sweep_runs_against_real_rebrew(self, tmp_path: Path) -> None:
        """End-to-end: the full default sweep passes on the fixture project.

        Uses the real `rebrew` CLI via uv run (the fixture project's config is
        deliberately minimal so every offline --json command works).
        """

        project = tmp_path / "proj"
        from tools.check_idempotency import main

        # Point the sweep at a subprocess cwd by invoking main with --fixture-dir.
        code = main(["--fixture-dir", str(project)])
        assert code == 0
        # Sanity: the project actually got created.
        assert (project / "original" / "mini_pe.exe").is_file()
