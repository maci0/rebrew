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


class TestTreeDigest:
    def test_ignores_mtime_but_not_content(self, tmp_path: Path) -> None:
        from tools.check_idempotency import tree_digest

        target = tmp_path / "a.c"
        target.write_text("x\n", encoding="utf-8")
        before = tree_digest(tmp_path)
        target.touch()
        assert tree_digest(tmp_path) == before
        target.write_text("y\n", encoding="utf-8")
        assert tree_digest(tmp_path) != before

    def test_lists_added_and_removed_paths(self, tmp_path: Path) -> None:
        from tools.check_idempotency import _tree_diff

        diff = _tree_diff({"a.c": "1", "b.c": "2"}, {"a.c": "9", "c.c": "3"})
        assert "added: c.c" in diff
        assert "removed: b.c" in diff
        assert "changed: a.c" in diff


class TestWriteIdempotency:
    """A mutating command must leave the same project behind on its second run."""

    def _install_rebrew(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str) -> None:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        script_path = bin_dir / "rebrew"
        script_path.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
        script_path.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")

    def test_convergent_command_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tools.check_idempotency import check_write_idempotency

        project = tmp_path / "proj"
        project.mkdir()
        self._install_rebrew(
            tmp_path,
            monkeypatch,
            'if [ -f note.c ]; then rm -f note.c; fi; echo "// once" > note.c',
        )
        assert check_write_idempotency("migrate-markers", project) == (True, "")

    def test_appending_command_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from tools.check_idempotency import check_write_idempotency

        project = tmp_path / "proj"
        project.mkdir()
        self._install_rebrew(tmp_path, monkeypatch, 'echo "// GLOBAL: SERVER 0x401000" >> note.c')
        ok, reason = check_write_idempotency("document-unmatched", project)
        assert not ok
        assert "note.c" in reason

    def test_exit_code_mismatch_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tools.check_idempotency import check_write_idempotency

        project = tmp_path / "proj"
        project.mkdir()
        self._install_rebrew(
            tmp_path,
            monkeypatch,
            f"if [ -f {project}/ran ]; then exit 3; fi; touch {project}/ran",
        )
        ok, reason = check_write_idempotency("gen-link-stubs", project)
        assert not ok
        assert "exit code mismatch" in reason

    def test_no_op_command_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A command that writes nothing proves nothing, so it must not pass.

        Exiting 0 twice and leaving the tree identical is what a mutating
        command looks like once it stops mutating — a guard that starts
        refusing, a renamed flag, an inventory key that no longer resolves.
        The tree compare alone cannot see that, so run 1 is required to
        change something.
        """
        from tools.check_idempotency import check_write_idempotency

        project = tmp_path / "proj"
        project.mkdir()
        self._install_rebrew(tmp_path, monkeypatch, 'echo "nothing to do"')
        ok, reason = check_write_idempotency("document-unmatched", project)
        assert not ok
        assert "unchanged" in reason


class TestFixtureProject:
    def test_write_fixture_project_assembles_project(self, tmp_path: Path) -> None:
        from tools.check_idempotency import write_fixture_project

        project = write_fixture_project(tmp_path / "proj")
        assert (project / "rebrew-project.toml").is_file()
        assert (project / "original" / "mini_pe.exe").is_file()
        assert (project / "src" / "SERVER" / "fcn.c").is_file()
        assert "mini_pe.exe" in (project / "rebrew-project.toml").read_text(encoding="utf-8")

    def test_fixture_ships_a_function_inventory(self, tmp_path: Path) -> None:
        """The write sweep's commands need functions to work on.

        Without an inventory, ``document-unmatched`` and ``skeleton`` have
        nothing to do, exit 0, and pass every re-run comparison while
        proving nothing about re-execution safety.
        """
        import json

        from rebrew.catalog import cached_function_list
        from rebrew.config import load_config
        from tools.check_idempotency import write_fixture_project

        project = write_fixture_project(tmp_path / "proj")
        inventory = project / "src" / "SERVER" / "function_structure.json"
        assert inventory.is_file()
        assert len(json.loads(inventory.read_text(encoding="utf-8"))) == 2

        cfg = load_config(project)
        # The fixture's lone source covers _func1; _func2 is left uncovered on
        # purpose so the inventory-driven write commands have real work.
        assert {f["name"] for f in cached_function_list(cfg)} == {"_func1", "_func2"}

    def test_fixture_dir_without_value_errors(self, capsys) -> None:
        from tools.check_idempotency import main

        assert main(["--fixture-dir"]) == 2
        assert "--fixture-dir requires a directory" in capsys.readouterr().out

    def test_fixture_dir_sweep_runs_against_real_rebrew(self, tmp_path: Path) -> None:
        """End-to-end: the read-only and write sweeps pass on the fixture project.

        Uses the real `rebrew` CLI (the fixture project's config is deliberately
        minimal so every offline --json command works).  The write sweep also
        proves the mutating commands leave the project byte-identical when run
        a second time.
        """

        project = tmp_path / "proj"
        from tools.check_idempotency import main

        # Point the sweep at a subprocess cwd by invoking main with --fixture-dir.
        code = main(["--fixture-dir", str(project)])
        assert code == 0
        # Sanity: the project actually got created.
        assert (project / "original" / "mini_pe.exe").is_file()
