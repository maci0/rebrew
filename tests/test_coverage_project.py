"""Live project coverage must reflect canonical inputs without export files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from bin_util import make_pe
from cli_json import cli_payload
from source_util import write_source
from tree_snapshot import project_files

from rebrew import coverage_project
from rebrew.coverage_project import ProjectCoverageError, load_project_coverage
from rebrew.metadata.functions import update_source_status


def _project(root: Path, *, extra: str = "") -> None:
    (root / "rebrew-project.toml").write_text(
        '[project]\nname = "live"\ndefault_target = "good"\nshared_dir = ""\n'
        '[compiler]\nprofile = "msvc-6.0"\nincludes = ""\nlibs = ""\n'
        '[targets.good]\nbinary = "game.exe"\nreversed_dir = "src"\nmodule = "GOOD"\n' + extra
    )
    (root / "game.exe").write_bytes(make_pe(b"\xc3"))
    source = root / "src" / "function.c"
    source.parent.mkdir()
    write_source(
        source,
        "// ADDRESS: GOOD 0x401000\nint foo(void) { return 0; }\n",
        metadata_dir=root,
        metadata_fields={
            "GOOD.0x401000": {"kind": "FUNCTION", "name": "foo", "size": 1, "status": "EXACT"}
        },
    )


class TestLiveProjectCoverage:
    def test_existing_epoch_timestamp_config_is_read(self, tmp_path: Path) -> None:
        _project(tmp_path)
        config = tmp_path / "rebrew-project.toml"
        os.utime(config, ns=(0, 0))
        assert config.stat().st_mtime_ns == 0
        view = load_project_coverage(tmp_path, refresh=True)
        assert "good" in view.snapshots and not view.failures

    def test_missing_config_stays_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(ProjectCoverageError, match="no rebrew-project.toml"):
            load_project_coverage(tmp_path, refresh=True)

    def test_reads_canonical_metadata_without_creating_exports(self, tmp_path: Path) -> None:
        _project(tmp_path)
        before = {p.relative_to(tmp_path) for p in project_files(tmp_path)}
        view = load_project_coverage(tmp_path)
        assert not view.failures
        assert view.snapshots["good"].functions[0].status == "EXACT"
        assert view.snapshots["good"].sections[".text"].size > 0
        assert {p.relative_to(tmp_path) for p in project_files(tmp_path)} == before

    def test_metadata_changes_replace_one_immutable_view(self, tmp_path: Path) -> None:
        _project(tmp_path)
        first = load_project_coverage(tmp_path)
        assert load_project_coverage(tmp_path) is first
        update_source_status(tmp_path, "NEAR_MATCHING", "GOOD", 0x401000, updated_by="test")
        second = load_project_coverage(tmp_path, refresh=True)
        assert second is not first
        assert second.versions != first.versions
        assert second.snapshots["good"].functions[0].status == "NEAR_MATCHING"
        assert first.snapshots["good"].functions[0].status == "EXACT"

    def test_one_broken_target_does_not_hide_healthy_targets(self, tmp_path: Path) -> None:
        _project(tmp_path, extra='[targets.bad]\nbinary = "bad.exe"\narch = "invalid-arch"\n')
        view = load_project_coverage(tmp_path)
        assert set(view.snapshots) == {"good"}
        assert "bad" in view.failures
        assert "invalid-arch" in view.failures["bad"]

    def test_malformed_project_never_falls_back_to_old_exports(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text("[broken")
        (tmp_path / "db").mkdir()
        with pytest.raises(ProjectCoverageError, match="cannot read project coverage"):
            load_project_coverage(tmp_path)

    def test_continuously_changing_inputs_do_not_publish_a_mixed_frame(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        original = coverage_project.build_catalog_data

        def _change_after_scan(cfg: Any, **kwargs: Any) -> dict[str, Any]:
            result = original(cfg, **kwargs)
            source = tmp_path / "src" / "function.c"
            source.write_text(source.read_text() + "\n/* concurrent edit */\n")
            return result

        monkeypatch.setattr(coverage_project, "build_catalog_data", _change_after_scan)
        view = load_project_coverage(tmp_path)
        assert not view.snapshots
        assert "inputs changed" in view.failures["good"]

    def test_live_dashboard_reports_failed_siblings(self, tmp_path: Path) -> None:
        import json

        from rebrew.dashboard import Dashboard

        _project(tmp_path, extra='[targets.bad]\nbinary = "bad.exe"\narch = "invalid-arch"\n')
        dashboard = Dashboard(tmp_path)
        for route in ("/api/targets", "/api/bootstrap", "/api/health"):
            code, _, body = dashboard.handle("GET", route, {})
            payload = json.loads(body)
            assert code == 200
            assert "invalid-arch" in payload["failures"]["bad"]
            if route == "/api/health":
                assert payload["status"] == "degraded"
        remote = Dashboard(tmp_path, expose_paths=False)
        payload = json.loads(remote.handle("GET", "/api/health", {})[2])
        assert "invalid-arch" not in payload["failures"]["bad"]
        assert "coverage_source" not in payload

    def test_inventory_rewrite_with_restored_mtime_rebuilds_names(self, tmp_path: Path) -> None:
        import json
        import os

        _project(tmp_path)
        inventory = tmp_path / "src" / "function_structure.json"
        inventory.write_text(json.dumps([{"va": 0x401000, "name": "alpha", "size": 1}]))
        before = inventory.stat()
        first = load_project_coverage(tmp_path)
        inventory.write_text(inventory.read_text().replace("alpha", "bravo"))
        os.utime(inventory, ns=(before.st_atime_ns, before.st_mtime_ns))
        second = load_project_coverage(tmp_path, refresh=True)
        assert first.snapshots["good"].functions[0].list_name == "alpha"
        assert second.snapshots["good"].functions[0].list_name == "bravo"

    def test_archive_and_compile_command_sources_are_inputs(self, tmp_path: Path) -> None:
        import json

        _project(tmp_path)
        from rebrew.config import load_config

        cfg = load_config(tmp_path)
        cfg.raw_link = tmp_path / "build" / "game.exe"
        cfg.external_libs = {"runtime": "refs/runtime.lib"}
        commands = cfg.raw_link.parent / "compile_commands.json"
        commands.parent.mkdir()
        commands.write_text(json.dumps([{"directory": str(tmp_path), "file": "outside.c"}]))
        paths = {row[0] for row in coverage_project._inputs(cfg)}
        assert str(commands) in paths
        assert str(tmp_path / "outside.c") in paths
        assert str(tmp_path / "refs" / "runtime.lib") in paths

    def test_shared_roots_are_walked_once_per_poll(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(
            tmp_path,
            extra='[targets.other]\nbinary = "game.exe"\nreversed_dir = "src"\nmodule = "OTHER"\n',
        )
        load_project_coverage(tmp_path)
        original = coverage_project.scan_files
        walked: list[Path] = []

        def scan(root: Path) -> list[Path]:
            walked.append(root)
            return original(root)

        monkeypatch.setattr(coverage_project, "scan_files", scan)
        load_project_coverage(tmp_path, refresh=True)
        assert walked.count(tmp_path / "src") == 1
        assert Path() not in walked

    def test_corrupt_binary_is_an_explicit_failure(self, tmp_path: Path) -> None:
        _project(tmp_path)
        (tmp_path / "game.exe").write_bytes(b"not an executable")
        view = load_project_coverage(tmp_path)
        assert not view.snapshots
        assert "good" in view.failures

    def test_unchanged_failure_reuses_the_same_view(self, tmp_path: Path) -> None:
        _project(tmp_path, extra='[targets.bad]\nbinary = "bad.exe"\narch = "invalid-arch"\n')
        first = load_project_coverage(tmp_path)
        second = load_project_coverage(tmp_path, refresh=True)
        assert second is first


class TestPortableHistoryMigration:
    def test_selected_import_ignores_broken_sibling_and_preview_writes_nothing(
        self, tmp_path: Path
    ) -> None:

        from typer.testing import CliRunner

        from rebrew.coverage_history import app
        from rebrew.coverage_toml import render_coverage_toml
        from rebrew.metadata.functions import load_status_history

        _project(tmp_path)
        portable = tmp_path / "portable"
        portable.mkdir()
        event = {
            "va": 0x401000,
            "old_status": "STUB",
            "new_status": "EXACT",
            "changed_at": "2026-10-10T12:00:00+00:00",
            "updated_by": "verify",
        }
        (portable / "coverage-good.toml").write_text(
            render_coverage_toml("good", {}, history=[event])
        )
        (portable / "coverage-bad.toml").write_text("[broken")
        before = {str(p): p.read_bytes() for p in project_files(tmp_path)}
        runner = CliRunner()
        args = ["--root", str(tmp_path), "--snapshots", str(portable), "--json"]
        rejected = runner.invoke(app, [*args, "--dry-run"])
        assert rejected.exit_code != 0
        preview = runner.invoke(app, [*args, "--target", "good", "--dry-run"])
        assert preview.exit_code == 0, preview.output
        assert cli_payload(preview)["results"][0]["functions_changed"] == 1
        assert before == {str(p): p.read_bytes() for p in project_files(tmp_path)}
        applied = runner.invoke(app, [*args, "--target", "good"])
        assert applied.exit_code == 0, applied.output
        assert load_status_history(tmp_path, "GOOD") == [event]

    def test_export_refuses_to_overwrite_unimported_history(self, tmp_path: Path) -> None:
        from rebrew.coverage_toml import render_coverage_toml, write_coverage_toml

        _project(tmp_path)
        portable = tmp_path / "portable"
        portable.mkdir()
        path = portable / "coverage-good.toml"
        path.write_text(
            render_coverage_toml(
                "good",
                {},
                history=[
                    {
                        "va": 0x401000,
                        "old_status": "STUB",
                        "new_status": "EXACT",
                        "changed_at": "2026-10-10T12:00:00+00:00",
                        "updated_by": "verify",
                    }
                ],
            )
        )
        before = path.read_bytes()
        from rebrew.coverage_toml import CoverageTomlError

        with pytest.raises(CoverageTomlError, match="import-history"):
            write_coverage_toml(tmp_path, portable, target="good")
        assert path.read_bytes() == before


class TestProjectCoherence:
    def test_shared_edit_during_second_target_withdraws_first_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(
            tmp_path,
            extra='[targets.zother]\nbinary="game.exe"\nreversed_dir="src"\nmodule ="GOOD"\n',
        )
        original = coverage_project.build_catalog_data
        changed = False

        def _edit_on_second(cfg: Any, **kwargs: Any) -> dict[str, Any]:
            nonlocal changed
            if cfg.target_name == "zother" and not changed:
                changed = True
                update_source_status(tmp_path, "NEAR_MATCHING", "GOOD", 0x401000, updated_by="test")
            return original(cfg, **kwargs)

        monkeypatch.setattr(coverage_project, "build_catalog_data", _edit_on_second)
        view = load_project_coverage(tmp_path)
        assert "good" not in view.snapshots
        assert "inputs changed" in view.failures["good"]
        assert view.snapshots["zother"].functions[0].status == "NEAR_MATCHING"

    def test_final_validation_error_is_target_scoped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(
            tmp_path,
            extra='[targets.zother]\nbinary="game.exe"\nreversed_dir="src"\nmodule ="OTHER"\n',
        )
        original = coverage_project._inputs
        calls: dict[str, int] = {}

        def _unreadable_at_publication(cfg: Any, scans: Any = None) -> Any:
            calls[cfg.target_name] = calls.get(cfg.target_name, 0) + 1
            if cfg.target_name == "good" and calls["good"] == 4:
                raise PermissionError("source became unreadable")
            return original(cfg, scans)

        monkeypatch.setattr(coverage_project, "_inputs", _unreadable_at_publication)
        view = load_project_coverage(tmp_path)
        assert set(view.snapshots) == {"zother"}
        assert "source became unreadable" in view.failures["good"]
