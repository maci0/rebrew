"""End-to-end sync reconciliation, evidence retention and failure recovery."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from rebrew.binsync.export import export_state, print_export_result
from rebrew.binsync.importer import import_state
from rebrew.binsync.serial import dump_artifact, load_artifact, new_struct, write_state_text
from rebrew.binsync.state import load_sync_baseline, sync_baseline_path
from rebrew.config import load_config
from rebrew.data_metadata import get_data_entry, set_data_fields_batch
from rebrew.metadata import get_entry, remove_field, update_field, update_source_status

pytest.importorskip("declib")


def _project(root: Path) -> Any:
    (root / "rebrew-project.toml").write_text(
        '[project]\ndefault_target="server"\n'
        '[targets.server]\nbinary="server.dll"\nreversed_dir="src"\n'
    )
    (root / "src").mkdir()
    (root / "src/foo.c").write_text("// FUNCTION: SERVER 0x1000\nint foo(void) { return 1; }\n")
    update_source_status(root, "EXACT", "SERVER", 0x1000, updated_by="verify")
    return load_config(root=root)


def _remote_name(state: Path, name: str) -> None:
    path = state / "functions/00001000.toml"
    func = load_artifact(path, "function")
    func.header.name = name
    dump_artifact(path, func)


def _pull(cfg: Any, state: Path, **options: Any) -> dict[str, Any]:
    return import_state(cfg, state, dry_run=False, json_output=True, **options)


class TestThreeWaySync:
    def test_local_note_survives_pull_and_push_is_idempotent(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        state = tmp_path / "state"
        update_field(cfg.metadata_dir, 0x1000, "note", "base", "SERVER", updated_by="data")
        export_state(cfg, state, dry_run=False)
        update_field(cfg.metadata_dir, 0x1000, "note", "local edit", "SERVER", updated_by="data")
        _pull(cfg, state)
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER")["note"] == "local edit"
        export_state(cfg, state, dry_run=False)
        paths = list(state.rglob("*.toml")) + [sync_baseline_path(cfg, state)]
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
        result = export_state(cfg, state, dry_run=False)
        assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths} == before
        assert not any(result["health"]["pending"].values())
        shared_name = load_artifact(state / "functions/00001000.toml", "function").name
        update_field(cfg.metadata_dir, 0x1000, "ghidra", shared_name, "SERVER", updated_by="data")
        assert not any(export_state(cfg, state, dry_run=False)["health"]["pending"].values())
        remove_field(cfg.metadata_dir, 0x1000, "note", "SERVER")
        result = export_state(cfg, state, dry_run=False)
        assert (state / "comments.toml").read_text() == ""
        assert not any(result["health"]["pending"].values())
        _pull(cfg, state)
        assert "note" not in get_entry(cfg.metadata_dir, 0x1000, "SERVER")

    def test_remote_rename_and_signature_land_and_reimport_is_noop(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        state = tmp_path / "state"
        export_state(cfg, state, dry_run=False)
        path = state / "functions/00001000.toml"
        func = load_artifact(path, "function")
        func.header.name = "_Renamed"
        func.header.type = "int __cdecl Renamed(int x)"
        dump_artifact(path, func)
        result = _pull(cfg, state)
        assert result["applied_names"] == result["applied_prototypes"] == 1
        text = (cfg.reversed_dir / "Renamed.c").read_text()
        assert "int __cdecl Renamed(int x)" in text
        entry = get_entry(cfg.metadata_dir, 0x1000, "SERVER")
        assert entry["status"] == "EXACT"
        assert entry["origins"]["name"]["tool"] == "binsync"
        result = _pull(cfg, state)
        assert result["applied_names"] == result["applied_prototypes"] == 0

    def test_two_changed_names_conflict_and_push_preserves_remote(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        cfg = _project(tmp_path)
        state = tmp_path / "state"
        export_state(cfg, state, dry_run=False)
        source = cfg.reversed_dir / "foo.c"
        source.write_text(source.read_text().replace("foo", "Local"))
        _remote_name(state, "_Remote")
        baseline = sync_baseline_path(cfg, state).read_bytes()
        result = _pull(cfg, state)
        assert result["conflicts"] == 1
        assert "Local" in source.read_text()
        result = export_state(cfg, state, dry_run=False)
        assert load_artifact(state / "functions/00001000.toml", "function").name == "_Remote"
        assert result["health"]["pending"]["conflict"] == 1
        assert sync_baseline_path(cfg, state).read_bytes() == baseline
        print_export_result(result, json_output=False, dry_run=False)
        assert "function.SERVER.0x1000 name: conflict" in capsys.readouterr().err

    def test_failed_rename_does_not_advance_baseline(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        cfg = _project(tmp_path)
        state = tmp_path / "state"
        export_state(cfg, state, dry_run=False)
        _remote_name(state, "_Remote")
        before = load_sync_baseline(cfg, state)
        monkeypatch.setattr("rebrew.binsync.importer.apply_binsync_func_name", lambda *a: False)
        assert _pull(cfg, state)["skipped"] == 1
        assert load_sync_baseline(cfg, state) == before

    @pytest.mark.parametrize(
        "artifact",
        [
            "functions/00001000.toml",
            "global_vars.toml",
            "structs/Point.toml",
            "enums.toml",
            "typedefs.toml",
        ],
    )
    def test_remote_removal_is_reported_without_resurrection(
        self, tmp_path: Path, artifact: str
    ) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "types.h").write_text(
            "typedef struct { int x; } Point;\n"
            "typedef enum { RED = 1, BLUE = 2 } Color;\n"
            "typedef unsigned int Count;\n"
        )
        (cfg.reversed_dir / "g.c").write_text("// GLOBAL: SERVER 0x2000\nint g;\n")
        state = tmp_path / "state"
        export_state(cfg, state, dry_run=False)
        path = state / artifact
        path.unlink()
        result = export_state(cfg, state, dry_run=False)
        assert not path.exists()
        assert result["health"]["pending"]["deletion_required"] >= 1

    def test_remote_type_update_replaces_existing_definition(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        header = cfg.reversed_dir / "types.h"
        header.write_text("typedef struct { int x; } Point;\n")
        state = tmp_path / "state"
        export_state(cfg, state, dry_run=False)
        dump_artifact(state / "structs/Point.toml", new_struct("Point", 1, {0: ("x", "char", 1)}))
        result = _pull(cfg, state)
        assert result["applied_structs"] == 1
        assert "char x;" in header.read_text()
        assert _pull(cfg, state)["applied_structs"] == 0

    @pytest.mark.parametrize("mismatch", ["binary", "binary_file", "schema"])
    def test_binary_and_schema_mismatch_refuse_writes(self, tmp_path: Path, mismatch: str) -> None:
        cfg = _project(tmp_path)
        state = tmp_path / "state"
        cfg.target_binary.write_bytes(b"image-a")
        export_state(cfg, state, dry_run=False)
        if mismatch == "binary":
            cfg.target_binary.write_bytes(b"image-b")
        elif mismatch == "binary_file":
            write_state_text(state / "binary_hash", "0" * 32)
        else:
            path = state / "manifest.toml"
            doc = tomlkit.parse(path.read_text())
            doc["metadata_schema"] = 999
            path.chmod(0o644)
            path.write_text(tomlkit.dumps(doc))
        before = {p: p.read_bytes() for p in state.rglob("*.toml")}
        issue = "schema_mismatch" if mismatch == "schema" else "binary_mismatch"
        with pytest.raises(ValueError, match=issue):
            _pull(cfg, state)
        with pytest.raises(ValueError, match=issue):
            export_state(cfg, state, dry_run=False)
        assert {p: p.read_bytes() for p in state.rglob("*.toml")} == before

    def test_preview_does_not_create_state_or_baseline(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        state = tmp_path / "state"
        export_state(cfg, state, dry_run=True)
        assert not state.exists()
        assert not (tmp_path / ".rebrew").exists()


class TestDurableEvidence:
    @pytest.mark.parametrize("change", ["none", "during", "batch"])
    def test_verify_captures_inputs_before_compilation(
        self, tmp_path: Path, monkeypatch: Any, change: str
    ) -> None:
        from rebrew.annotation import Annotation
        from rebrew.compile import CompareResult
        from rebrew.verify import run_verification, verify_entry

        cfg = _project(tmp_path)
        source = cfg.reversed_dir / "foo.c"
        entry = Annotation(va=0x1000, module="SERVER", symbol="foo", filepath="foo.c", size=1)
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a: b"\xc3")

        def compare(*args: Any, **kwargs: Any) -> Any:
            assert bool(entry.comparison_inputs) == (change != "batch")
            if change == "during":
                source.write_text(source.read_text().replace("return 1", "return 2"))
            return CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100,
                delta=0,
                obj_bytes=b"\xc3",
                reloc_offsets=[],
            )

        monkeypatch.setattr("rebrew.compile.compile_and_compare", compare)
        if change == "batch":

            def precompile(*args: Any, **kwargs: Any) -> Any:
                source.write_text(source.read_text().replace("return 1", "return 2"))
                return {id(entry): "precompiled.obj"}

            monkeypatch.setattr("rebrew.compile.precompile_batch", precompile)
            monkeypatch.setattr("rebrew.compile_cache.get_project_cache", lambda *a: None)
            passed, failed, *_ = run_verification([entry], cfg, 1, 1, 0, True, name_to_va={})
            assert (passed, failed) == (1, 0)
        else:
            assert verify_entry(entry, cfg).status == "EXACT"
        assert bool(entry.comparison_inputs) == (change == "none")

    def test_notes_and_rechecks_preserve_measurement_and_edit_stamps(self, tmp_path: Path) -> None:
        evidence = {"status": "EXACT", "writer": "verify", "input_hash": "a" * 64}
        first = datetime(2026, 1, 1, tzinfo=UTC)
        later = datetime(2026, 2, 1, tzinfo=UTC)
        update_source_status(
            tmp_path,
            "EXACT",
            "SERVER",
            0x1000,
            updated_by="verify",
            verification=evidence,
            now=first,
        )
        update_field(tmp_path, 0x1000, "note", "edited", "SERVER", updated_by="data", now=later)
        entry = get_entry(tmp_path, 0x1000, "SERVER")
        assert entry["verification"]["measured_at"] == first.isoformat()
        before = (tmp_path / "rebrew-functions.toml").read_bytes()
        update_source_status(
            tmp_path,
            "EXACT",
            "SERVER",
            0x1000,
            updated_by="verify",
            verification=evidence,
            now=later,
        )
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == before
        update_source_status(
            tmp_path,
            "EXACT",
            "SERVER",
            0x1000,
            updated_by="verify",
            verification={**evidence, "input_hash": "b" * 64},
            now=later,
        )
        after = get_entry(tmp_path, 0x1000, "SERVER")
        assert after["updated_by"] == "data"
        assert after["verification"]["input_hash"] == "b" * 64

    def test_invalid_global_size_cannot_partially_import_name(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "g.c").write_text("// GLOBAL: SERVER 0x2000\nint g;\n")
        set_data_fields_batch(
            cfg.metadata_dir,
            [
                {
                    "module": "SERVER",
                    "va": 0x2000,
                    "fields": {
                        "name": "g",
                        "size": 4,
                        "type": "int",
                        "section": ".data",
                        "status": "VERIFIED",
                    },
                    "updated_by": "verify",
                }
            ],
        )
        state = tmp_path / "state"
        export_state(cfg, state, dry_run=False)
        from rebrew.binsync.serial import dump_many, new_global_variable

        dump_many(
            state / "global_vars.toml",
            "global_variable",
            [new_global_variable(0x2000, "Remote", "int", -1)],
        )
        before = get_data_entry(cfg.metadata_dir, 0x2000, "SERVER")
        _pull(cfg, state)
        assert get_data_entry(cfg.metadata_dir, 0x2000, "SERVER") == before
