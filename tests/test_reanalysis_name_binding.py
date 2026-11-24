"""Re-analysis of a SQLite project whose function record names no C identifier.

An imported project can hold a record whose ``name`` is free text. The intake's
re-discovery writes a stub for it; the record and the stub must agree afterwards, a
store that already disagrees is repaired, and the project's reads keep answering.
"""

from __future__ import annotations

import json
import logging
from typing import Any
lazy from pathlib import Path

import pytest
from test_ops import _analyse_request, _worker_dirs

from rebrew.config import load_config
from rebrew.metadata.document import load_metadata_for_write
from rebrew.metadata.functions import (
    METADATA_FILENAME,
    clear_identity_fields,
    clear_metadata_cache,
    import_status_history,
    load_metadata,
)
from rebrew.metadata.storage import metadata_store
from rebrew.metadata_transfer import migrate_metadata, migration_input_digest
from rebrew.ops import BINDING_CONFLICT_DETAIL, WorkerConfig, dispatch

MODULE = "MINI"
VA = 0x401010
KEY = f"{MODULE}.0x{VA:08x}"
PLACEHOLDER = f"fcn_{VA:08x}"
FREE_TEXT = "lib_cont (split from a merged entry; round 1)"
HISTORY = {
    "old_status": "EXACT",
    "new_status": "UNKNOWN",
    "changed_at": "2026-01-02T03:04:05+00:00",
    "updated_by": "",
}


def _analyse(config: WorkerConfig) -> dict[str, Any]:
    status, raw = dispatch(config, "rebrew.analyse", json.dumps(_analyse_request()).encode())
    reply: dict[str, Any] = json.loads(raw)
    assert status == 200, reply
    return reply


def _store_name(metadata_dir: Path, name: str) -> None:
    """Write *name* into the record as an older engine did, past today's identity writer."""
    path = metadata_dir / METADATA_FILENAME
    document = load_metadata_for_write(path, "metadata")
    document[KEY]["name"] = name
    metadata_store(path).write(document, "metadata")
    clear_metadata_cache()


def _sqlite_project(root: Path) -> tuple[WorkerConfig, Path, Any]:
    """An analysed project moved to SQLite, whose 0x401010 record has comparison history."""
    filestore, workspace = _worker_dirs(root)
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    project = Path(_analyse(config)["project"])
    cfg = load_config(project, target="mini")
    migrate_metadata(cfg, "sqlite", expected_digest=migration_input_digest(cfg, "sqlite"))
    cfg = load_config(project, target="mini")
    assert cfg.metadata_backend == "sqlite"
    import_status_history(cfg.metadata_dir, MODULE, [{"va": VA, **HISTORY}])
    return config, project, cfg


def _unbound_free_text(root: Path) -> tuple[WorkerConfig, Path]:
    """Before production's re-analysis: the record names free text and has no source."""
    config, project, cfg = _sqlite_project(root)
    (cfg.reversed_dir / f"{PLACEHOLDER}.c").unlink()
    clear_identity_fields(cfg.metadata_dir, VA, MODULE, "file", "symbol", "kind")
    _store_name(cfg.metadata_dir, FREE_TEXT)
    return config, project


def _disagreeing_stub(root: Path) -> tuple[WorkerConfig, Path]:
    """After production's re-analysis: the stub defines the placeholder, the record names free text."""
    config, project, cfg = _sqlite_project(root)
    _store_name(cfg.metadata_dir, FREE_TEXT)
    return config, project


def _record(project: Path) -> dict[str, Any]:
    clear_metadata_cache()
    cfg = load_config(project, target="mini")
    return dict(load_metadata(cfg.metadata_dir)[(MODULE, VA)])


def _stub_name(project: Path) -> str:
    cfg = load_config(project, target="mini")
    text = (cfg.reversed_dir / f"{PLACEHOLDER}.c").read_text()
    (line,) = [line for line in text.splitlines() if line.startswith("void ")]
    return line.removeprefix("void ").split("(")[0]


def _assert_consistent(project: Path) -> dict[str, Any]:
    record = _record(project)
    assert _stub_name(project) == PLACEHOLDER
    assert (record["file"], record["symbol"], record["name"], record["kind"]) == (
        f"src/mini/{PLACEHOLDER}.c",
        f"_{PLACEHOLDER}",
        PLACEHOLDER,
        "STUB",
    )
    # The earlier text is kept in the note, and the comparison history stays.
    assert record["note"] == f"earlier name: {FREE_TEXT}"
    assert [dict(event) for event in record["status_history"]] == [HISTORY]
    return record


def test_reanalysis_leaves_a_record_its_stub_agrees_with(tmp_path: Path) -> None:
    config, project = _unbound_free_text(tmp_path)
    _analyse(config)
    _assert_consistent(project)


def test_reanalysis_keeps_an_identifier_name_in_the_stub(tmp_path: Path) -> None:
    config, project, cfg = _sqlite_project(tmp_path)
    (cfg.reversed_dir / f"{PLACEHOLDER}.c").unlink()
    clear_identity_fields(cfg.metadata_dir, VA, MODULE, "file", "symbol", "kind")
    _store_name(cfg.metadata_dir, "lib_cont")
    _analyse(config)
    record = _record(project)
    assert _stub_name(project) == "lib_cont"
    assert (record["name"], record["symbol"]) == ("lib_cont", "_lib_cont")
    assert "note" not in record


def test_reanalysis_repairs_a_record_its_stub_disagrees_with(tmp_path: Path) -> None:
    config, project = _disagreeing_stub(tmp_path)
    _analyse(config)
    repaired = _assert_consistent(project)
    # A second run finds nothing to repair and changes nothing.
    _analyse(config)
    assert _record(project) == repaired


@pytest.mark.parametrize("op", ["rebrew.data_list", "rebrew.identify_library"])
def test_project_reads_skip_a_disagreeing_record(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, op: str
) -> None:
    config, project = _disagreeing_stub(tmp_path)
    with caplog.at_level(logging.WARNING):
        status, raw = dispatch(config, op, json.dumps({"project_dir": str(project)}).encode())
    assert status == 200, json.loads(raw)
    # The reply says which records it left out, by key, never by name.
    assert json.loads(raw)["skipped_records"] == {"count": 1, "keys": [KEY], "truncated": False}
    if op == "rebrew.identify_library":
        # Logged in process: once, by the record's key, never its text.
        skipped = [r.getMessage() for r in caplog.records if KEY in r.getMessage()]
        assert len(skipped) == 1
        assert FREE_TEXT not in caplog.text
    # The read wrote nothing over the skipped record.
    assert _record(project)["name"] == FREE_TEXT


def test_doctor_reports_a_disagreeing_record(tmp_path: Path) -> None:
    from rebrew.doctor import check_function_bindings

    _, project = _disagreeing_stub(tmp_path)
    result = check_function_bindings(load_config(project, target="mini"))
    assert result.status == "warn"
    assert KEY in result.message and FREE_TEXT not in result.message


def test_a_write_touching_a_disagreeing_record_refuses_as_invalid_project(tmp_path: Path) -> None:
    from test_ops import KEY as BINARY_KEY
    from test_ops import SHA256, _store

    config, project = _disagreeing_stub(tmp_path)
    assert config.filestore is not None
    files = []
    for path in sorted(project.rglob("*")):
        relative = path.relative_to(project).as_posix()
        if not path.is_file() or relative.split("/")[0] in {".rebrew", "original"}:
            continue
        if path.suffix == ".toml" and path.name != "rebrew-project.toml":
            continue  # the TOML documents the migration to SQLite retained
        digest, key = _store(config.filestore, path.read_bytes())
        files.append({"path": relative, "digest": digest, "size": path.stat().st_size, "key": key})
    request = {
        "files": files,
        "rebrew_target": "mini",
        "sha256": SHA256,
        "binary_key": BINARY_KEY,
        "operation": "rename",
        "kind": "function",
        "old_name": f"0x{VA:x}",
        "new_name": "renamed",
    }
    status, raw = dispatch(config, "rebrew.retained_source_operation", json.dumps(request).encode())
    assert (status, json.loads(raw)) == (
        400,
        {
            "error": "invalid-project-config",
            "status": 400,
            "detail": BINDING_CONFLICT_DETAIL,
        },
    )
    assert _record(project)["name"] == FREE_TEXT


@pytest.mark.parametrize("op", ["rebrew.data_list", "rebrew.identify_library"])
def test_a_clean_projects_read_names_no_skipped_record(tmp_path: Path, op: str) -> None:
    config, project, _cfg = _sqlite_project(tmp_path)
    status, raw = dispatch(config, op, json.dumps({"project_dir": str(project)}).encode())
    assert status == 200, json.loads(raw)
    assert "skipped_records" not in json.loads(raw)


def test_skipped_records_past_the_bound_keep_their_count() -> None:
    from rebrew.ops import MAX_SKIPPED_RECORD_KEYS, _skipped_records

    skipped = {(MODULE, 0x401000 + 16 * i) for i in range(MAX_SKIPPED_RECORD_KEYS + 3)}
    reply = _skipped_records(skipped)
    assert reply["count"] == MAX_SKIPPED_RECORD_KEYS + 3 and reply["truncated"] is True
    assert (
        reply["keys"]
        == sorted(f"{MODULE}.0x{va:08x}" for _m, va in skipped)[:MAX_SKIPPED_RECORD_KEYS]
    )
    assert _skipped_records({(MODULE, VA)}) == {"count": 1, "keys": [KEY], "truncated": False}
