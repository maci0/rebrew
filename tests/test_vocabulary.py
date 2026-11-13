"""rebrew.vocabulary publishes the names a dispatch client matches instead of copying."""

from __future__ import annotations

lazy from pathlib import Path

from test_metadata_sets import _call
from test_ops import _worker_dirs

from rebrew.ops import WorkerConfig, dispatch
from rebrew.workspace.status import KNOWN_STATUSES, canonical_status


def _config(directory: Path) -> WorkerConfig:
    filestore, workspace = _worker_dirs(directory)
    return WorkerConfig(filestore.resolve(), workspace.resolve())


def test_the_status_table_is_the_one_rebrew_writes(tmp_path: Path) -> None:
    status, reply = _call(_config(tmp_path), "rebrew.vocabulary", {})
    assert status == 200, reply
    statuses = reply["statuses"]
    assert statuses["known"] == sorted(KNOWN_STATUSES)
    assert statuses["matched"] == ["EXACT", "RELOC"]
    # PROVEN is earned work, not a byte match; MATCHED is no stored status.
    assert statuses["earned"] == ["EXACT", "RELOC", "PROVEN"]
    assert "MATCHED" not in statuses["known"]
    assert "COMPILE_ERROR" in statuses["infrastructure"]
    assert statuses["aliases"] == [{"alias": "NEAR_MATCH", "canonical": "NEAR_MATCHING"}]
    for item in statuses["aliases"]:
        assert canonical_status(f" {item['alias'].lower()} ") == item["canonical"]


def test_the_request_takes_no_fields(tmp_path: Path) -> None:
    status, _body = dispatch(_config(tmp_path), "rebrew.vocabulary", b'{"x": 1}')
    assert status == 400


def test_cache_files_name_every_file_the_verify_cache_writes(tmp_path: Path) -> None:
    from test_target_result_cache import _cfg, _rows

    from rebrew.verify_cache import cache_path_for, load_verify_cache, save_verify_cache

    status, reply = _call(_config(tmp_path / "worker"), "rebrew.vocabulary", {})
    assert status == 200, reply
    project = tmp_path / "project"
    project.mkdir()
    cfg = _cfg(project, "Gold")
    entries, rows = _rows(cfg, 0x1000)
    before = {path for path in project.rglob("*") if path.is_file()}
    save_verify_cache(cache_path_for(cfg), cfg, rows, entries)
    assert load_verify_cache(cache_path_for(cfg), cfg) is not None
    written = {path.name for path in project.rglob("*") if path.is_file()} - {
        path.name for path in before
    }
    assert "verify_cache.toml" in written
    assert written <= set(reply["cache_files"])


def test_placeholder_name_is_the_rule_rebrew_applies(tmp_path: Path) -> None:
    import re

    from rebrew.workspace.names import is_placeholder_name

    status, reply = _call(_config(tmp_path), "rebrew.vocabulary", {})
    assert status == 200, reply
    rule = re.compile(reply["placeholder_name"])
    for name in ("", "FUN_00401000", "sub_401000", "fcn_00401000", "real_name", "sub_menu"):
        assert (rule.fullmatch(name) is not None) == is_placeholder_name(name), name
    assert rule.fullmatch("FUN_00401000") and not rule.fullmatch("real_name")
