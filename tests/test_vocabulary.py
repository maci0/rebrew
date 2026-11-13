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
