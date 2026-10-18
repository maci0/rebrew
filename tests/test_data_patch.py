"""Atomic non-verdict patches, strict previews and reviewed-input rejection."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from rebrew.metadata.data import (
    get_data_entry,
    patch_data_fields_batch,
    set_data_fields_batch,
)


def _update(va: int = 0x401000, **fields: Any) -> dict[str, Any]:
    return {"module": "GAME", "va": va, "fields": fields}


def _measured(directory: Path) -> Path:
    set_data_fields_batch(
        directory,
        [
            {
                **_update(name="g", size=4, status="EXACT"),
                "updated_by": "verify",
                "verification": {"status": "EXACT", "writer": "verify", "input_hash": "a" * 64},
            },
        ],
    )
    return directory / "rebrew-data.toml"


class TestDataPatch:
    def test_preview_creates_no_directory_or_lock(self, tmp_path: Path) -> None:
        directory = tmp_path / "absent"
        report = patch_data_fields_batch(directory, [_update(size=4, name="g")], dry_run=True)
        assert report["changed"] == 1
        assert len(report["input_digest"]) == 64
        assert not directory.exists()

    def test_multifield_multirow_has_one_publication(self, tmp_path: Path) -> None:
        from rebrew.utils import atomic_write_locked

        updates = [_update(name="g"), _update(size=4), _update(0x402000, type="int")]
        preview = patch_data_fields_batch(tmp_path, updates, dry_run=True)
        with patch("rebrew.metadata.files.atomic_write_locked", wraps=atomic_write_locked) as write:
            result = patch_data_fields_batch(
                tmp_path, updates, expected_digest=preview["input_digest"]
            )
        assert result["changed"] == 2
        assert write.call_count == 1
        row = get_data_entry(tmp_path, 0x401000, "GAME")
        assert row["name"] == "g" and row["size"] == 4
        assert "status" not in row
        assert (tmp_path / "rebrew-data.toml").stat().st_mode & 0o777 == 0o444

    @pytest.mark.parametrize(
        "updates",
        [
            [_update(note="valid"), _update(size=-1)],
            [_update(size=4), _update(size=8)],
            [_update(status="EXACT")],
            [_update(verification={"status": "EXACT"})],
            [{**_update(note="valid"), "updated_by": "verify"}],
            [_update(origins={})],
        ],
    )
    @pytest.mark.parametrize("dry_run", [True, False])
    def test_rejected_batch_preserves_all_store_bytes(
        self, tmp_path: Path, updates: list[dict[str, Any]], dry_run: bool
    ) -> None:
        path = _measured(tmp_path)
        before = path.read_bytes(), path.stat()
        with pytest.raises(ValueError):
            patch_data_fields_batch(tmp_path, updates, dry_run=dry_run)
        assert path.read_bytes() == before[0]
        assert path.stat() == before[1]

    def test_stale_digest_refuses_every_field(self, tmp_path: Path) -> None:
        path = _measured(tmp_path)
        preview = patch_data_fields_batch(tmp_path, [_update(type="int")], dry_run=True)
        patch_data_fields_batch(tmp_path, [_update(note="other writer")])
        before = path.read_bytes(), path.stat()
        with pytest.raises(ValueError, match="changed since preview"):
            patch_data_fields_batch(
                tmp_path, [_update(type="int")], expected_digest=preview["input_digest"]
            )
        assert (path.read_bytes(), path.stat()) == before

    def test_rechecks_digest_under_lock(self, tmp_path: Path) -> None:
        from collections.abc import Iterator
        from contextlib import contextmanager

        from rebrew.metadata.storage import metadata_write_lock

        path = _measured(tmp_path)
        preview = patch_data_fields_batch(tmp_path, [_update(note="reviewed")], dry_run=True)

        @contextmanager
        def racing_lock(directory: Path, filename: str) -> Iterator[None]:
            with metadata_write_lock(directory, filename):
                path.chmod(0o644)
                path.write_text(path.read_text() + "\n# concurrent edit\n")
                path.chmod(0o444)
                yield

        with (
            patch("rebrew.metadata.data.metadata_write_lock", racing_lock),
            pytest.raises(ValueError, match="changed since preview"),
        ):
            patch_data_fields_batch(
                tmp_path, [_update(note="reviewed")], expected_digest=preview["input_digest"]
            )
        assert "reviewed" not in path.read_text()
        assert "concurrent edit" in path.read_text()

    @pytest.mark.parametrize(
        "field,value",
        [
            ("size", 8),
            ("link_symbol", "_other"),
            ("storage_kind", "literal"),
            ("file", "src/other.c"),
            ("backing", "other"),
            ("type", "long"),
        ],
    )
    def test_identity_edits_invalidate_verdict_but_preserve_evidence(
        self, tmp_path: Path, field: str, value: Any
    ) -> None:
        _measured(tmp_path)
        evidence = get_data_entry(tmp_path, 0x401000, "GAME")["verification"]
        patch_data_fields_batch(tmp_path, [_update(**{field: value})])
        row = get_data_entry(tmp_path, 0x401000, "GAME")
        assert "status" not in row
        assert row["verification"] == evidence

    def test_note_and_noop_preserve_verdict(self, tmp_path: Path) -> None:
        path = _measured(tmp_path)
        patch_data_fields_batch(tmp_path, [_update(size=4, note="checked")])
        assert get_data_entry(tmp_path, 0x401000, "GAME")["status"] == "EXACT"
        before = path.read_bytes(), path.stat()
        report = patch_data_fields_batch(tmp_path, [_update(size=4, note="checked")])
        assert report["changed"] == 0
        assert (path.read_bytes(), path.stat()) == before

    def test_malformed_store_preview_creates_no_sidecar(self, tmp_path: Path) -> None:
        path = tmp_path / "rebrew-data.toml"
        path.write_text("broken [")
        with pytest.raises(ValueError):
            patch_data_fields_batch(tmp_path, [_update(note="x")], dry_run=True)
        assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]
