"""Status history survives dashboard restarts and explicit snapshot retirement."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from rebrew.metadata.functions import (
    get_entry,
    import_status_history,
    load_status_history,
    set_fields,
    update_source_status,
    update_statuses_batch,
)


def _event(va: int = 0x401000) -> dict:
    return {
        "va": va,
        "old_status": "STUB",
        "new_status": "EXACT",
        "changed_at": "2026-10-10T12:00:00+00:00",
        "updated_by": "verify",
    }


class TestStatusHistory:
    def test_comparison_and_transition_are_one_durable_write(self, tmp_path: Path) -> None:
        now = datetime(2026, 10, 15, tzinfo=UTC)
        update_source_status(tmp_path, "NEAR_MATCHING", "GAME", 0x401000, now=now)
        update_source_status(tmp_path, "EXACT", "GAME", 0x401000, updated_by="test", now=now)
        history = load_status_history(tmp_path, "GAME")
        assert history == [
            {
                **_event(),
                "old_status": "NEAR_MATCHING",
                "updated_by": "test",
                "changed_at": now.isoformat(),
            }
        ]
        before = (tmp_path / "rebrew-functions.toml").read_bytes()
        assert not update_source_status(tmp_path, "EXACT", "GAME", 0x401000)
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == before

    def test_refused_promotion_and_failed_batch_leave_no_events(self, tmp_path: Path) -> None:
        update_source_status(tmp_path, "SKIP", "GAME", 0x401000)
        assert not update_source_status(tmp_path, "EXACT", "GAME", 0x401000)
        before = (tmp_path / "rebrew-functions.toml").read_bytes()
        with pytest.raises(ValueError, match="unknown STATUS"):
            update_statuses_batch(
                tmp_path,
                [
                    {"module": "GAME", "va": 0x401000, "new_status": "EXACT", "force": True},
                    {"module": "GAME", "va": 0x401100, "new_status": "TYPO"},
                ],
            )
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == before
        assert load_status_history(tmp_path, "GAME") == []

    def test_preview_is_read_only_and_import_is_idempotent(self, tmp_path: Path) -> None:
        assert import_status_history(tmp_path, "GAME", [_event()], dry_run=True) == 1
        assert list(tmp_path.iterdir()) == []
        assert import_status_history(tmp_path, "GAME", [_event()]) == 1
        assert import_status_history(tmp_path, "GAME", [_event()]) == 0
        assert get_entry(tmp_path, 0x401000, "GAME").keys() == {"status_history"}
        assert load_status_history(tmp_path, "OTHER") == []
        assert load_status_history(tmp_path, "GAME") == [_event()]

    def test_invalid_import_is_all_or_nothing(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            import_status_history(
                tmp_path, "GAME", [_event(), {**_event(0x401100), "new_status": "TYPO"}]
            )
        assert list(tmp_path.iterdir()) == []

    def test_generic_setters_cannot_forge_history(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="import_status_history"):
            set_fields(tmp_path, 0x401000, {"status_history": [_event()]}, "GAME")

    def test_empty_historical_status_is_normalized_without_a_verdict(self, tmp_path: Path) -> None:
        import_status_history(tmp_path, "GAME", [{**_event(), "old_status": ""}])
        assert load_status_history(tmp_path, "GAME")[0]["old_status"] == "UNKNOWN"
        assert "status" not in get_entry(tmp_path, 0x401000, "GAME")

    def test_retired_history_survives_automatic_orphan_pruning(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.orphans import split_prunable

        import_status_history(tmp_path, "GAME", [_event()])
        cfg = SimpleNamespace(metadata_dir=tmp_path)
        orphans = [("GAME", 0x401000, "rebrew-functions.toml")]
        assert split_prunable(cfg, orphans, []) == []
        assert split_prunable(cfg, orphans, [], include_matched=True) == []

    def test_automatic_single_entry_deletion_preserves_history(self, tmp_path: Path) -> None:
        from rebrew.metadata.functions import delete_metadata_entry

        import_status_history(tmp_path, "GAME", [_event()])
        assert not delete_metadata_entry(tmp_path, 0x401000, "GAME")
        assert load_status_history(tmp_path, "GAME") == [_event()]
