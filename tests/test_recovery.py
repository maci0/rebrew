"""Backup/restore for irreplaceable state: GA log and SQLite metadata."""

from __future__ import annotations

import json
from types import SimpleNamespace
lazy from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.config import load_config
from rebrew.matcher.solutions import backup_ga_runs, restore_ga_runs
from rebrew.metadata.sqlite import (
    DATABASE_FILENAME,
    MetadataStorageError,
    backup_metadata_database,
    restore_metadata_database,
)
from rebrew.metadata.storage import metadata_store
from rebrew.metadata_transfer import migrate_metadata


def _seed_log(root: Path) -> Path:
    (root / ".rebrew").mkdir(parents=True, exist_ok=True)
    log = root / ".rebrew" / "ga_runs.jsonl"
    log.write_text(
        json.dumps(
            {
                "ts": "2026-01-01T00:00:00+00:00",
                "target": "SERVER",
                "va": "0x1000",
                "symbol": "_malloc",
                "cflags": "/O2",
                "size": 64,
                "matched": True,
                "score": 0.0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return log


class TestGaRunsBackup:
    def test_round_trip(self, tmp_path: Path) -> None:
        _seed_log(tmp_path)
        handed_off = tmp_path / "off-tree"
        dest = backup_ga_runs(tmp_path, handed_off)
        assert dest.read_bytes() == (tmp_path / ".rebrew" / "ga_runs.jsonl").read_bytes()
        assert dest.stat().st_mode & 0o777 == 0o644
        # Simulate losing the working tree.
        (tmp_path / ".rebrew" / "ga_runs.jsonl").unlink()
        restored = restore_ga_runs(dest, tmp_path)
        assert restored.read_bytes() == dest.read_bytes()

    def test_missing_log_raises_not_empty_backup(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            backup_ga_runs(tmp_path, tmp_path / "off-tree")

    def test_restore_preserves_current_log(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path)
        dest = backup_ga_runs(tmp_path, tmp_path / "off-tree")
        log.write_text('{"ts": "new", "matched": false}\n', encoding="utf-8")
        restore_ga_runs(dest, tmp_path)
        assert (tmp_path / ".rebrew" / "ga_runs.jsonl.before-restore").read_text(
            encoding="utf-8"
        ) == '{"ts": "new", "matched": false}\n'

    def test_corrupt_backup_leaves_log_alone(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path)
        bad = tmp_path / "bad.jsonl"
        bad.write_text("not json\n", encoding="utf-8")
        before = log.read_bytes()
        with pytest.raises(ValueError, match="corrupt"):
            restore_ga_runs(bad, tmp_path)
        assert log.read_bytes() == before

    def test_cli_backup_and_restore(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_log(tmp_path)
        monkeypatch.setattr(
            "rebrew.solutions_db.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                root=tmp_path, target_name="SERVER"
            ),
        )
        handed_off = tmp_path / "off-tree"
        result = CliRunner().invoke(app, ["match", "solutions", "--backup", str(handed_off)])
        assert result.exit_code == 0, result.output
        assert (handed_off / "ga_runs.backup.jsonl").is_file()
        (tmp_path / ".rebrew" / "ga_runs.jsonl").unlink()
        result = CliRunner().invoke(
            app, ["match", "solutions", "--restore", str(handed_off / "ga_runs.backup.jsonl")]
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / ".rebrew" / "ga_runs.jsonl").is_file()


def _project(root: Path, backend: str = "sqlite") -> SimpleNamespace:
    (root / "src").mkdir(exist_ok=True)
    (root / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "game"\nshared_dir = ""\n'
        '[targets.game]\nbinary = "game.exe"\nreversed_dir = "src"\nmodule = "GAME"\n'
        f'[metadata]\nbackend = "{backend}"\n'
    )
    return load_config(root)


class TestSqliteBackup:
    def test_round_trip_and_verify(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2, "GAME.0x1000": {"size": 4}}, "test")
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        assert dest.stat().st_mode & 0o777 == 0o444
        store.write({"format": 2, "GAME.0x1000": {"size": 8}}, "test")
        restore_metadata_database(dest, tmp_path)
        assert store.read("test")["GAME.0x1000"]["size"] == 4
        assert (tmp_path / (DATABASE_FILENAME + ".before-restore")).is_file()

    def test_missing_database_raises(self, tmp_path: Path) -> None:
        _project(tmp_path)
        with pytest.raises(FileNotFoundError):
            backup_metadata_database(tmp_path, tmp_path / "off-tree")

    def test_corrupt_backup_rejected(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2}, "test")
        bad = tmp_path / "bad.sqlite3"
        bad.write_bytes(b"not a database")
        with pytest.raises(MetadataStorageError):
            restore_metadata_database(bad, tmp_path)
        assert store.read("test") == {"format": 2}


class TestTransferSnapshot:
    def test_sqlite_destination_snapshotted_before_overwrite(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path, "toml")
        from rebrew.metadata.functions import update_field

        update_field(tmp_path, 0x1000, "SIZE", 4, "GAME")
        migrate_metadata(cfg, "sqlite")
        # Inactive sqlite destination now holds v1; edit the sqlite copy, so
        # the next transfer back to sqlite overwrites a different destination.
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        doc = store.read("test")
        doc["GAME.0x00001000"]["size"] = 7
        store.write(doc, "test")
        migrate_metadata(load_config(tmp_path), "toml")
        migrate_metadata(load_config(tmp_path), "sqlite")
        snapshot = tmp_path / ".rebrew" / (DATABASE_FILENAME + ".before-transfer")
        assert snapshot.is_file()
        # The snapshot holds the pre-transfer destination, not the new content.
        import sqlite3

        con = sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True)
        try:
            content = con.execute(
                "SELECT content FROM metadata_documents WHERE path = 'rebrew-functions.toml'"
            ).fetchone()[0]
        finally:
            con.close()
        assert "size = 7" in content  # pre-transfer destination held size 7, not 4
        assert "size = 4" not in content
