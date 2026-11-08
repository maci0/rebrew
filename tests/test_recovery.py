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
    backup_metadata_toml,
    restore_metadata_database,
    restore_metadata_toml,
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

    def test_restore_twice_preserves_current_log(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path)
        dest = backup_ga_runs(tmp_path, tmp_path / "off-tree")
        log.write_text('{"ts": "new", "matched": false}\n', encoding="utf-8")
        restore_ga_runs(dest, tmp_path)
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

    def test_restore_twice_keeps_first_preserved_copy(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2, "GAME.0x1000": {"size": 4}}, "test")
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        store.write({"format": 2, "GAME.0x1000": {"size": 8}}, "test")
        restore_metadata_database(dest, tmp_path)
        restore_metadata_database(dest, tmp_path)
        assert store.read("test")["GAME.0x1000"]["size"] == 4
        import sqlite3

        preserved = tmp_path / (DATABASE_FILENAME + ".before-restore")
        con = sqlite3.connect(f"file:{preserved}?mode=ro", uri=True)
        try:
            content = con.execute(
                "SELECT content FROM metadata_documents WHERE path = 'rebrew-functions.toml'"
            ).fetchone()[0]
        finally:
            con.close()
        assert "size = 8" in content

    def test_backup_carries_uploads_ledger_owner_only(self, tmp_path: Path) -> None:
        _project(tmp_path)
        _store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        _store.write({"format": 2}, "test")
        _ledger = _write_uploads_ledger(tmp_path)
        _dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        _backed = tmp_path / "off-tree" / ".rebrew" / "decompme-uploads.json"
        assert _backed.read_bytes() == _ledger.read_bytes()
        assert _backed.stat().st_mode & 0o777 == 0o600
        _ledger.unlink()
        restore_metadata_database(_dest, tmp_path)
        _restored = tmp_path / ".rebrew" / "decompme-uploads.json"
        assert _restored.read_bytes() == _backed.read_bytes()
        assert _restored.stat().st_mode & 0o777 == 0o600

    def test_sqlite_backup_roundtrips_verify_cache_and_ghidra_state(self, tmp_path: Path) -> None:
        # SQLite backup carries the verify cache/baseline (root and
        # per-target) and the Ghidra sync state, and restore brings
        # them back: a hand-rolled restore list once dropped them.
        _project(tmp_path)
        _store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        _store.write({"format": 2}, "test")
        _cache = tmp_path / ".rebrew" / "verify_cache.toml"
        _baseline = tmp_path / ".rebrew" / "verify_baseline.toml"
        _tgt_cache = tmp_path / ".rebrew" / "targets" / "abc123" / "verify_cache.toml"
        _tgt_baseline = tmp_path / ".rebrew" / "targets" / "abc123" / "verify_baseline.toml"
        _ghidra = tmp_path / ".rebrew" / "ghidra_sync_state.json"
        _tgt_cache.parent.mkdir(parents=True, exist_ok=True)
        _cache.write_text("entries = {}\n", encoding="utf-8")
        _baseline.write_text("target = 'game'\n", encoding="utf-8")
        _tgt_cache.write_text("entries = {}\n", encoding="utf-8")
        _tgt_baseline.write_text("target = 'game'\n", encoding="utf-8")
        _ghidra.write_text('{"a": "b"}\n', encoding="utf-8")
        for p in (_cache, _baseline, _tgt_cache, _tgt_baseline, _ghidra):
            p.chmod(0o444)
        _dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        for p in (_cache, _baseline, _tgt_cache, _tgt_baseline, _ghidra):
            p.unlink()
        restore_metadata_database(_dest, tmp_path)
        assert _cache.read_text(encoding="utf-8") == "entries = {}\n"
        assert _baseline.read_text(encoding="utf-8") == "target = 'game'\n"
        assert _tgt_cache.read_text(encoding="utf-8") == "entries = {}\n"
        assert _tgt_baseline.read_text(encoding="utf-8") == "target = 'game'\n"
        assert _ghidra.read_text(encoding="utf-8") == '{"a": "b"}\n'

    def test_restore_clears_stale_journal_and_verify_sidecar(self, tmp_path: Path) -> None:
        # A killed writer's rollback journal belongs to the pre-restore
        # database; left beside the restored file SQLite would replay it
        # against the new page image.  The verify-cache JSON sidecar is
        # likewise stale once the TOML is replaced.
        _project(tmp_path)
        _store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        _store.write({"format": 2, "GAME.0x1000": {"size": 4}}, "test")
        _cache = tmp_path / ".rebrew" / "verify_cache.toml"
        _cache.parent.mkdir(parents=True, exist_ok=True)
        _cache.write_text("entries = {}\n", encoding="utf-8")
        _dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        _journal = tmp_path / (DATABASE_FILENAME + "-journal")
        _journal.write_bytes(b"stale")
        _sidecar = tmp_path / ".rebrew" / "verify_cache.json"
        _sidecar.write_text('{"version": 1, "fingerprint": [1,2,3,4], "document": {}}')
        _store.write({"format": 2, "GAME.0x1000": {"size": 8}}, "test")
        _journal.write_bytes(b"stale2")
        restore_metadata_database(_dest, tmp_path)
        assert not _journal.exists()
        assert not _sidecar.exists()
        assert _store.read("test")["GAME.0x1000"]["size"] == 4

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


def _write_extra_durable(root: Path) -> None:
    """GA log + a BinSync baseline, the gitignored durable state."""
    (root / ".rebrew" / "sync").mkdir(parents=True, exist_ok=True)
    (root / ".rebrew" / "ga_runs.jsonl").write_text('{"ts":"r","matched":true}\n', encoding="utf-8")
    (root / ".rebrew" / "sync" / "baseline.toml").write_text(
        "format = 1\nrecords = {}\n", encoding="utf-8"
    )
    (root / ".rebrew" / "decompme-uploads.json").write_text(
        json.dumps({"digest1": {"slug": "abc", "claim_token": "tok", "api": "x", "at": "123"}}),
        encoding="utf-8",
    )


def _write_uploads_ledger(root: Path) -> Path:
    """The decomp.me claim-token ledger, as record_upload writes it: one JSON object."""
    path = root / ".rebrew" / "decompme-uploads.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "abc": {
                    "slug": "xyz",
                    "claim_token": "secret-token-123",
                    "api": "https://decomp.me",
                    "at": "123.0",
                }
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


class TestTomlBackup:
    def test_round_trip_covers_all_stores_and_dropins(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        dropins = tmp_path / "rebrew-functions.d"
        dropins.mkdir()
        (dropins / "game.toml").write_text("format=3\n", encoding="utf-8")
        (tmp_path / "rebrew-data.toml").write_text("format=2\n", encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        assert (bundle / "rebrew-functions.toml").is_file()
        assert (bundle / "rebrew-functions.d" / "game.toml").is_file()
        dest = tmp_path / "rebrew-functions.toml"
        dest.chmod(0o644)
        dest.write_text("format=3\nchanged=1\n", encoding="utf-8")
        installed = restore_metadata_toml(bundle, tmp_path)
        assert dest in installed
        assert dest.read_text(encoding="utf-8") == "format=3\n"
        assert (
            dest.with_name(dest.name + ".before-restore").read_text(encoding="utf-8")
            == "format=3\nchanged=1\n"
        )

    def test_restore_twice_keeps_first_preserved_copy(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\norig=1\n", encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        dest = tmp_path / "rebrew-functions.toml"
        dest.chmod(0o644)
        dest.write_text("format=3\norig=2\n", encoding="utf-8")
        restore_metadata_toml(bundle, tmp_path)
        restore_metadata_toml(bundle, tmp_path)
        assert dest.read_text(encoding="utf-8") == "format=3\norig=1\n"
        assert (
            dest.with_name(dest.name + ".before-restore").read_text(encoding="utf-8")
            == "format=3\norig=2\n"
        )

    def test_missing_stores_raise_not_empty_bundle(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            backup_metadata_toml(tmp_path, tmp_path / "off-tree")

    def test_backup_carries_ga_log_and_sync_baselines(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        _write_extra_durable(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        assert (bundle / ".rebrew" / "ga_runs.jsonl").read_text() == ('{"ts":"r","matched":true}\n')
        assert (bundle / ".rebrew" / "sync" / "baseline.toml").is_file()
        uploads = bundle / ".rebrew" / "decompme-uploads.json"
        assert json.loads(uploads.read_text())["digest1"]["claim_token"] == "tok"  # noqa: S105
        assert uploads.stat().st_mode & 0o777 == 0o600

    def test_restore_roundtrips_ga_log_and_baselines(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        _write_extra_durable(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        (tmp_path / ".rebrew" / "ga_runs.jsonl").unlink()
        (tmp_path / ".rebrew" / "sync" / "baseline.toml").unlink()
        (tmp_path / ".rebrew" / "decompme-uploads.json").unlink()
        installed = restore_metadata_toml(bundle, tmp_path)
        assert tmp_path / ".rebrew" / "ga_runs.jsonl" in installed
        assert (tmp_path / ".rebrew" / "ga_runs.jsonl").read_text() == (
            '{"ts":"r","matched":true}\n'
        )
        assert (tmp_path / ".rebrew" / "sync" / "baseline.toml").read_text() == (
            "format = 1\nrecords = {}\n"
        )
        uploads = tmp_path / ".rebrew" / "decompme-uploads.json"
        assert json.loads(uploads.read_text())["digest1"]["claim_token"] == "tok"  # noqa: S105
        assert uploads.stat().st_mode & 0o777 == 0o600

    def test_restore_roundtrips_uploads_ledger_owner_only(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        ledger = _write_uploads_ledger(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        backed = bundle / ".rebrew" / "decompme-uploads.json"
        assert backed.read_bytes() == ledger.read_bytes()
        assert backed.stat().st_mode & 0o777 == 0o600
        ledger.unlink()
        installed = restore_metadata_toml(bundle, tmp_path)
        assert tmp_path / ".rebrew" / "decompme-uploads.json" in installed
        restored = tmp_path / ".rebrew" / "decompme-uploads.json"
        assert restored.read_bytes() == backed.read_bytes()
        assert restored.stat().st_mode & 0o777 == 0o600

    def test_restore_rejects_corrupt_uploads_ledger_and_leaves_stores_alone(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        _write_uploads_ledger(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        bad = bundle / ".rebrew" / "decompme-uploads.json"
        bad.chmod(0o644)
        bad.write_text('{"abc": {"slug": "xyz"}\n', encoding="utf-8")
        with pytest.raises(MetadataStorageError, match="corrupt backup"):
            restore_metadata_toml(bundle, tmp_path)
        assert (tmp_path / "rebrew-functions.toml").read_text(encoding="utf-8") == "format=3\n"

    def test_restore_rejects_corrupt_ga_log_and_leaves_stores_alone(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        _write_extra_durable(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        ga = bundle / ".rebrew" / "ga_runs.jsonl"
        ga.chmod(0o644)
        ga.write_text("not json\n", encoding="utf-8")
        with pytest.raises(MetadataStorageError, match="corrupt backup line 1"):
            restore_metadata_toml(bundle, tmp_path)
        assert (tmp_path / ".rebrew" / "ga_runs.jsonl").read_text() == (
            '{"ts":"r","matched":true}\n'
        )

    def test_restore_rejects_corrupt_uploads_and_leaves_stores_alone(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        _write_extra_durable(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        uploads = bundle / ".rebrew" / "decompme-uploads.json"
        uploads.chmod(0o644)
        uploads.write_text('{"a": 5}', encoding="utf-8")
        with pytest.raises(MetadataStorageError, match="corrupt backup"):
            restore_metadata_toml(bundle, tmp_path)
        assert (
            json.loads((tmp_path / ".rebrew" / "decompme-uploads.json").read_text())["digest1"][
                "claim_token"
            ]
            == "tok"  # noqa: S105
        )

    def test_sqlite_backup_roundtrips_uploads(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2}, "test")
        _write_extra_durable(tmp_path)
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        uploads = tmp_path / ".rebrew" / "decompme-uploads.json"
        uploads.unlink()
        restore_metadata_database(dest, tmp_path)
        ledger = json.loads(uploads.read_text())
        assert ledger["digest1"]["claim_token"] == "tok"  # noqa: S105
        assert uploads.stat().st_mode & 0o777 == 0o600

    def test_corrupt_bundle_leaves_stores_alone(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        bad = bundle / "rebrew-functions.toml"
        bad.chmod(0o644)
        bad.write_text("not toml [[[\n", encoding="utf-8")
        with pytest.raises(MetadataStorageError):
            restore_metadata_toml(bundle, tmp_path)
        assert (tmp_path / "rebrew-functions.toml").read_text(encoding="utf-8") == "format=3\n"
