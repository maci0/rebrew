"""Backup/restore for irreplaceable state: GA log and SQLite metadata."""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace
lazy from collections.abc import Iterator
lazy from pathlib import Path
lazy from typing import Any

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
    verify_backup_manifest,
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

    def test_second_restore_keeps_the_first_displaced_log(self, tmp_path: Path) -> None:
        # Restoring a different backup must not overwrite the sidecar: it is
        # the only copy of what the first restore displaced.
        log = _seed_log(tmp_path)
        first = backup_ga_runs(tmp_path, tmp_path / "first")
        log.write_text('{"ts": "second", "matched": true}\n', encoding="utf-8")
        second = backup_ga_runs(tmp_path, tmp_path / "second")
        log.write_text('{"ts": "live", "matched": false}\n', encoding="utf-8")
        restore_ga_runs(first, tmp_path)
        restore_ga_runs(second, tmp_path)
        preserved = tmp_path / ".rebrew" / "ga_runs.jsonl.before-restore"
        # The second restore displaced the first backup; the first restore
        # displaced the live log, which now sits in the rotated sibling.
        assert preserved.read_bytes() == first.read_bytes()
        assert (
            preserved.with_name(preserved.name + ".1").read_text(encoding="utf-8")
            == '{"ts": "live", "matched": false}\n'
        )
        assert log.read_bytes() == second.read_bytes()

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
    def test_empty_tree_restore_recovers_config_binary_and_binsync(self, tmp_path: Path) -> None:
        _project(tmp_path)
        config = tmp_path / "rebrew-project.toml"
        config.write_text(
            config.read_text().replace(
                'module = "GAME"', 'module = "GAME"\nbinsync_state_dir = "sync/binsync"'
            ),
            encoding="utf-8",
        )
        config.chmod(0o600)
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ-reference")
        state = tmp_path / "sync" / "binsync"
        files = {
            ".git/HEAD": b"ref: refs/heads/binsync/rebrew\n",
            "functions/0x1000.toml": b'name = "f"\naddr = 4096\n',
        }
        for relative, payload in files.items():
            path = state / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 3, "GAME.0x1000": {"size": 4}}, "test")
        backup = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        restored = tmp_path / "restored"
        restore_metadata_database(backup, restored)
        assert (restored / "game.exe").read_bytes() == binary.read_bytes()
        for relative, payload in files.items():
            path = restored / "sync" / "binsync" / relative
            assert path.read_bytes() == payload
            assert path.stat().st_mode & 0o777 == 0o644
        assert (restored / "rebrew-project.toml").read_bytes() == config.read_bytes()
        assert (restored / "rebrew-project.toml").stat().st_mode & 0o777 == 0o600
        assert (backup.parent / "rebrew-project.toml").stat().st_mode & 0o777 == 0o600
        restored_store = metadata_store(restored / "rebrew-functions.toml")
        assert restored_store.read("test")["GAME.0x1000"]["size"] == 4
        assert "rebrew-project.toml" in verify_backup_manifest(backup.parent)

    def test_corrupt_bundle_config_is_rejected_before_restore(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 3}, "test")
        backup = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        config = backup.parent / "rebrew-project.toml"
        config.chmod(0o644)
        config.write_text("[broken", encoding="utf-8")
        _reseal_manifest(backup.parent)
        restored = tmp_path / "restored"
        with pytest.raises(MetadataStorageError, match="corrupt backup"):
            restore_metadata_database(backup, restored)
        assert not (restored / DATABASE_FILENAME).exists()
        assert not (restored / "rebrew-project.toml").exists()

    @pytest.mark.parametrize("failure", ["copy", "publish", "sync"])
    def test_database_publication_failure_keeps_project_files_consistent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
    ) -> None:
        from rebrew import utils
        from rebrew.metadata import sqlite as sqlite_store

        source = tmp_path / "source"
        target = tmp_path / "target"
        source.mkdir()
        target.mkdir()
        for root, size in ((source, 4), (target, 8)):
            _project(root)
            store = metadata_store(root / "rebrew-functions.toml", backend="sqlite", root=root)
            store.write({"format": 3, "GAME.0x1000": {"size": size}}, "test")
        (source / "game.exe").write_bytes(b"new-reference")
        (target / "game.exe").write_bytes(b"old-reference")
        config = target / "rebrew-project.toml"
        original_config = config.read_bytes() + b"# destination config\n"
        config.write_bytes(original_config)
        config.chmod(0o600)
        backup = backup_metadata_database(source, tmp_path / "backup")
        real_replace = sqlite_store.os.replace
        real_fsync = sqlite_store.os.fsync
        real_write = utils.atomic_write_bytes
        published = False

        def _write(dest: Path, payload: bytes, **kwargs: Any) -> None:
            real_write(dest, payload, **kwargs)
            if failure == "copy" and dest == target / "game.exe" and payload == b"new-reference":
                raise OSError("database companion copy failed")

        def _replace(src: Path | str, dest: Path | str) -> None:
            nonlocal published
            if Path(dest) == target / DATABASE_FILENAME:
                if failure == "publish":
                    raise OSError("database publish failed")
                real_replace(src, dest)
                published = True
            else:
                real_replace(src, dest)

        def _sync(fd: int) -> None:
            if published and failure == "sync":
                raise OSError("database directory sync failed")
            real_fsync(fd)

        monkeypatch.setattr(sqlite_store.os, "replace", _replace)
        monkeypatch.setattr(sqlite_store.os, "fsync", _sync)
        monkeypatch.setattr(utils, "atomic_write_bytes", _write)
        with pytest.raises(OSError, match="database"):
            restore_metadata_database(backup, target)
        assert config.with_name(config.name + ".before-restore").stat().st_mode & 0o777 == 0o600
        if failure != "sync":
            assert config.read_bytes() == original_config
            assert config.stat().st_mode & 0o777 == 0o600
            assert (target / "game.exe").read_bytes() == b"old-reference"
            expected_size = 8
        else:
            assert config.read_bytes() == (source / "rebrew-project.toml").read_bytes()
            assert (target / "game.exe").read_bytes() == b"new-reference"
            expected_size = 4
        store = metadata_store(target / "rebrew-functions.toml", backend="sqlite", root=target)
        assert store.read("test")["GAME.0x1000"]["size"] == expected_size

    def test_restore_locks_config_before_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import locking

        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 3}, "test")
        backup = backup_metadata_database(tmp_path, tmp_path / "backup")
        acquired: list[str] = []
        real_transaction = locking.file_transaction

        @contextmanager
        def _transaction(directory: Path, filename: str) -> Iterator[None]:
            acquired.append(filename)
            with real_transaction(directory, filename):
                yield

        monkeypatch.setattr(locking, "file_transaction", _transaction)
        restore_metadata_database(backup, tmp_path)
        assert acquired[:2] == ["rebrew-project.toml", DATABASE_FILENAME]

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

    def test_rerun_refuses_when_previous_backup_stays_readonly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2, "GAME.0x1000": {"size": 4}}, "test")
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        real = Path.chmod

        def _chmod(self: Path, mode: int) -> None:
            if self == dest and mode == 0o644:
                raise OSError("operation not permitted")
            real(self, mode)

        monkeypatch.setattr(Path, "chmod", _chmod)
        with pytest.raises(MetadataStorageError, match="cannot make the previous backup writable"):
            backup_metadata_database(tmp_path, tmp_path / "off-tree")
        assert dest.stat().st_mode & 0o777 == 0o444
        assert store.read("test")["GAME.0x1000"]["size"] == 4

    def test_restore_refuses_when_journal_cannot_be_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2, "GAME.0x1000": {"size": 4}}, "test")
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        store.write({"format": 2, "GAME.0x1000": {"size": 8}}, "test")
        journal = tmp_path / (DATABASE_FILENAME + "-journal")
        journal.write_bytes(b"old-journal")
        real = Path.unlink

        def _unlink(self: Path, missing_ok: bool = False) -> None:
            if self.name.endswith("-journal"):
                raise OSError("busy")
            real(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", _unlink)
        with pytest.raises(MetadataStorageError, match="stale SQLite sidecar"):
            restore_metadata_database(dest, tmp_path)
        assert journal.read_bytes() == b"old-journal"
        # The planted journal is what a read would replay; drop it only after
        # proving the restore left it, then check the live rows.
        real(journal)
        assert store.read("test")["GAME.0x1000"]["size"] == 8

    def test_second_restore_refuses_when_preserved_copy_stays_readonly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2, "GAME.0x1000": {"size": 4}}, "test")
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        store.write({"format": 2, "GAME.0x1000": {"size": 8}}, "test")
        restore_metadata_database(dest, tmp_path)
        store.write({"format": 2, "GAME.0x1000": {"size": 9}}, "test")
        preserved = tmp_path / (DATABASE_FILENAME + ".before-restore")
        real = Path.chmod

        def _chmod(self: Path, mode: int) -> None:
            if self == preserved and mode == 0o644:
                raise OSError("operation not permitted")
            real(self, mode)

        monkeypatch.setattr(Path, "chmod", _chmod)
        with pytest.raises(
            MetadataStorageError, match="cannot make the preserved database writable"
        ):
            restore_metadata_database(dest, tmp_path)
        assert preserved.stat().st_mode & 0o777 == 0o444
        assert store.read("test")["GAME.0x1000"]["size"] == 9

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

    def test_second_restore_keeps_the_first_displaced_database(self, tmp_path: Path) -> None:
        # Restoring a different backup must rotate the sidecar aside instead
        # of overwriting the only copy of what the first restore displaced.
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2, "GAME.0x1000": {"size": 4}}, "test")
        first = backup_metadata_database(tmp_path, tmp_path / "first")
        store.write({"format": 2, "GAME.0x1000": {"size": 8}}, "test")
        second = backup_metadata_database(tmp_path, tmp_path / "second")
        store.write({"format": 2, "GAME.0x1000": {"size": 9}}, "test")
        restore_metadata_database(first, tmp_path)
        restore_metadata_database(second, tmp_path)
        assert store.read("test")["GAME.0x1000"]["size"] == 8
        import sqlite3

        preserved = tmp_path / (DATABASE_FILENAME + ".before-restore")
        rotated = preserved.with_name(preserved.name + ".1")

        def _size(path: Path) -> str:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                return con.execute(
                    "SELECT content FROM metadata_documents WHERE path = 'rebrew-functions.toml'"
                ).fetchone()[0]
            finally:
                con.close()

        assert "size = 4" in _size(preserved)
        assert "size = 9" in _size(rotated)

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

    def test_sqlite_backup_roundtrips_pgsql_before_transfer_snapshots(self, tmp_path: Path) -> None:
        # The before-transfer snapshot is the only copy of the destination
        # a migrate pgsql replaced; the metadata bundle must carry it.
        _project(tmp_path)
        _store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        _store.write({"format": 2}, "test")
        _snapshot = tmp_path / ".rebrew" / "pgsql-before-transfer" / "rebrew-functions.toml"
        _snapshot.parent.mkdir(parents=True, exist_ok=True)
        _snapshot.write_text("format = 2\n", encoding="utf-8")
        _snapshot.chmod(0o444)
        # A later transfer rotates the previous snapshot aside; that copy is
        # the only record of the earlier destination, so it rides along too.
        _rotated = _snapshot.with_name(_snapshot.name + ".1")
        _rotated.write_text("format = 1\n", encoding="utf-8")
        _rotated.chmod(0o444)
        _dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        _snapshot.unlink()
        _rotated.unlink()
        restore_metadata_database(_dest, tmp_path)
        assert _snapshot.read_text(encoding="utf-8") == "format = 2\n"
        assert _rotated.read_text(encoding="utf-8") == "format = 1\n"

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

    def test_second_transfer_keeps_the_first_displaced_destination(self, tmp_path: Path) -> None:
        # A later transfer displaces different bytes.  The first snapshot is
        # the only copy of what the first transfer replaced, so the rerun
        # must rotate it aside instead of leaving it stale or dropping it.
        cfg = _project(tmp_path, "toml")
        from rebrew.metadata.functions import update_field

        update_field(tmp_path, 0x1000, "SIZE", 4, "GAME")
        migrate_metadata(cfg, "sqlite")
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        doc = store.read("test")
        doc["GAME.0x00001000"]["size"] = 7
        store.write(doc, "test")
        migrate_metadata(load_config(tmp_path), "toml")
        migrate_metadata(load_config(tmp_path), "sqlite")

        # Second displacement: the sqlite destination now holds size 7 while
        # the toml source still holds size 4, so the transfer overwrites a
        # destination the existing snapshot does not record.
        doc = store.read("test")
        doc["GAME.0x00001000"]["size"] = 9
        store.write(doc, "test")
        migrate_metadata(load_config(tmp_path), "toml")
        migrate_metadata(load_config(tmp_path), "sqlite")

        import sqlite3

        snapshot = tmp_path / ".rebrew" / (DATABASE_FILENAME + ".before-transfer")
        rotated = snapshot.with_name(snapshot.name + ".1")
        assert snapshot.is_file() and rotated.is_file()

        def _content(path: Path) -> str:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                return con.execute(
                    "SELECT content FROM metadata_documents WHERE path = 'rebrew-functions.toml'"
                ).fetchone()[0]
            finally:
                con.close()

        assert "size = 9" in _content(snapshot)
        assert "size = 7" in _content(rotated)

        # A rerun that displaces the same bytes again reuses the snapshot.
        migrate_metadata(load_config(tmp_path), "toml")
        migrate_metadata(load_config(tmp_path), "sqlite")
        assert not snapshot.with_name(snapshot.name + ".2").exists()
        assert "size = 9" in _content(snapshot)


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


def _reseal_manifest(bundle: Path) -> None:
    """Recompute the manifest hashes for a bundle whose payload was corrupted.

    Restore verifies the manifest before the payload validators, so a
    test that corrupts a payload and expects the payload validator's
    message must re-seal the manifest or the manifest check fires first.
    """
    import hashlib

    manifest = bundle / "rebrew-backup.manifest.json"
    manifest.chmod(0o644)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    for entry in document["files"]:
        target = bundle / entry["path"]
        payload = target.read_bytes()
        entry["size"] = len(payload)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class TestBackupManifest:
    """The bundle manifest proves a backup is complete before restore."""

    def test_toml_backup_writes_manifest_covering_every_file(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        _write_extra_durable(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        checked = verify_backup_manifest(bundle)
        assert "rebrew-functions.toml" in checked
        assert ".rebrew/ga_runs.jsonl" in checked
        assert ".rebrew/decompme-uploads.json" in checked
        assert ".rebrew/sync/baseline.toml" in checked

    def test_restore_refuses_bundle_with_corrupted_payload(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        bad = bundle / "rebrew-functions.toml"
        bad.chmod(0o644)
        bad.write_text("format=3\nchanged=1\n", encoding="utf-8")
        with pytest.raises(MetadataStorageError, match="manifest verification failed"):
            restore_metadata_toml(bundle, tmp_path)
        assert (tmp_path / "rebrew-functions.toml").read_text(encoding="utf-8") == "format=3\n"

    def test_restore_refuses_bundle_with_missing_file(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        _write_extra_durable(tmp_path)
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        (bundle / ".rebrew" / "ga_runs.jsonl").unlink()
        with pytest.raises(MetadataStorageError, match="missing file"):
            restore_metadata_toml(bundle, tmp_path)

    def test_restore_refuses_bundle_without_manifest(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        (bundle / "rebrew-backup.manifest.json").unlink()
        with pytest.raises(MetadataStorageError, match="no manifest"):
            restore_metadata_toml(bundle, tmp_path)

    def test_sqlite_backup_writes_manifest_and_restore_verifies_it(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2}, "test")
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        checked = verify_backup_manifest(tmp_path / "off-tree")
        assert "rebrew-metadata.backup.sqlite3" in checked
        # A corrupted database copy (same size, flipped byte) is refused
        # by the manifest before sqlite ever opens it.
        bad = tmp_path / "off-tree" / "rebrew-metadata.backup.sqlite3"
        bad.chmod(0o644)
        payload = bytearray(bad.read_bytes())
        payload[-1] ^= 0xFF
        bad.write_bytes(bytes(payload))
        with pytest.raises(MetadataStorageError, match="manifest verification failed"):
            restore_metadata_database(dest, tmp_path)

    def test_root_scan_caches_ride_along(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        (tmp_path / ".rebrew").mkdir(exist_ok=True)
        cover = tmp_path / ".rebrew" / "name-map-cover.json"
        roles = tmp_path / ".rebrew" / "data-scan-roles.json"
        cover.write_text('{"version": 2, "stamp": [], "files": {}}\n', encoding="utf-8")
        roles.write_text(
            '{"version": 1, "stamp": [], "identity": "", "files": {}}\n', encoding="utf-8"
        )
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        checked = verify_backup_manifest(bundle)
        assert ".rebrew/name-map-cover.json" in checked
        assert ".rebrew/data-scan-roles.json" in checked
        cover.unlink()
        roles.unlink()
        restore_metadata_toml(bundle, tmp_path)
        assert cover.read_text(encoding="utf-8") == '{"version": 2, "stamp": [], "files": {}}\n'
        assert roles.read_text(encoding="utf-8") == (
            '{"version": 1, "stamp": [], "identity": "", "files": {}}\n'
        )

    def test_metadata_doc_cache_rides_along(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        cache_dir = tmp_path / ".rebrew" / "metadata-doc"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached = cache_dir / "rebrew-functions.toml.json"
        cached.write_text('{"version": 1, "fingerprint": []}\n', encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        backed = bundle / ".rebrew" / "metadata-doc" / "rebrew-functions.toml.json"
        assert backed.read_text(encoding="utf-8") == '{"version": 1, "fingerprint": []}\n'
        assert ".rebrew/metadata-doc/rebrew-functions.toml.json" in verify_backup_manifest(bundle)
        cached.unlink()
        restore_metadata_toml(bundle, tmp_path)
        assert cached.read_text(encoding="utf-8") == '{"version": 1, "fingerprint": []}\n'

    def test_kept_source_preimage_rides_along(self, tmp_path: Path) -> None:
        # A shared import or skeleton --force leaves the only copy of the
        # removed bytes under .rebrew/source-backups/.  Losing the tree
        # must not lose that copy.
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        backups = tmp_path / ".rebrew" / "source-backups"
        backups.mkdir(parents=True)
        kept = backups / "f1.c.shared-import.1.abc.orig"
        kept.write_bytes(b"int f(void) { return 1; }\n")
        displaced = backups / "f1.c.shared-import.1.abc.orig.before-restore"
        displaced.write_bytes(b"not a source pre-image\n")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        rel = ".rebrew/source-backups/f1.c.shared-import.1.abc.orig"
        assert rel in verify_backup_manifest(bundle)
        assert (bundle / rel).read_bytes() == b"int f(void) { return 1; }\n"
        assert ".rebrew/source-backups/f1.c.shared-import.1.abc.orig.before-restore" not in (
            verify_backup_manifest(bundle)
        )
        kept.unlink()
        restore_metadata_toml(bundle, tmp_path)
        assert kept.read_bytes() == b"int f(void) { return 1; }\n"

    def test_toml_backup_carries_target_binary(self, tmp_path: Path) -> None:
        # The target binary is the non-regenerable input: a bundle that
        # omits it leaves a restored tree that cannot verify.
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "game"\n'
            '[targets.game]\nbinary = "original/game.exe"\n'
            'reversed_dir = "src"\nmodule = "GAME"\n'
            '[metadata]\nbackend = "toml"\n',
            encoding="utf-8",
        )
        binary = tmp_path / "original" / "game.exe"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"MZ\x00\x01\x02")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        assert "original/game.exe" in verify_backup_manifest(bundle)
        backed = bundle / "original" / "game.exe"
        assert backed.read_bytes() == b"MZ\x00\x01\x02"
        # Restore reinstalls it after the live copy is lost.
        binary.unlink()
        assert not binary.exists()
        restore_metadata_toml(bundle, tmp_path)
        assert binary.read_bytes() == b"MZ\x00\x01\x02"


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

    def test_second_restore_keeps_the_first_displaced_store(self, tmp_path: Path) -> None:
        # Restoring a different bundle must rotate the sidecar aside instead
        # of overwriting the only copy of what the first restore displaced.
        dest = tmp_path / "rebrew-functions.toml"
        dest.write_text("format=3\norig=1\n", encoding="utf-8")
        first = backup_metadata_toml(tmp_path, tmp_path / "first")
        dest.chmod(0o644)
        dest.write_text("format=3\norig=2\n", encoding="utf-8")
        second = backup_metadata_toml(tmp_path, tmp_path / "second")
        dest.chmod(0o644)
        dest.write_text("format=3\norig=3\n", encoding="utf-8")
        restore_metadata_toml(first, tmp_path)
        restore_metadata_toml(second, tmp_path)
        assert dest.read_text(encoding="utf-8") == "format=3\norig=2\n"
        preserved = dest.with_name(dest.name + ".before-restore")
        assert preserved.read_text(encoding="utf-8") == "format=3\norig=1\n"
        assert (
            preserved.with_name(preserved.name + ".1").read_text(encoding="utf-8")
            == "format=3\norig=3\n"
        )

    def test_missing_stores_raise_not_empty_bundle(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            backup_metadata_toml(tmp_path, tmp_path / "off-tree")

    def test_extern_and_name_map_caches_ride_along(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        rebrew_dir = tmp_path / ".rebrew"
        rebrew_dir.mkdir(exist_ok=True)
        extern = rebrew_dir / "extern-names.json"
        name_map = rebrew_dir / "name_to_va_cache.json"
        extern.write_text(
            '{"version": 1, "files": {"a.c": {"stamp": [1, 2, 3, 4], "names": ["f"]}}}\n',
            encoding="utf-8",
        )
        name_map.write_text(
            '{"version": 3, "key": "abc", "map": {"_helper": 1234}}\n', encoding="utf-8"
        )
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        checked = verify_backup_manifest(bundle)
        assert ".rebrew/extern-names.json" in checked
        assert ".rebrew/name_to_va_cache.json" in checked
        extern.unlink()
        name_map.unlink()
        restore_metadata_toml(bundle, tmp_path)
        assert extern.read_text(encoding="utf-8") == (
            '{"version": 1, "files": {"a.c": {"stamp": [1, 2, 3, 4], "names": ["f"]}}}\n'
        )
        assert name_map.read_text(encoding="utf-8") == (
            '{"version": 3, "key": "abc", "map": {"_helper": 1234}}\n'
        )

    def test_corrupt_new_caches_refuse_restore(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        (tmp_path / ".rebrew").mkdir(exist_ok=True)
        extern = tmp_path / ".rebrew" / "extern-names.json"
        extern.write_text('{"version": 1, "files": {}}\n', encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        bad = bundle / ".rebrew" / "extern-names.json"
        bad.chmod(0o644)
        bad.write_text("not json\n", encoding="utf-8")
        _reseal_manifest(bundle)
        with pytest.raises(MetadataStorageError, match="corrupt backup"):
            restore_metadata_toml(bundle, tmp_path)

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
        _reseal_manifest(bundle)
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
        _reseal_manifest(bundle)
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
        _reseal_manifest(bundle)
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

    def test_sqlite_backup_carries_target_binary(self, tmp_path: Path) -> None:
        # The target binary is irreplaceable; a SQLite backup that omits
        # it leaves a restored tree that cannot verify, same as TOML.
        _project(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "game"\nshared_dir = ""\n'
            '[targets.game]\nbinary = "original/game.exe"\nreversed_dir = "src"\nmodule = "GAME"\n'
            '[metadata]\nbackend = "sqlite"\n',
            encoding="utf-8",
        )
        binary = tmp_path / "original" / "game.exe"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"MZ\x00\x01\x02")
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        store.write({"format": 2}, "test")
        dest = backup_metadata_database(tmp_path, tmp_path / "off-tree")
        assert "original/game.exe" in verify_backup_manifest(tmp_path / "off-tree")
        binary.unlink()
        restore_metadata_database(dest, tmp_path)
        assert binary.read_bytes() == b"MZ\x00\x01\x02"

    def test_corrupt_bundle_leaves_stores_alone(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        bad = bundle / "rebrew-functions.toml"
        bad.chmod(0o644)
        bad.write_text("not toml [[[\n", encoding="utf-8")
        _reseal_manifest(bundle)
        with pytest.raises(MetadataStorageError):
            restore_metadata_toml(bundle, tmp_path)
        assert (tmp_path / "rebrew-functions.toml").read_text(encoding="utf-8") == "format=3\n"


class TestRestoreDrill:
    """A backup never restored is a hypothesis; pin the drill."""

    def test_full_round_trip_covers_snapshots_and_extras(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        (tmp_path / "rebrew-project.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        snap = tmp_path / "snapshots" / "coverage-game.toml"
        snap.parent.mkdir()
        snap.write_text("version=1\ntarget='game'\n", encoding="utf-8")
        (tmp_path / ".rebrew").mkdir(exist_ok=True)
        (tmp_path / ".rebrew" / "ga_runs.jsonl").write_text('{"a":1}\n', encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        from rebrew.metadata.sqlite import verify_backup_manifest

        assert "snapshots/coverage-game.toml" in verify_backup_manifest(bundle)
        assert ".rebrew/ga_runs.jsonl" in verify_backup_manifest(bundle)
        snap.unlink()
        (tmp_path / ".rebrew" / "ga_runs.jsonl").unlink()
        restore_metadata_toml(bundle, tmp_path)
        assert snap.read_text(encoding="utf-8") == "version=1\ntarget='game'\n"
        assert (tmp_path / ".rebrew" / "ga_runs.jsonl").read_text(encoding="utf-8") == '{"a":1}\n'

    def test_store_less_backup_refused(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        (tmp_path / ".rebrew").mkdir(exist_ok=True)
        (tmp_path / ".rebrew" / "ga_runs.jsonl").write_text('{"a":1}\n', encoding="utf-8")
        with pytest.raises(FileNotFoundError, match="no metadata stores"):
            backup_metadata_toml(tmp_path, tmp_path / "off-tree")

    def test_backup_carries_binsync_state_dir(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-functions.toml").write_text("format=3\n", encoding="utf-8")
        cfg = '[targets.game]\nbinary = "game.exe"\nbinsync_state_dir = "sync/binsync"\n'
        (tmp_path / "rebrew-project.toml").write_text(cfg, encoding="utf-8")
        state = tmp_path / "sync" / "binsync" / "functions"
        state.mkdir(parents=True)
        (state / "0x1000.toml").write_text("name='foo'\n", encoding="utf-8")
        git_dir = tmp_path / "sync" / "binsync" / ".git"
        git_dir.mkdir(parents=True, exist_ok=True)
        (git_dir / "HEAD").write_text("ref: refs/heads/binsync/rebrew\n", encoding="utf-8")
        bundle = backup_metadata_toml(tmp_path, tmp_path / "off-tree")
        manifest = verify_backup_manifest(bundle)
        assert "sync/binsync/functions/0x1000.toml" in manifest
        assert "sync/binsync/.git/HEAD" in manifest
        (state / "0x1000.toml").unlink()
        (git_dir / "HEAD").unlink()
        restore_metadata_toml(bundle, tmp_path)
        assert (state / "0x1000.toml").read_text(encoding="utf-8") == "name='foo'\n"
        assert (git_dir / "HEAD").read_text(encoding="utf-8") == "ref: refs/heads/binsync/rebrew\n"
