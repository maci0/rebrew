"""Ordered read failover, replicated writes and durable recovery contracts."""

from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from rebrew.config import load_config
from rebrew.metadata.functions import get_entry, update_field
from rebrew.metadata.replication import JOURNAL_PATH, MetadataConflictError
from rebrew.metadata.sqlite import MetadataStorageError, MetadataUnavailableError, SqliteStore
from rebrew.metadata.storage import backend_routes, metadata_store, project_metadata_stores
from rebrew.metadata_transfer import reconcile_metadata


def _project(root: Path, reads: list[str] | None = None, writes: list[str] | None = None) -> Any:
    root.mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir(exist_ok=True)
    doc = {
        "project": {"default_target": "game", "shared_dir": ""},
        "targets": {"game": {"binary": "game.exe", "reversed_dir": "src", "module": "GAME"}},
        "metadata": {
            "read_backends": reads or ["sqlite", "toml"],
            "write_backends": writes or ["sqlite", "toml"],
        },
    }
    (root / "rebrew-project.toml").write_text(tomlkit.dumps(doc))
    return load_config(root)


def _raw(root: Path, backend: str, name: str = "rebrew-functions.toml") -> Any:
    return metadata_store(root / name, backend=backend, root=root)


def _reconcile_process(root: str) -> dict[str, Any]:
    return reconcile_metadata(load_config(Path(root)))


def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    from collections.abc import Iterator  # noqa: TC003 - tests keep eager imports

    def read(self: SqliteStore, *args: Any, **kwargs: Any) -> Any:
        raise MetadataUnavailableError("offline")

    @contextmanager
    def transaction(self: SqliteStore) -> Iterator[None]:
        raise MetadataUnavailableError("offline")
        yield

    monkeypatch.setattr(SqliteStore, "read", read)
    monkeypatch.setattr(SqliteStore, "transaction", transaction)


class TestRoutingConfig:
    @pytest.mark.parametrize(
        "raw",
        [
            {"read_backends": []},
            {"write_backends": []},
            {"read_backends": ["missing"]},
            {"write_backends": ["sqlite", "sqlite"]},
            {"backend": "sqlite", "read_backends": ["toml"]},
            {"read_backends": "sqlite"},
            {"write_backends": [False]},
        ],
    )
    def test_invalid_routes_rejected(self, raw: dict[str, str | list[str] | list[bool]]) -> None:
        with pytest.raises(ValueError):
            backend_routes(raw)

    def test_read_and_write_lists_are_independent(self) -> None:
        assert backend_routes({"read_backends": ["sqlite"], "write_backends": ["toml"]}) == (
            ("sqlite",),
            ("toml",),
        )


class TestMetadataReplication:
    def test_domain_writes_reach_all_stores_and_discovery_preserves_routing(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        assert cfg.metadata_read_backends == ("sqlite", "toml")
        update_field(tmp_path, 0x1000, "NOTE", "shared", "GAME")
        assert _raw(tmp_path, "sqlite").read("test") == _raw(tmp_path, "toml").read("test")
        stores = project_metadata_stores(tmp_path)
        assert [store.path.name for store in stores] == ["rebrew-functions.toml"]
        stores[0].write({"format": 3}, "test")
        assert _raw(tmp_path, "sqlite").read("test") == {"format": 3}
        assert _raw(tmp_path, "toml").read("test") == {"format": 3}

    def test_reads_fall_back_only_when_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        _raw(tmp_path, "toml").write({"format": 3, "note": "fallback"}, "test")
        # An available but empty preferred backend is authoritative.
        assert metadata_store(tmp_path / "rebrew-functions.toml").read("test") == {}
        _offline(monkeypatch)
        assert metadata_store(tmp_path / "rebrew-functions.toml").read("test")["note"] == "fallback"

    def test_corruption_does_not_trigger_failover(self, tmp_path: Path) -> None:
        _project(tmp_path)
        _raw(tmp_path, "toml").write({"format": 3}, "test")
        (tmp_path / "rebrew-metadata.sqlite3").write_bytes(b"corrupt")
        with pytest.raises(MetadataStorageError):
            metadata_store(tmp_path / "rebrew-functions.toml").read("test")

    def test_failed_writer_is_queued_and_replayed_after_recovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "before", "GAME")
        with monkeypatch.context() as patch:
            _offline(patch)
            update_field(tmp_path, 0x1000, "NOTE", "offline update", "GAME")
            assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "offline update"
        assert _raw(tmp_path, "sqlite").read("test")["GAME.0x00001000"]["note"] == "before"
        # Recovery reads apply the committed journal overlay instead of serving stale values.
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "offline update"
        with ProcessPoolExecutor(1) as pool:
            report = pool.submit(_reconcile_process, str(tmp_path)).result(timeout=30)
        assert not any(item["pending"] for item in report["items"])
        assert _raw(tmp_path, "sqlite").read("test") == _raw(tmp_path, "toml").read("test")

    def test_next_write_automatically_replays_other_pending_documents(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        with monkeypatch.context() as patch:
            _offline(patch)
            metadata_store(tmp_path / "rebrew-data.toml").write({"format": 2}, "test")
        update_field(tmp_path, 0x1000, "NOTE", "trigger", "GAME")
        assert _raw(tmp_path, "sqlite", "rebrew-data.toml").read("test") == {"format": 2}

    def test_deleted_document_does_not_resurrect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "old", "GAME")
        with monkeypatch.context() as patch:
            _offline(patch)
            metadata_store(tmp_path / "rebrew-functions.toml").remove()
        assert not metadata_store(tmp_path / "rebrew-functions.toml").exists()
        reconcile_metadata(cfg)
        assert not _raw(tmp_path, "sqlite").exists()
        assert not _raw(tmp_path, "toml").exists()
        assert project_metadata_stores(tmp_path) == ()

    def test_preview_creates_no_storage(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        before = set(tmp_path.rglob("*"))
        reconcile_metadata(cfg, dry_run=True)
        assert set(tmp_path.rglob("*")) == before

    def test_failed_body_rolls_back_all_documents_and_journal(self, tmp_path: Path) -> None:
        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "before", "GAME")
        journal = (tmp_path / JOURNAL_PATH).read_bytes()
        store = metadata_store(tmp_path / "rebrew-functions.toml")
        with pytest.raises(RuntimeError, match="abort"), store.transaction():
            update_field(tmp_path, 0x1000, "NOTE", "temporary", "GAME")
            metadata_store(tmp_path / "rebrew-data.toml").write({"format": 2}, "test")
            assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "temporary"
            raise RuntimeError("abort")
        assert (tmp_path / JOURNAL_PATH).read_bytes() == journal
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "before"
        for backend in ("sqlite", "toml"):
            assert not _raw(tmp_path, backend, "rebrew-data.toml").exists()

    def test_independent_changes_are_preserved_as_a_conflict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "base", "GAME")
        with monkeypatch.context() as patch:
            _offline(patch)
            update_field(tmp_path, 0x1000, "NOTE", "local", "GAME")
        sqlite = _raw(tmp_path, "sqlite")
        doc = sqlite.read("test", roundtrip=True)
        doc["GAME.0x00001000"]["note"] = "independent"
        sqlite.write(doc, "test")
        before = sqlite.snapshot()
        with pytest.raises(MetadataConflictError):
            reconcile_metadata(cfg)
        assert sqlite.snapshot() == before
        assert _raw(tmp_path, "toml").read("test")["GAME.0x00001000"]["note"] == "local"

    def test_noop_writes_do_not_advance_timestamp(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml")
        store.write({"format": 3}, "test")
        before = store.fingerprint()
        store.write({"format": 3}, "test")
        assert store.fingerprint() == before

    def test_commit_failure_is_recovered_without_losing_the_committed_operation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from collections.abc import Iterator  # noqa: TC003 - tests keep eager imports

        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "before", "GAME")
        original = SqliteStore.transaction

        @contextmanager
        def fail_commit(self: SqliteStore) -> Iterator[None]:
            with original(self):
                yield
                if self.path.name == "metadata-replication.toml":
                    raise OSError("injected commit failure")

        with monkeypatch.context() as patch:
            patch.setattr(SqliteStore, "transaction", fail_commit)
            update_field(tmp_path, 0x1000, "NOTE", "after", "GAME")
        assert _raw(tmp_path, "sqlite").read("test")["GAME.0x00001000"]["note"] == "before"
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "after"
        reconcile_metadata(cfg)
        assert _raw(tmp_path, "sqlite").read("test")["GAME.0x00001000"]["note"] == "after"

    def test_read_discovery_keeps_newer_recreations_after_local_tombstone(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        store = metadata_store(tmp_path / "rebrew-functions.toml")
        store.write({"format": 3}, "test")
        store.remove()
        # A deliberate external recreation is newer than its backend's known tombstone.
        _raw(tmp_path, "sqlite").write({"format": 3}, "test")
        assert project_metadata_stores(tmp_path)[0].path == store.path
        reconcile_metadata(cfg)
        assert _raw(tmp_path, "toml").exists()

    def test_read_and_write_use_separate_backend_lists(self, tmp_path: Path) -> None:
        _project(tmp_path, reads=["sqlite"], writes=["toml"])
        store = metadata_store(tmp_path / "rebrew-functions.toml")
        store.write({"format": 3}, "test")
        assert store.read("test") == {"format": 3}
        assert _raw(tmp_path, "toml").exists() and not _raw(tmp_path, "sqlite").exists()

    def test_reconcile_cli_reports_unavailable_writer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.metadata_cli import app

        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "base", "GAME")
        monkeypatch.chdir(tmp_path)
        _offline(monkeypatch)
        result = CliRunner().invoke(app, ["reconcile", "--json"])
        assert result.exit_code == 0, result.output
        assert '"pending":true' in result.output

    def test_replication_journal_survives_toml_backup_restore(self, tmp_path: Path) -> None:
        from rebrew.metadata.sqlite import backup_metadata_toml, restore_metadata_toml

        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "backup", "GAME")
        before = (tmp_path / JOURNAL_PATH).read_bytes()
        bundle = backup_metadata_toml(tmp_path, tmp_path / "backup")
        (tmp_path / JOURNAL_PATH).chmod(0o644)
        (tmp_path / JOURNAL_PATH).write_text("corrupted")
        restore_metadata_toml(bundle, tmp_path)
        assert (tmp_path / JOURNAL_PATH).read_bytes() == before
        reconcile_metadata(cfg)

    def test_coordinated_source_failure_leaves_no_replication_commit(self, tmp_path: Path) -> None:
        from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction

        _project(tmp_path)
        source = tmp_path / "src/a.c"
        source.write_text("int a;\n")
        before = coordinated_inputs(tmp_path, [source])
        with (
            pytest.raises(RuntimeError, match="abort"),
            coordinated_transaction(tmp_path, [source], expected_inputs=before) as stage,
        ):
            stage.publish(source, b"int b;\n")
            update_field(tmp_path, 0x1000, "NOTE", "temporary", "GAME")
            raise RuntimeError("abort")
        assert source.read_text() == "int a;\n"
        assert not (tmp_path / JOURNAL_PATH).exists()
        assert project_metadata_stores(tmp_path) == ()

    def test_copying_a_checkout_does_not_reuse_its_writer_identity(self, tmp_path: Path) -> None:
        import shutil

        first, second = tmp_path / "one", tmp_path / "two"
        cfg = _project(first)
        update_field(first, 0x1000, "NOTE", "base", "GAME")
        shutil.copytree(first, second)
        update_field(first, 0x1000, "NOTE", "first", "GAME")
        update_field(second, 0x1000, "NOTE", "second", "GAME")
        first_node = tomlkit.parse((first / JOURNAL_PATH).read_text())["node"]
        second_node = tomlkit.parse((second / JOURNAL_PATH).read_text())["node"]
        assert first_node != second_node
        database = first / "rebrew-metadata.sqlite3"
        database.chmod(0o644)
        shutil.copy2(second / database.name, database)
        with pytest.raises(MetadataConflictError):
            reconcile_metadata(cfg)

    def test_an_unstamped_changed_replica_is_not_silently_overwritten(self, tmp_path: Path) -> None:
        from rebrew.metadata.replication import STATE_PATH

        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "known", "GAME")
        SqliteStore(tmp_path / STATE_PATH, tmp_path).remove()
        _raw(tmp_path, "sqlite").write({"format": 3}, "test")
        with pytest.raises(MetadataConflictError):
            reconcile_metadata(cfg)
        assert _raw(tmp_path, "sqlite").read("test") == {"format": 3}

    def test_distinct_unstamped_copies_require_review(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        _raw(tmp_path, "sqlite").write({"format": 3, "note": "one"}, "test")
        _raw(tmp_path, "toml").write({"format": 3, "note": "two"}, "test")
        with pytest.raises(MetadataConflictError):
            reconcile_metadata(cfg)
        assert not (tmp_path / JOURNAL_PATH).exists()
