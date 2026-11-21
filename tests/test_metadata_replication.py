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

    # Every SQLite read path (read, text, exists, fingerprint) opens the
    # database through _reader, which raises this error for a real outage.
    @contextmanager
    def reader(self: SqliteStore) -> Iterator[Any]:
        raise MetadataUnavailableError("offline")
        yield

    @contextmanager
    def transaction(self: SqliteStore) -> Iterator[None]:
        raise MetadataUnavailableError("offline")
        yield

    monkeypatch.setattr(SqliteStore, "_reader", reader)
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
        # An available preferred backend that lacks this document is authoritative.
        # (A database that holds no document at all is unprovisioned; see the
        # fresh-clone test.)
        sqlite_data = _raw(tmp_path, "sqlite", "rebrew-data.toml")
        with sqlite_data.transaction():
            sqlite_data.write({"format": 2}, "test")
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


_AWKWARD = "q\"\\ back\nslash\ttab \x01ctl \x7fdel é \U0001f600 ''' end"


class TestReplicationHotPaths:
    """Large stores must not pay tomlkit round-trips on every replicated operation."""

    def test_state_render_round_trips_through_the_loader(self, tmp_path: Path) -> None:
        from rebrew.metadata.files import TomlStore
        from rebrew.metadata.replication import _load, _Record, _save

        content = tomlkit.dumps({"a": {"s": _AWKWARD}})
        records = {
            "rebrew-functions.toml": _Record({"node:x": 3, 'odd "node"': 1}, 7, content, False),
            "rebrew-data.toml": _Record({"n": 1}, 9, "", True),
        }
        store = TomlStore(tmp_path / "state.toml", tmp_path)
        _save(store, records, 'node "id"')
        loaded, node = _load(store)
        assert node == 'node "id"'
        assert loaded == records
        assert loaded["rebrew-functions.toml"].digest == records["rebrew-functions.toml"].digest

    def test_state_load_trusts_the_digest_once_the_content_hash_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata.replication as replication
        from rebrew.metadata.files import TomlStore

        content = tomlkit.dumps({"a": {"s": _AWKWARD}})
        record = replication._Record({"node:x": 1}, 7, content, False)
        expected = record.digest
        store = TomlStore(tmp_path / "state.toml", tmp_path)
        replication._save(store, {"rebrew-functions.toml": record}, "")
        replication._LOADED.clear()

        def refuse(*args: Any, **kwargs: Any) -> str:
            raise AssertionError("semantic digest computed while loading state")

        monkeypatch.setattr(replication, "_digest", refuse)
        loaded, _ = replication._load(store)
        assert loaded["rebrew-functions.toml"].digest == expected

    def test_state_without_content_hash_still_verifies_the_digest(self, tmp_path: Path) -> None:
        import rebrew.metadata.replication as replication
        from rebrew.metadata.files import TomlStore

        content = tomlkit.dumps({"a": {"s": "x"}})
        record = replication._Record({"node:x": 1}, 7, content, False)
        rendered = replication._render_state({"rebrew-functions.toml": record}, "")
        # The layout releases before 6.59.0 wrote: format 1, no content hash.
        old = "\n".join(
            line for line in rendered.split("\n") if not line.startswith("content_sha256 = ")
        ).replace("format = 2\n", "format = 1\n", 1)
        (tmp_path / "state.toml").write_text(old)
        store = TomlStore(tmp_path / "state.toml", tmp_path)
        replication._LOADED.clear()
        loaded, _ = replication._load(store)
        assert loaded["rebrew-functions.toml"].digest == record.digest
        (tmp_path / "state.toml").write_text(old.replace('digest = "', 'digest = "0', 1))
        replication._LOADED.clear()
        with pytest.raises(MetadataStorageError, match="digest mismatch"):
            replication._load(TomlStore(tmp_path / "state.toml", tmp_path))

    def test_state_with_tampered_content_is_rejected(self, tmp_path: Path) -> None:
        import rebrew.metadata.replication as replication
        from rebrew.metadata.files import TomlStore

        content = tomlkit.dumps({"a": {"s": "x"}})
        record = replication._Record({"node:x": 1}, 7, content, False)
        rendered = replication._render_state({"rebrew-functions.toml": record}, "")
        (tmp_path / "state.toml").write_text(rendered.replace('s = \\"x\\"', 's = \\"y\\"'))
        replication._LOADED.clear()
        with pytest.raises(MetadataStorageError, match="content hash mismatch"):
            replication._load(TomlStore(tmp_path / "state.toml", tmp_path))

    def test_store_text_and_write_text(self, tmp_path: Path) -> None:
        _project(tmp_path)
        content = tomlkit.dumps({"format": 3, "x": {"s": _AWKWARD}})
        for backend in ("toml", "sqlite"):
            store = _raw(tmp_path, backend, "rebrew-data.toml")
            assert store.text() is None
            with store.transaction():
                store.write_text(content, "test")
            assert store.text() == content
            assert store.read("test") == tomlkit.parse(content).unwrap()

    def test_fragmented_toml_store_keeps_records_in_their_fragment(self, tmp_path: Path) -> None:
        from rebrew.metadata.files import TomlStore

        main = tmp_path / "rebrew-data.toml"
        main.write_text('format = 2\n\n["GAME.0x1000"]\nname = "a"\n')
        fragment = tmp_path / "rebrew-data.d" / "extra.toml"
        fragment.parent.mkdir()
        fragment.write_text('["GAME.0x2000"]\nname = "b"\n')
        store = TomlStore(main, tmp_path)
        merged = store.text()
        assert merged is not None
        assert tomlkit.parse(merged).unwrap()["GAME.0x2000"] == {"name": "b"}
        store.write_text(merged.replace('name = "b"', 'name = "c"'), "test")
        assert 'name = "c"' in fragment.read_text()
        assert "0x2000" not in main.read_text()

    def test_reconcile_publishes_without_tomlkit_round_trips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "shared", "GAME")
        edited = _raw(tmp_path, "toml").read("test", roundtrip=True)
        edited["GAME.0x00001000"]["note"] = "edited"
        _raw(tmp_path, "toml").write(edited, "external edit")

        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("tomlkit round-trip on a replication hot path")

        monkeypatch.setattr(tomlkit, "parse", refuse)
        monkeypatch.setattr(tomlkit, "dumps", refuse)
        reconcile_metadata(cfg)
        assert "edited" in (_raw(tmp_path, "sqlite").text() or "")

    def test_repeated_fingerprint_resolves_the_view_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "first", "GAME")
        fetches: list[int] = []
        text = SqliteStore.text

        def counting(self: SqliteStore) -> str | None:
            fetches.append(1)
            return text(self)

        monkeypatch.setattr(SqliteStore, "text", counting)
        store = metadata_store(tmp_path / "rebrew-functions.toml", root=tmp_path)
        first = store.fingerprint()
        fetched = len(fetches)
        assert fetched > 0
        assert [store.fingerprint() for _ in range(5)] == [first] * 5
        assert len(fetches) == fetched
        update_field(tmp_path, 0x1000, "NOTE", "second", "GAME")
        assert store.fingerprint() != first

    def test_library_override_lookup_walks_once_until_a_library_document_changes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata.functions as functions
        from rebrew.metadata.functions import (
            LIBRARY_METADATA_FILE,
            clear_library_override_cache,
            library_override_fingerprint,
        )

        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "provisions the database", "GAME")
        source_dir = tmp_path / "src" / "unit"
        source_dir.mkdir()
        clear_library_override_cache()
        walks: list[int] = []
        walk = functions.nearest_library_metadata_path

        def counting(start: Path | str, root: Path | str | None = None) -> Path | None:
            walks.append(1)
            return walk(start, root)

        monkeypatch.setattr(functions, "nearest_library_metadata_path", counting)
        assert library_override_fingerprint(source_dir, tmp_path) is None
        assert [library_override_fingerprint(source_dir, tmp_path) for _ in range(8)] == [None] * 8
        assert len(walks) == 1

        library = metadata_store(tmp_path / "src" / LIBRARY_METADATA_FILE, root=tmp_path)
        with library.transaction():
            library.write({"toolchain": "msvc-6.0-sp6"}, "test")
        found = library_override_fingerprint(source_dir, tmp_path)
        assert len(walks) == 2
        assert found is not None and found[0].endswith("src/" + LIBRARY_METADATA_FILE)
        assert library_override_fingerprint(source_dir, tmp_path) == found
        assert len(walks) == 2

        with library.transaction():
            library.write({"toolchain": "msvc-4.2"}, "test")
        edited = library_override_fingerprint(source_dir, tmp_path)
        assert len(walks) == 3
        assert edited is not None and edited != found

    def test_library_override_lookup_follows_a_retargeted_symlinked_directory(
        self, tmp_path: Path
    ) -> None:
        from rebrew.metadata.functions import (
            LIBRARY_METADATA_FILE,
            clear_library_override_cache,
            library_override_fingerprint,
        )

        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "provisions the database", "GAME")
        for name, toolchain in (("a", "msvc-6.0-sp6"), ("b", "msvc-4.2")):
            (tmp_path / "src" / name / "unit").mkdir(parents=True)
            library = metadata_store(tmp_path / "src" / name / LIBRARY_METADATA_FILE, root=tmp_path)
            with library.transaction():
                library.write({"toolchain": toolchain}, "test")
        link = tmp_path / "src" / "unit"
        link.symlink_to(tmp_path / "src" / "a" / "unit", target_is_directory=True)
        clear_library_override_cache()
        first = library_override_fingerprint(link, tmp_path)
        assert first is not None and first[0].endswith(f"src/a/{LIBRARY_METADATA_FILE}")

        link.unlink()
        link.symlink_to(tmp_path / "src" / "b" / "unit", target_is_directory=True)
        retargeted = library_override_fingerprint(link, tmp_path)
        assert retargeted is not None
        assert retargeted[0].endswith(f"src/b/{LIBRARY_METADATA_FILE}")

    def test_library_override_follows_a_replaced_database_with_equal_revisions(
        self, tmp_path: Path
    ) -> None:
        """A restore or copy of the database can hold other text under the same revisions."""
        from rebrew.compiler.overrides import resolve_compile_overrides_cached
        from rebrew.metadata.functions import LIBRARY_METADATA_FILE, clear_library_override_cache
        from rebrew.metadata.sqlite import DATABASE_FILENAME

        roots = {"msvc-6.0-sp6": tmp_path / "live", "msvc-4.2": tmp_path / "restored"}
        for toolchain, root in roots.items():
            _project(root, reads=["sqlite"], writes=["sqlite"])
            update_field(root, 0x1000, "NOTE", "provisions the database", "GAME")
            (root / "src" / "unit").mkdir()
            library = metadata_store(root / "src" / LIBRARY_METADATA_FILE, root=root)
            with library.transaction():
                library.write({"toolchain": toolchain}, "test")
        live = roots["msvc-6.0-sp6"]
        cfg = load_config(live)
        clear_library_override_cache()

        def toolchain() -> str | None:
            return resolve_compile_overrides_cached(cfg, live / "src" / "unit", None, None, "GAME")[
                0
            ]

        assert toolchain() == "msvc-6.0-sp6"
        (roots["msvc-4.2"] / DATABASE_FILENAME).replace(live / DATABASE_FILENAME)
        assert toolchain() == "msvc-4.2"


def _replicated_documents(root: Path) -> list[Path]:
    """The TOML journal and replication-state files of a replicated project."""
    return [root / JOURNAL_PATH, root / ".rebrew" / "metadata-replication.toml"]


def _rewrite(path: Path, old: str, new: str) -> None:
    path.chmod(0o644)
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new, 1))


class TestStateFormat:
    """The journal and replication-state ``format`` names the record fields an older reader refuses."""

    def test_records_with_a_content_hash_are_written_as_format_2(self, tmp_path: Path) -> None:
        import tomllib

        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "shared", "GAME")
        for path in _replicated_documents(tmp_path):
            doc = tomllib.loads(path.read_text())
            assert doc["format"] == 2, path
            assert doc["records"]
            assert all("content_sha256" in row for row in doc["records"].values()), path

    def test_format_1_with_content_hash_is_read_and_rewritten_as_format_2(
        self, tmp_path: Path
    ) -> None:
        import tomllib

        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "first", "GAME")
        # rebrew 6.59.0 wrote this exact layout under format 1.
        for path in _replicated_documents(tmp_path):
            _rewrite(path, "format = 2\n", "format = 1\n")
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "first"
        update_field(tmp_path, 0x1000, "NOTE", "second", "GAME")
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "second"
        for path in _replicated_documents(tmp_path):
            assert tomllib.loads(path.read_text())["format"] == 2, path

    def test_format_2_record_without_content_hash_is_invalid(self, tmp_path: Path) -> None:
        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "first", "GAME")
        journal = tmp_path / JOURNAL_PATH
        journal.chmod(0o644)
        journal.write_text(
            "\n".join(
                line
                for line in journal.read_text().split("\n")
                if not line.startswith("content_sha256 = ")
            )
        )
        with pytest.raises(MetadataStorageError, match="invalid metadata replication record"):
            update_field(tmp_path, 0x1000, "NOTE", "second", "GAME")

    def test_newer_format_is_refused_by_name(self, tmp_path: Path) -> None:
        _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "first", "GAME")
        _rewrite(tmp_path / JOURNAL_PATH, "format = 2\n", "format = 3\n")
        with pytest.raises(
            MetadataStorageError, match=r"format 3 is newer than this rebrew reads \(2\); upgrade"
        ):
            get_entry(tmp_path, 0x1000, "GAME")


def test_rendered_state_parser_matches_tomllib() -> None:
    import tomllib

    from rebrew.metadata.replication import _parse_rendered, _Record, _render_state

    content = tomlkit.dumps({"a": {"s": _AWKWARD}})
    records = {
        "rebrew-functions.toml": _Record({"node:x": 3, 'odd "node"': 1}, 7, content, False),
        "rebrew-data.toml": _Record({}, 9, "", True),
    }
    for node in ("", 'node "id"'):
        text = _render_state(records, node)
        assert _parse_rendered(text) == tomllib.loads(text)
        # 6.59.0 wrote the same layout under format 1.
        released = text.replace("format = 2\n", "format = 1\n", 1)
        assert _parse_rendered(released) == tomllib.loads(released)
    assert _parse_rendered(_render_state({}, "")) == tomllib.loads(_render_state({}, ""))
    # Any other layout is left to tomllib.
    other = {"format": 1, "records": {"rebrew-data.toml": {"clock": {"n": 1}, "updated_at_ns": 1}}}
    assert _parse_rendered(tomlkit.dumps(other)) is None
    assert _parse_rendered(text.replace("deleted = false", "deleted=false")) is None


def test_fresh_clone_without_the_database_reads_and_keeps_the_toml_replica(tmp_path: Path) -> None:
    """A clone carries the git-tracked TOML but not the SQLite file; it must not read as empty.

    An empty preferred backend is authoritative, so a never-created database
    used to answer every read with {} and the next write published a document
    holding only the new record to both backends, dropping the rest.
    """
    _project(tmp_path)
    update_field(tmp_path, 0x1000, "NOTE", "kept", "GAME")
    update_field(tmp_path, 0x2000, "NOTE", "also kept", "GAME")
    (tmp_path / "rebrew-metadata.sqlite3").unlink()
    for state in (tmp_path / ".rebrew").glob("metadata-*"):
        state.unlink()
    assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "kept"
    update_field(tmp_path, 0x3000, "NOTE", "new", "GAME")
    toml = _raw(tmp_path, "toml").read("test")
    assert {key: row["note"] for key, row in toml.items() if key != "format"} == {
        "GAME.0x00001000": "kept",
        "GAME.0x00002000": "also kept",
        "GAME.0x00003000": "new",
    }
    assert _raw(tmp_path, "sqlite").read("test") == toml
