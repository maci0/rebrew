"""Backend contracts, domain parity and reviewed metadata transfers."""

import ast
import multiprocessing
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import tomlkit
from typer.testing import CliRunner

from rebrew.config import load_config, project_toml_lock
from rebrew.metadata.data import get_data_entry, load_data_metadata, set_data_field
from rebrew.metadata.functions import (
    get_entry,
    load_metadata,
    record_function_identity,
    update_field,
    update_source_status,
)
from rebrew.metadata.source_provenance import (
    document_assembly,
    load_source_files,
    load_source_provenance,
    set_source_file,
)
from rebrew.metadata.sqlite import DATABASE_FILENAME, MetadataStorageError
from rebrew.metadata.storage import (
    input_digest,
    metadata_inputs,
    metadata_store,
    metadata_write_lock,
    project_metadata_stores,
)
from rebrew.metadata_transfer import migrate_metadata
from rebrew.workspace.config import walk_up_to_root


def _project(root: Path, backend: str = "toml") -> Any:
    (root / "src").mkdir(exist_ok=True)
    (root / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "game"\nshared_dir = ""\n'
        '[targets.game]\nbinary = "game.exe"\nreversed_dir = "src"\nmodule = "GAME"\n'
        f'[metadata]\nbackend = "{backend}"\n'
    )
    return load_config(root)


def _increment(root: str, count: int) -> None:
    directory = Path(root)
    for _ in range(count):
        with metadata_write_lock(directory, "rebrew-functions.toml"):
            value = get_entry(directory, 0x1000, "GAME").get("size", 0)
            update_field(directory, 0x1000, "SIZE", value + 1, "GAME")


class TestBackendContract:
    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_writable_reads_preserve_document_comments(self, tmp_path: Path, backend: str) -> None:
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend=backend, root=tmp_path)
        store.write(
            tomlkit.parse('# keep review context\nformat = 2\n["GAME.0x1000"]\nsize = 4\n'), "test"
        )
        doc = store.read("test", roundtrip=True)
        doc["GAME.0x1000"]["size"] = 8
        store.write(doc, "test")
        assert b"# keep review context" in (store.snapshot() or b"")
        assert store.read("test")["GAME.0x1000"]["size"] == 8

    def test_registered_backend_obeys_the_storage_contract(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import rebrew.metadata.storage as storage
        from rebrew.metadata.files import TomlStore

        class CustomStore(TomlStore):
            name = "custom"

        monkeypatch.setattr(storage, "_BACKENDS", None)
        monkeypatch.setattr(
            storage,
            "iter_optional_provider_dicts",
            lambda *args, **kwargs: iter(
                [(SimpleNamespace(origin="test"), {"custom": CustomStore, "toml": CustomStore})]
            ),
        )
        assert set(storage.refresh_metadata_backends()) == {"toml", "sqlite", "custom"}
        _project(tmp_path, "custom")
        update_field(tmp_path, 0x1000, "NOTE", "plugin", "GAME")
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "plugin"
        assert storage.metadata_store(tmp_path / "rebrew-functions.toml").name == "custom"
        assert "duplicate name or invalid factory" in caplog.text

    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_read_write_snapshot_remove_and_value_types(self, tmp_path: Path, backend: str) -> None:
        path = tmp_path / "rebrew-functions.toml"
        store = metadata_store(path, backend=backend, root=tmp_path)
        assert store.read("test") == {}
        assert store.snapshot() is None and store.digest() is None
        assert not store.exists() and store.fingerprint() == ()
        assert list(tmp_path.iterdir()) == []
        stamp = datetime(2026, 1, 2, tzinfo=UTC)
        document = {
            "format": 2,
            "GAME.0x1000": {
                "note": "café",
                "size": 4,
                "nested": {"when": stamp, "array": [1, "two"]},
            },
        }
        store.write(document, "test")
        assert store.exists() and store.read("test") == document
        assert (
            store.digest() == input_digest(path)
            if backend == "toml"
            else store.digest() is not None
        )
        before = store.fingerprint()
        snapshot = store.snapshot()
        store.write(document, "test")
        assert store.snapshot() == snapshot
        document["GAME.0x1000"]["size"] = 8  # type: ignore[index]
        store.write(document, "test")
        assert store.read("test")["GAME.0x1000"]["size"] == 8
        assert store.fingerprint() != before
        assert store.location.stat().st_mode & 0o777 == 0o444
        store.remove()
        assert not store.exists() and store.read("test") == {}

    def test_unknown_backend_and_invalid_settings_fail_closed(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "typo"\n')
        with pytest.raises(ValueError, match="unknown metadata backend"):
            load_metadata(tmp_path)
        assert not (tmp_path / DATABASE_FILENAME).exists()

    def test_corrupt_and_future_schema_databases_are_not_replaced(self, tmp_path: Path) -> None:
        path = tmp_path / DATABASE_FILENAME
        path.write_bytes(b"not a sqlite database")
        store = metadata_store(tmp_path / "rebrew-functions.toml", backend="sqlite", root=tmp_path)
        for action in (lambda: store.read("test"), lambda: store.write({"format": 2}, "test")):
            with pytest.raises(MetadataStorageError):
                action()
        assert path.read_bytes() == b"not a sqlite database"
        path.unlink()
        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA user_version = 999")
        with pytest.raises(MetadataStorageError, match="unsupported metadata schema"):
            store.read("test")

    def test_existing_non_rebrew_database_is_not_adopted(self, tmp_path: Path) -> None:
        path = tmp_path / DATABASE_FILENAME
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE important(value TEXT)")
            connection.execute("INSERT INTO important VALUES ('keep')")
        store = metadata_store(tmp_path / "rebrew-data.toml", backend="sqlite", root=tmp_path)
        with pytest.raises(MetadataStorageError, match="not a Rebrew"):
            store.write({"format": 2}, "test")
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            assert connection.execute("SELECT value FROM important").fetchone() == ("keep",)


class TestSqliteDomainParity:
    def test_all_five_owners_read_and_write_selected_backend(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.library import app
        from rebrew.metadata.functions import find_library_override
        from rebrew.type_metadata import bind_type, load_types

        cfg = _project(tmp_path, "sqlite")
        file = tmp_path / "src/a.c"
        file.write_text("int f(void) { return 0; }\n")
        record_function_identity(
            tmp_path, module="GAME", va=0x1000, file="src/a.c", name="f", kind="FUNCTION", size=4
        )
        update_source_status(tmp_path, "EXACT", "GAME", 0x1000, force=True)
        set_data_field(tmp_path, 0x4000, "size", 4, "GAME")
        document_assembly(tmp_path, file, "f", "GAME", "reviewed original")
        set_source_file(tmp_path, "src/helper.c", "GAME", "support")
        header = tmp_path / "src/types.h"
        header.write_text("typedef struct ITEM { int x; } ITEM;\n")
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        monkeypatch.setattr(
            "rebrew.type_metadata._inputs",
            lambda *args: dict.fromkeys(
                ("source_hash", "headers_hash", "context_hash", "binary_hash"), "a" * 64
            ),
        )
        bind_type(cfg, "item", header, "ITEM", 4, 4, "allocation", "native", {})
        result = CliRunner().invoke(app, ["set", str(file.parent), "--cflags=/Od"])
        assert result.exit_code == 0, result.output
        assert get_entry(tmp_path, 0x1000, "GAME")["status"] == "EXACT"
        assert get_data_entry(tmp_path, 0x4000, "GAME")["size"] == 4
        assert load_source_provenance(tmp_path)[0].evidence == "reviewed original"
        assert load_source_files(tmp_path)[0].purpose == "support"
        assert load_types(tmp_path)[0]["id"] == "item"
        override = find_library_override(file.parent, tmp_path)
        assert override is not None and override.cflags == "/Od"
        assert not list(tmp_path.glob("rebrew-functions.toml"))
        assert not list(tmp_path.rglob("rebrew-libraries.toml"))
        assert (tmp_path / DATABASE_FILENAME).is_file()
        assert cfg.metadata_backend == "sqlite"
        assert len(project_metadata_stores(tmp_path, recursive=True)) == 4
        assert tmp_path / DATABASE_FILENAME in metadata_inputs(tmp_path)

    def test_status_gate_and_validation_are_shared(self, tmp_path: Path) -> None:
        _project(tmp_path, "sqlite")
        update_source_status(tmp_path, "SKIP", "GAME", 0x1000, force=True)
        update_source_status(tmp_path, "EXACT", "GAME", 0x1000)
        assert get_entry(tmp_path, 0x1000, "GAME")["status"] == "SKIP"
        with pytest.raises(ValueError):
            update_field(tmp_path, 0x1000, "STATUS", "EXACT", "GAME")
        assert get_entry(tmp_path, 0x1000, "GAME")["status"] == "SKIP"

    def test_multi_store_transaction_rolls_back_and_missing_database_stays_missing(
        self, tmp_path: Path
    ) -> None:
        _project(tmp_path, "sqlite")
        with (
            pytest.raises(RuntimeError, match="abort"),
            metadata_write_lock(tmp_path, "rebrew-functions.toml"),
        ):
            update_field(tmp_path, 0x1000, "SIZE", 4, "GAME")
            set_data_field(tmp_path, 0x4000, "size", 8, "GAME")
            raise RuntimeError("abort")
        assert not (tmp_path / DATABASE_FILENAME).exists()
        assert load_metadata(tmp_path) == {} and load_data_metadata(tmp_path) == {}
        update_field(tmp_path, 0x1000, "SIZE", 4, "GAME")
        before = metadata_store(tmp_path / "rebrew-functions.toml").snapshot()
        with pytest.raises(RuntimeError), metadata_write_lock(tmp_path, "rebrew-functions.toml"):
            update_field(tmp_path, 0x1000, "SIZE", 16, "GAME")
            raise RuntimeError("abort")
        assert metadata_store(tmp_path / "rebrew-functions.toml").snapshot() == before

    def test_thread_and_process_writers_do_not_drop_updates(self, tmp_path: Path) -> None:
        _project(tmp_path, "sqlite")
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(lambda _: _increment(str(tmp_path), 5), range(2)))
        assert get_entry(tmp_path, 0x1000, "GAME")["size"] == 10
        context = multiprocessing.get_context("spawn")
        processes = [context.Process(target=_increment, args=(str(tmp_path), 5)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(30)
        assert all(process.exitcode == 0 for process in processes)
        assert get_entry(tmp_path, 0x1000, "GAME")["size"] == 20

    def test_cache_and_review_digest_notice_database_writes(self, tmp_path: Path) -> None:
        from rebrew.metadata.data import patch_data_fields_batch

        _project(tmp_path, "sqlite")
        set_data_field(tmp_path, 0x4000, "size", 4, "GAME")
        updates = [{"module": "GAME", "va": 0x4000, "fields": {"name": "g"}}]
        preview = patch_data_fields_batch(tmp_path, updates, dry_run=True)
        assert load_data_metadata(tmp_path)[("GAME", 0x4000)]["size"] == 4
        set_data_field(tmp_path, 0x4000, "size", 8, "GAME")
        assert load_data_metadata(tmp_path)[("GAME", 0x4000)]["size"] == 8
        with pytest.raises(ValueError, match="changed since preview"):
            patch_data_fields_batch(tmp_path, updates, expected_digest=preview["input_digest"])


class TestMetadataTransfer:
    def test_source_cache_keeps_the_backend_used_for_its_fingerprint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.files import TomlStore

        _project(tmp_path)
        set_source_file(tmp_path, "src/helper.c", "GAME", "toml purpose")
        path = tmp_path / "rebrew-functions.toml"
        doc = metadata_store(path).read("test")
        doc["source"]["files"]["src/helper.c"]["GAME"]["purpose"] = "sqlite purpose"
        metadata_store(path, backend="sqlite").write(doc, "test")
        config = tmp_path / "rebrew-project.toml"
        original = config.read_text()
        fingerprint = TomlStore.fingerprint

        def switch_after_fingerprint(self: TomlStore) -> Any:
            result = fingerprint(self)
            if self.path == path:
                config.write_text(original.replace('backend = "toml"', 'backend = "sqlite"'))
            return result

        with monkeypatch.context() as patch:
            patch.setattr(TomlStore, "fingerprint", switch_after_fingerprint)
            assert load_source_files(tmp_path)[0].purpose == "toml purpose"
        config.write_text(original)
        assert load_source_files(tmp_path)[0].purpose == "toml purpose"

    def test_waiting_writer_reselects_backend_after_migration(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata.storage as storage

        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "NOTE", "before", "GAME")
        path = tmp_path / "rebrew-functions.toml"
        original = path.read_bytes()
        resolved = threading.Event()
        real_store = storage.metadata_store

        def observe(*args: Any, **kwargs: Any) -> Any:
            store = real_store(*args, **kwargs)
            if threading.current_thread().name.startswith("writer"):
                resolved.set()
            return store

        monkeypatch.setattr(storage, "metadata_store", observe)
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="writer") as executor:
            with project_toml_lock(tmp_path):
                pending = executor.submit(update_field, tmp_path, 0x1000, "NOTE", "after", "GAME")
                assert resolved.wait(5)
                migrate_metadata(cfg, "sqlite")
            pending.result(timeout=10)
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "after"
        assert path.read_bytes() == original

    def test_round_trip_preserves_dropins_and_source_bytes(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        record_function_identity(
            tmp_path, module="GAME", va=0x1000, file="src/a.c", name="f", kind="FUNCTION", size=4
        )
        update_source_status(tmp_path, "EXACT", "GAME", 0x1000, force=True)
        main = tmp_path / "rebrew-functions.toml"
        directory = main.with_suffix(".d")
        directory.mkdir()
        shard = directory / "game.toml"
        main.rename(shard)
        before = shard.read_bytes()
        purpose = "support"
        set_source_file(tmp_path, "src/helper.c", "GAME", purpose)
        preview = migrate_metadata(cfg, "sqlite", dry_run=True)
        assert not (tmp_path / DATABASE_FILENAME).exists()
        result = migrate_metadata(cfg, "sqlite", expected_digest=preview["input_digest"])
        assert result["changed"]
        assert shard.read_bytes() == before
        assert get_entry(tmp_path, 0x1000, "GAME")["status"] == "EXACT"
        update_field(tmp_path, 0x1000, "NOTE", "sqlite edit", "GAME")
        assert shard.read_bytes() == before
        assert load_source_files(tmp_path)[0].purpose == purpose
        migrate_metadata(load_config(tmp_path), "toml")
        assert load_config(tmp_path).metadata_backend == "toml"
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "sqlite edit"
        assert main.exists()  # The new source-purpose record owns the main document.
        assert (tmp_path / DATABASE_FILENAME).exists()

    def test_stale_preview_and_invalid_source_never_select_destination(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "SIZE", 4, "GAME")
        preview = migrate_metadata(cfg, "sqlite", dry_run=True)
        update_field(tmp_path, 0x1000, "SIZE", 8, "GAME")
        with pytest.raises(ValueError, match="changed since preview"):
            migrate_metadata(cfg, "sqlite", expected_digest=preview["input_digest"])
        assert load_config(tmp_path).metadata_backend == "toml"
        assert not (tmp_path / DATABASE_FILENAME).exists()
        source = tmp_path / "rebrew-source.toml"
        source.write_text("format = 1\n")
        with pytest.raises(ValueError, match="retired"):
            migrate_metadata(cfg, "sqlite")
        assert not (tmp_path / DATABASE_FILENAME).exists()

    def test_cli_preview_and_apply(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.metadata_cli import app

        _project(tmp_path)
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(app, ["migrate", "sqlite", "--dry-run", "--json"])
        assert result.exit_code == 0, result.output
        assert not (tmp_path / DATABASE_FILENAME).exists()
        assert runner.invoke(app, ["migrate", "sqlite", "--json"]).exit_code == 0
        assert load_config(tmp_path).metadata_backend == "sqlite"


class TestStorageBoundary:
    def test_domain_consumers_do_not_import_the_file_backend(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src/rebrew"
        violations = []
        for path in root.rglob("*.py"):
            if path.relative_to(root).as_posix() in {"metadata/files.py", "metadata/storage.py"}:
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.ImportFrom) and node.module == "rebrew.metadata.files":
                    violations.append(str(path.relative_to(root)))
        assert violations == []


class TestBackendIntegration:
    def test_sqlite_previews_do_not_create_or_touch_storage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.library import app
        from rebrew.metadata.data import move_data_entry
        from rebrew.metadata.source_provenance import rename_source_provenance

        _project(tmp_path, "sqlite")
        monkeypatch.chdir(tmp_path)
        before = set(tmp_path.rglob("*"))
        preview = CliRunner().invoke(app, ["set", "--library", "custom", "--dry-run"])
        assert preview.exit_code == 0, preview.output
        with pytest.raises(ValueError, match="no data row"):
            move_data_entry(tmp_path, "GAME", 0x1000, 0x2000, dry_run=True)
        assert set(tmp_path.rglob("*")) == before
        file = tmp_path / "src/a.c"
        old, new = "int f(void) { return 0; }", "int g(void) { return 0; }"
        file.write_text(old)
        document_assembly(tmp_path, file, "f", "GAME", "reviewed")
        set_data_field(tmp_path, 0x4000, "size", 4, "GAME")
        database = tmp_path / DATABASE_FILENAME
        original = database.read_bytes(), database.stat()
        rename_source_provenance(
            tmp_path, {file: (old, new)}, symbol_rename=("f", "g"), dry_run=True
        )
        move_data_entry(tmp_path, "GAME", 0x4000, 0x5000, dry_run=True)
        assert database.read_bytes() == original[0]
        assert database.stat().st_mtime_ns == original[1].st_mtime_ns
        assert database.stat().st_ctime_ns == original[1].st_ctime_ns

    def test_switching_back_does_not_resurrect_removed_library_settings(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        library = tmp_path / "src/rebrew-libraries.toml"
        metadata_store(library).write({"cflags": "/Od"}, "test")
        migrate_metadata(cfg, "sqlite")
        metadata_store(library).remove()
        assert library.exists()  # Inactive TOML is retained until a reviewed export.
        preview = migrate_metadata(load_config(tmp_path), "toml", dry_run=True)
        assert preview["removed_destination_stores"] == ["src/rebrew-libraries.toml"]
        migrate_metadata(load_config(tmp_path), "toml", expected_digest=preview["input_digest"])
        assert not library.exists()
        migrate_metadata(load_config(tmp_path), "sqlite")
        assert not metadata_store(library).exists()

    def test_destination_changes_invalidate_transfer_preview(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "SIZE", 4, "GAME")
        preview = migrate_metadata(cfg, "sqlite", dry_run=True)
        inactive = metadata_store(tmp_path / "rebrew-data.toml", backend="sqlite", root=tmp_path)
        inactive.write({"format": 2}, "test")
        with pytest.raises(ValueError, match="changed since preview"):
            migrate_metadata(cfg, "sqlite", expected_digest=preview["input_digest"])
        assert load_config(tmp_path).metadata_backend == "toml"

    def test_failed_transfer_does_not_select_partially_written_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.sqlite import SqliteStore

        cfg = _project(tmp_path)
        update_field(tmp_path, 0x1000, "SIZE", 4, "GAME")
        set_data_field(tmp_path, 0x4000, "size", 8, "GAME")
        before = {path: path.read_bytes() for path in tmp_path.glob("rebrew-*.toml")}
        real = SqliteStore.write

        def fail(self: SqliteStore, doc: dict[str, Any], description: str) -> None:
            if self.path.name == "rebrew-functions.toml":
                raise OSError("disk full")
            real(self, doc, description)

        monkeypatch.setattr(SqliteStore, "write", fail)
        with pytest.raises(OSError, match="disk full"):
            migrate_metadata(cfg, "sqlite")
        assert {path: path.read_bytes() for path in tmp_path.glob("rebrew-*.toml")} == before
        assert not (tmp_path / DATABASE_FILENAME).exists()

    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_live_coverage_and_cmake_use_selected_storage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        from bin_util import make_pe

        from rebrew.cmake_sources import app
        from rebrew.coverage_project import load_project_coverage

        _project(tmp_path, backend)
        (tmp_path / "game.exe").write_bytes(make_pe(b"\xc3"))
        (tmp_path / "src/a.c").write_text("int f(void) { return 0; }\n")
        record_function_identity(
            tmp_path, module="GAME", va=0x401000, file="src/a.c", name="f", kind="FUNCTION", size=1
        )
        update_source_status(tmp_path, "EXACT", "GAME", 0x401000, force=True)
        first = load_project_coverage(tmp_path, refresh=True)
        assert not first.failures
        assert first.snapshots["game"].functions[0].status == "EXACT"
        update_source_status(tmp_path, "NEAR_MATCHING", "GAME", 0x401000)
        second = load_project_coverage(tmp_path, refresh=True)
        assert second.versions != first.versions
        assert second.snapshots["game"].functions[0].status == "NEAR_MATCHING"
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--dry-run"])
        assert result.exit_code == 0, result.output
        assert "src/a.c" in result.output
        if backend == "sqlite":
            assert DATABASE_FILENAME in result.output
            assert "_rebrew_metadata_dropins" not in result.output
        else:
            assert "_rebrew_metadata_dropins" in result.output

    def test_lint_diagnostics_read_sqlite_documents(self, tmp_path: Path) -> None:
        from rebrew.lint import _check_W031_metadata_store, _check_W034_identity_paths

        cfg = _project(tmp_path, "sqlite")
        metadata_store(tmp_path / "rebrew-functions.toml").write(
            {"format": 2, "GAME.0x1000": {"file": "../outside.c", "typo": "bad"}}, "test"
        )
        assert _check_W031_metadata_store(cfg)
        assert _check_W034_identity_paths(cfg)

    def test_stray_store_lint_discovers_only_the_active_backend(self, tmp_path: Path) -> None:
        from rebrew.lint import _check_W036_stray_metadata_store

        cfg = _project(tmp_path, "sqlite")
        inactive = tmp_path / "old/rebrew-data.toml"
        metadata_store(inactive, backend="toml").write({"format": 2}, "test")
        stray = tmp_path / "other/rebrew-data.toml"
        metadata_store(stray).write({"format": 2}, "test")
        results = _check_W036_stray_metadata_store(cfg)
        assert [result.filepath for result in results] == [stray]


def test_store_resolution_caches_the_project_walk_and_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A whole-tree scan resolves the same store once per directory.

    Every cached metadata read asks for the store; the ancestor walk and the
    object construction are process-constant for one project.
    """
    import rebrew.metadata.storage as storage

    _project(tmp_path)
    path = tmp_path / "rebrew-functions.toml"
    storage.metadata_store(path)  # prime the process caches
    calls = {"n": 0}
    real = walk_up_to_root

    def counting(start: Path) -> Path | None:
        calls["n"] += 1
        return real(start)

    monkeypatch.setattr(storage, "walk_up_to_root", counting)
    first = storage.metadata_store(path)
    second = storage.metadata_store(path)
    assert calls["n"] == 0
    assert first is second


def test_hot_load_does_not_resolve_an_already_resolved_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cached read path is one fingerprint plus one cache lookup.

    The document cache is keyed on the resolved store path; resolving it again
    per read walked every component of a path the caller already resolved.
    """
    from rebrew.metadata.functions import clear_metadata_cache

    _project(tmp_path)
    record_function_identity(
        tmp_path, module="GAME", va=0x1000, file="src/f.c", name="f", kind="FUNCTION"
    )
    clear_metadata_cache()
    assert load_metadata(tmp_path)
    calls = {"n": 0}
    real = Path.resolve

    def counting(self: Path, *args: Any, **kwargs: Any) -> Path:
        calls["n"] += 1
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", counting)
    # The factory cache was primed above; repeated reads must not resolve the
    # already-resolved store path again.
    assert load_metadata(tmp_path)
    assert load_metadata(tmp_path)
    assert calls["n"] == 0


def test_project_root_cache_survives_scan_and_rechecks_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.metadata.storage as storage

    config = tmp_path / "rebrew-project.toml"
    paths = [tmp_path / f"dir{i}" / "rebrew-functions.toml" for i in range(96)]
    for path in paths:
        path.parent.mkdir()
    assert storage.metadata_store(paths[0]).name == "toml"
    config.write_text('[metadata]\nbackend = "sqlite"\n')
    assert all(storage.metadata_store(path).name == "sqlite" for path in paths)
    calls = 0
    real = storage.walk_up_to_root

    def counting(start: Path) -> Path | None:
        nonlocal calls
        calls += 1
        return real(start)

    monkeypatch.setattr(storage, "walk_up_to_root", counting)
    assert all(storage.metadata_store(path).name == "sqlite" for path in paths)
    assert calls == 0
    config.write_text('[metadata]\nbackend = "toml"\n')
    assert all(storage.metadata_store(path).name == "toml" for path in paths)
    config.unlink()
    assert all(storage.metadata_store(path).name == "toml" for path in paths)
    config.write_text('[metadata]\nbackend = "sqlite"\n')
    assert all(storage.metadata_store(path).name == "sqlite" for path in paths)


def test_project_root_cache_evicts_only_least_recently_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collections import OrderedDict

    import rebrew.metadata.storage as storage

    monkeypatch.setattr(storage, "_PROJECT_ROOTS", OrderedDict())
    monkeypatch.setattr(storage, "walk_up_to_root", lambda _: tmp_path)
    dirs = [tmp_path / str(i) for i in range(storage._PROJECT_ROOTS_MAX + 1)]
    for directory in dirs[:-1]:
        storage._project_root(directory)
    storage._project_root(dirs[0])
    storage._project_root(dirs[-1])
    assert len(storage._PROJECT_ROOTS) == storage._PROJECT_ROOTS_MAX
    assert dirs[0] in storage._PROJECT_ROOTS
    assert dirs[1] not in storage._PROJECT_ROOTS
