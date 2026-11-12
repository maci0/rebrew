"""PostgreSQL metadata contract; integration cases use REBREW_TEST_PGSQL_DSN."""

import os
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import tomlkit

from rebrew.config import load_config
from rebrew.metadata.functions import get_entry, update_field
from rebrew.metadata.pgsql import PgsqlStore
from rebrew.metadata.sqlite import MetadataStorageError
from rebrew.metadata.storage import metadata_store, metadata_write_lock, validate_backend_settings
from rebrew.metadata_transfer import migrate_metadata

_DSN = os.environ.get("REBREW_TEST_PGSQL_DSN")


def _project(root: Path, *, project: str | None = None, backend: str = "pgsql") -> Any:
    root.mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir(exist_ok=True)
    doc = {
        "project": {"default_target": "game", "shared_dir": ""},
        "targets": {"game": {"binary": "game.exe", "reversed_dir": "src", "module": "GAME"}},
        "metadata": {"backend": backend, "pgsql": {"dsn": _DSN, "project": project or uuid4().hex}},
    }
    (root / "rebrew-project.toml").write_text(tomlkit.dumps(doc))
    return load_config(root)


def _replicated_project(root: Path, project: str) -> Any:
    _project(root, project=project)
    path = root / "rebrew-project.toml"
    doc = tomlkit.parse(path.read_text())
    del doc["metadata"]["backend"]
    doc["metadata"]["read_backends"] = ["pgsql", "sqlite", "toml"]
    doc["metadata"]["write_backends"] = ["pgsql", "sqlite", "toml"]
    path.write_text(tomlkit.dumps(doc))
    return load_config(root)


def _store(root: Path, name: str = "rebrew-functions.toml") -> Any:
    return metadata_store(root / name)


def _increment(root: str, count: int) -> None:
    for _ in range(count):
        with metadata_write_lock(Path(root), "rebrew-functions.toml"):
            value = get_entry(Path(root), 0x1000, "GAME").get("size", 0)
            update_field(Path(root), 0x1000, "SIZE", value + 1, "GAME")


class TestPgsqlConfig:
    @pytest.mark.parametrize(
        "settings",
        [
            None,
            {},
            {"dsn": "service=test"},
            {"dsn": "", "project": "game"},
            {"dsn": "service=test", "project": ""},
            {"dsn": "service=test", "project": "game", "typo": True},
        ],
    )
    def test_invalid_settings(self, settings: dict[str, str | bool] | None) -> None:
        with pytest.raises(ValueError, match="metadata.pgsql"):
            validate_backend_settings({"backend": "pgsql", "pgsql": settings})

    def test_connection_can_be_configured_before_migration(self) -> None:
        assert (
            validate_backend_settings(
                {"backend": "toml", "pgsql": {"dsn": "service=rebrew", "project": "game"}}
            )
            == "toml"
        )

    def test_driver_is_optional_and_error_has_install_hint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys

        from rebrew.metadata import pgsql

        monkeypatch.setitem(sys.modules, "psycopg", None)
        with pytest.raises(MetadataStorageError, match=r"rebrew\[pgsql\]"):
            pgsql._driver()

    def test_schema_check_rejects_table_without_constraints(self) -> None:
        from rebrew.metadata import pgsql

        columns = [
            ("project", "text", True),
            ("path", "text", True),
            ("content", "text", True),
            ("revision", "bigint", True),
            ("schema_version", "integer", True),
        ]

        def make_connection(pk_columns: Any, check_defs: Any) -> Any:
            class _Cursor:
                def __init__(self, rows: Any) -> None:
                    self._rows = rows

                def fetchone(self) -> Any:
                    r = self._rows
                    return r[0]

                def fetchall(self) -> Any:
                    return self._rows

            class _Connection:
                def execute(self, sql: str, params: Any = None) -> Any:
                    if sql.startswith("SELECT to_regclass"):
                        return _Cursor([("public.rebrew_metadata_documents",)])
                    if "unnest(i.indkey)" in sql:
                        return _Cursor([(name,) for name in pk_columns])
                    if "pg_attribute" in sql:
                        return _Cursor(columns)
                    if "pg_constraint" in sql:
                        return _Cursor([(defn,) for defn in check_defs])
                    raise AssertionError(sql)

            return _Connection()

        store = pgsql.PgsqlStore.__new__(pgsql.PgsqlStore)
        ok_pk = ["project", "path"]
        ok_checks = ["CHECK ((revision > 0))", "CHECK ((schema_version = 1))"]
        connection = make_connection(ok_pk, ok_checks)
        assert store._present(connection) is True
        # A validated schema is remembered on the connection; asking again
        # must not re-run the catalog queries.
        def _not_called(sql: str, params: Any = None) -> Any:
            raise AssertionError(sql)

        connection.execute = _not_called
        assert store._present(connection) is True
        for pk_columns, check_defs in (
            ([], ok_checks),
            (["content"], ok_checks),
            # Index order, not table order: ON CONFLICT (project, path) does
            # not infer PRIMARY KEY (path, project).
            (["path", "project"], ok_checks),
            (ok_pk, []),
            (ok_pk, ["CHECK ((revision < 0))"]),
            (ok_pk, ["CHECK ((schema_version = 1))"]),
            (ok_pk, ok_checks + ["CHECK ((content > ''))"]),
        ):
            with pytest.raises(
                MetadataStorageError, match="unsupported PostgreSQL metadata schema"
            ):
                store._present(make_connection(pk_columns, check_defs))

        # Absence is not cached.  A catalog read that fails is reported as
        # unavailable by the caller; remembering it as "no table" would make
        # the next call on this connection skip validation.
        class _Flaky:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, sql: str, params: Any = None) -> Any:
                self.calls += 1
                if sql.startswith("SELECT to_regclass"):

                    class _Empty:
                        def fetchone(self) -> Any:
                            return (None,)

                    return _Empty()
                raise AssertionError(sql)

        flaky = _Flaky()
        assert store._present(flaky) is False
        assert store._present(flaky) is False
        assert flaky.calls == 2

    @pytest.mark.parametrize("command", ["backup", "restore"])
    def test_file_backup_commands_reject_postgresql(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
    ) -> None:
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.metadata_cli as cli

        monkeypatch.setattr(
            cli,
            "require_config",
            lambda **kwargs: SimpleNamespace(root=tmp_path, metadata_backend="pgsql"),
        )
        option = "--dir" if command == "backup" else "--file"
        result = CliRunner().invoke(cli.app, [command, option, str(tmp_path / "backup"), "--json"])
        assert result.exit_code == 2
        assert "pg_dump" in result.output if command == "backup" else "pg_restore" in result.output
        assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(not _DSN, reason="set REBREW_TEST_PGSQL_DSN for PostgreSQL integration")
class TestPgsqlStore:
    def test_contract_and_project_isolation(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        assert cfg.metadata_backend == "pgsql"
        store = _store(tmp_path)
        assert isinstance(store, PgsqlStore)
        assert store.read("test") == {}
        assert store.snapshot() is None and store.digest() is None
        assert store.fingerprint() == () and not store.exists()
        assert store.documents() == ()
        doc = tomlkit.parse("# context\nformat = 3\n")
        doc["stamp"] = datetime(2026, 1, 2, tzinfo=UTC)
        doc["note"] = "café"
        store.write(doc, "test")
        assert store.read("test") == dict(doc)
        assert b"# context" in (store.snapshot() or b"")
        fp = store.fingerprint()
        store.write(doc, "test")
        assert store.fingerprint() == fp
        other_root = tmp_path / "other"
        _project(other_root)
        assert not _store(other_root).exists()
        doc["note"] = "changed"
        store.write(doc, "test")
        assert store.fingerprint() != fp
        assert store.documents() == (store.path,)
        store.remove()
        assert not store.exists()

    def test_shared_checkout_reads_remote_changes(self, tmp_path: Path) -> None:
        project = uuid4().hex
        first, second = tmp_path / "one", tmp_path / "two"
        _project(first, project=project)
        _project(second, project=project)
        update_field(first, 0x1000, "NOTE", "before", "GAME")
        assert get_entry(second, 0x1000, "GAME")["note"] == "before"
        update_field(first, 0x1000, "NOTE", "after", "GAME")
        assert get_entry(second, 0x1000, "GAME")["note"] == "after"

    def test_transaction_rolls_back_all_documents(self, tmp_path: Path) -> None:
        _project(tmp_path)
        functions, data = _store(tmp_path), _store(tmp_path, "rebrew-data.toml")
        functions.write({"format": 3}, "test")
        with pytest.raises(RuntimeError, match="abort"), functions.transaction():
            functions.write({"format": 3, "note": "temporary"}, "test")
            data.write({"format": 2}, "test")
            raise RuntimeError("abort")
        assert functions.read("test") == {"format": 3}
        assert not data.exists()

    def test_migration_roundtrip_preserves_destination(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path, backend="toml")
        update_field(tmp_path, 0x1000, "NOTE", "original", "GAME")
        migrate_metadata(cfg, "pgsql")
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "original"
        update_field(tmp_path, 0x1000, "NOTE", "remote", "GAME")
        migrate_metadata(load_config(tmp_path), "toml")
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "remote"
        update_field(tmp_path, 0x1000, "NOTE", "local", "GAME")
        migrate_metadata(load_config(tmp_path), "pgsql")
        snapshot = tmp_path / ".rebrew/pgsql-before-transfer/rebrew-functions.toml"
        assert b"remote" in snapshot.read_bytes()
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "local"

    def test_concurrent_checkouts_do_not_lose_updates(self, tmp_path: Path) -> None:
        project = uuid4().hex
        roots = [tmp_path / str(i) for i in range(2)]
        for root in roots:
            _project(root, project=project)
        with ProcessPoolExecutor(2) as pool:
            futures = [pool.submit(_increment, str(root), 5) for root in roots]
            for future in futures:
                future.result(timeout=30)
        assert get_entry(roots[0], 0x1000, "GAME")["size"] == 10

    def test_live_coverage_fingerprint_detects_remote_updates(self, tmp_path: Path) -> None:
        from rebrew.coverage_project import coverage_inputs

        project = uuid4().hex
        first, second = tmp_path / "one", tmp_path / "two"
        cfg = _project(first, project=project)
        _project(second, project=project)
        update_field(first, 0x1000, "NOTE", "before", "GAME")
        before = coverage_inputs(cfg)
        update_field(second, 0x1000, "NOTE", "after", "GAME")
        assert coverage_inputs(cfg) != before

    def test_coordinated_edit_rolls_back_source_and_metadata(self, tmp_path: Path) -> None:
        from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction

        _project(tmp_path)
        source = tmp_path / "src/a.c"
        source.write_text("int f(void) { return 1; }\n")
        update_field(tmp_path, 0x1000, "NOTE", "before", "GAME")
        inputs = coordinated_inputs(tmp_path, [source])
        with (
            pytest.raises(RuntimeError, match="abort"),
            coordinated_transaction(tmp_path, [source], expected_inputs=inputs) as staged,
        ):
            staged.publish(source, b"replacement")
            update_field(tmp_path, 0x1000, "NOTE", "temporary", "GAME")
            raise RuntimeError("abort")
        assert source.read_text() == "int f(void) { return 1; }\n"
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "before"

    def test_failed_migration_keeps_source_and_destination(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.data import set_data_field

        cfg = _project(tmp_path, backend="toml")
        update_field(tmp_path, 0x1000, "NOTE", "source", "GAME")
        set_data_field(tmp_path, 0x4000, "size", 8, "GAME")
        destination = metadata_store(tmp_path / "rebrew-functions.toml", backend="pgsql")
        destination.write({"format": 3}, "test")
        original = PgsqlStore.write

        def fail(self: PgsqlStore, doc: dict[str, Any], description: str) -> None:
            if self.path.name == "rebrew-functions.toml":
                raise RuntimeError("injected failure")
            original(self, doc, description)

        monkeypatch.setattr(PgsqlStore, "write", fail)
        with pytest.raises(RuntimeError, match="injected failure"):
            migrate_metadata(cfg, "pgsql")
        assert load_config(tmp_path).metadata_backend == "toml"
        assert destination.read("test") == {"format": 3}
        data = metadata_store(tmp_path / "rebrew-data.toml", backend="pgsql")
        assert not data.exists()
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "source"

    def test_backend_errors_do_not_expose_connection_credentials(self, tmp_path: Path) -> None:
        _project(tmp_path)
        store = _store(tmp_path)
        store.dsn = "host=127.0.0.1 port=1 password=private-connection-secret"
        with pytest.raises(MetadataStorageError) as caught:
            store.read("test")
        assert "private-connection-secret" not in str(caught.value)
        assert caught.value.__suppress_context__

    def test_all_three_backends_recover_after_postgresql_publication_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata_transfer import reconcile_metadata

        cfg = _replicated_project(tmp_path, uuid4().hex)
        update_field(tmp_path, 0x1000, "NOTE", "before", "GAME")
        original = PgsqlStore.write

        def fail(self: PgsqlStore, doc: dict[str, Any], description: str) -> None:
            if self.path.name == "rebrew-functions.toml":
                raise OSError("connection lost during publication")
            original(self, doc, description)

        with monkeypatch.context() as patch:
            patch.setattr(PgsqlStore, "write", fail)
            update_field(tmp_path, 0x1000, "NOTE", "queued", "GAME")
        path = tmp_path / "rebrew-functions.toml"
        assert (
            metadata_store(path, backend="pgsql").read("test")["GAME.0x00001000"]["note"]
            == "before"
        )
        assert get_entry(tmp_path, 0x1000, "GAME")["note"] == "queued"
        assert not any(item["pending"] for item in reconcile_metadata(cfg)["items"])
        documents = [
            metadata_store(path, backend=backend).read("test")
            for backend in ("pgsql", "sqlite", "toml")
        ]
        assert documents[0] == documents[1] == documents[2]

    def test_independent_checkouts_conflict_even_when_one_clock_is_ahead(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from rebrew.metadata import replication
        from rebrew.metadata.sqlite import MetadataUnavailableError
        from rebrew.metadata_transfer import reconcile_metadata

        project = uuid4().hex
        first, second = tmp_path / "one", tmp_path / "two"
        cfg = _replicated_project(first, project)
        _replicated_project(second, project)
        update_field(first, 0x1000, "NOTE", "base", "GAME")
        # Seed the second checkout with the same known causal version.
        reconcile_metadata(load_config(second))

        def unavailable(*args: Any, **kwargs: Any) -> Any:
            raise MetadataUnavailableError("offline")

        with monkeypatch.context() as patch:
            patch.setattr(PgsqlStore, "transaction", unavailable)
            patch.setattr(PgsqlStore, "read", unavailable)
            patch.setattr(time, "time_ns", lambda: 8_000_000_000_000_000_000)
            update_field(first, 0x1000, "NOTE", "offline first", "GAME")
        update_field(second, 0x1000, "NOTE", "online second", "GAME")
        with pytest.raises(replication.MetadataConflictError):
            reconcile_metadata(cfg)
        remote = metadata_store(second / "rebrew-functions.toml", backend="pgsql")
        assert remote.read("test")["GAME.0x00001000"]["note"] == "online second"
        local = metadata_store(first / "rebrew-functions.toml", backend="toml")
        assert local.read("test")["GAME.0x00001000"]["note"] == "offline first"

    def test_invalid_remote_path_is_rejected(self, tmp_path: Path) -> None:
        import psycopg

        _project(tmp_path)
        store = _store(tmp_path)
        store.write({"format": 3}, "test")
        with psycopg.connect(_DSN or "") as connection:
            connection.execute(
                "INSERT INTO public.rebrew_metadata_documents(project, path, content) "
                "VALUES (%s, %s, %s)",
                (store.project, "../escape.toml", "format = 3"),
            )
        with pytest.raises(MetadataStorageError, match="invalid.*path"):
            store.documents(recursive=True)
