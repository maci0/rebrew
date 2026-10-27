"""Experimental transactional SQLite persistence for managed metadata documents."""

import contextlib
import threading
lazy import hashlib
lazy import os
lazy import sqlite3
lazy import tomllib
lazy from collections.abc import Callable, Iterator
lazy from pathlib import Path
lazy from typing import Any

lazy import tomlkit
lazy from tomlkit.exceptions import ParseError

from rebrew.errors import RebrewError
lazy from rebrew.metadata.locking import file_transaction, project_transaction

DATABASE_FILENAME = "rebrew-metadata.sqlite3"
_SCHEMA_VERSION = 1
_CONNECTIONS = threading.local()


class MetadataStorageError(RebrewError, ValueError):
    """A metadata database is corrupt, incompatible, inaccessible or busy."""


def _connections() -> dict[Path, sqlite3.Connection]:
    connections: dict[Path, sqlite3.Connection] | None = getattr(_CONNECTIONS, "active", None)
    if connections is None:
        connections = {}
        _CONNECTIONS.active = connections
    return connections


class SqliteStore:
    """One logical metadata document inside a project SQLite database.

    Document encoding remains TOML to preserve the full existing value domain,
    including dates, without lossy JSON conversions or executable deserialization.
    """

    name = "sqlite"

    def __init__(self, path: Path, root: Path) -> None:
        self.path = path
        self.root = root
        self.location = root / DATABASE_FILENAME
        self.key = path.relative_to(root).as_posix()
        if ".." in Path(self.key).parts:
            raise MetadataStorageError(f"{path}: metadata path must stay inside {root}")

    def _check_schema(self, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != _SCHEMA_VERSION:
            raise MetadataStorageError(f"{self.location}: unsupported metadata schema {version}")

    @contextlib.contextmanager
    def _reader(self) -> Iterator[sqlite3.Connection | None]:
        active = _connections().get(self.location)
        if active is not None:
            yield active
            return
        try:
            self.location.stat()
        except FileNotFoundError:
            yield None
            return
        try:
            with contextlib.closing(
                sqlite3.connect(self.location.as_uri() + "?mode=ro", uri=True, timeout=30)
            ) as connection:
                self._check_schema(connection)
                yield connection
        except sqlite3.Error as exc:
            raise MetadataStorageError(f"{self.location}: {exc}") from exc

    def _row(self) -> tuple[str, int] | None:
        with self._reader() as connection:
            if connection is None:
                return None
            row = connection.execute(
                "SELECT content, revision FROM metadata_documents WHERE path = ?", (self.key,)
            ).fetchone()
            return (str(row[0]), int(row[1])) if row else None

    def read(
        self,
        description: str,
        *,
        validate: Callable[[Any], Any] | None = None,
        roundtrip: bool = False,
    ) -> dict[str, Any]:
        """Read a committed document without creating a missing database."""
        row = self._row()
        if row is None:
            return {}
        try:
            doc = tomlkit.parse(row[0]) if roundtrip else tomllib.loads(row[0])
        except (tomllib.TOMLDecodeError, ParseError) as exc:
            raise MetadataStorageError(
                f"{self.location}: invalid {description} for {self.key}: {exc}"
            ) from exc
        if validate is not None:
            validate(doc)
        return doc

    def write(self, doc: dict[str, Any], description: str) -> None:
        """Replace a document atomically, advancing its revision only on change."""
        content = tomlkit.dumps(doc)
        with self.transaction():
            connection = _connections()[self.location]
            connection.execute(
                "INSERT INTO metadata_documents(path, content, revision) VALUES (?, ?, 1) "
                "ON CONFLICT(path) DO UPDATE SET content=excluded.content, revision=revision+1 "
                "WHERE metadata_documents.content != excluded.content",
                (self.key, content),
            )

    def exists(self) -> bool:
        """Whether this logical document exists, independently of other stores."""
        with self._reader() as connection:
            return (
                connection is not None
                and connection.execute(
                    "SELECT 1 FROM metadata_documents WHERE path = ?", (self.key,)
                ).fetchone()
                is not None
            )

    def inputs(self) -> tuple[Path, ...]:
        """The canonical database and its rollback journal, including missing inputs."""
        return self.location, self.location.with_name(self.location.name + "-journal")

    def fingerprint(self) -> tuple[tuple[str, int, int, int, int], ...]:
        """Fingerprint the committed document and its physical database."""
        with self._reader() as connection:
            if connection is None:
                return ()
            row = connection.execute(
                "SELECT revision FROM metadata_documents WHERE path = ?", (self.key,)
            ).fetchone()
        if row is None:
            return ()
        stat = self.location.stat()
        return (
            (str(self.location), stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino),
            (self.key, int(row[0]), 0, 0, _SCHEMA_VERSION),
        )

    def snapshot(self) -> bytes | None:
        """Return a stable logical snapshot, independent of database page layout."""
        row = self._row()
        return row[0].encode() if row else None

    def digest(self) -> str | None:
        """Hash the logical document used by reviewed edits."""
        content = self.snapshot()
        return hashlib.sha256(content).hexdigest() if content is not None else None

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """Use one reentrant BEGIN IMMEDIATE transaction for all stores in this database."""
        with (
            project_transaction(self.root, self.path.name),
            file_transaction(self.location.parent, self.location.name),
        ):
            connections = _connections()
            if self.location in connections:
                yield
                return
            self.location.parent.mkdir(parents=True, exist_ok=True)
            existed = self.location.exists()
            committed = False
            if existed:
                self.location.chmod(0o644)
            try:
                with contextlib.closing(
                    sqlite3.connect(self.location, timeout=30, isolation_level=None)
                ) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    version = connection.execute("PRAGMA user_version").fetchone()[0]
                    if version == 0:
                        tables = connection.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                        if tables:
                            raise MetadataStorageError(
                                f"{self.location}: not a Rebrew metadata database"
                            )
                        connection.execute(
                            "CREATE TABLE metadata_documents(path TEXT PRIMARY KEY, revision INTEGER NOT NULL, content TEXT NOT NULL)"
                        )
                        connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                    self._check_schema(connection)
                    connections[self.location] = connection
                    try:
                        yield
                        connection.commit()
                        committed = True
                    except BaseException:
                        connection.rollback()
                        raise
                    finally:
                        connections.pop(self.location, None)
            except sqlite3.Error as exc:
                raise MetadataStorageError(f"{self.location}: {exc}") from exc
            finally:
                if not existed and not committed:
                    self.location.unlink(missing_ok=True)
                elif self.location.exists():
                    os.chmod(self.location, 0o444)

    def remove(self) -> None:
        """Remove this logical store without affecting other documents."""
        with self.transaction():
            _connections()[self.location].execute(
                "DELETE FROM metadata_documents WHERE path = ?", (self.key,)
            )

    def documents(self, *, recursive: bool = False) -> tuple[Path, ...]:
        """List logical metadata paths persisted in this database."""
        with self._reader() as connection:
            if connection is None:
                return ()
            result = []
            for (key,) in connection.execute("SELECT path FROM metadata_documents ORDER BY path"):
                path = self.root / key
                if (
                    Path(key).is_absolute()
                    or ".." in Path(key).parts
                    or not path.resolve().is_relative_to(self.root)
                ):
                    raise MetadataStorageError(f"{self.location}: invalid metadata path {key!r}")
                if path.is_relative_to(self.path.parent) and (
                    recursive or path.parent == self.path.parent
                ):
                    result.append(path)
            return tuple(result)
