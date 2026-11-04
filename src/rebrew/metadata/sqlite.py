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
#: The one DDL this store creates.  ``_check_schema`` compares the stored
#: ``CREATE TABLE`` against it so a database whose table was hand-altered to
#: drop the primary key or the revision check is rejected instead of being
#: trusted — ``user_version`` alone cannot tell those apart.
_EXPECTED_DDL = (
    "CREATE TABLE metadata_documents(path TEXT NOT NULL PRIMARY KEY, "
    "revision INTEGER NOT NULL CHECK (revision > 0), content TEXT NOT NULL)"
)
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
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='metadata_documents'"
        ).fetchone()
        if row is None or " ".join(str(row[0]).split()) != _EXPECTED_DDL:
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
                    connection.execute("PRAGMA journal_mode = DELETE")
                    connection.execute("PRAGMA synchronous = FULL")
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
                            "CREATE TABLE metadata_documents(path TEXT NOT NULL PRIMARY KEY, revision INTEGER NOT NULL CHECK (revision > 0), content TEXT NOT NULL)"
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


METADATA_BACKUP_FILENAME = "rebrew-metadata.backup.sqlite3"
METADATA_TOML_BACKUP_DIRNAME = "rebrew-metadata.backup.toml"

#: The four managed TOML collections, mirrored from
#: :data:`rebrew.metadata.files.METADATA_FILENAMES` without importing it
#: (that module imports the locking helper this module uses).
_TOML_STORE_NAMES = (
    "rebrew-functions.toml",
    "rebrew-data.toml",
    "rebrew-types.toml",
    "rebrew-libraries.toml",
)

#: Destination name for a TOML backup bundle: one directory holding the
#: trees as they were on disk, so a restore is a copy back, not a merge.
TOML_BACKUP_DIRNAME = METADATA_TOML_BACKUP_DIRNAME


def _toml_store_tree(root: Path, name: str) -> list[Path]:
    """Main TOML plus its ``.d/*.toml`` drop-ins, when present."""
    main = root / name
    tree = [main] if main.is_file() else []
    dropins = main.with_suffix(".d")
    if dropins.is_dir():
        tree.extend(
            sorted(p for p in dropins.iterdir() if p.suffix == ".toml" and p.is_file())
        )
    return tree


def _toml_stores_present(root: Path) -> list[tuple[str, list[Path]]]:
    """Non-empty ``(name, tree)`` pairs for the managed TOML stores."""
    present = []
    for name in _TOML_STORE_NAMES:
        tree = _toml_store_tree(root, name)
        if tree:
            present.append((name, tree))
    return present


def backup_metadata_toml(root: Path, backup_dir: Path) -> Path:
    """Copy every present managed TOML store tree to *backup_dir*.

    The TOML backend is the default, yet ``rebrew metadata backup`` only
    ever copied the experimental SQLite database, so a default project
    had no backup command for its durable stores.  Each tree is copied
    under the same relative layout (main file plus ``.d/`` drop-ins)
    through the shared atomic replace, and every copied byte is compared
    against its source, so a short copy raises instead of reporting
    success.  A project with no TOML store raises ``FileNotFoundError``
    rather than writing an empty bundle a restore would mistake for a
    backup.  Returns the bundle directory.
    """
    from rebrew.utils import atomic_write_bytes

    present = _toml_stores_present(root)
    if not present:
        raise FileNotFoundError(f"no metadata stores at {root}")
    bundle = backup_dir / TOML_BACKUP_DIRNAME
    for _name, tree in present:
        for source in tree:
            dest = bundle / source.relative_to(root)
            payload = source.read_bytes()
            atomic_write_bytes(dest, payload, mode=0o444)
            if dest.read_bytes() != payload:
                raise MetadataStorageError(f"{dest}: backup verification failed")
    return bundle


def restore_metadata_toml(bundle: Path, root: Path) -> tuple[Path, ...]:
    """Install a bundle made by :func:`backup_metadata_toml` back into *root*.

    Every current store tree is first preserved as ``<file>.before-restore``
    beside it, so a restore pointed at the wrong bundle is itself
    reversible.  A bundle file that does not parse as TOML raises and
    leaves the current stores alone.  Returns the installed paths.
    """
    from rebrew.utils import atomic_write_bytes, load_tomllib

    if not bundle.is_dir():
        raise FileNotFoundError(f"no metadata backup bundle at {bundle}")
    planned = []
    for name in _TOML_STORE_NAMES:
        for source in _toml_store_tree(bundle, name):
            try:
                load_tomllib(source)
            except (ValueError, OSError) as exc:
                raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
            planned.append(source.relative_to(bundle))
    if not planned:
        raise FileNotFoundError(f"no metadata stores in backup bundle at {bundle}")
    installed = []
    for rel in planned:
        raw = (bundle / rel).read_bytes()
        dest = root / rel
        if dest.is_file():
            atomic_write_bytes(
                dest.with_name(dest.name + ".before-restore"), dest.read_bytes(), mode=0o444
            )
        atomic_write_bytes(dest, raw, mode=0o444)
        if dest.read_bytes() != raw:
            raise MetadataStorageError(f"{dest}: restored copy verification failed")
        installed.append(dest)
    return tuple(installed)


def backup_metadata_database(root: Path, backup_dir: Path) -> Path:
    """Copy the SQLite metadata database to *backup_dir* via the backup API.

    A plain file copy of a live SQLite database can capture a torn page
    image if a writer is mid-transaction; ``sqlite3``'s online backup API
    copies a transactionally consistent snapshot instead.  The copy is
    then opened read-only and its schema version and row count checked,
    so a backup that cannot be restored raises here rather than at
    restore time.  A missing database raises ``FileNotFoundError``.
    """
    from rebrew.metadata.locking import file_transaction

    location = root / DATABASE_FILENAME
    if not location.is_file():
        raise FileNotFoundError(f"no metadata database at {location}")
    dest = backup_dir / METADATA_BACKUP_FILENAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    # A previous backup left this destination read-only (0444, below); the
    # backup API opens its target for writing, so a re-run would fail with
    # "attempt to write a readonly database" unless the mode is relaxed
    # first (the copy is re-sealed 0444 after verification).
    with contextlib.suppress(OSError):
        if dest.exists():
            dest.chmod(0o644)
    with file_transaction(location.parent, location.name):
        source = sqlite3.connect(location.as_uri() + "?mode=ro", uri=True, timeout=30)
        try:
            with contextlib.closing(sqlite3.connect(dest, timeout=30)) as target:
                source.backup(target)
        finally:
            source.close()
    os.chmod(dest, 0o444)
    check = sqlite3.connect(dest.as_uri() + "?mode=ro", uri=True, timeout=30)
    try:
        version = check.execute("PRAGMA user_version").fetchone()[0]
        count = check.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[0]
    except sqlite3.Error as exc:
        raise MetadataStorageError(f"{dest}: backup verification failed: {exc}") from exc
    finally:
        check.close()
    if version != _SCHEMA_VERSION:
        raise MetadataStorageError(f"{dest}: unsupported metadata schema version {version}")
    if count == 0:
        # An empty database is a valid state only if the source is empty;
        # re-check the source so a torn copy cannot pass silently.
        src = sqlite3.connect(location.as_uri() + "?mode=ro", uri=True, timeout=30)
        try:
            src_count = src.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[0]
        finally:
            src.close()
        if src_count:
            raise MetadataStorageError(f"{dest}: backup is empty but source holds {src_count} rows")
    return dest


def restore_metadata_database(backup: Path, root: Path) -> Path:
    """Install a backup made by :func:`backup_metadata_database` as the database.

    The current database, if any, is first preserved as
    ``rebrew-metadata.sqlite3.before-restore`` beside it.  The backup is
    validated (schema version, integrity) before anything is written; a
    corrupt backup raises and leaves the current database alone. The
    restored bytes are built in a sibling temp file and published with
    ``os.replace`` plus fsyncs, so a crash cannot leave a torn database
    at the live path.
    """
    from rebrew.metadata.locking import file_transaction

    if not backup.is_file():
        raise FileNotFoundError(f"no metadata database backup at {backup}")
    check = sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True, timeout=30)
    try:
        version = check.execute("PRAGMA user_version").fetchone()[0]
        integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
        try:
            count = check.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[0]
        except sqlite3.Error as exc:
            raise MetadataStorageError(f"{backup}: corrupt backup: {exc}") from exc
    except sqlite3.Error as exc:
        raise MetadataStorageError(f"{backup}: corrupt backup: {exc}") from exc
    finally:
        check.close()
    if version != _SCHEMA_VERSION:
        raise MetadataStorageError(f"{backup}: unsupported metadata schema version {version}")
    if integrity != "ok":
        raise MetadataStorageError(f"{backup}: integrity check failed: {integrity}")
    location = root / DATABASE_FILENAME
    location.parent.mkdir(parents=True, exist_ok=True)
    with file_transaction(location.parent, location.name):
        if location.is_file():
            preserved = location.with_name(location.name + ".before-restore")
            # As in backup_metadata_database: a previous restore left the
            # preserved copy read-only (0444), and the backup API would
            # refuse to write it on a second restore.
            with contextlib.suppress(OSError):
                if preserved.exists():
                    preserved.chmod(0o644)
            source = sqlite3.connect(location.as_uri() + "?mode=ro", uri=True, timeout=30)
            try:
                with contextlib.closing(sqlite3.connect(preserved, timeout=30)) as target:
                    source.backup(target)
            finally:
                source.close()
            os.chmod(preserved, 0o444)
        import time

        tmp = location.with_name(f"{location.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
        try:
            source = sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True, timeout=30)
            try:
                with contextlib.closing(sqlite3.connect(tmp, timeout=30)) as target:
                    source.backup(target)
            finally:
                source.close()
            # Verify the staged copy before it becomes the live database.
            staged = sqlite3.connect(tmp.as_uri() + "?mode=ro", uri=True, timeout=30)
            try:
                staged_version = staged.execute("PRAGMA user_version").fetchone()[0]
                staged_integrity = staged.execute("PRAGMA integrity_check").fetchone()[0]
                staged_count = staged.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[
                    0
                ]
            except sqlite3.Error as exc:
                raise MetadataStorageError(
                    f"{backup}: restored copy verification failed: {exc}"
                ) from exc
            finally:
                staged.close()
            if (
                staged_version != _SCHEMA_VERSION
                or staged_integrity != "ok"
                or staged_count != count
            ):
                raise MetadataStorageError(f"{backup}: restored copy verification failed")
            # fsync the staged file, publish atomically, fsync the directory.
            fd = os.open(tmp, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(tmp, 0o444)
            os.replace(tmp, location)
            dir_fd = os.open(location.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
    return location
