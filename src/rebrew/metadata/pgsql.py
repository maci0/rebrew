"""Project-scoped PostgreSQL persistence for managed TOML documents."""

import contextlib
import threading
from typing import TYPE_CHECKING
lazy import hashlib
lazy import tomllib
lazy from collections.abc import Iterator
lazy from pathlib import Path
lazy from typing import Any

if TYPE_CHECKING:
    from psycopg import Connection

lazy import tomlkit
lazy from tomlkit.exceptions import ParseError

lazy from rebrew.metadata.locking import project_transaction
lazy from rebrew.metadata.sqlite import MetadataStorageError, MetadataUnavailableError
lazy from rebrew.utils import load_tomllib

_CONNECTIONS = threading.local()
_TABLE = "public.rebrew_metadata_documents"
_DDL = f"""CREATE TABLE IF NOT EXISTS {_TABLE} (
    project TEXT NOT NULL,
    path TEXT NOT NULL,
    content TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    PRIMARY KEY (project, path)
)"""


def validate_pgsql_settings(raw: Any) -> None:
    """Require an explicit connection and stable project namespace."""
    if not isinstance(raw, dict) or set(raw) != {"dsn", "project"}:
        raise ValueError("[metadata.pgsql] requires only dsn and project")
    for key in ("dsn", "project"):
        if not isinstance(raw[key], str) or not raw[key].strip() or "\0" in raw[key]:
            raise ValueError(f"[metadata.pgsql].{key} must be a nonempty string without NUL")


def _driver() -> Any:
    """Load the optional driver only when PostgreSQL storage is used."""
    try:
        import psycopg
    except ImportError:
        raise MetadataUnavailableError(
            "PostgreSQL metadata requires rebrew[pgsql] and the system libpq library"
        ) from None
    return psycopg


def _connections() -> dict[tuple[str, str], Any]:
    active: dict[tuple[str, str], Any] | None = getattr(_CONNECTIONS, "active", None)
    if active is None:
        active = {}
        _CONNECTIONS.active = active
    return active


class PgsqlStore:
    """One document in a shared database, isolated by an explicit project key."""

    name = "pgsql"

    def __init__(self, path: Path, root: Path) -> None:
        self.path = path
        self.root = root
        self.location = root / "rebrew-project.toml"
        self.key = path.relative_to(root).as_posix()
        if ".." in Path(self.key).parts or not path.resolve().is_relative_to(root):
            raise MetadataStorageError("metadata path must stay inside the project")
        settings = load_tomllib(self.location).get("metadata", {}).get("pgsql", {})
        validate_pgsql_settings(settings)
        self.dsn = settings["dsn"]
        self.project = settings["project"]
        self.identity = (self.dsn, self.project)

    @contextlib.contextmanager
    def _connection(self) -> Iterator[Connection[tuple[str | int, ...]]]:
        active = _connections().get(self.identity)
        driver = _driver()
        try:
            if active is not None:
                yield active
                return
            with driver.connect(self.dsn, connect_timeout=30, autocommit=True) as connection:
                yield connection
        except driver.OperationalError:
            raise MetadataUnavailableError("PostgreSQL metadata backend unavailable") from None
        except driver.Error:
            # Server diagnostics can contain connection passwords or document content.
            raise MetadataStorageError("PostgreSQL metadata operation failed") from None

    def _present(self, connection: Any) -> bool:
        if connection.execute("SELECT to_regclass(%s)", (_TABLE,)).fetchone()[0] is None:
            return False
        columns = connection.execute(
            "SELECT attname, format_type(atttypid, atttypmod), attnotnull FROM pg_attribute "
            "WHERE attrelid = to_regclass(%s) AND attnum > 0 AND NOT attisdropped "
            "ORDER BY attnum",
            (_TABLE,),
        ).fetchall()
        if columns != [
            ("project", "text", True),
            ("path", "text", True),
            ("content", "text", True),
            ("revision", "bigint", True),
            ("schema_version", "integer", True),
        ]:
            raise MetadataStorageError("unsupported PostgreSQL metadata schema")
        return True

    def _row(self) -> tuple[str, int] | None:
        with self._connection() as connection:
            if not self._present(connection):
                return None
            row = connection.execute(
                "SELECT content, revision, schema_version FROM public.rebrew_metadata_documents "
                "WHERE project = %s AND path = %s",
                (self.project, self.key),
            ).fetchone()
            if row is None:
                return None
            if row[2] != 1 or int(row[1]) < 1:
                raise MetadataStorageError("unsupported PostgreSQL metadata schema")
            return str(row[0]), int(row[1])

    def read(
        self, description: str, *, validate: Any = None, roundtrip: bool = False
    ) -> dict[str, Any]:
        """Read and validate without creating tables or rows."""
        row = self._row()
        if row is None:
            return {}
        try:
            doc = tomlkit.parse(row[0]) if roundtrip else tomllib.loads(row[0])
        except tomllib.TOMLDecodeError, ParseError:
            raise MetadataStorageError(f"invalid {description} for {self.key}") from None
        if validate is not None:
            validate(doc)
        return doc

    def write(self, doc: dict[str, Any], description: str) -> None:
        """Replace a document, preserving its revision when content is unchanged."""
        content = tomlkit.dumps(doc) or "\n"
        with self.transaction(), self._connection() as connection:
            self._row()
            connection.execute(
                "INSERT INTO public.rebrew_metadata_documents AS current "
                "(project, path, content, schema_version) VALUES (%s, %s, %s, 1) "
                "ON CONFLICT (project, path) DO UPDATE "
                "SET content = excluded.content, revision = current.revision + 1 "
                "WHERE current.content <> excluded.content",
                (self.project, self.key, content),
            )

    def exists(self) -> bool:
        """Whether the selected project contains this document."""
        return self._row() is not None

    def snapshot(self) -> bytes | None:
        """Return the complete logical document for review guards."""
        row = self._row()
        return row[0].encode() if row else None

    def digest(self) -> str | None:
        """Hash a complete logical snapshot."""
        content = self.snapshot()
        return hashlib.sha256(content).hexdigest() if content is not None else None

    def fingerprint(self) -> tuple[tuple[str, int, int, int, int], ...]:
        """Detect remote edits and delete/recreate cycles without local file changes."""
        row = self._row()
        if row is None:
            return ()
        token = int.from_bytes(hashlib.sha256(row[0].encode()).digest(), "big")
        scope = hashlib.sha256(repr(self.identity).encode()).hexdigest()
        return ((scope + ":" + self.key, row[1], token, 0, 1),)

    def inputs(self) -> tuple[Path, ...]:
        """Watch connection settings; remote edits are detected by fingerprints."""
        return (self.location,)

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """Serialize project writers across clients, sharing one reentrant transaction."""
        with project_transaction(self.root, self.path.name):
            if self.identity in _connections():
                yield
                return
            with self._connection() as connection, connection.transaction():
                connection.execute("SET LOCAL lock_timeout = '30s'")
                if not self._present(connection):
                    # Serialize first-use DDL across projects sharing the same database.
                    connection.execute("SELECT pg_advisory_xact_lock(%s)", (7354829341,))
                    connection.execute(_DDL)
                lock = int.from_bytes(
                    hashlib.sha256(self.project.encode()).digest()[:8], "big", signed=True
                )
                connection.execute("SELECT pg_advisory_xact_lock(%s)", (lock,))
                _connections()[self.identity] = connection
                try:
                    yield
                finally:
                    _connections().pop(self.identity, None)

    def remove(self) -> None:
        """Delete this document without affecting other projects or documents."""
        with self.transaction(), self._connection() as connection:
            self._row()
            connection.execute(
                "DELETE FROM public.rebrew_metadata_documents WHERE project = %s AND path = %s",
                (self.project, self.key),
            )

    def documents(self, *, recursive: bool = False) -> tuple[Path, ...]:
        """Discover project-relative document paths in the configured namespace."""
        with self._connection() as connection:
            if not self._present(connection):
                return ()
            rows = connection.execute(
                "SELECT path FROM public.rebrew_metadata_documents WHERE project = %s ORDER BY path",
                (self.project,),
            ).fetchall()
        result = []
        for (raw_key,) in rows:
            key = str(raw_key)
            if key == ".rebrew/metadata-replication.toml":
                continue
            path = self.root / key
            if (
                Path(key).is_absolute()
                or ".." in Path(key).parts
                or not path.resolve().is_relative_to(self.root)
            ):
                raise MetadataStorageError("invalid PostgreSQL metadata path")
            if path.is_relative_to(self.path.parent) and (
                recursive or path.parent == self.path.parent
            ):
                result.append(path)
        return tuple(result)
