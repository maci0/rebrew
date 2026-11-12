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

__all__ = [
    "DATABASE_FILENAME",
    "METADATA_TOML_BACKUP_DIRNAME",
    "TOML_BACKUP_DIRNAME",
    "MetadataStorageError",
    "MetadataUnavailableError",
    "SqliteStore",
    "backup_metadata_database",
    "backup_metadata_toml",
    "extra_durable_sources",
    "metadata_paths",
    "restore_metadata_database",
    "restore_metadata_toml",
    "toml_store_trees",
    "verify_backup_manifest",
]

DATABASE_FILENAME = "rebrew-metadata.sqlite3"
_SCHEMA_VERSION = 2
#: The one DDL this store creates.  ``_check_schema`` compares the stored
#: ``CREATE TABLE`` against it so a database whose table was hand-altered to
#: drop the primary key or the revision check is rejected instead of being
#: trusted — ``user_version`` alone cannot tell those apart.  The integer
#: primary key makes SQLite pick a rowid alias (no ``sqlite_autoindex``
#: table), so the no-extra-indexes clause of ``_check_schema`` can stay
#: narrowly pinned; ``path`` keeps a UNIQUE constraint and every column
#: keeps its NOT NULL/CHECK, so the store's own access by ``path`` still
#: resolves on an index.
_EXPECTED_DDL = (
    "CREATE TABLE metadata_documents(id INTEGER NOT NULL PRIMARY KEY, "
    "path TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL CHECK (revision > 0), "
    "content TEXT NOT NULL)"
)
#: DDL of the 6.24.0 store (``path`` was the primary key, no surrogate ``id``).
#: Databases with this exact DDL are upgraded in place on first open: the
#: table is rebuilt under the new DDL, preserving every (path, revision,
#: content) row, so an upgrade is not a data loss and needs no manual
#: ``rebrew metadata migrate``.  Any other DDL is still rejected.
_LEGACY_DDL = (
    "CREATE TABLE metadata_documents(path TEXT NOT NULL PRIMARY KEY, "
    "revision INTEGER NOT NULL CHECK (revision > 0), content TEXT NOT NULL)"
)
_CONNECTIONS = threading.local()


def _check_database_schema(connection: sqlite3.Connection, location: Path) -> None:
    """Reject a database whose schema is not exactly the one this store creates."""
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version != _SCHEMA_VERSION:
        raise MetadataStorageError(f"{location}: unsupported metadata schema {version}")
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='metadata_documents'"
    ).fetchone()
    if row is None or " ".join(str(row[0]).split()) != _EXPECTED_DDL:
        raise MetadataStorageError(f"{location}: unsupported metadata schema {version}")
    extra = connection.execute(
        "SELECT type, name FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND NOT (type='table' AND name='metadata_documents') "
        "AND NOT (type='index' AND name='sqlite_autoindex_metadata_documents_1')"
    ).fetchall()
    if extra:
        raise MetadataStorageError(f"{location}: unsupported metadata schema {version}")


def _migrate_legacy_schema(connection: sqlite3.Connection, location: Path) -> None:
    """Rebuild a 6.24.0-era database under the current DDL, preserving rows.

    Runs inside the caller's ``BEGIN IMMEDIATE`` transaction, so a failure
    rolls back and leaves the original table untouched.  The legacy table has
    ``(path, revision, content)``; the new table adds a surrogate ``id`` (rowid
    alias) and keeps ``path`` UNIQUE.  Rows are copied in ``path`` order so
    ``id`` is deterministic.
    """
    tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    others = {name for (name,) in tables if name != "metadata_documents"}
    if others:
        raise MetadataStorageError(f"{location}: unsupported metadata schema 1")
    connection.execute("ALTER TABLE metadata_documents RENAME TO metadata_documents_legacy")
    connection.execute(_EXPECTED_DDL)
    connection.execute(
        "INSERT INTO metadata_documents(path, revision, content) "
        "SELECT path, revision, content FROM metadata_documents_legacy ORDER BY path"
    )
    connection.execute("DROP TABLE metadata_documents_legacy")
    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
    # A legacy database may carry stray indexes from the old UNIQUE/PK; the
    # rebuild above drops them with the old table, so only the new
    # autoindex remains.  Verify no extra survives.
    extra = connection.execute(
        "SELECT type, name FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND NOT (type='table' AND name='metadata_documents') "
        "AND NOT (type='index' AND name='sqlite_autoindex_metadata_documents_1')"
    ).fetchall()
    if extra:
        raise MetadataStorageError(f"{location}: unsupported metadata schema 1")


def _is_migratable_legacy(location: Path) -> bool:
    """Whether *location* is a 6.24.0 database eligible for in-place upgrade."""
    try:
        with contextlib.closing(
            sqlite3.connect(location.as_uri() + "?mode=ro", uri=True, timeout=30)
        ) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version != 1:
                return False
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='metadata_documents'"
            ).fetchone()
            return row is not None and " ".join(str(row[0]).split()) == _LEGACY_DDL
    except sqlite3.Error:
        return False


class MetadataStorageError(RebrewError, ValueError):
    """A metadata database is corrupt, incompatible, inaccessible or busy."""


class MetadataUnavailableError(MetadataStorageError):
    """A backend cannot currently be reached; another configured reader may be used."""


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
        _check_database_schema(connection, self.location)

    @contextlib.contextmanager
    def _reader(self) -> Iterator[sqlite3.Connection | None]:
        active = _connections().get(self.location)
        if active is not None:
            try:
                yield active
            except sqlite3.OperationalError as exc:
                raise MetadataUnavailableError(f"{self.location}: {exc}") from exc
            except sqlite3.Error as exc:
                raise MetadataStorageError(f"{self.location}: {exc}") from exc
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
                connection.execute("PRAGMA busy_timeout = 30000")
                try:
                    self._check_schema(connection)
                except MetadataStorageError:
                    # A 6.24.0 database (user_version 1, legacy DDL) is upgraded
                    # in place on first access, even for a read: the read-only
                    # check above rejects it, so upgrade through the write path
                    # and retry the read on the migrated database.
                    if not _is_migratable_legacy(self.location):
                        raise
                    with self.transaction():
                        pass
                    connection.execute("PRAGMA busy_timeout = 30000")
                    self._check_schema(connection)
                yield connection
        except sqlite3.OperationalError as exc:
            raise MetadataUnavailableError(f"{self.location}: {exc}") from exc
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
        content = tomlkit.dumps(doc) or "\n"
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
                try:
                    yield
                except sqlite3.OperationalError as exc:
                    raise MetadataUnavailableError(f"{self.location}: {exc}") from exc
                except sqlite3.Error as exc:
                    raise MetadataStorageError(f"{self.location}: {exc}") from exc
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
                    connection.execute("PRAGMA busy_timeout = 30000")
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
                        connection.execute(_EXPECTED_DDL)
                        connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                    elif version == 1:
                        row = connection.execute(
                            "SELECT sql FROM sqlite_master WHERE type='table' "
                            "AND name='metadata_documents'"
                        ).fetchone()
                        if row is None or " ".join(str(row[0]).split()) != _LEGACY_DDL:
                            raise MetadataStorageError(
                                f"{self.location}: unsupported metadata schema {version}"
                            )
                        _migrate_legacy_schema(connection, self.location)
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
            except sqlite3.OperationalError as exc:
                raise MetadataUnavailableError(f"{self.location}: {exc}") from exc
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
                if key == ".rebrew/metadata-replication.toml":
                    continue
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

#: Project config holding every target's paths and metadata backend choice.
#: Without it a restore has no root to install into and a re-pointed
#: ``metadata_dir`` would strand the restored stores.
_PROJECT_CONFIG_NAME = "rebrew-project.toml"

#: Manifest written into every backup bundle: the source-relative path of
#: every file backed up with its byte count and sha256, so a later reader
#: can confirm the bundle is complete and uncorrupted before restoring
#: (a backup never re-opened is a hypothesis, not a backup).  The
#: manifest is generated data, not durable state; restores ignore it.
BACKUP_MANIFEST_FILENAME = "rebrew-backup.manifest.json"
BACKUP_MANIFEST_VERSION = 1

#: Durable state under ``.rebrew/`` that git never sees (``.rebrew/`` is
#: gitignored) and that no regenerating command reproduces.  The GA log
#: holds win fingerprints a re-run cannot reproduce, and the BinSync
#: baselines hold the three-way reconciliation sidecars.  The metadata
#: backup bundle carries both so one off-tree backup covers the whole
#: project; the GA log also keeps its own ``rebrew match solutions
#: --backup`` spelling.  The decomp.me upload ledger holds claim tokens
#: whose loss re-uploads scratches already claimed on decomp.me; it is
#: durable for the same reason (90-day dedup window) and rides in the
#: same bundle.  The ledger is a single JSON object (not JSONL) and holds
#: credentials, so backups must keep it owner-only (0600): the writer in
#: ``rebrew.decompme.record_upload`` seals it 0600, and a 0444 bundle copy
#: would both broaden its exposure and strand the next in-place update.
_GA_RUNS_REL = Path(".rebrew") / "ga_runs.jsonl"
_SYNC_DIR_REL = Path(".rebrew") / "sync"
_UPLOADS_REL = Path(".rebrew") / "decompme-uploads.json"
_VERIFY_CACHE_REL = Path(".rebrew") / "verify_cache.toml"
_VERIFY_BASELINE_REL = Path(".rebrew") / "verify_baseline.toml"
_VERIFY_TARGETS_REL = Path(".rebrew") / "targets"
_GHIDRA_SYNC_STATE_REL = Path(".rebrew") / "ghidra_sync_state.json"
# Legacy JSON verify cache (pre-TOML migration). Still live: the TOML
# writer publishes it as a compat sidecar, so without it in the bundle a
# restore would lose the JSON view the next run reads first.
_VERIFY_JSON_REL = Path(".rebrew") / "verify_cache.json"
_NAME_COVER_REL = Path(".rebrew") / "name-map-cover.json"
_DATA_SCAN_ROLES_REL = Path(".rebrew") / "data-scan-roles.json"
_EXTERN_NAMES_REL = Path(".rebrew") / "extern-names.json"
_NAME_TO_VA_CACHE_REL = Path(".rebrew") / "name_to_va_cache.json"
_PGSQL_SNAPSHOT_DIR_REL = Path(".rebrew") / "pgsql-before-transfer"
_SNAPSHOTS_DIR_REL = Path("snapshots")
_SOURCE_BACKUP_DIR_REL = Path(".rebrew") / "source-backups"

#: Mode the uploads ledger must keep in backups and on restore: it holds
#: decomp.me claim tokens, so no group/other access, matching
#: ``rebrew.decompme._UPLOADS_FILE_MODE``.
_UPLOADS_MODE = 0o600

#: Mode for a BinSync state-dir copy in a bundle: a git repo, so keep it
#: writable for the next in-place git operation.
_BINSYNC_MODE = 0o644


def _load_json_object(source: Path) -> dict[str, Any]:
    import json as _json

    try:
        parsed = _json.loads(source.read_bytes())
    except (ValueError, OSError) as exc:
        raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
    if not isinstance(parsed, dict):
        raise MetadataStorageError(f"{source}: corrupt backup: not a JSON object")
    return parsed


def _validate_uploads_ledger(source: Path) -> None:
    """Validate the uploads ledger as one JSON object, or raise.

    The ledger is a single JSON document (``json.dumps`` of a dict in
    ``rebrew.decompme.record_upload``), not JSONL: validating it line by
    line as the GA log is would reject every real ledger, so a backup
    holding one could never be restored.  Only parseability as a JSON
    object is required here; entry shape stays ``read_uploads``' job,
    which filters fields and token format on each read.
    """
    parsed = _load_json_object(source)
    for digest, entry in parsed.items():
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(k), str) for k in ("slug", "claim_token", "api", "at")
        ):
            raise MetadataStorageError(f"{source}: corrupt backup: entry {digest!r} is incomplete")


def _validate_extra(source: Path) -> None:
    """Validate one ``.rebrew/`` extra durable file before it is installed."""
    if source == _GA_RUNS_REL or source.name == _GA_RUNS_REL.name:
        # The GA log is JSONL; validate every non-blank line parses as a
        # JSON object so a corrupt log cannot be installed.
        import json as _json

        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
        for lineno, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                parsed = _json.loads(line)
            except _json.JSONDecodeError as exc:
                raise MetadataStorageError(f"{source}: corrupt backup line {lineno}") from exc
            if not isinstance(parsed, dict):
                raise MetadataStorageError(f"{source}: corrupt backup line {lineno}")
    elif source.suffix == ".orig":
        # A kept source pre-image is opaque bytes (any encoding the source
        # used).  Nothing to parse; an unreadable copy is still corrupt.
        try:
            source.read_bytes()
        except OSError as exc:
            raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
        return
    elif source.suffix == ".json":
        # The uploads ledger validates as one JSON object with claim-token
        # entries; the Ghidra sync state is a plain dedup hash map where only
        # JSON-object parseability is required to block a corrupt install.
        if source.name == "decompme-uploads.json":
            _validate_uploads_ledger(source)
        else:
            _load_json_object(source)
    elif ".toml" in source.suffixes:
        from rebrew.utils import load_tomllib as _lt

        try:
            _lt(source)
        except (ValueError, OSError) as exc:
            raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
    else:
        raise MetadataStorageError(f"{source}: unrecognized durable file in backup")


def _extra_mode(source: Path) -> int:
    """Write mode for one ``.rebrew/`` extra, owner-only for the ledger."""
    if source.name == "decompme-uploads.json":
        return _UPLOADS_MODE
    return 0o444


def preserve_displaced(dest: Path, current: bytes, mode: int) -> None:
    """Record *current*, the bytes *dest* is about to lose, beside it.

    The sidecar is ``<name>.before-restore``.  A re-run that displaces the
    same bytes finds them already recorded and writes nothing.  A later run
    that displaces different bytes rotates the sidecar aside first
    (:func:`rotate_preserved_copy`), so every displaced copy survives and an
    oscillation between two states reuses the two copies instead of growing
    a new file each time.
    """
    preserved = dest.with_name(dest.name + ".before-restore")
    if preserved.is_file():
        kept = preserved.read_bytes()
        if kept == current:
            return
        rotate_preserved_copy(preserved, kept)
    from rebrew.utils import atomic_write_bytes

    atomic_write_bytes(preserved, current, mode=mode)


def rotate_preserved_copy(target: Path, held: bytes) -> None:
    """Move *target* aside so a newer preserved copy can take its name.

    A restore or transfer keeps the bytes it is about to replace under
    ``<name>.before-restore`` / ``<name>.before-transfer``.  Re-running the
    same operation finds those bytes already recorded and does nothing;
    running it again against different bytes used to overwrite the sidecar,
    which is the only copy of what the first run displaced.  Numbered
    siblings (``<name>.1``, ``<name>.2``, …) hold the earlier copies.  An
    identical sibling is reused, so oscillating between two states does not
    grow the set without bound.

    The copy lands before *target* is removed: a crash between the two
    leaves both, and the next rotation reuses the sibling instead of
    losing the bytes.
    """
    index = 1
    while True:
        sibling = target.with_name(f"{target.name}.{index}")
        if not sibling.exists():
            break
        if sibling.is_file() and sibling.read_bytes() == held:
            target.unlink()
            return
        index += 1
    from rebrew.utils import atomic_write_bytes

    atomic_write_bytes(sibling, held, mode=target.stat().st_mode & 0o777)
    if sibling.read_bytes() != held:
        raise OSError(f"preserved copy verification failed for {sibling}")
    target.unlink()


def _is_in_binsync_state(root: Path, source: Path) -> bool:
    """Whether *source* sits under a configured BinSync state dir at *root*."""
    rel = source.relative_to(root)
    return any(rel == b or b in rel.parents for b in _binsync_state_relpaths(root))


def _write_backup_manifest(bundle: Path, files: list[tuple[str, bytes]]) -> None:
    """Write the bundle manifest: relative path, size and sha256 per file.

    The manifest lists every file the backup wrote (never the manifest
    itself) so a later reader can confirm the bundle is complete before
    restoring.  ``files`` is ``(relative_path, payload)`` in write order.
    """
    import json as _json

    entries = [
        {
            "path": rel,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for rel, payload in files
    ]
    document = {"version": BACKUP_MANIFEST_VERSION, "files": entries}
    from rebrew.utils import atomic_write_bytes

    atomic_write_bytes(
        bundle / BACKUP_MANIFEST_FILENAME,
        (_json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o444,
    )


def verify_backup_manifest(bundle: Path) -> list[str]:
    """Confirm every file the bundle manifest lists is present and intact.

    Returns the manifest's relative paths on success.  A bundle with no
    manifest (an older backup), a corrupt manifest, a missing file or a
    size/sha256 mismatch raises ``MetadataStorageError`` — restore must
    not trust a bundle it has not re-opened.  Extra files the manifest
    does not list are allowed (the database backup carries the manifest
    beside the ``.sqlite3`` file).
    """
    import json as _json

    manifest = bundle / BACKUP_MANIFEST_FILENAME
    if not manifest.is_file():
        raise MetadataStorageError(
            f"{manifest}: backup has no manifest; refusing unverified restore"
        )
    try:
        document = _json.loads(manifest.read_bytes())
    except (ValueError, OSError) as exc:
        raise MetadataStorageError(f"{manifest}: corrupt backup manifest: {exc}") from exc
    if not isinstance(document, dict) or document.get("version") != BACKUP_MANIFEST_VERSION:
        raise MetadataStorageError(f"{manifest}: unsupported backup manifest version")
    entries = document.get("files")
    if not isinstance(entries, list):
        raise MetadataStorageError(f"{manifest}: corrupt backup manifest: files is not a list")
    checked: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise MetadataStorageError(
                f"{manifest}: corrupt backup manifest: entry is not an object"
            )
        rel = entry.get("path")
        size = entry.get("size")
        digest = entry.get("sha256")
        if not isinstance(rel, str) or not isinstance(size, int) or not isinstance(digest, str):
            raise MetadataStorageError(f"{manifest}: corrupt backup manifest: entry is incomplete")
        if Path(rel).is_absolute() or ".." in Path(rel).parts:
            raise MetadataStorageError(f"{manifest}: corrupt backup manifest: unsafe path {rel!r}")
        target = bundle / rel
        if not target.is_file():
            raise MetadataStorageError(f"{target}: backup manifest lists a missing file")
        payload = target.read_bytes()
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
            raise MetadataStorageError(f"{target}: backup manifest verification failed")
        checked.append(rel)
    if not checked:
        raise MetadataStorageError(f"{manifest}: backup manifest lists no files")
    return checked


def _kept(path: Path) -> bool:
    """A durable file, excluding a restore's own preserved copies.

    ``<name>.before-restore`` and the numbered copies a later restore
    rotated aside record what a restore displaced.  They are not project
    state, and backing them up would reinstall them on the next restore.
    """
    return path.is_file() and ".before-restore" not in path.name


def extra_durable_sources(root: Path) -> list[Path]:
    """GA log, BinSync baselines, upload ledger, journal, replication
    sidecar, verify cache/baseline, Ghidra sync state, the root
    scan caches (``name-map-cover.json``, ``data-scan-roles.json``),
    the extern-name cache (``extern-names.json``) and the name-to-VA cache
    (``name_to_va_cache.json``), the metadata-doc parsed-document caches,
    and coverage snapshots, when present.

    All live under the gitignored ``.rebrew/`` directory, so a backup
    that only walks the TOML store trees silently drops them: the
    GA wins have no regenerating command, losing the baselines
    loses the three-way decisions a later push/pull relied on, and
    losing the upload ledger re-uploads scratches already claimed on
    decomp.me.  The verify cache and ``--compare`` baseline ride
    along so a restored tree resumes verification without a full
    re-verify (they carry compiler/binary identity guards, so a
    stale copy degrades to a re-measure, not a wrong verdict).
    ``ghidra_sync_state.json`` is the pushed-op dedup map; loss
    re-pushes.  Backing up and restoring call this one function on
    the live tree and on the backup bundle respectively, so the two
    lists cannot drift.  Peer worktrees under ``.rebrew/sync/peers/``
    are transient snapshots and stay out.  The ``pgsql-before-transfer``
    snapshots are the only copy of the destination a ``metadata migrate
    pgsql`` replaced, so they ride along too; they are ``.toml`` only
    (nested paths are possible via ``metadata_dir``).  Coverage
    snapshots (``snapshots/coverage-*.toml``) carry the durable
    ``history[]`` status-transition log that ``coverage
    import-history`` imports; losing them loses the audit trail that
    cannot be regenerated without re-running every verification.
    The root scan caches (``name-map-cover.json``,
    ``data-scan-roles.json``) carry store-fingerprint-guarded parse
    facts; a stale copy degrades to a re-parse, never a wrong verdict,
    but losing them on restore forces a full re-scan.
    ``extern-names.json`` (``rebrew todo`` caller counts) and
    ``name_to_va_cache.json`` (single-file ``rebrew test`` name map)
    are the same kind: fingerprint-guarded, regenerable with a full
    re-scan, but that scan is a whole-tree parse, so they ride along
    to avoid paying it after a restore.
    """
    sources = []
    ga_runs = root / _GA_RUNS_REL
    if _kept(ga_runs):
        sources.append(ga_runs)
    uploads = root / _UPLOADS_REL
    if _kept(uploads):
        sources.append(uploads)
    for name in ("metadata-journal.toml", "metadata-replication.toml"):
        state = root / ".rebrew" / name
        if _kept(state):
            sources.append(state)
    for rel in (_VERIFY_CACHE_REL, _VERIFY_BASELINE_REL):
        candidate = root / rel
        if _kept(candidate):
            sources.append(candidate)
    targets_dir = root / _VERIFY_TARGETS_REL
    if targets_dir.is_dir():
        sources.extend(sorted(p for p in targets_dir.rglob("verify_cache.toml") if _kept(p)))
        sources.extend(sorted(p for p in targets_dir.rglob("verify_baseline.toml") if _kept(p)))
    ghidra_state = root / _GHIDRA_SYNC_STATE_REL
    if _kept(ghidra_state):
        sources.append(ghidra_state)
    for rel in (_NAME_COVER_REL, _DATA_SCAN_ROLES_REL, _EXTERN_NAMES_REL, _NAME_TO_VA_CACHE_REL):
        candidate = root / rel
        if _kept(candidate):
            sources.append(candidate)
    doc_cache_dir = root / ".rebrew" / "metadata-doc"
    if doc_cache_dir.is_dir():
        # Parsed-document caches carry hand-reviewed fingerprints; a
        # stale copy degrades to a re-parse, never a wrong verdict.
        sources.extend(sorted(p for p in doc_cache_dir.iterdir() if _kept(p)))
    sync_dir = root / _SYNC_DIR_REL
    if sync_dir.is_dir():
        sources.extend(sorted(p for p in sync_dir.iterdir() if p.suffix == ".toml" and _kept(p)))
    pgsql_snapshots = root / _PGSQL_SNAPSHOT_DIR_REL
    if pgsql_snapshots.is_dir():
        # ``*.toml`` is the latest snapshot; ``*.toml.<n>`` are the copies a
        # later transfer rotated aside so they were not overwritten.
        sources.extend(
            sorted(p for p in pgsql_snapshots.rglob("*") if _kept(p) and ".toml" in p.suffixes)
        )
    source_backups = root / _SOURCE_BACKUP_DIR_REL
    if source_backups.is_dir():
        # Kept pre-images of hand-edited sources a destructive command
        # rewrote or deleted (shared import, skeleton --force).  An
        # in-flight climb/qualifier copy is removed on a clean finish, so
        # what remains is the only copy of bytes the live tree no longer
        # holds.  ``*.before-restore`` is what the last restore displaced
        # and is not a second source of truth.
        sources.extend(
            sorted(
                p
                for p in source_backups.glob("*.orig")
                if p.is_file() and not p.name.endswith(".before-restore")
            )
        )
    snapshots = root / _SNAPSHOTS_DIR_REL
    if snapshots.is_dir():
        sources.extend(sorted(p for p in snapshots.glob("coverage-*.toml") if _kept(p)))
    verify_json = root / _VERIFY_JSON_REL
    if _kept(verify_json):
        sources.append(verify_json)
    return sources


def _toml_store_tree(root: Path, name: str) -> list[Path]:
    """Main TOML plus its ``.d/*.toml`` drop-ins, when present."""
    main = root / name
    tree = [main] if main.is_file() else []
    dropins = main.with_suffix(".d")
    if dropins.is_dir():
        tree.extend(sorted(p for p in dropins.iterdir() if p.suffix == ".toml" and p.is_file()))
    return tree


def toml_store_trees(root: Path) -> list[tuple[Path, list[Path]]]:
    """``(directory, tree)`` pairs for every managed store under *root*.

    Stores may sit in a nested ``metadata_dir`` (``cfg.metadata_dir``) rather
    than at the project root; the walk finds them anywhere below *root*.
    The walk skips nested projects (a directory holding its own
    ``rebrew-project.toml``) so an unrelated checkout is never swept in, and
    mirrors :data:`rebrew.metadata.files.TomlStore`'s pruning without
    importing it (that import would be a layering violation).
    """
    found: dict[Path, list[Path]] = {}
    for directory, folders, files in os.walk(root):
        parent = Path(directory)
        if parent != root and _PROJECT_CONFIG_NAME in files:
            folders[:] = []
            continue
        for name in _TOML_STORE_NAMES:
            if name in files:
                found.setdefault(parent, []).extend(metadata_paths(parent / name))
        folders[:] = [
            folder
            for folder in folders
            if not folder.startswith(".")
            and folder not in {"node_modules", "__pycache__"}
            and Path(folder).with_suffix(".toml").name not in _TOML_STORE_NAMES
        ]
    return sorted(found.items())


def metadata_paths(path: Path) -> tuple[Path, ...]:
    """Main TOML plus its ``.d/*.toml`` drop-ins, when present.

    Mirrors ``rebrew.metadata.files.metadata_paths`` without importing it
    (that module imports the locking helper this module uses).
    """
    try:
        path.stat()
    except FileNotFoundError:
        paths: list[Path] = []
    else:
        paths = [path]
    try:
        members = list(path.with_suffix(".d").iterdir())
    except FileNotFoundError, NotADirectoryError:
        members = []
    paths.extend(sorted(p for p in members if p.suffix == ".toml" and p.is_file()))
    return tuple(paths)


def _project_config(root: Path) -> Path | None:
    """The project config at *root*, when present."""
    candidate = root / _PROJECT_CONFIG_NAME
    return candidate if candidate.is_file() else None


def _config_relpaths(root: Path, key: str, *, want_dir: bool) -> list[Path]:
    """Project-relative paths named by *key* under ``[targets.*]`` at *root*.

    Only relative, in-tree entries that exist as the requested kind are
    returned (directory for BinSync state dirs, file for target binaries).
    A missing or unparseable config yields no paths.
    """
    config = root / _PROJECT_CONFIG_NAME
    if not config.is_file():
        return []
    try:
        raw = tomllib.loads(config.read_text(encoding="utf-8-sig"))
    except ValueError, OSError:
        return []
    targets = raw.get("targets")
    if not isinstance(targets, dict):
        return []
    rels: list[Path] = []
    for table in targets.values():
        if not isinstance(table, dict):
            continue
        entry = table.get(key)
        if not isinstance(entry, str) or not entry.strip():
            continue
        rel = Path(entry.strip())
        if rel.is_absolute() or ".." in rel.parts:
            continue
        if want_dir:
            if not (root / rel).is_dir():
                continue
        elif not (root / rel).is_file():
            continue
        rels.append(rel)
    return sorted(set(rels))


def _binsync_state_relpaths(root: Path) -> list[Path]:
    """Project-relative BinSync state-dir paths named by the project config."""
    return _config_relpaths(root, "binsync_state_dir", want_dir=True)


def _target_binary_relpaths(root: Path) -> list[Path]:
    """Project-relative target binaries named by the project config."""
    return _config_relpaths(root, "binary", want_dir=False)


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
    backup.  The project config is copied too: without it a bare store
    bundle cannot be installed into a fresh tree.  Returns the bundle
    directory.
    """
    from rebrew.utils import atomic_write_bytes

    trees = toml_store_trees(root)
    config = _project_config(root)
    extras = extra_durable_sources(root)
    if not trees:
        raise FileNotFoundError(f"no metadata stores at {root}")
    bundle = backup_dir / TOML_BACKUP_DIRNAME
    sources: list[Path] = []
    for _directory, tree in trees:
        sources.extend(tree)
    if config is not None:
        sources.append(config)
    for rel in _target_binary_relpaths(root):
        sources.append(root / rel)
    for rel in _binsync_state_relpaths(root):
        sources.extend(sorted(p for p in (root / rel).rglob("*") if p.is_file()))
    sources.extend(extras)
    written: list[tuple[str, bytes]] = []
    for source in sources:
        dest = bundle / source.relative_to(root)
        payload = source.read_bytes()
        mode = _BINSYNC_MODE if _is_in_binsync_state(root, source) else _extra_mode(source)
        atomic_write_bytes(dest, payload, mode=mode)
        if dest.read_bytes() != payload:
            raise MetadataStorageError(f"{dest}: backup verification failed")
        written.append((str(source.relative_to(root)), payload))
    _write_backup_manifest(bundle, written)
    return bundle


def restore_metadata_toml(bundle: Path, root: Path) -> tuple[Path, ...]:
    """Install a bundle made by :func:`backup_metadata_toml` back into *root*.

    Every current store tree is first preserved as ``<file>.before-restore``
    beside it, so a restore pointed at the wrong bundle is itself
    reversible.  A bundle file that does not parse as TOML raises and
    leaves the current stores alone.  The project config, when the bundle
    carries one, is installed first so a nested ``metadata_dir`` still
    resolves after the stores land.  Returns the installed paths.
    """
    from rebrew.utils import atomic_write_bytes, load_tomllib

    if not bundle.is_dir():
        raise FileNotFoundError(f"no metadata backup bundle at {bundle}")
    verify_backup_manifest(bundle)
    planned: list[Path] = []
    config = bundle / _PROJECT_CONFIG_NAME
    trees = toml_store_trees(bundle)
    if config.is_file():
        try:
            load_tomllib(config)
        except (ValueError, OSError) as exc:
            raise MetadataStorageError(f"{config}: corrupt backup: {exc}") from exc
        planned.append(config.relative_to(bundle))
    for _directory, tree in trees:
        for source in tree:
            try:
                load_tomllib(source)
            except (ValueError, OSError) as exc:
                raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
            planned.append(source.relative_to(bundle))
    for rel in _target_binary_relpaths(bundle):
        if rel not in planned:
            planned.append(rel)
    for rel in _binsync_state_relpaths(bundle):
        for source in sorted(p for p in (bundle / rel).rglob("*") if p.is_file()):
            entry = source.relative_to(bundle)
            if entry not in planned:
                planned.append(entry)
    extras = extra_durable_sources(bundle)
    for source in extras:
        rel = source.relative_to(bundle)
        _validate_extra(source)
        if rel not in planned:
            planned.append(rel)
    if not planned:
        raise FileNotFoundError(f"no metadata stores in backup bundle at {bundle}")
    if not any(rel.name in _TOML_STORE_NAMES for rel in planned):
        raise FileNotFoundError(f"no metadata stores in backup bundle at {bundle}")
    installed: list[tuple[Path, int]] = []
    # Snapshot destinations first: a mid-restore failure must roll back
    # already-installed files instead of leaving a half-restored store
    # (silent data loss — the pre-restore bytes survive only in
    # ``.before-restore`` sidecars, which a later run does not re-apply).
    before: dict[Path, bytes | None] = {}
    for rel in planned:
        dest = root / rel
        before[dest] = dest.read_bytes() if dest.is_file() else None
    try:
        for rel in planned:
            raw = (bundle / rel).read_bytes()
            dest = root / rel
            original = before[dest]
            mode = _BINSYNC_MODE if _is_in_binsync_state(root, dest) else _extra_mode(dest)
            if original is not None and original != raw:
                preserve_displaced(dest, original, mode)
            atomic_write_bytes(dest, raw, mode=mode)
            if dest.read_bytes() != raw:
                raise MetadataStorageError(f"{dest}: restored copy verification failed")
            installed.append((dest, mode))
    except BaseException:
        for dest, mode in reversed(installed):
            original = before[dest]
            if original is None:
                dest.unlink(missing_ok=True)
            else:
                atomic_write_bytes(dest, original, mode=mode)
        raise
    return tuple(dest for dest, _mode in installed)


def backup_metadata_database(root: Path, backup_dir: Path) -> Path:
    """Copy the SQLite metadata database to *backup_dir* via the backup API."""

    from rebrew.metadata.locking import file_transaction

    location = root / DATABASE_FILENAME
    if not location.is_file():
        raise FileNotFoundError(f"no metadata database at {location}")
    dest = backup_dir / METADATA_BACKUP_FILENAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    # A previous backup left this destination read-only (0444, below); the
    # backup API opens its target for writing, so a re-run would fail with
    # "attempt to write a readonly database" unless the mode is relaxed
    # first (the copy is re-sealed 0444 after verification). A chmod that
    # does not land must fail here: the backup API's later error names the
    # database, not the permission that blocked the replacement.
    if dest.exists():
        try:
            dest.chmod(0o644)
        except OSError as exc:
            raise MetadataStorageError(
                f"{dest}: cannot make the previous backup writable for replacement: {exc}"
            ) from exc
    with file_transaction(location.parent, location.name):
        db_source = sqlite3.connect(location.as_uri() + "?mode=ro", uri=True, timeout=30)
        try:
            with contextlib.closing(sqlite3.connect(dest, timeout=30)) as target:
                db_source.backup(target)
        finally:
            db_source.close()
    os.chmod(dest, 0o444)
    check = sqlite3.connect(dest.as_uri() + "?mode=ro", uri=True, timeout=30)
    try:
        _check_database_schema(check, dest)
        count = check.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[0]
    except sqlite3.Error as exc:
        raise MetadataStorageError(f"{dest}: backup verification failed: {exc}") from exc
    finally:
        check.close()
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
    from rebrew.utils import atomic_write_bytes

    written: list[tuple[str, bytes]] = [(METADATA_BACKUP_FILENAME, dest.read_bytes())]
    for rel in _target_binary_relpaths(root):
        payload = (root / rel).read_bytes()
        copied = backup_dir / rel
        atomic_write_bytes(copied, payload, mode=0o444)
        if copied.read_bytes() != payload:
            raise MetadataStorageError(f"{copied}: backup verification failed")
        written.append((str(rel), payload))
    for extra in extra_durable_sources(root):
        payload = extra.read_bytes()
        copied_extra = backup_dir / extra.relative_to(root)
        atomic_write_bytes(copied_extra, payload, mode=_extra_mode(extra))
        if copied_extra.read_bytes() != payload:
            raise MetadataStorageError(f"{copied_extra}: backup verification failed")
        written.append((str(extra.relative_to(root)), payload))
    for rel in _binsync_state_relpaths(root):
        for source in sorted(p for p in (root / rel).rglob("*") if p.is_file()):
            payload = source.read_bytes()
            copied_file = backup_dir / source.relative_to(root)
            atomic_write_bytes(copied_file, payload, mode=_BINSYNC_MODE)
            if copied_file.read_bytes() != payload:
                raise MetadataStorageError(f"{copied_file}: backup verification failed")
            written.append((str(source.relative_to(root)), payload))
    _write_backup_manifest(backup_dir, written)
    return dest


def restore_metadata_database(backup: Path, root: Path) -> Path:
    """Install a backup made by :func:`backup_metadata_database` as the database."""
    from rebrew.metadata.locking import file_transaction

    if not backup.is_file():
        raise FileNotFoundError(f"no metadata database backup at {backup}")
    verify_backup_manifest(backup.parent)
    check = sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True, timeout=30)
    try:
        _check_database_schema(check, backup)
        integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
        try:
            count = check.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[0]
        except sqlite3.Error as exc:
            raise MetadataStorageError(f"{backup}: corrupt backup: {exc}") from exc
    except MetadataStorageError:
        raise
    except sqlite3.Error as exc:
        raise MetadataStorageError(f"{backup}: corrupt backup: {exc}") from exc
    finally:
        check.close()
    if integrity != "ok":
        raise MetadataStorageError(f"{backup}: integrity check failed: {integrity}")
    _siblings: list[tuple[Path, Path]] = []
    _backup_root = backup.parent
    # Restore exactly what the backup carries: extra_durable_sources
    # walks the backup root the same way it walks a live project, so
    # the GA log, upload ledger, journal, replication sidecar, verify
    # cache/baseline (root and per-target), Ghidra sync state and
    # BinSync baselines all come back.  A hand-rolled sibling list
    # here once drifted from the backup list and silently dropped the
    # verify cache and Ghidra state on SQLite restore.
    for _src in extra_durable_sources(_backup_root):
        # _validate_extra dispatches on suffix: GA log as JSONL,
        # uploads ledger / Ghidra JSON as JSON objects, rest as TOML.
        _validate_extra(_src)
        _siblings.append((_src, root / _src.relative_to(_backup_root)))
    for rel in _target_binary_relpaths(_backup_root):
        if rel not in [s.relative_to(_backup_root) for s, _ in _siblings]:
            _siblings.append((_backup_root / rel, root / rel))
    for rel in _binsync_state_relpaths(_backup_root):
        for _src in sorted(p for p in (_backup_root / rel).rglob("*") if p.is_file()):
            if _src.relative_to(_backup_root) not in [
                s.relative_to(_backup_root) for s, _ in _siblings
            ]:
                _siblings.append((_src, root / _src.relative_to(_backup_root)))
    location = root / DATABASE_FILENAME
    location.parent.mkdir(parents=True, exist_ok=True)
    with file_transaction(location.parent, location.name):
        if location.is_file():
            preserved = location.with_name(location.name + ".before-restore")

            # Re-running a restore must not overwrite the preserved copy
            # with the live database's current (already-restored) bytes:
            # the sidecar is the only copy of what the first restore
            # displaced.  Compare logical snapshots so a re-run is a no-op
            # for the sidecar even if the physical file was rewritten.
            def _snapshot(db: Path) -> list[tuple[str, str]] | None:
                try:
                    conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=30)
                    try:
                        return conn.execute(
                            "SELECT path, content FROM metadata_documents ORDER BY path"
                        ).fetchall()
                    finally:
                        conn.close()
                except sqlite3.Error:
                    return None

            current_content = _snapshot(location)
            preserved_content = _snapshot(preserved) if preserved.is_file() else None
            backup_content = _snapshot(backup)
            # A re-run of the same restore finds the live database already
            # carrying the backup's content; preserving again would replace
            # the sidecar with the restored bytes.  A later restore of a
            # different backup rotates the sidecar aside first, so the copy
            # of what the first restore displaced survives.
            if current_content not in (backup_content, preserved_content):
                # Stage the new sidecar before touching the old one.  A crash
                # mid-copy then leaves the previous displaced database intact,
                # and the next restore rotates it aside instead of finding a
                # half-written sidecar.
                staged = preserved.with_name(f"{preserved.name}.staging")
                # A killed restore leaves this behind; the backup API cannot
                # open an existing database as a fresh target.
                staged.unlink(missing_ok=True)
                # As in backup_metadata_database: a previous restore left the
                # preserved copy read-only (0444).  Rotating it aside writes a
                # sibling through atomic_write_bytes, which chmods the existing
                # file writable first.  Fail here when the mode cannot be
                # relaxed, so the operator sees this file and not a later
                # "readonly database" from that chmod.
                if preserved.exists():
                    try:
                        preserved.chmod(0o644)
                    except OSError as exc:
                        raise MetadataStorageError(
                            f"{preserved}: cannot make the preserved database writable "
                            f"for replacement: {exc}"
                        ) from exc
                source = sqlite3.connect(location.as_uri() + "?mode=ro", uri=True, timeout=30)
                try:
                    with contextlib.closing(sqlite3.connect(staged, timeout=30)) as target:
                        source.backup(target)
                finally:
                    source.close()
                os.chmod(staged, 0o444)
                if preserved.is_file() and preserved_content != current_content:
                    rotate_preserved_copy(preserved, preserved.read_bytes())
                staged.replace(preserved)
        import time

        from rebrew.utils import atomic_write_bytes as _awb

        # Snapshot the extras' current bytes first, so a failure while
        # staging the database rolls the extras back instead of leaving a
        # half-restored tree (database from before, extras from the backup).
        _before: dict[Path, bytes | None] = {}
        for _src, _dest in _siblings:
            _before[_dest] = _dest.read_bytes() if _dest.is_file() else None
        _installed: list[tuple[Path, int]] = []
        try:
            for _src, _dest in _siblings:
                _raw = _src.read_bytes()
                _current = _before[_dest]
                # A BinSync state file stays writable, matching the backup copy.
                _mode = (
                    _BINSYNC_MODE
                    if _is_in_binsync_state(_backup_root, _src)
                    else _extra_mode(_dest)
                )
                if _current is not None and _current != _raw:
                    # Keep every displaced copy (see the database
                    # preservation above and restore_ga_runs).
                    preserve_displaced(_dest, _current, _mode)
                _awb(_dest, _raw, mode=_mode)
                if _dest.read_bytes() != _raw:
                    raise MetadataStorageError(f"{_dest}: restored copy verification failed")
                _installed.append((_dest, _mode))
        except BaseException:
            for _dest, _mode in reversed(_installed):
                _original = _before[_dest]
                if _original is None:
                    _dest.unlink(missing_ok=True)
                else:
                    _awb(_dest, _original, mode=_mode)
            raise

        tmp = location.with_name(f"{location.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
        try:
            db_source = sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True, timeout=30)
            try:
                with contextlib.closing(sqlite3.connect(tmp, timeout=30)) as target:
                    db_source.backup(target)
            finally:
                db_source.close()
            # Verify the staged copy before it becomes the live database.
            check = sqlite3.connect(tmp.as_uri() + "?mode=ro", uri=True, timeout=30)
            try:
                _check_database_schema(check, tmp)
                staged_integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
                staged_count = check.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[
                    0
                ]
            except MetadataStorageError as exc:
                raise MetadataStorageError(
                    f"{backup}: restored copy verification failed: {exc}"
                ) from exc
            except sqlite3.Error as exc:
                raise MetadataStorageError(
                    f"{backup}: restored copy verification failed: {exc}"
                ) from exc
            finally:
                check.close()
            if staged_integrity != "ok" or staged_count != count:
                raise MetadataStorageError(f"{backup}: restored copy verification failed")
            # fsync the staged file, publish atomically, fsync the directory.
            fd = os.open(tmp, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(tmp, 0o444)
            # A stale rollback journal (or WAL sidecar) from a killed
            # writer belongs to the pre-restore database; left beside the
            # restored file SQLite would replay/rollback against the new
            # page image.  Clear them before publishing, and refuse to
            # publish when one is still there: a swallowed unlink would
            # install the new pages under the old journal.
            for _suffix in ("-journal", "-wal", "-shm"):
                sidecar = location.with_name(location.name + _suffix)
                try:
                    sidecar.unlink(missing_ok=True)
                except OSError as exc:
                    if sidecar.exists():
                        raise MetadataStorageError(
                            f"{sidecar}: cannot remove stale SQLite sidecar before restore: {exc}"
                        ) from exc
            # Restored verify caches make any pre-restore JSON sidecar
            # stale; its fingerprint would miss anyway, but leaving it
            # around invites a later stat-collision hit.
            for _src, _dest in _siblings:
                if _dest.name in ("verify_cache.toml", "verify_baseline.toml"):
                    with contextlib.suppress(OSError):
                        _dest.with_suffix(".json").unlink(missing_ok=True)
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
