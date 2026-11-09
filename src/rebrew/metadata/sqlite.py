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
_SCHEMA_VERSION = 1
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
_NAME_COVER_REL = Path(".rebrew") / "name-map-cover.json"
_DATA_SCAN_ROLES_REL = Path(".rebrew") / "data-scan-roles.json"
_PGSQL_SNAPSHOT_DIR_REL = Path(".rebrew") / "pgsql-before-transfer"
_SNAPSHOTS_DIR_REL = Path("snapshots")

#: Mode the uploads ledger must keep in backups and on restore: it holds
#: decomp.me claim tokens, so no group/other access, matching
#: ``rebrew.decompme._UPLOADS_FILE_MODE``.
_UPLOADS_MODE = 0o600


def _validate_uploads_ledger(source: Path) -> None:
    """Validate the uploads ledger as one JSON object, or raise.

    The ledger is a single JSON document (``json.dumps`` of a dict in
    ``rebrew.decompme.record_upload``), not JSONL: validating it line by
    line as the GA log is would reject every real ledger, so a backup
    holding one could never be restored.  Only parseability as a JSON
    object is required here; entry shape stays ``read_uploads``' job,
    which filters fields and token format on each read.
    """
    import json as _json

    try:
        parsed = _json.loads(source.read_bytes())
    except (ValueError, OSError) as exc:
        raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
    if not isinstance(parsed, dict):
        raise MetadataStorageError(f"{source}: corrupt backup: not a JSON object")
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
    elif source.suffix == ".json":
        # The uploads ledger validates as one JSON object with claim-token
        # entries; the Ghidra sync state is a plain dedup hash map where only
        # JSON-object parseability is required to block a corrupt install.
        if source.name == "decompme-uploads.json":
            _validate_uploads_ledger(source)
        else:
            import json as _json

            try:
                parsed = _json.loads(source.read_bytes())
            except (ValueError, OSError) as exc:
                raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
            if not isinstance(parsed, dict):
                raise MetadataStorageError(f"{source}: corrupt backup: not a JSON object")
    else:
        from rebrew.utils import load_tomllib as _lt

        try:
            _lt(source)
        except (ValueError, OSError) as exc:
            raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc


def _extra_mode(source: Path) -> int:
    """Write mode for one ``.rebrew/`` extra, owner-only for the ledger."""
    return _UPLOADS_MODE if source.name == "decompme-uploads.json" else 0o444


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


def extra_durable_sources(root: Path) -> list[Path]:
    """GA log, BinSync baselines, upload ledger, journal, replication
    sidecar, verify cache/baseline, Ghidra sync state, the root
    scan caches (``name-map-cover.json``, ``data-scan-roles.json``),
    the metadata-doc parsed-document caches, and coverage snapshots, when present.

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
    """
    sources = []
    ga_runs = root / _GA_RUNS_REL
    if ga_runs.is_file():
        sources.append(ga_runs)
    uploads = root / _UPLOADS_REL
    if uploads.is_file():
        sources.append(uploads)
    for name in ("metadata-journal.toml", "metadata-replication.toml"):
        state = root / ".rebrew" / name
        if state.is_file():
            sources.append(state)
    for rel in (_VERIFY_CACHE_REL, _VERIFY_BASELINE_REL):
        candidate = root / rel
        if candidate.is_file():
            sources.append(candidate)
    targets_dir = root / _VERIFY_TARGETS_REL
    if targets_dir.is_dir():
        sources.extend(sorted(p for p in targets_dir.rglob("verify_cache.toml") if p.is_file()))
        sources.extend(sorted(p for p in targets_dir.rglob("verify_baseline.toml") if p.is_file()))
    ghidra_state = root / _GHIDRA_SYNC_STATE_REL
    if ghidra_state.is_file():
        sources.append(ghidra_state)
    for rel in (_NAME_COVER_REL, _DATA_SCAN_ROLES_REL):
        candidate = root / rel
        if candidate.is_file():
            sources.append(candidate)
    doc_cache_dir = root / ".rebrew" / "metadata-doc"
    if doc_cache_dir.is_dir():
        # Parsed-document caches carry hand-reviewed fingerprints; a
        # stale copy degrades to a re-parse, never a wrong verdict.
        sources.extend(sorted(p for p in doc_cache_dir.iterdir() if p.is_file()))
    sync_dir = root / _SYNC_DIR_REL
    if sync_dir.is_dir():
        sources.extend(sorted(p for p in sync_dir.iterdir() if p.suffix == ".toml" and p.is_file()))
    pgsql_snapshots = root / _PGSQL_SNAPSHOT_DIR_REL
    if pgsql_snapshots.is_dir():
        sources.extend(sorted(p for p in pgsql_snapshots.rglob("*.toml") if p.is_file()))
    snapshots = root / _SNAPSHOTS_DIR_REL
    if snapshots.is_dir():
        sources.extend(
            sorted(
                p
                for p in snapshots.glob("coverage-*.toml")
                if p.is_file() and not p.name.endswith(".before-restore")
            )
        )
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


def _target_binary_relpaths(root: Path) -> list[Path]:
    """Project-relative target binaries named by the project config.

    The target binary is the one irreplaceable input rebrew cannot
    regenerate: verification, layout and toolchain detection all read
    it, and a restore without it leaves a tree that cannot verify.
    ``rebrew doctor`` already names it; the backup bundle must
    carry it so an off-tree copy is a complete recovery set.
    """
    config = root / _PROJECT_CONFIG_NAME
    if not config.is_file():
        return []
    try:
        raw = tomllib.loads(config.read_text(encoding="utf-8"))
    except ValueError, OSError:
        return []
    targets = raw.get("targets")
    if not isinstance(targets, dict):
        return []
    rels: list[Path] = []
    for table in targets.values():
        if not isinstance(table, dict):
            continue
        binary = table.get("binary")
        if not isinstance(binary, str) or not binary.strip():
            continue
        rel = Path(binary.strip())
        if rel.is_absolute() or ".." in rel.parts:
            continue
        if not (root / rel).is_file():
            continue
        rels.append(rel)
    return sorted(set(rels))


def _toml_stores_present(root: Path) -> list[tuple[str, list[Path]]]:
    """Non-empty ``(name, tree)`` pairs for the managed TOML stores.

    Kept for the flat layout and existing callers; the backup/restore pair
    below uses :func:`toml_store_trees` so a nested ``metadata_dir`` is
    covered too.
    """
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
    sources.extend(extras)
    written: list[tuple[str, bytes]] = []
    for source in sources:
        dest = bundle / source.relative_to(root)
        payload = source.read_bytes()
        atomic_write_bytes(dest, payload, mode=_extra_mode(source))
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
    installed = []
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
            if original is not None and original != raw:
                preserved = dest.with_name(dest.name + ".before-restore")
                # Keep the first preserved copy across a re-run: overwriting
                # it with the already-restored bytes would discard the only
                # copy of what the restore displaced (see restore_ga_runs).
                if not preserved.is_file() or preserved.read_bytes() != original:
                    atomic_write_bytes(preserved, original, mode=_extra_mode(dest))
            atomic_write_bytes(dest, raw, mode=_extra_mode(dest))
            if dest.read_bytes() != raw:
                raise MetadataStorageError(f"{dest}: restored copy verification failed")
            installed.append(dest)
    except BaseException:
        for dest in reversed(installed):
            original = before[dest]
            if original is None:
                dest.unlink(missing_ok=True)
            else:
                atomic_write_bytes(dest, original, mode=0o444)
        raise
    return tuple(installed)


def backup_metadata_database(root: Path, backup_dir: Path) -> Path:
    """Copy the SQLite metadata database to *backup_dir* via the backup API.

    A plain file copy of a live SQLite database can capture a torn page
    image if a writer is mid-transaction; ``sqlite3``'s online backup API
    copies a transactionally consistent snapshot instead.  The copy is
    then opened read-only and its schema version and table checked,
    so a backup that cannot be restored raises here rather than at
    restore time.  A missing database raises ``FileNotFoundError``.

    The GA log (``.rebrew/ga_runs.jsonl``), the BinSync baselines
    (``.rebrew/sync/*.toml``), the upload ledger, the journal and
    replication sidecar, the verify cache/baseline and the Ghidra
    sync state ride alongside the database when present, via
    :func:`extra_durable_sources`: none survives under git and
    none is regenerable without loss.
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
        copied = backup_dir / extra.relative_to(root)
        atomic_write_bytes(copied, payload, mode=_extra_mode(extra))
        if copied.read_bytes() != payload:
            raise MetadataStorageError(f"{copied}: backup verification failed")
        written.append((str(extra.relative_to(root)), payload))
    _write_backup_manifest(backup_dir, written)
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

    The ``.rebrew/`` extras saved alongside the backup (GA log,
    BinSync baselines, upload ledger, journal, replication sidecar,
    verify cache/baseline, Ghidra sync state) are installed the same
    way, each preserved as ``.before-restore`` first; a corrupt one
    raises and leaves everything alone.
    """
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
            # the sidecar with the restored bytes, discarding what the first
            # restore displaced.
            if current_content not in (backup_content, preserved_content):
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

        from rebrew.utils import atomic_write_bytes as _awb

        # Snapshot the extras' current bytes first, so a failure while
        # staging the database rolls the extras back instead of leaving a
        # half-restored tree (database from before, extras from the backup).
        _before: dict[Path, bytes | None] = {}
        for _src, _dest in _siblings:
            _before[_dest] = _dest.read_bytes() if _dest.is_file() else None
        _installed: list[Path] = []
        try:
            for _src, _dest in _siblings:
                _raw = _src.read_bytes()
                _current = _before[_dest]
                if _current is not None and _current != _raw:
                    _preserved = _dest.with_name(_dest.name + ".before-restore")
                    # Keep the first preserved copy across a re-run (see the
                    # database preservation above and restore_ga_runs).
                    if not _preserved.is_file() or _preserved.read_bytes() != _current:
                        _awb(_preserved, _current, mode=_extra_mode(_dest))
                _awb(_dest, _raw, mode=_extra_mode(_dest))
                if _dest.read_bytes() != _raw:
                    raise MetadataStorageError(f"{_dest}: restored copy verification failed")
                _installed.append(_dest)
        except BaseException:
            for _dest in reversed(_installed):
                _original = _before[_dest]
                if _original is None:
                    _dest.unlink(missing_ok=True)
                else:
                    _awb(_dest, _original, mode=_extra_mode(_dest))
            raise

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
                _check_database_schema(staged, tmp)
                staged_integrity = staged.execute("PRAGMA integrity_check").fetchone()[0]
                staged_count = staged.execute("SELECT COUNT(*) FROM metadata_documents").fetchone()[
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
                staged.close()
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
            # page image.  Clear them before publishing.
            for _suffix in ("-journal", "-wal", "-shm"):
                with contextlib.suppress(OSError):
                    location.with_name(location.name + _suffix).unlink(missing_ok=True)
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
