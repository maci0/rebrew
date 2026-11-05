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

#: Project config holding every target's paths and metadata backend choice.
#: Without it a restore has no root to install into and a re-pointed
#: ``metadata_dir`` would strand the restored stores.
_PROJECT_CONFIG_NAME = "rebrew-project.toml"

#: Durable state under ``.rebrew/`` that git never sees (``.rebrew/`` is
#: gitignored) and that no regenerating command reproduces.  The GA log
#: holds win fingerprints a re-run cannot reproduce, and the BinSync
#: baselines hold the three-way reconciliation sidecars.  The metadata
#: backup bundle carries both so one off-tree backup covers the whole
#: project; the GA log also keeps its own ``rebrew match solutions
#: --backup`` spelling.  The decomp.me upload ledger holds claim tokens
#: whose loss re-uploads scratches already claimed on decomp.me; it is
#: durable for the same reason (90-day dedup window) and rides in the
#: same bundle.
_GA_RUNS_REL = Path(".rebrew") / "ga_runs.jsonl"
_SYNC_DIR_REL = Path(".rebrew") / "sync"
_UPLOADS_REL = Path(".rebrew") / "decompme-uploads.json"


def _extra_durable_sources(root: Path) -> list[Path]:
    """GA log, BinSync baseline sidecars, and upload ledger, when present.

    All live under the gitignored ``.rebrew/`` directory, so a backup
    that only walks the TOML store trees silently drops them: the
    GA wins have no regenerating command, losing the baselines
    loses the three-way decisions a later push/pull relied on, and
    losing the upload ledger re-uploads scratches already claimed on
    decomp.me.  Peer worktrees under ``.rebrew/sync/peers/`` are
    transient snapshots and stay out.
    """
    sources = []
    ga_runs = root / _GA_RUNS_REL
    if ga_runs.is_file():
        sources.append(ga_runs)
    uploads = root / _UPLOADS_REL
    if uploads.is_file():
        sources.append(uploads)
    sync_dir = root / _SYNC_DIR_REL
    if sync_dir.is_dir():
        sources.extend(sorted(p for p in sync_dir.iterdir() if p.suffix == ".toml" and p.is_file()))
    return sources


def _toml_store_tree(root: Path, name: str) -> list[Path]:
    """Main TOML plus its ``.d/*.toml`` drop-ins, when present."""
    main = root / name
    tree = [main] if main.is_file() else []
    dropins = main.with_suffix(".d")
    if dropins.is_dir():
        tree.extend(sorted(p for p in dropins.iterdir() if p.suffix == ".toml" and p.is_file()))
    return tree


def _toml_store_trees(root: Path) -> list[tuple[Path, list[Path]]]:
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


def _toml_stores_present(root: Path) -> list[tuple[str, list[Path]]]:
    """Non-empty ``(name, tree)`` pairs for the managed TOML stores.

    Kept for the flat layout and existing callers; the backup/restore pair
    below uses :func:`_toml_store_trees` so a nested ``metadata_dir`` is
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

    trees = _toml_store_trees(root)
    config = _project_config(root)
    extras = _extra_durable_sources(root)
    if not trees and config is None and not extras:
        raise FileNotFoundError(f"no metadata stores at {root}")
    bundle = backup_dir / TOML_BACKUP_DIRNAME
    sources: list[Path] = []
    for _directory, tree in trees:
        sources.extend(tree)
    if config is not None:
        sources.append(config)
    sources.extend(extras)
    for source in sources:
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
    leaves the current stores alone.  The project config, when the bundle
    carries one, is installed first so a nested ``metadata_dir`` still
    resolves after the stores land.  Returns the installed paths.
    """
    from rebrew.utils import atomic_write_bytes, load_tomllib

    if not bundle.is_dir():
        raise FileNotFoundError(f"no metadata backup bundle at {bundle}")
    planned: list[Path] = []
    config = bundle / _PROJECT_CONFIG_NAME
    trees = _toml_store_trees(bundle)
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
    extras = _extra_durable_sources(bundle)
    for source in extras:
        rel = source.relative_to(bundle)
        if source.suffix == ".toml":
            try:
                load_tomllib(source)
            except (ValueError, OSError) as exc:
                raise MetadataStorageError(f"{source}: corrupt backup: {exc}") from exc
        else:
            # The GA log is JSONL; validate every non-blank line parses
            # as a JSON object so a corrupt log cannot be installed.
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
            if dest.is_file():
                atomic_write_bytes(
                    dest.with_name(dest.name + ".before-restore"),
                    dest.read_bytes(),
                    mode=0o444,
                )
            atomic_write_bytes(dest, raw, mode=0o444)
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

    The GA log (``.rebrew/ga_runs.jsonl``) and the BinSync baselines
    (``.rebrew/sync/*.toml``) ride alongside the database when present:
    neither survives under git and neither is regenerable.
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

    for extra in _extra_durable_sources(root):
        payload = extra.read_bytes()
        copied = backup_dir / extra.relative_to(root)
        atomic_write_bytes(copied, payload, mode=0o444)
        if copied.read_bytes() != payload:
            raise MetadataStorageError(f"{copied}: backup verification failed")
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

    The GA log and the BinSync baselines saved alongside the backup
    (``.rebrew/ga_runs.jsonl``, ``.rebrew/sync/*.toml``) are installed
    the same way, each preserved as ``.before-restore`` first; a corrupt
    one raises and leaves everything alone.
    """
    from rebrew.metadata.locking import file_transaction

    if not backup.is_file():
        raise FileNotFoundError(f"no metadata database backup at {backup}")
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
    import json as _json

    _ga_rel = _GA_RUNS_REL
    _sync_rel = _SYNC_DIR_REL
    _siblings: list[tuple[Path, Path]] = []
    _backup_root = backup.parent
    for _rel, _kind in ((_ga_rel, "ga"), (_sync_rel, "sync")):
        _src_dir = _backup_root / _rel
        if _kind == "ga":
            _candidates = [_src_dir] if _src_dir.is_file() else []
        else:
            _candidates = (
                sorted(x for x in _src_dir.iterdir() if x.suffix == ".toml" and x.is_file())
                if _src_dir.is_dir()
                else []
            )
        for _src in _candidates:
            _raw = _src.read_bytes()
            _dest = root / _src.relative_to(_backup_root)
            if _kind == "ga":
                for _lineno, _line in enumerate(
                    _raw.decode("utf-8", errors="replace").splitlines(), 1
                ):
                    if not _line.strip():
                        continue
                    try:
                        _parsed = _json.loads(_line)
                    except _json.JSONDecodeError as _exc:
                        raise MetadataStorageError(
                            f"{_src}: corrupt backup line {_lineno}"
                        ) from _exc
                    if not isinstance(_parsed, dict):
                        raise MetadataStorageError(f"{_src}: corrupt backup line {_lineno}")
            else:
                try:
                    from rebrew.utils import load_tomllib as _lt

                    _lt(_src)
                except (ValueError, OSError) as _exc:
                    raise MetadataStorageError(f"{_src}: corrupt backup: {_exc}") from _exc
            _siblings.append((_src, _dest))
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

        from rebrew.utils import atomic_write_bytes as _awb

        for _src, _dest in _siblings:
            _raw = _src.read_bytes()
            if _dest.is_file():
                _awb(
                    _dest.with_name(_dest.name + ".before-restore"),
                    _dest.read_bytes(),
                    mode=0o444,
                )
            _awb(_dest, _raw, mode=0o444)
            if _dest.read_bytes() != _raw:
                raise MetadataStorageError(f"{_dest}: restored copy verification failed")

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
