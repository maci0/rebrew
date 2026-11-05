"""Backend-neutral access to the four managed metadata stores.

Project configuration stays in TOML. Domain owners validate documents and earn
verdicts; backends own persistence, input discovery, snapshots and transactions.
"""

import contextlib
import logging
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
lazy import hashlib

lazy from rebrew.metadata.files import METADATA_FILENAMES, TomlStore
lazy from rebrew.metadata.locking import project_transaction
lazy from rebrew.metadata.pgsql import PgsqlStore, validate_pgsql_settings
lazy from rebrew.metadata.replication import RoutedStore
lazy from rebrew.metadata.sqlite import SqliteStore
lazy from rebrew.registry import iter_optional_provider_dicts
lazy from rebrew.utils import load_tomllib
lazy from rebrew.workspace.config import CONFIG_NAME, walk_up_to_root

Fingerprint = tuple[tuple[str, int, int, int, int], ...]
Validator = Callable[[Any], Any]


@runtime_checkable
class MetadataStore(Protocol):
    """A logical metadata document with transactional persistence."""

    name: str
    path: Path
    root: Path
    location: Path

    def read(
        self, description: str, *, validate: Validator | None = None, roundtrip: bool = False
    ) -> dict[str, Any]:
        """Read without creating storage; validate physical members and the combined document."""
        ...

    def write(self, doc: dict[str, Any], description: str) -> None:
        """Write a document atomically within the active transaction."""
        ...

    def exists(self) -> bool:
        """Whether this logical document exists."""
        ...

    def documents(self, *, recursive: bool = False) -> tuple[Path, ...]:
        """Existing logical document paths in this directory or its subtree."""
        ...

    def inputs(self) -> tuple[Path, ...]:
        """Physical paths and discovery locations used by file watchers."""
        ...

    def fingerprint(self) -> Fingerprint:
        """Cheap change token; empty means absent."""
        ...

    def snapshot(self) -> bytes | None:
        """Complete snapshot for review guards; None means absent."""
        ...

    def digest(self) -> str | None:
        """SHA-256 of the complete snapshot."""
        ...

    def transaction(self) -> contextlib.AbstractContextManager[None]:
        """Serialize a complete read/modify/write, reentrantly."""
        ...

    def remove(self) -> None:
        """Remove this logical document and its physical fragments."""
        ...


BackendFactory = Callable[[Path, Path], MetadataStore]
_BACKENDS: dict[str, BackendFactory] | None = None
_BACKEND_LOCK = threading.Lock()
logger = logging.getLogger(__name__)


def refresh_metadata_backends() -> dict[str, BackendFactory]:
    """Publish built-in and optional entry-point backends as one snapshot."""
    global _BACKENDS
    merged: dict[str, BackendFactory] = {
        "toml": TomlStore,
        "sqlite": SqliteStore,
        "pgsql": PgsqlStore,
    }
    for registration, provided in iter_optional_provider_dicts(
        "rebrew.metadata_backends", logger, expected="dict[str, backend factory]"
    ):
        for name, factory in provided.items():
            if name in merged or not callable(factory):
                logger.warning(
                    "skipping metadata backend %r from %s: duplicate name or invalid factory",
                    name,
                    registration.origin,
                )
                continue
            merged[name] = factory
    with _BACKEND_LOCK:
        _BACKENDS = merged
    return dict(merged)


def available_metadata_backends() -> tuple[str, ...]:
    """Registered backend names."""
    with _BACKEND_LOCK:
        current = _BACKENDS
    if current is None:
        current = refresh_metadata_backends()
    return tuple(sorted(current))


def backend_routes(raw: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Validate independent ordered readers and replicated write destinations."""
    if not isinstance(raw, dict) or set(raw) - {
        "backend",
        "read_backends",
        "write_backends",
        "pgsql",
    }:
        raise ValueError("[metadata] accepts backend, read_backends, write_backends and pgsql")
    if "backend" in raw and "read_backends" in raw:
        raise ValueError("choose backend or read_backends, not both")
    reads = raw.get("read_backends", [raw.get("backend", "toml")])
    writes = raw.get("write_backends", reads)
    known = available_metadata_backends()
    for key, names in (("read_backends", reads), ("write_backends", writes)):
        if (
            not isinstance(names, list)
            or not names
            or any(not isinstance(name, str) or name not in known for name in names)
        ):
            raise ValueError(
                f"unknown metadata backend in {key}; expected a nonempty list from {known}"
            )
        if len(set(names)) != len(names):
            raise ValueError(f"[metadata].{key} must not contain duplicates")
    assert isinstance(reads, list) and isinstance(writes, list)
    if "pgsql" in (*reads, *writes) or "pgsql" in raw:
        validate_pgsql_settings(raw.get("pgsql"))
    return tuple(reads), tuple(writes)


def validate_backend_settings(raw: Any) -> str:
    """Return the preferred read backend after validating all routes."""
    return backend_routes(raw)[0][0]


@lru_cache(maxsize=64)
def _configured_routes(
    path: Path, fingerprint: tuple[int, int, int, int]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return backend_routes(load_tomllib(path).get("metadata", {}))


#: ``directory -> (project root, ancestor identities)``.  The walk lstats every
#: ancestor; a whole-tree scan calls ``metadata_store`` once per source file.
#: Misses are not cached: a config created later must still be found.  A hit is
#: only reused while every ancestor's identity is unchanged, so creating or
#: removing a ``rebrew-project.toml`` marker above a cached directory — or
#: replacing an ancestor with a lookalike — invalidates the memo instead of
#: keeping the old root for the life of the process.
_PROJECT_ROOTS: OrderedDict[Path, tuple[Path, tuple[tuple[str, tuple[int, ...] | None], ...]]] = (
    OrderedDict()
)
_PROJECT_ROOTS_LOCK = threading.Lock()
_PROJECT_ROOTS_MAX = 256


def _marker_identity(directory: Path) -> tuple[int, int, int, int, int] | None:
    """Stat identity of the project marker in *directory*, ``None`` when absent."""
    try:
        st = (directory / "rebrew-project.toml").stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_ctime_ns, st.st_ino, st.st_size, 1)


def _ancestor_identities(directory: Path) -> tuple[tuple[str, tuple[int, ...] | None], ...]:
    """Marker identity of *directory* and every ancestor, for cache validation."""
    identities: list[tuple[str, tuple[int, ...] | None]] = []
    current: Path | None = directory
    while current is not None:
        identities.append((str(current), _marker_identity(current)))
        parent = current.parent
        if parent == current:
            break
        current = parent
    return tuple(identities)


def _project_root(directory: Path) -> Path:
    """Find and memoize the project root for *directory*, if one exists."""
    with _PROJECT_ROOTS_LOCK:
        cached = _PROJECT_ROOTS.get(directory)
    if cached is not None and cached[1] == _ancestor_identities(directory):
        with _PROJECT_ROOTS_LOCK:
            if directory in _PROJECT_ROOTS:
                _PROJECT_ROOTS.move_to_end(directory)
        return cached[0]
    walked = walk_up_to_root(directory)
    if walked is None:
        return directory
    identities = _ancestor_identities(directory)
    with _PROJECT_ROOTS_LOCK:
        _PROJECT_ROOTS[directory] = (walked, identities)
        _PROJECT_ROOTS.move_to_end(directory)
        while len(_PROJECT_ROOTS) > _PROJECT_ROOTS_MAX:
            _PROJECT_ROOTS.popitem(last=False)
    return walked


def _backend_factory(backend: str) -> BackendFactory:
    """The registered factory for *backend*, refreshing the registry once."""
    with _BACKEND_LOCK:
        current = _BACKENDS
    if current is None:
        current = refresh_metadata_backends()
    factory = current.get(backend)
    if factory is None:
        known = ", ".join(sorted(current))
        raise ValueError(f"unknown metadata backend {backend!r}; known: {known}")
    return factory


#: ``path -> (config identity, store)`` for the project-selected backend.
#: Only populated when the project config exists: a config created later must
#: still be found, so the no-config case keeps walking each call.
_SELECTED_STORES: dict[Path, tuple[tuple[int, int, int, int], MetadataStore]] = {}
_SELECTED_STORES_LOCK = threading.Lock()
_SELECTED_STORES_MAX = 128


@lru_cache(maxsize=128)
def _builtin_store(path: Path, backend: str, project: Path) -> MetadataStore:
    """One stateless built-in store instance per identity and project.

    ``state``/``root`` are plain paths and the backend contract is stateless, so
    repeated resolution need not allocate a new object on every cached read.
    """
    factories: dict[str, BackendFactory] = {
        "toml": TomlStore,
        "sqlite": SqliteStore,
    }
    return factories[backend](path, project)


def metadata_store(
    path: Path, *, backend: str | None = None, root: Path | None = None
) -> MetadataStore:
    """Resolve a logical filename to the project's selected storage backend.

    An explicit backend is for reviewed imports/exports and backend tests. Every
    normal caller uses the project selection. Non-metadata files retain TOML
    locking, especially rebrew-project.toml itself.
    """
    if not path.is_absolute():
        path = path.absolute()
    if path.name not in METADATA_FILENAMES:
        return TomlStore(path, path.parent)
    project = root.resolve() if root is not None else _project_root(path.parent)
    config = project / CONFIG_NAME
    try:
        stat = config.stat()
    except FileNotFoundError:
        config_identity: tuple[int, int, int, int] | None = None
    else:
        config_identity = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino)
    if backend is None and config_identity is not None:
        # One dict lookup for the whole common case: the project selects the
        # backend and has not rewritten its config since the store was built.
        with _SELECTED_STORES_LOCK:
            selected = _SELECTED_STORES.get(path)
        if selected is not None and selected[0] == config_identity:
            return selected[1]
        reads, writes = _configured_routes(config, config_identity)
        if len(reads) > 1 or len(writes) > 1 or reads != writes:
            return RoutedStore(
                path,
                project,
                reads,
                writes,
                {name: _backend_factory(name) for name in dict.fromkeys((*reads, *writes))},
            )
        backend = reads[0]
        factory = _backend_factory(backend)
        if factory in (TomlStore, SqliteStore):
            store = _builtin_store(path, backend, project)
            with _SELECTED_STORES_LOCK:
                if len(_SELECTED_STORES) >= _SELECTED_STORES_MAX:
                    _SELECTED_STORES.clear()
                _SELECTED_STORES[path] = (config_identity, store)
            return store
        selected_store = factory(path, project)
        if not isinstance(selected_store, MetadataStore):
            raise ValueError(f"metadata backend {backend!r} does not implement MetadataStore")
        return selected_store
    if backend is None:
        backend = "toml"
    factory = _backend_factory(backend)
    if factory in (TomlStore, SqliteStore):
        return _builtin_store(path, backend, project)
    store = factory(path, project)
    if not isinstance(store, MetadataStore):
        raise ValueError(f"metadata backend {backend!r} does not implement MetadataStore")
    return store


@contextlib.contextmanager
def metadata_write_lock(directory: Path, filename: str) -> Iterator[None]:
    """Hold the selected store's transaction across a domain read/modify/write."""
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise ValueError(f"invalid metadata filename: {filename!r}")
    path = directory / filename
    selected = metadata_store(path)
    # Migration may have changed the selection while this writer waited.
    with project_transaction(selected.root, filename), metadata_store(path).transaction():
        yield


def project_metadata_stores(
    directory: Path, *, backend: str | None = None, recursive: bool = False
) -> tuple[MetadataStore, ...]:
    """Discover logical metadata documents without exposing physical backend layout."""
    selected = metadata_store(directory / "rebrew-functions.toml", backend=backend)
    paths = selected.documents(recursive=recursive)
    if any(path.name not in METADATA_FILENAMES for path in paths):
        raise ValueError(f"{selected.location}: unrecognized managed metadata document")
    return tuple(metadata_store(path, backend=backend, root=selected.root) for path in paths)


def metadata_inputs(directory: Path) -> tuple[Path, ...]:
    """Physical metadata inputs for live caches, build dependencies and watchers."""
    stores = project_metadata_stores(directory)
    selected = metadata_store(directory / "rebrew-functions.toml")
    return tuple(sorted({path for store in (*stores, selected) for path in store.inputs()}))


def snapshot_input(path: Path) -> bytes:
    """Snapshot a mixed source/config/metadata review input through its owning API."""
    if path.name in METADATA_FILENAMES:
        content = metadata_store(path).snapshot()
        if content is None:
            raise FileNotFoundError(path)
        return content
    return path.read_bytes()


def input_digest(path: Path) -> str:
    """Hash a mixed review input without bypassing metadata storage."""
    return hashlib.sha256(snapshot_input(path)).hexdigest()


def input_exists(path: Path) -> bool:
    """Test a logical metadata input or an ordinary file."""
    return metadata_store(path).exists() if path.name in METADATA_FILENAMES else path.is_file()


def metadata_store_paths(directory: Path) -> tuple[Path, ...]:
    """Logical metadata paths for backend-independent review snapshots."""
    return tuple(store.path for store in project_metadata_stores(directory))


def toml_fragment_paths(store: MetadataStore) -> tuple[Path, ...]:
    """Return physical fragments for owner-level exception rollback."""
    if store.name != "toml":
        raise ValueError("physical fragment paths require a TOML store")
    from rebrew.metadata.files import metadata_paths

    return metadata_paths(store.path)


def managed_metadata_filenames() -> frozenset[str]:
    """Return names of logical managed metadata collections."""
    return METADATA_FILENAMES
