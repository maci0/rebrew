"""Backend-neutral access to the four managed metadata stores.

Project configuration stays in TOML. Domain owners validate documents and earn
verdicts; backends own persistence, input discovery, snapshots and transactions.
"""

import contextlib
import contextvars
import logging
import os
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
lazy from rebrew.metadata.replication import JOURNAL_PATH, RoutedStore
lazy from rebrew.metadata.sqlite import SqliteStore
lazy from rebrew.registry import iter_optional_provider_dicts
lazy from rebrew.utils import load_tomllib
lazy from rebrew.workspace.config import CONFIG_NAME, walk_up_to_root

Fingerprint = tuple[tuple[str, int, int, int, int], ...]
Validator = Callable[[Any], Any]
_ConfigIdentity = tuple[int, int, int, int, int]
_ProjectRoute = tuple[Path, Path, _ConfigIdentity | None]
_MarkerProbe = tuple[str, str]


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

    def text(self) -> str | None:
        """Exact TOML text of the logical document; None means absent."""
        ...

    def write_text(self, content: str, description: str) -> None:
        """Write already-rendered TOML text atomically within the active transaction."""
        ...

    def provisioned(self) -> bool:
        """Whether the backend's storage exists; an unprovisioned replica cannot answer reads."""
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


_PINNED_STORES: contextvars.ContextVar[dict[Path, MetadataStore] | None] = contextvars.ContextVar(
    "rebrew_pinned_metadata_stores", default=None
)


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
    path: Path, fingerprint: _ConfigIdentity
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return backend_routes(load_tomllib(path).get("metadata", {}))


#: Watch nearer markers and the selected config. Markers above a live project
#: cannot take precedence. A directory without a project is never cached.
_PROJECT_ROOTS: OrderedDict[str, tuple[_ProjectRoute, str, tuple[_MarkerProbe, ...]]] = (
    OrderedDict()
)
_PROJECT_ROOTS_LOCK = threading.Lock()
_PROJECT_ROOTS_MAX = 256


def _config_identity(
    path: str | Path, missing: type[OSError] = FileNotFoundError
) -> _ConfigIdentity | None:
    """Stat identity for routing, including rewrites that preserve mtime."""
    try:
        st = os.stat(path)  # noqa: PTH116 -- cached marker paths are strings
    except missing:
        return None
    return (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino, st.st_dev)


def _nearer_markers(directory: str, project: str) -> tuple[_MarkerProbe, ...] | None:
    """Watch missing markers between the source directory and its project."""
    markers: list[_MarkerProbe] = []
    current = directory
    while current != project:
        marker = os.path.join(current, CONFIG_NAME)  # noqa: PTH118 -- the marker cache uses strings
        parent = os.path.dirname(current)
        if (
            parent == current
            or os.path.islink(current)  # noqa: PTH114 -- the marker cache uses strings
            or _config_identity(marker, OSError) is not None
        ):
            return None
        markers.append((current, marker))
        current = parent
    return tuple(markers)


def _project_root(directory: Path) -> _ProjectRoute:
    """Find the project and reuse the config identity checked by the marker walk."""
    spelling = str(directory)
    with _PROJECT_ROOTS_LOCK:
        cached = _PROJECT_ROOTS.get(spelling)
    if (
        cached is not None
        and all(
            not os.path.islink(directory)  # noqa: PTH114 -- the marker cache uses strings
            and _config_identity(marker, OSError) is None
            for directory, marker in cached[2]
        )
        and _config_identity(cached[1], OSError) == cached[0][2]
    ):
        with _PROJECT_ROOTS_LOCK:
            if spelling in _PROJECT_ROOTS:
                _PROJECT_ROOTS.move_to_end(spelling)
        return cached[0]
    walked = walk_up_to_root(directory)
    project = directory if walked is None else walked
    config = project / CONFIG_NAME
    identity = _config_identity(config)
    result = (project, config, identity)
    if walked is None or identity is None:
        return result
    markers = _nearer_markers(spelling, os.fspath(project))
    if markers is None:
        return result
    with _PROJECT_ROOTS_LOCK:
        _PROJECT_ROOTS[spelling] = (result, os.fspath(config), markers)
        _PROJECT_ROOTS.move_to_end(spelling)
        while len(_PROJECT_ROOTS) > _PROJECT_ROOTS_MAX:
            _PROJECT_ROOTS.popitem(last=False)
    return result


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
_SELECTED_STORES: OrderedDict[Path, tuple[_ConfigIdentity, MetadataStore]] = OrderedDict()
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
    pinned = (_PINNED_STORES.get() or {}).get(path)
    if pinned is not None and backend is None and (root is None or root.resolve() == pinned.root):
        return pinned
    if root is None:
        project, config, config_identity = _project_root(path.parent)
    else:
        project = root.resolve()
        config = project / CONFIG_NAME
        config_identity = _config_identity(config)
    if backend is None and config_identity is not None:
        # One dict lookup for the whole common case: the project selects the
        # backend and has not rewritten its config since the store was built.
        with _SELECTED_STORES_LOCK:
            selected = _SELECTED_STORES.get(path)
        if selected is not None and selected[0] == config_identity and selected[1].root == project:
            return selected[1]
        reads, writes = _configured_routes(config, config_identity)
        store: MetadataStore
        if len(reads) > 1 or len(writes) > 1 or reads != writes:
            factories = {name: _backend_factory(name) for name in dict.fromkeys((*reads, *writes))}
            store = RoutedStore(path, project, reads, writes, factories)
            # Built-in backends only, as below: a plugin factory may be replaced.
            if not set(factories.values()) <= {TomlStore, SqliteStore}:
                return store
        else:
            backend = reads[0]
            factory = _backend_factory(backend)
            if factory not in (TomlStore, SqliteStore):
                selected_store = factory(path, project)
                if not isinstance(selected_store, MetadataStore):
                    raise ValueError(
                        f"metadata backend {backend!r} does not implement MetadataStore"
                    )
                return selected_store
            store = _builtin_store(path, backend, project)
        with _SELECTED_STORES_LOCK:
            # A full clear drops every store a peer thread resolved in
            # this same window, including ones still inside a transaction.
            # Drop the oldest entries instead, and refresh a path that
            # was already cached so it is not the next one evicted.
            _SELECTED_STORES[path] = (config_identity, store)
            _SELECTED_STORES.move_to_end(path)
            while len(_SELECTED_STORES) > _SELECTED_STORES_MAX:
                _SELECTED_STORES.popitem(last=False)
        return store
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
def pin_metadata_stores(stores: list[MetadataStore]) -> Iterator[None]:
    """Keep owner APIs on the transaction's already-selected stores."""
    selected = dict(_PINNED_STORES.get() or {})
    for store in stores:
        path = store.path.absolute()
        previous = selected.get(path)
        if previous is not None and (previous.name != store.name or previous.root != store.root):
            raise ValueError("conflicting pinned metadata stores")
        selected[path] = store
    token = _PINNED_STORES.set(selected)
    try:
        yield
    finally:
        _PINNED_STORES.reset(token)


def metadata_stores_pinned() -> bool:
    """Return whether this transaction can route individual paths differently."""
    return bool(_PINNED_STORES.get())


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


def named_documents_token(
    root: Path, name: str, *, selected: MetadataStore | None = None
) -> tuple[object, ...] | None:
    """Exact change token for every document named *name*; None when not cacheable.

    Covers a SQLite store and a replicated store whose first read backend is a
    provisioned SQLite database: the ``(path, content SHA-256)`` of each such document
    plus the replication journal's stat.  Other backends, and an unprovisioned
    replica whose reads fall back to TOML, return None.

    A store just selected by normal routing can supply the SQLite reader for
    the same resolved root. Transaction pins can differ per path.
    """
    store: MetadataStore
    if (
        (
            type(selected) is SqliteStore
            or (type(selected) is RoutedStore and selected.factories[selected.name] is SqliteStore)
        )
        and name in METADATA_FILENAMES
        and not _PINNED_STORES.get()
        and os.fspath(root) == os.fspath(selected.root) == os.path.realpath(root)
    ):
        store = selected
    else:
        store = metadata_store(root / name, root=root)
    journal: tuple[object, ...] = ()
    if isinstance(store, RoutedStore):
        journal = TomlStore(root / JOURNAL_PATH, root).fingerprint()
        primary = store.read_backends[0]
        if type(store) is RoutedStore and store.factories[primary] is SqliteStore:
            store = _builtin_store(store.path, "sqlite", store.root)
        else:
            store = store.store(primary, store.key)
    if not isinstance(store, SqliteStore):
        return None
    documents = store.provisioned_documents_named(name)
    return None if documents is None else (journal, documents)


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
