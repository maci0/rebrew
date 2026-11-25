"""Reviewed transfer of managed metadata between storage backends."""

lazy import contextlib
lazy import hashlib
lazy import json
lazy import tempfile
lazy import unicodedata
lazy from functools import partial
lazy from pathlib import Path
lazy from typing import Any

lazy import tomlkit

lazy from rebrew.config import ProjectConfig, project_toml_lock
lazy from rebrew.metadata.data import DATA_METADATA_FIELDS
lazy from rebrew.metadata.document import (
    FUNCTION_FORMAT_VERSION,
    metadata_format,
    parse_metadata_doc,
    parse_metadata_key,
)
lazy from rebrew.metadata.functions import (
    FUNCTION_IDENTITY_FIELDS,
    METADATA_FIELDS,
    validate_library_document,
)
lazy from rebrew.metadata.storage import (
    MetadataStore,
    available_metadata_backends,
    metadata_store,
    project_metadata_stores,
)
lazy from rebrew.type_metadata import validate_type_document
lazy from rebrew.utils import (
    atomic_write_bytes,
    atomic_write_text,
    load_toml_for_write_strict,
    sha256_file,
)

#: Suffix beside the inactive destination holding its pre-transfer bytes.
DESTINATION_SNAPSHOT_SUFFIX = ".before-transfer"


def validate_store_document(path: Path, doc: dict[str, Any]) -> None:
    """Apply the existing owning schema before transferring durable records."""
    match path.name:
        case "rebrew-functions.toml":
            metadata_format(path)
            parse_metadata_doc(
                doc,
                known_fields=METADATA_FIELDS | {key.upper() for key in FUNCTION_IDENTITY_FIELDS},
                version=FUNCTION_FORMAT_VERSION,
            )
        case "rebrew-data.toml":
            parse_metadata_doc(doc, known_fields=DATA_METADATA_FIELDS)
        case "rebrew-types.toml":
            validate_type_document(doc)
        case "rebrew-libraries.toml":
            validate_library_document(path, doc)
        case _:
            raise ValueError(f"unsupported metadata store {path}")


def _stores(cfg: ProjectConfig, backend: str | None = None) -> tuple[MetadataStore, ...]:
    return project_metadata_stores(cfg.root.resolve(), backend=backend, recursive=True)


def reconcile_metadata(cfg: ProjectConfig, *, dry_run: bool = False) -> dict[str, Any]:
    """Reconcile configured read/write replicas without changing backend selection."""
    from rebrew.metadata.replication import RoutedStore

    selected = metadata_store(cfg.root.resolve() / "rebrew-functions.toml")
    if not isinstance(selected, RoutedStore):
        raise ValueError("configure multiple metadata read_backends/write_backends to reconcile")
    return selected.reconcile(dry_run=dry_run, validate=validate_store_document)


#: The stores whose records are keyed MODULE.0xVA; module scoping drops the other modules' records from these.
MODULE_KEYED_STORES = frozenset({"rebrew-functions.toml", "rebrew-data.toml"})


def scope_metadata_to_module(cfg: ProjectConfig, module: str) -> int:
    """Remove every function and data record of a module other than *module*; return how many were removed.

    A project imported for one target keeps that target's own records (its
    ``MODULE.0xVA`` keys) and every record without a module key, such as the
    format stamp; the type and library stores are unchanged.  Each store is
    read without its formatting (a format-preserving parse of a whole-game
    store costs most of an import), the records kept are validated with the
    owning schema, and the store is rewritten through its backend under the
    project and store locks.
    """
    root = cfg.root.resolve()
    module = unicodedata.normalize("NFC", module)
    removed = 0
    with project_toml_lock(root):
        for store in _stores(cfg):
            if store.path.name not in MODULE_KEYED_STORES:
                continue
            with store.transaction():
                doc = store.read("module scope")
                kept = {
                    key: value
                    for key, value in doc.items()
                    if (parsed := parse_metadata_key(key)) is None or parsed[0] == module
                }
                if len(kept) == len(doc):
                    continue
                validate_store_document(store.path, kept)
                store.write(kept, "module scope")
                removed += len(doc) - len(kept)
    return removed


def _input_digest(
    stores: tuple[MetadataStore, ...], destinations: tuple[MetadataStore, ...], config: Path
) -> str:
    """The digest a migration pins: every source and destination snapshot and the project config."""
    inputs = {f"source:{store.path}": store.digest() for store in stores}
    inputs.update({f"destination:{store.path}": store.digest() for store in destinations})
    inputs[str(config)] = sha256_file(config)
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def migration_input_digest(cfg: ProjectConfig, backend: str) -> str:
    """The ``input_digest`` a preview of migrating to *backend* would report, without reading any store's records.

    A caller that needs no preview report pins a migration with it
    (``expected_digest``) for the cost of hashing the stores' bytes.
    """
    root = cfg.root.resolve()
    return _input_digest(_stores(cfg), _stores(cfg, backend), root / "rebrew-project.toml")


def migrate_metadata(
    cfg: ProjectConfig, backend: str, *, dry_run: bool = False, expected_digest: str | None = None
) -> dict[str, Any]:
    """Copy validated documents, then select the destination; retain the source unchanged."""
    if backend not in available_metadata_backends():
        raise ValueError(f"unknown metadata backend {backend!r}")
    from rebrew.metadata.replication import RoutedStore

    if isinstance(metadata_store(cfg.root / "rebrew-functions.toml"), RoutedStore):
        raise ValueError("use metadata reconcile for a project with multiple configured backends")
    root = cfg.root.resolve()
    config_path = root / "rebrew-project.toml"

    def prepare() -> tuple[
        tuple[MetadataStore, ...], list[tuple[Path, dict[str, Any]]], dict[str, Any]
    ]:
        source = metadata_store(root / "rebrew-functions.toml").name
        metadata_format(root / "rebrew-functions.toml")
        stores = _stores(cfg)
        destinations = _stores(cfg, backend)
        digest = _input_digest(stores, destinations, config_path)
        if expected_digest is not None and digest != expected_digest:
            raise ValueError("metadata inputs changed since preview; review a new preview")
        documents = []
        for store in stores:
            doc = store.read(
                "metadata transfer",
                validate=partial(validate_store_document, store.path),
                roundtrip=True,
            )
            documents.append((store.path, doc))
        if _input_digest(stores, destinations, config_path) != digest:
            raise ValueError("metadata changed while preparing transfer; retry")
        return (
            stores,
            documents,
            {
                "source": source,
                "backend": backend,
                "experimental": backend in {"sqlite", "pgsql"},
                "stores": [str(path.relative_to(root)) for path, _doc in documents],
                "removed_destination_stores": [
                    str(store.path.relative_to(root))
                    for store in destinations
                    if store.path not in {path for path, _doc in documents}
                ],
                "input_digest": digest,
                "dry_run": dry_run,
                "changed": source != backend,
            },
        )

    # A preview, or a migration onto the selected backend, only reports. A transfer reads its
    # sources once, under the locks it writes with: each format-preserving read is a full parse.
    if dry_run or metadata_store(root / "rebrew-functions.toml").name == backend:
        return prepare()[2]
    with project_toml_lock(root), contextlib.ExitStack() as locks:
        for store in sorted(
            {store.location: store for store in _stores(cfg)}.values(),
            key=lambda store: str(store.location),
        ):
            locks.enter_context(store.transaction())
        stores, documents, report = prepare()
        if not report["changed"]:
            return report
        destination = metadata_store(root / "rebrew-functions.toml", backend=backend, root=root)
        # Preserve the inactive destination before overwriting it: a
        # transfer is the one deliberate mass-replace of durable metadata,
        # and without this copy the previous destination bytes exist nowhere
        # once the writes below land.  The copy is written atomically and
        # verified; a failed copy aborts the transfer before any write.
        if backend != "pgsql":
            _snapshot_destination(root, backend, _stores(cfg, backend))
        with destination.transaction():
            if backend == "pgsql":
                _snapshot_destination(root, backend, _stores(cfg, backend))
            current_paths = {path for path, _doc in documents}
            for obsolete in _stores(cfg, backend):
                if obsolete.path not in current_paths:
                    obsolete.remove()
            for path, doc in documents:
                target = metadata_store(path, backend=backend, root=root)
                target.write(doc, "metadata transfer")
                if target.read("metadata transfer") != dict(doc):
                    raise ValueError(f"metadata transfer verification failed for {path}")
        # A failed transfer never changes the active backend. Inactive copies
        # remain safe to retry; source metadata is never deleted.
        config = load_toml_for_write_strict(config_path, "project configuration")
        config.setdefault("metadata", {})["backend"] = backend
        atomic_write_text(config_path, tomlkit.dumps(config))
    return report


def _snapshot_destination(
    root: Path, backend: str, destinations: tuple[MetadataStore, ...]
) -> None:
    """Copy the inactive destination's bytes beside it before a transfer.

    For the SQLite backend the copy is a consistent backup-API snapshot of
    the whole database (a file copy can be torn mid-transaction); for TOML
    it is the store's own snapshot bytes. Raises on a failed copy so the
    caller aborts before any destination write.
    """
    if backend == "sqlite":
        from rebrew.metadata.sqlite import DATABASE_FILENAME, backup_metadata_database

        location = root / DATABASE_FILENAME
        if not location.is_file():
            return
        sqlite_snapshot = root / ".rebrew" / (DATABASE_FILENAME + DESTINATION_SNAPSHOT_SUFFIX)
        # The copy goes outside the project first.  The snapshot dir is
        # inside it, so a copy taken there would record the snapshot it is
        # about to replace, and a crash mid-copy would leave that snapshot
        # half-written.  Only a verified copy is installed, and only when
        # the stored rows differ: a re-run of the same transfer is a no-op,
        # and a different existing snapshot is rotated aside first so the
        # copy of what the first transfer displaced survives.
        import sqlite3

        def _rows(db: Path) -> list[tuple[str, str]] | None:
            try:
                with contextlib.closing(
                    sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=30)
                ) as conn:
                    return conn.execute(
                        "SELECT path, content FROM metadata_documents ORDER BY path"
                    ).fetchall()
            except sqlite3.Error:
                return None

        with tempfile.TemporaryDirectory(prefix="rebrew-snapshot-") as staging:
            dest = backup_metadata_database(root, Path(staging))
            payload = dest.read_bytes()
            recorded = _rows(sqlite_snapshot) if sqlite_snapshot.is_file() else None
            copied = _rows(dest)
            if recorded is not None and copied is not None and recorded == copied:
                return
            if sqlite_snapshot.is_file():
                _rotate_snapshot(sqlite_snapshot, sqlite_snapshot.read_bytes())
            atomic_write_bytes(sqlite_snapshot, payload, mode=0o444)
            if sqlite_snapshot.read_bytes() != payload:
                raise ValueError(
                    f"metadata destination snapshot verification failed for {sqlite_snapshot}"
                )
    for store in destinations:
        data = store.snapshot()
        if data is None:
            continue
        target = (
            root / ".rebrew" / "pgsql-before-transfer" / store.path.relative_to(root)
            if backend == "pgsql"
            else store.location.with_name(store.location.name + DESTINATION_SNAPSHOT_SUFFIX)
        )
        # Keep every displaced copy.  A re-run of the same transfer (the
        # destination already holds the bytes this snapshot recorded) is a
        # no-op.  A later transfer that displaces different bytes rotates
        # the current snapshot aside before writing the new one: the
        # sidecar is the only copy of what a transfer replaced, and
        # overwriting it discards that copy (see restore_ga_runs).
        if target.is_file() and target.read_bytes() == data:
            continue
        if target.exists():
            _rotate_snapshot(target, target.read_bytes())
        atomic_write_bytes(target, data, mode=0o444)
        if target.read_bytes() != data:
            raise ValueError(f"metadata destination snapshot verification failed for {target}")


def _rotate_snapshot(target: Path, held: bytes) -> None:
    """Move *target* aside; see :func:`rebrew.metadata.sqlite.rotate_preserved_copy`."""
    from rebrew.metadata.sqlite import rotate_preserved_copy

    rotate_preserved_copy(target, held)
