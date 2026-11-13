"""Backend-neutral descriptors and record diffs of a project's metadata files.

A dispatch client treats rebrew's metadata files as opaque: it learns which files
a project reads, their logical documents and their record changes here, never by
parsing or naming them itself. See ``docs/METADATA.md#dispatch-metadata-contract``.
"""

lazy import datetime as dt
lazy import hashlib
lazy import math
lazy from pathlib import Path
lazy from typing import Any

lazy import tomlkit

lazy from rebrew.errors import RebrewError
lazy from rebrew.metadata.document import parse_metadata_key
lazy from rebrew.metadata.records import metadata_records
lazy from rebrew.metadata.replication import STATE_PATH
lazy from rebrew.metadata.sqlite import DATABASE_FILENAME, SqliteStore, metadata_database_documents
lazy from rebrew.metadata.storage import (
    MetadataStore,
    backend_routes,
    managed_metadata_filenames,
    metadata_store,
    project_metadata_stores,
    toml_fragment_paths,
)
lazy from rebrew.workspace import read_config

#: The backends whose metadata is a closed set of files in the project tree.
LOCAL_BACKENDS = ("toml", "sqlite")

#: The ``store`` a logical document belongs to, by file name.
STORE_KINDS = {
    "rebrew-functions.toml": "functions",
    "rebrew-data.toml": "data",
    "rebrew-types.toml": "types",
    "rebrew-libraries.toml": "libraries",
    Path(STATE_PATH).name: "replication",
}

#: The function registry document a carry takes from the target.
_REGISTRY = "rebrew-functions.toml"

_SQLITE_SIDECARS = ("-journal", "-wal", "-shm")


class MetadataSetError(RebrewError):
    """A project tree whose metadata cannot be described."""


def _utf8(path: str) -> bytes:
    return path.encode("utf-8", errors="surrogateescape")


def metadata_backend(root: Path) -> str:
    """The one local backend *root*'s config selects for reading and writing."""
    try:
        reads, writes = backend_routes(read_config(root).get("metadata", {}))
    except ValueError as exc:
        raise MetadataSetError(str(exc)) from exc
    if len(reads) != 1 or writes != reads or reads[0] not in LOCAL_BACKENDS:
        raise MetadataSetError("metadata requires one local backend, toml or sqlite")
    return reads[0]


def _store(root: Path, backend: str, relative: str) -> MetadataStore:
    """The *backend* store of one logical document under *root*.

    The replication state is no managed collection, so storage selection would
    always answer its TOML file; under SQLite it is a document of the database.
    """
    if relative == STATE_PATH and backend == "sqlite":
        return SqliteStore(root / relative, root)
    return metadata_store(root / relative, backend=backend, root=root)


def _is_toml_metadata(path: Path) -> bool:
    """A TOML store file or one of its ``.d`` drop-ins."""
    names = managed_metadata_filenames()
    return path.name in names or (
        path.suffix == ".toml"
        and path.parent.suffix == ".d"
        and path.parent.with_suffix(".toml").name in names
    )


def _refuse_foreign(root: Path, backend: str) -> None:
    """Refuse a file of the other backend: it would be carried and never read."""
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if backend == "toml":
            foreign = path.name == DATABASE_FILENAME or any(
                path.name == DATABASE_FILENAME + suffix for suffix in _SQLITE_SIDECARS
            )
        else:
            foreign = relative == STATE_PATH or _is_toml_metadata(path)
        if foreign:
            raise MetadataSetError(f"{relative} is not read by this project's {backend} metadata")


def _logical_digests(root: Path, backend: str) -> dict[str, str]:
    if backend == "sqlite":
        database = root / DATABASE_FILENAME
        if not database.is_file():
            raise MetadataSetError(f"sqlite metadata requires {DATABASE_FILENAME}")
        return metadata_database_documents(database)
    stores = project_metadata_stores(root, backend="toml", recursive=True)
    documents = [store.path.relative_to(root).as_posix() for store in stores]
    if (root / STATE_PATH).is_file():
        documents.append(STATE_PATH)
    digests = {}
    for relative in documents:
        digest = _store(root, backend, relative).digest()
        if digest is not None:
            digests[relative] = digest
    return digests


def _physical_files(root: Path, backend: str, documents: dict[str, str]) -> list[Path]:
    if backend == "sqlite":
        return [root / DATABASE_FILENAME]
    return [
        path
        for relative in documents
        for path in toml_fragment_paths(_store(root, backend, relative))
    ]


def describe_metadata(root: Path, *, exclusive: bool = True) -> dict[str, Any]:
    """The descriptor of the metadata *root*'s config reads.

    ``files`` are the physical files with the SHA-256 of their bytes;
    ``documents`` the logical documents, hashed over the storage layer's
    snapshot. Every document is parsed, so a malformed one is refused.
    *exclusive* refuses a tree that also holds the other backend's files, as a
    supplied file set must; a worker's own tree keeps a migration's source files.
    """
    backend = metadata_backend(root)
    if exclusive:
        _refuse_foreign(root, backend)
    try:
        documents = _logical_digests(root, backend)
        for relative in documents:
            _store(root, backend, relative).read(f"{relative} metadata")
        files = _physical_files(root, backend, documents)
    except (OSError, ValueError) as exc:
        raise MetadataSetError(str(exc)) from exc
    return {
        "files": sorted(
            (
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in files
            ),
            key=lambda entry: _utf8(entry["path"]),
        ),
        "documents": [
            {"path": path, "logical_sha256": documents[path]}
            for path in sorted(documents, key=_utf8)
        ],
    }


def read_metadata_documents(root: Path) -> dict[str, dict[str, Any]]:
    """Every logical document *root* reads, parsed through its storage backend."""
    backend = metadata_backend(root)
    _refuse_foreign(root, backend)
    try:
        return {
            relative: _store(root, backend, relative).read(f"{relative} metadata")
            for relative in _logical_digests(root, backend)
        }
    except (OSError, ValueError) as exc:
        raise MetadataSetError(str(exc)) from exc


def _json_value(value: Any) -> Any:
    """A TOML value as JSON: dates and times as ISO 8601 text, non-finite floats as text."""
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


def _records(path: str, document: dict[str, Any]) -> dict[tuple[str, ...], dict[str, Any]]:
    """The document's records by key path; its top-level scalars are the empty key."""
    records: dict[tuple[str, ...], dict[str, Any]] = {}
    scalars = {key: value for key, value in document.items() if not isinstance(value, dict)}
    if scalars:
        records[()] = scalars
    tables = {key: value for key, value in document.items() if isinstance(value, dict)}
    try:
        for keys, value in metadata_records(tables, Path(path)):
            records[keys] = value if isinstance(value, dict) else {"": value}
    except AttributeError as exc:
        raise MetadataSetError(f"{path}: a record container is not a table") from exc
    return records


def diff_metadata(before: Path, after: Path) -> list[dict[str, Any]]:
    """Every record that differs between two project trees, field by field."""
    old, new = read_metadata_documents(before), read_metadata_documents(after)
    changes = []
    for document in sorted(old.keys() | new.keys(), key=_utf8):
        old_records = _records(document, old.get(document, {}))
        new_records = _records(document, new.get(document, {}))
        for key in sorted(
            old_records.keys() | new_records.keys(), key=lambda keys: [_utf8(k) for k in keys]
        ):
            was, now = old_records.get(key), new_records.get(key)
            if was == now:
                continue
            was_fields, now_fields = was or {}, now or {}
            fields = [
                {
                    "field": name,
                    "before": _json_value(was_fields.get(name)),
                    "after": _json_value(now_fields.get(name)),
                }
                for name in sorted(was_fields.keys() | now_fields.keys(), key=_utf8)
                if name not in was_fields
                or name not in now_fields
                or was_fields[name] != now_fields[name]
            ]
            address = parse_metadata_key(key[0]) if len(key) == 1 else None
            changes.append(
                {
                    "document": document,
                    "store": STORE_KINDS[Path(document).name],
                    "key": list(key),
                    "module": address[0] if address else "",
                    "va": address[1] if address else None,
                    "change": "added" if was is None else "removed" if now is None else "changed",
                    "fields": fields,
                }
            )
    return changes


def _document_texts(root: Path, backend: str) -> dict[str, bytes]:
    """Each logical document as one TOML text; a store with drop-ins is merged."""
    texts: dict[str, bytes] = {}
    for relative in _logical_digests(root, backend):
        store = _store(root, backend, relative)
        if backend == "toml" and toml_fragment_paths(store) != (store.path,):
            merged = store.read(f"{relative} metadata", roundtrip=True)
            texts[relative] = tomlkit.dumps(merged).encode("utf-8")
            continue
        content = store.snapshot()
        if content is not None:
            texts[relative] = content
    return texts


def _set_record(document: Any, keys: tuple[str, ...], value: Any) -> None:
    table = document
    for key in keys[:-1]:
        if key not in table:
            table[key] = tomlkit.table()
        table = table[key]
    table[keys[-1]] = value


def _merged_registry(path: str, published: bytes, fresh: bytes) -> bytes:
    """The published function registry with the records only a fresh analysis found.

    A record in both keeps the published one whole: it carries applied proposals.
    A fresh function whose name or symbol a published row already uses keeps its
    address placeholder instead, so no published identity is renamed.
    """
    from rebrew.metadata.bindings import derive_c_symbol

    merged = tomlkit.parse(published.decode("utf-8"))
    kept = dict(metadata_records(merged, Path(path)))
    names = {row.get("name") for row in kept.values() if isinstance(row, dict)} - {None}
    symbols = {row.get("symbol") for row in kept.values() if isinstance(row, dict)} - {None}
    for keys, value in metadata_records(tomlkit.parse(fresh.decode("utf-8")), Path(path)):
        if keys in kept:
            continue
        address = parse_metadata_key(keys[0]) if len(keys) == 1 else None
        if (
            address is not None
            and isinstance(value, dict)
            and (value.get("name") in names or value.get("symbol") in symbols)
        ):
            placeholder = f"fcn_{address[1]:08x}"
            value["name"] = placeholder
            value["symbol"] = derive_c_symbol(placeholder, "")
            if placeholder in names or value["symbol"] in symbols:
                raise MetadataSetError(f"{keys[0]}: its placeholder name is already published")
        _set_record(merged, keys, value)
    return tomlkit.dumps(merged).encode("utf-8")


def carry_metadata(capture: Path, target: Path, into: Path) -> None:
    """Write into *into* a target's metadata carried onto a fresh capture of its binary.

    *into* gets the target's ``rebrew-project.toml`` and the capture's logical
    documents, each function registry the target published merged per record
    (``_merged_registry``). A SQLite capture is imported through the reviewed migration
    (preview, then apply with its expected digest), which selects SQLite in the
    config; the result must hold exactly the documents written.
    """
    from rebrew.config import load_config
    from rebrew.metadata_transfer import migrate_metadata

    backend = metadata_backend(capture)
    captured = _document_texts(capture, backend)
    published = _document_texts(target, metadata_backend(target))
    documents = dict(captured)
    for relative, text in published.items():
        if Path(relative).name == _REGISTRY:
            fresh = captured.get(relative)
            documents[relative] = text if fresh is None else _merged_registry(relative, text, fresh)
    if not any(Path(path).name == _REGISTRY for path in documents):
        raise MetadataSetError(f"carried metadata holds no {_REGISTRY}")
    config = tomlkit.parse((target / "rebrew-project.toml").read_text(encoding="utf-8"))
    config.pop("metadata", None)
    (into / "rebrew-project.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    written = []
    for relative, text in documents.items():
        destination = into / relative
        if not destination.resolve().is_relative_to(into.resolve()):
            raise MetadataSetError(f"{relative} leaves the carried project")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(text)
        written.append(destination)
    if backend == "sqlite":
        cfg = load_config(into)
        preview = migrate_metadata(cfg, "sqlite", dry_run=True)
        migrate_metadata(cfg, "sqlite", expected_digest=preview["input_digest"])
        # The migration leaves its TOML sources; the carried project reads only the store.
        for path in written:
            path.chmod(0o644)
            path.unlink()
    expected = {path: hashlib.sha256(text).hexdigest() for path, text in documents.items()}
    carried = describe_metadata(into)
    if {item["path"]: item["logical_sha256"] for item in carried["documents"]} != expected:
        raise MetadataSetError("carried metadata differs from the documents written")
