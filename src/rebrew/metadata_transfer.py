"""Reviewed transfer of managed metadata between storage backends."""

lazy import contextlib
lazy import hashlib
lazy import json
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
lazy from rebrew.utils import atomic_write_text, load_toml_for_write_strict


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


def migrate_metadata(
    cfg: ProjectConfig, backend: str, *, dry_run: bool = False, expected_digest: str | None = None
) -> dict[str, Any]:
    """Copy validated documents, then select the destination; retain the source unchanged."""
    if backend not in available_metadata_backends():
        raise ValueError(f"unknown metadata backend {backend!r}")
    root = cfg.root.resolve()
    config_path = root / "rebrew-project.toml"

    def prepare() -> tuple[
        tuple[MetadataStore, ...], list[tuple[Path, dict[str, Any]]], dict[str, Any]
    ]:
        source = metadata_store(root / "rebrew-functions.toml").name
        metadata_format(root / "rebrew-functions.toml")
        stores = _stores(cfg)
        destinations = _stores(cfg, backend)
        inputs = {f"source:{store.path}": store.digest() for store in stores}
        inputs.update({f"destination:{store.path}": store.digest() for store in destinations})
        inputs[str(config_path)] = hashlib.sha256(config_path.read_bytes()).hexdigest()
        digest = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
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
        if any(store.digest() != inputs[f"source:{store.path}"] for store in stores):
            raise ValueError("metadata changed while preparing transfer; retry")
        return (
            stores,
            documents,
            {
                "source": source,
                "backend": backend,
                "experimental": backend == "sqlite",
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

    stores, documents, report = prepare()
    if dry_run or not report["changed"]:
        return report
    with project_toml_lock(root), contextlib.ExitStack() as locks:
        for store in sorted(
            {store.location: store for store in stores}.values(),
            key=lambda store: str(store.location),
        ):
            locks.enter_context(store.transaction())
        stores, documents, report = prepare()
        if not report["changed"]:
            return report
        destination = metadata_store(root / "rebrew-functions.toml", backend=backend, root=root)
        with destination.transaction():
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
