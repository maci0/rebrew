"""Target-scoped original-assembly evidence for source definitions without VAs."""

from functools import lru_cache
lazy import hashlib
lazy from collections.abc import Sequence
lazy from contextlib import nullcontext
lazy from copy import deepcopy
lazy from pathlib import Path
lazy from typing import Any

lazy import tomlkit

from rebrew.metadata.functions import FUNCTION_IDENTITY_FIELDS, METADATA_FIELDS
lazy from rebrew.c_parser import (
    find_function_name_in_node,
    mask_msvc_syntax,
    mask_va_arg_types,
    parse_c_source,
)
lazy from rebrew.metadata.document import (
    FUNCTION_FORMAT_VERSION,
    load_metadata_for_write,
    metadata_format,
    parse_metadata_doc,
)
lazy from rebrew.metadata.source_schema import (
    AssemblyProvenance,
    SourceFilePurpose,
    validate_identity_file,
    validate_source_files,
    validate_source_metadata,
)
lazy from rebrew.metadata.storage import metadata_store, metadata_write_lock
lazy from rebrew.utils import (
    preset_module_key,
    read_source_text,
)

__all__ = [
    "AssemblyProvenance",
    "SourceFilePurpose",
    "SOURCE_PROVENANCE_FILENAME",
    "function_definition_hashes",
    "load_source_provenance",
    "document_assembly",
    "rename_source_provenance",
    "load_source_files",
    "set_source_file",
    "replace_source_metadata",
    "consolidate_source_metadata",
]

SOURCE_PROVENANCE_FILENAME = "rebrew-functions.toml"
_FUNCTION_FIELDS = METADATA_FIELDS | frozenset(k.upper() for k in FUNCTION_IDENTITY_FIELDS)


def function_definition_hashes(source: str) -> dict[str, str]:
    """Hash unique, parseable definitions; ambiguous conditional bodies are excluded."""
    tree, parsed = parse_c_source(mask_va_arg_types(mask_msvc_syntax(source)))
    raw = source.encode("utf-8", errors="surrogateescape")
    hashes: dict[str, str] = {}
    ambiguous: set[str] = set()
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type != "function_definition":
            pending.extend(node.children)
            continue
        declarator = node.child_by_field_name("declarator")
        name = find_function_name_in_node(declarator, parsed) if declarator else None
        if not name:
            continue
        if name in hashes or node.has_error:
            ambiguous.add(name)
        hashes[name] = hashlib.sha256(raw[node.start_byte : node.end_byte]).hexdigest()
    return {name: digest for name, digest in hashes.items() if name not in ambiguous}


@lru_cache(maxsize=16)
def _read(
    path: Path, backend: str, root: Path, fingerprint: tuple[tuple[str, int, int, int, int], ...]
) -> tuple[tuple[AssemblyProvenance, ...], tuple[SourceFilePurpose, ...]]:
    document = metadata_store(path, backend=backend, root=root).read("source metadata")
    parse_metadata_doc(
        document, known_fields=_FUNCTION_FIELDS, source=str(path), version=FUNCTION_FORMAT_VERSION
    )
    source = document.get("source", {"definitions": {}, "files": {}})
    return validate_source_metadata(source), validate_source_files(source["files"])


@lru_cache(maxsize=64)
def _resolved_store_path(directory: Path) -> Path:
    """Store path resolved once per directory spelling.

    Both provenance views are read repeatedly per scan; the symlink walk is
    process-constant for a project directory.
    """
    return (directory / SOURCE_PROVENANCE_FILENAME).resolve()


def load_source_provenance(directory: Path) -> tuple[AssemblyProvenance, ...]:
    """Read immutable records, rejecting malformed stores instead of trusting evidence."""
    path = _resolved_store_path(directory)
    metadata_format(path)
    store = metadata_store(path)
    fingerprint = store.fingerprint()
    return _read(path, store.name, store.root, fingerprint)[0] if fingerprint else ()


def document_assembly(
    directory: Path,
    file: Path,
    symbol: str,
    module: str,
    evidence: str | None,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Record or clear evidence atomically; never write target identities or verdicts."""
    directory = directory.resolve()
    file = (directory / file).resolve()
    relative = file.relative_to(directory).as_posix()
    validate_identity_file(relative)
    if not symbol.isidentifier() or not module.strip():
        raise ValueError("a C symbol and target module are required")
    module = preset_module_key(module)
    entry = None
    if evidence is not None:
        source, _ = read_source_text(file)
        hashes = function_definition_hashes(source)
        if symbol not in hashes:
            raise ValueError(f"{symbol!r} has no unique parseable definition in {relative}")
        entry = {"source_hash": hashes[symbol], "evidence": evidence.strip()}
        validate_source_metadata(
            {"definitions": {relative: {symbol: {module: entry}}}, "files": {}}
        )
    path = directory / SOURCE_PROVENANCE_FILENAME
    report = {
        "file": relative,
        "symbol": symbol,
        "module": module,
        "evidence": entry,
        "cleared": entry is None,
        "dry_run": dry_run,
    }
    if dry_run:
        load_source_provenance(directory)
        return report
    with metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME):
        store = load_metadata_for_write(path, "function metadata", known_fields=_FUNCTION_FIELDS)
        doc = store.setdefault("source", {"definitions": {}, "files": {}})
        definitions = doc.setdefault("definitions", {})
        modules = definitions.get(relative, {}).get(symbol, {})
        if modules.get(module) == entry:
            return report
        if entry is None:
            del modules[module]
            if not modules:
                del definitions[relative][symbol]
            if not definitions[relative]:
                del definitions[relative]
            if not definitions:
                doc["definitions"] = tomlkit.table()
        else:
            definitions.setdefault(relative, {}).setdefault(symbol, {})[module] = entry
        metadata_store(path).write(store, "function metadata")
    return report


def rename_source_provenance(
    directory: Path,
    edits: dict[Path, tuple[str, str]],
    *,
    symbol_rename: tuple[str, str] | None = None,
    move: tuple[Path, Path] | None = None,
    dry_run: bool = False,
) -> None:
    """Follow mechanical source renames without making stale evidence current."""
    directory = directory.resolve()
    path = directory / SOURCE_PROVENANCE_FILENAME
    if (not edits and move is None) or not metadata_store(path).exists():
        return
    with nullcontext() if dry_run else metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME):
        store = load_metadata_for_write(path, "function metadata", known_fields=_FUNCTION_FIELDS)
        doc = store.setdefault("source", {"definitions": {}, "files": {}})
        definitions = doc["definitions"]
        changed = False
        if move:
            old_relative = move[0].resolve().relative_to(directory).as_posix()
            new_relative = move[1].resolve().relative_to(directory).as_posix()
            files = doc["files"]
            if old_relative != new_relative and old_relative in files:
                if new_relative in files:
                    raise ValueError(f"source file metadata already exists for {new_relative}")
                files[new_relative] = files.pop(old_relative)
                changed = True
        for file, (before, after) in edits.items():
            file = file.resolve()
            if not file.is_relative_to(directory):
                continue
            relative = file.relative_to(directory).as_posix()
            records = definitions.get(relative)
            if not records:
                continue
            destination = move[1].resolve() if move and file == move[0].resolve() else file
            new_relative = destination.relative_to(directory).as_posix()
            if new_relative != relative and new_relative in definitions:
                raise ValueError(f"source provenance already exists for {new_relative}")
            old_hashes, new_hashes = (function_definition_hashes(text) for text in (before, after))
            for symbol in list(records):
                new_symbol = (
                    symbol_rename[1] if symbol_rename and symbol == symbol_rename[0] else symbol
                )
                if new_symbol != symbol and new_symbol in records:
                    raise ValueError(
                        f"source provenance already exists for {relative}:{new_symbol}"
                    )
                modules = records[symbol]
                for entry in modules.values():
                    if (
                        entry["source_hash"] == old_hashes.get(symbol)
                        and new_symbol in new_hashes
                        and entry["source_hash"] != new_hashes[new_symbol]
                    ):
                        entry["source_hash"] = new_hashes[new_symbol]
                        changed = True
                if new_symbol != symbol:
                    del records[symbol]
                    records[new_symbol] = modules
                    changed = True
            if new_relative != relative:
                del definitions[relative]
                definitions[new_relative] = records
                changed = True
        if move and not edits:
            # A pure move keeps the definitions and their hashes; only the
            # path key changes.  Without this the documented evidence stays
            # filed under a path nobody reads any more.
            old_relative = move[0].resolve().relative_to(directory).as_posix()
            new_relative = move[1].resolve().relative_to(directory).as_posix()
            if old_relative != new_relative and old_relative in definitions:
                if new_relative in definitions:
                    raise ValueError(f"source provenance already exists for {new_relative}")
                definitions[new_relative] = definitions.pop(old_relative)
                changed = True
        if changed and not dry_run:
            metadata_store(path).write(store, "function metadata")


def load_source_files(directory: Path) -> tuple[SourceFilePurpose, ...]:
    """Read validated file metadata; source comments never supply file purpose."""
    path = _resolved_store_path(directory)
    metadata_format(path)
    store = metadata_store(path)
    fingerprint = store.fingerprint()
    return _read(path, store.name, store.root, fingerprint)[1] if fingerprint else ()


def set_source_file(directory: Path, file: str, module: str, purpose: str) -> None:
    """Record a support file's purpose under the shared metadata lock."""
    path = directory / SOURCE_PROVENANCE_FILENAME
    entry = {file: {preset_module_key(module): {"purpose": purpose}}}
    validate_source_files(entry)
    with metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME):
        store = load_metadata_for_write(path, "function metadata", known_fields=_FUNCTION_FIELDS)
        doc = store.setdefault("source", {"definitions": {}, "files": {}})
        modules = doc["files"].setdefault(file, {})
        if modules.get(preset_module_key(module)) == {"purpose": purpose}:
            return
        modules[preset_module_key(module)] = {"purpose": purpose}
        validate_source_metadata(doc)
        metadata_store(path).write(store, "function metadata")


def replace_source_metadata(
    directory: Path,
    definitions: Sequence[AssemblyProvenance],
    files: Sequence[SourceFilePurpose],
    *,
    expected_hash: str | None,
) -> None:
    """Replace source metadata from reviewed records, requiring the prior byte digest."""
    doc = tomlkit.document()
    doc.update({"definitions": {}, "files": {}})
    for record in definitions:
        modules = doc["definitions"].setdefault(record.file, {}).setdefault(record.symbol, {})
        if record.module in modules:
            raise ValueError(f"duplicate definition {record.file}:{record.symbol}:{record.module}")
        modules[record.module] = {"source_hash": record.source_hash, "evidence": record.evidence}
    for file_record in files:
        modules = doc["files"].setdefault(file_record.file, {})
        if file_record.module in modules:
            raise ValueError(f"duplicate source file {file_record.file}:{file_record.module}")
        modules[file_record.module] = {"purpose": file_record.purpose}
    validate_source_metadata(doc)
    path = directory / SOURCE_PROVENANCE_FILENAME
    with metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME):
        current = metadata_store(path).digest()
        if current != expected_hash:
            raise ValueError(f"{path} changed since its records were reviewed")
        store = load_metadata_for_write(path, "function metadata", known_fields=_FUNCTION_FIELDS)
        store["source"] = doc
        metadata_store(path).write(store, "function metadata")


def consolidate_source_metadata(
    directory: Path, *, dry_run: bool = False, expected_digest: str | None = None
) -> dict[str, Any]:
    """Upgrade reviewed format-2 functions and source evidence to the single format-3 store."""
    directory = directory.resolve()
    function_path = directory / SOURCE_PROVENANCE_FILENAME
    selected = metadata_store(function_path)
    if selected.name != "toml":
        raise ValueError("source consolidation requires the TOML backend; migrate to toml first")
    legacy = metadata_store(directory / "rebrew-source.toml")
    source_path = legacy.path
    with (
        nullcontext() if dry_run else metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME),
        nullcontext() if dry_run else metadata_write_lock(directory, source_path.name),
    ):
        function_raw = selected.snapshot()
        source_raw = legacy.snapshot()
        digest = hashlib.sha256()
        for name, raw in ((function_path.name, function_raw), (source_path.name, source_raw)):
            digest.update(name.encode())
            digest.update(b"\0missing\0" if raw is None else b"\0present\0" + raw)
        input_digest = digest.hexdigest()
        store = (
            selected.read("legacy function metadata", roundtrip=True)
            if function_raw is not None
            else tomlkit.document()
        )
        version = store.get("format", 2)
        before_store = deepcopy(store)
        if (not isinstance(version, int) or isinstance(version, bool)) or version not in {
            2,
            FUNCTION_FORMAT_VERSION,
        }:
            raise ValueError("source consolidation requires format-2 or current format-3 functions")
        if function_raw is not None:
            parse_metadata_doc(
                store,
                known_fields=_FUNCTION_FIELDS,
                source=str(function_path),
                version=version,
            )
        imported: dict[str, Any] = {"definitions": {}, "files": {}}
        if source_raw is not None:
            old_source = legacy.read("legacy source metadata", roundtrip=True)
            if (
                set(old_source) != {"format", "definitions", "files"}
                or (
                    not isinstance(old_source["format"], int)
                    or isinstance(old_source["format"], bool)
                )
                or old_source["format"] != 2
            ):
                raise ValueError(
                    "source consolidation requires format = 2, definitions and files in rebrew-source.toml"
                )
            imported = {"definitions": old_source["definitions"], "files": old_source["files"]}
            validate_source_metadata(imported)
            if "source" in store and store["source"] != imported:
                raise ValueError(
                    "function source section conflicts with rebrew-source.toml; no files changed"
                )
            store["source"] = imported
        records = validate_source_metadata(store.get("source", {"definitions": {}, "files": {}}))
        files = validate_source_files(store.get("source", {"files": {}})["files"])
        changed = (
            function_raw is None or version != FUNCTION_FORMAT_VERSION or source_raw is not None
        )
        store["format"] = FUNCTION_FORMAT_VERSION
        parse_metadata_doc(store, source=str(function_path), version=FUNCTION_FORMAT_VERSION)
        report = {
            "dry_run": dry_run,
            "input_digest": input_digest,
            "changed": changed,
            "functions": len(parse_metadata_doc(store, version=FUNCTION_FORMAT_VERSION)),
            "definitions": len(records),
            "files": len(files),
            "retired_source_store": source_raw is not None,
        }
        if not dry_run:
            if expected_digest != input_digest:
                raise ValueError(
                    "source metadata inputs changed or --expected-digest was not supplied; preview consolidation again"
                )
            if changed:
                selected.write(store, "function metadata")
                try:
                    legacy.remove()
                except OSError:
                    if function_raw is None:
                        selected.remove()
                    else:
                        selected.write(before_store, "function metadata")
                    raise
        return report
