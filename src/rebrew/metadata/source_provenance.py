"""Target-scoped original-assembly evidence for source definitions without VAs."""

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

import tomlkit

from rebrew.c_parser import find_function_name_in_node, mask_msvc_syntax, parse_c_source
from rebrew.metadata.document import metadata_write_lock
from rebrew.metadata.functions import validate_identity_file
from rebrew.utils import (
    atomic_write_locked,
    load_toml_for_write_strict,
    load_tomllib,
    preset_module_key,
    read_source_text,
)

SOURCE_PROVENANCE_FILENAME = "rebrew-source.toml"


@dataclass(frozen=True)
class AssemblyProvenance:
    """One reviewed definition, bound to its content and a target module."""

    file: str
    symbol: str
    module: str
    source_hash: str
    evidence: str


def function_definition_hashes(source: str) -> dict[str, str]:
    """Hash unique, parseable definitions; ambiguous conditional bodies are excluded."""
    tree, parsed = parse_c_source(mask_msvc_syntax(source))
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


def _validate(document: Any) -> tuple[AssemblyProvenance, ...]:
    if (
        set(document) != {"format", "definitions", "files"}
        or not isinstance(document["format"], int)
        or isinstance(document["format"], bool)
        or document["format"] != 2
    ):
        raise ValueError("source metadata requires format = 2, definitions and files")
    _validate_files(document["files"])
    definitions = document["definitions"]
    if not isinstance(definitions, dict):
        raise ValueError("source provenance definitions must be a table")
    records = []
    for file, symbols in definitions.items():
        if (
            not file
            or validate_identity_file(file) != file
            or PurePosixPath(file).as_posix() != file
            or "\\" in file
        ):
            raise ValueError(f"invalid source provenance file {file!r}")
        if not isinstance(symbols, dict):
            raise ValueError(f"source provenance for {file!r} must be a table")
        for symbol, modules in symbols.items():
            if not symbol.isidentifier() or not isinstance(modules, dict):
                raise ValueError(f"invalid source definition {file!r}: {symbol!r}")
            for module, entry in modules.items():
                if not module or preset_module_key(module) != module or not isinstance(entry, dict):
                    raise ValueError(f"invalid source provenance module {module!r}")
                if set(entry) != {"source_hash", "evidence"}:
                    raise ValueError(f"invalid source provenance fields for {symbol!r}")
                digest, evidence = entry["source_hash"], entry["evidence"]
                if (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(c not in "0123456789abcdef" for c in digest)
                ):
                    raise ValueError(f"invalid source hash for {symbol!r}")
                if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 2000:
                    raise ValueError(
                        f"original-assembly evidence for {symbol!r} must contain 1–2000 characters"
                    )
                records.append(AssemblyProvenance(file, symbol, module, digest, evidence))
    return tuple(records)


@lru_cache(maxsize=16)
def _read(path: Path, fingerprint: tuple[int, int, int]) -> tuple[AssemblyProvenance, ...]:
    return _validate(load_tomllib(path))


def load_source_provenance(directory: Path) -> tuple[AssemblyProvenance, ...]:
    """Read immutable records, rejecting malformed stores instead of trusting evidence."""
    path = (directory / SOURCE_PROVENANCE_FILENAME).resolve()
    try:
        stat = path.stat()
    except FileNotFoundError:
        return ()
    return _read(path, (stat.st_mtime_ns, stat.st_size, stat.st_ino))


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
        _validate({"format": 2, "definitions": {relative: {symbol: {module: entry}}}, "files": {}})
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
        doc = load_toml_for_write_strict(path, "source provenance")
        if path.exists():
            _validate(doc)
        else:
            doc["format"] = 2
            doc["definitions"] = tomlkit.table()
            doc["files"] = tomlkit.table()
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
        doc["format"] = 2
        atomic_write_locked(path, tomlkit.dumps(doc))
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
    if not edits or not path.exists():
        return
    with metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME):
        doc = load_toml_for_write_strict(path, "source provenance")
        _validate(doc)
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
        if changed and not dry_run:
            atomic_write_locked(path, tomlkit.dumps(doc))


@dataclass(frozen=True)
class SourceFilePurpose:
    """A target-scoped reason for a support translation unit with no native VA."""

    file: str
    module: str
    purpose: str


def _validate_files(files: Any) -> tuple[SourceFilePurpose, ...]:
    if not isinstance(files, dict):
        raise ValueError("source metadata files must be a table")
    records = []
    for file, modules in files.items():
        if validate_identity_file(file) != file or PurePosixPath(file).as_posix() != file:
            raise ValueError(f"invalid source metadata file {file!r}")
        if not isinstance(modules, dict):
            raise ValueError(f"source file targets for {file!r} must be a table")
        for module, entry in modules.items():
            if not module or preset_module_key(module) != module or not isinstance(entry, dict):
                raise ValueError(f"invalid source file target {module!r}")
            if (
                set(entry) != {"purpose"}
                or not isinstance(entry["purpose"], str)
                or not entry["purpose"].strip()
            ):
                raise ValueError(f"source support file {file!r} requires a non-empty purpose")
            records.append(SourceFilePurpose(file, module, entry["purpose"]))
    return tuple(records)


def load_source_files(directory: Path) -> tuple[SourceFilePurpose, ...]:
    """Read validated file metadata; source comments never supply file purpose."""
    path = directory / SOURCE_PROVENANCE_FILENAME
    if not path.exists():
        return ()
    document = load_tomllib(path)
    _validate(document)
    return _validate_files(document["files"])


def set_source_file(directory: Path, file: str, module: str, purpose: str) -> None:
    """Record a support file's purpose under the shared metadata lock."""
    path = directory / SOURCE_PROVENANCE_FILENAME
    entry = {file: {preset_module_key(module): {"purpose": purpose}}}
    _validate_files(entry)
    with metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME):
        doc = (
            load_toml_for_write_strict(path, "source metadata")
            if path.exists()
            else tomlkit.document()
        )
        if path.exists():
            _validate(doc)
        else:
            doc.update({"format": 2, "definitions": {}, "files": {}})
        modules = doc["files"].setdefault(file, {})
        if modules.get(preset_module_key(module)) == {"purpose": purpose}:
            return
        modules[preset_module_key(module)] = {"purpose": purpose}
        _validate(doc)
        atomic_write_locked(path, tomlkit.dumps(doc))


def replace_source_metadata(
    directory: Path,
    definitions: Sequence[AssemblyProvenance],
    files: Sequence[SourceFilePurpose],
    *,
    expected_hash: str | None,
) -> None:
    """Replace source metadata from reviewed records, requiring the prior byte digest."""
    doc = tomlkit.document()
    doc.update({"format": 2, "definitions": {}, "files": {}})
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
    _validate(doc)
    path = directory / SOURCE_PROVENANCE_FILENAME
    with metadata_write_lock(directory, SOURCE_PROVENANCE_FILENAME):
        current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        if current != expected_hash:
            raise ValueError(f"{path} changed since its records were reviewed")
        atomic_write_locked(path, tomlkit.dumps(doc))
