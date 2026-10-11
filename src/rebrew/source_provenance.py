"""Target-scoped original-assembly evidence for source definitions without VAs."""

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

import tomlkit

from rebrew.c_parser import find_function_name_in_node, mask_msvc_syntax, parse_c_source
from rebrew.metadata import validate_identity_file
from rebrew.metadata_doc import metadata_write_lock
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
        set(document) != {"format", "definitions"}
        or not isinstance(document["format"], int)
        or isinstance(document["format"], bool)
        or document["format"] != 1
    ):
        raise ValueError("source provenance requires format = 1 and definitions")
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
        _validate({"format": 1, "definitions": {relative: {symbol: {module: entry}}}})
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
            doc["format"] = 1
            doc["definitions"] = tomlkit.table()
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
        doc["format"] = 1
        atomic_write_locked(path, tomlkit.dumps(doc))
    return report
