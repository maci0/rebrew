"""Strict schemas for addressless definitions and support files in the function store."""

from dataclasses import dataclass
lazy from pathlib import PurePosixPath
lazy from typing import Any

lazy from rebrew.utils import preset_module_key


def validate_identity_file(value: str) -> str:
    """Return *value* when it is a project-relative source path.

    The stored ``file`` identity is joined onto a project root by several
    consumers (``verify`` compiles it, ``rename`` rewrites it, BinSync reads
    it), and an absolute path or ``..`` segment makes that join read whatever
    the file's author chose (``docs/THREAT_MODEL.md`` records the exposure).
    Rejecting it at the one write gate keeps a cloned project's metadata from
    naming a path outside the clone.  An empty value stays empty: a row
    without identity is legal, and ``record_function_rows`` skips it.
    """
    text = str(value).strip()
    if not text:
        return ""
    normalised = text.replace("\\", "/")
    if normalised.startswith("/") or (len(normalised) > 1 and normalised[1] == ":"):
        raise ValueError(f"file {value!r} must be relative to the project, not absolute")
    # Only a path containing ".." can have a ".." part; building the parsed
    # path for every plain row made this the most expensive check in the
    # compiled-source binding loop.
    if ".." in normalised and ".." in PurePosixPath(normalised).parts:
        raise ValueError(f"file {value!r} must not escape the project with '..'")
    return text


@dataclass(frozen=True)
class AssemblyProvenance:
    """One reviewed definition, bound to its content and a target module."""

    file: str
    symbol: str
    module: str
    source_hash: str
    evidence: str


@dataclass(frozen=True)
class SourceFilePurpose:
    """A target-scoped reason for a support translation unit with no native VA."""

    file: str
    module: str
    purpose: str


def validate_source_metadata(document: Any) -> tuple[AssemblyProvenance, ...]:
    """Validate the reserved source section and return its definition receipts."""
    if not isinstance(document, dict) or set(document) != {"definitions", "files"}:
        raise ValueError("source metadata requires definitions and files")
    validate_source_files(document["files"])
    definitions = document["definitions"]
    if not isinstance(definitions, dict):
        raise ValueError("source provenance definitions must be a table")
    records = []
    for file, symbols in definitions.items():
        if (
            not isinstance(file, str)
            or not file
            or validate_identity_file(file) != file
            or PurePosixPath(file).as_posix() != file
            or "\\" in file
        ):
            raise ValueError(f"invalid source provenance file {file!r}")
        if not isinstance(symbols, dict):
            raise ValueError(f"source provenance for {file!r} must be a table")
        for symbol, modules in symbols.items():
            if (
                not isinstance(symbol, str)
                or not symbol.isidentifier()
                or not isinstance(modules, dict)
            ):
                raise ValueError(f"invalid source definition {file!r}: {symbol!r}")
            for module, entry in modules.items():
                if (
                    not isinstance(module, str)
                    or not module
                    or preset_module_key(module) != module
                    or not isinstance(entry, dict)
                ):
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


def validate_source_files(files: Any) -> tuple[SourceFilePurpose, ...]:
    """Validate target-scoped support purposes without assigning addresses."""
    if not isinstance(files, dict):
        raise ValueError("source metadata files must be a table")
    records = []
    for file, modules in files.items():
        if (
            not isinstance(file, str)
            or not file
            or validate_identity_file(file) != file
            or PurePosixPath(file).as_posix() != file
            or "\\" in file
        ):
            raise ValueError(f"invalid source metadata file {file!r}")
        if not isinstance(modules, dict):
            raise ValueError(f"source file targets for {file!r} must be a table")
        for module, entry in modules.items():
            if (
                not isinstance(module, str)
                or not module
                or preset_module_key(module) != module
                or not isinstance(entry, dict)
            ):
                raise ValueError(f"invalid source file target {module!r}")
            if (
                set(entry) != {"purpose"}
                or not isinstance(entry["purpose"], str)
                or not entry["purpose"].strip()
            ):
                raise ValueError(f"source support file {file!r} requires a non-empty purpose")
            records.append(SourceFilePurpose(file, module, entry["purpose"]))
    return tuple(records)
