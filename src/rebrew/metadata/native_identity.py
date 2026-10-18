"""Locked publication of reviewed native names, separate from source providers."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rebrew.metadata.document import load_metadata_for_write, resolve_metadata_key, stamp_format
from rebrew.metadata.functions import (
    FUNCTION_IDENTITY_FIELDS,
    METADATA_FIELDS,
    METADATA_FILENAME,
    resolve_metadata_dir,
)
from rebrew.metadata.storage import input_digest, metadata_store, metadata_write_lock


def validate_native_identity(value: Any) -> dict[str, Any]:
    """Validate a durable full-object proof receipt rather than a comparison status."""
    if not isinstance(value, dict) or set(value) != {
        "symbol",
        "size",
        "binary_hash",
        "object_hash",
        "bindings",
        "claim",
        "reason",
        "reviewed_at",
    }:
        raise ValueError("invalid reviewed native identity receipt")
    if not isinstance(value["symbol"], str) or not value["symbol"].strip():
        raise ValueError("native identity requires a symbol")
    if type(value["size"]) is not int or value["size"] <= 0:
        raise ValueError("native identity requires a complete positive extent")
    for key in ("binary_hash", "object_hash"):
        if (
            not isinstance(value[key], str)
            or len(value[key]) != 64
            or any(c not in "0123456789abcdef" for c in value[key])
        ):
            raise ValueError("native identity requires complete SHA-256 inputs")
    if (
        not isinstance(value["reason"], str)
        or not value["reason"].strip()
        or len(value["reason"]) > 2000
    ):
        raise ValueError("native identity reason must contain 1–2000 characters")
    stamp = datetime.fromisoformat(value["reviewed_at"])
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("native identity review time requires a timezone")
    if not isinstance(value["bindings"], dict) or any(
        not isinstance(k, str) or type(v) is not int or v < 0 for k, v in value["bindings"].items()
    ):
        raise ValueError("native identity requires exact named operand bindings")
    if (
        not isinstance(value["claim"], dict)
        or set(value["claim"]) - set(FUNCTION_IDENTITY_FIELDS)
        or any(not isinstance(v, str) for v in value["claim"].values())
    ):
        raise ValueError("invalid native identity source claim")
    return copy.deepcopy(value)


def record_native_identity(
    directory: Path,
    module: str,
    va: int,
    evidence: dict[str, Any],
    *,
    expected_digest: str,
    expected_inputs: dict[Path, str],
) -> None:
    """Publish a checked receipt against the exact metadata and proof inputs."""
    evidence = validate_native_identity(evidence)
    directory = resolve_metadata_dir(directory)
    path = directory / METADATA_FILENAME
    with metadata_write_lock(directory, METADATA_FILENAME):
        if metadata_store(path).digest() != expected_digest:
            raise ValueError("native identity metadata changed since review")
        for input_path, digest in expected_inputs.items():
            if (
                metadata_store(path).digest() if input_path == path else input_digest(input_path)
            ) != digest:
                raise ValueError(f"native identity input changed: {input_path}")
        doc = load_metadata_for_write(
            path,
            "function metadata",
            known_fields=METADATA_FIELDS | {k.upper() for k in FUNCTION_IDENTITY_FIELDS},
        )
        key = resolve_metadata_key(doc, module, va)
        entry = doc.get(key, {})
        if (
            entry.get("kind") != "LIBRARY"
            or entry.get("size") != evidence["size"]
            or {k: entry[k] for k in FUNCTION_IDENTITY_FIELDS if k in entry} != evidence["claim"]
        ):
            raise ValueError("native library claim changed since review")
        entry["native_identity"] = evidence
        stamp_format(doc)
        metadata_store(path).write(doc, "metadata")


def native_identity_receipt(
    symbol: str,
    size: int,
    binary_hash: str,
    object_hash: str,
    bindings: dict[str, int],
    claim: dict[str, str],
    reason: str,
) -> dict[str, Any]:
    """Construct a validated receipt after strict full-extent proof succeeds."""
    return validate_native_identity(
        {
            "symbol": symbol,
            "size": size,
            "binary_hash": binary_hash,
            "object_hash": object_hash,
            "bindings": bindings,
            "claim": claim,
            "reason": reason,
            "reviewed_at": datetime.now(UTC).isoformat(),
        }
    )
