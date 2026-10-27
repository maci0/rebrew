"""Complete object proofs for explicitly reviewed native library names."""

from __future__ import annotations

lazy import hashlib
lazy import json
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.coff_reloc import build_name_to_va, smart_reloc_compare
lazy from rebrew.config import ProjectConfig, target_module
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.metadata.functions import FUNCTION_IDENTITY_FIELDS, METADATA_FILENAME, get_entry
lazy from rebrew.metadata.native_identity import native_identity_receipt, record_native_identity
lazy from rebrew.metadata.storage import input_digest, metadata_store
lazy from rebrew.object_evidence import audit_literals, native_span, object_function


def review_native_identity(
    cfg: ProjectConfig,
    va: int,
    obj: Path,
    symbol: str,
    *,
    reason: str,
    dry_run: bool = False,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    """Require full code, exact typed operands and complete literals before trust."""
    metadata_path = cfg.metadata_dir / METADATA_FILENAME
    metadata_raw, binary_raw, object_raw = (
        metadata_store(metadata_path).snapshot(),
        cfg.target_binary.read_bytes(),
        obj.read_bytes(),
    )
    if metadata_raw is None:
        raise ValueError("native identity requires function metadata")
    inputs = {
        metadata_path: hashlib.sha256(metadata_raw).hexdigest(),
        cfg.target_binary: hashlib.sha256(binary_raw).hexdigest(),
        obj: hashlib.sha256(object_raw).hexdigest(),
    }
    digest = hashlib.sha256(
        json.dumps({str(p.resolve()): v for p, v in inputs.items()}, sort_keys=True).encode()
    ).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("native identity inputs changed; review a new preview")
    entry = get_entry(cfg.metadata_dir, va, target_module(cfg))
    if entry.get("kind") != "LIBRARY" or type(entry.get("size")) is not int or entry["size"] <= 0:
        raise ValueError("select a library metadata row with a complete positive SIZE")
    function = object_function(object_raw, symbol, entry["size"])
    binary = load_binary(cfg.target_binary)
    if binary.data != binary_raw:
        raise ValueError("binary changed during native identity review")
    if not any(
        s.is_code_section and s.va <= va and va + entry["size"] <= s.va + min(s.size, s.raw_size)
        for s in binary.sections.values()
    ):
        raise ValueError("native identity requires a complete executable span")
    literal_report = audit_literals(function, binary, va)
    if not literal_report["complete"]:
        raise ValueError("complete literal audit failed; inspect data audit-literals")
    resolver = build_name_to_va(cfg)
    # Literal addresses come from the checked operand, never from a byte search.
    local = {name: va + offset for name, offset in function.local_symbols.items()}
    for row in literal_report["literals"]:
        name, address = row["symbol"], row["native_va"]
        if name in local and local[name] != address:
            raise ValueError("literal conflicts with an object-local binding")
        local[name] = address
    if symbol in resolver and resolver[symbol] != va:
        raise ValueError("native symbol already resolves to a different address")
    local[symbol] = va
    bindings: dict[str, int] = {}
    for reloc in function.relocs:
        if reloc.type == 0:
            continue
        if reloc.symbol not in local:
            # Resolve exactly; avoid tolerant underscore aliases in proof receipts.
            if reloc.symbol not in resolver:
                raise ValueError(f"unresolved strict native operand: {reloc.symbol}")
            bindings[reloc.symbol] = resolver[reloc.symbol]
    matched, _, _, _, invalid = smart_reloc_compare(
        function.code,
        native_span(binary, va, entry["size"]),
        function.relocs,
        {**resolver, **local},
        section_va=va,
        strict=True,
    )
    if not matched or invalid:
        raise ValueError("complete native code/operand proof failed")
    evidence = native_identity_receipt(
        symbol,
        entry["size"],
        inputs[cfg.target_binary],
        inputs[obj],
        bindings,
        {k: entry[k] for k in FUNCTION_IDENTITY_FIELDS if k in entry},
        reason,
    )
    if any(
        (metadata_store(p).digest() if p == metadata_path else input_digest(p)) != value
        for p, value in inputs.items()
    ):
        raise ValueError("native identity inputs changed during review")
    if not dry_run:
        record_native_identity(
            cfg.metadata_dir,
            target_module(cfg),
            va,
            evidence,
            expected_digest=inputs[metadata_path],
            expected_inputs=inputs,
        )
    return {
        "dry_run": dry_run,
        "input_digest": digest,
        "va": va,
        "native_identity": evidence,
        "literal_audit": literal_report,
        "provider_changed": False,
        "status_changed": False,
    }
