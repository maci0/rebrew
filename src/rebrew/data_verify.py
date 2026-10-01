"""data_verify.py - Byte-compare built data sections against the reference.

Track 1 of the gap-analysis goal: rebrew can place data (data_layout fill /
own / converge) but cannot confirm it.  This module compares per-symbol
bytes of a built binary's ``.data`` / ``.rdata`` sections against the
reference bytes, attributed per metadata symbol (right bytes at the right
address vs wrong bytes vs missing symbol).

Pure logic here (dicts in, report out) so it is unit-testable without a
link; the binary-reading thin layer lives in ``verify --data``.
"""

import hashlib
from pathlib import Path
from typing import Any

from rebrew.data_metadata import data_definition_hash, iter_data_symbols


def verify_data_bytes(
    *,
    metadata_path: Path,
    expected: dict[int, bytes],
    actual: dict[int, bytes],
    sizes: dict[int, int],
    sections: tuple[str, ...] = (".data", ".rdata"),
    cfg: Any | None = None,
) -> dict[str, Any]:
    """Compare per-symbol bytes; return ``matched`` / ``mismatched`` / ``missing``.

    *metadata_path* supplies symbol definitions (``rebrew-data.toml``). *expected*
    maps VA to reference bytes, *actual* maps VA to built bytes, and *sizes*
    supplies available extents and a fallback for unsized symbols.
    Only symbols whose metadata ``section`` is in
    *sections* are compared.  Symbols absent from *actual* are ``missing``;
    present-but-different bytes are ``mismatched`` with the first differing
    offset.  Symbols with no name in metadata are skipped (unnamed inventory
    cannot be attributed).
    ``results`` preserves each symbol's ``(module, VA)`` identity and verdict;
    aliases are compared at their own sizes. With *cfg*, other targets are
    excluded from both results and totals. Incomplete reference bytes remain
    UNCHECKED, and incomplete built bytes are missing rather than matched.
    **Coverage is reported, because the summary is otherwise misleading.** A
    symbol is comparable only when its ``section`` is in *sections* *and*
    ``section_symbol_bytes`` could read bytes for it. A zero-fill span inside
    the image is supplied as zeros; a span past that image's virtual size never
    reaches *sizes*. ``total`` counts every named symbol, ``not_comparable``
    the difference, and ``coverage`` is the fraction compared, so a caller can
    tell "122 matched" from "122 of 329 matched".
    """
    from rebrew.data_layout import data_symbol_size
    from rebrew.data_metadata import module_visible_to_target
    from rebrew.utils import load_tomllib

    db = load_tomllib(metadata_path)
    matched = 0
    mismatched: list[dict[str, Any]] = []
    missing: list[str] = []
    compared = 0
    results: list[dict[str, Any]] = []
    for module, va, fields in iter_data_symbols(db, section=None):
        if not fields.get("name") or not module_visible_to_target(module, cfg):
            continue
        name = str(fields["name"])
        size = data_symbol_size(fields, arch=getattr(cfg, "arch", "x86_32"))
        if "size" not in fields and "type" not in fields:
            size = sizes.get(va, 0)
        row = {
            "module": module,
            "va": f"0x{va:x}",
            "name": name,
            "size": size,
            "status": "UNCHECKED",
        }
        definition_hash = data_definition_hash(
            module, va, fields, arch=getattr(cfg, "arch", "x86_32")
        )
        row["definition_hash"] = definition_hash
        digest = hashlib.sha256(definition_hash.encode())
        for label, data in (("reference", expected.get(va)), ("built", actual.get(va))):
            digest.update(label.encode())
            digest.update(b"missing" if data is None else hashlib.sha256(data[:size]).digest())
        row["input_hash"] = digest.hexdigest()
        results.append(row)
        exp = expected.get(va)
        got = actual.get(va)
        if not _section_selected(str(fields.get("section") or ""), sections):
            continue
        if size <= 0 or va not in sizes or exp is None or len(exp) < size:
            continue
        compared += 1
        if got is None or len(got) < size:
            row["status"] = "DRIFT"
            missing.append(name)
            continue
        exp_slice = exp[:size]
        got_slice = got[:size]
        if exp_slice == got_slice:
            row["status"] = "VERIFIED"
            matched += 1
            continue
        first_diff = next(
            (i for i, (a, b) in enumerate(zip(exp_slice, got_slice, strict=False)) if a != b),
            min(len(exp_slice), len(got_slice)),
        )
        row["status"] = "DRIFT"
        row["first_diff"] = first_diff
        mismatched.append(dict(row))
    total = len(results)
    return {
        "matched": matched,
        "mismatched": mismatched,
        "missing": missing,
        "total": total,
        "compared": compared,
        "not_comparable": total - compared,
        "coverage": (compared / total) if total else 0.0,
        "results": results,
    }


# PE images from MSVC keep BSS as the .data tail and the IAT inside .rdata.
# Metadata still labels those rows .bss and .idata.
_SECTION_ALIAS = {".bss": ".data", ".idata": ".rdata"}


def _canonical_section(name: str) -> str:
    return _SECTION_ALIAS.get(name, name)


def _section_selected(declared: str, sections: tuple[str, ...]) -> bool:
    """True when *declared* or its file section is one of *sections*."""
    return declared in sections or _canonical_section(declared) in sections


def section_symbol_bytes(
    *,
    metadata_path: Path,
    binary_path: Path,
    sections: tuple[str, ...] = (".data", ".rdata"),
    cfg: Any | None = None,
    zero_fill: set[int] | None = None,
) -> tuple[dict[int, bytes], dict[int, int]]:
    """Read per-symbol bytes for metadata symbols from *binary_path* sections.

    Returns ``(by_va, sizes)``: for each named metadata symbol in *sections*
    with a known size, the raw bytes at its VA sliced from the binary's
    section data.  A ``.bss`` row is read from ``.data`` and a ``.idata`` row
    from ``.rdata`` when the image has no section of the declared name.  A
    span that lies in the zero-fill tail and inside the virtual size is
    returned as zeros, and its VA is added to *zero_fill* when that set is
    given.  A zero-fill span past the virtual size is skipped.  A file-backed
    span past the virtual size raises.  With *cfg*, another target's module
    is skipped: its VAs are not in this binary, and writing them back as
    UNCHECKED would erase that target's verdict.
    """
    from rebrew.binary_loader import load_binary
    from rebrew.data_layout import data_symbol_size
    from rebrew.data_metadata import module_visible_to_target
    from rebrew.utils import load_tomllib

    db = load_tomllib(metadata_path)
    info = load_binary(binary_path)
    by_va: dict[int, bytes] = {}
    sizes: dict[int, int] = {}
    for module, va, val in iter_data_symbols(db, section=None):
        declared = str(val.get("section") or "")
        if not _section_selected(declared, sections):
            continue
        if not val.get("name"):
            continue
        if not module_visible_to_target(module, cfg):
            continue
        size = data_symbol_size(
            val, arch=getattr(info, "arch", "") or getattr(cfg, "arch", "x86_32")
        )
        if size <= sizes.get(va, 0):
            continue
        sec = info.sections.get(declared)
        if sec is None:
            sec = info.sections.get(_canonical_section(declared))
        if sec is None:
            continue
        offset = va - sec.va
        extent = sec.size or sec.raw_size
        if offset < 0 or offset >= extent:
            continue
        if offset + size > extent:
            # A zero-fill span past this image is not a bad SIZE. The
            # reference virtual size can be longer than the built image.
            if offset >= sec.raw_size:
                continue
            raise ValueError(
                f"symbol {val.get('name')} at 0x{va:x} (size {size}) overruns "
                f"section {sec.name} extent 0x{sec.va:x}+0x{extent:x} — fix the "
                "SIZE in rebrew-data.toml"
            )
        if offset >= sec.raw_size:
            if zero_fill is not None:
                zero_fill.add(va)
            by_va[va] = b"\x00" * size
            sizes[va] = size
            continue
        if offset + size > sec.raw_size:
            file_n = sec.raw_size - offset
            start = sec.file_offset + offset
            by_va[va] = bytes(info.data[start : start + file_n]) + b"\x00" * (size - file_n)
            sizes[va] = size
            continue
        start = sec.file_offset + offset
        by_va[va] = bytes(info.data[start : start + size])
        sizes[va] = size
    return by_va, sizes
