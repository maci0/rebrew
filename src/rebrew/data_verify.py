"""data_verify.py - Byte-compare built data sections against the reference.

Track 1 of the gap-analysis goal: rebrew can place data (data_layout fill /
own / converge) but cannot confirm it.  This module compares per-symbol
bytes of a built binary's ``.data`` / ``.rdata`` sections against the
reference bytes, attributed per metadata symbol (right bytes at the right
address vs wrong bytes vs missing symbol).

Pure logic here (dicts in, report out) so it is unit-testable without a
link; the binary-reading thin layer lives in ``verify --data``.
"""

from pathlib import Path
from typing import Any


def verify_data_bytes(
    *,
    metadata_path: Path,
    expected: dict[int, bytes],
    actual: dict[int, bytes],
    sizes: dict[int, int],
    sections: tuple[str, ...] = (".data", ".rdata"),
) -> dict[str, Any]:
    """Compare per-symbol bytes; return ``matched`` / ``mismatched`` / ``missing``.

    *metadata_path* supplies symbol names (``rebrew-data.toml``).  *expected*
    maps VA to reference bytes, *actual* maps VA to built bytes, *sizes* maps
    VA to the compared length.  Only symbols whose metadata ``section`` is in
    *sections* are compared.  Symbols absent from *actual* are ``missing``;
    present-but-different bytes are ``mismatched`` with the first differing
    offset.  Symbols with no name in metadata are skipped (unnamed inventory
    cannot be attributed).
    """
    import tomllib

    with open(metadata_path, "rb") as fh:
        db = tomllib.load(fh)
    names: dict[int, str] = {}
    kept: set[int] = set()
    for key, val in db.items():
        if not isinstance(val, dict):
            continue
        name = val.get("name")
        if not name:
            continue
        _module, sep, addr_text = str(key).rpartition(".")
        if not sep:
            continue
        try:
            va = int(addr_text, 16)
        except ValueError:
            continue
        names[va] = str(name)
        if str(val.get("section") or "") in sections:
            kept.add(va)

    matched = 0
    mismatched: list[dict[str, Any]] = []
    missing: list[str] = []
    for va, size in sizes.items():
        if va not in kept:
            continue
        name = names.get(va)
        if name is None:
            continue
        exp = expected.get(va)
        got = actual.get(va)
        if exp is None or got is None:
            missing.append(name)
            continue
        exp_slice = exp[:size]
        got_slice = got[:size]
        if exp_slice == got_slice:
            matched += 1
            continue
        first_diff = next(
            (i for i, (a, b) in enumerate(zip(exp_slice, got_slice, strict=False)) if a != b),
            min(len(exp_slice), len(got_slice)),
        )
        mismatched.append({"name": name, "va": f"0x{va:x}", "size": size, "first_diff": first_diff})
    return {"matched": matched, "mismatched": mismatched, "missing": missing}


def section_symbol_bytes(
    *,
    metadata_path: Path,
    binary_path: Path,
    sections: tuple[str, ...] = (".data", ".rdata"),
) -> tuple[dict[int, bytes], dict[int, int]]:
    """Read per-symbol bytes for metadata symbols from *binary_path* sections.

    Returns ``(by_va, sizes)``: for each named metadata symbol in *sections*
    with a known size, the raw bytes at its VA sliced from the binary's
    section data.  Symbols outside the section bounds or without a size are
    skipped (the caller reports them as missing).
    """
    import tomllib

    from rebrew.binary_loader import load_binary

    with open(metadata_path, "rb") as fh:
        db = tomllib.load(fh)
    info = load_binary(binary_path)
    by_va: dict[int, bytes] = {}
    sizes: dict[int, int] = {}
    for key, val in db.items():
        if not isinstance(val, dict):
            continue
        if str(val.get("section") or "") not in sections:
            continue
        if not val.get("name"):
            continue
        _module, sep, addr_text = str(key).rpartition(".")
        if not sep:
            continue
        try:
            va = int(addr_text, 16)
        except ValueError:
            continue
        try:
            size = int(val.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if size <= 0:
            continue
        sec = info.sections.get(str(val.get("section")))
        if sec is None:
            continue
        offset = va - sec.va
        extent = sec.size or sec.raw_size
        if offset < 0 or offset >= extent:
            continue
        if offset + size > extent:
            raise ValueError(
                f"symbol {val.get('name')} at 0x{va:x} (size {size}) overruns "
                f"section {sec.name} extent 0x{sec.va:x}+0x{extent:x} — fix the "
                "SIZE in rebrew-data.toml"
            )
        if offset + size > sec.raw_size:
            continue  # zero-fill tail (BSS): no file bytes to read
        start = sec.file_offset + offset
        by_va[va] = bytes(info.data[start : start + size])
        sizes[va] = size
    return by_va, sizes
