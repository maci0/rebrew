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
    **Coverage is reported, because the summary is otherwise misleading.** A
    symbol is comparable only when its ``section`` is in *sections* *and*
    ``section_symbol_bytes`` could read bytes for it. A zero-fill span inside
    the image is supplied as zeros; a span past that image's virtual size never
    reaches *sizes*. ``total`` counts every named symbol, ``not_comparable``
    the difference, and ``coverage`` is the fraction compared, so a caller can
    tell "122 matched" from "122 of 329 matched".
    """
    from rebrew.utils import load_tomllib

    db = load_tomllib(metadata_path)
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
        if _section_selected(str(val.get("section") or ""), sections):
            kept.add(va)

    matched = 0
    mismatched: list[dict[str, Any]] = []
    missing: list[str] = []
    compared = 0
    for va, size in sizes.items():
        if va not in kept:
            continue
        name = names.get(va)
        if name is None:
            continue
        compared += 1
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
    total = len(names)
    return {
        "matched": matched,
        "mismatched": mismatched,
        "missing": missing,
        "total": total,
        "compared": compared,
        "not_comparable": total - compared,
        "coverage": (compared / total) if total else 0.0,
    }


# PE images from MSVC keep BSS as the .data tail and the IAT inside .rdata.
# Metadata still labels those rows .bss and .idata.
_SECTION_ALIAS = {".bss": ".data", ".idata": ".rdata"}


def _canonical_section(name: str) -> str:
    return _SECTION_ALIAS.get(name, name)


def _section_selected(declared: str, sections: tuple[str, ...]) -> bool:
    """True when *declared* or its file section is one of *sections*."""
    return declared in sections or _canonical_section(declared) in sections


def fill_uncovered_zero_fill(
    ref_bytes: dict[int, bytes],
    ref_sizes: dict[int, int],
    built_bytes: dict[int, bytes],
    built_sizes: dict[int, int],
    ref_zero_fill: set[int],
) -> None:
    """Compare reference zero-fill the built image ends before as zeros.

    The reference loader zero-fills the span. The built image stops short of
    it and holds no other bytes there, so the two sides do not differ. A span
    the built image does cover keeps the bytes that image actually holds.
    """
    for va in ref_zero_fill:
        if va in built_sizes:
            continue
        size = ref_sizes.get(va, 0)
        blob = ref_bytes.get(va)
        if size <= 0 or blob is None:
            continue
        built_bytes[va] = b"\x00" * size
        built_sizes[va] = size


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
    from rebrew.data_layout import estimate_type_size
    from rebrew.data_metadata import module_visible_to_target
    from rebrew.utils import load_tomllib

    db = load_tomllib(metadata_path)
    info = load_binary(binary_path)
    by_va: dict[int, bytes] = {}
    sizes: dict[int, int] = {}
    for key, val in db.items():
        if not isinstance(val, dict):
            continue
        declared = str(val.get("section") or "")
        if not _section_selected(declared, sections):
            continue
        if not val.get("name"):
            continue
        module, sep, addr_text = str(key).rpartition(".")
        if not sep:
            continue
        if not module_visible_to_target(module, cfg):
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
            # Fall back to the declared type.  `size` is an optional field and
            # a project may carry none at all (guild-rebrew: 310 entries, zero
            # `size`, but 303 with a `type`), in which case skipping meant
            # `rebrew verify --data` compared NOTHING and still reported
            # "0 matched, 0 mismatched, 0 missing" -- a pass that had verified
            # nothing.  The type is what the summary already sizes globals by.
            size = estimate_type_size(str(val.get("type") or "")) if val.get("type") else 0
        if size <= 0:
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
