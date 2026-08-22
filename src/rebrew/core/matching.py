"""Core matching and relocation handling logic.

Provides byte-level comparison of compiled bytes against target binary bytes
with COFF relocation masking, using NumPy vectorization for performance.
"""

from __future__ import annotations

import logging
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

import numpy as np

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig

log = logging.getLogger(__name__)

# IMAGE_REL_I386_*
_REL_DIR32 = 0x0006
_REL_REL32 = 0x0014


@dataclass(frozen=True)
class CoffRelocRecord:
    """One COFF relocation entry with its IMAGE_REL_I386_* type preserved."""

    offset: int  # byte offset inside the function's .text slice
    type: int  # IMAGE_REL_I386_* (0x06=DIR32, 0x14=REL32, ...)
    symbol: str  # target symbol name (with leading underscore on MSVC)


# Accepted coff_relocs shapes for smart_reloc_compare
RelocInput = list[int] | dict[int, str] | Sequence[CoffRelocRecord] | None


class UnresolvedSymbolError(Exception):
    """Raised when a relocation references a symbol with no VA in the catalog."""

    def __init__(self, symbol: str) -> None:
        super().__init__(symbol)
        self.symbol = symbol


def build_symbol_resolver(
    funcs_by_va: dict[int, str],
    data_by_name: dict[str, int],
) -> Callable[[str], int | None]:
    """Compose a symbol → VA resolver from the function catalog + data metadata.

    Function names win on collision: a data label can never shadow a function
    name (caught in lint elsewhere). MSVC-style leading underscores in the
    caller's query are stripped on lookup.
    """
    by_name = {name: va for va, name in funcs_by_va.items()}
    # Also index by stripped form for tolerant lookup across leading underscore
    # mangling variants (MSVC adds `_` to __cdecl names; C source-level `__ftol`
    # appears in the COFF symbol table as `___ftol`).
    by_stripped: dict[str, int] = {}
    for name, va in by_name.items():
        by_stripped[name.lstrip("_")] = va
    data_by_stripped: dict[str, int] = {}
    for name, va in data_by_name.items():
        data_by_stripped[name.lstrip("_")] = va

    def resolve(symbol: str) -> int | None:
        # Functions win over data labels; within each, the exact spelling
        # beats the leading-underscore-stripped form (same precedence as
        # _resolve_exact_then_stripped, so test/verify and round-trip agree).
        va = _resolve_exact_then_stripped(by_name, symbol)
        if va is not None:
            return va
        va = _resolve_exact_then_stripped(data_by_name, symbol)
        if va is not None:
            return va
        # Names indexed only under a stripped spelling (MSVC adds a second
        # leading underscore for some __cdecl variants) are a last resort.
        stripped = symbol.lstrip("_")
        if stripped in by_stripped:
            return by_stripped[stripped]
        if stripped in data_by_stripped:
            return data_by_stripped[stripped]
        return None

    return resolve


def build_iat_region(cfg: ProjectConfig) -> set[int]:
    """Return the set of import-related slot VAs to mask in comparisons.

    Used by :func:`smart_reloc_compare` to mask DIR32 slots whose target
    value lands in a linker-filled pointer region:

    - the PE **import-address table** (``imp.iat_address``), and
    - configured ``iat_thunks`` (jmp-stub trampolines, e.g.
      ``ff 25 <addr>`` in ``.text``) — a function calling *through* a stub
      dereferences the stub address, not the IAT slot.

    A catalog name↔VA mismatch in these regions (e.g. swapped ordinal
    import names, common for ws2_32) must not demote a RELOC match into a
    byte mismatch.  Returns ``{}`` when the binary can't be loaded or has
    no import table.
    """
    binary = getattr(cfg, "target_binary", None)
    if not binary or not Path(binary).exists():
        return set()
    region: set[int] = set()
    # Configured jmp-stub trampolines first (works even without LIEF).
    for va in getattr(cfg, "iat_thunks", None) or []:
        if isinstance(va, int) and va:
            region.add(va & 0xFFFFFFFF)
    # The raw import-address table (shared LIEF scan with the catalog
    # registry — see rebrew.binary_loader.iat_slot_vas).
    from rebrew.binary_loader import iat_slot_vas

    region |= iat_slot_vas(binary)
    return region


def build_name_to_va(cfg: ProjectConfig) -> dict[str, int]:
    """Build a symbol-name → VA map from globals AND the function catalog.

    Shared by ``rebrew test`` and ``rebrew verify`` so both paths apply the
    same DIR32 absolute-address and REL32 callee checks.  Includes exported
    symbols, annotated functions, scanned globals, and data metadata —
    without the function half, REL32 callee validation would miss every call
    target and mask wrong-function calls as valid RELOC.  Returns ``{}`` if
    the scan fails.
    """
    name_to_va: dict[str, int] = {}
    try:
        from rebrew.data import scan_globals

        scan = scan_globals(cfg.reversed_dir, cfg)
        for entry in scan.data_annotations:
            name = entry.get("name", "")
            va_int = entry.get("va")
            if isinstance(name, str) and isinstance(va_int, int) and name:
                name_to_va[name] = va_int
        for name, glob in scan.globals.items():
            if glob.va:
                name_to_va[name] = glob.va
        # scan_globals only reads the .c sources; the annotated globals in
        # rebrew-data.toml carry the authoritative name↔VA pairs.  Without
        # them, DIR32 absolute-address validation silently no-ops.
        from rebrew.data_metadata import load_data_metadata

        meta = load_data_metadata(cfg.metadata_dir)
        for (_module, va), entry in meta.items():
            name = entry.get("name", "")
            if isinstance(name, str) and name and isinstance(va, int):
                name_to_va[name] = va

        # Function catalog: exported symbols + annotated function names.  The
        # REL32 callee validation needs them — a data-only map misses every
        # call target, masking wrong-function calls as valid RELOC.
        for va, name in (getattr(cfg, "dll_exports", None) or {}).items():
            if isinstance(name, str) and name and isinstance(va, int):
                name_to_va[name] = va
        from rebrew.annotation import parse_c_file_multi
        from rebrew.cli import iter_sources

        for path in iter_sources(cfg.reversed_dir, cfg):
            for ann in parse_c_file_multi(path):
                if ann.name and ann.va:
                    name_to_va[ann.name] = ann.va
    except (ImportError, OSError, ValueError, KeyError, AttributeError) as exc:
        # A scan failure returning {} is indistinguishable from "nothing to
        # validate" — every caller (verify, test) then silently skips reloc
        # validation, masking wrong-callee calls as valid RELOC.  Surface the
        # failure at WARNING so the degraded run is visible.
        log.warning(
            "build_name_to_va: global/function scan failed — reloc validation degraded: %s", exc
        )
        return {}
    return name_to_va


def apply_coff_relocations(
    text: bytes,
    relocs: list[CoffRelocRecord],
    resolve_va: Callable[[str], int | None],
    *,
    section_va: int,
) -> bytes:
    """Apply COFF relocations to a .text byte blob.

    For each relocation, read the addend at ``relocs[i].offset``, resolve the
    target VA via ``resolve_va(symbol)``, compute the patched value per the
    relocation type, and write it back as little-endian 32-bit.

    :param text: Raw bytes for a single function as compiled.
    :param relocs: Relocation records from ``parse_obj_relocs_full``.
    :param resolve_va: Callable mapping symbol → absolute VA (None if unknown).
    :param section_va: VA of the function's start (used for REL32 PC-relative arithmetic).

    :raises UnresolvedSymbolError: Symbol not in the catalog.
    :raises NotImplementedError: Unsupported relocation type.
    """
    buf = bytearray(text)
    for r in relocs:
        sym = r.symbol.lstrip("_")
        target_va = resolve_va(r.symbol) or resolve_va(sym)
        if target_va is None:
            raise UnresolvedSymbolError(r.symbol)

        addend = struct.unpack_from("<I", buf, r.offset)[0]
        if r.type == _REL_DIR32:
            value = (target_va + addend) & 0xFFFFFFFF
        elif r.type == _REL_REL32:
            pc = section_va + r.offset + 4
            value = (target_va + addend - pc) & 0xFFFFFFFF
        else:
            raise NotImplementedError(f"IMAGE_REL_I386_* type 0x{r.type:04x} not supported")

        struct.pack_into("<I", buf, r.offset, value)

    return bytes(buf)


def _resolve_exact_then_stripped(name_to_va: dict[str, int], sym_name: str) -> int | None:
    """Look up *sym_name* in a name→VA map, exact spelling first.

    Single documented precedence shared by every tolerant lookup: the exact
    spelling wins over its leading-underscore-stripped form (``_foo`` before
    ``foo``). MSVC mangles __cdecl names with a leading ``_`` in the COFF
    symbol table, so the exact spelling is the authoritative one; the stripped
    form is only a fallback for source-level references. Keeping one helper
    means ``rebrew test`` and ``rebrew round-trip`` agree on the same VA when
    both spellings exist in the catalog.
    """
    if sym_name in name_to_va:
        return name_to_va[sym_name]
    stripped = sym_name.lstrip("_")
    if stripped != sym_name and stripped in name_to_va:
        return name_to_va[stripped]
    return None


def _lookup_symbol_va(name_to_va: dict[str, int], sym_name: str) -> int | None:
    """Resolve *sym_name* in *name_to_va*, tolerating a leading underscore."""
    return _resolve_exact_then_stripped(name_to_va, sym_name)


def _validate_dir32(
    obj_bytes: bytes,
    target_bytes: bytes,
    offset: int,
    symbol: str,
    name_to_va: dict[str, int],
    catalog_va_set: set[int],
    iat_region: set[int] | None = None,
) -> bool:
    """Return True if the DIR32 slot is valid (or uncatalogued)."""
    target_va = _lookup_symbol_va(name_to_va, symbol)
    try:
        addend = struct.unpack_from("<I", obj_bytes, offset)[0]
        actual = struct.unpack_from("<I", target_bytes, offset)[0]
    except struct.error:
        return False
    # A value inside the import-address table is a linker-filled pointer,
    # not a data address — catalog name↔VA mismatch there (e.g. swapped
    # ordinal import names) must not demote a RELOC match.  Mask by position.
    if iat_region and actual in iat_region:
        return True
    if target_va is None:
        return True  # uncatalogued — mask only
    expected = (target_va + addend) & 0xFFFFFFFF
    if actual == expected:
        return True
    # Wrong absolute symbol with the same addend?  The membership test is
    # algebraic: actual == (other + addend) & mask  ⟺  other == (actual -
    # addend) & mask.  O(1) instead of scanning the catalog per failing
    # DIR32 (perf-review: ~500x on the failing-reloc path).
    other = (actual - addend) & 0xFFFFFFFF
    return other not in catalog_va_set or other == target_va


def _validate_rel32(
    obj_bytes: bytes,
    target_bytes: bytes,
    offset: int,
    symbol: str,
    name_to_va: dict[str, int],
    section_va: int,
) -> bool:
    """Return True if the REL32 slot matches ``symbol_va + addend - pc``."""
    target_va = _lookup_symbol_va(name_to_va, symbol)
    if target_va is None:
        return True  # uncatalogued — mask only
    try:
        addend = struct.unpack_from("<I", obj_bytes, offset)[0]
        actual = struct.unpack_from("<I", target_bytes, offset)[0]
    except struct.error:
        return False
    pc = section_va + offset + 4
    expected = (target_va + addend - pc) & 0xFFFFFFFF
    return bool(actual == expected)


def smart_reloc_compare(
    obj_bytes: bytes,
    target_bytes: bytes,
    coff_relocs: RelocInput = None,
    name_to_va: dict[str, int] | None = None,
    *,
    section_va: int | None = None,
    iat_region: set[int] | None = None,
) -> tuple[bool, int, int, list[int], list[int]]:
    """Compare bytes with relocation masking and target validation.

    Operates in four modes depending on *coff_relocs*:

    - **list[CoffRelocRecord]**: Typed relocs (preferred). DIR32 slots validated
      as ``actual == symbol_va + addend``; REL32 slots validated as
      ``actual == symbol_va + addend - pc`` when *section_va* is provided,
      otherwise masked without absolute checks.
    - **list[int]**: Plain offsets — 4 bytes at each offset are masked as valid
      relocations without symbol resolution.
    - **dict[int, str]**: Offset → symbol name mapping — when *name_to_va* is
      also provided, validates DIR32-style ``actual == symbol_va + addend``
      heuristically (wrong absolute symbols rejected; REL32-like values masked).
    - **None**: Falls back to zero-span detection (scanning for ``00 00 00 00``
      runs in *obj_bytes* aligned with non-zero *target_bytes*).

    *iat_region* is a set of VAs that are import-address-table slots (the
    ``.idata`` section).  A DIR32 whose target value lands inside it is masked
    without symbol-name validation: IAT slots are linker-filled pointers, so a
    catalog name↔VA mismatch there (e.g. swapped ordinal import names) must not
    convert a RELOC match into a byte mismatch.

    Args:
        obj_bytes: The compiled output bytes to verify.
        target_bytes: The original target bytes to compare against.
        coff_relocs: Offset list, dict mapping offset → symbol, or typed records.
        name_to_va: Global VA lookup table from the active Data Catalog.
        section_va: Function start VA — enables precise REL32 checks for typed
            reloc records.  Optional.
        iat_region: Set of import-address-slot VAs (``.idata``) — optional.

    Returns:
        (matched, match_count, total_bytes, valid_relocs, invalid_relocs)

    """
    min_len = min(len(obj_bytes), len(target_bytes))
    max_len = max(len(obj_bytes), len(target_bytes))

    # Trivial case: both empty → vacuous match
    if max_len == 0:
        return True, 0, 0, [], []

    valid_relocs: list[int] = []
    invalid_relocs: list[int] = []

    # Fast set lookup for absolute-address validation (built once per compare).
    catalog_va_set: set[int] = set(name_to_va.values()) if name_to_va else set()

    if coff_relocs is not None:
        # Prefer typed CoffRelocRecord sequence when present.
        if (
            isinstance(coff_relocs, (list, tuple))
            and coff_relocs
            and isinstance(coff_relocs[0], CoffRelocRecord)
        ):
            typed_relocs = cast(Sequence[CoffRelocRecord], coff_relocs)
            for rec in typed_relocs:
                r = rec.offset
                if r + 4 > min_len:
                    continue
                valid = True
                if name_to_va:
                    if rec.type == _REL_DIR32:
                        valid = _validate_dir32(
                            obj_bytes,
                            target_bytes,
                            r,
                            rec.symbol,
                            name_to_va,
                            catalog_va_set,
                            iat_region,
                        )
                    elif rec.type == _REL_REL32 and section_va is not None:
                        valid = _validate_rel32(
                            obj_bytes, target_bytes, r, rec.symbol, name_to_va, section_va
                        )
                    # else: other types / REL32 without section_va → mask only
                if valid:
                    valid_relocs.append(r)
                else:
                    invalid_relocs.append(r)
        elif isinstance(coff_relocs, dict):
            # Dict branch: offset -> symbol_name with heuristic DIR32 validation.
            for r, raw_sym in coff_relocs.items():
                if r + 4 > min_len:
                    continue
                valid = True
                if name_to_va:
                    valid = _validate_dir32(
                        obj_bytes,
                        target_bytes,
                        r,
                        str(raw_sym),
                        name_to_va,
                        catalog_va_set,
                        iat_region,
                    )
                if valid:
                    valid_relocs.append(r)
                else:
                    invalid_relocs.append(r)
        else:
            # List[int] branch: plain offset list (no symbol resolution)
            valid_relocs.extend(r for r in coff_relocs if isinstance(r, int) and r + 4 <= min_len)
    else:
        i = 0
        while i <= min_len - 4:
            if (
                obj_bytes[i : i + 4] == b"\x00\x00\x00\x00"
                and obj_bytes[i : i + 4] != target_bytes[i : i + 4]
            ):
                valid_relocs.append(i)
                i += 4
            else:
                i += 1

    # Vectorized comparison: build a boolean relocation mask and use NumPy
    # for the byte-level match instead of a Python-level per-byte loop.
    reloc_mask = np.zeros(min_len, dtype=bool)
    for r in valid_relocs:
        end = min(r + 4, min_len)
        if r < min_len:
            reloc_mask[r:end] = True

    obj_arr = np.frombuffer(obj_bytes[:min_len], dtype=np.uint8)
    target_arr = np.frombuffer(target_bytes[:min_len], dtype=np.uint8)
    match_mask = reloc_mask | (obj_arr == target_arr)
    match_count = int(np.count_nonzero(match_mask))
    has_mismatch = not np.all(match_mask)

    masked_match = not has_mismatch and len(obj_bytes) == len(target_bytes)
    return masked_match, match_count, max_len, valid_relocs, invalid_relocs
