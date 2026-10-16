"""Core matching and relocation handling logic.

Provides byte-level comparison of compiled bytes against target binary bytes
with COFF relocation masking, using NumPy vectorization for performance.
"""

from __future__ import annotations

import hashlib
import logging
import struct
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from rebrew.errors import RebrewError
from rebrew.sources import iter_sources
from rebrew.utils import binary_fingerprint, preset_module_key

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig

log = logging.getLogger(__name__)

# IMAGE_REL_I386_* (the historical default reloc table)
_REL_ABSOLUTE = 0x0000
_REL_DIR32 = 0x0006
_REL_REL32 = 0x0014

# A conflicting identity is present but cannot resolve to a native address.
AMBIGUOUS_VA = -1

# Per-format/arch relocation semantics (multi-arch P0): a reloc type maps to
# how its patched value is computed.  ``abs32`` = target VA + addend;
# ``rel32`` = target VA + addend - pc; ``none`` = a no-op entry (ABSOLUTE) that
# carries no patch and no symbol.  Types absent from a table are unsupported by
# the masking path (raise NotImplementedError).
_RELOC_TABLES: dict[str, dict[int, str]] = {
    "coff-i386": {
        _REL_ABSOLUTE: "none",
        _REL_DIR32: "abs32",
        _REL_REL32: "rel32",
    },
    "elf-mips": {
        2: "abs32",  # R_MIPS_32
        3: "rel32",  # R_MIPS_REL32
        # R_MIPS_26 (jump), R_MIPS_HI16/LO16 (pair) are not maskable with the
        # simple addend model — Phase 1 (MIPS object parsing) extends this.
        # Real IDO 7.1 objects additionally emit GOT16/CALL16 (O32 GOT
        # calling convention) for external calls; the *compare* path masks
        # any type absent from a table (test_multi_arch_p0 pins this), so
        # IDO-built MIPS verification is safe — only the round-trip patch
        # path (apply_coff_relocations) raises for these.
    },
    "elf-ppc": {
        1: "abs32",  # R_PPC_ADDR32
        # R_PPC_REL24 (call) needs 24-bit extraction — Phase 1.
    },
}

# Byte order of the addend slot each table's targets are stored in.  COFF/i386
# is little-endian; the MIPS and PowerPC ELF objects these tables decode are
# big-endian, and the IDO/N64 targets that produce them default to big-endian in
# binary_loader.endian_mode_bits.  Selecting a table picks the semantics, so it
# picks the byte order too — reading an R_MIPS_32 addend as little-endian turns
# the patched value byte-reversed and silently mislinks.
_RELOC_BYTE_ORDER: dict[str, str] = {
    "coff-i386": "little",
    "elf-mips": "big",
    "elf-ppc": "big",
}


def reloc_byte_order(reloc_table: str) -> str:
    """``struct`` byte-order prefix for *reloc_table*'s on-disk addend slots."""
    return "<" if _RELOC_BYTE_ORDER.get(reloc_table, "little") == "little" else ">"


def _reloc_fmt(reloc_table: str) -> str:
    """Format string for a 4-byte relocation addend slot in *reloc_table*."""
    return f"{reloc_byte_order(reloc_table)}I"


@dataclass(frozen=True)
class CoffRelocRecord:
    """One relocation entry with its format's type preserved."""

    offset: int  # byte offset inside the function's .text slice
    type: int  # e.g. IMAGE_REL_I386_* (0x06=DIR32, 0x14=REL32), or ELF-MIPS/PPC reloc type
    symbol: str  # target symbol name (with leading underscore on MSVC)


_RELOC_ALIGNMENT = 4

# Accepted coff_relocs shapes for smart_reloc_compare
RelocInput = list[int] | dict[int, str] | Sequence[CoffRelocRecord] | None


# Sentinel returned by build_name_to_va when the global/function scan fails.
# Fail-closed marker: callers (test/verify) must not mask typed/dict relocs
# when the VA map is unavailable — an unvalidated mask would report RELOC on
# wrong-callee calls.  A degraded map with SOME entries still validates what
# it knows; only a total scan failure raises.
class CatalogScanError(RebrewError, Exception):
    """Raised when the global/function scan fails to build the VA map."""


class UnresolvedSymbolError(RebrewError, Exception):
    """Raised when a relocation references a symbol with no VA in the catalog.

    ``symbol`` names the reference that could not be resolved, so a consumer
    fixing a catalog does not have to parse it back out of the message.
    """

    _STRUCTURED_FIELDS = (*RebrewError._STRUCTURED_FIELDS, "symbol")

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
    # appears in the COFF symbol table as `___ftol`).  Skip empty keys that
    # would collide with bare-underscore symbols.
    by_stripped: dict[str, int] = {}
    for name, va in by_name.items():
        stripped = name.lstrip("_")
        if stripped:
            by_stripped[stripped] = va
    data_by_stripped: dict[str, int] = {}
    for name, va in data_by_name.items():
        stripped = name.lstrip("_")
        if stripped:
            data_by_stripped[stripped] = va

    def resolve(symbol: str) -> int | None:
        # Functions win over data labels; within each, the exact spelling
        # beats the leading-underscore-stripped form (same precedence as
        # _resolve_exact_then_stripped, so test/verify and round-trip agree).
        va = _resolve_exact_then_stripped(by_name, symbol)
        if va is not None:
            return va if va != AMBIGUOUS_VA else None
        va = _resolve_exact_then_stripped(data_by_name, symbol)
        if va is not None:
            return va if va != AMBIGUOUS_VA else None
        # Names indexed only under a stripped spelling (MSVC adds a second
        # leading underscore for some __cdecl variants) are a last resort.
        stripped = symbol.lstrip("_")
        if stripped in by_stripped:
            return by_stripped[stripped] if by_stripped[stripped] != AMBIGUOUS_VA else None
        if stripped in data_by_stripped:
            return (
                data_by_stripped[stripped] if data_by_stripped[stripped] != AMBIGUOUS_VA else None
            )
        return None

    return resolve


# Mask set per (binary identity, configured thunks).  The batch paths ask
# for it once per function and the answer is a whole-run constant; keying on
# the binary's stat fingerprint keeps a rebuilt binary from reading a stale
# entry.  Bounded, and eviction is a multi-step next(iter)+pop on a shared
# dict, so lookup and replacement share the lock.
_iat_region_cache: dict[tuple[Any, ...], frozenset[int]] = {}
_IAT_REGION_CACHE_MAX = 16
_iat_region_lock = threading.Lock()


def build_iat_region(cfg: ProjectConfig) -> frozenset[int]:
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

    The result depends only on the target binary's identity and the
    configured thunks, both fixed for a run; the batch paths call this once
    per function, so the union is memoized and the stored ``frozenset`` is
    handed back unshared.  Invalidation keys on the binary's stat
    fingerprint, matching :func:`rebrew.formats.binary_loader.iat_slot_vas`, so an
    ``iat_thunks`` edit still takes effect immediately.
    """
    binary = getattr(cfg, "target_binary", None)
    if not binary:
        return frozenset()
    thunks = tuple(
        (va & 0xFFFFFFFF)
        for va in (getattr(cfg, "iat_thunks", None) or [])
        if isinstance(va, int) and va
    )
    key = (str(binary), thunks, binary_fingerprint(binary))
    with _iat_region_lock:
        cached = _iat_region_cache.get(key)
        if cached is not None:
            _iat_region_cache[key] = _iat_region_cache.pop(key)
            return cached
    region: set[int] = set()
    if Path(binary).exists():
        # Configured jmp-stub trampolines first (works even without LIEF).
        region.update(thunks)
        # The raw import-address table (shared LIEF scan with the catalog
        # registry — see rebrew.formats.binary_loader.iat_slot_vas).
        from rebrew.formats.binary_loader import iat_slot_vas

        region |= iat_slot_vas(binary)
    frozen = frozenset(region)
    with _iat_region_lock:
        if len(_iat_region_cache) >= _IAT_REGION_CACHE_MAX:
            _iat_region_cache.pop(next(iter(_iat_region_cache)), None)
        _iat_region_cache[key] = frozen
    return frozen


def build_name_to_va(
    cfg: ProjectConfig,
    *,
    annotations: Sequence[Any] | None = None,
) -> dict[str, int]:
    """Build a symbol-name → VA map from globals AND the function catalog.

    Shared by ``rebrew test`` and ``rebrew verify`` so both paths apply the
    same DIR32 absolute-address and REL32 callee checks.  Includes exported
    symbols, annotated functions, scanned globals, and data metadata —
    without the function half, REL32 callee validation would miss every call
    target and mask wrong-function calls as valid RELOC.

    When *annotations* is provided (e.g. the list already returned by
    ``scan_reversed_dir``), the function-name half is filled from that list
    instead of re-walking and re-parsing every source — verify's prepare
    pass already paid that cost once.

    :raises CatalogScanError: the scan failed — callers must fail closed
        (no reloc masking without validation), never mask on an empty map.
    """
    name_to_va: dict[str, int] = {}
    try:
        from rebrew.config import target_module
        from rebrew.data_scan import scan_globals

        # Every source of pairs below is scoped to the ACTIVE target's module.
        # A shared file carries one `// DATA:`/`// GLOBAL:` marker per target
        # and the same symbol sits at a different VA in each binary; unscoped,
        # the last entry wins and the other target's compare validates its
        # absolute references against the wrong binary (guild-rebrew round
        # 1292: GOLDTL's log tables resolved to the SERVER VAs 0x10027078...).
        active_module = target_module(cfg)

        scan = scan_globals(cfg.reversed_dir, cfg, record_roles=False)
        for name, glob in scan.globals.items():
            if glob.va:
                name_to_va[name] = glob.va
        # scan_globals only reads the .c sources; the annotated globals in
        # rebrew-data.toml carry the authoritative name↔VA pairs.  Without
        # them, DIR32 absolute-address validation silently no-ops.
        from rebrew.metadata.data import load_data_metadata

        meta = load_data_metadata(cfg.metadata_dir)
        for (_module, va), entry in meta.items():
            if (
                active_module
                and _module
                and preset_module_key(_module) != preset_module_key(active_module)
            ):
                continue
            for field in ("name", "link_symbol"):
                name = entry.get(field, "")
                if isinstance(name, str) and name and isinstance(va, int):
                    name_to_va[name] = va

        # Function catalog: exported symbols + annotated function names.  The
        # REL32 callee validation needs them — a data-only map misses every
        # call target, masking wrong-function calls as valid RELOC.
        name_to_va.update(
            {
                name: va
                for va, name in (getattr(cfg, "dll_exports", None) or {}).items()
                if isinstance(name, str) and name and isinstance(va, int)
            }
        )
        from rebrew.function_providers import select_source_bindings

        if annotations is None:
            from rebrew.metadata.bindings import read_source_bindings

            annotations = [
                ann
                for path in iter_sources(cfg.reversed_dir, cfg)
                for ann in read_source_bindings(
                    path,
                    target_name=active_module,
                    base_dir=cfg.reversed_dir,
                    metadata_dir=cfg.metadata_dir,
                    project_root=getattr(cfg, "root", None),
                )
            ]
        selected, _duplicates = select_source_bindings(cfg, annotations)
        ambiguous_names: set[str] = set()
        for ann in selected:
            # Library identifications can have swapped attribution names;
            # provider selection does not establish a trusted native callee.
            if getattr(ann, "kind", "") == "LIBRARY":
                continue
            ann_name = getattr(ann, "name", None)
            ann_va = getattr(ann, "va", None)
            if isinstance(ann_name, str) and ann_name and isinstance(ann_va, int) and ann_va:
                for name in {ann_name, getattr(ann, "symbol", "")} - {""}:
                    if name in name_to_va and name_to_va[name] != ann_va:
                        ambiguous_names.add(name)
                    else:
                        name_to_va[name] = ann_va
        from rebrew.rename_ops import c_name_from_symbol

        ambiguous_keys = {
            spelling
            for name in ambiguous_names
            for spelling in {
                name,
                c_name_from_symbol(name),
                name.lstrip("_"),
                c_name_from_symbol(name).lstrip("_"),
            }
            if spelling
        }
        for name in set(name_to_va) | ambiguous_keys:
            if {
                name,
                c_name_from_symbol(name),
                name.lstrip("_"),
                c_name_from_symbol(name).lstrip("_"),
            } & ambiguous_keys:
                name_to_va[name] = AMBIGUOUS_VA
        # Only explicit, binary-bound full-object reviews establish library names.
        from rebrew.metadata.functions import FUNCTION_IDENTITY_FIELDS, load_metadata
        from rebrew.metadata.native_identity import validate_native_identity

        pending = []
        native_binary_hash: str | None = None
        for (owner, va), entry in load_metadata(cfg.metadata_dir).items():
            if (
                preset_module_key(owner) != preset_module_key(active_module)
                or entry.get("kind") != "LIBRARY"
                or not entry.get("native_identity")
            ):
                continue
            receipt = validate_native_identity(entry["native_identity"])
            if native_binary_hash is None:
                native_binary_hash = hashlib.sha256(cfg.target_binary.read_bytes()).hexdigest()
            claim = {k: entry[k] for k in FUNCTION_IDENTITY_FIELDS if k in entry}
            if (
                receipt["binary_hash"] == native_binary_hash
                and receipt["size"] == entry.get("size")
                and receipt["claim"] == claim
            ):
                pending.append((va, receipt))
        # Reject conflicting reviewed names, including ambiguous aliases.
        claimed: dict[str, set[int]] = {}
        for va, receipt in pending:
            claimed.setdefault(receipt["symbol"], set()).add(va)
        while pending:
            remaining = []
            for va, receipt in pending:
                name = receipt["symbol"]
                if len(claimed[name]) != 1 or (name in name_to_va and name_to_va[name] != va):
                    continue
                if all(name_to_va.get(k) == value for k, value in receipt["bindings"].items()):
                    name_to_va[name] = va
                else:
                    remaining.append((va, receipt))
            if len(remaining) == len(pending):
                break
            pending = remaining
    except (ImportError, OSError, ValueError, KeyError, AttributeError) as exc:
        # Fail closed: a scan failure is indistinguishable from "nothing to
        # validate" to every caller — verify/test would then silently skip
        # reloc validation, masking wrong-callee calls as valid RELOC.  Raise
        # so the run errors instead of shipping a false RELOC.
        raise CatalogScanError(
            f"global/function scan failed, reloc validation unavailable: {exc}"
        ) from exc
    return name_to_va


def apply_coff_relocations(
    text: bytes,
    relocs: list[CoffRelocRecord],
    resolve_va: Callable[[str], int | None],
    *,
    section_va: int,
    reloc_table: str = "coff-i386",
) -> bytes:
    """Apply COFF relocations to a .text byte blob.

    For each relocation, read the addend at ``relocs[i].offset``, resolve the
    target VA via ``resolve_va(symbol)``, compute the patched value per the
    relocation type, and write it back in *reloc_table*'s byte order.

    :param text: Raw bytes for a single function as compiled.
    :param relocs: Relocation records from ``parse_obj_relocs_full``.
    :param resolve_va: Callable mapping symbol → absolute VA (None if unknown).
    :param section_va: VA of the function's start (used for REL32 PC-relative arithmetic).
    :param reloc_table: Which relocation-type table decodes the records; it
        also fixes the byte order of the addend slots (see
        :func:`reloc_byte_order`).

    :raises UnresolvedSymbolError: Symbol not in the catalog.
    :raises NotImplementedError: Unsupported relocation type.
    """
    from rebrew.rename_ops import c_name_from_symbol

    buf = bytearray(text)
    table = _RELOC_TABLES.get(reloc_table, _RELOC_TABLES["coff-i386"])
    fmt = _reloc_fmt(reloc_table)
    for r in relocs:
        kind = table.get(r.type)
        if kind == "none":
            continue  # IMAGE_REL_I386_ABSOLUTE: no patch, no symbol to resolve
        if kind is None:
            raise NotImplementedError(f"reloc type 0x{r.type:04x} not supported ({reloc_table})")

        # Exact spelling first. ``hook@@12`` is ``hook``; one leading
        # ``_`` left that relocation unresolved. ``__foo`` is ``_foo``.
        c_name = c_name_from_symbol(r.symbol)
        target_va = resolve_va(r.symbol) or resolve_va(c_name)
        if target_va is None:
            raise UnresolvedSymbolError(r.symbol)
        if r.offset < 0 or r.offset + 4 > len(buf):
            # The record offset is bounded by the compiled bytes, not by the
            # function body handed in (which may be rstrip()ed shorter).
            continue
        addend = struct.unpack_from(fmt, buf, r.offset)[0]
        if kind == "abs32":
            value = (target_va + addend) & 0xFFFFFFFF
        elif kind == "rel32":
            pc = section_va + r.offset + 4
            value = (target_va + addend - pc) & 0xFFFFFFFF
        else:
            raise NotImplementedError(f"reloc kind {kind!r} not supported")

        struct.pack_into(fmt, buf, r.offset, value)

    return bytes(buf)


def _slot_in_prefix(offset: int, min_len: int) -> bool:
    """True when *offset* addresses a whole 4-byte slot inside the compared prefix.

    ``struct.unpack_from`` reads backwards from the end of the buffer for a
    negative offset, so an out-of-range record would otherwise be validated
    against the wrong window and reported as a reloc at a position the caller
    never has.  ``apply_coff_relocations`` guards the same way.
    """
    return offset >= 0 and offset + 4 <= min_len


def _resolve_exact_then_stripped(name_to_va: dict[str, int], sym_name: str) -> int | None:
    """Look up *sym_name* in a name→VA map, exact spelling first.

    Single documented precedence shared by every tolerant lookup: the exact
    spelling wins, then the C name (``hook@@12`` is ``hook``, ``__foo`` is
    ``_foo``, ``___ftol`` is ``__ftol``), then a full leading-underscore
    strip. The strip stays so a catalog key that is already fully stripped
    still matches. Keeping one helper means ``rebrew test`` and
    ``rebrew build round-trip`` agree on the same VA when both spellings
    exist in the catalog.
    """
    if sym_name in name_to_va:
        return name_to_va[sym_name]
    from rebrew.rename_ops import c_name_from_symbol

    c_name = c_name_from_symbol(sym_name)
    if c_name and c_name != sym_name and c_name in name_to_va:
        return name_to_va[c_name]
    # Guard against empty/bare-underscore queries — lstrip("_") on "__" yields ""
    # which may collide with a data label named "" or cause confusion in the caller.
    stripped = sym_name.lstrip("_")
    if stripped and stripped != sym_name and stripped in name_to_va:
        return name_to_va[stripped]
    return None


def _validate_dir32(
    obj_bytes: bytes,
    target_bytes: bytes,
    offset: int,
    symbol: str,
    name_to_va: dict[str, int],
    catalog_va_set: set[int],
    iat_region: frozenset[int] | None = None,
    reloc_table: str = "coff-i386",
    *,
    strict: bool = False,
    check_known_bindings: bool = False,
) -> bool:
    """Return True if the DIR32 slot is valid (or uncatalogued)."""
    target_va = _resolve_exact_then_stripped(name_to_va, symbol)
    fmt = _reloc_fmt(reloc_table)
    try:
        addend = struct.unpack_from(fmt, obj_bytes, offset)[0]
        actual = struct.unpack_from(fmt, target_bytes, offset)[0]
    except struct.error:
        return False
    # A value inside the import-address table is a linker-filled pointer,
    # not a data address — catalog name↔VA mismatch there (e.g. swapped
    # ordinal import names) must not demote a RELOC match.  Mask by position.
    if iat_region and actual in iat_region:
        return True
    if target_va == AMBIGUOUS_VA:
        return False
    if target_va is None:
        return not strict  # uncatalogued — agreement only, never a bound proof
    expected = (target_va + addend) & 0xFFFFFFFF
    if actual == expected:
        return True
    if strict or check_known_bindings:
        return False
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
    reloc_table: str = "coff-i386",
    *,
    strict: bool = False,
) -> bool:
    """Return True if the REL32 slot matches ``symbol_va + addend - pc``."""
    target_va = _resolve_exact_then_stripped(name_to_va, symbol)
    if target_va == AMBIGUOUS_VA:
        return False
    if target_va is None:
        return not strict  # uncatalogued — agreement only, never a bound proof
    fmt = _reloc_fmt(reloc_table)
    try:
        addend = struct.unpack_from(fmt, obj_bytes, offset)[0]
        actual = struct.unpack_from(fmt, target_bytes, offset)[0]
    except struct.error:
        return False
    pc = section_va + offset + 4
    expected = (target_va + addend - pc) & 0xFFFFFFFF
    return bool(actual == expected)


_CATALOG_VA_SET_LOCK = threading.Lock()
_catalog_va_set_memo: tuple[dict[str, int], set[int]] | None = None


def _catalog_va_set(name_to_va: dict[str, int] | None) -> set[int]:
    """``set(name_to_va.values())``, memoised against the last map seen.

    Identity, not equality, so a fresh ``build_name_to_va`` result builds its
    own set instead of comparing a full symbol map on every call.  A single
    slot bounds the memory to one map and one set.

    Identity does NOT detect an in-place edit: a caller that mutates the dict
    after the first call still gets the set taken before the edit.  Every
    caller in the tree hands over a map ``build_name_to_va`` just built, so
    that does not arise; a caller that reuses and mutates one must pass a copy
    (or clear ``_catalog_va_set_memo``).
    """
    global _catalog_va_set_memo
    if not name_to_va:
        return set()
    with _CATALOG_VA_SET_LOCK:
        memo = _catalog_va_set_memo
        if memo is not None and memo[0] is name_to_va:
            return memo[1]
    result = set(name_to_va.values())
    with _CATALOG_VA_SET_LOCK:
        _catalog_va_set_memo = (name_to_va, result)
    return result


def relocation_binding_evidence(
    obj_bytes: bytes,
    target_bytes: bytes,
    coff_relocs: RelocInput,
    name_to_va: dict[str, int] | None,
    *,
    section_va: int | None = None,
    iat_region: frozenset[int] | None = None,
    reloc_table: str = "coff-i386",
) -> list[dict[str, Any]]:
    """Explain bound, conflicting and unresolved operands without promoting masks to proof."""
    table = _RELOC_TABLES.get(reloc_table, _RELOC_TABLES["coff-i386"])
    if isinstance(coff_relocs, dict):
        records = [(offset, "abs32", symbol, False) for offset, symbol in coff_relocs.items()]
    else:
        records = [
            (rec.offset, table.get(rec.type, "unsupported"), rec.symbol, True)
            if isinstance(rec, CoffRelocRecord)
            else (rec, "mask", "", False)
            for rec in coff_relocs or []
        ]
    evidence: list[dict[str, Any]] = []
    for offset, kind, symbol, typed in records:
        row: dict[str, Any] = {"offset": offset, "symbol": symbol, "kind": kind, "typed": typed}
        if kind == "none":
            row["status"] = "IGNORED"
        elif not _slot_in_prefix(offset, len(obj_bytes)):
            row["status"] = "OUT_OF_EXTENT"
        elif kind not in {"abs32", "rel32"}:
            row["status"] = "UNSUPPORTED"
        else:
            addend = struct.unpack_from(_reloc_fmt(reloc_table), obj_bytes, offset)[0]
            bound = _resolve_exact_then_stripped(name_to_va or {}, symbol)
            row.update(
                {"addend": addend, "bound_va": bound, "byte_order": reloc_byte_order(reloc_table)}
            )
            if (
                bound is not None
                and bound != AMBIGUOUS_VA
                and (kind == "abs32" or section_va is not None)
            ):
                expected = (bound + addend) & 0xFFFFFFFF
                if kind == "rel32" and section_va is not None:
                    expected = (expected - section_va - offset - 4) & 0xFFFFFFFF
                row["expected_value"] = expected
            if not _slot_in_prefix(offset, len(target_bytes)):
                row["status"] = "OUT_OF_EXTENT"
                evidence.append(row)
                continue
            actual = struct.unpack_from(_reloc_fmt(reloc_table), target_bytes, offset)[0]
            row["native_value"] = actual
            if kind == "abs32" and iat_region and actual in iat_region:
                row["status"] = "IAT_POLICY"
            elif bound is None or (kind == "rel32" and section_va is None):
                row["status"] = "UNRESOLVED"
            elif bound == AMBIGUOUS_VA:
                row["status"] = "AMBIGUOUS"
                row.pop("expected_value", None)
            else:
                row["status"] = "VALIDATED" if actual == row["expected_value"] else "CONFLICT"
        evidence.append(row)
    return evidence


def refresh_binding_evidence(
    evidence: list[dict[str, Any]],
    target_bytes: bytes,
    *,
    iat_region: frozenset[int] | None = None,
) -> list[dict[str, Any]]:
    """Re-evaluate recorded operand expectations against a complete native window."""
    refreshed = []
    for original in evidence:
        row = dict(original)
        if "byte_order" in row:
            offset = row["offset"]
            row.pop("native_value", None)
            if not _slot_in_prefix(offset, len(target_bytes)):
                row["status"] = "OUT_OF_EXTENT"
            else:
                actual = struct.unpack_from(f"{row['byte_order']}I", target_bytes, offset)[0]
                row["native_value"] = actual
                if row["kind"] == "abs32" and iat_region and actual in iat_region:
                    row["status"] = "IAT_POLICY"
                elif "expected_value" not in row:
                    row["status"] = "UNRESOLVED"
                else:
                    row["status"] = "VALIDATED" if actual == row["expected_value"] else "CONFLICT"
        refreshed.append(row)
    return refreshed


def known_bindings_match(
    evidence: list[dict[str, Any]],
    target_bytes: bytes,
    *,
    iat_region: frozenset[int] | None = None,
) -> bool:
    """Recheck mapped operands in an extended comparison before writing a new SIZE."""
    return all(
        row["status"] in {"VALIDATED", "IAT_POLICY"}
        for row in refresh_binding_evidence(evidence, target_bytes, iat_region=iat_region)
        if "expected_value" in row
    )


def binding_summary(evidence: list[dict[str, Any]]) -> str:
    """A short explanation of conflicts and unresolved operand masks."""
    conflicts = [row for row in evidence if row["status"] == "CONFLICT"]
    unresolved = sum(row["status"] == "UNRESOLVED" for row in evidence)
    parts = []
    if conflicts:
        names = ", ".join(f"{row['symbol']} at +0x{row['offset']:x}" for row in conflicts[:8])
        parts.append(f"{len(conflicts)} known binding conflict(s): {names}")
    if unresolved:
        parts.append(f"{unresolved} unresolved operand(s), masked without proof")
    return "; ".join(parts)


def smart_reloc_compare(
    obj_bytes: bytes,
    target_bytes: bytes,
    coff_relocs: RelocInput = None,
    name_to_va: dict[str, int] | None = None,
    *,
    section_va: int | None = None,
    iat_region: frozenset[int] | None = None,
    reloc_table: str = "coff-i386",
    strict: bool = False,
    check_known_bindings: bool = False,
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

    Fail-closed: a caller that could not build its VA map must surface a
    hard error (``CatalogScanError`` from ``build_name_to_va``) instead of
    comparing — an empty/unusable map marks every typed/dict reloc invalid
    (unresolved → mismatch), never silently masks.

    Args:
        obj_bytes: The compiled output bytes to verify.
        target_bytes: The original target bytes to compare against.
        coff_relocs: Offset list, dict mapping offset → symbol, or typed records.
        name_to_va: Global VA lookup table from the active Data Catalog.
        section_va: Function start VA — enables precise REL32 checks for typed
            reloc records.  Optional.
        iat_region: Set of import-address-slot VAs (``.idata``) — optional.
        reloc_table: Which relocation-type table decodes the records'
            ``type`` field: ``"coff-i386"`` (default), ``"elf-mips"``, or
            ``"elf-ppc"``.  Only consulted for typed records; an unknown name
            falls back to ``coff-i386``.  A type absent from the table is
            masked as a difference (compare path) — the round-trip
            :func:`apply_coff_relocations` instead raises for it.
        strict: Require supplied relocation claims to resolve exactly. Known
            DIR32 targets must equal symbol VA plus addend, even when the
            competing native address is uncatalogued. Unbound symbols,
            unsupported types, REL32 without section_va, and plain offset
            masks fail the proof and appear in invalid_relocs. Implicit zero
            masking is disabled. Explicit IAT-region policy still applies;
            bind compiler-local table labels to their actual VAs. The default
            retains tolerant source agreement.
        check_known_bindings: Reject conflicting mapped DIR32 operands even
            when the competing native address is not catalogued. Unbound
            operands retain tolerant agreement; this is not a complete proof.

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

    # Fast set lookup for absolute-address validation.  One ``name_to_va`` map is
    # threaded through a whole compare run (it is built once per config, not per
    # function), so the derived set is memoised against that exact object instead
    # of being rebuilt for every function compared.
    catalog_va_set: set[int] = _catalog_va_set(name_to_va)

    if coff_relocs is not None:
        # Prefer typed CoffRelocRecord sequence when present.  Fail closed on
        # a missing VA map: without validation a typed/dict mask is an
        # unverified claim, so every typed/dict reloc is unresolved and the
        # compare mismatches at those slots instead of masking blindly.
        # ``{}`` means "scan failed or catalog genuinely empty" — callers
        # must surface a hard error (CatalogScanError) instead of passing it.
        # Plain-offset and zero-span modes carry no symbol claims and mask as
        # before (their byte windows still have to agree outside the mask).
        map_unusable = not name_to_va
        if (
            isinstance(coff_relocs, (list, tuple))
            and coff_relocs
            and isinstance(coff_relocs[0], CoffRelocRecord)
        ):
            typed_relocs = cast(Sequence[CoffRelocRecord], coff_relocs)
            table = _RELOC_TABLES.get(reloc_table, _RELOC_TABLES["coff-i386"])
            for rec in typed_relocs:
                r = rec.offset
                if not _slot_in_prefix(r, min_len):
                    if strict:
                        invalid_relocs.append(r)
                    continue
                valid = True
                if map_unusable:
                    valid = False
                elif name_to_va:
                    kind = table.get(rec.type)
                    if kind == "none":
                        # ABSOLUTE: a no-op reloc (alignment/terminator).  Do not
                        # mask — a real difference at this offset must show.
                        continue
                    if kind == "abs32":
                        valid = _validate_dir32(
                            obj_bytes,
                            target_bytes,
                            r,
                            rec.symbol,
                            name_to_va,
                            catalog_va_set,
                            iat_region,
                            reloc_table,
                            strict=strict,
                            check_known_bindings=check_known_bindings,
                        )
                    elif kind == "rel32" and section_va is not None:
                        valid = _validate_rel32(
                            obj_bytes,
                            target_bytes,
                            r,
                            rec.symbol,
                            name_to_va,
                            section_va,
                            reloc_table,
                            strict=strict,
                        )
                    else:
                        # Agreement can mask a slot without an address model.
                        valid = not strict
                if valid:
                    valid_relocs.append(r)
                else:
                    invalid_relocs.append(r)
        elif isinstance(coff_relocs, dict):
            # Dict branch: offset -> symbol_name with heuristic DIR32 validation.
            for r, raw_sym in coff_relocs.items():
                if not _slot_in_prefix(r, min_len):
                    if strict:
                        invalid_relocs.append(r)
                    continue
                valid = True
                if map_unusable:
                    valid = False
                elif name_to_va:
                    valid = _validate_dir32(
                        obj_bytes,
                        target_bytes,
                        r,
                        str(raw_sym),
                        name_to_va,
                        catalog_va_set,
                        iat_region,
                        reloc_table,
                        strict=strict,
                        check_known_bindings=check_known_bindings,
                    )
                if valid:
                    valid_relocs.append(r)
                else:
                    invalid_relocs.append(r)
        else:
            # List[int] branch: plain offset list (no symbol resolution)
            (invalid_relocs if strict else valid_relocs).extend(
                r
                for r in coff_relocs
                if isinstance(r, int) and (strict or _slot_in_prefix(r, min_len))
            )
    # Zero-reloc objects: candidate slots are 4-byte-ALIGNED zero dwords
    # in the object that differ from the target.  Skip the byte-by-byte
    # scan entirely when no zero dword exists — common for leaf functions.
    # Unaligned zero dwords are coincidental data, not linker-filled reloc
    # slots — only offsets divisible by _RELOC_ALIGNMENT are masked.
    elif (
        not strict
        and min_len >= _RELOC_ALIGNMENT
        and b"\x00" * _RELOC_ALIGNMENT in obj_bytes[:min_len]
    ):
        i = 0
        while i <= min_len - _RELOC_ALIGNMENT:
            if (
                i % _RELOC_ALIGNMENT == 0
                and obj_bytes[i : i + _RELOC_ALIGNMENT] == b"\x00" * _RELOC_ALIGNMENT
                and obj_bytes[i : i + _RELOC_ALIGNMENT] != target_bytes[i : i + _RELOC_ALIGNMENT]
            ):
                valid_relocs.append(i)
                i += _RELOC_ALIGNMENT
            else:
                i += 1

    # Ambiguous claims cannot inherit the tolerant policy for unknown names.
    claimed_records = (
        coff_relocs.items()
        if isinstance(coff_relocs, dict)
        else (
            (r.offset, r.symbol)
            for r in coff_relocs or []
            if isinstance(r, CoffRelocRecord) and r.type
        )
    )
    ambiguous_offsets = {
        offset
        for offset, name in claimed_records
        if _resolve_exact_then_stripped(name_to_va or {}, name) == AMBIGUOUS_VA
    }
    if ambiguous_offsets:
        valid_relocs = [offset for offset in valid_relocs if offset not in ambiguous_offsets]
        invalid_relocs = sorted(set(invalid_relocs) | ambiguous_offsets)
    # Vectorized comparison: build a boolean relocation mask and use NumPy
    # for the byte-level match instead of a Python-level per-byte loop.
    import numpy as np  # deferred: ~60 ms of startup for non-compile commands

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

    masked_match = (
        not has_mismatch
        and len(obj_bytes) == len(target_bytes)
        and not ((strict or ambiguous_offsets) and invalid_relocs)
    )
    return masked_match, match_count, max_len, valid_relocs, invalid_relocs
