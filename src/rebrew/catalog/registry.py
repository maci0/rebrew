"""catalog/registry.py - Function registry building and size resolution.

Merges discovery inventory and Ghidra function lists into a unified registry with
size resolution (jump table detection, padding absorption, etc.).
"""

import logging
import struct
from pathlib import Path
from typing import Any, TypedDict

from rebrew.config import ProjectConfig, arch_byte_order, arch_pointer_size
from rebrew.sections import has_back_jumps, trim_trailing_padding

logger = logging.getLogger(__name__)


class RegistryEntry(TypedDict, total=False):
    """Type-safe schema for a single function in the registry.

    All fields are technically optional (``total=False``), but
    ``_new_registry_entry`` always sets: ``detected_by``, ``size_by_tool``,
    ``list_name``, ``ghidra_name``, ``is_thunk``, ``is_export``, ``canonical_size``.
    ``size_reason`` is set alongside ``canonical_size`` during registry construction.
    """

    detected_by: list[str]
    size_by_tool: dict[str, int]
    list_name: str
    ghidra_name: str
    is_thunk: bool
    is_export: bool
    canonical_size: int
    size_reason: str


def _new_registry_entry(
    va: int,
    cfg: ProjectConfig | None,
    *,
    is_export: bool = False,
    iat_thunks: frozenset[int] = frozenset(),
) -> RegistryEntry:
    """Create a default registry entry for *va*.

    *iat_thunks* is the config's list, already set-ized by the caller: the
    membership test runs once per inventory entry and a linear scan over a
    PE's thunk table made it O(entries x thunks).
    """
    return RegistryEntry(
        detected_by=[],
        size_by_tool={},
        list_name="",
        ghidra_name="",
        is_thunk=va in iat_thunks,
        is_export=is_export or (va in cfg.dll_exports if cfg else False),
        canonical_size=0,
    )


def _entry_for(
    registry: dict[int, RegistryEntry],
    va: int,
    cfg: ProjectConfig | None,
    iat_thunks: frozenset[int],
    *,
    is_export: bool = False,
) -> RegistryEntry:
    """The entry for *va*, created on first sight.

    ``dict.setdefault`` would build a default entry for every already-known
    VA and throw it away, which is the per-function work this replaced.
    """
    entry = registry.get(va)
    if entry is None:
        entry = registry[va] = _new_registry_entry(
            va, cfg, is_export=is_export, iat_thunks=iat_thunks
        )
    return entry


# ---------------------------------------------------------------------------
# Jump table detection (shared by registry + grid)
# ---------------------------------------------------------------------------


def is_jump_table(
    data: bytes,
    section_va: int,
    section_size: int,
    arch: str = "x86_32",
    endian: str = "",
) -> bool:
    """Check if *data* looks like a jump/switch table (array of .text pointers).

    Skips leading alignment bytes (NOP 0x90, INT3 0xCC, ``mov edi,edi`` 0x8BFF)
    before checking for a run of at least 2 consecutive .text pointers.
    Validates that the pointer array is *arch*-aligned and reads each entry at
    the target's pointer width and byte order, so a 64-bit table is not
    mis-strided and a big-endian one is not read byte-reversed.

    *endian* is the image's own byte order (``BinaryInfo.endian``) and
    overrides *arch*'s default, so a little-endian MIPS build is read
    little-endian rather than as the arch's usual big-endian.  Leave it empty
    when no image was parsed.

    The x86 alignment-prefix heuristics apply only to x86 arches; other
    arches (multi-arch P0) get the plain aligned-pointer-array check until
    their own jump-table conventions land (Phase 1).
    """
    is_x86 = arch.startswith("x86")
    ptr_size = arch_pointer_size(arch)
    order = arch_byte_order(arch, endian)
    fmt = f"{order}{'H' if ptr_size == 2 else 'I' if ptr_size == 4 else 'Q'}"
    if len(data) < 2 * ptr_size:
        return False
    # The table is a whole number of pointer-sized entries.
    if len(data) % ptr_size != 0:
        return False
    # Skip alignment prefix (x86-only: NOP 0x90 / INT3 0xCC).
    off = 0
    if is_x86:
        while off < len(data) and data[off] in (0x90, 0xCC):
            off += 1
    # The prefix must keep the remaining pointer array pointer-aligned —
    # 1..ptr_size-1 NOP/INT3 bytes before the table would misalign every read.
    if (len(data) - off) % ptr_size != 0:
        return False
    # Also skip ``mov edi, edi`` (8B FF) — common MSVC hotpatch 2-byte NOP
    if is_x86 and off + 1 < len(data) and data[off] == 0x8B and data[off + 1] == 0xFF:
        off += 2
        # Re-check alignment after skipping hotpatch bytes
        if (len(data) - off) % ptr_size != 0:
            return False
    remaining = data[off:]
    if len(remaining) < 2 * ptr_size:
        return False
    n_ptrs = len(remaining) // ptr_size
    count = 0
    for i in range(n_ptrs):
        val = struct.unpack_from(fmt, remaining, i * ptr_size)[0]
        if section_va <= val < section_va + section_size:
            count += 1
        else:
            break
    return count >= 2


# ---------------------------------------------------------------------------
# Canonical size resolution
# ---------------------------------------------------------------------------


def _resolve_canonical_size(
    sizes: dict[str, int],
    va: int,
    text_data: bytes | None,
    text_va: int,
    text_size: int,
    arch: str = "x86_32",
    endian: str = "",
) -> tuple[int, str]:
    """Resolve canonical size when multiple sources disagree.

    Handles missing sources and, when list_size > ghidra_size, checks if
    the extra bytes are jump table / padding.  *arch* and *endian* are the
    target's, so the jump-table probe reads pointer slots at the right width
    and byte order.  Returns (canonical_size, reason_string).
    """
    ghidra_size = sizes.get("ghidra", 0)
    list_size = sizes.get("list", 0)

    if not ghidra_size and not list_size:
        return 0, "none"

    if not ghidra_size:
        return list_size, "list (only source)"
    if not list_size:
        return ghidra_size, "ghidra (only source)"

    if ghidra_size >= list_size:
        return ghidra_size, "ghidra (larger or equal)"

    # list_size > ghidra_size — check if extra bytes are jump table / padding
    if text_data is None:
        return ghidra_size, "ghidra (no binary data to verify)"

    func_offset = va - text_va
    ghidra_end = func_offset + ghidra_size
    list_end = func_offset + list_size

    if func_offset < 0 or ghidra_end < 0 or list_end > len(text_data):
        return ghidra_size, "ghidra (extra bytes out of range)"

    extra = text_data[ghidra_end:list_end]
    if not extra:
        return ghidra_size, "ghidra (no extra bytes)"

    if trim_trailing_padding(extra) == 0:
        return list_size, "list (includes tail padding)"

    if is_jump_table(extra, text_va, text_size, arch, endian):
        return list_size, "list (includes jump table)"

    # Out-of-line code: jmp/jcc in the extra bytes targeting func_start..ghidra_end
    if has_back_jumps(extra, func_offset, ghidra_end, base_offset=ghidra_end):
        return list_size, "list (includes out-of-line code)"

    # A region with no ret and no padding is straight-line code of the SAME
    # function — Ghidra truncated the size (out-of-line tails, string-pointer
    # arrays, etc.).  Trust the list size there: a truncated canonical size
    # silently drops real code from comparisons, while an over-count at worst
    # makes the byte comparison visibly mismatch.
    #
    # x86-only, like the alignment-prefix probes above: 0xC3/0xC2 are the x86
    # RET encodings.  No other arch emits them, so probing an ARM or MIPS tail
    # for those bytes always answers "no terminator" and made this branch
    # claim the list size for every function on those targets.  They fall
    # through to the conservative default instead, which is also what an x86
    # tail that does end in a ret gets.
    if arch.startswith("x86") and 0xC3 not in extra and 0xC2 not in extra:
        return list_size, "list (code tail, no terminator)"

    # Default: trust Ghidra when we can't identify the extra bytes
    return ghidra_size, "ghidra (unrecognized extra bytes)"


# ---------------------------------------------------------------------------
# Registry builder
# ---------------------------------------------------------------------------


def build_function_registry(
    funcs: list[dict[str, Any]],
    cfg: ProjectConfig | None,
    ghidra_path: Path | None = None,
    bin_path: Path | None = None,
) -> dict[int, RegistryEntry]:
    """Build a unified function registry merging discovery + ghidra + exports.

    Returns dict keyed by VA with:
        detected_by: list of tool names
        size_by_tool: {tool: size}
        list_name / ghidra_name: tool-specific names
        is_thunk: bool
        is_export: bool
        canonical_size: best-known size
        size_reason: explanation for chosen canonical size

    VAs inside the PE import-address table are dropped — they are data, not
    functions.  MSVC PEs place the IAT at the START of ``.text`` (before the
    code), so a linear sweep walks it as code and reports a fake function per
    slot (``sym.imp.`` entries from rizin, or generic ``fcn.`` names from
    other sweeps); skeleton generation would create bogus source files for
    them.
    """
    from rebrew.binary_loader import iat_slot_vas

    registry: dict[int, RegistryEntry] = {}
    iat_vas = iat_slot_vas(bin_path) if bin_path else set()

    # --- Discovery inventory ---
    r2_bogus = set(getattr(cfg, "r2_bogus_vas", [])) if cfg else set()
    iat_thunks = frozenset(getattr(cfg, "iat_thunks", []) or ()) if cfg else frozenset()
    for func in funcs:
        va = int(func["va"])
        if va in iat_vas:
            continue
        if str(func["name"]).startswith("case."):
            # Ghidra jump-table case labels are data inside their parent
            # function, not functions; clustering them breaks overlap checks.
            continue
        entry = _entry_for(registry, va, cfg, iat_thunks)
        if "list" not in entry["detected_by"]:
            entry["detected_by"].append("list")
        list_size = int(func["size"])
        if va not in r2_bogus:
            entry["size_by_tool"]["list"] = list_size
        entry["list_name"] = str(func["name"])

    # --- Function structure (from cached JSON) ---
    from rebrew.catalog.loaders import load_function_structure

    structure_entries = load_function_structure(ghidra_path) if ghidra_path else []

    for struc_func in structure_entries:
        va = struc_func.va
        if va == 0 or struc_func.size == 0 or va in iat_vas:
            continue

        entry = _entry_for(registry, va, cfg, iat_thunks)
        if "ghidra" not in entry["detected_by"]:
            entry["detected_by"].append("ghidra")
        entry["size_by_tool"]["ghidra"] = struc_func.size
        entry["ghidra_name"] = struc_func.tool_name or struc_func.name

    # --- Exports ---
    exports: dict[int, str] = cfg.dll_exports if cfg else {}
    for va in exports:
        entry = _entry_for(registry, va, cfg, iat_thunks, is_export=True)
        if "exports" not in entry["detected_by"]:
            entry["detected_by"].append("exports")

    # --- Load .text section data ---
    text_data: bytes | None = None
    text_va = 0
    text_size_val = 0
    # Target identity for the jump-table probe.  The image header's own byte
    # order wins over the arch default, so a little-endian MIPS build is not
    # probed as big-endian.
    target_arch = "x86_32"
    target_endian = ""
    # is_file(), not exists(): an unset target_binary is the truthy ``Path(".")``
    # (see list_uncovered's function_list note), and handing a directory to
    # LIEF aborts the process with bad_alloc instead of returning None.
    if bin_path and Path(bin_path).is_file():
        try:
            from rebrew.binary_loader import load_binary

            info = load_binary(bin_path)
            target_arch = info.arch or target_arch
            target_endian = info.endian
            if ".text" in info.sections:
                sec = info.sections[".text"]
                text_va = sec.va
                text_size_val = sec.size
                raw = getattr(sec, "raw_size", sec.size)
                text_data = info.data[sec.file_offset : sec.file_offset + raw]
        except (OSError, KeyError, ValueError):
            logger.debug(".text section load failed for %s", bin_path, exc_info=True)

    # --- Resolve canonical size ---
    for va, entry in registry.items():
        sizes = entry["size_by_tool"]
        canonical, reason = _resolve_canonical_size(
            sizes, va, text_data, text_va, text_size_val, target_arch, target_endian
        )
        entry["canonical_size"] = canonical
        entry["size_reason"] = reason

    return registry


def count_detection_sources(registry: dict[int, RegistryEntry]) -> tuple[int, int, int, int]:
    """Count ghidra/list/both/thunk detection breakdown across registry entries.

    Shared by the catalog CLI and ``rebrew verify`` summary output so both
    surfaces report identical source statistics.
    """
    ghidra_count = list_count = both_count = thunk_count = 0
    for entry in registry.values():
        detected = entry["detected_by"]
        has_ghidra = "ghidra" in detected
        has_list = "list" in detected
        if has_ghidra:
            ghidra_count += 1
        if has_list:
            list_count += 1
        if has_ghidra and has_list:
            both_count += 1
        if entry["is_thunk"]:
            thunk_count += 1
    return ghidra_count, list_count, both_count, thunk_count
