"""Core matching and relocation handling logic.

Provides byte-level comparison of compiled bytes against target binary bytes
with COFF relocation masking, using NumPy vectorization for performance.
"""

import struct
from collections.abc import Callable

import numpy as np

from rebrew.matcher.parsers import CoffRelocRecord

# IMAGE_REL_I386_*
_REL_DIR32 = 0x0006
_REL_REL32 = 0x0014


class UnresolvedSymbolError(Exception):
    """Raised when a relocation references a symbol with no VA in the catalog."""

    def __init__(self, symbol: str) -> None:
        super().__init__(symbol)
        self.symbol = symbol


def apply_coff_relocations(
    text: bytes,
    relocs: list[CoffRelocRecord],
    resolve_va: Callable[[str], int | None],
    *,
    image_base: int,
    section_va: int,
) -> bytes:
    """Apply COFF relocations to a .text byte blob.

    For each relocation, read the addend at ``relocs[i].offset``, resolve the
    target VA via ``resolve_va(symbol)``, compute the patched value per the
    relocation type, and write it back as little-endian 32-bit.

    :param text: Raw bytes for a single function as compiled.
    :param relocs: Relocation records from ``parse_obj_relocs_full``.
    :param resolve_va: Callable mapping symbol → absolute VA (None if unknown).
    :param image_base: PE ImageBase (e.g. 0x10000000 for an MSVC6 DLL).
    :param section_va: VA of the function's start (used for REL32 PC-relative arithmetic).

    :raises UnresolvedSymbolError: Symbol not in the catalog.
    :raises NotImplementedError: Unsupported relocation type.
    """
    buf = bytearray(text)
    for r in relocs:
        sym = r.symbol.lstrip("_") if r.symbol.startswith("_") else r.symbol
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


def smart_reloc_compare(
    obj_bytes: bytes,
    target_bytes: bytes,
    coff_relocs: list[int] | dict[int, str] | None = None,
    name_to_va: dict[str, int] | None = None,
) -> tuple[bool, int, int, list[int], list[int]]:
    """Compare bytes with relocation masking and target validation.

    Operates in three modes depending on *coff_relocs*:

    - **list[int]**: Plain offsets — 4 bytes at each offset are masked as valid
      relocations without symbol resolution.
    - **dict[int, str]**: Offset → symbol name mapping — when *name_to_va* is
      also provided, resolves each symbol's expected VA and validates it against
      the actual 32-bit value in *target_bytes*, catching wrong-global-variable
      references.
    - **None**: Falls back to zero-span detection (scanning for ``00 00 00 00``
      runs in *obj_bytes* aligned with non-zero *target_bytes*).

    Args:
        obj_bytes: The compiled output bytes to verify.
        target_bytes: The original target bytes to compare against.
        coff_relocs: Offset list OR dict mapping offset → symbol name.
        name_to_va: Global VA lookup table from the active Data Catalog.

    Returns:
        (matched, match_count, total_bytes, valid_relocs, invalid_relocs)

    """
    min_len = min(len(obj_bytes), len(target_bytes))
    max_len = max(len(obj_bytes), len(target_bytes))

    # Trivial case: both empty → vacuous match
    if max_len == 0:
        return True, 0, 0, [], []

    valid_relocs = []
    invalid_relocs = []

    if coff_relocs is not None:
        if isinstance(coff_relocs, dict):
            # Dict branch: offset -> symbol_name mapping with VA validation
            for r in coff_relocs:
                if r + 4 <= min_len:
                    valid = True

                    # Check absolute address if we have name mapping
                    if name_to_va:
                        sym_name = str(coff_relocs[r])

                        # Remove underscore prefix for C names if present
                        clean_sym = sym_name.lstrip("_") if sym_name.startswith("_") else sym_name

                        target_va = name_to_va.get(clean_sym) or name_to_va.get(sym_name)
                        if target_va:
                            try:
                                # Read absolute address from target bytes (little endian 32-bit)
                                actual_target_va = struct.unpack("<I", target_bytes[r : r + 4])[0]
                                if actual_target_va != target_va:
                                    valid = False
                            except struct.error:
                                valid = False

                    if valid:
                        valid_relocs.append(r)
                    else:
                        invalid_relocs.append(r)
        else:
            # List branch: plain offset list (no symbol resolution needed)
            valid_relocs.extend(r for r in coff_relocs if r + 4 <= min_len)
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
