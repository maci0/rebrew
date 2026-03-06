"""Core matching and relocation handling logic.

This module provides the central logic for comparing compiled bytes against
target binary bytes, handling COFF relocation masking, and classifying diffs.
"""


def smart_reloc_compare(
    obj_bytes: bytes,
    target_bytes: bytes,
    coff_relocs: list[int] | dict[int, str] | None = None,
    name_to_va: dict[str, int] | None = None,
) -> tuple[bool, int, int, list[int], list[int]]:
    """Compare bytes with relocation masking and target validation.

    Uses COFF relocation records if available, falls back to zero-span detection.
    If name_to_va is provided and coff_relocs is a dict, it will resolve the
    target symbol and ensure its mapped VA matches the actual target_bytes
    offset, catching when C code references the wrong global variable.

    Args:
        obj_bytes: The compiled output bytes to verify.
        target_bytes: The original target bytes to compare against.
        coff_relocs: Offset list OR dict mapping `offset` -> `symbol_name`.
        name_to_va: Global VA lookup table from the active Data Catalog.

    Returns:
        (matched, match_count, total_bytes, valid_relocs, invalid_relocs)

    """
    import struct

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
            for r in coff_relocs:
                if r + 4 <= min_len:
                    valid_relocs.append(r)
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

    reloc_set = set()
    for r in valid_relocs:
        for j in range(4):
            if r + j < min_len:
                reloc_set.add(r + j)

    match_count = 0
    mismatches = []
    for i in range(min_len):
        if i in reloc_set or obj_bytes[i] == target_bytes[i]:
            match_count += 1
        else:
            mismatches.append(i)

    masked_match = not mismatches and len(obj_bytes) == len(target_bytes)
    return masked_match, match_count, max_len, valid_relocs, invalid_relocs
