"""pe_headers.py — read/patch PE header fields for byte-identical reconstruction.

Byte-identical output needs more than matched function bytes: the PE header
carries linker/OS/subsystem versions, DLL characteristics (TSAWARE), stack/
heap sizes, timestamp, and checksum that MSVC6's default link does not
reproduce.  This module reads those fields from a PE, patches a byte copy
(the ``rebrew round-trip --fix-headers`` path), and reports parity between
the original and the patched copy.

File alignment / section merge are NOT patched here — they require a relink
(`/ALIGN`, `/MERGE`) because they change raw section offsets.  Parity still
reports them so the gap is visible.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# (offset_from_e_lfanew, size_bytes, label) for each patchable/parable field.
# Offsets follow the PE32 optional-header layout (see docs/TOOLCHAIN notes).
_FIELD_SPECS: list[tuple[int, int, str]] = [
    (0x08, 4, "timestamp"),  # COFF TimeDateStamp
    (0x1A, 1, "linker_version_major"),
    (0x1B, 1, "linker_version_minor"),
    (0x40, 2, "os_version_major"),
    (0x42, 2, "os_version_minor"),
    (0x44, 2, "image_version_major"),
    (0x46, 2, "image_version_minor"),
    (0x48, 2, "subsystem_version_major"),
    (0x4A, 2, "subsystem_version_minor"),
    (0x58, 4, "checksum"),  # recomputed, not copied
    (0x5E, 2, "dll_characteristics"),  # e.g. 0x8000 TSAWARE
    (0x60, 4, "stack_reserve"),
    (0x64, 4, "stack_commit"),
    (0x68, 4, "heap_reserve"),
    (0x6C, 4, "heap_commit"),
    (0x3C, 4, "file_align"),  # parity only — needs relink to change
]

# Fields --fix-headers actually patches (everything except file_align).
PATCHABLE = {label for _o, _s, label in _FIELD_SPECS if label != "file_align"}


@dataclass
class PeHeaderFields:
    """Parsed PE header fields keyed by label (see _FIELD_SPECS)."""

    values: dict[str, int]

    def get(self, label: str) -> int | None:
        return self.values.get(label)


def _lfanew(data: bytes | bytearray) -> int | None:
    """Return e_lfanew (offset of the PE signature) or None if not a PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = int(struct.unpack_from("<I", data, 0x3C)[0])
    if e_lfanew + 4 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    return e_lfanew


def read_pe_header_fields(data: bytes) -> PeHeaderFields | None:
    """Parse every known header field from *data*.  None if not a PE."""
    lfanew = _lfanew(data)
    if lfanew is None:
        return None
    values: dict[str, int] = {}
    for offset, size, label in _FIELD_SPECS:
        pos = lfanew + offset
        if pos + size > len(data):
            continue
        # Read exactly *size* bytes: a 4-byte unpack would raise struct.error
        # when fewer than 4 bytes remain after *pos*.
        values[label] = int.from_bytes(data[pos : pos + size], "little")
    return PeHeaderFields(values)


def _pe_checksum(data: bytes) -> int:
    """Compute the PE checksum per the spec: sum of all 16-bit LE words with the
    checksum field itself treated as zero, plus the file length, folded."""
    lfanew = _lfanew(data)
    cksum_off = (lfanew + 0x58) if lfanew is not None else -1
    tmp = bytearray(data)
    if 0 <= cksum_off < len(tmp):
        tmp[cksum_off : cksum_off + 4] = b"\x00\x00\x00\x00"
    # Pad to even length for 16-bit words (spec).
    if len(tmp) & 1:
        tmp.append(0)
    checksum = 0
    for i in range(0, len(tmp), 2):
        checksum += struct.unpack_from("<H", tmp, i)[0]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += len(data)
    return (checksum & 0xFFFF) + (checksum >> 16)


def patch_pe_headers(data: bytes, fields: dict[str, int]) -> bytes:
    """Patch *fields* into a byte copy of *data*.

    *fields* is ``{label: value}`` for any PATCHABLE label (file_align is
    ignored — it needs a relink).  The checksum is always recomputed last.
    """
    out = bytearray(data)
    lfanew = _lfanew(out)
    if lfanew is None:
        return bytes(out)
    for offset, size, label in _FIELD_SPECS:
        if label not in PATCHABLE or label not in fields:
            continue
        pos = lfanew + offset
        if pos + size > len(out):
            continue
        # Write exactly *size* bytes: a 4-byte pack would clobber the
        # adjacent fields (e.g. linker_version_major at 1 byte would zero
        # linker_version_minor and spill into SizeOfCode).
        value = fields[label] & ((1 << (8 * size)) - 1)
        out[pos : pos + size] = value.to_bytes(size, "little")
    # Recompute checksum over the patched image.
    struct.pack_into("<I", out, lfanew + 0x58, _pe_checksum(bytes(out)))
    return bytes(out)


def header_parity(
    original: bytes, candidate: bytes, configured: dict[str, int] | None = None
) -> list[dict[str, object]]:
    """Compare header fields between *original* and *candidate*.

    Returns one dict per field: ``{field, original, reasm, match}``.
    *configured* (from ``[link]``) values, when present, are shown as the
    intended value for fields that still differ.
    """
    orig = read_pe_header_fields(original)
    cand = read_pe_header_fields(candidate)
    if orig is None or cand is None:
        return []
    out: list[dict[str, object]] = []
    for _offset, _size, label in _FIELD_SPECS:
        o = orig.values.get(label)
        c = cand.values.get(label)
        if o is None or c is None:
            continue
        out.append(
            {
                "field": label,
                "original": o,
                "reasm": c,
                "match": o == c,
                "configured": configured.get(label) if configured else None,
            }
        )
    return out
