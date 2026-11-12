"""One NE segment as a raw 16-bit image with its relocations applied, for the decompiler.

kuna reads a segment as a flat image at base 0 (``--raw-image``), so the NE fixups the loader would
apply have to be applied to the slice or its far calls and segment references read as chain links.
Far calls and jumps to another segment or to an import cannot be addressed inside the slice: each
distinct target gets a one-instruction stub after the segment's data, and :meth:`NeSlice.name_calls`
renames the stub (and the segment's own offsets) in the decompiled text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
lazy import struct

from rebrew.formats.ne_loader import (
    NeHeader,
    NeParseError,
    NeSegment,
    parse_entry_table,
    parse_imports,
    parse_segments,
    read_ne_header,
)

SEGMENT_HAS_RELOCATIONS = 0x0100
SEGMENT_LIMIT = 0x10000
RELOCATION_RECORD_SIZE = 8
CHAIN_END = 0xFFFF
MOVABLE_SEGMENT = 0xFF
FAR_CALL_OPCODE = 0x9A
FAR_JUMP_OPCODE = 0xEA
#: ``retf`` plus padding: the body of a stub, so a call to it decompiles as a call.
STUB_BODY = b"\xcb\x90\x90\x90"
STUB_SIZE = len(STUB_BODY)

#: Where a fixup applies (the low nibble of a record's first byte).
SOURCE_LOW_BYTE = 0
SOURCE_SELECTOR = 2
SOURCE_FAR_POINTER = 3
SOURCE_OFFSET = 5
#: What it resolves to (the low two bits of a record's flags).
TARGET_INTERNAL = 0
TARGET_IMPORT_ORDINAL = 1
TARGET_IMPORT_NAME = 2
TARGET_OS_FIXUP = 3
TARGET_MASK = 3
ADDITIVE_FLAG = 4

#: Bytes a fixup of each source type overwrites; an unknown source type clears one word.
_SOURCE_WIDTH = {SOURCE_LOW_BYTE: 1, SOURCE_SELECTOR: 2, SOURCE_FAR_POINTER: 4, SOURCE_OFFSET: 2}
_DEFAULT_WIDTH = 2

_SUB_NAME = re.compile(r"\bsub_([0-9a-fA-F]+)\b")
_NON_IDENTIFIER = re.compile(r"\W")
_NAME_MIN_DIGITS = 4


@dataclass(frozen=True)
class NeFixup:
    """One fixed-up location of a segment after its chains are followed."""

    source: int
    flags: int
    target1: int
    target2: int
    additive: bool


@dataclass
class NeSlice:
    """A segment's bytes with its relocations applied, plus what to call each stub.

    ``image`` is the segment followed by the stubs; ``length`` is the segment's own size, so an
    address below it is an offset inside the segment. ``unapplied`` counts the fixups left as in
    the file or cleared, by reason.
    """

    segment: int
    length: int
    image: bytes
    stub_names: dict[int, str]
    applied: int
    unapplied: dict[str, int] = field(default_factory=dict)

    def flat_va(self, offset: int) -> int:
        """The address rebrew and the backend give a function: ``((segment - 1) << 16) | offset``."""
        return ((self.segment - 1) << 16) | offset

    def name_calls(self, code: str) -> str:
        """Rename kuna's ``sub_<offset>`` tokens: stubs to their target, offsets to flat addresses."""

        def rename(match: re.Match[str]) -> str:
            address = int(match.group(1), 16)
            if address in self.stub_names:
                return self.stub_names[address]
            if address < self.length:
                return f"sub_{self.flat_va(address):0{_NAME_MIN_DIGITS}x}"
            return match.group(0)

        return _SUB_NAME.sub(rename, code)

    def summary(self) -> str:
        """The comment appended to the decompiled code: what was and was not relocated."""
        left = ", ".join(f"{count} {reason}" for reason, count in sorted(self.unapplied.items()))
        return (
            f"/* NE segment {self.segment}: {self.applied} relocations applied"
            f"{'; not applied: ' + left if left else ''}. Selector operands outside far calls are "
            "NE segment numbers; far calls to other segments and imports are named after their target. */"
        )


def _u16(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<H", data, at)[0])


def read_segment_fixups(data: bytes, segment: NeSegment, raw: bytes) -> dict[int, NeFixup]:
    """Follow a segment's relocation records, one entry per fixed-up location.

    A record without the additive flag starts a chain: the location holds the offset of the next
    location (0xFFFF ends it), so the file's bytes there are links, not the target. An additive
    record fixes one location. A table that runs past the file is a parse error.
    """
    if not segment.flags & SEGMENT_HAS_RELOCATIONS or not segment.on_disk:
        return {}
    table = segment.file_offset + segment.length
    if table + 2 > len(data):
        raise NeParseError(f"segment {segment.index} has a truncated fixup count")
    count = _u16(data, table)
    if table + 2 + count * RELOCATION_RECORD_SIZE > len(data):
        raise NeParseError(f"segment {segment.index} has a truncated fixup block")
    fixups: dict[int, NeFixup] = {}
    for index in range(count):
        record = table + 2 + index * RELOCATION_RECORD_SIZE
        source, flags, location, target1, target2 = struct.unpack_from("<BBHHH", data, record)
        fixup = NeFixup(source & 0x0F, flags, target1, target2, bool(flags & ADDITIVE_FLAG))
        if fixup.additive:
            # Byte addends need no two-byte chain link.
            addend_size = 1 if fixup.source == SOURCE_LOW_BYTE else 2
            if location + addend_size <= len(raw):
                fixups[location] = fixup
            continue
        for _ in range(len(raw)):
            if location + 2 > len(raw) or location in fixups:
                break
            fixups[location] = fixup
            following = _u16(raw, location)
            if following == CHAIN_END:
                break
            location = following
    return fixups


class _Builder:
    """Applies the fixups of one segment to a copy of its bytes."""

    def __init__(
        self, data: bytes, header: NeHeader, ne_offset: int, segment: NeSegment, fixup_limit: int
    ) -> None:
        self.segment = segment
        self.raw = data[segment.file_offset : segment.file_offset + segment.length]
        self.image = bytearray(self.raw)
        self.fixups = read_segment_fixups(data[:fixup_limit], segment, self.raw)
        self.modules = [module.module for module in parse_imports(data, ne_offset, header)]
        self.imported_names = ne_offset + header.imported_names_offset
        self.data = data
        self.entries = {
            ordinal: (seg, off) for ordinal, seg, off in parse_entry_table(data, ne_offset, header)
        }
        self.stub_offsets: dict[str, int] = {}
        self.applied = 0
        self.unapplied: dict[str, int] = {}
        self.stub_base = (segment.length + STUB_SIZE - 1) // STUB_SIZE * STUB_SIZE

    def _put(self, location: int, value: int, width: int) -> None:
        self.image[location : location + width] = value.to_bytes(width, "little")

    def _skip(self, reason: str, location: int, width: int, *, clear: bool = True) -> None:
        self.unapplied[reason] = self.unapplied.get(reason, 0) + 1
        if clear:
            self.image[location : location + width] = bytes(width)

    def _stub(self, name: str) -> int | None:
        """The offset of the stub called *name*, allocating it after the segment on first use."""
        if name not in self.stub_offsets:
            offset = self.stub_base + len(self.stub_offsets) * STUB_SIZE
            if offset + STUB_SIZE > SEGMENT_LIMIT:
                return None
            self.stub_offsets[name] = offset
        return self.stub_offsets[name]

    def _import_name(self, fixup: NeFixup) -> str:
        module = (
            self.modules[fixup.target1 - 1] if 1 <= fixup.target1 <= len(self.modules) else "IMPORT"
        )
        if fixup.flags & TARGET_MASK == TARGET_IMPORT_ORDINAL:
            what = str(fixup.target2)
        else:
            at = self.imported_names + fixup.target2
            length = self.data[at] if at < len(self.data) else 0
            what = self.data[at + 1 : at + 1 + length].decode("latin-1")
        return _NON_IDENTIFIER.sub("_", f"{module}_{what}")

    def _internal(self, fixup: NeFixup, addend: int) -> tuple[int, int] | None:
        """The ``(segment, offset)`` an internal fixup points at, or None for a missing entry."""
        segment, offset = fixup.target1 & 0xFF, fixup.target2
        if segment == MOVABLE_SEGMENT:
            entry = self.entries.get(fixup.target2)
            if entry is None:
                return None
            segment, offset = entry
        return segment, (offset + (addend if fixup.additive else 0)) & 0xFFFF

    def apply(self, location: int, fixup: NeFixup) -> None:
        width = _SOURCE_WIDTH.get(fixup.source, _DEFAULT_WIDTH)
        if location + width > len(self.image):
            self._skip("past the segment", location, 0, clear=False)
            return
        kind = fixup.flags & TARGET_MASK
        if kind == TARGET_OS_FIXUP:
            self._skip("OS fixups left as in the file", location, width, clear=False)
            return
        addend = self.raw[location] if fixup.source == SOURCE_LOW_BYTE else _u16(self.raw, location)
        far_transfer = location > 0 and self.raw[location - 1] in (FAR_CALL_OPCODE, FAR_JUMP_OPCODE)
        if kind == TARGET_INTERNAL:
            target = self._internal(fixup, addend)
            if target is None:
                self._skip("entry ordinals missing from the entry table", location, width)
                return
            segment, offset = target
            if fixup.source == SOURCE_FAR_POINTER:
                # kuna addresses a far call as (selector << 16) | offset, so a far call or jump
                # gets selector 0 and an offset inside the slice (the segment or a stub).
                if far_transfer and segment != self.segment.index:
                    stub = self._stub(f"sub_{((segment - 1) << 16 | offset):0{_NAME_MIN_DIGITS}x}")
                    if stub is None:
                        self._skip("no room for a far-call stub", location, width)
                        return
                    offset = stub
                self._put(location, offset, 2)
                self._put(location + 2, 0 if far_transfer else segment, 2)
            elif fixup.source == SOURCE_SELECTOR:
                self._put(location, segment, 2)
            elif fixup.source == SOURCE_OFFSET:
                self._put(location, offset, 2)
            elif fixup.source == SOURCE_LOW_BYTE:
                self._put(location, offset & 0xFF, 1)
            else:
                self._skip(f"source type {fixup.source} unsupported", location, width)
                return
            self.applied += 1
            return
        if fixup.source != SOURCE_FAR_POINTER:
            self._skip("import offsets and selectors", location, width)
            return
        stub = self._stub(self._import_name(fixup))
        if stub is None:
            self._skip("no room for a far-call stub", location, width)
            return
        self._put(location, stub, 2)
        self._put(location + 2, 0, 2)
        self.applied += 1


def build_ne_slice(data: bytes, segment_index: int) -> NeSlice:
    """The bytes of NE segment *segment_index* (1-based) with its relocations applied."""
    ne_offset, header = read_ne_header(data)
    segments = parse_segments(data, ne_offset, header)
    if not 1 <= segment_index <= len(segments):
        raise NeParseError(f"NE segment {segment_index} does not exist")
    segment = segments[segment_index - 1]
    if not segment.on_disk or segment.is_iterated:
        raise NeParseError(f"NE segment {segment_index} has no plain bytes in the file")
    if segment.file_offset + segment.length > len(data):
        raise NeParseError(f"NE segment {segment_index} extends beyond the file")
    fixup_limit = min(
        (
            s.file_offset
            for s in segments
            if s.on_disk and s.file_offset >= segment.file_offset + segment.length
        ),
        default=len(data),
    )
    builder = _Builder(data, header, ne_offset, segment, fixup_limit)
    for location in sorted(builder.fixups):
        builder.apply(location, builder.fixups[location])
    image = bytes(builder.image)
    stub_names = {offset: name for name, offset in builder.stub_offsets.items()}
    if stub_names:
        image = image.ljust(builder.stub_base, b"\x00") + STUB_BODY * len(stub_names)
    return NeSlice(
        segment=segment_index,
        length=segment.length,
        image=image,
        stub_names=stub_names,
        applied=builder.applied,
        unapplied=builder.unapplied,
    )
