"""Validated NE segment/fixup inventories and explicitly positional/content comparisons."""

from __future__ import annotations

from dataclasses import dataclass
lazy import collections
lazy import struct
lazy from pathlib import Path

lazy from rebrew.formats.ne_loader import (
    NeParseError,
    parse_exports,
    parse_segments,
    read_ne_header,
)


@dataclass(frozen=True)
class NeFixup:
    """One declared fixup record; source chains are not expanded into code references."""

    address_type: int
    relocation_type: int
    target: int
    addend: int


class NeImage:
    """Physical NE image. Segment indices here are zero-based, selectors are one-based."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        self.header, header = read_ne_header(self.data)
        self.align = header.sector_size
        self.seg_count = header.segment_count
        exports = parse_exports(self.data, self.header, header)
        self.module = next((e.name for e in exports if e.ordinal == 0), "")
        self.segment_records = parse_segments(self.data, self.header, header)
        self.segments = [(s.file_offset, s.length, s.flags) for s in self.segment_records]
        for segment in self.segment_records:
            if segment.on_disk and segment.file_offset + segment.length > len(self.data):
                raise NeParseError(f"segment {segment.index} extends beyond the file")

    def seg_bytes(self, index: int) -> bytes:
        """Stored bytes, including encoded iterated data; no virtual expansion is implied."""
        off, length, _ = self.segments[index]
        return self.data[off : off + length]

    def fixups(self, index: int) -> list[NeFixup]:
        """Read a complete relocation block; reject truncation instead of partial counts."""
        segment = self.segment_records[index]
        if not segment.flags & 0x0100:
            return []
        if not segment.on_disk:
            raise NeParseError(f"segment {index + 1} has fixups without stored bytes")
        start = segment.file_offset + segment.length
        limit = min(
            (s.file_offset for s in self.segment_records if s.on_disk and s.file_offset >= start),
            default=len(self.data),
        )
        if start + 2 > limit:
            raise NeParseError(f"segment {index + 1} has a truncated fixup count")
        count = struct.unpack_from("<H", self.data, start)[0]
        if start + 2 + count * 8 > limit:
            raise NeParseError(f"segment {index + 1} has a truncated fixup block")
        return [
            NeFixup(*struct.unpack_from("<BB2xHH", self.data, start + 2 + i * 8))
            for i in range(count)
        ]


def block_set(image: bytes, size: int) -> set[bytes]:
    """All overlapping full windows; incomplete tails do not become matches."""
    if size < 1:
        raise ValueError("window size must be positive")
    return {image[i : i + size] for i in range(len(image) - size + 1)}


def covered_bytes(data: bytes, runs: set[bytes], window: int) -> int:
    """Union of complete matching window spans, counted once per byte."""
    if window < 1:
        raise ValueError("window size must be positive")
    covered = end = 0
    for i in range(len(data) - window + 1):
        if data[i : i + window] in runs:
            next_end = i + window
            covered += next_end - max(i, end)
            end = next_end
    return covered


def byte_score(a: NeImage, b: NeImage, window: int = 32) -> tuple[int, int]:
    """Matched content anywhere in the rebuild; this is not file or source equality."""
    return covered_bytes(a.data, block_set(b.data, window), window), len(a.data)


def _segment_budget(a: NeImage, runs: set[bytes], window: int) -> list[tuple[int, int, int]]:
    rows = [
        (i, len(a.seg_bytes(i)), covered_bytes(a.seg_bytes(i), runs, window))
        for i in range(a.seg_count)
    ]
    last = max((off + length for off, length, _ in a.segments), default=0)
    tail = a.data[last:]
    rows.append((-1, len(tail), covered_bytes(tail, runs, window)))
    return rows


def comparison_content(
    a: NeImage, b: NeImage, window: int = 32
) -> tuple[int, int, list[tuple[int, int, int]]]:
    """Whole-file and segment overlap against the same rebuilt windows."""
    runs = block_set(b.data, window)
    return covered_bytes(a.data, runs, window), len(a.data), _segment_budget(a, runs, window)


def relocation_census(ne: NeImage) -> tuple[collections.Counter[int], collections.Counter[int]]:
    """Histograms of declared fixup address and relocation types."""
    records = [fixup for i in range(ne.seg_count) for fixup in ne.fixups(i)]
    return (
        collections.Counter(f.address_type for f in records),
        collections.Counter(f.relocation_type for f in records),
    )
