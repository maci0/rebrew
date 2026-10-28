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
    source_offset: int
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
        self.modrefs = header.module_reference_count
        self.flags = header.flags
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
            NeFixup(*struct.unpack_from("<BBHHH", self.data, start + 2 + i * 8))
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


def segment_budget(a: NeImage, b: NeImage, window: int = 32) -> list[tuple[int, int, int]]:
    """Physical segment and trailing-region content overlap, without source claims."""
    return _segment_budget(a, block_set(b.data, window), window)


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


def unit_census(path: Path, index: int) -> tuple[dict[int, int], int, int]:
    """Address types, zero-selector internal far fixups, and internal fixup records."""
    ne = NeImage(path)
    records = ne.fixups(index)
    internal = [f for f in records if f.relocation_type & 3 == 0]
    raw = ne.seg_bytes(index)
    zeroed = 0
    for record in internal:
        if record.address_type == 3:
            if record.source_offset + 4 > len(raw):
                raise NeParseError("far fixup source extends beyond its segment")
            zeroed += struct.unpack_from("<H", raw, record.source_offset + 2)[0] == 0
    return (
        dict(sorted(collections.Counter(f.address_type for f in records).items())),
        zeroed,
        len(internal),
    )


def segment_refs(ne: NeImage) -> tuple[dict[int, set[int]], dict[int, int]]:
    """Internal segment edges and imported fixup counts (OS fixups excluded)."""
    refs: dict[int, set[int]] = {}
    imports: dict[int, int] = {}
    for index, segment in enumerate(ne.segment_records):
        if not segment.flags & 0x0100:
            continue
        records = ne.fixups(index)
        refs[index] = {
            f.target - 1
            for f in records
            if f.relocation_type & 3 == 0 and 1 <= f.target <= ne.seg_count
        }
        imports[index] = sum(f.relocation_type & 3 in (1, 2) for f in records)
    return refs, imports


def run_sets(ne: NeImage, block: int = 32) -> list[set[bytes]]:
    """Build each segment's overlapping windows once."""
    return [block_set(ne.seg_bytes(i), block) for i in range(ne.seg_count)]


def best_match(runs: set[bytes], rebuilt_runs: list[set[bytes]]) -> tuple[int, float]:
    """Best segment by shared distinct windows; ties retain the earlier index."""
    best, score = -1, 0
    for i, other in enumerate(rebuilt_runs):
        shared = len(runs & other)
        if shared > score:
            best, score = i, shared
    return best, 100.0 * score / len(runs) if runs else 0.0


def published_method_candidates(
    data: bytes,
    class_name: str,
    *,
    source_segment: int = 0,
    fixups: dict[tuple[int, int], tuple[int, int]] | None = None,
) -> list[tuple[str, int]]:
    """Decode a complete Delphi 1 same-segment published-method table candidate.

    Segment indices in fixups are zero-based. The key is (source segment,
    pointer site), and the value is (target segment, offset). Cross-segment
    pointers cannot be represented by this offset-only API. Invalid/truncated
    candidates are skipped; no partial table is returned. This string-marker
    probe is structural evidence, not proof that the class owns a procedure.
    """
    name_bytes = class_name.encode("latin1")
    if not 0 < len(name_bytes) <= 255:
        raise ValueError("class name must fit a Delphi short string")
    marker = bytes([len(name_bytes)]) + name_bytes
    start = 0
    while True:
        at = data.find(marker, start)
        if at < 0:
            return []
        start = at + 1
        pos = at + len(marker)
        if pos + 2 > len(data):
            continue
        count = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        # Bound speculative class-marker probes before accepting a complete table.
        if not 0 < count <= 64:
            continue
        methods = []
        for _ in range(count):
            if pos + 5 > len(data):
                break
            site = pos
            pointer = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            size = data[pos]
            if not 0 < size <= 64 or pos + 1 + size > len(data):
                break
            name = data[pos + 1 : pos + 1 + size].decode("latin1")
            if not name.replace("_", "").isalnum():
                break
            offset = pointer & 0xFFFF
            if fixups and (source_segment, site) in fixups:
                target_segment, offset = fixups[(source_segment, site)]
                if target_segment != source_segment:
                    break
            if offset >= len(data):
                break
            methods.append((name, offset))
            pos += 1 + size
        else:
            return methods
