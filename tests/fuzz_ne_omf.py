"""Atheris (libFuzzer) target: NE and 16-bit OMF parsers.

Same harness body and invariants as tests/test_property_ne_lzexe.py
(NE tables) and tests/test_property_omf16.py (OMF records), which
Hypothesis drives in CI; this file is the coverage-guided libFuzzer
entry point for local/OSSFuzz runs.

    uv run --frozen --group fuzz python tests/fuzz_ne_omf.py <corpus_dir> [flags]
    uv run --frozen --group fuzz python tests/fuzz_ne_omf.py tests/fixtures -runs=1000

Seed corpus: tests/fixtures/{mini_ne.exe,tg_msvc16.obj,tg_msvc16_o1.obj,
tg_msvc16_far.obj} (real committed shapes, never production traffic).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.ne_loader import (
    NeParseError,
    parse_exports,
    parse_imports,
    parse_ne_header,
    parse_segments,
    read_ne_header,
    segment_file_ranges,
)
from rebrew.formats.omf16 import Omf16Error, is_omf16, parse_omf16


def TestOneInput(data: bytes) -> None:
    """Both parsers must fail only with their public error type, and
    whatever they return must keep its documented shape.

    NE cross-check (pair assertion): every segment range reported by
    segment_file_ranges must lie inside the input, and the segment table
    re-parsed from the header read_ne_header recovered must match the
    table parsed directly from the same bytes."""
    # NE surface on the raw input.
    try:
        ne_offset, header = read_ne_header(data)
    except NeParseError:
        ne_offset, header = None, None
    if header is not None:
        assert ne_offset is not None and 0 <= ne_offset < len(data)
        assert 0 <= header.alignment_shift <= 16
        assert header.sector_size == 1 << header.alignment_shift
        try:
            segments = parse_segments(data, ne_offset, header)
        except NeParseError:
            segments = None
        if segments is not None:
            assert len(segments) == header.segment_count
            for i, seg in enumerate(segments):
                assert seg.index == i + 1
                assert seg.file_offset >= 0
                assert seg.min_allocation > 0
                if not seg.on_disk:
                    assert seg.file_offset == 0 and seg.length == 0
            # Pair: the header re-read from the same bytes yields the
            # same segment table.
            again = parse_segments(data, *read_ne_header(data))
            assert [(s.index, s.file_offset, s.length) for s in again] == [
                (s.index, s.file_offset, s.length) for s in segments
            ]
            ranges = segment_file_ranges(data)
            for start, end in ranges:
                assert 0 <= start <= end <= len(data)
        try:
            modules = parse_imports(data, ne_offset, header)
        except NeParseError:
            modules = []
        for mod in modules:
            assert isinstance(mod.module, str)
            assert isinstance(mod.imports, list)
            for imp in mod.imports:
                assert imp.name is not None or 0 <= imp.ordinal <= 0xFFFF
        try:
            exports = parse_exports(data, ne_offset, header)
        except NeParseError:
            exports = []
        for exp in exports:
            assert isinstance(exp.name, str)
            assert 0 <= exp.ordinal <= 0xFFFF
        # The direct header entry point agrees with read_ne_header.
        direct = parse_ne_header(data, ne_offset)
        assert direct.segment_count == header.segment_count

    # OMF surface on the raw input: is_omf16 and parse_omf16 must agree,
    # and a decoded module's code must end with its own code records.
    try:
        mod = parse_omf16(data)
    except Omf16Error:
        mod = None
    assert (mod is not None) == is_omf16(data)
    if mod is not None:
        assert all(isinstance(n, str) and n.isascii() for n in mod.names)
        assert all(0 <= off <= 0xFFFF for off in mod.publics.values())
        assert mod.code.endswith(b"".join(mod.code_records))
        # Pair: re-parsing exactly the same bytes is deterministic.
        again = parse_omf16(data)
        assert again.code == mod.code and again.publics == mod.publics
        assert again.names == mod.names and again.code_records == mod.code_records


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
