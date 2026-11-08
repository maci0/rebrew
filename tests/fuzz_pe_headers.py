"""Atheris (libFuzzer) target: PE header + PE image parsers.

Same harness body and invariants as tests/test_property_pe_headers.py and
tests/test_property_pe_image.py (Hypothesis drives them in CI; this file
is the coverage-guided libFuzzer entry point for local/OSSFuzz runs).

    uv run --frozen --group fuzz --group dev python tests/fuzz_pe_headers.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_pe_headers.py tests/fixtures/mini_pe.exe -runs=1000

Seed corpus: tests/fixtures/mini_pe.exe (real committed shape, never
production traffic).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.pe_headers import (
    SECTION_ENTRY_SIZE,
    header_parity,
    patch_pe_headers,
    pe_image_base,
    pe_layout,
    pe_lfanew,
    read_pe_header_fields,
    sections_at,
)
from rebrew.formats.pe_image import parse_pe

_MAX_PARSED_ENTRIES = 65536
# Patch/re-read fields probing the mask: a field patched to all-ones and read
# back yields its width, so PE32 and PE32+ stay distinguished without
# hard-coding the table.
_PROBE_FIELDS = ("timestamp", "stack_reserve", "heap_commit")


def TestOneInput(data: bytes) -> None:
    """Every entry point must never raise (except ValueError from parse_pe);
    whatever it returns must keep its documented shape.

    Pair assertions across the trust boundary: a section offset reported
    by pe_layout must be where sections_at reads it back, a header
    patched then read back must yield the written value masked to the
    field width, and patching twice is a no-op."""
    lfanew = pe_lfanew(data)
    layout = pe_layout(data)
    if layout is not None:
        assert lfanew == layout.e_lfanew
        assert layout.section_table_offset == (
            layout.e_lfanew + 0x18 + layout.size_of_optional_header
        )
        assert layout.magic is None or 0 <= layout.magic <= 0xFFFF
        assert len(layout.sections) <= layout.number_of_sections
        for index, section in enumerate(layout.sections):
            assert section.header_offset == layout.section_table_offset + SECTION_ENTRY_SIZE * index
            assert section.header_offset + SECTION_ENTRY_SIZE <= len(data)
            assert len(section.name) <= 8
            assert 0 <= section.virtual_size <= 0xFFFFFFFF
            assert section.pointer_to_raw_data <= 0xFFFFFFFF
        # Pair: sections_at re-read from the layout offset matches.
        again = sections_at(data, layout.section_table_offset, layout.number_of_sections)
        assert len(again) == len(layout.sections)
        for a, b in zip(again, layout.sections, strict=True):
            assert a == b
        base = pe_image_base(data)
        assert base is None or 0 <= base < (1 << 64)
        # Pair: patch a field to all ones, read it back masked, re-patch.
        for label in _PROBE_FIELDS:
            fields = read_pe_header_fields(patch_pe_headers(data, {label: (1 << 64) - 1}))
            if fields is None or label not in fields:
                continue
            mask = fields[label]
            patched_once = patch_pe_headers(data, {label: mask})
            read_back = read_pe_header_fields(patched_once)
            assert read_back is not None and read_back[label] == mask
            assert patch_pe_headers(patched_once, {label: mask}) == patched_once
            break
    else:
        assert lfanew is None or lfanew + 0x18 > len(data)
        assert patch_pe_headers(data, {"timestamp": 1}) == data
    values = read_pe_header_fields(data)
    if values is not None:
        assert all(isinstance(v, int) and 0 <= v < (1 << 64) for v in values.values())
    for row in header_parity(data, data):
        assert set(row) == {"field", "original", "reasm", "match", "configured"}
        assert row["match"] is (row["original"] == row["reasm"])

    # parse_pe: strict sibling; ValueError is the only rejection.
    try:
        sections, exports, imports, pe = parse_pe(data)
    except ValueError:
        return
    assert pe["header_size"] <= len(data)
    assert data[pe["e_lfanew"] : pe["e_lfanew"] + 4] == b"PE\x00\x00"
    for section in sections:
        assert section.raw_ptr + section.raw_size >= section.raw_ptr
        assert isinstance(section.name, str)
    for export in exports:
        assert isinstance(export["ordinal"], int)
        assert isinstance(export["va"], int)
        assert export["name"] is None or isinstance(export["name"], str)
    for imp in imports:
        assert isinstance(imp.dll, str) and imp.dll
        assert imp.name is None or isinstance(imp.name, str)
        assert imp.ordinal is None or 0 <= imp.ordinal <= 0xFFFF
        assert (imp.name is None) != (imp.ordinal is None)
    assert len(exports) <= _MAX_PARSED_ENTRIES
    assert len(imports) <= _MAX_PARSED_ENTRIES * _MAX_PARSED_ENTRIES
    assert pe["reloc_va"] is None or isinstance(pe["reloc_va"], int)
    # Pair: determinism on exactly the same bytes.
    assert parse_pe(data) == (sections, exports, imports, pe)

    # Same parsers behind a file-path surface, as the CLI drives them.
    fd, name = tempfile.mkstemp(suffix=".exe")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        assert pe_layout(Path(name).read_bytes()) == layout
    finally:
        os.unlink(name)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
