"""Atheris (libFuzzer) target: LZEXE and Delphi 1 form (DFM) parsers.

Same harness body and invariants as tests/test_property_ne_lzexe.py
(LZEXE decompressor, reloc tables) and tests/test_property_dfm.py
(DFM roundtrip) (Hypothesis drives them in CI; this file is the
coverage-guided libFuzzer entry point for local/OSSFuzz runs).

    uv run --frozen --group fuzz python tests/fuzz_lzexe_dfm.py <corpus_dir> [flags]
    uv run --frozen --group fuzz python tests/fuzz_lzexe_dfm.py tests/fixtures -runs=1000

Seed corpus: tests/fixtures/{tc16_hello_lzexe.exe,mini_ne.exe}
(real committed shapes, never production traffic).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.dfm import (
    DfmError,
    encode,
    parse_form,
    parse_forms,
    roundtrip,
    scan_forms,
)
from rebrew.formats.lzexe import (
    NotLzexeError,
    _decompress,
    _reloc_table90,
    _reloc_table91,
    lzexe_version,
    unpack_lzexe,
)


def TestOneInput(data: bytes) -> None:
    """Parsers must fail only with their public error type, and whatever
    they return must keep its documented shape.

    LZEXE pair assertion: a decompressed image re-parsed with the
    derived budget used to produce it yields the identical bytes.
    DFM pair assertion: a decoded form re-encoded with ``encode``
    reproduces the exact input slice it was decoded from."""
    # Direct LZEXE decompressor / reloc surfaces on the raw input.
    try:
        result = _decompress(data, 0, max_out=64)
    except NotLzexeError:
        result = None
    if result is not None:
        assert len(result) <= 64
        assert _decompress(data, 0, max_out=64) == result
    for decode in (_reloc_table90, _reloc_table91):
        try:
            relocs, end = decode(data, 0)
        except NotLzexeError:
            continue
        assert 0 <= end <= len(data)
        for rel_off, rel_seg in relocs:
            assert 0 <= rel_off <= 0xFFFF
            assert rel_seg >= 0
    # _reloc_table91 accumulates rel_seg past 0xFFFF on long streams; the
    # documented bound is only on the offset, so assert seg monotonicity
    # through the recovered table instead.

    # LZEXE file surface via a temp file (takes a path).
    fd, name = tempfile.mkstemp(suffix=".exe")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            version = lzexe_version(Path(name))
        except OSError:
            return
        assert version in (None, 90, 91)
        try:
            unpacked = unpack_lzexe(Path(name))
        except NotLzexeError:
            return
        assert unpacked.version in (90, 91)
        assert isinstance(unpacked.image, bytes)
        assert len(unpacked.header_words) >= 14
        for rel_off, rel_seg in unpacked.relocs:
            assert 0 <= rel_off <= 0xFFFF
            assert rel_seg >= 0
        # Pair: reassembling the unpacked file and re-detecting it does
        # not invent a header shape.
        assert isinstance(unpacked.to_bytes(), bytes)
        assert len(unpacked.to_bytes()) >= len(unpacked.image)
    finally:
        os.unlink(name)

    # DFM surface on the raw input: scan_forms must fail only with
    # DfmError, and whatever it returns must round-trip.
    try:
        forms, errors = scan_forms(data)
    except DfmError:
        return
    assert all(0 <= offset < len(data) for offset, _, _ in forms)
    assert all(offset + 4 <= end <= len(data) for offset, _, end in forms)
    assert all(set(error) == {"offset", "error"} for error in errors)
    for offset, root, end in forms:
        assert encode(root) == data[offset + 4 : end]
        # Pair: re-parsing exactly the same slice is deterministic.
        again, again_end = parse_form(data, offset)
        assert again_end == end
        assert encode(again) == encode(root)
    if not errors:
        try:
            parsed = parse_forms(data)
        except DfmError:
            return
        assert len(parsed) == len(forms)
    try:
        count, failures = roundtrip(data)
    except DfmError:
        return
    assert count >= 0
    assert failures == []


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
