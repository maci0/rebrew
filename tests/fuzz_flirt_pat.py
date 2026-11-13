"""Atheris (libFuzzer) target: FLIRT .pat generation from COFF/ELF objects.

Same harness body and invariants as tests/test_gen_flirt_pat.py and
tests/test_property_parsers.py (Hypothesis drives them in CI; this file
is the coverage-guided libFuzzer entry point for local/OSSFuzz runs).

    uv run --frozen --group fuzz --group dev python tests/fuzz_flirt_pat.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_flirt_pat.py tests/fixtures/mini.obj -runs=1000

Seed corpus: tests/fixtures/{mini.obj,mini.lib,thumb_arm.o,tg_watcom.o}
(real committed shapes, never production traffic).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.archives import parse_archive
from rebrew.formats.coff import _coff_symbol_names, load_coff
from rebrew.gen_flirt_pat import (
    _crc16_flirt,
    _reloc_span,
    bytes_to_pat_line,
    is_weak_signature,
    parse_coff_aliases,
    parse_coff_obj,
    parse_elf_obj,
)

_MAX_RESULTS = 65536


def _assert_obj_results(data: bytes, results: list[tuple[str, bytes, set[int]]]) -> None:
    """Each (name, code, relocs) triple keeps its documented shape and
    its reloc offsets point inside the code it masks (pair assertion
    across the trust boundary: the offsets the writer masks are exactly
    the bytes it reads back)."""
    assert isinstance(results, list) and len(results) <= _MAX_RESULTS
    for name, code, relocs in results:
        assert isinstance(name, str) and name
        assert isinstance(code, bytes) and len(code) >= 4
        assert isinstance(relocs, set)
        assert all(isinstance(r, int) and 0 <= r < len(code) for r in relocs)
        line = bytes_to_pat_line(name, code, relocs)
        parts = line.split()
        assert parts[-1] == name and parts[-2] == ":0000"
        lead = parts[0]
        lead_len = min(len(code), 32)
        assert len(lead) == 2 * lead_len
        for i in range(lead_len):
            pair = lead[2 * i : 2 * i + 2]
            if i in relocs:
                assert pair == ".."
            else:
                assert int(pair, 16) == code[i]
        assert int(parts[3], 16) == len(code)
        # Determinism on exactly the same bytes.
        assert bytes_to_pat_line(name, code, relocs) == line
        assert isinstance(is_weak_signature(line), bool)


def TestOneInput(data: bytes) -> None:
    """Object/archive parsers must never raise (except documented
    ValueError/OSError/struct.error and LIEF's own rejections); whatever
    they return must keep its documented shape.

    _reloc_span / _reloc_fixup_width never return an unbounded width:
    a bogus LIEF bit-size yields a clamped 1..8 span, and an unknown
    COFF type falls back to a positive width.  _crc16_flirt stays in
    domain and is deterministic.
    """
    assert 1 <= _reloc_span(0) <= 8
    assert _reloc_span(2**64 - 1) <= 8
    assert 0 <= _crc16_flirt(data) <= 0xFFFF
    assert _crc16_flirt(data) == _crc16_flirt(data)

    loaded = load_coff(data)
    if loaded is not None:
        _binary, symbols, names = loaded
        assert len(symbols) == len(names)
        raw = _coff_symbol_names(data)
        assert isinstance(raw, list) and all(isinstance(n, str) for n in raw)
        for sym, name in zip(symbols, names, strict=True):
            assert isinstance(name, str)
            assert name or str(sym.name)

    _assert_obj_results(data, list(parse_coff_obj(data)))
    aliases = list(parse_coff_aliases(data))
    assert isinstance(aliases, list)
    for alias, target in aliases:
        assert isinstance(alias, str) and alias
        assert isinstance(target, str) and target
    _assert_obj_results(data, list(parse_elf_obj(data)))

    # Archive surface via a temp file (parse_archive takes a path).
    fd, name = tempfile.mkstemp(suffix=".lib")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            members = list(parse_archive(name))
        except ValueError:
            return
        assert isinstance(members, list) and len(members) <= _MAX_RESULTS
        for mname, body in members:
            assert isinstance(mname, str) and mname
            assert isinstance(body, bytes) and (body in data or body == b"")
            # Round-trip across the boundary: same bytes, same names.
            _assert_obj_results(body, list(parse_coff_obj(body)))
    finally:
        os.unlink(name)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
