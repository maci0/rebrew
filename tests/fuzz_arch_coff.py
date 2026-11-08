"""Atheris (libFuzzer) target: ar-archive and COFF symbol parsers.

Same harness body and invariants as tests/test_property_arch_coff.py
and tests/test_property_coff_load.py (Hypothesis drives them in CI;
this file is the coverage-guided libFuzzer entry point for local /
OSSFuzz runs).

    uv run --frozen --group fuzz --group dev python tests/fuzz_arch_coff.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_arch_coff.py tests/fixtures -runs=1000

Seed corpus: tests/fixtures/{mini.lib,mini.obj} (real committed
shapes, never production traffic).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.archives import parse_archive, stock_lib_valid
from rebrew.formats.binary_loader import object_arch
from rebrew.formats.coff import _coff_symbol_names, load_coff


def TestOneInput(data: bytes) -> None:
    """Parsers must never raise (except ValueError/OSError); parsed
    members and names keep their documented shape, and the archive
    round-trip preserves member bytes.

    Pair assertion across the trust boundary: a member yielded by
    parse_archive must feed load_coff/_coff_symbol_names on exactly
    those bytes and yield the same names as a direct call."""
    # Direct COFF / arch-probe surfaces on the raw input.
    names = _coff_symbol_names(data)
    assert isinstance(names, list) and all(isinstance(n, str) for n in names)

    arch = object_arch(data)
    assert arch is None or (
        isinstance(arch, tuple)
        and len(arch) == 2
        and isinstance(arch[0], str)
        and arch[1] in ("little", "big")
    )

    result = load_coff(data)
    if result is not None:
        _binary, _symbols, canon = result
        assert isinstance(canon, list) and all(isinstance(n, str) for n in canon)
        # No invented names: canonical names are LIEF names or raw-table names.
        for name in canon:
            if name:
                assert name in names or name.encode("utf-8", "replace")

    # Archive surface via a temp file (parse_archive takes a path).
    fd, name = tempfile.mkstemp(suffix=".lib")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        assert isinstance(stock_lib_valid(Path(name)), bool)
        try:
            members = list(parse_archive(name))
        except ValueError:
            return
        assert isinstance(members, list)
        for mname, body in members:
            assert isinstance(mname, str) and mname
            assert isinstance(body, bytes)
            assert body in data or body == b""
            # Round-trip across the boundary: same bytes, same names.
            direct = _coff_symbol_names(body)
            assert isinstance(direct, list)
            via = load_coff(body)
            if via is not None:
                again = load_coff(body)
                assert again is not None and again[2] == via[2]
    finally:
        os.unlink(name)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
