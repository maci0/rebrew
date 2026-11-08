"""Atheris (libFuzzer) target: matcher object-symbol dispatch.

Same harness body and invariants as tests/test_property_obj_symbol.py
(Hypothesis drives it in CI; this file is the coverage-guided libFuzzer
entry point for local/OSSFuzz runs).

    uv run --frozen python tests/fuzz_obj_symbol.py <corpus_dir> [flags]
    uv run --frozen python tests/fuzz_obj_symbol.py tests/fixtures -runs=1000

Seed corpus: tests/fixtures/{mini.obj,thumb_arm.o,tg_msvc16.obj,tg_watcom.o}.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.matcher.parsers import list_obj_symbols, parse_obj_symbol_bytes

_SYMBOL = "_func1"


def TestOneInput(data: bytes) -> None:
    """Dispatch must never raise (except OSError/ValueError); returned
    pairs keep their documented shape."""
    fd, name = tempfile.mkstemp(suffix=".obj")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            code, relocs = parse_obj_symbol_bytes(name, _SYMBOL)
        except OSError, ValueError:
            return
        if code is None:
            assert relocs is None
        else:
            assert isinstance(code, bytes)
            assert relocs is None or isinstance(relocs, dict)
            if relocs:
                for off, rname in relocs.items():
                    assert isinstance(off, int) and 0 <= off < len(code)
                    assert isinstance(rname, str)
            assert len(code) <= len(data)
            if code:
                assert code in data or code.rstrip(b"\x00\xcc\x90") in data
        try:
            syms = list_obj_symbols(name)
        except OSError, ValueError:
            return
        assert isinstance(syms, list) and all(isinstance(s, str) for s in syms)
        if code is not None:
            assert any(s.lstrip("_") == "func1" for s in syms)
    finally:
        os.unlink(name)


if __name__ == "__main__":
    atheris.Setup(TestOneInput)
    atheris.Fuzz()
