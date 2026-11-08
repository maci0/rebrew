"""Property-based fuzz tests for the matcher object-symbol dispatch.

``matcher.parsers.parse_obj_symbol_bytes`` / ``list_obj_symbols`` are the
highest-risk untrusted-input surface with no prior fuzz harness: they sniff
magic bytes (COFF / ELF / Mach-O / OMF) and hand the file to LIEF.  Every
sibling parser already had a Hypothesis harness (OMF, DFM, NE, LZEXE, PE,
archives) — this dispatcher had none.  The harness below is also the
libFuzzer/Atheris target body (see ``tests/fuzz_obj_symbol.py``): when Atheris
is installed it drives the same ``_run`` over mutated inputs with native
coverage guidance; Hypothesis drives it here in CI.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.matcher.parsers import list_obj_symbols, parse_obj_symbol_bytes

FIXTURES = Path(__file__).parent / "fixtures"
_SEEDS = ("mini.obj", "thumb_arm.o", "tg_msvc16.obj", "tg_watcom.o")
_SYMBOL = "_func1"

# Structured magic prefixes the dispatcher branches on.
_MAGICS = (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\x4c\x01\x00\x00", b"\x80\x04\x00\x00")


@st.composite
def _obj_like(draw: st.DrawFn) -> bytes:
    """A valid magic prefix + raw payload, occasionally truncated."""
    magic = draw(st.sampled_from(_MAGICS + (b"",)))
    body = draw(st.binary(max_size=256, min_size=0))
    data = magic + body
    if draw(st.booleans()) and data:
        cut = draw(st.integers(0, len(data)))
        data = data[:cut]
    return data


@settings(max_examples=60, deadline=None)
@given(_obj_like())
def test_obj_dispatch_never_crashes(data: bytes) -> None:
    """Raw/mutated object bytes must never make the dispatch raise (except
    OSError/ValueError, which callers already handle), and any returned
    pair must keep its documented shape."""
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
        assert isinstance(syms, list)
        assert all(isinstance(s, str) for s in syms)
        if code is not None:
            assert any(s.lstrip("_") == "func1" for s in syms)
    finally:
        os.unlink(name)


@settings(max_examples=20, deadline=None)
@given(st.sampled_from(_SEEDS), st.integers(0, 63), st.integers(0, 255))
def test_mutated_fixture_never_crashes(seed_name: str, pos: int, xor: int) -> None:
    """Single-byte mutations of real committed fixtures (the shapes parsers
    actually encounter) must keep the same contract."""
    data = bytearray((FIXTURES / seed_name).read_bytes())
    if not data:
        return
    data[pos % len(data)] ^= xor or 1
    fd, name = tempfile.mkstemp(suffix=".obj")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(bytes(data))
        try:
            code, relocs = parse_obj_symbol_bytes(name, _SYMBOL)
        except OSError, ValueError:
            return
        if code is None:
            assert relocs is None
            return
        assert isinstance(code, bytes)
        assert relocs is None or isinstance(relocs, dict)
        if relocs:
            for off, rname in relocs.items():
                assert isinstance(off, int) and 0 <= off < len(code)
                assert isinstance(rname, str)
        try:
            syms = list_obj_symbols(name)
        except OSError, ValueError:
            return
        assert all(isinstance(s, str) for s in syms)
    finally:
        os.unlink(name)


@settings(max_examples=10, deadline=None)
@given(st.sampled_from([s for s in _SEEDS if (FIXTURES / s).exists()]))
def test_real_fixture_roundtrip(seed_name: str) -> None:
    """The unmutated seeds resolve to known code (anchors the harness: a
    dispatch that always returns (None, None) must fail here)."""
    path = str(FIXTURES / seed_name)
    code, relocs = parse_obj_symbol_bytes(
        path, _SYMBOL if seed_name == "mini.obj" else "thumb_probe"
    )
    if seed_name == "mini.obj":
        assert code is not None
        assert code in (FIXTURES / "mini.obj").read_bytes()
        assert relocs == {5: "_extern_var"}
        assert "_func1" in list_obj_symbols(path)
    else:
        # Remaining seeds may be unsupported by the dispatcher; the
        # invariant is only that the call returns a well-formed pair.
        assert code is None or isinstance(code, bytes)
        assert relocs is None or isinstance(relocs, dict)


def test_seed_corpus_present() -> None:
    for name in _SEEDS:
        assert (FIXTURES / name).is_file(), f"seed corpus missing tests/fixtures/{name}"
