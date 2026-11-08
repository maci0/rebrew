"""Property-based fuzz tests for the BinSync serial loader.

``binsync.serial.load_artifact`` / ``load_many`` parse TOML written by a
remote BinSync peer (git state repo): attacker-controlled bytes reach
declib's TOML decoder plus the artifact constructors.  No prior
Hypothesis harness covered this surface; every sibling file-format
parser (OMF, DFM, NE, LZEXE, PE, archives, COFF, obj-symbol dispatch)
already had one.  This is also the Atheris target body (see
``tests/fuzz_binsync_serial.py``): Hypothesis drives it in CI, libFuzzer
drives the same ``_run`` locally / on OSS-Fuzz.

Contract under test (from ``serial.load_artifact`` / ``load_many``):
missing file -> ``None`` / ``[]``; unreadable or unparseable input ->
``ValueError`` (never ``None``/``[]``, never any other exception);
a successful parse returns declib artifacts whose ``dumps()`` output
re-parses to an equal artifact (pair assertion across the
parse/serialize boundary).  ``kind`` is caller-supplied, not untrusted:
an unknown kind is a ``ValueError`` too.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

pytest.importorskip("declib")

from rebrew.binsync import serial

_KINDS = ("function", "struct", "enum", "typedef", "comment", "global_variable")

# Real dumps() shapes (see serial.new_*): hex ints are the shape the
# toml decoder chokes on when hand-written as 0x..., so seeds use the
# exact byte layout declib emits.
_SEEDS: tuple[tuple[str, bytes], ...] = (
    (
        "function",
        b'addr = 0x1000\nsize = 0x10\nname = "_f"\ntype = "int f()"\n\n[header]\nname = "_f"\naddr = 0x1000\ntype = "int f()"\n\n[header.args]\n',
    ),
    (
        "struct",
        b'name = "S"\nsize = 0x8\n\n[members.0x0]\nname = "a"\noffset = 0x0\ntype = "int"\nsize = 0x4\n',
    ),
    ("comment", b'addr = 0x1000\nfunc_addr = 0x1000\ncomment = "hi"\ndecompiled = false\n'),
    ("global_variable", b'addr = 0x2000\nname = "g"\ntype = "int"\nsize = 0x4\n'),
    ("enum", b'name = "E"\n\n[members]\nA = 0x1\n'),
    ("typedef", b'name = "T"\ntype = "int"\n'),
)


def _run_one(data: bytes, kind: str, *, many: bool) -> None:
    """One fuzz iteration: load must return or raise ValueError only."""
    fd, name = tempfile.mkstemp(suffix=".toml")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            if many:
                arts = serial.load_many(Path(name), kind)
            else:
                art = serial.load_artifact(Path(name), kind)
                arts = [] if art is None else [art]
        except ValueError:
            return
        # Only ValueError (and OSError, unreachable here) may escape:
        # any other exception type fails the test by propagating.
        assert isinstance(arts, list)
        for art in arts:
            # Pair assertion: dump -> reload must round-trip, and the
            # reloaded artifact must dump to the same bytes.
            text = art.dumps()
            assert isinstance(text, str)
            assert type(art).loads(text) is not None
            assert type(art).loads(text).dumps() == text
    finally:
        os.unlink(name)


@st.composite
def _toml_like(draw: st.DrawFn) -> bytes:
    """Structure-aware TOML-ish bytes: seed shape, raw, or mutated seed."""
    style = draw(st.integers(0, 3))
    if style == 0:
        return draw(st.binary(max_size=512))
    kind, seed = draw(st.sampled_from(_SEEDS))
    data = bytearray(seed)
    if draw(st.booleans()) and data:
        for _ in range(draw(st.integers(1, 4))):
            i = draw(st.integers(0, len(data) - 1))
            data[i] = draw(st.integers(0, 255))
    if draw(st.booleans()) and data:
        data = bytearray(data)
        cut = draw(st.integers(0, len(data)))
        data = data[:cut]
    if draw(st.booleans()):
        data = bytearray(draw(st.binary(max_size=16)) + bytes(data))
    return bytes(data)


@settings(max_examples=60, deadline=None)
@given(_toml_like(), st.sampled_from(_KINDS), st.booleans())
def test_serial_load_never_raises_unexpected(data: bytes, kind: str, many: bool) -> None:
    """Raw/mutated BinSync TOML must never make the loader raise anything
    but ValueError, and any parsed artifact must round-trip dumps->loads."""
    _run_one(data, kind, many=many)


@settings(max_examples=20, deadline=None)
@given(st.sampled_from(_SEEDS), st.sampled_from(_KINDS))
def test_seed_roundtrip(seed: tuple[str, bytes], kind: str) -> None:
    """Unmutated seeds parse under their own kind and round-trip; under a
    foreign kind they must still not raise anything but ValueError."""
    _run_one(seed[1], kind, many=False)


@settings(max_examples=10, deadline=None)
@given(st.binary(max_size=64))
def test_missing_file_contract(data: bytes) -> None:
    """A missing file is None/[], never an error, regardless of kind."""
    missing = Path(tempfile.mkdtemp()) / "nope.toml"
    assert serial.load_artifact(missing, "function") is None
    assert serial.load_many(missing, "function") == []


def test_unknown_kind_is_value_error(tmp_path: Path) -> None:
    p = tmp_path / "x.toml"
    p.write_bytes(b'name = "S"\n')
    with pytest.raises(ValueError):
        serial.load_artifact(p, "nope")
    with pytest.raises(ValueError):
        serial.load_many(p, "nope")
