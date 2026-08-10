"""tests/test_pak_extract.py — Quantum .PAK decoder robustness + validity.

``tools/DELPHI10/pak_extract.py`` is the from-scratch Quantum archive decoder
(arithmetic-coded LZ77) that unpacks the Borland Delphi 1.0 installer
archives.  These tests pin two contracts:

1. Valid archives decode correctly (header, file list, decompressed bytes).
2. Malformed/truncated/random archives raise a clean ``ValueError`` — never
   crash with ``IndexError``/``struct.error`` (fuzz regression: 67/200
   header mutations used to crash before the bounds checks were added).

The fixtures are the MIT-licensed reference archives from the `unquantum`
project (Quantum 0.97, 1 and 3 files).
"""

from __future__ import annotations

import random
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tools.DELPHI10.pak_extract import parse_archive, quantum_decompress

FIXTURES = Path(__file__).parent / "fixtures"


class TestValidArchive:
    def test_multi_header_and_files(self) -> None:
        """test_multi.q: 3 files with known names/sizes, table size 10."""
        data = (FIXTURES / "test_multi.q").read_bytes()
        header, files, stream_off = parse_archive(data)
        major, minor, num_files, table_size, flags = header
        assert (major, minor) == (0, 0x61)  # 0.97
        assert num_files == 3
        assert table_size == 10
        assert [(f["name"], f["size"]) for f in files] == [
            ("TEST1.TXT", 56),
            ("TEST2.TXT", 37),
            ("TEST3.TXT", 451),
        ]
        assert stream_off < len(data)

    def test_multi_decompresses_to_declared_sizes(self) -> None:
        data = (FIXTURES / "test_multi.q").read_bytes()
        header, files, stream_off = parse_archive(data)
        out = quantum_decompress(data[stream_off:], [int(f["size"]) for f in files], header[3])
        assert len(out) == 56 + 37 + 451
        assert out[:13] == b"Hello, World!"  # TEST1.TXT content

    def test_single_archive(self) -> None:
        data = (FIXTURES / "test_single.q").read_bytes()
        header, files, stream_off = parse_archive(data)
        assert len(files) == 1
        assert files[0]["name"] == "TEST1.TXT"
        out = quantum_decompress(data[stream_off:], [56], header[3])
        assert len(out) == 56


class TestMalformedInputs:
    @pytest.mark.parametrize(
        "blob",
        [
            b"",
            b"DS",
            b"XX" + b"\x00" * 20,
            b"DS\x00\x5a\x10\x00",  # truncated before the full header
            b"DS\x00\x5a" + b"\xff\xff" + b"\x12\x03" + b"name" + b"\x00" * 20,  # huge nfiles
            bytes(random.Random(1).randrange(256) for _ in range(64)),
            bytes(random.Random(2).randrange(256) for _ in range(512)),
        ],
        ids=[
            "empty",
            "short",
            "bad_magic",
            "truncated_header",
            "huge_nfiles",
            "random_64",
            "random_512",
        ],
    )
    def test_raises_valueerror(self, blob: bytes) -> None:
        """Malformed archives must fail with ValueError, not crash."""
        with pytest.raises(ValueError):
            parse_archive(blob)

    def test_mutation_fuzz_no_crash(self) -> None:
        """Header mutations may fail — but never with a non-ValueError crash."""
        from contextlib import suppress

        real = (FIXTURES / "test_multi.q").read_bytes()[:200]
        rng = random.Random(7)
        for _ in range(150):
            blob = bytearray(real)
            for _ in range(rng.randint(1, 12)):
                blob[rng.randrange(len(blob))] = rng.randrange(256)
            with suppress(ValueError):
                parse_archive(bytes(blob))  # clean rejection — the contract

    def test_decompress_rejects_impossible_sizes(self) -> None:
        """A declared size the stream cannot produce must raise ValueError."""
        data = (FIXTURES / "test_single.q").read_bytes()
        header, _files, stream_off = parse_archive(data)
        with pytest.raises(ValueError):
            quantum_decompress(data[stream_off:], [10_000_000], header[3])


# ---------------------------------------------------------------------------
# Hypothesis property tests — structure-aware fuzzing of the Quantum decoder
# ---------------------------------------------------------------------------


@st.composite
def quantum_archive(draw: Any) -> bytes:
    """Generate a structurally-plausible Quantum archive (valid magic +
    random header fields + name table + trailing data)."""
    nfiles = draw(st.integers(0, 24))
    header = (
        b"DS"
        + bytes([draw(st.integers(0, 1)), draw(st.integers(0, 0x7F))])
        + nfiles.to_bytes(2, "little")
        + bytes([draw(st.integers(10, 21)), draw(st.integers(0, 0xFF))])
    )
    body = bytearray(header)
    for _ in range(nfiles):
        name = draw(
            st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=24)
        )
        nb = name.encode("latin-1")
        body.append(min(len(nb), 127))
        body += nb[:127]
        body.append(0)  # empty comment varstring
        body += draw(st.binary(min_size=8, max_size=8))  # size + time + date
    body += draw(st.binary(max_size=96))
    return bytes(body)


class TestHypothesisPak:
    @settings(max_examples=200, deadline=None)
    @given(quantum_archive())
    def test_parse_archive_never_crashes(self, blob: bytes) -> None:
        """Structure-aware header fuzz: parse either succeeds or raises a
        clean ValueError — never IndexError/struct.error."""
        with suppress(ValueError):
            parse_archive(blob)

    @settings(max_examples=200, deadline=None)
    @given(
        st.binary(min_size=1, max_size=256),
        st.lists(st.integers(min_value=0, max_value=4096), min_size=1, max_size=8),
        st.integers(min_value=10, max_value=21),
    )
    def test_decompress_never_crashes(
        self, stream: bytes, file_sizes: list[int], window_bits: int
    ) -> None:
        """Random arithmetic-coded streams + declared sizes: the decoder must
        raise ValueError (truncation/overrun) or return — never crash."""
        with suppress(ValueError):
            quantum_decompress(stream, file_sizes, window_bits)
