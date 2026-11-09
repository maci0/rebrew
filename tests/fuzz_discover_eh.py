"""Atheris (libFuzzer) target: ELF ``.eh_frame`` unwind-record parser.

Same harness body and invariants as the ``TestEhFrame`` Hypothesis
tests in tests/test_discover.py (Hypothesis drives them in CI; this
file is the coverage-guided libFuzzer entry point for local/OSSFuzz
runs).

``rebrew.discover._parse_eh_frame`` walks the ``.eh_frame`` section of
an ELF the user points the CLI at: CIE/FDE record lengths, ULEB128
augmentation strings, and pointer encodings are all untrusted bytes.
Arbitrary bytes -- mutated, truncated, or structured -- must surface
as a clean partial parse (``[]`` or the extents read before the first
malformed record), never as an unhandled exception, and every
reported extent must be well-formed.

    uv run --frozen --group fuzz python tests/fuzz_discover_eh.py <corpus_dir> [flags]
    uv run --frozen --group fuzz python tests/fuzz_discover_eh.py tests/fixtures/eh_frame -runs=1000

Seed corpus: tests/fixtures/eh_frame/x86_64.eh_frame (a real
``.eh_frame`` section dumped from a committed-shape ELF build, never
production traffic).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.discover import _parse_eh_frame

_SECTION_VA = 0x1100
_POINTER_SIZES = (4, 8)


def TestOneInput(data: bytes) -> None:
    """The parser must never raise; whatever it returns must be well-formed.

    Pair assertions across the trust boundary: a shorter section can
    only report a prefix of the full section's extents (the parse
    walks forward and stops at the first malformed record, so
    truncation can never invent an extent the whole section did not
    have), and appending bytes after the zero-length terminator
    changes nothing (the terminator ends the section)."""
    for pointer_size in _POINTER_SIZES:
        for big_endian in (False, True):
            result = _parse_eh_frame(
                data, _SECTION_VA, pointer_size=pointer_size, big_endian=big_endian
            )
            assert isinstance(result, list)
            assert all(isinstance(start, int) and start >= 0 for start, _size in result)
            assert all(isinstance(size, int) and size > 0 for _start, size in result)
            # Determinism on exactly the same bytes.
            assert (
                _parse_eh_frame(
                    data, _SECTION_VA, pointer_size=pointer_size, big_endian=big_endian
                )
                == result
            )
            # Truncation can only shrink the result to a prefix of it.
            if data:
                cut = len(data) // 2
                truncated = _parse_eh_frame(
                    data[:cut],
                    _SECTION_VA,
                    pointer_size=pointer_size,
                    big_endian=big_endian,
                )
                assert truncated == result[: len(truncated)]
            # Bytes after the terminator are not parsed.
            terminated = data + b"\x00\x00\x00\x00"
            assert _parse_eh_frame(
                terminated, _SECTION_VA, pointer_size=pointer_size, big_endian=big_endian
            ) == _parse_eh_frame(
                terminated + b"\xde\xad\xbe\xef",
                _SECTION_VA,
                pointer_size=pointer_size,
                big_endian=big_endian,
            )


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
