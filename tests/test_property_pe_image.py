"""Property-based fuzz tests for ``rebrew.pe_image.parse_pe`` on corrupted images.

``parse_pe`` is the hand-rolled PE32 walk behind ``rebrew build layout`` and
``rebrew build sweep-link-flags``: it reads a reference binary the user points the CLI at,
so every offset, count, and RVA in it is untrusted.  These tests mutate the
committed PE fixture (headers, section table, export/import directories,
truncation) and pin the documented outcomes: a self-consistent parse, or a
``ValueError`` for an image it refuses.  ``derive_link_options`` is fuzzed over
the same inputs because it renders the parsed fields straight into linker
flags.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hypothesis import event, given, settings
from hypothesis import strategies as st

from rebrew.pe_headers import SECTION_ENTRY_SIZE
from rebrew.pe_image import PeImport, derive_link_options, parse_pe

FIXTURES = Path(__file__).parent / "fixtures"
_SEED = (FIXTURES / "mini_pe.exe").read_bytes()

#: Mutations land in the headers, section table, and the two data directories
#: ``parse_pe`` walks, which is where the parser branches on file content.
_MUTATE_SPAN = 0x800
#: Hard cap mirroring the parser's own table caps, so a forged count cannot
#: turn a hang into a test timeout (the parse itself must terminate).
_MAX_PARSED_ENTRIES = 65536


@st.composite
def _mutated_image(draw: st.DrawFn) -> bytes:
    """The PE fixture with drawn byte patches and an optional truncation."""
    data = bytearray(_SEED)
    span = min(_MUTATE_SPAN, len(data))
    patches = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=span - 1), st.binary(min_size=1, max_size=4)
            ),
            max_size=10,
        )
    )
    for offset, chunk in patches:
        data[offset : offset + len(chunk)] = chunk
    if draw(st.booleans()):
        data = data[: draw(st.integers(min_value=0, max_value=len(data)))]
    return bytes(data)


def _parse(
    blob: bytes,
) -> tuple[list[Any], list[dict[str, Any]], list[PeImport], dict[str, Any]] | None:
    """``parse_pe`` over *blob*; ``None`` when it rejects the image."""
    try:
        return parse_pe(blob)
    except ValueError:
        return None


@settings(max_examples=200, deadline=None)
@given(_mutated_image())
def test_parse_pe_mutated_fixture_is_self_consistent(blob: bytes) -> None:
    parsed = _parse(blob)
    event("parsed" if parsed is not None else "rejected")
    if parsed is None:
        return
    sections, exports, imports, pe = parsed

    # The header block the parser claims to have read must fit the file: a
    # section table that overruns the image is exactly the forged case the
    # truncation guard exists for.
    assert pe["header_size"] <= len(blob)
    # The signature sits where ``e_lfanew`` points, which is the contract
    # ``pe_lfanew`` enforces.  Not ``find``, the first ``PE\0\0`` anywhere: a
    # mutation drops a decoy one before the real header all the time, and
    # demanding the parser follow the decoy asserts the opposite of the guard
    # that rejects such an image.
    assert blob[pe["e_lfanew"] : pe["e_lfanew"] + 4] == b"PE\0\0"

    for section in sections:
        assert section.raw_ptr + section.raw_size >= section.raw_ptr
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

    # reloc_va is derived (image_base + reloc_rva) only when the reloc RVA
    # lands in a section, so it is None or an int — never a str or a float.
    assert pe["reloc_va"] is None or isinstance(pe["reloc_va"], int)


@settings(max_examples=200, deadline=None)
@given(_mutated_image())
def test_derive_link_options_is_deterministic_and_flag_shaped(blob: bytes) -> None:
    parsed = _parse(blob)
    if parsed is None:
        return
    options, link_toml = derive_link_options(parsed[3])
    assert all(option.startswith("/") for option in options)
    assert len(options) == len(set(options)), "a field emitted the same LINK option twice"
    assert link_toml.startswith("[link]\n")
    assert link_toml.endswith("\n")
    assert derive_link_options(parsed[3]) == (options, link_toml)


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=1024))
def test_parse_pe_random_bytes_rejected_or_consistent(blob: bytes) -> None:
    parsed = _parse(blob)
    if parsed is None:
        return
    sections, exports, imports, pe = parsed
    assert pe["header_size"] <= len(blob)
    # sections_at stops at the end of the image, so a forged
    # NumberOfSections cannot inflate the list past the bytes the file holds.
    assert len(sections) * SECTION_ENTRY_SIZE <= len(blob)
    assert all(isinstance(section.name, str) for section in sections)
    assert all(isinstance(imp.dll, str) for imp in imports)
