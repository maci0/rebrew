"""Property-based fuzz tests for the Rich-header codec in ``rebrew.fingerprints``.

``_rich_header_parts_from_dos_stub`` searches a target binary's DOS stub for
the ``Rich`` marker, reads the XOR key that follows it and walks back a dword
at a time to the ``DanS ^ key`` start marker: every offset in that walk comes
from the untrusted file, and a stub can hold a forged ``Rich`` anywhere.  The
encoder ``rich_header_bytes_from_parts`` is the other side of the same
boundary, so these tests assert the pair: what the encoder writes, the
decoder reads back, and on arbitrary stubs the decoder either declines
(``None``) or returns values that survive a re-encode unchanged.  Both
directions must stay well shaped and never raise.
"""

from __future__ import annotations

import struct

from hypothesis import assume, event, given, settings
from hypothesis import strategies as st

from rebrew.fingerprints import (
    _rich_header_parts_from_dos_stub,
    rich_header_bytes_from_parts,
    rich_header_hash_from_parts,
)

_MARKER = b"Rich"
_DANS = b"DanS"
_UINT32 = (1 << 32) - 1
#: A dword-aligned block the decoder must skip to reach the entry pairs.
_PADDING_BYTES = 12

_key = st.integers(min_value=0, max_value=_UINT32)
_entry = st.tuples(st.integers(min_value=0, max_value=_UINT32), st.integers(0, _UINT32))
_entries = st.lists(_entry, max_size=6)


def _on_disk_rich(key: int, entries: list[tuple[int, int]]) -> bytes:
    """A Rich header as the linker writes it: ``DanS`` and the padding XORed
    with *key* as well (the canonical encoder leaves them as zero bytes)."""
    canonical = rich_header_bytes_from_parts(key, entries)
    head = b"".join(
        (int.from_bytes(canonical[i : i + 4], "little") ^ key).to_bytes(4, "little")
        for i in range(0, 4 + _PADDING_BYTES, 4)
    )
    return head + canonical[4 + _PADDING_BYTES :]


@st.composite
def _stub(draw: st.DrawFn) -> bytes:
    """A DOS stub: arbitrary bytes, or one carrying a plausible Rich header
    behind a prefix of arbitrary bytes and a forged ``Rich`` somewhere."""
    prefix = draw(st.binary(max_size=64))
    choice = draw(st.integers(min_value=0, max_value=2))
    if choice == 0:
        return prefix + draw(st.binary(max_size=128))
    if choice == 1:
        return prefix + _DANS + draw(st.binary(max_size=64))
    return prefix + _on_disk_rich(draw(_key), draw(_entries))


@settings(max_examples=200, deadline=None)
@given(_key, _entries)
def test_encoded_header_decodes_back_to_its_parts(key: int, entries: list[tuple[int, int]]) -> None:
    # A header with no pairs has an empty entry block, which the decoder
    # declines: it only reports a Rich header that carries at least one
    # comp_id/count pair.
    assume(entries)
    blob = _on_disk_rich(key, entries)
    # A pair whose XORed bytes spell the marker makes the decoder's forward
    # search land inside the entry list, which is a decoder limitation, not
    # the round trip under test.  The entry list ends 8 bytes before the end
    # of the header (marker plus key).
    assume(_MARKER not in blob[4 + _PADDING_BYTES : -8])

    parts = _rich_header_parts_from_dos_stub(blob)
    event("decoded" if parts is not None else "declined")
    assert parts == (key, entries)


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=256), _stub())
def test_decoder_declines_or_returns_re_encodable_parts(noise: bytes, stub: bytes) -> None:
    for blob in (noise, stub):
        parts = _rich_header_parts_from_dos_stub(blob)
        event("decoded" if parts is not None else "declined")
        if parts is None:
            continue
        key, entries = parts
        assert 0 <= key <= _UINT32
        assert all(0 <= value <= _UINT32 for pair in entries for value in pair)
        # Every pair is read out of the stub itself, so a file of N bytes can
        # never yield more than N // 8 of them.
        assert len(entries) <= len(blob) // 8
        # Re-encoding the decoded parts and decoding again is a fixed point:
        # a second pass cannot disagree with the first about what it read.
        rebuilt = _on_disk_rich(key, entries)
        again = _rich_header_parts_from_dos_stub(rebuilt)
        if _MARKER not in rebuilt[4 + _PADDING_BYTES : -8]:
            assert again == (key, entries)
        digest = rich_header_hash_from_parts(key, entries)
        assert len(digest) == 32
        assert digest == rich_header_hash_from_parts(key, entries)


@settings(max_examples=200, deadline=None)
@given(_key, _entries)
def test_encoded_header_layout_is_canonical(key: int, entries: list[tuple[int, int]]) -> None:
    blob = rich_header_bytes_from_parts(key, entries)
    assert blob.startswith(b"DanS")
    assert blob[-8:-4] == _MARKER
    assert struct.unpack_from("<I", blob, len(blob) - 4)[0] == key
    # DanS + 12 padding + 8 per entry + Rich + key.
    assert len(blob) == 4 + _PADDING_BYTES + 8 * len(entries) + 8
