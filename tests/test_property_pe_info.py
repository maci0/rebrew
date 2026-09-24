"""Property-based fuzz tests for ``rebrew.pe_info.pe_info`` on corrupted images.

``rebrew pe-info`` dumps whatever binary the user points it at, so every byte
of the file is untrusted.  These tests mutate the committed PE and ELF
fixtures (header bytes, section table, truncation) and hold ``pe_info`` to its
documented outcomes: a JSON-serializable, run-to-run identical payload, or a
``ValueError`` for an unparseable file.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hypothesis import event, given, settings
from hypothesis import strategies as st

from rebrew.pe_info import pe_info

FIXTURES = Path(__file__).parent / "fixtures"
_SEEDS = {
    "pe": (FIXTURES / "mini_pe.exe").read_bytes(),
    "elf": (FIXTURES / "mini.elf").read_bytes(),
}
#: Mutations land in the headers and section table, where the parsers branch.
_HEADER_SPAN = 0x400
_IDENTITY_KEYS = {"format", "arch", "bits", "image_base", "entry_point", "size"}


@st.composite
def _mutated_image(draw: st.DrawFn) -> bytes:
    """A fixture image with drawn byte patches and an optional truncation."""
    data = bytearray(_SEEDS[draw(st.sampled_from(sorted(_SEEDS)))])
    span = min(_HEADER_SPAN, len(data))
    patches = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=span - 1), st.binary(min_size=1, max_size=4)
            ),
            max_size=8,
        )
    )
    for offset, chunk in patches:
        data[offset : offset + len(chunk)] = chunk
    if draw(st.booleans()):
        data = data[: draw(st.integers(min_value=0, max_value=len(data)))]
    return bytes(data)


def _run(blob: bytes) -> dict[str, object] | None:
    """``pe_info`` over *blob* on disk; ``None`` when it reports ``ValueError``."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "target.bin"
        path.write_bytes(blob)
        try:
            return pe_info(path)
        except ValueError:
            return None


@settings(max_examples=150, deadline=None)
@given(_mutated_image())
def test_pe_info_mutated_fixture_payload_or_value_error(blob: bytes) -> None:
    payload = _run(blob)
    event("parsed" if payload is not None else "rejected")
    if payload is None:
        return
    assert payload.keys() >= _IDENTITY_KEYS
    assert payload["size"] == len(blob)
    encoded = json.dumps(payload, sort_keys=True)
    assert json.dumps(_run(blob), sort_keys=True) == encoded


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=512))
def test_pe_info_random_bytes_payload_or_value_error(blob: bytes) -> None:
    payload = _run(blob)
    if payload is not None:
        json.dumps(payload)
