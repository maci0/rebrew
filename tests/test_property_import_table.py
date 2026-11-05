"""Property-based fuzz tests for the import-table parsers.

``rebrew.formats.import_table`` reads untrusted target binaries through LIEF
(PE import directory, ELF dynamic imports) and the native NE loader (16-bit module
imports), then derives the ``{iat_va: api_name}`` table and the ``FF 25`` import
stubs that name imported APIs for every analysis pass.  A malformed import
directory, version-requirement table, or stub displacement must surface as an
empty/partial record list, never as an unhandled exception, crash, or invented
slot/name pair.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from rebrew.formats.import_table import find_import_stubs, parse_import_table, parse_imports

_RECORD_KEYS = {"dll", "name", "iat_va", "ordinal", "hint_name_rva"}
_FIXTURES = Path(__file__).parent / "fixtures"
_PE_SEED = (_FIXTURES / "mini_pe.exe").read_bytes()
_NE_SEED = (_FIXTURES / "mini_ne.exe").read_bytes()


@st.composite
def _mutated_image(draw: st.DrawFn, seed: bytes) -> bytes:
    """A committed fixture image with drawn byte patches and a truncation."""
    data = bytearray(seed)
    span = min(0x600, len(data))
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


def _assert_import_shape(records: list[dict[str, object]]) -> None:
    assert isinstance(records, list)
    for record in records:
        assert set(record) == _RECORD_KEYS
        assert isinstance(record["dll"], str)
        assert isinstance(record["name"], str)
        assert isinstance(record["iat_va"], int) and record["iat_va"] >= 0
        assert record["ordinal"] is None or (
            isinstance(record["ordinal"], int) and record["ordinal"] >= 0
        )
        assert record["hint_name_rva"] is None or (
            isinstance(record["hint_name_rva"], int) and record["hint_name_rva"] >= 0
        )
        if record["ordinal"] is not None:
            assert record["name"] == f"ordinal_{record['ordinal']}"


@pytest.mark.parametrize("seed", [_PE_SEED, _NE_SEED])
@settings(max_examples=100, deadline=None)
@given(st.data())
def test_mutated_image_imports_are_shaped_and_consistent(seed: bytes, data: st.DataObject) -> None:
    blob = data.draw(_mutated_image(seed))
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "target.exe"
        path.write_bytes(blob)
        records = parse_imports(path)
        event("records" if records else "empty")
        _assert_import_shape(records)
        # Pair assertion across the derivation boundary: the convenience
        # table is exactly the record view, and every stub names a table entry.
        table = parse_import_table(path)
        assert table == {rec["iat_va"]: rec["name"] for rec in records}
        for stub_va, name in find_import_stubs(path).items():
            assert isinstance(stub_va, int) and stub_va >= 0
            assert name in table.values()


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=1024))
def test_random_bytes_yield_empty_or_shaped_imports(blob: bytes) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "target.exe"
        path.write_bytes(blob)
        records = parse_imports(path)
        _assert_import_shape(records)
        assert parse_import_table(path) == {rec["iat_va"]: rec["name"] for rec in records}
        assert set(find_import_stubs(path).values()) <= set(parse_import_table(path).values())
