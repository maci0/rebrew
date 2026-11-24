"""``rendered_toml.loads`` returns exactly what ``tomllib.loads`` returns.

Equality here is by value, type and key order, since callers iterate the
documents. Invalid text must raise ``TOMLDecodeError`` as ``tomllib`` does.
"""

from __future__ import annotations

import tomllib
from typing import Any

import pytest
import tomlkit
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.metadata import rendered_toml
from rebrew.metadata.rendered_toml import _Fallback, _parse


def _same(got: Any, expected: Any, where: str = "$") -> None:
    assert type(got) is type(expected), where
    if isinstance(expected, dict):
        assert list(got) == list(expected), where
        for key in expected:
            _same(got[key], expected[key], f"{where}.{key}")
    elif isinstance(expected, list):
        assert len(got) == len(expected), where
        for index, (item, want) in enumerate(zip(got, expected, strict=True)):
            _same(item, want, f"{where}[{index}]")
    else:
        assert got == expected, where


def _agrees(text: str) -> None:
    try:
        expected = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        with pytest.raises(tomllib.TOMLDecodeError) as actual:
            rendered_toml.loads(text)
        assert str(actual.value) == str(error)
        return
    _same(rendered_toml.loads(text), expected)


#: The shapes rebrew's functions store renders, one of each.
_RENDERED = """format = 3

["GOLD.0x00401000"]
file = "src/Develop/Unassigned/GOLDTL.fcn_00401000.c"
symbol = "_fcn_00401000"
name = "Grüße \\"quoted\\" path\\\\to"
size = 297
similarity = 98.50746268656717
globals = ["SERVER 0x100a8c30", "GOLD 0x00500000"]

["GOLD.0x00401000".verification]
status = "EXACT"
headers_hash = "0123abcd"

[["GOLD.0x00401000".binding_history]]
file = "src/old.c"

["GOLD.0x00401000".binding_history.previous]
symbol = "_old"

["GOLD.0x00401000".binding_history.previous.verification]
size = 12

[["GOLD.0x00401000".binding_history]]
file = "src/older.c"

[source.definitions."src/Develop/Units/vfs/GOLDTL.SaveBMP24.c".fill0.GOLDTL]
kind = "FUNCTION"
"""


def test_the_rendered_layout_is_read_on_the_fast_path_and_matches() -> None:
    _same(_parse(_RENDERED), tomllib.loads(_RENDERED))
    _same(rendered_toml.loads(_RENDERED), tomllib.loads(_RENDERED))


def test_repeated_field_keys_are_local_to_their_table() -> None:
    text = '[a]\nsize = 1\nname = "f"\n[b]\n"name" = "g"\n"size" = 2\n'
    _same(_parse(text), tomllib.loads(text))
    _agrees(text + "size = 3\n")


@pytest.mark.parametrize(
    "text",
    [
        "a = 1 # comment\n",  # trailing comment: value parsed by tomllib alone
        'a = "tab\\tescape"\n',  # an escape json and TOML might not share
        "a = 1979-05-27T07:32:00Z\n",  # a date
        "a = 0x1F\n",
        "a = +1\n",
        "a = 1_000\n",
        "a = inf\n",
    ],
)
def test_a_value_outside_the_fast_forms_still_matches(text: str) -> None:
    _same(rendered_toml.loads(text), tomllib.loads(text))


@pytest.mark.parametrize(
    "text",
    [
        "# comment\na = 1\n",
        "a = 1\r\nb = 2\r\n",
        "  a = 1\n",
        "a.b = 1\n",
        "a = { b = 1 }\n[a.c]\nd = 2\n",
        'a = """\nmulti\n"""\n',
        "a = [\n  1,\n]\n",
        "[a]\nb = 1\n[a]\nc = 2\n",
        "a = 1\na = 2\n",
        "[a]\nb = 1\n[a.b]\nc = 2\n",
        "a = [1]\n[[a]]\nb = 1\n",
        "[[a]]\nb = 1\n[a]\nc = 2\n",
        "[ a ]\nb = 1\n",
        '"a\\u0041" = 1\n',
    ],
)
def test_text_outside_the_layout_is_read_by_tomllib(text: str) -> None:
    with pytest.raises(_Fallback):
        _parse(text)
    _agrees(text)


@pytest.mark.parametrize(
    "text",
    ['a = "unterminated\n', "[a\nb = 1\n", 'a = "ctrl\x01"\n', 'a = "del\x7f"\n', "a =\n"],
)
def test_invalid_text_raises_as_tomllib_does(text: str) -> None:
    with pytest.raises(tomllib.TOMLDecodeError):
        tomllib.loads(text)
    with pytest.raises(tomllib.TOMLDecodeError):
        rendered_toml.loads(text)


_KEYS = st.text(st.characters(codec="utf-8", exclude_categories=("Cs",)), max_size=6)
_SCALARS = st.one_of(
    st.text(st.characters(codec="utf-8", exclude_categories=("Cs",)), max_size=12),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.floats(allow_nan=False, allow_infinity=False),
    st.booleans(),
)
_VALUES = st.one_of(_SCALARS, st.lists(st.text(max_size=6), max_size=3))
_TABLES = st.recursive(
    st.dictionaries(_KEYS, _VALUES, max_size=4),
    lambda inner: st.dictionaries(
        _KEYS, st.one_of(_VALUES, inner, st.lists(inner, min_size=1, max_size=2)), max_size=4
    ),
    max_leaves=12,
)


@settings(max_examples=300, deadline=None)
@given(_TABLES)
def test_a_document_rendered_by_tomlkit_reads_the_same(doc: dict[str, Any]) -> None:
    _agrees(tomlkit.dumps(doc))


@settings(max_examples=300, deadline=None)
@given(st.data())
def test_an_edited_rendering_reads_the_same_or_fails_the_same(data: st.DataObject) -> None:
    text = tomlkit.dumps(data.draw(_TABLES))
    if text:
        at = data.draw(st.integers(0, len(text) - 1))
        text = (
            text[:at]
            + data.draw(st.sampled_from(['"', "\\", "[", "]", "=", "\n", ".", " ", "#", ""]))
            + text[at + 1 :]
        )
    _agrees(text)
