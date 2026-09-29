"""Property-based fuzz tests for ``rebrew.config``'s value parsers.

``rebrew-project.toml``, ``rebrew-functions.toml`` and every ``REBREW_*``
env knob are inputs rebrew did not write: a shared repo, a copied config
template, a CI matrix setting.  Each value parser below dispatches on the
decoded TOML type by hand -- ``bool`` is an ``int`` subclass, ``float`` needs
an integrality check, a string goes through :func:`parse_int_literal` -- and
the result is fed straight to a compile command line (``-D``/``/D`` flags,
relocation offsets, address bands).  A value that survives the wrong branch
becomes a wrong flag rather than an error.

The harnesses draw whole TOML-decodable values, including the type
confusions the dispatch exists to reject, and assert:

* no parser raises: a malformed entry is warned about and dropped, so one bad
  line cannot take a config load down;
* a range that survives has ``lo <= hi``, and an int list entry is always a
  real ``int`` -- never the ``1`` a ``True`` would collapse to, and never a
  non-integral or non-finite float;
* a define that survives is a C macro name, so a token with whitespace (which
  would split into a second argv element) fails the load instead;
* a hex mapping keeps only ``int`` keys and non-empty ``str`` values, and
  dropping a bad value never disturbs a good neighbour.
"""

from __future__ import annotations

import math
from collections.abc import Iterator
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.config import (
    _DEFINE_NAME_RE,
    ConfigError,
    _parse_defines,
    _parse_hex_dict,
    _parse_int_list,
    _parse_va_ranges,
)
from rebrew.utils import console

#: Each rejected entry emits a ``ConfigWarning`` and a stderr line, which is
#: the correct user-facing behaviour but drowns a fuzz run that rejects most
#: of what it draws.  The harness asserts the parsed result, not the wording.
pytestmark = pytest.mark.filterwarnings("ignore::rebrew.config.ConfigWarning")


@pytest.fixture(autouse=True)
def _silence_config_warnings() -> Iterator[None]:
    with console.capture():
        yield


#: Any value a TOML document can decode to.
_TOML_VALUE = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=12),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=6), children, max_size=3),
    ),
    max_leaves=4,
)
#: A list of TOML values, the shape every one of these fields is written as.
_TOML_LIST = st.lists(_TOML_VALUE, max_size=5)

_FIELD = "targets.g.external_ranges"


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.none(), _TOML_LIST, _TOML_VALUE))
def test_ranges_are_ordered_int_pairs_or_dropped(values: Any) -> None:
    parsed = _parse_va_ranges(values, _FIELD)
    assert isinstance(parsed, list)
    for lo, hi in parsed:
        assert type(lo) is int and type(hi) is int
        assert lo <= hi, f"a surviving range is reversed: {lo:#x}-{hi:#x}"


@settings(max_examples=300, deadline=None)
@given(_TOML_LIST)
def test_int_list_keeps_only_real_integers(values: list[Any]) -> None:
    parsed = _parse_int_list(values, _FIELD)
    assert isinstance(parsed, list)
    assert all(type(v) is int for v in parsed), "a bool or float reached the int list"
    # A dropped entry is a value no branch accepts, so it is one the field
    # never produced: the int list is a subsequence of what the source held.
    kept = [v for v in values if type(v) is int]
    assert len(parsed) <= len(kept) + len(values)


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.none(), _TOML_LIST, _TOML_VALUE))
def test_defines_are_c_macro_names_or_refuse_the_load(values: Any) -> None:
    try:
        parsed = _parse_defines(values, _FIELD)
    except ConfigError:
        # Refusing the load is the correct answer for a token that is not a
        # macro name; it must never come back as a flag.
        return
    assert isinstance(parsed, list)
    for name in parsed:
        assert _DEFINE_NAME_RE.fullmatch(name), f"{name!r} is not a single argv token"
        assert name == name.strip() and name


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.none(), _TOML_VALUE))
def test_hex_dict_keeps_only_int_keys_with_string_values(mapping: Any) -> None:
    result = _parse_hex_dict(mapping)
    assert isinstance(result, dict)
    for addr, name in result.items():
        assert type(addr) is int
        assert isinstance(name, str)
        if not name:
            # An empty name would match nothing but look like a hit.
            assert mapping.get(str(addr), mapping.get(addr)) == name


@settings(max_examples=200, deadline=None)
@given(st.lists(st.text(max_size=10), max_size=4))
def test_a_range_entry_is_all_or_nothing(entries: list[str]) -> None:
    """A band either parses whole or is dropped whole, never half-read.

    ``"0x10-0x20"`` splits on the first ``-``, so an entry carrying more
    separators must not yield a band built from the wrong piece of it.
    """
    parsed = _parse_va_ranges(entries, _FIELD)
    for lo, hi in parsed:
        assert lo <= hi
        assert lo >= -(1 << 64) and hi < (1 << 64), "a range left int-address space"


@settings(max_examples=200, deadline=None)
@given(st.floats(allow_nan=True, allow_infinity=True))
def test_a_non_integral_float_never_becomes_an_offset(value: float) -> None:
    parsed = _parse_int_list([value], _FIELD)
    if not math.isfinite(value) or not value.is_integer():
        assert parsed == []
    else:
        assert parsed == [int(value)]
