"""Property-based fuzzing of the Ghidra/discovery JSON loaders.

Ghidra export JSON and rizin ``afl`` output are untrusted input: hand-edited
after an export, written by a third-party tool, or left behind by a crashed
run.  These harnesses assert the invariants callers rely on, so a malformed
payload surfaces as the documented load error instead of an ``AttributeError``
or a silently mis-typed field.
"""

import itertools
import json
import tempfile
import warnings
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.catalog.loaders import load_function_structure, load_ghidra_data_labels, parse_rizin_afl
from rebrew.catalog.models import FunctionEntry, GhidraDataLabel

#: Any value a JSON document can carry, including the ones a broken exporter emits.
_json_value = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**64),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=12),
    st.lists(st.integers(), max_size=3),
    st.dictionaries(st.text(max_size=6), st.integers(), max_size=3),
)

_json_entry = st.dictionaries(st.text(max_size=8), _json_value, max_size=6)

# A Ghidra entry with its real keys.  Purely random keys almost never spell
# "label"/"state", so the field-level cases below are what reach the coercion.
_known_entry = st.fixed_dictionaries(
    {},
    optional={
        "va": _json_value,
        "size": _json_value,
        "label": _json_value,
        "state": _json_value,
        "name": _json_value,
        "tool_name": _json_value,
        "ghidra_name": _json_value,
    },
)

#: Half arbitrary keys, half real export keys.
_entry = st.one_of(_json_entry, _known_entry)

#: A loadable label row (nonzero va, positive size) whose ``label`` is not a
#: string: the shape that reached ``_classify_ghidra_label`` and raised
#: ``AttributeError`` on ``.lower()``.  The generic strategies above almost
#: never land on it, so it is spelled out here.
_bad_label_entry = st.builds(
    lambda va, size, label: {"va": va, "size": size, "label": label},
    st.integers(min_value=1, max_value=0xFFFFFFFF),
    st.integers(min_value=1, max_value=0xFFFF),
    st.one_of(
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.booleans(),
        st.lists(st.integers(), min_size=1, max_size=3),
        st.dictionaries(st.text(max_size=4), st.integers(), min_size=1, max_size=3),
    ),
)

# The loaders look for a fixed filename, and they memoize a decode per path
# (stat-fingerprinted), so each example gets its own directory under one
# temporary root: a rewritten file alone would not defeat the cache.
_case_counter = itertools.count()


def _case_dir(root: Path) -> Path:
    d = root / f"case{next(_case_counter)}"
    d.mkdir()
    return d


def _write_json(directory: Path, name: str, payload: Any) -> Path:
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@settings(max_examples=200, deadline=None)
@given(st.lists(st.one_of(_entry, _bad_label_entry), max_size=8))
def test_ghidra_data_labels_survive_arbitrary_json(entries: list[dict[str, Any]]) -> None:
    """Every surviving entry is a fully typed label; nothing raises.

    A non-string ``label`` previously reached ``_classify_ghidra_label`` and
    raised ``AttributeError`` on ``.lower()``.
    """
    with tempfile.TemporaryDirectory() as td:
        src = _case_dir(Path(td))
        _write_json(src, "ghidra_data_labels.json", entries)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            labels = load_ghidra_data_labels(src)

    for va, gdl in labels.items():
        assert isinstance(gdl, GhidraDataLabel)
        assert va == gdl.va != 0
        assert gdl.size > 0
        assert isinstance(gdl.label, str)
        assert isinstance(gdl.state, str)
        assert gdl.state in ("data", "thunk")
        assert (gdl.state == "thunk") == gdl.label.lower().startswith("thunk_")


@settings(max_examples=200, deadline=None)
@given(st.lists(_bad_label_entry, min_size=1, max_size=8))
def test_ghidra_data_labels_reject_non_string_label(entries: list[dict[str, Any]]) -> None:
    """A loadable row whose ``label`` is not a string is dropped, not a crash.

    ``GhidraDataLabel.from_dict`` promised ``label: str`` while passing the raw
    JSON value through, so ``_classify_ghidra_label`` raised ``AttributeError``
    on ``.lower()`` for a hand-edited or half-written export.
    """
    with tempfile.TemporaryDirectory() as td:
        src = _case_dir(Path(td))
        _write_json(src, "ghidra_data_labels.json", entries)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            labels = load_ghidra_data_labels(src)

    assert all(isinstance(gdl.label, str) for gdl in labels.values())


@settings(max_examples=200, deadline=None)
@given(st.lists(_entry, max_size=8))
def test_function_structure_survive_arbitrary_json(entries: list[dict[str, Any]]) -> None:
    """Decodable entries are fully typed; unusable ones raise the documented ValueError."""
    with tempfile.TemporaryDirectory() as td:
        path = _write_json(_case_dir(Path(td)), "function_structure.json", entries)
        try:
            loaded = load_function_structure(path)
        except ValueError:
            # A corrupt document, or an entry with no usable va/size: the
            # documented contract, which cached_function_list handles.
            return
    for entry in loaded:
        assert isinstance(entry, FunctionEntry)
        assert isinstance(entry.va, int) and isinstance(entry.size, int)
        assert isinstance(entry.name, str) and isinstance(entry.tool_name, str)


@settings(max_examples=200, deadline=None)
@given(st.lists(_entry, max_size=8))
def test_function_entry_from_dict_types_hold(entries: list[dict[str, Any]]) -> None:
    """A dict that decodes at all produces a fully typed FunctionEntry."""
    for d in entries:
        try:
            entry = FunctionEntry.from_dict(d)
        except ValueError:
            continue
        assert isinstance(entry.va, int) and isinstance(entry.size, int)
        assert isinstance(entry.name, str) and isinstance(entry.tool_name, str)


@settings(max_examples=200, deadline=None)
@given(st.lists(_entry, max_size=8))
def test_ghidra_data_label_from_dict_types_hold(entries: list[dict[str, Any]]) -> None:
    """from_dict never raises, and always yields the str/str/int contract."""
    for d in entries:
        gdl = GhidraDataLabel.from_dict(d)
        assert isinstance(gdl.va, int) and isinstance(gdl.size, int)
        assert isinstance(gdl.label, str)
        assert isinstance(gdl.state, str)


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=300))
def test_parse_rizin_afl_output_shape(text: str) -> None:
    """Parsed rows are (va, size, name) with a non-negative va/size and a usable name."""
    rows = parse_rizin_afl(text)
    for va, size, name in rows:
        assert isinstance(va, int) and va >= 0
        assert isinstance(size, int) and size >= 0
        assert isinstance(name, str) and name
    # A placeholder name (`->`, `loc`, `sub.*`) is normalized, never kept.
    assert all(n not in ("->", "loc") and not n.startswith("sub.") for _, _, n in rows)


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=300))
def test_parse_rizin_afl_is_idempotent(text: str) -> None:
    """Re-parsing the parser's own canonical output reproduces the same rows."""
    once = parse_rizin_afl(text)
    rebuilt = "\n".join(f"0x{va:08x} {size} {name}" for va, size, name in once)
    assert parse_rizin_afl(rebuilt) == once
