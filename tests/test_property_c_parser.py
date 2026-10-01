"""Property-based fuzzing for the C-source parsers (``rebrew.c_parser``,
``rebrew.struct_parser``).

Both modules read hand-written or machine-written (decompiler / LLM) C source,
which is untrusted input in the same way a downloaded binary is: arbitrary
bytes, no guarantee a declarator or struct body is terminated.  The harnesses
below build translation units out of declarations, function definitions,
struct/union/enum bodies and raw byte noise — the shapes these parsers branch
on — plus an arbitrary-byte strategy, and assert the shape invariants every
caller relies on:

* every ``ExternVar`` carries a non-empty name, and every ``array_suffix`` is
  empty or a run of balanced ``[...]`` spans.  ``data_scan`` and
  ``binsync.export`` paste ``type_str`` into a generated header and persist its
  size, so a suffix with a dangling ``[`` renders a header no compiler reads.
  Regression: tree-sitter's zero-width ``]`` recovery on a truncated declarator
  (``extern int a[;``) used to yield ``array_suffix="["``, leaving the reported
  type unbalanced;
* the reported ``type_str`` keeps its ``[``/``]`` pairs balanced, so
  ``estimate_type_size`` counts whole dimensions rather than a partial one;
* every definition ``struct_parser`` hands to Ghidra's ``parse-c-structure``
  has balanced braces and no NUL (the plugin truncates its payload at a NUL);
* no parser raises on arbitrary bytes — a malformed declaration is skipped.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.c_parser import ExternVar, find_extern_variables, protected_spans
from rebrew.struct_parser import (
    extract_enums_from_file,
    extract_structs_from_file,
    extract_type_definitions,
)

_EXTRACTORS = (extract_structs_from_file, extract_type_definitions, extract_enums_from_file)

_IDENT = st.sampled_from(["a", "b", "g_x", "Foo", "_t", "x1", "é", "struct", "__declspec"])
_TYPE = st.sampled_from(
    ["int", "char *", "unsigned long", "struct S", "enum E", "MyType", "const char *", "void"]
)
#: Bracket forms that reach the array-suffix extractor, including the truncated
#: ones that must not produce a dangling ``[`` suffix.
_ARRAY = st.lists(
    st.sampled_from(
        [
            "[4]",
            "[]",
            "[0]",
            "[0x10]",
            "[a+b]",
            "[",
            "]",
            "[]]",
            "[1][2]",
            "[999999999]",
            "[*]",
            "[ ]",
        ]
    ),
    max_size=3,
).map(lambda parts: "".join(parts))
_DECL = st.builds(lambda t, n, a: f"extern {t} {n}{a};", _TYPE, _IDENT, _ARRAY)
_FUNCTION = st.builds(
    lambda t, n, params: f"{t} __cdecl {n}({params}) {{ return 0; }}",
    _TYPE,
    _IDENT,
    st.lists(_TYPE, max_size=3).map(", ".join),
)
_MEMBER = st.sampled_from(
    ["int x;", "char *p;", "struct { int y; } n;", "};", "{", "unsigned a, b;", "enum { A } e;"]
)
_BODY = st.builds(
    lambda kind, members: f"typedef {kind} {{ {' '.join(members)} }} Alias{kind};",
    st.sampled_from(["struct", "union", "enum"]),
    st.lists(_MEMBER, max_size=6),
)
_NOISE = st.binary(max_size=64).map(lambda b: b.decode("utf-8", "replace"))
_UNIT = st.lists(st.one_of(_DECL, _FUNCTION, _BODY, _NOISE), max_size=5).map("\n".join)


def _assert_well_formed(var: ExternVar, source: str) -> None:
    """Every bracket ``_extract_array_suffix`` reported is a closed span."""
    suffix = var.array_suffix
    assert suffix == "" or (suffix.startswith("[") and suffix.endswith("]")), (source, var)
    assert suffix.count("[") == suffix.count("]"), (source, var)
    assert var.type_str.count("[") == var.type_str.count("]"), (source, var)
    assert var.name and var.name.strip() == var.name, (source, var)


@settings(max_examples=200, deadline=None)
@given(_UNIT, st.booleans())
def test_find_extern_variables_yields_balanced_declarations(
    source: str, include_definitions: bool
) -> None:
    """No ``ExternVar`` carries an unbalanced bracket run, whatever the source."""
    for var in find_extern_variables(source, include_definitions=include_definitions):
        _assert_well_formed(var, source)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=128))
def test_find_extern_variables_survives_arbitrary_bytes(blob: bytes) -> None:
    """Arbitrary bytes are a declaration to skip, never a crash."""
    source = blob.decode("utf-8", "replace")
    for var in find_extern_variables(source, include_definitions=True):
        _assert_well_formed(var, source)


@settings(max_examples=100, deadline=None)
@given(_UNIT)
def test_struct_definitions_are_gherkin_ready(source: str) -> None:
    """Every definition handed to Ghidra is a balanced, NUL-free C fragment."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "unit.c"
        path.write_bytes(source.encode("utf-8", "surrogateescape"))
        for extract in _EXTRACTORS:
            for definition in extract(path):
                assert definition.count("{") == definition.count("}"), (source, definition)
                assert "\0" not in definition, (source, definition)


@settings(max_examples=100, deadline=None)
@given(_UNIT)
def test_protected_spans_are_ordered_and_bounded(source: str) -> None:
    """``protected_spans`` returns sorted, non-overlapping spans inside the text."""
    raw = source.encode("utf-8", "surrogateescape")
    spans = protected_spans(source)
    assert all(0 <= start <= end <= len(raw) for start, end in spans)
    assert spans == sorted(spans)
    assert all(spans[i][1] <= spans[i + 1][0] for i in range(len(spans) - 1))
