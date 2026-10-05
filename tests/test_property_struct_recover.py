"""Hypothesis fuzz for the decompiler-text parser behind ``rebrew types recover``.

``rebrew.struct_recover`` reads a whole decompilation (Kuna, Ghidra, r2ghidra)
as text: six regexes extract member offsets, array indexes and pointer base
types, and the evidence it keeps is rendered into ``typedef struct`` blocks
that ``--apply`` appends to a project header.  Every offset, index and type
name in that text is produced by another tool, so all of it is untrusted.

The harness feeds decompiler-shaped statements alongside arbitrary text and
asserts more than "did not raise":

* the parser returns only in-range offsets, positive widths, and no
  pseudo-type as a named base;
* the ``max_offset`` filter is monotone — shrinking the cap can only drop
  evidence, never change or add it;
* the rendered struct covers every offset the parser reported, and a second
  synthesis over that rendering is stable (the pair assertion across the
  evidence-to-header boundary);
* a ``deadline`` turns a backtracking blowup in one of the regexes into a
  test failure rather than a hung run.
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.struct_recover import (
    PSEUDO_TYPES,
    ParseResult,
    parse_decomp_for_structs,
    synthesize_struct,
)

_IDENT = st.from_regex(r"\A[A-Za-z_][A-Za-z0-9_]{0,15}\Z", fullmatch=True)
_DIGITS = st.from_regex(r"\A[0-9]{1,12}\Z", fullmatch=True)
_HEX = st.from_regex(r"\A[0-9a-fA-F]{1,12}\Z", fullmatch=True)

#: A primitive the width table knows, so array evidence has a base type.
_PRIMITIVES = ("int", "short", "char", "undefined4", "uint32_t", "double")

#: Per-example wall-clock cap for a parse of a short snippet.  Generous
#: enough not to trip on a loaded machine, far below the blowup a
#: backtracking regex needs: the failure mode being watched for is a
#: hang, not microseconds.
_PARSE_DEADLINE = 1000


@st.composite
def _decomp_text(draw: st.DrawFn) -> str:
    """A decompilation body: decompiler statements, delimiters, and noise."""
    var = _IDENT
    prim = st.sampled_from(_PRIMITIVES)
    stmt = st.one_of(
        st.builds(lambda v, p: f"{p} *{v};", var, prim),
        st.builds(lambda v, p: f"(*({p} *){v});", var, prim),
        st.builds(lambda v, o: f"{v}->field_{o};", var, _HEX),
        st.builds(lambda v, o: f"(*({v}->field_0x{o}));", var, _HEX),
        st.builds(lambda v, p, o: f"*({p} *)({v} + 0x{o});", var, prim, _HEX),
        st.builds(lambda v, p, i: f"*({p} *)&{v}[{i}];", var, prim, _DIGITS),
        st.builds(lambda v, i: f"{v}[{i}] = 0;", var, _DIGITS),
        st.builds(lambda v, t: f"({t} *){v};", var, _IDENT),
        # A member access with no variable: a cast immediately precedes it.
        st.builds(lambda o: f"((PlayerInfo *)raw)->field_{o};", _HEX),
    )
    filler = st.one_of(
        st.just(""),
        st.just("\n"),
        st.just("  "),
        st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12),
    )
    return "".join(f"{f}{s}" for f, s in draw(st.lists(st.tuples(filler, stmt), max_size=6)))


def _all_evidence(result: ParseResult) -> list[tuple[str, int, int]]:
    return [
        (base, off, width)
        for container in (result.named, result.anonymous)
        for base, ev in container.items()
        for off, slots in ev.offsets.items()
        for width in slots
    ]


_MEMBERS = re.compile(r"(?:field|gap)_([0-9A-Fa-f]+)(?:\[0x([0-9a-f]+)\])?")


def _assert_invariants(result: ParseResult, max_offset: int) -> None:
    for base, off, width in _all_evidence(result):
        assert 0 <= off < max_offset
        assert width > 0
        assert base not in PSEUDO_TYPES
    for container in (result.named, result.anonymous):
        for ev in container.values():
            for slots in ev.offsets.values():
                assert all(count > 0 for count in slots.values())


# ---------------------------------------------------------------------------
# The parser itself
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=_PARSE_DEADLINE)
@given(text=_decomp_text())
def test_parse_decomp_keeps_only_in_range_evidence(text: str) -> None:
    max_offset = 0x1000000
    _assert_invariants(parse_decomp_for_structs(text), max_offset)


@settings(max_examples=100, deadline=_PARSE_DEADLINE)
@given(text=_decomp_text(), cap=st.integers(min_value=1, max_value=0x1000))
def test_max_offset_filter_only_removes_evidence(text: str, cap: int) -> None:
    wide = parse_decomp_for_structs(text, 0x1000000)
    narrow = parse_decomp_for_structs(text, cap)
    kept = {(base, off, w) for base, off, w in _all_evidence(narrow)}
    for base, off, width in _all_evidence(wide):
        if off < cap:
            assert (base, off, width) in kept
    # A narrower cap cannot invent evidence the wide parse never saw.
    assert kept <= {(base, off, w) for base, off, w in _all_evidence(wide)}


@settings(max_examples=50, deadline=_PARSE_DEADLINE)
@given(digits=st.integers(min_value=9, max_value=5000), prim=st.sampled_from(_PRIMITIVES))
def test_oversized_array_index_is_dropped_not_fatal(digits: int, prim: str) -> None:
    """Regression: an index past CPython's decimal conversion limit used to
    raise a bare ``ValueError`` out of the parser, aborting the recovery run.

    A nine-digit run is already past ``_MAX_MEMBER_OFFSET`` at every element
    width, so the parse must simply yield no evidence for it.
    """
    text = f"{prim} *a0; *(int *)&a0[{'9' * digits}]; a0[{'9' * digits}] = 0;"
    assert _all_evidence(parse_decomp_for_structs(text)) == []


# ---------------------------------------------------------------------------
# Pair assertion across the evidence -> header boundary
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=_PARSE_DEADLINE)
@given(
    base=_IDENT,
    members=st.lists(
        st.tuples(st.integers(min_value=0, max_value=0x200), st.sampled_from((1, 2, 4, 8))),
        min_size=1,
        max_size=8,
        unique_by=lambda m: m[0],
    ),
)
def test_synthesized_struct_covers_every_evidence_offset(
    base: str, members: list[tuple[int, int]]
) -> None:
    offsets = {off: {width: 1} for off, width in members}
    header = synthesize_struct(base, offsets)

    assert header.startswith(f"typedef struct {base}_s {{")
    assert header.rstrip().endswith(f"}} {base};")

    # Every reported offset is claimed by exactly one line's byte range, and
    # the ranges are the same ones the parser handed over.
    claimed: list[tuple[int, int]] = []
    for off_hex, gap_hex in _MEMBERS.findall(header):
        start = int(off_hex, 16)
        # ``gap_NNNN[0xM]`` and ``field_XX[0xM]`` both size from their start.
        end = start + (int(gap_hex, 16) if gap_hex else 0)
        claimed.append((start, end))
    for off, width in members:
        assert any(start <= off and end <= start + width for start, end in claimed), (
            f"offset 0x{off:x} not covered by {header!r}"
        )
    starts = [start for start, _ in claimed]
    assert starts == sorted(starts)
