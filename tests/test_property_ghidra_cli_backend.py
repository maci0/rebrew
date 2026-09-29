"""Property-based fuzz tests for ``rebrew.ghidra.cli_backend`` argv construction.

``apply_commands_via_cli`` is the ``ghidra-cli`` half of rebrew's Ghidra
sync: it turns each op dict into a subprocess argv and runs it.  The op list
normally comes from ``rebrew.ghidra.commands`` in-tree, but the function is
public -- a library consumer drives it with ops it built itself -- so ``tool``
and ``args`` are untrusted values, not a closed schema.  Nothing pinned that:
``args`` was read with a bare ``op.get("args", {}).get(...)``, so a ``None``,
a list, a string or a number in that slot raised ``AttributeError`` out of a
loop whose whole job is to count failures and carry on.

The harnesses draw op dicts over every JSON value and assert:

* ``_op_to_args`` is total -- no op raises, and a rejected op is ``None``
  rather than a half-built argv the caller would still run;
* a known tool whose ``args`` is not a mapping is rejected exactly like an
  unknown tool, while an op with no ``args`` key at all still translates (an
  absent mapping is an empty one);
* a returned argv is all ``str``, opens with its tool's fixed subcommand head,
  and is never short enough to shift a positional into a flag's place;
* address lookup is the same for every alias, so which spelling a producer
  used cannot change what is sent.
"""

from __future__ import annotations

from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.ghidra.cli_backend import _op_args, _op_to_args

#: Each tool's fixed subcommand head and the argv length below which a
#: positional could be missing and shift the rest of the command along.
_HEAD: dict[str, tuple[tuple[str, ...], int]] = {
    "create-function": (("function", "create"), 3),
    "create-label": (("symbol", "create"), 4),
    "set-comment": (("comment", "set"), 4),
    "set-bookmark": (("comment", "set"), 6),
    "parse-c-structure": (("type", "create"), 3),
    "set-function-prototype": (("function", "set-signature"), 6),
}

#: Every JSON value an ``args`` slot can decode to, including the non-mapping
#: ones the op builders never emit but a consumer's decoded payload can.
_JSON_VALUE = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=8), children, max_size=3),
    ),
    max_leaves=5,
)


@st.composite
def _op(draw: st.DrawFn) -> dict[str, Any]:
    """An op dict with a drawn tool and a drawn ``args`` slot."""
    op: dict[str, Any] = {
        "tool": draw(st.one_of(st.sampled_from(sorted(_HEAD)), st.text(max_size=12), st.none()))
    }
    if draw(st.booleans()):
        op["args"] = draw(_JSON_VALUE)
    return op


@settings(max_examples=300, deadline=None)
@given(_op())
def test_op_to_args_is_total_and_well_formed(op: dict[str, Any]) -> None:
    argv = _op_to_args(op)
    if argv is None:
        # Rejected: an unknown or absent tool, or a known tool whose ``args``
        # is not a mapping.  Either way no argv is emitted.
        assert op.get("tool") not in _HEAD or _op_args(op) is None
        return

    head, min_len = _HEAD[op["tool"]]
    assert all(isinstance(a, str) for a in argv)
    assert tuple(argv[: len(head)]) == head
    # A missing field becomes "", never a dropped positional that would shift
    # the next element into its place.
    assert len(argv) >= min_len


@settings(max_examples=300, deadline=None)
@given(st.sampled_from(sorted(_HEAD)), _JSON_VALUE)
def test_a_known_tool_rejects_a_non_mapping_args(tool: str, args: Any) -> None:
    """Every JSON value is an acceptable ``args``; only a dict translates."""
    argv = _op_to_args({"tool": tool, "args": args})
    head, min_len = _HEAD[tool]
    if isinstance(args, dict):
        assert argv is not None
        assert tuple(argv[: len(head)]) == head
        assert len(argv) >= min_len
    else:
        assert argv is None


@settings(max_examples=200, deadline=None)
@given(st.sampled_from(sorted(_HEAD)))
def test_an_empty_args_mapping_still_translates(tool: str) -> None:
    """Absent fields are empty ones, so an empty ``args`` is a usable op."""
    head, min_len = _HEAD[tool]
    argv = _op_to_args({"tool": tool, "args": {}})
    assert argv is not None
    assert tuple(argv[: len(head)]) == head
    assert len(argv) >= min_len


@settings(max_examples=200, deadline=None)
@given(st.sampled_from(["address", "addressOrSymbol", "location"]), st.text(max_size=12))
def test_every_address_alias_reaches_the_same_argv_slot(alias: str, value: str) -> None:
    """Which spelling a producer used cannot change what is sent."""
    assert _op_to_args({"tool": "create-function", "args": {alias: value}}) == [
        "function",
        "create",
        value,
    ]


@settings(max_examples=200, deadline=None)
@given(_op())
def test_translation_is_deterministic(op: dict[str, Any]) -> None:
    assert _op_to_args(op) == _op_to_args(op)
