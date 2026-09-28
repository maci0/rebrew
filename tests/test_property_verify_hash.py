"""Property-based fuzz tests for the verify cache's CFLAGS comparison.

``cflags_equivalent`` decides whether a cached verification result may be
re-served.  Both sides are text the user controls: ``current`` comes from the
project config and library overrides, ``stored`` from ``rebrew-verify.json``
on disk.  It tokenizes each with :mod:`shlex`, which raises ``ValueError`` on
an unbalanced quote, so the harness asserts the comparator answers for every
pair rather than propagating a tokenizer error out of the verify pipeline,
and that the answers stay the ones callers rely on: reflexive for a string
that tokenizes, symmetric, and never equivalent across a material difference.
"""

from __future__ import annotations

import shlex

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from rebrew.verify_hash import cflags_equivalent

#: A CFLAGS string with an arbitrary tail: the tail is what decides whether
#: shlex can tokenize the whole string (quotes, controls, truncation).
_cflags = st.text(alphabet=st.characters(min_codepoint=1, max_codepoint=0x7F), max_size=24).map(
    lambda tail: f"/O2 /Gd{tail}"
)


def _tokenizes(text: str) -> bool:
    try:
        shlex.split(text)
    except ValueError:
        return False
    return True


class TestCflagsEquivalent:
    def test_never_raises_and_is_reflexive(self) -> None:
        @given(stored=_cflags, current=_cflags)
        @settings(max_examples=300)
        def check(stored: str, current: str) -> None:
            result = cflags_equivalent(stored, current)
            assert isinstance(result, bool)
            assume(_tokenizes(stored) and _tokenizes(current))
            assert cflags_equivalent(stored, stored)
            assert result == cflags_equivalent(current, stored)

        check()

    def test_empty_side_is_never_equivalent(self) -> None:
        @given(text=_cflags, side=st.sampled_from(["stored", "current"]))
        @settings(max_examples=200)
        def check(text: str, side: str) -> None:
            pair = ("", text) if side == "stored" else (text, "")
            assert not cflags_equivalent(*pair)

        check()

    def test_unterminated_quote_is_a_cache_miss(self) -> None:
        @given(broken=st.sampled_from(['"', "'", '/O2 "x', "/O2 'x", '"']))
        @settings(max_examples=50)
        def check(broken: str) -> None:
            assume(not _tokenizes(broken))
            assert not cflags_equivalent(broken, "/O2")
            assert not cflags_equivalent("/O2", broken)

        check()

    def test_flag_order_does_not_matter_across_groups(self) -> None:
        # /O2 (option) and /Gd (checkbox) are separate groups, so they
        # commute.  Two members of ONE group do not: MSVC takes the last, so
        # ``/O2 /Ot`` and ``/Ot /O2`` are a material difference.
        @given(
            left=st.lists(st.sampled_from(["/O2", "/Gd"]), unique=True, min_size=1, max_size=2),
            right=st.lists(st.sampled_from(["/O2", "/Gd"]), unique=True, min_size=1, max_size=2),
        )
        @settings(max_examples=200)
        def check(left: list[str], right: list[str]) -> None:
            assume(sorted(left) == sorted(right))
            assert cflags_equivalent(" ".join(left), " ".join(right))

        check()

    def test_same_group_order_is_material(self) -> None:
        @given(first=st.sampled_from(["/O2", "/Ot"]), second=st.sampled_from(["/O2", "/Ot"]))
        @settings(max_examples=50)
        def check(first: str, second: str) -> None:
            assume(first != second)
            assert not cflags_equivalent(f"{first} {second}", f"{second} {first}")

        check()
