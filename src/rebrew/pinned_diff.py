"""pinned_diff.py — SequenceMatcher with known line pins.

Adapted from reccmp (isledecomp/reccmp, MIT License)
``compare/pinned_sequences.py``.

Finds the differences between two string sequences where some
associations (pins) between the lines are known.  The result format is
compatible with ``difflib.SequenceMatcher`` opcodes: each pin splits the
streams into independent islands that are diffed separately, so one big
mismatch in the middle cannot scramble the alignment of the surrounding
known-good spans.

In rebrew this upgrades ``near_diag``'s alignment: byte-identical
instructions that act as reliable anchors become pins, keeping a
structural churn in one block from shifting the classification of every
later block.
"""

from __future__ import annotations

import difflib
import itertools
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field


@dataclass
class DiffOpcode:
    """Same shape as ``difflib`` opcodes, plus per-side line lists.

    ``tag`` is one of ``replace`` / ``delete`` / ``insert`` / ``equal``;
    ``a`` / ``b`` carry the actual lines so callers need not re-slice.
    """

    tag: str
    a_start: int
    a_end: int
    b_start: int
    b_end: int
    a: list[str] = field(default_factory=list)
    b: list[str] = field(default_factory=list)


def get_grouped_opcodes(opcodes: list[DiffOpcode], n: int = 3) -> list[list[DiffOpcode]]:
    """Isolate change clusters by eliminating ``equal`` runs longer than *n*.

    Adapted from reccmp (MIT).  Groups the opcodes the way
    ``difflib.SequenceMatcher.get_grouped_opcodes`` does so a renderer can
    show context around each mismatch without the equal padding flooding it.
    """
    # Split the opcode stream at every non-equal opcode, keeping up to *n*
    # equal lines of context on each side of the changed run.
    groups: list[list[DiffOpcode]] = []
    group: list[DiffOpcode] = []
    for op in opcodes:
        if op.tag == "equal" and op.a_end - op.a_start > 2 * n:
            if group:
                group.append(
                    DiffOpcode("equal", op.a_start, op.a_start + n, op.b_start, op.b_start + n)
                )
                groups.append(group)
            group = [DiffOpcode("equal", op.a_end - n, op.a_end, op.b_end - n, op.b_end)]
            continue
        group.append(op)
    if group and any(op.tag != "equal" for op in group):
        groups.append(group)
    return groups


class SequenceMatcherWithPins:
    """difflib-compatible matcher seeded with known (a_index, b_index) pins.

    Pins must be monotonically non-decreasing on both sides and index into
    ``a`` and ``b``.  Invalid pins (out of range) are silently dropped, as
    in reccmp.  Each consecutive pin pair bounds an island that is diffed
    with a plain ``difflib.SequenceMatcher``; the weighted match ratio sums
    the islands' ratios weighted by island size.
    """

    def __init__(
        self,
        a: Sequence[str],
        b: Sequence[str],
        pinned_lines: Iterable[tuple[int, int]],
    ):
        self.a = list(a)
        self.b = list(b)
        valid_pins = (
            (ai, bi)
            for ai, bi in pinned_lines
            if ai in range(len(self.a)) and bi in range(len(self.b))
        )
        # Anchor the stream ends so pairwise() covers every island.
        pins = list(itertools.chain([(0, 0)], valid_pins, [(len(self.a), len(self.b))]))

        self._opcodes: list[DiffOpcode] = []
        total_lines = 0
        weighted_ratio = 0.0

        for (a0, b0), (a1, b1) in itertools.pairwise(pins):
            if a0 > a1 or b0 > b1:
                raise ValueError(f"Pins are not monotonous: {pinned_lines}")
            a_block = self.a[a0:a1]
            b_block = self.b[b0:b1]
            block_lines = len(a_block) + len(b_block)

            diff = difflib.SequenceMatcher(None, a_block, b_block, autojunk=False)
            for tag, ia0, ia1, ib0, ib1 in diff.get_opcodes():
                self._opcodes.append(
                    DiffOpcode(
                        tag,
                        a0 + ia0,
                        a0 + ia1,
                        b0 + ib0,
                        b0 + ib1,
                        a_block[ia0:ia1],
                        b_block[ib0:ib1],
                    )
                )
            total_lines += block_lines
            weighted_ratio += diff.ratio() * block_lines

        self._ratio = weighted_ratio / total_lines if total_lines else 1.0

    def get_opcodes(self) -> list[DiffOpcode]:
        """The pin-partitioned opcodes (difflib-compatible shape)."""
        return self._opcodes

    def ratio(self) -> float:
        """Size-weighted mean of the per-island match ratios."""
        return self._ratio
