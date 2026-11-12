"""Instruction alignment shared by comparison reports and statement search."""

from __future__ import annotations

import re
from difflib import Match, SequenceMatcher
from typing import Any, override
lazy from collections.abc import Callable, Sequence

lazy import capstone

lazy from rebrew.analysis import Insn
lazy from rebrew.compiler.compile import CompareResult
lazy from rebrew.config import ProjectConfig

_ADDRESS_RE = re.compile(r"0x[0-9a-f]{6,}")
_SHORT_ADDEND_RE = re.compile(r"\[0x[0-9a-f]{1,5}\]")


def normalize_instruction(insn: Insn) -> str:
    """Instruction text as the alignment compares it.

    Address-sized immediates fold to ``g``, and the operands an object
    carries for a relocation — a bare ``[0]`` or a short addend — fold
    onto ``g`` too, because the target side has the resolved address
    there.  guild-rebrew's ``scripts/seqdiff.py:norm`` applies the same
    folds; without them the aligner paired 624 of the target's
    instructions where the sequence diff pairs 740.
    """
    text = _ADDRESS_RE.sub("g", f"{insn.mnemonic} {insn.op_str}")
    text = text.replace("[0]", "[g]")
    return _SHORT_ADDEND_RE.sub("[g]", text).strip()


def instruction_texts(cfg: ProjectConfig, target_bytes: bytes, section_va: int) -> list[str]:
    """The target's normalized instruction texts, built once per climb.

    Climb caches the target side across candidate swaps. Architecture and
    mode come from the selected target for both sides of every comparison.
    """
    # Imported here, not at module scope, so a test that swaps the disassembler
    # on rebrew.analysis is seen by the call that follows.
    from rebrew.analysis import disasm_insns

    insns = disasm_insns(
        target_bytes,
        section_va,
        getattr(cfg, "capstone_arch", "CS_ARCH_X86"),
        getattr(cfg, "capstone_mode", "CS_MODE_32"),
    )
    return [normalize_instruction(i) for i in insns]


# Rolling-hash base for the aligned-instruction matcher.  64-bit, odd, and
# verified against the tokens themselves, so a collision cannot change a block.
_ALIGN_HASH_BASE = 911382323
_ALIGN_HASH_MASK = (1 << 64) - 1


def _align_token_ids(left: Sequence[Any], right: Sequence[Any]) -> tuple[list[int], list[int]]:
    """Map both sequences onto one dense id space."""
    table: dict[Any, int] = {}

    def convert(seq: Sequence[Any]) -> list[int]:
        out: list[int] = []
        for token in seq:
            number = table.get(token)
            if number is None:
                number = len(table) + 1
                table[token] = number
            out.append(number)
        return out

    return convert(left), convert(right)


def _align_has_adjacent_pair(
    left: Sequence[int], right: Sequence[int], alo: int, ahi: int, blo: int, bhi: int
) -> tuple[bool, int]:
    """Whether a length-2 window in the a-range also occurs in the b-range.

    The second value is the number of token positions read.
    """
    if ahi - alo < 2 or bhi - blo < 2:
        return False, 0
    pairs = {(right[j], right[j + 1]) for j in range(blo, bhi - 1)}
    found = any((left[i], left[i + 1]) in pairs for i in range(alo, ahi - 1))
    return found, (ahi - alo) + (bhi - blo)


def _align_window_hashes(
    ids: Sequence[int], start: int, end: int, width: int
) -> tuple[list[int], int]:
    """Hash of every ``ids[i:i+width]`` for ``i`` in ``start .. end-width``.

    The second value is the number of token positions the rolling hash reads.
    """
    count = end - width - start + 1
    if width <= 0 or count <= 0:
        return [], 0
    base = _ALIGN_HASH_BASE
    mask = _ALIGN_HASH_MASK
    high = pow(base, width - 1, mask + 1)
    digest = 0
    for token in ids[start : start + width]:
        digest = (digest * base + token) & mask
    hashes = [digest]
    for index in range(start + width, end):
        digest = (digest - ids[index - width] * high) & mask
        digest = (digest * base + ids[index]) & mask
        hashes.append(digest)
    return hashes, end - start


def _align_longest_match(
    left: Sequence[int], right: Sequence[int], alo: int, ahi: int, blo: int, bhi: int
) -> tuple[int, int, int, int]:
    """Earliest maximal contiguous match inside the two ranges, plus tokens read.

    Same tie-break as ``difflib.SequenceMatcher.find_longest_match`` with no
    junk: longest block, then the one that starts earliest in *left*, then
    earliest in *right*.  A hash hit is accepted only when the tokens match.
    """
    limit = min(ahi - alo, bhi - blo)
    best_i, best_j, best_k = alo, blo, 0
    visits = 0
    low = 1
    high = limit
    while low <= high:
        width = (low + high) // 2
        found, spent = _align_earliest_window(left, right, alo, ahi, blo, bhi, width)
        visits += spent
        if found is None:
            high = width - 1
        else:
            best_i, best_j, best_k = found
            low = width + 1
    return best_i, best_j, best_k, visits


def _align_earliest_window(
    left: Sequence[int],
    right: Sequence[int],
    alo: int,
    ahi: int,
    blo: int,
    bhi: int,
    width: int,
) -> tuple[tuple[int, int, int] | None, int]:
    """Earliest ``width`` match, or None, and the token positions read."""
    right_hashes, visits = _align_window_hashes(right, blo, bhi, width)
    if not right_hashes:
        return None, visits
    places: dict[int, list[int]] = {}
    for offset, digest in enumerate(right_hashes):
        places.setdefault(digest, []).append(blo + offset)
    left_hashes, spent = _align_window_hashes(left, alo, ahi, width)
    visits += spent
    for offset, digest in enumerate(left_hashes):
        origin = alo + offset
        for start in places.get(digest, ()):
            if left[origin : origin + width] == right[start : start + width]:
                return (origin, start, width), visits + width
            visits += width
    return None, visits


def _align_singleton_blocks(
    left: Sequence[int],
    right_index: dict[int, list[int]],
    alo: int,
    ahi: int,
    blo: int,
    bhi: int,
) -> tuple[list[Match], int]:
    """Length-1 matches in Ratcliff/Obershelp order, plus index probes.

    With no adjacent pair, every match has size 1, and the earliest-i then
    earliest-j rule is one forward scan.  Adjacent size-1 matches cannot occur
    here: they would be a length-2 pair.
    """
    blocks: list[Match] = []
    floor = blo
    visits = 0
    for index in range(alo, ahi):
        places = right_index.get(left[index])
        visits += 1
        if not places:
            continue
        # places is sorted.  The first entry at or after floor is the earliest j.
        lo = 0
        hi = len(places)
        while lo < hi:
            mid = (lo + hi) // 2
            visits += 1
            if places[mid] < floor:
                lo = mid + 1
            else:
                hi = mid
        if lo < len(places) and places[lo] < bhi:
            start = places[lo]
            blocks.append(Match(index, start, 1))
            floor = start + 1
    return blocks, visits


class AlignedMatcher(SequenceMatcher[str]):
    """``SequenceMatcher(autojunk=False)`` blocks without the popular-token scan.

    difflib keeps every copy of a repeated opcode in its index and walks that
    list from every copy on the other side.  On a stream of ``mov`` that is
    quadratic.  ``last_visits`` is the number of token positions the most recent
    alignment examined.  It is the load-independent cost of the match: scheduler
    delay does not change it.  Junk and ``autojunk`` fall back to difflib; the
    climb scorer uses neither.

    The stdlib stub omits the instance attributes ``__init__`` sets, so they are
    declared here and assigned again after ``super().__init__``.
    """

    last_visits: int = 0
    a: Sequence[str]
    b: Sequence[str]
    isjunk: Callable[[str], bool] | None
    autojunk: bool
    matching_blocks: list[Match] | None

    @override
    def __init__(
        self,
        isjunk: Callable[[str], bool] | None = None,
        a: Sequence[str] = "",
        b: Sequence[str] = "",
        autojunk: bool = True,
    ) -> None:
        super().__init__(isjunk, a, b, autojunk)
        self.a = a
        self.b = b
        self.isjunk = isjunk
        self.autojunk = autojunk
        self.matching_blocks = None

    @override
    def get_matching_blocks(self) -> list[Match]:
        if self.matching_blocks is not None:
            return self.matching_blocks
        if self.isjunk is not None or self.autojunk:
            return super().get_matching_blocks()
        left, right = _align_token_ids(self.a, self.b)
        right_index: dict[int, list[int]] = {}
        for index, token in enumerate(right):
            right_index.setdefault(token, []).append(index)
        visits = len(left) + len(right)
        queue = [(0, len(left), 0, len(right))]
        blocks: list[Match] = []
        while queue:
            alo, ahi, blo, bhi = queue.pop()
            paired, spent = _align_has_adjacent_pair(left, right, alo, ahi, blo, bhi)
            visits += spent
            if not paired:
                singles, spent = _align_singleton_blocks(left, right_index, alo, ahi, blo, bhi)
                blocks.extend(singles)
                visits += spent
                continue
            start_i, start_j, size, spent = _align_longest_match(left, right, alo, ahi, blo, bhi)
            visits += spent
            if size:
                blocks.append(Match(start_i, start_j, size))
                if alo < start_i and blo < start_j:
                    queue.append((alo, start_i, blo, start_j))
                if start_i + size < ahi and start_j + size < bhi:
                    queue.append((start_i + size, ahi, start_j + size, bhi))
        blocks.sort()
        collapsed: list[Match] = []
        current_i = current_j = current_size = 0
        for start_i, start_j, size in blocks:
            if current_i + current_size == start_i and current_j + current_size == start_j:
                current_size += size
            else:
                if current_size:
                    collapsed.append(Match(current_i, current_j, current_size))
                current_i, current_j, current_size = start_i, start_j, size
        if current_size:
            collapsed.append(Match(current_i, current_j, current_size))
        collapsed.append(Match(len(left), len(right), 0))
        self.matching_blocks = collapsed
        type(self).last_visits = visits
        return collapsed


def align_texts(target: list[str], candidate: list[str]) -> dict[str, int | float]:
    """Count normalized matching instructions and non-equal alignment hunks."""
    aligner = AlignedMatcher(a=candidate, b=target, autojunk=False)
    pairs = sum(block.size for block in aligner.get_matching_blocks())
    total = len(target) + len(candidate)
    return {
        "aligned_pairs": pairs,
        "target_instructions": len(target),
        "candidate_instructions": len(candidate),
        "hunks": sum(op[0] != "equal" for op in aligner.get_opcodes()),
        "similarity": 2 * pairs / total if total else 0.0,
    }


def measure_alignment(
    cfg: ProjectConfig, target: bytes, candidate: bytes, section_va: int
) -> dict[str, int | float]:
    """Measure full compiled bytes without changing byte comparison semantics."""
    return align_texts(
        instruction_texts(cfg, target, section_va), instruction_texts(cfg, candidate, section_va)
    )


def record_alignment(
    cfg: ProjectConfig,
    result: CompareResult,
    target: bytes,
    section_va: int,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Attach alignment and optional verification evidence to one compiled result."""
    if result.obj_bytes is None:
        return
    candidate = result.full_obj_bytes if result.full_obj_bytes is not None else result.obj_bytes
    try:
        result.alignment = measure_alignment(cfg, target, candidate, section_va)
    except capstone.CsError, ValueError:
        return
    result.similarity = float(result.alignment["similarity"]) * 100
    if evidence is not None:
        evidence.update(result.alignment)
        evidence["similarity"] = result.similarity
