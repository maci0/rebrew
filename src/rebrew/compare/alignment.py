"""Instruction alignment shared by comparison reports and statement search."""

from __future__ import annotations

import re
from difflib import Match, SequenceMatcher
from typing import Any, override
lazy from collections.abc import Callable, Sequence

lazy import capstone
lazy import numpy as np
lazy from rapidfuzz.distance import LCSseq

lazy from rebrew.binary.analysis import Insn
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
    # on rebrew.binary.analysis is seen by the call that follows.
    from rebrew.binary.analysis import disasm_insns

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


class WindowHashes:
    """Prefix hashes of one token sequence, so every window hash of a range is one array step.

    ``windows(start, end, width)`` equals :func:`_align_window_hashes`'s rolling
    hashes: ``prefix[i + width] - prefix[i] * base**width`` modulo 2**64, which
    ``uint64`` arithmetic wraps to.
    """

    def __init__(self, ids: Sequence[int]) -> None:
        prefix = [0]
        digest = 0
        for token in ids:
            digest = (digest * _ALIGN_HASH_BASE + token) & _ALIGN_HASH_MASK
            prefix.append(digest)
        self.prefix = np.array(prefix, dtype=np.uint64)

    def windows(self, start: int, end: int, width: int) -> np.ndarray[Any, Any]:
        """Hash of every ``ids[i:i+width]`` for ``i`` in ``start .. end-width``."""
        power = np.uint64(pow(_ALIGN_HASH_BASE, width, _ALIGN_HASH_MASK + 1))
        return self.prefix[start + width : end + 1] - self.prefix[start : end - width + 1] * power


def earliest_window(
    left: Sequence[int],
    right: Sequence[int],
    left_hashes: WindowHashes,
    right_hashes: WindowHashes,
    span: tuple[int, int, int, int],
    width: int,
) -> tuple[tuple[int, int, int] | None, int]:
    """:func:`earliest_window_scalar`'s answer and count, from array hashes.

    The right windows are ranked by hash (a stable sort keeps equal hashes in
    address order), each left window finds its run of equal hashes by binary
    search, and the candidates are verified in the scalar scan's order.
    """
    alo, ahi, blo, bhi = span
    if width <= 0 or bhi - blo < width:
        return None, 0
    visits = bhi - blo
    if ahi - alo < width:
        return None, visits
    visits += ahi - alo
    right_h = right_hashes.windows(blo, bhi, width)
    left_h = left_hashes.windows(alo, ahi, width)
    order = np.argsort(right_h, kind="stable")
    ranked = right_h[order]
    first = np.searchsorted(ranked, left_h, "left")
    last = np.searchsorted(ranked, left_h, "right")
    for offset in np.flatnonzero(last > first).tolist():
        origin = alo + offset
        for index in order[first[offset] : last[offset]].tolist():
            start = blo + index
            visits += width
            if left[origin : origin + width] == right[start : start + width]:
                return (origin, start, width), visits
    return None, visits


def earliest_window_scalar(
    left: Sequence[int],
    right: Sequence[int],
    alo: int,
    ahi: int,
    blo: int,
    bhi: int,
    width: int,
) -> tuple[tuple[int, int, int] | None, int]:
    """Earliest ``width`` match, or None, and the token positions read.

    The scalar twin of :func:`earliest_window`, which the alignment runs; the
    differential tests hold the two to the same answer.
    """
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


class AlignedMatcher(SequenceMatcher[str]):
    """``SequenceMatcher(autojunk=False)`` backed by ``rapidfuzz.distance.LCSseq``.

    difflib keeps every copy of a repeated opcode in its index and walks that
    list from every copy on the other side.  On a stream of ``mov`` that is
    quadratic.  ``LCSseq.opcodes`` computes an optimal LCS alignment in C++
    bit-parallel time, feeding its ``equal`` runs into ``SequenceMatcher`` so
    ``get_opcodes()`` / ``ratio()`` / ``quick_ratio()`` keep the standard
    interface.  ``last_visits`` records ``len(a) + len(b)`` as the
    load-independent work count.  Junk and ``autojunk`` fall back to difflib;
    the climb scorer uses neither.

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
        blocks = [
            Match(op.src_start, op.dest_start, op.src_end - op.src_start)
            for op in LCSseq.opcodes(self.a, self.b)
            if op.tag == "equal"
        ]
        blocks.append(Match(len(self.a), len(self.b), 0))
        self.matching_blocks = blocks
        type(self).last_visits = len(self.a) + len(self.b)
        return blocks


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
