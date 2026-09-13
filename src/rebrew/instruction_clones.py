"""instruction_clones: exact duplicate structure over instruction streams.

This module adds exactly the two things a resemblance score cannot report
about code the project already disassembles:

- **Common runs** (:func:`find_common_runs`): the maximal common runs of
  normalized instructions *inside* two functions, each reported as
  ``(left_va, right_va, length)`` with the matched instruction text, so a
  reader sees which part of one function corresponds to which part of
  another.  A score says the two are alike; this says where.
- **Identical groups** (:func:`cluster_units`): functions whose normalized
  instruction sequence is identical, grouped largest first.  This is what
  makes "these forty functions are the same thunk" visible.

It is **not a second similarity engine**.  Similarity ranking is
``rebrew similar`` (this target, mnemonic histogram) and the sibling
`resembl` project, whose MinHash + LSH index over a persisted cross-project
corpus answers fragment queries that are "a small fragment of a larger
function" and already keys every snippet by the SHA256 of its normalized
code, so identical functions collide there.  rebrew consumes resembl's
scoring core through the optional ``similarity`` extra
(``rebrew.matcher.scoring.code_similarity``).  Everything here is the
opposite case: in-process, exact, one target, no index, no persistence.
Cross-project duplicate detection, near-duplicate clustering, or a fragment
query against a snippet library belongs on resembl; growing an index or a
MinHash inside rebrew would be a second answer to that question.

Normalization
-------------
Keys are built from the diff path's register stripping
(:func:`rebrew.near_diag.normalized_operands`) plus immediate masking, so two
thunks that differ only in the address they jump to land in one cluster.

resembl's ``string_normalize``/``code_tokenize`` normalize too, but they are
not reused here.  Two reasons: resembl is an optional extra
(``pyproject.toml [similarity]``), and a required import would turn
``rebrew similar --cluster`` into a feature that fails on a plain install;
and they produce one flat token stream for a whole snippet, with no
instruction boundaries, which cannot yield the ``(left_va, right_va)``
offsets :func:`find_common_runs` exists to report.

Cost
----
Sub-matching is quadratic in the two functions' instruction counts, which is
why it is a per-pair operation (``rebrew similar <VA> --other <VA>``) and why
:data:`MAX_SUBMATCH_INSTRUCTIONS` refuses a pair of very large functions
instead of grinding through it.  Clustering fingerprints every function once
(linear in total instructions) and stops after :data:`MAX_CLUSTER_CANDIDATES`
functions, reporting how many it skipped rather than truncating silently.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from rebrew.config import FUNCTION_STRUCTURE_JSON
from rebrew.near_diag import disasm_insns, normalized_operands

#: Shortest common instruction run reported by sub-function matching.  A run
#: of fewer instructions is noise: a shared prologue of two or three
#: instructions (``push ebp``/``mov ebp, esp``) says nothing.
MIN_RUN_INSTRUCTIONS = 4

#: Largest instruction count either side of a sub-match pair may have.
#: ``difflib.SequenceMatcher`` is quadratic in the two lengths; a pair of
#: 20k-instruction functions would take minutes, so it is refused.
MAX_SUBMATCH_INSTRUCTIONS = 5000

#: Largest number of functions a corpus cluster pass fingerprints.  Beyond it
#: the pass stops and reports the skipped count.
MAX_CLUSTER_CANDIDATES = 4000

DEFAULT_CS_ARCH = "CS_ARCH_X86"
DEFAULT_CS_MODE = "CS_MODE_32"

#: Immediates and displacements normalised away before comparison: a thunk
#: that jumps to 0x1000 and one that jumps to 0x2000 are the same thunk.
_IMMEDIATE_RE = re.compile(r"\b(?:0x[0-9a-fA-F]+|\d+)\b")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedInsn:
    """One instruction in both its readable and its comparison form.

    Attributes:
        va: Instruction address.
        size: Encoded length in bytes.
        text: Disassembly as ``"mnemonic op_str"``.
        key: Normalized comparison key (registers and immediates masked).
    """

    va: int
    size: int
    text: str
    key: str


@dataclass(frozen=True)
class MatchRun:
    """A maximal common run of normalized instructions.

    Attributes:
        left_va: Address of the run's first instruction in the left function.
        right_va: Same for the right function.
        length: Instruction count (always >= the requested minimum).
        instructions: The matched instruction text, left side, in order.
    """

    left_va: int
    right_va: int
    length: int
    instructions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FunctionUnit:
    """A function's normalized instruction stream.

    Attributes:
        va: Function start VA.
        size: Function byte size from the catalog.
        name: Catalog name (``list_name``/``ghidra_name``), may be empty.
        instructions: Normalized instructions in address order.
    """

    va: int
    size: int
    name: str
    instructions: list[NormalizedInsn]


@dataclass(frozen=True)
class DuplicateCluster:
    """Functions whose normalized instruction sequence is identical.

    Attributes:
        signature: Hex digest of the shared instruction sequence.
        members: Function VAs in the group, ascending.
        size: Member count (the group's size).
        instruction_count: Length of the shared sequence.
        names: Catalog names, parallel to ``members``.
    """

    signature: str
    members: list[int]
    size: int
    instruction_count: int
    names: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


class _InsnView:
    """Minimal ``.op_str`` carrier for the diff path's operand stripper."""

    __slots__ = ("mnemonic", "op_str")

    def __init__(self, op_str: str) -> None:
        self.mnemonic = ""
        self.op_str = op_str


def normalize_operands(op_str: str) -> str:
    """Operand text with registers and immediates replaced by placeholders.

    Registers are masked by the diff path's own stripper (``eax``/``ebx`` →
    ``R``); immediates and displacements collapse to ``IMM``.  The result is
    the comparison key's operand part: it is identical for two instructions
    that differ only in register allocation or in the address they name.
    """
    return _IMMEDIATE_RE.sub("IMM", normalized_operands(_InsnView(op_str)))


def normalized_instructions(
    code: bytes,
    va: int,
    cs_arch: int | str = DEFAULT_CS_ARCH,
    cs_mode: int | str = DEFAULT_CS_MODE,
) -> list[NormalizedInsn]:
    """Disassemble *code* at *va* into normalized instructions."""
    out: list[NormalizedInsn] = []
    for insn in disasm_insns(code, va, cs_arch, cs_mode):
        text = f"{insn.mnemonic} {insn.op_str}".rstrip()
        out.append(
            NormalizedInsn(
                va=insn.va,
                size=insn.size,
                text=text,
                key=f"{insn.mnemonic} {normalize_operands(insn.op_str)}".rstrip(),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Sub-function matching
# ---------------------------------------------------------------------------


def find_common_runs(
    left: list[NormalizedInsn],
    right: list[NormalizedInsn],
    min_run: int = MIN_RUN_INSTRUCTIONS,
) -> list[MatchRun]:
    """Maximal common runs of normalized instructions between two streams.

    Runs come from a longest-common-subsequence alignment of the normalized
    keys, so a run is reported only where the two functions genuinely agree in
    order.  Runs shorter than *min_run* are dropped; no agreement yields an
    empty list (never an exception).

    Raises:
        ValueError: either side exceeds :data:`MAX_SUBMATCH_INSTRUCTIONS`.

    """
    if len(left) > MAX_SUBMATCH_INSTRUCTIONS or len(right) > MAX_SUBMATCH_INSTRUCTIONS:
        raise ValueError(
            f"sub-match refuses {len(left)}x{len(right)} instructions "
            f"(cap {MAX_SUBMATCH_INSTRUCTIONS} per function): the match is quadratic, "
            "split the function or lower the scope"
        )
    if not left or not right:
        return []

    matcher = difflib.SequenceMatcher(
        None,
        [insn.key for insn in left],
        [insn.key for insn in right],
        autojunk=False,
    )
    runs: list[MatchRun] = []
    for block in matcher.get_matching_blocks():
        if block.size < min_run:
            continue
        chunk = left[block.a : block.a + block.size]
        runs.append(
            MatchRun(
                left_va=chunk[0].va,
                right_va=right[block.b].va,
                length=block.size,
                instructions=[insn.text for insn in chunk],
            )
        )
    return runs


# ---------------------------------------------------------------------------
# Corpus clustering
# ---------------------------------------------------------------------------


def _sequence_signature(instructions: list[NormalizedInsn]) -> str:
    """Digest of an instruction stream's normalization (identity key)."""
    payload = "\n".join(insn.key for insn in instructions)
    return hashlib.sha256(payload.encode("utf-8", errors="surrogateescape")).hexdigest()[:16]


def cluster_units(units: list[FunctionUnit], min_size: int = 2) -> list[DuplicateCluster]:
    """Group *units* whose normalized instruction sequence is identical.

    Groups smaller than *min_size* are dropped; the rest are ordered by size
    (largest first) then by lowest member VA, so the output is deterministic.
    """
    if min_size < 2:
        raise ValueError(f"min_size must be at least 2, got {min_size}")
    groups: dict[str, list[FunctionUnit]] = {}
    for unit in units:
        if not unit.instructions:
            continue
        groups.setdefault(_sequence_signature(unit.instructions), []).append(unit)

    clusters: list[DuplicateCluster] = []
    for signature, members in groups.items():
        if len(members) < min_size:
            continue
        members.sort(key=lambda u: u.va)
        clusters.append(
            DuplicateCluster(
                signature=signature,
                members=[u.va for u in members],
                size=len(members),
                instruction_count=len(members[0].instructions),
                names=[u.name for u in members],
            )
        )
    clusters.sort(key=lambda c: (-c.size, c.members[0]))
    return clusters


# ---------------------------------------------------------------------------
# Target-binary loading
# ---------------------------------------------------------------------------


def _cs_pair(cfg: Any) -> tuple[int | str, int | str]:
    return (
        getattr(cfg, "capstone_arch", DEFAULT_CS_ARCH),
        getattr(cfg, "capstone_mode", DEFAULT_CS_MODE),
    )


def _unit_for(
    cfg: Any, va: int, size: int, name: str, cs_arch: Any, cs_mode: Any
) -> FunctionUnit | None:
    from rebrew.binary_loader import extract_raw_bytes

    if size <= 0:
        return None
    code = extract_raw_bytes(cfg.target_binary, va, size)
    if not code:
        return None
    return FunctionUnit(
        va=va,
        size=size,
        name=name,
        instructions=normalized_instructions(code, va, cs_arch, cs_mode),
    )


def _registry(cfg: Any) -> dict[int, Any]:
    from rebrew.catalog import build_function_registry, parse_function_list

    return build_function_registry(
        parse_function_list(cfg.function_list),
        cfg,
        cfg.reversed_dir / FUNCTION_STRUCTURE_JSON,
        cfg.target_binary,
    )


def function_unit(
    cfg: Any,
    va: int,
    size: int | None = None,
    name: str = "",
) -> FunctionUnit | None:
    """Normalized unit for the function at *va*, or ``None`` when unavailable."""
    if size is None:
        entry = _registry(cfg).get(va)
        if entry is None:
            return None
        size = int(entry.get("canonical_size", 0))
        name = name or str(entry.get("list_name") or entry.get("ghidra_name") or "")
    cs_arch, cs_mode = _cs_pair(cfg)
    return _unit_for(cfg, va, size, name, cs_arch, cs_mode)


def load_function_units(
    cfg: Any,
    limit: int = MAX_CLUSTER_CANDIDATES,
) -> tuple[list[FunctionUnit], int]:
    """Normalized units for the target binary's functions.

    Returns ``(units, skipped)`` where *skipped* is the number of eligible
    functions left out because *limit* was reached: an honest count, not a
    silent truncation.
    """
    registry = _registry(cfg)
    cs_arch, cs_mode = _cs_pair(cfg)
    units: list[FunctionUnit] = []
    skipped = 0
    for va, entry in sorted(registry.items()):
        if entry.get("is_thunk"):
            continue
        size = int(entry.get("canonical_size", 0))
        if size <= 0:
            continue
        if len(units) >= limit:
            skipped += 1
            continue
        unit = _unit_for(
            cfg,
            va,
            size,
            str(entry.get("list_name") or entry.get("ghidra_name") or ""),
            cs_arch,
            cs_mode,
        )
        if unit is not None:
            units.append(unit)
    return units, skipped
