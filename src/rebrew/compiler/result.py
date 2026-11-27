"""Structured compile-and-compare verdict types and status classification."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal, Self, cast, get_args
lazy import dataclasses
lazy import math
lazy from collections.abc import Mapping
lazy from pathlib import Path

from rebrew.errors import RebrewError
from rebrew.workspace.status import MATCHED_STATUSES
lazy from rebrew.metadata.functions import canonical_status
lazy from rebrew.utils import read_source_text

#: Status strings :class:`CompareResult` may carry.  Superset of the
#: annotation vocabulary — includes machine outcomes (``COMPILE_ERROR``,
#: ``SIZE_MISMATCH``, …) that ``rebrew test`` / ``rebrew verify`` persist.
CompareStatus = Literal[
    "STUB",
    "EXACT",
    "RELOC",
    "PROVEN",
    "NEAR_MATCHING",
    "SKIP",
    "SIZE_MISMATCH",
    "COMPILE_ERROR",
    "EXTRACT_ERROR",
    "MISSING_SIZE",
    "MISSING_FILE",
    "INVALID_VA",
    "INTERNAL_ERROR",
    "NOT_RUN",
]

#: The same vocabulary at runtime, for validating a status that arrived as
#: data (:meth:`CompareResult.from_dict` on a foreign payload).
_COMPARE_STATUS_VALUES: frozenset[str] = frozenset(get_args(CompareStatus))


class CompareResultError(RebrewError, ValueError):
    """A :class:`CompareResult` was built with self-contradictory fields.

    Only :meth:`CompareResult.__post_init__` raises it: ``matched=True``
    alongside a status that is not a byte match (or the reverse) is a
    programming error in whoever constructed the result.  Carries both
    offending fields so a caller can branch on the data instead of parsing
    the message.  It keeps the ``ValueError`` base, so a pre-existing
    ``except ValueError`` around result construction still works.
    """

    def __init__(
        self,
        message: str,
        *,
        matched: bool = False,
        status: CompareStatus = "INTERNAL_ERROR",
    ) -> None:
        super().__init__(message)
        self.matched = matched
        self.status = status

    STRUCTURED_FIELDS = (*RebrewError.STRUCTURED_FIELDS, "matched", "status")


@dataclass
class CompareResult:
    """Result of a compile-and-compare operation.

    Returned by :func:`compile_and_compare` and consumed by both
    ``rebrew test`` and ``rebrew verify`` so that status/delta/match_percent
    classification is done in one place rather than duplicated.
    """

    matched: bool
    status: CompareStatus
    match_percent: float
    delta: int
    obj_bytes: bytes | None
    reloc_offsets: list[int] | None
    message: str = ""
    inv_reloc_offsets: list[int] = field(default_factory=list)
    full_obj_size: int | None = None
    full_obj_bytes: bytes | None = None
    #: Matching bytes in the compared region. ``None`` when classification never reached a byte compare.
    match_count: int | None = None
    #: Number of differing disassembly lines between the compiled and target bytes (``None`` when not computed).
    diff_lines: int | None = None
    #: Normalized instruction alignment as a percent; never a byte verdict.
    similarity: float | None = None
    #: Matching pairs, instruction counts, hunks, and unit-interval similarity.
    alignment: dict[str, int | float] | None = None
    #: Number of register-encoding-only differing instructions (``None`` on non-x86-32 targets).
    reg_delta: int | None = None
    #: True when the byte delta is entirely register allocation.
    effective_match: bool = False
    #: SHA-256 of the supplied compile context, or ``None`` when compiled bare.
    context_hash: str | None = None
    #: The structured failure behind a ``NOT_RUN``, ``COMPILE_ERROR`` or ``EXTRACT_ERROR`` verdict.
    error: RebrewError | None = None
    #: Operand diagnostics when the target enables known-binding checks.
    relocation_bindings: list[dict[str, Any]] | None = None
    #: Remote compile metadata when a remote backend produced ``obj_bytes``.
    remote_compile: dict[str, Any] | None = None
    #: Instruction-level comparison when requested and not byte-identical.
    instructions: dict[str, Any] | None = None
    #: 32-bit self-relocation field offsets inside the compiled function section.
    self_relocations: dict[int, int] = field(default_factory=dict)
    #: Relocation symbol names keyed by field start offset.
    reloc_symbols: dict[int, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject a ``matched`` flag that contradicts ``status``."""
        if self.matched != (self.status in _BYTE_MATCH_STATUSES):
            raise CompareResultError(
                f"CompareResult matched={self.matched} contradicts status={self.status!r}",
                matched=self.matched,
                status=self.status,
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize comparison result to a JSON-safe dictionary."""
        return {
            "matched": self.matched,
            "status": self.status,
            "match_percent": self.match_percent,
            "match_count": self.match_count,
            "delta": self.delta,
            "message": self.message,
            "reloc_offsets": list(self.reloc_offsets) if self.reloc_offsets is not None else None,
            "inv_reloc_offsets": list(self.inv_reloc_offsets),
            "full_obj_size": self.full_obj_size,
            "diff_lines": self.diff_lines,
            "similarity": self.similarity,
            "alignment": self.alignment,
            "reg_delta": self.reg_delta,
            "effective_match": self.effective_match,
            "context_hash": self.context_hash,
            "error": self.error.to_dict() if self.error is not None else None,
            **(
                {"relocation_bindings": self.relocation_bindings}
                if self.relocation_bindings is not None
                else {}
            ),
            **({"remote_compile": self.remote_compile} if self.remote_compile is not None else {}),
            **({"instructions": self.instructions} if self.instructions is not None else {}),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Construct a :class:`CompareResult` from a dictionary (e.g. from :meth:`to_dict`)."""
        valid_fields = {f.name for f in dataclasses.fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in valid_fields}
        kwargs.setdefault("obj_bytes", None)
        kwargs.setdefault("reloc_offsets", None)
        kwargs.setdefault("message", "")
        status = kwargs.get("status")
        if status not in _COMPARE_STATUS_VALUES:
            raise CompareResultError(
                f"CompareResult.from_dict got status {status!r}, "
                f"expected one of {sorted(_COMPARE_STATUS_VALUES)}",
                matched=bool(kwargs.get("matched", False)),
                status="INTERNAL_ERROR",
            )
        raw_error = kwargs.get("error")
        if isinstance(raw_error, Mapping):
            kwargs["error"] = RebrewError.from_dict(raw_error)
        elif raw_error is not None:
            raise CompareResultError(
                f"CompareResult.from_dict got error {raw_error!r}, "
                "expected None or a serialized error mapping",
                matched=bool(kwargs.get("matched", False)),
                status=cast("CompareStatus", status),
            )
        try:
            return cls(**kwargs)
        except TypeError as exc:
            raise CompareResultError(
                f"CompareResult.from_dict cannot build a result: {exc}",
                matched=bool(kwargs.get("matched", False)),
                status=cast("CompareStatus", status),
            ) from exc


#: Compare statuses that mean the compiled bytes equal the target (after
#: reloc masking).  PROVEN is not a byte match and never sets ``matched``.
_BYTE_MATCH_STATUSES: frozenset[CompareStatus] = frozenset(
    status for status in get_args(CompareStatus) if status in MATCHED_STATUSES
)

#: Match-quality threshold for NEAR_MATCHING vs STUB classification.
NEAR_MATCH_THRESHOLD = 0.60

#: Message prefix a compare step writes before classification knows NEAR_MATCHING from STUB.
UNCLASSIFIED_DIFF = "NEAR_MATCHING/STUB"

#: A candidate body this small against a much larger target is an unimplemented skeleton stub.
_STUB_BODY_MAX_BYTES = 8
_STUB_TARGET_MIN_BYTES = 12


def _result_unavailable(error: RebrewError | None) -> bool:
    """True when *error* came from a remote/unoffered compiler that gave no verdict."""
    from rebrew.compiler.recompile_client import RecompileError
    from rebrew.compiler.toolchain import CompilerNotOffered

    return isinstance(error, (RecompileError, CompilerNotOffered))


def matched_byte_count(
    match_percent: float | None,
    *,
    matched: bool,
    compared_len: int,
    total: int,
    match_count: int | None = None,
) -> int:
    """Reconstruct matching bytes from ``match_percent``, or pass through *match_count*."""
    if matched:
        return total
    if match_count is not None:
        return match_count
    if compared_len <= 0 or match_percent is None or not math.isfinite(match_percent):
        return 0
    return max(0, min(compared_len, math.floor(match_percent / 100.0 * compared_len)))


def comparison_counts(cmp: CompareResult, target_size: int) -> tuple[int, int, int]:
    """``(obj_size, total, match_count)`` of *cmp* against *target_size* target bytes."""
    obj_bytes = cmp.obj_bytes or b""
    obj_size = cmp.full_obj_size if cmp.full_obj_size is not None else len(obj_bytes)
    total = max(target_size, obj_size) if (obj_bytes or target_size) else 0
    match_count = matched_byte_count(
        cmp.match_percent,
        matched=cmp.matched,
        compared_len=len(obj_bytes),
        total=total,
        match_count=cmp.match_count,
    )
    return obj_size, total, match_count


_INLINE_ASM = re.compile(r"\b(?:__asm|_asm|__emit)\b")


def clears_blocker(status: str, source: Path) -> bool:
    """True when a promotion to *status* should clear the function's BLOCKER."""
    if not is_matched(status):
        return False
    try:
        text, _encoding = read_source_text(source)
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Could not read %s to decide whether BLOCKER still documents "
            "inline asm; leaving the blocker in place: %s",
            source,
            exc,
        )
        return False
    return _INLINE_ASM.search(text) is None


def is_matched(status: str) -> bool:
    """True when *status* is byte-matched (EXACT or RELOC; PROVEN is not)."""
    return canonical_status(status) in MATCHED_STATUSES


def classify_match_status(
    matched: bool,
    match_count: int,
    total: int,
    relocs: list[int] | tuple[()] = (),
) -> str:
    """Determine the canonical status string from match results."""
    if matched:
        return "RELOC" if relocs else "EXACT"
    if total > 0 and (match_count / total) >= NEAR_MATCH_THRESHOLD:
        return "NEAR_MATCHING"
    return "STUB"


def classify_compare_result(
    matched: bool,
    msg: str,
    target_bytes: bytes | None,
    obj_bytes: bytes | None,
    reloc_offsets: list[int] | None,
    inv_reloc_offsets: list[int] | None = None,
    *,
    size_mismatch: bool = False,
    size_delta: int = 0,
    full_obj_size: int | None = None,
    full_obj_bytes: bytes | None = None,
    full_target_size: int | None = None,
    error: RebrewError | None = None,
) -> CompareResult:
    """Classify a raw compile-and-compare outcome into a :class:`CompareResult`."""
    inv = inv_reloc_offsets or []
    relocs = reloc_offsets or []

    if matched:
        n = len(target_bytes) if target_bytes is not None else 0
        return CompareResult(
            matched=True,
            status="RELOC" if relocs else "EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=obj_bytes,
            reloc_offsets=relocs,
            message=msg,
            inv_reloc_offsets=inv,
            match_count=n,
            full_obj_size=full_obj_size,
            full_obj_bytes=full_obj_bytes,
        )

    if _result_unavailable(error):
        from rebrew.compiler.toolchain import CompilerNotOffered

        why = "" if isinstance(error, CompilerNotOffered) else " (service unavailable)"
        return CompareResult(
            matched=False,
            status="NOT_RUN",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message=f"not run{why}: {error}",
            match_count=0,
            error=error,
        )

    from rebrew.compiler.toolchain import ToolchainError

    if isinstance(error, ToolchainError):
        return CompareResult(
            matched=False,
            status="NOT_RUN",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message=f"not run (toolchain): {error}",
            match_count=0,
            error=error,
        )

    if "EXTRACT_ERROR" in msg:
        return CompareResult(
            matched=False,
            status="EXTRACT_ERROR",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message=msg,
            match_count=0,
            error=error,
        )

    if "COMPILE_ERROR" in msg or obj_bytes is None:
        return CompareResult(
            matched=False,
            status="COMPILE_ERROR",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message=msg,
            match_count=0,
            error=error,
        )

    if "MISSING" in msg:
        return CompareResult(
            matched=False,
            status="MISSING_SIZE" if "SIZE" in msg else "MISSING_FILE",
            match_percent=0.0,
            delta=0,
            obj_bytes=obj_bytes,
            reloc_offsets=relocs,
            message=msg,
            match_count=0,
        )

    match_percent = 0.0
    delta = 0
    matching_bytes = 0
    if target_bytes is not None:
        import numpy as np

        target_len = len(target_bytes)
        cmp_len = min(target_len, len(obj_bytes))
        t_arr = np.frombuffer(target_bytes[:cmp_len], dtype=np.uint8)
        o_arr = np.frombuffer(obj_bytes[:cmp_len], dtype=np.uint8)
        diff_mask = t_arr != o_arr
        if relocs and cmp_len > 0:
            reloc_mask = np.zeros(cmp_len, dtype=bool)
            for r in relocs:
                if 0 <= r < cmp_len:
                    end = min(r + 4, cmp_len)
                    reloc_mask[r:end] = True
            diff_mask = diff_mask & ~reloc_mask
        mismatches = int(np.count_nonzero(diff_mask))
        matching_bytes = cmp_len - mismatches
        match_percent = (matching_bytes / target_len) * 100 if target_len else 0.0
        delta = abs(len(target_bytes) - len(obj_bytes)) + mismatches + size_delta

    if size_mismatch or "SIZE_MISMATCH" in msg:
        orig_cand = full_obj_size if full_obj_size is not None else len(obj_bytes or b"")
        orig_tgt = full_target_size if full_target_size is not None else len(target_bytes or b"")
        status: CompareStatus
        if (
            obj_bytes is not None
            and orig_cand <= _STUB_BODY_MAX_BYTES
            and orig_tgt >= _STUB_TARGET_MIN_BYTES
            and orig_tgt > orig_cand * 2
        ):
            status = "STUB"
            msg = (
                f"candidate is a minimal {orig_cand}B stub body - the target is "
                f"{orig_tgt}B; the skeleton default was never implemented"
            )
        else:
            status = "SIZE_MISMATCH"
    elif match_percent >= NEAR_MATCH_THRESHOLD * 100:
        status = "NEAR_MATCHING"
        if msg and not msg.startswith("NEAR_MATCHING"):
            msg = f"{msg} - run 'rebrew match flags <file>' to try flag variants"
    else:
        status = "STUB"
    if msg.startswith(UNCLASSIFIED_DIFF):
        msg = status + msg.removeprefix(UNCLASSIFIED_DIFF)

    return CompareResult(
        matched=False,
        status=status,
        match_percent=match_percent,
        delta=delta,
        obj_bytes=obj_bytes,
        reloc_offsets=relocs,
        message=msg,
        inv_reloc_offsets=inv,
        match_count=matching_bytes,
        full_obj_size=full_obj_size,
        full_obj_bytes=full_obj_bytes,
    )
