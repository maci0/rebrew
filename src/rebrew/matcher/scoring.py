"""scoring.py – Binary comparison and scoring for GA matching.

Provides score_candidate() for computing match quality between target and
candidate function bytes, and diff_functions() for instruction-level diffs.
Uses capstone for x86 disassembly and numpy for vectorized byte comparison.
"""

import difflib
import threading
from typing import Any

import capstone
import numpy as np

from .core import Score, StructuralSimilarity

# Default architecture (x86-32).  Functions accept optional arch/mode
# parameters so callers can override without circular config imports.
_DEFAULT_CS_ARCH = capstone.CS_ARCH_X86
_DEFAULT_CS_MODE = capstone.CS_MODE_32


# Capstone ``Cs`` objects wrap a libcapstone handle whose internal state is
# mutated on every ``disasm`` call, so a single instance cannot be shared
# across threads safely.  ``score_candidate`` runs concurrently in
# ``flag_sweep`` / ``BinaryMatchingGA`` worker pools; per-thread caching keeps
# the construction-elision win without inviting handle-level races.
_cs_tls = threading.local()


def _get_cs(cs_arch: int, cs_mode: int, *, detail: bool = False) -> capstone.Cs:
    """Return a per-thread cached Capstone disassembler instance.

    Each thread keeps its own dict keyed by (arch, mode, detail) so that
    repeated calls in the GA scoring hot path skip the ``capstone.Cs``
    constructor without sharing a mutable handle across workers.
    """
    cache: dict[tuple[int, int, bool], capstone.Cs] | None = getattr(_cs_tls, "cache", None)
    if cache is None:
        cache = {}
        _cs_tls.cache = cache
    key = (cs_arch, cs_mode, detail)
    md = cache.get(key)
    if md is None:
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = detail
        cache[key] = md
    return md


# ---------------------------------------------------------------------------
# Scoring weights — tuned empirically for MSVC6 x86 binary matching.
# ---------------------------------------------------------------------------
# Prologue bytes receive extra weight because matching the function entry
# point is a strong positive signal (calling convention, stack frame setup).
_PROLOGUE_LEN = 20  # first N bytes weighted as prologue
_PROLOGUE_WEIGHT = 3.0  # per-byte weight multiplier for prologue region
_PROLOGUE_BONUS = -100.0  # score reduction (improvement) when first 20 bytes match exactly

# Continuity bonus caps the reward for long matching mnemonic runs,
# preventing a single long match from overwhelming all other signals.
_CONTINUITY_CAP = 20.0  # maximum continuity bonus (points)
_CONTINUITY_PER_INSN = 0.5  # bonus per instruction in longest matching run
_CONTINUITY_MIN_RUN = 4  # minimum run length to qualify for bonus

# Final score = weighted sum of component scores.  Lower is better.
# These weights control the relative importance of each signal:
_WEIGHT_LEN_DIFF = 3.0  # per missing/extra byte
_WEIGHT_BYTE = 1000.0  # per raw byte difference (weighted)
_WEIGHT_RELOC = 500.0  # per reloc-normalized byte difference
_WEIGHT_MNEMONIC = 200.0  # per mnemonic-level difference (0-100 scale)


def _normalize_with_reloc_offsets(
    code: bytes, reloc_offsets: dict[int, str] | list[int] | None, pointer_size: int = 4
) -> bytes:
    """Zero relocation slots described by explicit relocation offsets.

    For each offset, zeros ``pointer_size`` consecutive bytes starting at
    that position.  When *reloc_offsets* is a dict, only the integer keys
    are used; the symbol-name values are ignored.
    """
    if reloc_offsets is None:
        return code
    out = bytearray(code)
    code_len = len(out)
    for ro in reloc_offsets:
        start = max(0, ro)
        end = min(ro + pointer_size, code_len)
        if start < end:
            out[start:end] = b"\x00" * (end - start)
    return bytes(out)


def _build_invalid_reloc_mask(
    code: bytes, invalid_relocs: list[int] | None, pointer_size: int = 4
) -> list[bool]:
    """Return a per-byte boolean mask of the invalid relocation spans in *code*.

    Each invalid reloc marks ``pointer_size`` consecutive bytes starting at
    its offset.  Used by :func:`diff_functions` so the overlap test per
    instruction is O(1) instead of scanning every invalid reloc.
    """
    if not invalid_relocs:
        return []
    mask = [False] * len(code)
    for ro in invalid_relocs:
        start = max(0, ro)
        end = min(ro + pointer_size, len(code))
        if start < end:
            for i in range(start, end):
                mask[i] = True
    return mask


def _zero_reloc_fields(insn: capstone.CsInsn, out: bytearray) -> None:
    """Zero the relocatable fields of one detail-disassembled x86-32 insn.

    Shared by :func:`_normalize_reloc_x86_32` and
    :func:`_normalize_and_mnems_x86_32` (the GA hot path merges normalization
    and mnemonic extraction into ONE candidate disassembly).

    Hot-path notes (the GA scores thousands of candidates): every relocatable
    field is a 32-bit immediate/displacement, so an instruction shorter than
    5 bytes can never carry one — those return before any attribute access
    (capstone attribute reads are the per-instruction cost).
    """
    size = insn.size
    if size < 5:
        return  # no room for a 32-bit relocatable field
    addr = insn.address
    # call rel32 / jmp rel32 / MOV abs32 (A0-A3)
    if insn.opcode[0] in (0xE8, 0xE9, 0xA0, 0xA1, 0xA2, 0xA3):
        if size >= 5:
            for i in range(1, 5):
                if addr + i < len(out):
                    out[addr + i] = 0
    # cmp [abs32], imm8 / conditional jmp near
    elif (insn.opcode[0] == 0x83 and len(insn.bytes) >= 2 and insn.bytes[1] == 0x3D) or (
        insn.opcode[0] == 0x0F and len(insn.bytes) >= 2 and (insn.bytes[1] & 0xF0) == 0x80
    ):
        if size >= 6:
            for i in range(2, 6):
                if addr + i < len(out):
                    out[addr + i] = 0
    # push imm32 (if it looks like an address)
    elif insn.opcode[0] == 0x68 or 0xB8 <= insn.opcode[0] <= 0xBF:
        if size >= 5:
            imm = int.from_bytes(insn.bytes[1:5], byteorder="little")
            if imm > 0x10000000:
                for i in range(1, 5):
                    if addr + i < len(out):
                        out[addr + i] = 0
    # call/jmp dword ptr [abs32] (FF 15/25) or mov reg,[abs32] / mov [abs32],reg
    elif (
        size >= 6
        and len(insn.bytes) >= 2
        and (
            (insn.opcode[0] == 0xFF and insn.bytes[1] in (0x15, 0x25))
            or (
                insn.opcode[0] in (0x8B, 0x89)
                and insn.bytes[1]
                in (
                    0x05,
                    0x0D,
                    0x15,
                    0x1D,
                    0x25,
                    0x2D,
                    0x35,
                    0x3D,
                )
            )
        )
    ):
        for i in range(2, 6):
            if addr + i < len(out):
                out[addr + i] = 0

    # General fallback: Any instruction with a 32-bit displacement that looks like an address (> 0x10000)
    # Handles SIB+disp32, lea reg, [reg*scale + disp32], and other indirect addressing modes.
    # A 32-bit displacement needs at least 6 bytes (opcode + modrm + disp32), so
    # smaller instructions skip the detail attribute reads entirely.
    if size >= 6 and insn.disp_size == 4 and insn.disp_offset > 0:
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                disp = op.mem.disp
                if disp > 0x10000 or disp < -0x10000:
                    offset = addr + insn.disp_offset
                    for i in range(4):
                        if offset + i < len(out):
                            out[offset + i] = 0


def _normalize_reloc_x86_32(
    code: bytes,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> bytes:
    """Zero out relocatable fields in x86-32 machine code."""
    md = _get_cs(cs_arch, cs_mode, detail=True)
    out = bytearray(code)
    for insn in md.disasm(code, 0):
        _zero_reloc_fields(insn, out)
    return bytes(out)


def _normalize_and_mnems_x86_32(
    code: bytes,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> tuple[bytes, list[str]]:
    """Normalize relocatable fields AND collect mnemonics in ONE disassembly.

    The GA/flag-sweep hot path needs both (heuristic reloc scoring +
    mnemonic similarity) but disassembled the candidate twice: once with
    ``detail=True`` for normalization, once without for mnemonics.  The
    mnemonic list does not depend on the address base or detail mode, so a
    single pass serves both.

    Hot-path note: detail mode builds per-instruction operand objects (the
    GA scores thousands of candidates), so the normalization here runs on a
    NON-detail disassembly using raw instruction bytes — the four opcode
    branches of :func:`_zero_reloc_fields` only need ``bytes``/``size``/
    ``address`` and an opcode byte that is cheaply recoverable from the raw
    bytes (legacy prefixes skipped).  Instructions that could carry a 32-bit
    displacement (the rare SIB/disp32 fallback, which needs detail
    attributes) are re-disassembled individually with a detail handle.
    """
    md = _get_cs(cs_arch, cs_mode, detail=False)
    md_det = _get_cs(cs_arch, cs_mode, detail=True)
    out = bytearray(code)
    mnems: list[str] = []
    for insn in md.disasm(code, 0):
        mnems.append(insn.mnemonic)
        _zero_reloc_fields_raw(insn, out, md_det)
    return bytes(out), mnems


#: x86 legacy prefixes — skipped to recover the first real opcode byte from
#: raw instruction bytes (capstone's ``opcode[0]`` skips them too).
_PREFIX_BYTES: frozenset[int] = frozenset(
    (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF2, 0xF3)
)


def _first_opcode_byte(insn_bytes: bytes) -> int:
    """The first real opcode byte of *insn_bytes* (legacy prefixes skipped).

    Equivalent to ``capstone.CsInsn.opcode[0]`` for the opcode set
    :func:`_zero_reloc_fields_raw` checks — x86-32 has no REX/VEX, so the
    legacy prefix set is complete.
    """
    for b in insn_bytes:
        if b not in _PREFIX_BYTES:
            return b
    return insn_bytes[0] if insn_bytes else 0


def _has_disp32(insn_bytes: bytes) -> bool:
    """Cheap superset test: could this instruction carry a 32-bit displacement?

    Mirrors the ModR/M/SIB conditions under which capstone reports
    ``disp_size == 4``: mod=10 (disp32), mod=00 with rm=101 (absolute disp32),
    or a SIB byte with mod=00 base=101 / mod=10.  A superset is safe — false
    positives only cost a redundant detail re-check.
    """
    i = 0
    n = len(insn_bytes)
    while i < n and insn_bytes[i] in _PREFIX_BYTES:
        i += 1
    if i >= n:
        return False
    op0 = insn_bytes[i]
    if op0 == 0x0F and i + 1 < n:  # two-byte opcode (0F xx): modrm follows
        i += 1
    i += 1
    if i >= n:
        return False
    modrm = insn_bytes[i]
    mod, rm = modrm >> 6, modrm & 7
    if mod == 0b10:
        return True
    if mod == 0b00 and rm == 0b101:
        return True
    if rm == 0b100 and i + 1 < n:  # SIB byte follows
        base = insn_bytes[i + 1] & 7
        if mod == 0b00 and base == 0b101:
            return True
        if mod == 0b10:
            return True
    return False


def _zero_reloc_fields_raw(insn: capstone.CsInsn, out: bytearray, md_det: capstone.Cs) -> None:
    """Non-detail variant of :func:`_zero_reloc_fields`.

    Reads opcode bytes directly from ``insn.bytes`` (no detail attribute
    access) for the four common reloc patterns.  Instructions that could
    carry a 32-bit displacement (the detail-only fallback) are re-disassembled
    with *md_det* and delegated to :func:`_zero_reloc_fields` — identical
    semantics, detail work limited to the rare cases.
    """
    size = insn.size
    if size < 5:
        return  # no room for a 32-bit relocatable field
    addr = insn.address
    b = insn.bytes
    op0 = _first_opcode_byte(b)
    # call rel32 / jmp rel32 / MOV abs32 (A0-A3)
    if op0 in (0xE8, 0xE9, 0xA0, 0xA1, 0xA2, 0xA3):
        for i in range(1, 5):
            if addr + i < len(out):
                out[addr + i] = 0
        return
    # cmp [abs32], imm8 / conditional jmp near
    if (op0 == 0x83 and len(b) >= 2 and b[1] == 0x3D) or (
        op0 == 0x0F and len(b) >= 2 and (b[1] & 0xF0) == 0x80
    ):
        if size >= 6:
            for i in range(2, 6):
                if addr + i < len(out):
                    out[addr + i] = 0
        return
    # push imm32 (if it looks like an address)
    if op0 == 0x68 or 0xB8 <= op0 <= 0xBF:
        imm = int.from_bytes(b[1:5], byteorder="little")
        if imm > 0x10000000:
            for i in range(1, 5):
                if addr + i < len(out):
                    out[addr + i] = 0
        return
    # call/jmp dword ptr [abs32] (FF 15/25) or mov reg,[abs32] / mov [abs32],reg
    if (
        size >= 6
        and len(b) >= 2
        and (
            (op0 == 0xFF and b[1] in (0x15, 0x25))
            or (
                op0 in (0x8B, 0x89)
                and b[1]
                in (
                    0x05,
                    0x0D,
                    0x15,
                    0x1D,
                    0x25,
                    0x2D,
                    0x35,
                    0x3D,
                )
            )
        )
    ):
        for i in range(2, 6):
            if addr + i < len(out):
                out[addr + i] = 0
        return

    # Rare SIB/disp32 fallback — needs detail attributes; re-disassemble just
    # this instruction and apply the original detail-based logic verbatim.
    if size >= 6 and _has_disp32(b):
        for det in md_det.disasm(b, addr):
            _zero_reloc_fields(det, out)


def _mask_registers_inplace(insns: list[capstone.CsInsn], buf: bytearray) -> None:
    """Apply the register-encoding mask to *buf* using ALREADY-disassembled
    (detail) instructions — the old path re-disassembled each side inside
    ``_mask_registers_x86_32``, adding two detail passes per diff.

    Mask semantics are identical: reg (bits 3-5) and rm (bits 0-2) of the
    ModR/M byte are cleared (mod bits kept), and the opcode byte of
    inc/dec/push/pop-reg, xchg-reg, and mov-reg-imm32 instructions has its
    register field masked.
    """
    for insn in insns:
        modrm_offset = insn.modrm_offset
        if modrm_offset > 0:
            offset = insn.address + modrm_offset
            if offset < len(buf):
                buf[offset] &= 0xC0

        op0 = insn.opcode[0]
        if (
            (0x40 <= op0 <= 0x5F)  # inc/dec/push/pop reg
            or (0x90 <= op0 <= 0x97)  # xchg eax, reg
            or (0xB8 <= op0 <= 0xBF)  # mov reg, imm32
        ):
            for i in range(insn.size):
                if buf[insn.address + i] == op0:
                    buf[insn.address + i] &= 0xF8
                    break


def _mask_registers_x86_32(
    code: bytes,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> bytes:
    """Mask out register encodings in ModR/M and opcode bytes for register-aware diff."""
    md = _get_cs(cs_arch, cs_mode, detail=True)
    out = bytearray(code)
    _mask_registers_inplace(list(md.disasm(code, 0)), out)
    return bytes(out)


def score_candidate(
    target_bytes: bytes,
    candidate_bytes: bytes,
    reloc_offsets: dict[int, str] | list[int] | None = None,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
    pointer_size: int = 4,
    *,
    _pre_norm_target: bytes | None = None,
    _pre_target_mnems: list[str] | None = None,
) -> Score:
    """Score a candidate against the target bytes.

    Optional keyword-only args for hot-path callers (GA engine):
        _pre_norm_target: Pre-computed ``_normalize_reloc_x86_32(target_bytes)``.
        _pre_target_mnems: Pre-computed mnemonic list from target disassembly.
    """
    len_diff = abs(len(target_bytes) - len(candidate_bytes))
    min_len = min(len(target_bytes), len(candidate_bytes))

    # Exact-match fast path: identical bytes make every metric zero except the
    # prologue bonus (target[:N] == candidate[:N] trivially).  Skipping the
    # candidate disassembly and the numpy compares is a large win in converged
    # GA populations, where many members are byte-identical copies.
    if target_bytes == candidate_bytes:
        prologue_bonus = _PROLOGUE_BONUS if min_len >= _PROLOGUE_LEN else 0.0
        return Score(
            length_diff=0,
            byte_score=0.0,
            reloc_score=0.0,
            mnemonic_score=0.0,
            prologue_bonus=prologue_bonus,
            total=prologue_bonus,
        )

    # Convert to numpy arrays for vectorized comparison
    if min_len > 0:
        t_arr = np.frombuffer(target_bytes[:min_len], dtype=np.uint8)
        c_arr = np.frombuffer(candidate_bytes[:min_len], dtype=np.uint8)
        diff_mask = t_arr != c_arr
    else:
        diff_mask = np.array([], dtype=bool)

    # Relocation mask — a reloc'd call/jmp/ptr displacement is
    # linker-determined, not source-determined, so its bytes are not a
    # source-level mismatch.  Built once and applied to BOTH the byte and
    # reloc scores.  (Excluding them from byte_score too was the missing
    # half: every reloc-bearing candidate previously sat at a byte_score
    # floor of ~N reloc bytes, so the GA/flag-sweep `exact: score < 0.1`
    # gate could never accept a RELOC match — it kept mutating a perfect
    # candidate and sweeps reported no match.)
    reloc_mask: np.ndarray | None = None
    if reloc_offsets is not None and min_len > 0:
        reloc_mask = np.zeros(min_len, dtype=bool)
        # Vectorized span marking: every reloc covers [ro, ro + pointer_size),
        # so build one index array from all offsets at once instead of
        # slicing per offset in a Python loop.
        if isinstance(reloc_offsets, dict):
            offsets = np.asarray(list(reloc_offsets), dtype=np.int64)
        else:
            offsets = np.asarray(reloc_offsets, dtype=np.int64)
        if offsets.size:
            idx = (offsets[:, None] + np.arange(pointer_size)).ravel()
            idx = idx[(idx >= 0) & (idx < min_len)]
            if idx.size:
                reloc_mask[idx] = True

    # 1. Byte similarity (weighted towards prologue) — reloc sites excluded
    if min_len > 0:
        byte_diff = diff_mask & ~reloc_mask if reloc_mask is not None else diff_mask
        prologue_len = min(_PROLOGUE_LEN, min_len)
        prologue_diffs = np.count_nonzero(byte_diff[:prologue_len])
        body_diffs = np.count_nonzero(byte_diff[prologue_len:])
        byte_score = float(prologue_diffs * _PROLOGUE_WEIGHT + body_diffs)
    else:
        byte_score = 0.0

    # Penalize missing bytes as full mismatches (weight 1.0 each).
    # Without this, deleting N bytes saves ~N×1000 in byte_score but only
    # costs N×3 via len_diff — making deletion 333× cheaper than fixing
    # wrong bytes.  Adding len_diff here makes deletion cost ~1003 per byte,
    # on par with having wrong bytes (~1000 per byte).
    byte_score += float(len_diff)

    # 2. Relocation-aware similarity
    reloc_score = 0.0
    cand_mnems: list[str] | None = None
    target_mnems: list[str] | None = None
    if reloc_offsets is not None:
        if min_len > 0 and reloc_mask is not None:
            # byte_diff (diff_mask & ~reloc_mask) was already computed above —
            # reuse it instead of recomputing the boolean AND per candidate.
            reloc_score = float(np.count_nonzero(byte_diff))
    else:
        # Fallback to heuristic normalization — reuse pre-computed target if
        # available.  The merged detail disasm yields BOTH the normalized
        # bytes and the mnemonic list, replacing the previous two candidate
        # disassemblies (detail normalize + plain mnemonics) — and the target
        # mnemonic list is carried here too, so no second target disasm.
        if _pre_norm_target is not None:
            norm_target = _pre_norm_target
            norm_cand, cand_mnems = _normalize_and_mnems_x86_32(candidate_bytes, cs_arch, cs_mode)
        else:
            norm_target, target_mnems = _normalize_and_mnems_x86_32(target_bytes, cs_arch, cs_mode)
            norm_cand, cand_mnems = _normalize_and_mnems_x86_32(candidate_bytes, cs_arch, cs_mode)
        if min_len > 0:
            nt_arr = np.frombuffer(norm_target[:min_len], dtype=np.uint8)
            nc_arr = np.frombuffer(norm_cand[:min_len], dtype=np.uint8)
            reloc_score = float(np.count_nonzero(nt_arr != nc_arr))

    # 3. Mnemonic similarity — instruction-aligned scoring
    #
    # Instead of a single global ratio, use get_opcodes() to identify
    # contiguous matching blocks.  This rewards long matching runs and
    # penalises isolated insertions/deletions more precisely.
    # A single extra PUSH at the top no longer tanks the entire score.
    md = _get_cs(cs_arch, cs_mode)
    # Reuse pre-computed target mnemonics if available (GA hot path); the
    # candidate mnemonics may already exist from the merged reloc-fallback
    # disassembly above, and the target mnemonics from the same pass.
    # ``disasm_lite`` returns (addr, size, mnemonic, op_str) tuples instead of
    # CsInsn objects — identical output at ~2.7x the speed (no per-instruction
    # ctypes objects), which matters here: the GA scores thousands of
    # candidates per run and this disasm dominates the call.
    target_mnems = (
        _pre_target_mnems
        if _pre_target_mnems is not None
        else target_mnems
        if target_mnems is not None
        else [m for (_a, _s, m, _o) in md.disasm_lite(target_bytes, 0x1000)]
    )
    if cand_mnems is None:
        cand_mnems = [m for (_a, _s, m, _o) in md.disasm_lite(candidate_bytes, 0x1000)]

    # Fast path: identical mnemonic sequences (the GA's common case — bytes
    # differ only in immediates/reloc slots, e.g. `mov eax, 0x10` vs
    # `mov eax, 0x20`).  SequenceMatcher on equal lists emits exactly one
    # `equal` opcode covering everything, so this shortcut is byte-identical
    # to the full walk while skipping difflib's O(n) setup entirely.
    if target_mnems == cand_mnems:
        total_matched = len(target_mnems)
        total_diffed = 0
        longest_run = len(target_mnems)
    else:
        sm = difflib.SequenceMatcher(None, target_mnems, cand_mnems)

        # Walk opcodes: reward contiguous equal blocks, penalise diffs
        total_matched = 0
        total_diffed = 0
        longest_run = 0
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                run_len = i2 - i1
                total_matched += run_len
                longest_run = max(longest_run, run_len)
            else:
                # replace, insert, delete — count both sides
                total_diffed += max(i2 - i1, j2 - j1)

    total_insns = max(len(target_mnems), len(cand_mnems), 1)
    # NOTE: no coverage multiplier here.  total_diffed already counts every
    # missing target instruction (the delete opcode adds max(i2-i1, j2-j1)),
    # so shortfall is penalized directly.  Multiplying by coverage
    # min(cand,target)/len(target) made a short candidate's ratio *smaller*
    # (better) — the opposite of the intended penalty.

    # Continuity bonus: reward long matching runs
    continuity_bonus = (
        min(_CONTINUITY_CAP, longest_run * _CONTINUITY_PER_INSN)
        if longest_run > _CONTINUITY_MIN_RUN
        else 0.0
    )

    mnemonic_score = (total_diffed / total_insns) * 100.0 - continuity_bonus
    mnemonic_score = max(0.0, mnemonic_score)  # floor at 0

    # 4. Prologue bonus
    prologue_bonus = 0.0
    if min_len >= _PROLOGUE_LEN and target_bytes[:_PROLOGUE_LEN] == candidate_bytes[:_PROLOGUE_LEN]:
        prologue_bonus = _PROLOGUE_BONUS

    total = (
        (len_diff * _WEIGHT_LEN_DIFF)
        + (byte_score * _WEIGHT_BYTE)
        + (reloc_score * _WEIGHT_RELOC)
        + (mnemonic_score * _WEIGHT_MNEMONIC)
        + prologue_bonus
    )

    return Score(
        length_diff=len_diff,
        byte_score=byte_score,
        reloc_score=reloc_score,
        mnemonic_score=mnemonic_score,
        prologue_bonus=prologue_bonus,
        total=total,
    )


def precompute_target(
    target_bytes: bytes,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> tuple[bytes, list[str]]:
    """Pre-compute target normalization and mnemonics for GA hot path.

    Returns (norm_target, target_mnems) to pass as ``_pre_norm_target``
    and ``_pre_target_mnems`` to ``score_candidate()``.

    Delegates to :func:`_normalize_and_mnems_x86_32`: the old
    implementation normalized with a ``detail=True`` pass and then
    re-disassembled the same bytes via ``disasm_lite`` for the mnemonic
    list — two full disassemblies of the target per GA run.  The combined
    pass produces byte-identical normalization and the same mnemonics in
    one disassembly (verified against the old split pass).
    """
    return _normalize_and_mnems_x86_32(target_bytes, cs_arch, cs_mode)


def diff_functions(
    target_bytes: bytes,
    candidate_bytes: bytes,
    reloc_offsets: dict[int, str] | list[int] | None = None,
    invalid_relocs: list[int] | None = None,
    mismatches_only: bool = False,
    register_aware: bool = False,
    as_dict: bool = False,
    summary_only: bool = False,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
    pointer_size: int = 4,
) -> dict[str, Any] | None:
    r"""Diff target and candidate disassembly side-by-side.

    When ``as_dict`` is False (default), prints the diff to stdout and
    returns ``None``.  When ``as_dict`` is True, suppresses printing and
    returns a structured dict.  When ``summary_only`` is True (implies
    ``as_dict``), the per-instruction rows are skipped and the return dict
    carries only ``summary`` plus ``mnemonics`` — the fast path for callers
    that need just the counts (structural_similarity).

    Args:
        target_bytes: Ground-truth target bytes.
        candidate_bytes: Compiled candidate bytes.
        reloc_offsets: Optional list/dict of known relocation offsets.
        invalid_relocs: Optional list of invalid relocation offsets.
        mismatches_only: If True, only print lines with structural differences
            (``**`` markers). Equivalent to ``| grep '\\*\\*'`` but built-in.
        register_aware: Highlight register allocation differences (RR markers).
        as_dict: If True, return a structured dict instead of printing.
        cs_arch: Capstone architecture (default x86).
        cs_mode: Capstone mode (default 32-bit).
        pointer_size: Pointer size in bytes (default 4).

    Returns:
        A dict with diff data when ``as_dict`` is True, otherwise None.

    """
    md = _get_cs(cs_arch, cs_mode)

    if reloc_offsets is not None:
        # Disassemble at base 0 so instruction addresses equal byte offsets
        # in the human-readable diff output.
        target_insns = list(md.disasm(target_bytes, 0))
        cand_insns = list(md.disasm(candidate_bytes, 0))
        norm_target = _normalize_with_reloc_offsets(target_bytes, reloc_offsets, pointer_size)
        norm_cand = _normalize_with_reloc_offsets(candidate_bytes, reloc_offsets, pointer_size)
    else:
        # Reloc-less diff: a NON-detail disassembly serves the rows; the
        # norm buffers are zeroed from raw bytes (_zero_reloc_fields_raw,
        # the GA fast path) so detail mode is only entered when the
        # register-aware mask needs modrm/opcode attributes.
        if register_aware:
            md_det = _get_cs(cs_arch, cs_mode, detail=True)
            target_insns = list(md_det.disasm(target_bytes, 0))
            cand_insns = list(md_det.disasm(candidate_bytes, 0))
        else:
            target_insns = list(md.disasm(target_bytes, 0))
            cand_insns = list(md.disasm(candidate_bytes, 0))
        norm_target_buf = bytearray(target_bytes)
        norm_cand_buf = bytearray(candidate_bytes)
        # Cached detail handle for the rare SIB/disp32 fallback in the raw
        # zeroing (only actually disassembles when such an instruction appears).
        _md_det_fallback = _get_cs(cs_arch, cs_mode, detail=True)
        for insn in target_insns:
            _zero_reloc_fields_raw(insn, norm_target_buf, _md_det_fallback)
        for insn in cand_insns:
            _zero_reloc_fields_raw(insn, norm_cand_buf, _md_det_fallback)
        norm_target = bytes(norm_target_buf)
        norm_cand = bytes(norm_cand_buf)
    if register_aware and norm_target:
        _t_buf = bytearray(norm_target)
        _mask_registers_inplace(target_insns, _t_buf)
        reg_norm_target = bytes(_t_buf)
    else:
        reg_norm_target = None
    if register_aware and norm_cand:
        _c_buf = bytearray(norm_cand)
        _mask_registers_inplace(cand_insns, _c_buf)
        reg_norm_cand = bytes(_c_buf)
    else:
        reg_norm_cand = None

    # Precompute a boolean "invalid reloc" byte mask once instead of scanning
    # invalid_relocs per instruction (O(insns × invalid_relocs) → O(bytes)).
    invalid_mask = _build_invalid_reloc_mask(target_bytes, invalid_relocs, pointer_size)

    # Build rows with match markers.  When as_dict is True we collect
    # structured dicts and simple counters instead of formatted lines.
    # summary_only (used by structural_similarity, which needs only the
    # counts + mnemonics) skips the per-instruction hex/disasm/dict building
    # entirely — that overhead was significant in the verify hot path.
    rows: list[tuple[str, str]] = []  # (match_char, formatted_line) — populated in print mode
    insn_data: list[dict[str, Any]] = []  # populated only when as_dict=True
    target_mnems: list[str] = []
    cand_mnems: list[str] = []
    exact_count = 0
    reloc_count = 0
    invalid_reloc_count = 0
    reg_count = 0
    mismatch_count = 0
    max_insns = max(len(target_insns), len(cand_insns))
    for i in range(max_insns):
        t_bytes_hex = ""
        t_disasm = ""
        t_str = ""
        if i < len(target_insns):
            ti = target_insns[i]
            target_mnems.append(ti.mnemonic)
            if not summary_only:
                t_bytes_hex = ti.bytes.hex()
                t_disasm = f"{ti.mnemonic} {ti.op_str}".strip()
                if not as_dict:
                    t_str = f"{ti.mnemonic:6} {ti.op_str}"

        c_bytes_hex = ""
        c_disasm = ""
        c_str = ""
        match_char = "  "
        if i < len(cand_insns):
            ci = cand_insns[i]
            cand_mnems.append(ci.mnemonic)
            if not summary_only:
                c_bytes_hex = ci.bytes.hex()
                c_disasm = f"{ci.mnemonic} {ci.op_str}".strip()
                if not as_dict:
                    c_str = f"{ci.mnemonic:6} {ci.op_str}"

            if i < len(target_insns):
                ti = target_insns[i]
                if ti.bytes == ci.bytes:
                    match_char = "=="
                else:
                    t_norm = norm_target[ti.address : ti.address + ti.size]
                    c_norm = norm_cand[ci.address : ci.address + ci.size]
                    if t_norm == c_norm and t_norm:
                        # Check if any byte in this instruction overlaps an
                        # invalid reloc span (O(1) via the precomputed mask).
                        is_invalid = bool(invalid_mask) and any(
                            invalid_mask[ti.address : ti.address + ti.size]
                        )
                        match_char = "XX" if is_invalid else "~~"
                    elif (
                        register_aware and reg_norm_target is not None and reg_norm_cand is not None
                    ):
                        t_reg = reg_norm_target[ti.address : ti.address + ti.size]
                        c_reg = reg_norm_cand[ci.address : ci.address + ci.size]
                        match_char = "RR" if (t_reg == c_reg and t_reg) else "**"
                    else:
                        match_char = "**"

        # Classify unpaired instructions (one side exhausted) as structural diffs
        if match_char == "  " and (i < len(target_insns) or i < len(cand_insns)):
            match_char = "**"

        # Track counts
        if match_char == "==":
            exact_count += 1
        elif match_char == "~~":
            reloc_count += 1
        elif match_char == "XX":
            invalid_reloc_count += 1
            mismatch_count += 1
        elif match_char == "RR":
            reg_count += 1
        elif match_char == "**":
            mismatch_count += 1

        if summary_only:
            continue
        if as_dict:
            insn_data.append(
                {
                    "index": i,
                    "match": match_char.strip() or None,
                    "target": {"bytes": t_bytes_hex, "disasm": t_disasm} if t_bytes_hex else None,
                    "candidate": {"bytes": c_bytes_hex, "disasm": c_disasm}
                    if c_bytes_hex
                    else None,
                }
            )
        else:
            line = f"{t_bytes_hex:20} {t_str:30} | {match_char} | {c_bytes_hex:20} {c_str}"
            rows.append((match_char, line))

    if as_dict:
        payload: dict[str, Any] = {
            "target_size": len(target_bytes),
            "candidate_size": len(candidate_bytes),
            "summary": {
                "exact": exact_count,
                "reloc": reloc_count,
                "reg": reg_count,
                "structural": mismatch_count,
                "total": max_insns,
            },
        }
        if summary_only:
            # structural_similarity needs the mnemonics too — collected during
            # the same pass, so it avoids re-disassembling both sides.
            payload["mnemonics"] = {"target": target_mnems, "candidate": cand_mnems}
        else:
            payload["instructions"] = insn_data
        return payload

    # Print header
    print(f"\nTarget ({len(target_bytes)}B) vs Candidate ({len(candidate_bytes)}B)")
    if mismatches_only:
        print(f"Showing {mismatch_count} structural differences only (** lines)")
    print("-" * 80)
    print(
        f"{'Target bytes':20} {'Target disassembly':30} | MS | "
        f"{'Candidate bytes':20} {'Candidate disassembly'}"
    )
    print("-" * 80)

    for match_char, line in rows:
        if mismatches_only and match_char != "**":
            continue
        print(line)

    print("-" * 80)
    if not mismatches_only:
        print("== : exact match")
        print("~~ : relocation difference (acceptable)")
        if register_aware:
            print("RR : register encoding difference")
        print("** : structural difference")
    print(
        f"Summary: {mismatch_count} structural diff(s), "
        f"{reg_count} register diff(s), "
        f"{reloc_count} reloc diff(s), {invalid_reloc_count} invalid reloc(s), "
        f"{exact_count} exact match(es)"
    )
    return None


def structural_similarity(
    target_bytes: bytes,
    candidate_bytes: bytes,
    reloc_offsets: dict[int, str] | list[int] | None = None,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
    pointer_size: int = 4,
) -> StructuralSimilarity:
    """Compute structural similarity to distinguish flag-fixable vs structural diffs."""
    summary = diff_functions(
        target_bytes,
        candidate_bytes,
        reloc_offsets,
        register_aware=True,
        as_dict=True,
        summary_only=True,
        cs_arch=cs_arch,
        cs_mode=cs_mode,
        pointer_size=pointer_size,
    )
    if summary is None:
        raise RuntimeError(
            "diff_functions(as_dict=True) returned None — indicates a bug in the scoring pipeline"
        )

    s = summary["summary"]
    total = s["total"]
    exact = s["exact"]
    reloc = s["reloc"]
    reg = s["reg"]
    structural = s["structural"]

    # Mnemonics come from the same pass (summary_only collects them) — no
    # second disassembly of either side.
    mnemonic_map = summary.get("mnemonics") or {}
    target_mnems = mnemonic_map.get("target")
    cand_mnems = mnemonic_map.get("candidate")
    if not target_mnems or not cand_mnems:
        md = _get_cs(cs_arch, cs_mode)
        target_mnems = [m for (_a, _s, m, _o) in md.disasm_lite(target_bytes, 0)]
        cand_mnems = [m for (_a, _s, m, _o) in md.disasm_lite(candidate_bytes, 0)]
    sm = difflib.SequenceMatcher(None, target_mnems, cand_mnems)
    mnemonic_ratio = sm.ratio()

    structural_ratio = structural / total if total > 0 else 0.0

    # Flag-sensitive heuristic: Why do we care about flag sensitivity?
    # We want to avoid running a full 20-minute GA flag sweep if the issue is a
    # genuine source code structural mismatch (like a missing 'if' statement).
    # If the only differences are register allocation choices (RR), flags won't help.
    # If the code is wildly different (low mnemonic ratio), flags won't help.
    # We only run sweeps when the structure is close, but has small fixable differences.
    flag_sensitive = structural > 0 and structural_ratio < 0.5 and mnemonic_ratio > 0.80

    return StructuralSimilarity(
        total_insns=total,
        exact=exact,
        reloc_only=reloc,
        register_only=reg,
        structural=structural,
        mnemonic_match_ratio=round(mnemonic_ratio, 4),
        structural_ratio=round(structural_ratio, 4),
        flag_sensitive=flag_sensitive,
    )


def _nasm_text(code: bytes, md: capstone.Cs) -> str:
    """Render *code* as NASM-ish assembly text, one instruction per line.

    Resembl's scoring core tokenizes *assembly text* (via a Pygments NASM
    lexer), so rebrew's byte buffers are rendered to text before scoring.
    Each capstone instruction becomes ``<mnemonic> <op_str>`` on its own
    line — the operand grammar capstone emits is close enough to NASM for
    the lexer to classify registers/immediates/labels correctly.
    """
    lines: list[str] = []
    for insn in md.disasm(code, 0):
        op = insn.op_str
        lines.append(f"{insn.mnemonic} {op}".rstrip())
    return "\n".join(lines)


def code_similarity(
    target_bytes: bytes,
    candidate_bytes: bytes,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> float:
    """Structural similarity (0–100) between two function byte buffers.

    Delegates to the ``resembl`` scoring core: both buffers are disassembled
    and rendered to assembly text, whose tokens are normalized (registers →
    ``REG``, immediates → ``IMM``, memory sizes → ``MEM_SIZE``), shingled,
    and compared as a hybrid of weighted Jaccard (over shingles) and a
    text-level ratio — exactly this project's customary
    ``score_hybrid(jaccard, ratio)`` blend.  The result is robust to register
    allocation and immediate-value differences that raw byte comparison (and
    ``match_percent``) are blind to.

    100.0 means the normalized structure is identical.  Returns
    ``None``-eligible via the caller only if the lazier path is unavailable:
    this function returns a plain float and is ``try/except``-wrapped by
    callers for best-effort use (import of ``resembl`` is optional).

    Raises ``RuntimeError`` when the optional ``resembl`` dependency is not
    installed (guarded import, mirroring ``prove.py``'s optional ``angr``).
    """
    if target_bytes == candidate_bytes:
        return 100.0
    try:
        # Lazy import: the heavy_db surface of resembl stays unloaded unless
        # this scoring path actually runs, so plain rebrew uses (and tests
        # that don't exercise similarity) never pay for it.
        from rapidfuzz import fuzz
        from resembl.scoring import (
            _minhash_from_tokens,
            code_tokenize,
            minhash_jaccard,
            minhash_pack,
            score_hybrid,
        )
    except ImportError as exc:
        raise RuntimeError(
            "code_similarity requires the optional 'resembl' dependency "
            "(uv pip install -e .[similarity])"
        ) from exc

    md = _get_cs(cs_arch, cs_mode)
    text_a = _nasm_text(target_bytes, md)
    text_b = _nasm_text(candidate_bytes, md)
    if not text_a or not text_b:
        # One side has no instructions (empty/undecodable) — nothing to
        # compare structurally beyond the byte-equality fast path above.
        return 0.0 if text_a or text_b else 100.0
    ma = _minhash_from_tokens(code_tokenize(text_a))
    mb = _minhash_from_tokens(code_tokenize(text_b))
    jaccard = minhash_jaccard(minhash_pack(ma), minhash_pack(mb))
    ratio = float(fuzz.ratio(text_a, text_b))
    return float(round(score_hybrid(float(jaccard), ratio, 0.4), 1))
