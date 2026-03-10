"""scoring.py – Binary comparison and scoring for GA matching.

Provides score_candidate() for computing match quality between target and
candidate function bytes, and diff_functions() for instruction-level diffs.
Uses capstone for x86 disassembly and numpy for vectorized byte comparison.
"""

import difflib
from typing import Any

import capstone
import numpy as np

from .core import Score, StructuralSimilarity

# Default architecture (x86-32).  Functions accept optional arch/mode
# parameters so callers can override without circular config imports.
_DEFAULT_CS_ARCH = capstone.CS_ARCH_X86
_DEFAULT_CS_MODE = capstone.CS_MODE_32

# ---------------------------------------------------------------------------
# Scoring weights — tuned empirically for MSVC6 x86 binary matching.
# ---------------------------------------------------------------------------
# Prologue bytes receive extra weight because matching the function entry
# point is a strong positive signal (calling convention, stack frame setup).
_PROLOGUE_LEN = 20  # first N bytes weighted as prologue
_PROLOGUE_WEIGHT = 3.0  # per-byte weight multiplier for prologue region
_PROLOGUE_BONUS = -100.0  # score bonus when first 20 bytes match exactly

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
    """Zero relocation slots described by explicit relocation offsets."""
    if reloc_offsets is None:
        return code
    out = bytearray(code)
    for ro in reloc_offsets:
        for j in range(pointer_size):
            idx = ro + j
            if 0 <= idx < len(out):
                out[idx] = 0
    return bytes(out)


def _normalize_reloc_x86_32(
    code: bytes,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> bytes:
    """Zero out relocatable fields in x86-32 machine code."""
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    out = bytearray(code)

    for insn in md.disasm(code, 0):
        # call rel32 / jmp rel32 / MOV abs32 (A0-A3)
        if insn.opcode[0] in (0xE8, 0xE9, 0xA0, 0xA1, 0xA2, 0xA3):
            if insn.size >= 5:
                for i in range(1, 5):
                    if insn.address + i < len(out):
                        out[insn.address + i] = 0
        # cmp [abs32], imm8 / conditional jmp near
        elif (insn.opcode[0] == 0x83 and len(insn.bytes) >= 2 and insn.bytes[1] == 0x3D) or (
            insn.opcode[0] == 0x0F and len(insn.bytes) >= 2 and (insn.bytes[1] & 0xF0) == 0x80
        ):
            if insn.size >= 6:
                for i in range(2, 6):
                    if insn.address + i < len(out):
                        out[insn.address + i] = 0
        # push imm32 (if it looks like an address)
        elif insn.opcode[0] == 0x68 or 0xB8 <= insn.opcode[0] <= 0xBF:
            if insn.size >= 5:
                imm = int.from_bytes(insn.bytes[1:5], byteorder="little")
                if imm > 0x10000000:
                    for i in range(1, 5):
                        if insn.address + i < len(out):
                            out[insn.address + i] = 0
        # call/jmp dword ptr [abs32] (FF 15/25) or mov reg,[abs32] / mov [abs32],reg
        elif (
            insn.size >= 6
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
                if insn.address + i < len(out):
                    out[insn.address + i] = 0

        # General fallback: Any instruction with a 32-bit displacement that looks like an address (> 0x10000)
        # Handles SIB+disp32, lea reg, [reg*scale + disp32], and other indirect addressing modes
        if getattr(insn, "disp_size", 0) == 4 and getattr(insn, "disp_offset", 0) > 0:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    disp = op.mem.disp
                    if disp > 0x10000 or disp < -0x10000:
                        offset = insn.address + insn.disp_offset
                        for i in range(4):
                            if offset + i < len(out):
                                out[offset + i] = 0

    return bytes(out)


def _mask_registers_x86_32(
    code: bytes,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> bytes:
    """Mask out register encodings in ModR/M and opcode bytes for register-aware diff."""
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    out = bytearray(code)

    for insn in md.disasm(code, 0):
        modrm_offset = getattr(insn, "modrm_offset", 0)
        if modrm_offset > 0:
            offset = insn.address + modrm_offset
            # Mask out reg (bits 3-5) and rm (bits 0-2), keep mod (bits 6-7)
            out[offset] &= 0xC0

        op0 = insn.opcode[0]
        if (
            (0x40 <= op0 <= 0x5F)  # inc/dec/push/pop reg
            or (0x90 <= op0 <= 0x97)  # xchg eax, reg
            or (0xB8 <= op0 <= 0xBF)  # mov reg, imm32
        ):
            for i in range(insn.size):
                if out[insn.address + i] == op0:
                    out[insn.address + i] &= 0xF8
                    break

    return bytes(out)


def score_candidate(
    target_bytes: bytes,
    candidate_bytes: bytes,
    reloc_offsets: dict[int, str] | list[int] | None = None,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
    pointer_size: int = 4,
) -> Score:
    """Score a candidate against the target bytes."""
    len_diff = abs(len(target_bytes) - len(candidate_bytes))
    min_len = min(len(target_bytes), len(candidate_bytes))

    # Convert to numpy arrays for vectorized comparison
    if min_len > 0:
        t_arr = np.frombuffer(target_bytes[:min_len], dtype=np.uint8)
        c_arr = np.frombuffer(candidate_bytes[:min_len], dtype=np.uint8)
        diff_mask = t_arr != c_arr
    else:
        diff_mask = np.array([], dtype=bool)

    # 1. Byte similarity (weighted towards prologue)
    if min_len > 0:
        weights = np.ones(min_len, dtype=np.float64)
        weights[: min(_PROLOGUE_LEN, min_len)] = _PROLOGUE_WEIGHT
        byte_score = float(np.dot(diff_mask.astype(np.float64), weights))
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
    if reloc_offsets is not None:
        if min_len > 0:
            reloc_mask = np.zeros(min_len, dtype=bool)
            for ro in reloc_offsets:
                for j in range(pointer_size):
                    idx = ro + j
                    if 0 <= idx < min_len:
                        reloc_mask[idx] = True
            reloc_score = float(np.count_nonzero(diff_mask & ~reloc_mask))
    else:
        # Fallback to heuristic normalization
        norm_target = _normalize_reloc_x86_32(target_bytes, cs_arch, cs_mode)
        norm_cand = _normalize_reloc_x86_32(candidate_bytes, cs_arch, cs_mode)
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
    md = capstone.Cs(cs_arch, cs_mode)
    target_mnems = [i.mnemonic for i in md.disasm(target_bytes, 0x1000)]
    cand_mnems = [i.mnemonic for i in md.disasm(candidate_bytes, 0x1000)]

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
    # Scale by instruction coverage to prevent small candidates gaming ratio
    if len(target_mnems) > 0:
        coverage = min(len(cand_mnems), len(target_mnems)) / len(target_mnems)
    else:
        coverage = 1.0

    # Continuity bonus: reward long matching runs
    continuity_bonus = (
        min(_CONTINUITY_CAP, longest_run * _CONTINUITY_PER_INSN)
        if longest_run > _CONTINUITY_MIN_RUN
        else 0.0
    )

    mnemonic_score = ((total_diffed / total_insns) * coverage) * 100.0 - continuity_bonus
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


def diff_functions(
    target_bytes: bytes,
    candidate_bytes: bytes,
    reloc_offsets: dict[int, str] | list[int] | None = None,
    invalid_relocs: list[int] | None = None,
    mismatches_only: bool = False,
    register_aware: bool = False,
    as_dict: bool = False,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
    pointer_size: int = 4,
) -> dict[str, Any] | None:
    """Print a side-by-side diff of target and candidate disassembly.

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
    md = capstone.Cs(cs_arch, cs_mode)

    # Use base address 0 so instruction addresses equal byte offsets
    # (matches _normalize_reloc_x86_32 which also disassembles at base 0).
    target_insns = list(md.disasm(target_bytes, 0))
    cand_insns = list(md.disasm(candidate_bytes, 0))

    if reloc_offsets is not None:
        norm_target = _normalize_with_reloc_offsets(target_bytes, reloc_offsets, pointer_size)
        norm_cand = _normalize_with_reloc_offsets(candidate_bytes, reloc_offsets, pointer_size)
    else:
        norm_target = _normalize_reloc_x86_32(target_bytes, cs_arch, cs_mode)
        norm_cand = _normalize_reloc_x86_32(candidate_bytes, cs_arch, cs_mode)
    reg_norm_target = (
        _mask_registers_x86_32(norm_target, cs_arch, cs_mode) if register_aware else None
    )
    reg_norm_cand = _mask_registers_x86_32(norm_cand, cs_arch, cs_mode) if register_aware else None

    # Build rows with match markers.  When as_dict is True we collect
    # structured dicts and simple counters instead of formatted lines.
    rows: list[tuple[str, str]] = []  # (match_char, formatted_line) — print mode only
    insn_data: list[dict[str, Any]] = []  # populated only when as_dict=True
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
                        # Check if any byte in this instruction is an invalid reloc
                        is_invalid = False
                        if invalid_relocs:
                            for offset in invalid_relocs:
                                # A reloc spans pointer_size bytes, check overlap with this instruction
                                if max(ti.address, offset) < min(
                                    ti.address + ti.size, offset + pointer_size
                                ):
                                    is_invalid = True
                                    break
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
        if match_char == "  " and (t_bytes_hex or c_bytes_hex):
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
        return {
            "target_size": len(target_bytes),
            "candidate_size": len(candidate_bytes),
            "summary": {
                "exact": exact_count,
                "reloc": reloc_count,
                "reg": reg_count,
                "structural": mismatch_count,
                "total": max_insns,
            },
            "instructions": insn_data,
        }

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

    md = capstone.Cs(cs_arch, cs_mode)
    target_mnems = [i.mnemonic for i in md.disasm(target_bytes, 0)]
    cand_mnems = [i.mnemonic for i in md.disasm(candidate_bytes, 0)]
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
