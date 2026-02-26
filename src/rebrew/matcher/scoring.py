"""scoring.py – Binary comparison and scoring for GA matching.

Provides score_candidate() for computing match quality between target and
candidate function bytes, and diff_functions() for instruction-level diffs.
Uses capstone for x86 disassembly and numpy for vectorized byte comparison.
"""

import difflib
from typing import Any

import capstone
import numpy as np

from .core import Score

# Default architecture (x86-32).  Functions accept optional arch/mode
# parameters so callers can override without circular config imports.
_DEFAULT_CS_ARCH = capstone.CS_ARCH_X86
_DEFAULT_CS_MODE = capstone.CS_MODE_32


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

    return bytes(out)


def score_candidate(
    target_bytes: bytes,
    candidate_bytes: bytes,
    reloc_offsets: list[int] | None = None,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
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
        weights[: min(20, min_len)] = 3.0
        byte_score = float(np.dot(diff_mask.astype(np.float64), weights))
    else:
        byte_score = 0.0

    # 2. Relocation-aware similarity
    reloc_score = 0.0
    if reloc_offsets is not None:
        if min_len > 0:
            reloc_mask = np.zeros(min_len, dtype=bool)
            for ro in reloc_offsets:
                for j in range(4):
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

    # 3. Mnemonic similarity
    md = capstone.Cs(cs_arch, cs_mode)
    target_mnems = [i.mnemonic for i in md.disasm(target_bytes, 0x1000)]
    cand_mnems = [i.mnemonic for i in md.disasm(candidate_bytes, 0x1000)]

    sm = difflib.SequenceMatcher(None, target_mnems, cand_mnems)
    mnemonic_score = (1.0 - sm.ratio()) * 100.0

    # 4. Prologue bonus
    prologue_bonus = 0.0
    if min_len >= 20 and target_bytes[:20] == candidate_bytes[:20]:
        prologue_bonus = -100.0

    total = (
        (len_diff * 3.0)
        + (byte_score * 1000.0)
        + (reloc_score * 500.0)
        + (mnemonic_score * 200.0)
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
    reloc_offsets: list[int] | None = None,
    mismatches_only: bool = False,
    as_dict: bool = False,
    cs_arch: int = _DEFAULT_CS_ARCH,
    cs_mode: int = _DEFAULT_CS_MODE,
) -> dict[str, Any] | None:
    """Print a side-by-side diff of target and candidate disassembly.

    Args:
        mismatches_only: If True, only print lines with structural differences
            (``**`` markers). Equivalent to ``| grep '\\*\\*'`` but built-in.
        as_dict: If True, return a structured dict instead of printing.

    Returns:
        A dict with diff data when ``as_dict`` is True, otherwise None.
    """
    md = capstone.Cs(cs_arch, cs_mode)

    # Use base address 0 so instruction addresses equal byte offsets
    # (matches _normalize_reloc_x86_32 which also disassembles at base 0).
    target_insns = list(md.disasm(target_bytes, 0))
    cand_insns = list(md.disasm(candidate_bytes, 0))

    norm_target = _normalize_reloc_x86_32(target_bytes, cs_arch, cs_mode)
    norm_cand = _normalize_reloc_x86_32(candidate_bytes, cs_arch, cs_mode)

    # Build rows with match markers.  When as_dict is True we collect
    # structured dicts and simple counters instead of formatted lines.
    rows: list[tuple[str, str]] = []  # (match_char, formatted_line) — print mode only
    insn_data: list[dict[str, Any]] = []  # populated only when as_dict=True
    exact_count = 0
    reloc_count = 0
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
                    match_char = "~~" if t_norm == c_norm and len(t_norm) > 0 else "**"

        # Classify unpaired instructions (one side exhausted) as structural diffs
        if match_char == "  " and (t_bytes_hex or c_bytes_hex):
            match_char = "**"

        # Track counts
        if match_char == "==":
            exact_count += 1
        elif match_char == "~~":
            reloc_count += 1
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
        print("** : structural difference")
    print(
        f"Summary: {mismatch_count} structural diff(s), "
        f"{reloc_count} reloc diff(s), "
        f"{exact_count} exact match(es)"
    )
    return None
