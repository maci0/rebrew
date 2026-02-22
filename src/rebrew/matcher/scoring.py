import capstone
from typing import Optional, Tuple, List
from .core import Score

# Architecture from config (fallback to x86-32)
try:
    from rebrew.config import cfg as _cfg
    _CS_ARCH = _cfg.capstone_arch
    _CS_MODE = _cfg.capstone_mode
except Exception:
    _CS_ARCH = capstone.CS_ARCH_X86
    _CS_MODE = capstone.CS_MODE_32


def _normalize_reloc_x86_32(code: bytes) -> bytes:
    """Zero out relocatable fields in x86-32 machine code."""
    md = capstone.Cs(_CS_ARCH, _CS_MODE)
    md.detail = True
    out = bytearray(code)

    for insn in md.disasm(code, 0):
        # call rel32 / jmp rel32
        if insn.opcode[0] in (0xE8, 0xE9):
            if insn.size >= 5:
                for i in range(1, 5):
                    if insn.address + i < len(out):
                        out[insn.address + i] = 0
        # mov eax, [moffs32]
        elif insn.opcode[0] == 0xA1:
            if insn.size >= 5:
                for i in range(1, 5):
                    if insn.address + i < len(out):
                        out[insn.address + i] = 0
        # cmp [abs32], imm8
        elif insn.opcode[0] == 0x83 and insn.opcode[1] == 0x3D:
            if insn.size >= 6:
                for i in range(2, 6):
                    if insn.address + i < len(out):
                        out[insn.address + i] = 0
        # conditional jumps near (0F 8x)
        elif insn.opcode[0] == 0x0F and (insn.opcode[1] & 0xF0) == 0x80:
            if insn.size >= 6:
                for i in range(2, 6):
                    if insn.address + i < len(out):
                        out[insn.address + i] = 0
        # push imm32 (if it looks like an address)
        elif insn.opcode[0] == 0x68:
            if insn.size >= 5:
                imm = int.from_bytes(insn.bytes[1:5], byteorder="little")
                if imm > 0x10000000:
                    for i in range(1, 5):
                        if insn.address + i < len(out):
                            out[insn.address + i] = 0
        # mov reg, imm32 (if it looks like an address)
        elif 0xB8 <= insn.opcode[0] <= 0xBF:
            if insn.size >= 5:
                imm = int.from_bytes(insn.bytes[1:5], byteorder="little")
                if imm > 0x10000000:
                    for i in range(1, 5):
                        if insn.address + i < len(out):
                            out[insn.address + i] = 0
        # mov reg, [abs32] or mov [abs32], reg
        elif insn.opcode[0] in (0x8B, 0x89):
            if insn.size >= 6 and insn.opcode[1] in (
                0x0D,
                0x15,
                0x1D,
                0x25,
                0x2D,
                0x35,
                0x3D,
            ):
                for i in range(2, 6):
                    if insn.address + i < len(out):
                        out[insn.address + i] = 0

    return bytes(out)


def score_candidate(
    target_bytes: bytes,
    candidate_bytes: bytes,
    reloc_offsets: Optional[List[int]] = None,
) -> Score:
    """Score a candidate against the target bytes."""
    len_diff = abs(len(target_bytes) - len(candidate_bytes))

    # 1. Byte similarity (weighted towards prologue)
    byte_score = 0.0
    min_len = min(len(target_bytes), len(candidate_bytes))
    for i in range(min_len):
        if target_bytes[i] != candidate_bytes[i]:
            weight = 3.0 if i < 20 else 1.0
            byte_score += weight
    byte_score += len_diff * 2.0

    # 2. Relocation-aware similarity
    reloc_score = 0.0
    if reloc_offsets is not None:
        # If we have exact reloc offsets from .obj, use them
        reloc_set = set()
        for ro in reloc_offsets:
            for j in range(4):
                if ro + j < len(candidate_bytes):
                    reloc_set.add(ro + j)

        for i in range(min_len):
            if i in reloc_set:
                continue
            if target_bytes[i] != candidate_bytes[i]:
                reloc_score += 1.0
        reloc_score += len_diff * 1.0
    else:
        # Fallback to heuristic normalization
        norm_target = _normalize_reloc_x86_32(target_bytes)
        norm_cand = _normalize_reloc_x86_32(candidate_bytes)
        for i in range(min_len):
            if norm_target[i] != norm_cand[i]:
                reloc_score += 1.0
        reloc_score += len_diff * 1.0

    # 3. Mnemonic similarity
    md = capstone.Cs(_CS_ARCH, _CS_MODE)
    target_mnems = [i.mnemonic for i in md.disasm(target_bytes, 0x1000)]
    cand_mnems = [i.mnemonic for i in md.disasm(candidate_bytes, 0x1000)]

    import difflib

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
    reloc_offsets: Optional[List[int]] = None,
):
    """Print a side-by-side diff of target and candidate disassembly."""
    md = capstone.Cs(_CS_ARCH, _CS_MODE)

    target_insns = list(md.disasm(target_bytes, 0))
    cand_insns = list(md.disasm(candidate_bytes, 0))

    print(f"\nTarget ({len(target_bytes)}B) vs Candidate ({len(candidate_bytes)}B)")
    print("-" * 80)
    print(
        f"{'Target bytes':20} {'Target disassembly':30} | MS | {'Candidate bytes':20} {'Candidate disassembly'}"
    )
    print("-" * 80)

    reloc_set = set()
    if reloc_offsets:
        for ro in reloc_offsets:
            for j in range(4):
                reloc_set.add(ro + j)

    norm_target = _normalize_reloc_x86_32(target_bytes)
    norm_cand = _normalize_reloc_x86_32(candidate_bytes)

    max_insns = max(len(target_insns), len(cand_insns))
    for i in range(max_insns):
        t_str = ""
        t_bytes = ""
        if i < len(target_insns):
            ti = target_insns[i]
            t_str = f"{ti.mnemonic:6} {ti.op_str}"
            t_bytes = ti.bytes.hex()

        c_str = ""
        c_bytes = ""
        match_char = "  "
        if i < len(cand_insns):
            ci = cand_insns[i]
            c_str = f"{ci.mnemonic:6} {ci.op_str}"
            c_bytes = ci.bytes.hex()

            if i < len(target_insns):
                ti = target_insns[i]
                if ti.bytes == ci.bytes:
                    match_char = "=="
                else:
                    # Check if it's just a relocation difference
                    t_norm = norm_target[ti.address : ti.address + ti.size]
                    c_norm = norm_cand[ci.address : ci.address + ci.size]
                    if t_norm == c_norm and len(t_norm) > 0:
                        match_char = "~~"
                    else:
                        match_char = "**"

        print(f"{t_bytes:20} {t_str:30} | {match_char} | {c_bytes:20} {c_str}")

    print("-" * 80)
    print("== : exact match")
    print("~~ : relocation difference (acceptable)")
    print("** : structural difference")
