"""asm.py – Disassemble and export function bytes from the target binary.

Two output formats controlled by ``--format``:

* ``hex``  (default) — capstone disassembly with hex dump and optional call
  annotation.  Suitable for quick interactive triage.

* ``nasm`` — NASM-reassembleable source with round-trip verification.
  Round-trip guarantee: ``nasm -f bin output.asm`` → byte-identical to original.
  Instructions NASM encodes differently are replaced with ``db`` directives.

``--inline-c`` wraps the NASM output as an exact-bytes naked C skeleton
(``__asm _emit`` on MSVC / ``__asm__(".byte ...")`` on GCC — raw bytes, no
assembler-encoding risk) behind the ``REBREW_ALLOW_NAKED`` fence, with a
plain-C fallback for the comparison build and a ``// SIZE`` annotation so
the file is self-contained for ``rebrew test`` (iterate with
``--cflags /DREBREW_ALLOW_NAKED``; round-trip uses the naked branch via
``rebrew round-trip --allow-naked``).

Usage:
    rebrew asm 0x10003ca0 --size 77
    rebrew asm 0x10003ca0 --size 77 --format nasm -o func.asm
    rebrew asm 0x10003ca0 --size 77 --format nasm --inline-c -o func.c
    rebrew asm --all --out-dir output/asm/ --format nasm
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.catalog import load_function_structure
from rebrew.cli import (
    DISPLAY_STATUSES,
    EXIT_ERROR,
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.sources import (
    iter_sources,
    target_marker,
)

console = Console(stderr=True)
logger = logging.getLogger(__name__)

# Pre-compiled regex for sanitizing NASM labels (used in disassemble_to_nasm).
_NASM_LABEL_RE = re.compile(r"[^a-zA-Z0-9_]")

# Per-instruction hint patterns (_hint_for runs for every disassembled insn).
_ESP_HINT_OPS = frozenset({"lea", "cmp", "add", "sub", "mov", "push", "and", "or", "xor", "test"})
_ESP_REF_RE = re.compile(r"\[esp")
_IAT_ABS_RE = re.compile(r"dword ptr \[0x[0-9a-fA-F]+\]")
# `mov reg, [esp+X]` — the load half of the IAT-forwarder push pair.
_ESP_LOAD_RE = re.compile(r"^[a-z0-9]+, dword ptr \[esp")
_JMP_TABLE_RE = re.compile(r"dword ptr \[[a-z0-9]+\s*\*\s*4")
_BYTE_TABLE_FETCH_RE = re.compile(r"byte ptr \[[a-z0-9]+\s*\+\s*0x")

# ---------------------------------------------------------------------------
# Shared disassembly helper
# ---------------------------------------------------------------------------


def disasm_bytes(code_bytes: bytes, va: int, cfg: ProjectConfig | None = None) -> str:
    """Disassemble *code_bytes* starting at *va* and return a formatted string.

    Each line: ``  {address:08X}  {hex_bytes:20s}  {mnemonic:6s} {operands}``

    Uses ``cfg.capstone_arch``/``cfg.capstone_mode`` when *cfg* is provided;
    falls back to 32-bit x86.

    Shared by any module that needs a quick human-readable disassembly
    representation without the full hex-mode output of :func:`_run_hex_mode`.
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError as exc:
        raise RuntimeError("capstone not installed") from exc

    arch = cfg.capstone_arch if cfg is not None else CS_ARCH_X86
    mode = cfg.capstone_mode if cfg is not None else CS_MODE_32
    md = Cs(arch, mode)
    lines = []
    for insn in md.disasm(code_bytes, va):
        hex_bytes = insn.bytes.hex()
        lines.append(f"  {insn.address:08X}  {hex_bytes:20s}  {insn.mnemonic:6s} {insn.op_str}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Hex / capstone mode helpers
# ---------------------------------------------------------------------------


def build_function_lookup(cfg: ProjectConfig) -> dict[int, tuple[str, str]]:
    """Build a VA → (name, status) lookup from Ghidra JSON and existing .c files."""
    lookup: dict[int, tuple[str, str]] = {}

    ghidra_json = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
    ghidra_funcs = load_function_structure(ghidra_json)
    for func in ghidra_funcs:
        if func.va and func.name:
            lookup[func.va] = (func.name, "")

    src_dir = Path(cfg.reversed_dir)
    if src_dir.is_dir():
        for cfile in iter_sources(src_dir, cfg):
            try:
                entries = parse_c_file_multi(
                    cfile, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
                )
                for entry in entries:
                    symbol = (entry.symbol or "").lstrip("_")
                    display = symbol or cfile.stem
                    lookup[entry.va] = (display, entry.status)
            except (OSError, KeyError, ValueError, TypeError):
                continue

    return lookup


def _build_import_map(bin_path: Path) -> dict[int, str]:
    """IAT slot VA -> import name, best-effort."""
    try:
        from rebrew.imports import parse_import_table

        return parse_import_table(bin_path)
    except Exception:  # recon aid, never block disasm
        logger.debug("import map build failed for %s", bin_path, exc_info=True)
        return {}


def _build_string_map(bin_path: Path) -> dict[int, str]:
    """String start VA -> decoded text, best-effort (ASCII and UTF-16)."""
    try:
        from rebrew.analysis import iter_strings
        from rebrew.binary_loader import load_binary

        info = load_binary(bin_path)
        strings = iter_strings(info, min_len=4)
        if not strings:
            # Binaries without data sections (synthetic test PEs) keep
            # strings inside .text — scan it as a fallback.
            strings = iter_strings(info, min_len=4, section_names=[".text"])
        return {s.va: s.text for s in strings}
    except Exception:
        logger.debug("string map build failed for %s", bin_path, exc_info=True)
        return {}


def _hint_for(insns: list[Any], i: int) -> str | None:
    """Return a decompiler-relevant annotation for ``insns[i]``, or None.

    These are the codegen idioms that repeatedly cost time during manual
    decompilation — recognizing them up front avoids trial-and-error C.
    """
    insn = insns[i]
    m = insn.mnemonic
    ops = insn.op_str

    # EH-ctor prolog: `mov eax, imm32; call <helper>` — the compiler-
    # generated __eh_ctor registration pattern (58 functions in the mspaint
    # corpus).  Not C-reproducible: skip or document, don't decompile.
    if m == "call" and i >= 1:
        prev = insns[i - 1]
        if (
            prev.mnemonic == "mov"
            and prev.op_str.startswith("eax, ")
            and prev.op_str.split(",")[1].strip().startswith("0x")
        ):
            return (
                "EH-ctor prolog (compiler-generated __eh_ctor) — not C-reproducible, skip/document"
            )

    # `lea reg, [esp+X]` / `cmp [esp+X], imm` in naked asm: MASM folds these
    # into short/disp8 encodings that do NOT match MSVC's `8d 44 24 XX`
    # disp8 forms — force the bytes with _emit (a recurring naked-asm
    # mismatch in the mspaint corpus).
    if m in _ESP_HINT_OPS and _ESP_REF_RE.search(ops):
        return (
            "esp-relative disp8 in naked asm — MASM folds to a short form; "
            "force the exact encoding with _emit if the bytes differ"
        )

    # Post-decrement loop counter: mov r1,r2 / dec r2 / test r1 / jcc
    if m in ("je", "jne", "jg", "jle", "ja", "jae", "jb", "jbe") and i >= 3:
        t = insns[i - 1]
        d = insns[i - 2]
        mv = insns[i - 3]
        if t.mnemonic == "test" and d.mnemonic == "dec" and mv.mnemonic == "mov":
            t_op = t.op_str.split(",")[0].strip()
            d_op = d.op_str.split(",")[0].strip()
            mv_dst = mv.op_str.split(",")[0].strip()
            mv_src = mv.op_str.split(",")[1].strip()
            if t_op == mv_dst and d_op == mv_src:
                return "post-decrement counter — write while(x-- > 0)"

    # SEH prologue: push ebp-frame stuff + push -1 + push handler... mov reg, fs:[0]
    if m == "mov" and "fs:[0]" in ops and i >= 3:
        for j in range(max(0, i - 6), i):
            if insns[j].mnemonic == "push" and insns[j].op_str == "-1":
                return "SEH prologue (__try/__except) — compiler-generated, not C-reproducible"

    # CRT word-at-a-time strlen/strcpy magic constant
    if m == "mov" and "0x7efefeff" in ops:
        return "CRT strlen/strcpy word-at-a-time — asm implementation"

    # movsx = char promoted to int when passed to a function
    if m == "movsx":
        return "char promoted to int — callee param is int, not char"

    # Direct memory word increment — requires a declared global symbol in C
    if m == "inc" and "word ptr" in ops:
        return "word-global inc — C needs a declared global symbol (cast-deref won't match)"

    # IAT forwarding stub: an indirect call through an IAT slot preceded by
    # several `mov reg,[esp+X]; push reg` pairs is an N-arg forwarder to an
    # imported (usually stdcall) function.  The forwarder's own convention
    # is cdecl (plain ret) while the callee cleans — declare a __stdcall
    # function pointer for the call or MSVC emits a spurious `add esp,N`.
    if m == "call" and _IAT_ABS_RE.search(ops):
        push_count = 0
        # An IAT forwarder pushes ARGUMENTS RELOADED FROM THE STACK
        # (`mov reg,[esp+X]; push reg` — including final bare pushes of
        # registers loaded earlier).  A plain `push imm` / `push reg`
        # argument call is not a forwarder and must not be labeled.
        run: list[tuple[str, str]] = []
        j = i - 1
        while j >= 0 and j >= i - 16 and insns[j].mnemonic in ("mov", "push"):
            run.append((insns[j].mnemonic, insns[j].op_str))
            j -= 1
        run.reverse()  # forward order
        loaded: set[str] = set()
        for mn, op in run:
            if mn == "push":
                if op.strip() in loaded:
                    push_count += 1
            elif _ESP_LOAD_RE.search(op):
                loaded.add(op.split(",")[0].strip())
        if push_count >= 3:
            return (
                f"{push_count}-arg IAT forwarder — declare a __stdcall function "
                "pointer for the call (the callee cleans; the forwarder is cdecl)"
            )

    # Jump-table switch dispatch: jmp dword ptr [reg*4 + 0x...]
    if m == "jmp" and _JMP_TABLE_RE.search(ops):
        # Two-level (byte-compressed) form: the index is fetched from a
        # byte table first (mov dl, byte ptr [reg + 0x...]) — MSVC uses
        # this for sparse switches with shared handlers, and a plain C
        # switch often does NOT reproduce it (the compiler may pick a
        # direct table instead).  Warn so the user doesn't chase the
        # lowering difference after writing the obvious switch.
        for j in range(max(0, i - 5), i):
            prev = insns[j]
            if prev.mnemonic == "mov" and _BYTE_TABLE_FETCH_RE.search(prev.op_str):
                return (
                    "byte-compressed switch (two-level dispatch) — decode with "
                    "`rebrew switch <va>`; a plain C switch may not reproduce this"
                )
        return "switch dispatch (jump table) — decode the case table with `rebrew switch <va>`"

    # `cmp reg,1; sbb reg,reg` (+ optional inc) — MSVC's equality-boolean
    # lowering (x == 0 → -1/0, or with inc → 0/1 for `!x`).  Plain C
    # compiles these to a different epilogue under MSVC5 (neg/sbb/neg/dec
    # or setcc) — a naked-asm function needs the exact bytes.
    if m == "sbb" and i >= 1:
        prev = insns[i - 1]
        if prev.mnemonic == "cmp" and prev.op_str.split(",")[-1].strip() in ("1", "0x1"):
            return (
                "equality-boolean idiom (cmp 1/sbb) — `!x`/`x==0` lowering; "
                "plain C may compile to a different epilogue, write it in naked asm"
            )

    return None


def detect_function_pattern(cfg: ProjectConfig, va: int) -> str | None:
    """Return the decomp-relevant codegen pattern for the function at *va*,
    or ``None`` for plain code.  Function-level counterpart to ``_hint_for``:
    the recognizable categories that decide skip-vs-decompile up front.
    Best-effort (any disassembly failure → None).  x86-32 only."""
    if getattr(cfg, "arch", "") != "x86_32" or not cfg.target_binary.exists():
        return None
    try:
        from rebrew.binary_loader import extract_raw_bytes

        raw = extract_raw_bytes(cfg.target_binary, va, 64)
        if not raw:
            return None
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        insns = list(md.disasm(raw, va))
        if not insns:
            return None

        i0 = insns[0]
        # Import thunk: jmp [IAT] (1-2 insns total).
        if i0.mnemonic == "jmp" and "[" in i0.op_str and "0x" in i0.op_str:
            return "import thunk (jmp [IAT]) — linker glue, not a decomp target"
        # EH-ctor: mov eax, imm32; call helper.
        if (
            len(insns) >= 2
            and i0.mnemonic == "mov"
            and i0.op_str.startswith("eax, ")
            and i0.op_str.split(",")[1].strip().startswith("0x")
            and insns[1].mnemonic == "call"
        ):
            return "EH-ctor prolog (__eh_ctor) — not C-reproducible"
        # Switch dispatch anywhere in the window.
        if any(
            x.mnemonic == "jmp" and re.search(r"dword ptr \[[a-z0-9]+\s*\*\s*4", x.op_str)
            for x in insns
        ):
            return "switch dispatch (jump table)"
        # IAT forwarder: ≥3 pushes of stack-loaded args + call [IAT]
        # (+ ret after).  A plain `push imm`/`push reg` argument call is
        # not a forwarder and must not be labeled.
        call = next((x for x in reversed(insns) if x.mnemonic == "call"), None)
        if call and re.search(r"dword ptr \[0x[0-9a-fA-F]+\]", call.op_str):
            ci = insns.index(call)
            run: list[tuple[str, str]] = []
            j = ci - 1
            while j >= 0 and j >= ci - 12 and insns[j].mnemonic in ("mov", "push"):
                run.append((insns[j].mnemonic, insns[j].op_str))
                j -= 1
            run.reverse()  # forward order
            loaded: set[str] = set()
            pushes = 0
            for mn, op in run:
                if mn == "push":
                    if op.strip() in loaded:
                        pushes += 1
                elif _ESP_LOAD_RE.search(op):
                    loaded.add(op.split(",")[0].strip())
            if pushes >= 3:
                return f"IAT forwarder ({pushes}-arg) — stdcall callee; the forwarder is cdecl"
    except Exception:  # best-effort pattern tag
        logger.debug("pattern scan failed at 0x%08x", va, exc_info=True)
        return None
    return None


def ret_pop_count(op_str: str) -> int:
    """The immediate of a ``ret N`` operand as a byte-pop count (0 on garbage).

    Capstone renders the operand in hex with a ``0x`` prefix (or plain
    decimal for small values); a bare ``ret`` yields 0.
    """
    try:
        n = int(op_str, 16) if op_str.startswith(("0x", "0X")) else int(op_str)
    except ValueError:
        return 0
    return max(0, n)


def calling_convention(insns: list[Any]) -> str:
    """Infer the calling convention from a disassembled function.

    Rules (x86/32, MSVC-flavoured):
    - ends in a plain ``ret`` → cdecl (caller cleans).
    - ends in ``ret N`` → stdcall or thiscall; if ECX is used as a pointer
      (``[ecx`` memory access) or saved to a callee-saved register early
      (``mov esi, ecx``) → thiscall, else stdcall.
    - ends in an unconditional ``jmp`` → tail call / thunk; ``mov ecx, imm``
      opening → thiscall ctor thunk; ``mov ecx, [ebp-X]`` opening → EH-guard
      thunk; otherwise a generic tail-call thunk.
    - no terminator found → unknown.

    This is the per-function calling-convention answer that every manual
    decompilation pass re-derives from the epilogue — surfaced here so the
    C signature (``__stdcall`` vs ``__fastcall``/``__thiscall`` emulation vs
    naked asm) is known before writing a single line.
    """
    if not insns:
        return "unknown"
    first = insns[0]
    # If the very first instruction loads ecx from memory (`mov ecx,[esp+4]`
    # passing an argument), ecx is NOT the this pointer — a thiscall keeps
    # the incoming this in ecx untouched.
    loads_ecx_from_mem_first = (
        first.mnemonic == "mov" and first.op_str.startswith("ecx, ") and "[" in first.op_str
    )
    ecx_as_this = not loads_ecx_from_mem_first and any(
        "[ecx" in i.op_str
        or (
            i.mnemonic == "mov"
            and "," in i.op_str
            and i.op_str.split(",")[1].strip() == "ecx"
            and i.op_str.split(",")[0].strip() in ("esi", "edi", "ebx")
        )
        for i in insns[:10]
    )
    # The extraction can run past the function's end into the next one.  A
    # function ends with its LAST ret (early returns precede it); if there is
    # no ret at all it is a tail-jmp thunk (which has no internal branches).
    # Use the LAST jmp too: the extent-padded window can bleed into the next
    # function, and a jmp-table dispatcher followed by the next function's
    # code yields several jmps with no ret — the terminal one is the
    # function's true end (matching the rets[-1] logic above).
    rets = [insn for insn in insns if insn.mnemonic.startswith("ret")]
    if rets:
        last = rets[-1]
    else:
        jmps = [insn for insn in insns if insn.mnemonic == "jmp"]
        if not jmps:
            return "unknown"
        last = jmps[-1]
    m = last.mnemonic
    if m == "jmp":
        first = insns[0]
        if first.mnemonic == "mov" and "ecx" in first.op_str:
            if "[" in first.op_str and "ebp" in first.op_str:
                return "thiscall (EH-guard thunk)"
            if "0x" in first.op_str:
                return "thiscall (ctor thunk)"
        # A jmp that ends a REAL body (>2 instructions) is a tail call from
        # a forwarding function, not a pure thunk — the jmp IS the body only
        # for 1-2 instruction thunks (e.g. `jmp [IAT]`, `push; jmp`).
        if len(insns) > 2:
            return "tail call"
        return "tail-call thunk"
    if m.startswith("ret"):
        n = ret_pop_count(last.op_str)
        if n == 0:
            # Plain ret: cdecl, or thiscall with NO stack args (ecx=this only
            # the caller has nothing to clean).
            return "thiscall (no stack args)" if ecx_as_this else "cdecl"
        return "thiscall" if ecx_as_this else "stdcall"
    return "unknown"


def disassembled_extent_window(cfg: ProjectConfig, va: int) -> tuple[list[Any], str | None]:
    """Disassemble an EXTENT-derived window at *va* for epilogue analysis.

    Shared by ``calling_convention_at`` and skeleton generation.  The window
    is exact when the extent terminated on a ``ret`` (or a tiny <=16 B
    ``jmp`` thunk); otherwise it is padded past a branch-merge ``jmp`` so
    the true epilogue stays visible (a flat 64-byte slice truncated longer
    functions mid-code and inference said "unknown").  Works for 16-bit
    DOS/NE targets too.

    Returns ``(insns, extent_kind)`` — empty list and None kind on any
    failure (unsupported arch, unreadable binary, capstone missing).
    """
    arch = getattr(cfg, "arch", "")
    if arch not in ("x86_32", "x86_16"):
        return [], None
    try:
        import capstone

        from rebrew.binary_loader import extract_raw_bytes, function_extent_from_disasm

        kind = None
        extent: int | None = None
        extent_kind = function_extent_from_disasm(cfg.target_binary, va, with_kind=True)
        if extent_kind is not None:
            extent, kind = extent_kind
        if (
            kind == "jmp"
            and extent is not None
            and extent <= 16
            or kind == "ret"
            and extent is not None
        ):
            window = extent
        else:
            window = min(max(extent or 0, 48) + 96, 256)
        raw = extract_raw_bytes(cfg.target_binary, va, window)
        if not raw:
            return [], None
        mode = capstone.CS_MODE_32 if arch == "x86_32" else capstone.CS_MODE_16
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        return list(md.disasm(raw, va)), kind
    except Exception:  # best-effort inference
        logger.debug("instruction window read failed at 0x%08x", va, exc_info=True)
        return [], None


def calling_convention_at(cfg: ProjectConfig, va: int) -> str:
    """Infer the calling convention of the function at *va* (extent-based).

    Shared by ``rebrew describe`` and skeleton generation.  Returns
    ``"unknown"`` on any failure.
    """
    insns, _kind = disassembled_extent_window(cfg, va)
    if not insns:
        return "unknown"
    return calling_convention(insns)


def _extract_hex_operand(op_str: str) -> int | None:
    """Return the first ``0x...`` absolute operand, or None."""
    m = re.search(r"0x([0-9a-fA-F]+)", op_str)
    return int(m.group(1), 16) if m else None


def _annotation_for_operand(op_str: str, lookup: dict[int, str]) -> str | None:
    """Resolve an absolute operand in *op_str* against *lookup*.

    Only absolute (non-bracketed) immediates match — ``call [0x4130c8]`` and
    ``push 0x4130c8`` both resolve, but ``[eax+0xc]`` does not (the hex is a
    register-relative displacement, not an address).
    """
    if "0x" not in op_str:
        return None
    # Skip register-relative forms: any '[' that is not a bare [0x...].
    if "[" in op_str:
        try:
            inner = op_str[op_str.index("[") + 1 : op_str.index("]")]
        except ValueError:
            return None
        if inner.startswith("0x") and "+" not in inner and "-" not in inner:
            addr = _extract_hex_operand(inner)
            return lookup.get(addr) if addr is not None else None
        return None
    addr = _extract_hex_operand(op_str)
    return lookup.get(addr) if addr is not None else None


def _run_hex_mode(
    va_int: int,
    size: int,
    cfg: ProjectConfig,
    annotate: bool,
    json_output: bool,
    *,
    resolve_imports: bool = False,
    resolve_strings: bool = False,
    pattern_hints: bool = False,
    stale_size: bool = False,
    declared_size: int | None = None,
) -> None:
    """Capstone hex-dump disassembly (default format)."""
    bin_path = cfg.target_binary
    if not bin_path.exists():
        error_exit(f"Binary not found at {bin_path}", json_mode=json_output)

    func_lookup: dict[int, tuple[str, str]] = {}
    if annotate and not json_output:
        func_lookup = build_function_lookup(cfg)

    # NE context: the segment containing the requested VA (for the header).
    ne_seg: int | None = None
    ne_seg_name = ""
    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(bin_path)
        if info.format == "ne":
            for s in info.ne_segments:  # type: ignore[attr-defined]
                if s.base_va <= va_int < s.base_va + s.length:
                    ne_seg = s.index
                    ne_seg_name = "code" if s.is_code else "data"
                    break
    except Exception:  # segment context is cosmetic
        logger.debug("NE segment context lookup failed at 0x%x", va_int, exc_info=True)

    import_map: dict[int, str] = {}
    string_map: dict[int, str] = {}
    if resolve_imports:
        import_map = _build_import_map(bin_path)
    if resolve_strings:
        string_map = _build_string_map(bin_path)

    from rebrew.binary_loader import extract_raw_bytes

    try:
        data = extract_raw_bytes(cfg.target_binary, va_int, size)
        if not data:
            error_exit(
                f"No code at VA 0x{va_int:08x} — address is outside the binary image",
                json_mode=json_output,
            )
        truncated = size > 0 and len(data) < size
        if truncated:
            console.print(
                f"[yellow]warning:[/yellow] requested {size} bytes, got {len(data)} "
                "(reached end of image)"
            )
        try:
            from capstone import Cs

            md = Cs(cfg.capstone_arch, cfg.capstone_mode)
            md.detail = False
            # With --hints, disassemble a small lookbehind window so prologue
            # patterns (e.g. `push -1` SEH registration a few bytes before the
            # function start) are visible to the pattern detector.  Only
            # instructions at/after *va_int* are printed.
            pre_va = va_int
            if pattern_hints and va_int > 12:
                try:
                    from rebrew.analysis import section_range
                    from rebrew.binary_loader import load_binary

                    rng = section_range(load_binary(bin_path), ".text")
                    text_start = rng[0] if rng else 0
                    pre_va = max(text_start, va_int - 12)
                except Exception:  # lookbehind is best-effort
                    logger.debug("lookbehind window probe failed", exc_info=True)
                    pre_va = va_int - 12
            pre_data = extract_raw_bytes(cfg.target_binary, pre_va, size + (va_int - pre_va))
            insn_list = list(md.disasm(pre_data, pre_va))
            shown_offset = next(
                (i for i, insn in enumerate(insn_list) if insn.address >= va_int), 0
            )
            shown_list = insn_list[shown_offset:]

            if json_output:
                conv = calling_convention(shown_list)
                instr_json = []
                for idx, insn in enumerate(shown_list):
                    entry: dict[str, Any] = {
                        "address": f"0x{insn.address:08x}",
                        "bytes": insn.bytes.hex(),
                        "mnemonic": insn.mnemonic,
                        "operands": insn.op_str,
                    }
                    if resolve_imports:
                        entry["import"] = _annotation_for_operand(insn.op_str, import_map)
                    if resolve_strings:
                        entry["string"] = _annotation_for_operand(insn.op_str, string_map)
                    if pattern_hints:
                        entry["hint"] = _hint_for(insn_list, shown_offset + idx)
                    instr_json.append(entry)
                json_print(
                    {
                        "va": f"0x{va_int:08x}",
                        "size": len(data),
                        "requested_size": declared_size if stale_size else size,
                        "truncated": truncated,
                        "stale_size": stale_size,
                        "calling_convention": conv,
                        "instruction_count": len(shown_list),
                        "instructions": instr_json,
                    }
                )
                return

            console.print(
                f"Dumping [cyan]0x{va_int:08x}[/] ({len(data)} bytes) from {bin_path.name}:"
            )
            if ne_seg is not None:
                console.print(f"  [dim]SEG{ne_seg}:0x{va_int & 0xFFFF:04x} ({ne_seg_name})[/dim]")
            conv = calling_convention(shown_list)
            if conv != "unknown":
                console.print(f"  [dim]calling convention: {conv}[/dim]")
            console.print()
            for idx, insn in enumerate(shown_list):
                hex_bytes = insn.bytes.hex()
                line = (
                    f"  0x{insn.address:08x}:  {hex_bytes:<20s}  {insn.mnemonic:<8s} {insn.op_str}"
                )
                if annotate and insn.mnemonic in ("call", "jmp") and insn.op_str.startswith("0x"):
                    try:
                        target_va = int(insn.op_str, 16)
                        if target_va in func_lookup:
                            name, status = func_lookup[target_va]
                            tag = f" ({status})" if status else ""
                            line += f"  ; {name}{tag}"
                    except ValueError:
                        pass
                if annotate and insn.mnemonic == "lcall":
                    # 16-bit far call: annotate the target segment.  Borland
                    # index convention: selectors at or below the segment
                    # count equal the segment index (the \\xNN\\x00 marker);
                    # 0x0:0xffff is the loader-patched system-call pattern.
                    try:
                        parts = [p.strip() for p in insn.op_str.split(",")]
                        if len(parts) == 2:
                            seg = int(parts[0], 16)
                            off = int(parts[1], 16)
                            if seg == 0:
                                line += "  ; system far call"
                            elif ne_seg is not None and 1 <= seg <= info.ne_header.segment_count:  # type: ignore[attr-defined]
                                line += f"  ; SEG{seg}:0x{off:04x} (far)"
                    except ValueError:
                        pass
                if resolve_imports and insn.mnemonic in ("call", "jmp"):
                    imp = _annotation_for_operand(insn.op_str, import_map)
                    if imp:
                        line += f"  ; {imp}"
                if resolve_strings and insn.mnemonic in ("push", "mov", "lea", "cmp"):
                    s = _annotation_for_operand(insn.op_str, string_map)
                    if s:
                        line += f'  ; "{s}"'
                if pattern_hints:
                    hint = _hint_for(insn_list, shown_offset + idx)
                    if hint:
                        line += f"  ; {hint}"
                print(line)

        except ImportError:
            if json_output:
                error_exit("capstone not installed", json_mode=json_output)
            console.print("[yellow](capstone not installed, showing hex dump)[/]")
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"  0x{va_int + i:08x}:  {hex_str:<48s}  {ascii_str}")

    except (OSError, KeyError, ValueError, TypeError) as e:
        error_exit(str(e), json_mode=json_output)
    except Exception as e:  # capstone.CsError and friends
        # CsError (bad arch/mode config) and capstone internals are not in
        # the tuple above; report them as clean errors, not tracebacks.
        error_exit(f"capstone error: {e}", json_mode=json_output)


# ---------------------------------------------------------------------------
# NASM mode helpers
# ---------------------------------------------------------------------------


def _get_capstone_x86() -> tuple[int, int, int, Any]:
    """Import capstone x86 constants/classes lazily."""
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, Cs
    except ImportError as e:
        raise RuntimeError("capstone required. Install: pip install capstone") from e
    return CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, Cs


def capstone_to_nasm(mnemonic: str, op_str: str) -> str:
    """Convert capstone Intel syntax to NASM-compatible syntax."""
    line = f"{mnemonic} {op_str}".strip() if op_str else mnemonic
    line = line.replace("ptr ", "")
    return line


def disassemble_to_nasm(
    code: bytes,
    base_va: int,
    label: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Disassemble bytes to NASM source with round-trip verification."""
    cs_arch_x86, cs_mode_32, cs_opt_syntax_intel, cs_cls = _get_capstone_x86()
    md = cs_cls(cs_arch_x86, cs_mode_32)
    md.syntax = cs_opt_syntax_intel
    md.detail = False

    instructions = list(md.disasm(code, base_va))
    total_insns = len(instructions)

    safe_label = None
    if label:
        safe_label = _NASM_LABEL_RE.sub("_", label.lstrip("_"))
        if not safe_label or not safe_label[0].isalpha():
            safe_label = "func_" + safe_label

    insn_data = []
    for insn in instructions:
        nasm_text = capstone_to_nasm(insn.mnemonic, insn.op_str)
        insn_data.append(
            {
                "addr": insn.address,
                "raw": bytes(insn.bytes),
                "nasm": nasm_text,
                "offset": insn.address - base_va,
                "size": len(insn.bytes),
            }
        )

    covered = sum(i["size"] for i in insn_data)
    trailing = code[covered:] if covered < len(code) else b""

    pass1_lines = _build_nasm_lines(insn_data, base_va, safe_label, trailing, set())
    pass1_src = "\n".join(pass1_lines)
    pass1_bin = _run_nasm(pass1_src)

    bad_indices: set[int] = set()
    if pass1_bin is not None and len(pass1_bin) == len(code):
        for idx, entry in enumerate(insn_data):
            off = entry["offset"]
            sz = entry["size"]
            if pass1_bin[off : off + sz] != entry["raw"]:
                bad_indices.add(idx)
    else:
        bad_indices = _find_bad_instructions_individually(insn_data, base_va, code)

    final_lines = (
        _build_nasm_lines(insn_data, base_va, safe_label, trailing, bad_indices)
        if bad_indices
        else pass1_lines
    )

    db_fallbacks = len(bad_indices)
    nasm_ok = total_insns - db_fallbacks

    stats = {
        "total_instructions": total_insns,
        "nasm_ok": nasm_ok,
        "db_fallbacks": db_fallbacks,
        "pct_nasm": (nasm_ok / total_insns * 100) if total_insns else 0,
        "total_bytes": len(code),
        "base_va": base_va,
    }

    return "\n".join(final_lines), stats


def _find_bad_instructions_individually(
    insn_data: list[dict[str, Any]],
    base_va: int,
    code: bytes,
) -> set[int]:
    """Test each instruction by embedding it in a db-padded file.

    Reuses a single temporary directory for all NASM invocations to avoid
    the overhead of creating/destroying one per instruction.
    """
    bad: set[int] = set()
    total_insn_size = sum(e["size"] for e in insn_data)
    trailing = code[total_insn_size:]
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for idx, entry in enumerate(insn_data):
            src_lines = ["bits 32", f"org 0x{base_va:08X}"]
            for j, e in enumerate(insn_data):
                if j == idx:
                    src_lines.append(e["nasm"])
                else:
                    db_hex = ", ".join(f"0x{b:02X}" for b in e["raw"])
                    src_lines.append(f"db {db_hex}")
            if trailing:
                db_hex = ", ".join(f"0x{b:02X}" for b in trailing)
                src_lines.append(f"db {db_hex}")
            result = _run_nasm("\n".join(src_lines), tmpdir=tmp)
            if result is None or len(result) != len(code):
                bad.add(idx)
                continue
            off = entry["offset"]
            sz = entry["size"]
            if result[off : off + sz] != entry["raw"]:
                bad.add(idx)
    return bad


def _build_nasm_lines(
    insn_data: list[dict[str, Any]],
    base_va: int,
    safe_label: str | None,
    trailing: bytes,
    db_indices: set[int],
) -> list[str]:
    lines: list[str] = []
    lines.append("bits 32")
    lines.append(f"org 0x{base_va:08X}")
    lines.append("")
    if safe_label:
        lines.append(f"{safe_label}:")
    for idx, entry in enumerate(insn_data):
        addr = entry["addr"]
        raw = entry["raw"]
        nasm_text = entry["nasm"]
        if idx in db_indices:
            db_hex = ", ".join(f"0x{b:02X}" for b in raw)
            lines.append(f"    db {db_hex:40s} ; {addr:08X}  {nasm_text}")
        else:
            lines.append(f"    {nasm_text:40s} ; {addr:08X}  {raw.hex()}")
    if trailing:
        db_hex = ", ".join(f"0x{b:02X}" for b in trailing)
        lines.append(f"    db {db_hex}  ; trailing data")
    lines.append("")
    return lines


def generate_inline_c(
    code: bytes,
    cfg: ProjectConfig,
    va: int,
    symbol: str | None,
) -> str:
    """Generate a C file with a naked exact-bytes reconstruction.

    The function is emitted behind the ``REBREW_ALLOW_NAKED`` fence: the
    ``__declspec(naked)``/``__attribute__((naked))`` + raw-byte branch
    reproduces the target bytes VERBATIM for **round-trip verification**
    builds (``rebrew round-trip --allow-naked`` defines it), while the
    ``#else`` branch is an idiomatic C fallback that keeps the comparison
    build compiling (``rebrew prove`` can establish it as PROVEN without
    byte equality).

    Bytes are emitted with ``__asm _emit 0xNN`` (MSVC) / ``__asm__(".byte
    0xNN, ...")`` (GCC) — never assembler mnemonics: MSVC's inline
    assembler rejects NASM operand syntax (``dword [x]`` vs ``dword ptr
    [x]``) and its encodings are not guaranteed to match the original, so
    the exact-bytes branch must not depend on it.  Mnemonics from a
    capstone pass over *code* are kept as comments; *code* is the ground
    truth emitted verbatim.

    The file is self-contained for ``rebrew test``: VA from the
    ``// FUNCTION`` marker, size from ``// SIZE``, symbol from the C
    definition — no ``--va/--size/--symbol`` needed to iterate on it.
    """
    marker = cfg.marker if cfg.marker else "TARGET"
    sym = symbol or f"_func_{va:08x}"
    func_name = sym.lstrip("_")

    is_gcc = "clang" in cfg.compiler_profile.lower() or "gcc" in cfg.compiler_profile.lower()
    naked_attr = "__attribute__((naked))" if is_gcc else "__declspec(naked)"

    # Disassemble *code* for the per-instruction mnemonic comments (any
    # trailing bytes capstone cannot decode are emitted as bare data).
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    insns = list(md.disasm(code, va))
    covered = sum(len(i.bytes) for i in insns)
    leftover = code[covered:] if covered < len(code) else b""

    lines: list[str] = []
    lines.append(f"// FUNCTION: {marker} 0x{va:08x}")
    lines.append(f"// SIZE: {len(code)}")
    lines.append("// SOURCE: naked")
    lines.append("")
    lines.append("// Exact-bytes naked reconstruction (generated by `rebrew asm --inline-c`).")
    lines.append("// The guarded branch emits the target bytes verbatim (_emit/.byte) —")
    lines.append("// byte-exact by construction; implement the real C in the fallback")
    lines.append("// branch and drop -DREBREW_ALLOW_NAKED once it matches.")
    lines.append("")
    lines.append("#ifdef REBREW_ALLOW_NAKED")
    lines.append(f"{naked_attr} void {func_name}(void)")
    lines.append("{")
    if is_gcc:
        lines.append("    __asm__(")
        for insn in insns:
            comment = f" /* {insn.mnemonic} {insn.op_str} */".rstrip()
            byte_list = ", ".join(f"0x{b:02x}" for b in insn.bytes)
            lines.append(f'        ".byte {byte_list}{comment}\\n"')
        if leftover:
            byte_list = ", ".join(f"0x{b:02x}" for b in leftover)
            lines.append(f'        ".byte {byte_list} /* data */\\n"')
        lines.append("    );")
    else:
        lines.append("    __asm {")
        for insn in insns:
            comment = f" /* {insn.mnemonic} {insn.op_str} */".rstrip()
            for idx, b in enumerate(insn.bytes):
                lines.append(f"        _emit 0x{b:02x}{comment if idx == 0 else ''}")
        if leftover:
            for idx, b in enumerate(leftover):
                lines.append(f"        _emit 0x{b:02x}{' /* data */' if idx == 0 else ''}")
        lines.append("    }")
    lines.append("}")
    lines.append("#else")
    lines.append(f"void {func_name}(void)")
    lines.append("{")
    lines.append("    /* TODO: idiomatic C89 fallback for the comparison build — replace with")
    lines.append("       the real C (rebrew prove can mark it PROVEN); the naked branch above")
    lines.append("       reproduces the exact bytes for round-trip builds (--allow-naked). */")
    lines.append("}")
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines)


def _run_nasm(source: str, *, tmpdir: Path | None = None) -> bytes | None:
    """Run nasm on source text, return binary output or None.

    When *tmpdir* is provided the caller owns the directory lifetime and
    this function reuses it (avoids creating/destroying a temp dir per call).
    """

    def _assemble(tmp: Path) -> bytes | None:
        asm_path = tmp / "input.asm"
        bin_path = tmp / "output.bin"
        asm_path.write_text(source, encoding="utf-8")
        try:
            r = subprocess.run(
                ["nasm", "-f", "bin", "-o", str(bin_path), str(asm_path)],
                capture_output=True,
                timeout=5,
            )
            if r.returncode != 0:
                return None
            if bin_path.exists():
                return bin_path.read_bytes()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    if tmpdir is not None:
        return _assemble(tmpdir)
    with tempfile.TemporaryDirectory() as td:
        return _assemble(Path(td))


def verify_roundtrip(nasm_source: str, original_bytes: bytes) -> tuple[bool, str]:
    """Assemble NASM source and verify it matches original bytes exactly."""
    result = _run_nasm(nasm_source)
    if result is None:
        return False, "NASM assembly failed"
    if result == original_bytes:
        return True, f"PASS: {len(original_bytes)} bytes identical"
    if len(result) != len(original_bytes):
        return False, f"FAIL: size mismatch (nasm={len(result)}, original={len(original_bytes)})"
    diffs = [i for i in range(len(original_bytes)) if result[i] != original_bytes[i]]
    return False, f"FAIL: {len(diffs)} byte diffs at offsets {diffs[:10]}"


def _parse_annotations(filepath: Path, metadata_dir: Path | None = None) -> list[dict[str, Any]]:
    """Parse reccmp-style annotations from a reversed .c file."""
    entries = parse_c_file_multi(filepath, metadata_dir=metadata_dir)
    results: list[dict[str, Any]] = []
    for entry in entries:
        if entry.status not in DISPLAY_STATUSES:
            continue
        if not entry.size:
            continue
        results.append(
            {
                "va": entry.va,
                "size": entry.size,
                "symbol": entry.symbol,
                "status": entry.status,
                "filepath": filepath,
            }
        )
    return results


def batch_extract_nasm(
    cfg: ProjectConfig,
    out_dir: Path,
    verify_flag: bool = False,
    stubs_only: bool = False,
    inline_c: bool = False,
) -> None:
    """Extract NASM (or naked-C skeletons with ``inline_c``) for all annotated
    functions in reversed_dir.

    With ``inline_c`` each function is written as a ``// SOURCE: naked``
    fenced skeleton (``rebrew asm --inline-c`` output) — the whole-binary
    byte-coverage baseline: every function becomes compileable and iterable
    through ``rebrew test --cflags /DREBREW_ALLOW_NAKED``, and ``rebrew
    status``/``todo`` bucket them as naked reconstructions (byte-exact, not
    decompiled) until the real C bodies land.
    """
    reversed_dir = cfg.reversed_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    entries = []
    for cfile in iter_sources(reversed_dir, cfg):
        for info in _parse_annotations(cfile, metadata_dir=cfg.metadata_dir):
            if info["size"] < 6:
                continue
            if stubs_only and info["status"] != "STUB":
                continue
            entries.append(info)

    entries.sort(key=lambda x: x["va"])
    total = len(entries)
    ok = 0
    fail = 0

    for i, entry in enumerate(entries, 1):
        va = entry["va"]
        size = entry["size"]
        symbol = entry["symbol"] or f"func_{va:08x}"
        stem = entry["filepath"].name

        try:
            from rebrew.binary_loader import extract_raw_bytes

            code = extract_raw_bytes(cfg.target_binary, va, size)
            if code is None:
                raise ValueError("VA not in any section")
        except (OSError, KeyError, ValueError) as e:
            console.print(f"  \\[{i}/{total}] {stem}: [yellow]SKIP[/] (extraction error: {e})")
            continue

        nasm_src, stats = disassemble_to_nasm(code, va, symbol)
        # Multi-function sources share a file stem — include the VA or the
        # second function's output would silently overwrite the first's.
        if inline_c:
            out_src = generate_inline_c(code, cfg, va, symbol)
            ext = ".c"
            pct = stats["pct_nasm"]
            db = stats["db_fallbacks"]
            status_line = f"naked-c  nasm={pct:5.1f}% db={db:2d}"
        else:
            out_src = nasm_src
            ext = ".asm"
            status_line = ""
        out_file = out_dir / f"{stem}.{va:08x}{ext}"
        out_file.write_text(out_src, encoding="utf-8")

        if verify_flag:
            passed, msg = verify_roundtrip(nasm_src, code)
            status = "PASS" if passed else f"FAIL ({msg})"
            if passed:
                ok += 1
            else:
                fail += 1
        else:
            status = "OK"
            ok += 1

        console.print(f"  \\[{i}/{total}] {stem:40s} {size:4d}B  {status_line}{status}")

    console.print(f"\nDone: [green]{ok} ok[/], [red]{fail} failed[/], {total} total")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew asm 0x10003ca0 --size 77 · · · · · · · · · · · Disassemble (hex format, default)\n\n"
    "  rebrew asm 0x10003ca0 --no-annotate · · · · · · · · · Skip call/jmp name annotations\n\n"
    "  rebrew asm 0x10003ca0 --size 77 --format nasm · · NASM output\n\n"
    "  rebrew asm 0x10003ca0 --size 77 --format nasm --verify  Verify round-trip\n\n"
    "  rebrew asm 0x10003ca0 --size 77 --format nasm --inline-c -o f.c  Inline C\n\n"
    "  rebrew asm --all --out-dir output/asm/ --format nasm · · Batch NASM extract\n\n"
    "  rebrew asm 0x10003ca0 --size 77 --json · · · · · · · · JSON output\n\n"
    "[bold]Formats:[/bold]\n\n"
    "  hex · · Capstone disassembly with hex dump and call annotation (default)\n\n"
    "  nasm · · NASM-reassembleable source with optional round-trip verification\n\n"
    "[dim]Uses capstone for x86 disassembly. Reads binary and arch from rebrew-project.toml.[/dim]"
)

app = typer.Typer(
    help="Disassemble a function from the target binary (hex dump or NASM source).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _list_size_for(cfg: ProjectConfig, va_int: int) -> int | None:
    """Function-list size for *va_int*, if the list knows it.

    Lets ``rebrew asm <va>`` default to the real function size instead of a
    hardcoded 32-byte window (which bleeds into the adjacent function).
    """
    func_list_path = getattr(cfg, "function_list", "")
    if not func_list_path or not Path(func_list_path).is_file():
        return None
    from rebrew.catalog import parse_function_list

    try:
        for f in parse_function_list(Path(func_list_path)):
            if int(f["va"]) == va_int:
                return int(f["size"])
    except (OSError, ValueError, KeyError):
        return None
    return None


@app.callback(invoke_without_command=True)
def main(
    va: str | None = typer.Argument(None, help="Function VA in hex"),
    size: int | None = typer.Option(None, "--size", help="Function size in bytes"),
    fmt: str = typer.Option("hex", "--format", "-f", help="Output format: hex, nasm"),
    annotate: bool = typer.Option(
        True, "--annotate/--no-annotate", help="(hex) Annotate calls with known function names"
    ),
    resolve_imports: bool = typer.Option(
        False, "--imports", help="(hex) Annotate call/jmp [IAT] with import names"
    ),
    resolve_strings: bool = typer.Option(
        False, "--strings", help="(hex) Annotate push/mov/lea of string addresses with text"
    ),
    pattern_hints: bool = typer.Option(
        False, "--hints", help="(hex) Annotate decompiler-relevant codegen patterns"
    ),
    # nasm-specific options
    bin_file: Path | None = typer.Option(None, "--bin", help="(nasm) Raw .bin file"),
    label: str | None = typer.Option(None, "--label", help="(nasm) Label name for the function"),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file (default: stdout)"
    ),
    verify: bool = typer.Option(
        False, "--verify", help="(nasm) Verify round-trip: assemble and compare"
    ),
    stats: bool = typer.Option(False, "--stats", help="(nasm) Print stats only, no ASM output"),
    inline_c: bool = typer.Option(
        False,
        "--inline-c",
        help=(
            "(nasm) Output an exact-bytes naked C skeleton: raw _emit/.byte "
            "emission behind the REBREW_ALLOW_NAKED fence + a plain-C fallback, "
            "self-contained for `rebrew test` (VA/SIZE/symbol from the file)"
        ),
    ),
    extract_all: bool = typer.Option(False, "--all", help="(nasm) Batch extract all functions"),
    batch_stubs: bool = typer.Option(
        False, "--batch-stubs", help="(nasm) Batch: STUB functions only"
    ),
    out_dir: Path | None = typer.Option(None, "--out-dir", help="(nasm) Output dir for batch mode"),
    base_va: str = typer.Option("0", "--base-va", help="(nasm) Base VA for --bin files"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Disassemble a function from the target binary."""
    cfg = require_config(target=target, json_mode=json_output)
    if fmt not in ("hex", "nasm"):
        # Bad argument value — usage error (2), not "needs code work" (1).
        error_exit("--format must be 'hex' or 'nasm'", json_mode=json_output, code=EXIT_ERROR)

    # --- NASM batch modes ---
    if fmt == "nasm" and (extract_all or batch_stubs):
        if out_dir is not None and not out_dir.is_absolute():
            batch_out_dir = cfg.root / out_dir
        else:
            batch_out_dir = out_dir or (cfg.root / "output" / ("naked" if inline_c else "asm"))
        try:
            batch_extract_nasm(
                cfg,
                batch_out_dir,
                verify_flag=verify,
                stubs_only=batch_stubs,
                inline_c=inline_c,
            )
        except RuntimeError as e:
            error_exit(str(e), json_mode=json_output)
        return

    # --- Resolve VA ---
    va_str = va
    if not va_str and not bin_file:
        error_exit("Specify VA as a positional argument or --bin FILE", json_mode=json_output)

    va_int = parse_va(va_str, json_mode=json_output) if va_str else None
    if size is not None and size <= 0:
        error_exit("--size must be a positive integer", json_mode=json_output)
    # Default to the known canonical size (function list) when no --size is
    # given — 32 is only a fallback for functions the list does not know.
    effective_size = size or (_list_size_for(cfg, va_int) if va_int else None) or 32

    # A stale function-list size truncates the dump mid-instruction and
    # breaks the calling-convention inference (no `ret` in the truncated
    # window → "unknown" → wrong skeleton signature).  When the
    # disassembly extent runs past the declared size, extend the dump to it
    # with a warning.  An explicit `--size` is user intent: warn, but honor
    # the request.  x86-32 only — the extent walker is an x86 disassembler.
    stale_size = False
    declared_size = effective_size
    if va_int is not None and getattr(cfg, "arch", "") == "x86_32" and cfg.target_binary.exists():
        from rebrew.binary_loader import function_extent_from_disasm

        disasm_extent = function_extent_from_disasm(cfg.target_binary, va_int)
        if disasm_extent is not None and effective_size < disasm_extent:
            if size is None:
                console.print(
                    f"[yellow]warning:[/yellow] function-list size {effective_size}B is stale — "
                    f"code continues to at least {disasm_extent}B; extending the dump"
                )
                effective_size = disasm_extent
                stale_size = True
            else:
                console.print(
                    f"[yellow]warning:[/yellow] size {size}B may be stale — "
                    f"disassembly continues to at least {disasm_extent}B (re-run with --size "
                    f"{disasm_extent} to see it)"
                )

    # --- hex format ---
    if fmt == "hex":
        if not va_str:
            error_exit("--format hex requires a VA as a positional argument", json_mode=json_output)
        assert va_int is not None  # va_str is truthy above
        _run_hex_mode(
            va_int,
            effective_size,
            cfg,
            annotate,
            json_output,
            resolve_imports=resolve_imports,
            resolve_strings=resolve_strings,
            pattern_hints=pattern_hints,
            stale_size=stale_size,
            declared_size=declared_size,
        )
        return

    # --- nasm format ---
    if bin_file:
        code = bin_file.read_bytes()
        computed_base_va = parse_va(base_va, json_mode=json_output)
        computed_label = label or bin_file.stem
    elif va_str and effective_size:
        assert va_int is not None  # va_str is truthy above
        computed_va = va_int
        from rebrew.binary_loader import extract_raw_bytes

        code = extract_raw_bytes(cfg.target_binary, computed_va, effective_size)
        if code is None:
            error_exit(
                f"Could not extract {effective_size} bytes at VA 0x{computed_va:08X}",
                json_mode=json_output,
            )
        computed_base_va = computed_va
        computed_label = label or f"func_{computed_va:08X}"
    else:
        error_exit("Specify VA HEX --size N or --bin FILE for --format nasm", json_mode=json_output)

    try:
        nasm_src, run_stats = disassemble_to_nasm(code, computed_base_va, computed_label)
    except RuntimeError as e:
        error_exit(str(e), json_mode=json_output)

    if inline_c:
        out_src = generate_inline_c(code, cfg, computed_base_va, computed_label)
    else:
        out_src = nasm_src

    if stats or json_output:
        result: dict[str, Any] = {
            "function": computed_label,
            "base_va": f"0x{run_stats['base_va']:08X}",
            "total_bytes": run_stats["total_bytes"],
            "total_instructions": run_stats["total_instructions"],
            "nasm_ok": run_stats["nasm_ok"],
            "pct_nasm": round(run_stats["pct_nasm"], 1),
            "db_fallbacks": run_stats["db_fallbacks"],
        }
        if verify:
            passed, msg = verify_roundtrip(nasm_src, code)
            result["roundtrip_pass"] = passed
            result["roundtrip_message"] = msg
        if json_output:
            json_print(result)
        else:
            console.print(f"[bold]Function:[/] {computed_label}")
            console.print(f"  Base VA: [cyan]0x{run_stats['base_va']:08X}[/]")
            console.print(f"  Size: {run_stats['total_bytes']} bytes")
            console.print(f"  Instructions: {run_stats['total_instructions']}")
            console.print(
                f"  NASM-compatible: {run_stats['nasm_ok']} ({run_stats['pct_nasm']:.1f}%)"
            )
            console.print(f"  db fallbacks: {run_stats['db_fallbacks']}")
        return

    if output:
        output.write_text(out_src, encoding="utf-8")
        console.print(f"Written to {output}")
    else:
        print(out_src)

    if verify:
        _, msg = verify_roundtrip(nasm_src, code)
        console.print(f"\nRound-trip verification: {msg}")


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
