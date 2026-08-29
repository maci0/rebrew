"""skeleton.py - Generate .c skeleton file for an uncovered function.

Given a VA address, generates a properly annotated .c file skeleton with:
- reccmp-style marker line (FUNCTION/LIBRARY/STUB:  MODULE 0xVA)
- A placeholder function body
- Prints the exact rebrew test command to verify it

All volatile metadata (STATUS, SIZE, CFLAGS, BLOCKER) is written to the
``rebrew-functions.toml`` metadata by this generator, not into the .c file.

Usage:
    rebrew skeleton 0x10003da0                    # Generate skeleton
    rebrew skeleton 0x10003da0 --name my_func     # Custom name
    rebrew skeleton 0x10003da0 --output path.c    # Custom output path
    rebrew skeleton --batch 10                    # Generate 10 skeletons at once
"""

from __future__ import annotations

import importlib
import logging
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.catalog import FunctionEntry

import httpx
import typer
from rich.console import Console

from rebrew.annotation import (
    marker_for_module,
    parse_c_file_multi,
)
from rebrew.catalog import load_function_structure
from rebrew.cli import (
    EXIT_ERROR,
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
    resolve_cflags,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.decompiler import fetch_decompilation
from rebrew.naming import (
    load_existing_vas,
    make_filename,
    sanitize_name,
)
from rebrew.sources import (
    target_marker,
)
from rebrew.utils import (
    atomic_write_text,
    read_source_text,
    rel_display_path,
)

console = Console(stderr=True)
logger = logging.getLogger(__name__)

#: 16-bit DOS profiles whose C compiler rejects ``//`` comments (C89-strict).
#: Their skeleton markers are emitted as ``/* ... */`` instead.
C89_STRICT_PROFILES = frozenset({"tc20", "msvc1.52", "watcom16"})


def c_comment_safe(text: str) -> str:
    """Make *text* safe to embed inside a generated ``/* ... */`` comment.

    Ghidra/symbol names derive from the analyzed binary, so an attacker can
    plant ``*/`` in a function name to close the comment early and inject
    arbitrary C into the generated skeleton (which ``rebrew test`` compiles).
    Splitting ``*/`` keeps the text readable while defusing the breakout;
    other control characters become spaces.
    """
    return "".join(" " if not ch.isprintable() else ch for ch in text.replace("*/", "* /"))


def _render_annotation_block(
    marker: str,
    cfg_marker: str,
    va: int,
    xref_context: str | None,
    decomp_code: str | None,
    decomp_backend: str,
    func_name: str,
    ghidra_name: str,
    todo_text: str | None = None,
    decomp_body: bool = False,
    convention_stub: str | None = None,
    convention_note: str | None = None,
    profile: str = "",
) -> str:
    # The annotation marker must use ``/* */`` for the C89-strict 16-bit
    # compilers that reject ``//`` comments (Turbo C 2.0 errors on any
    # ``//`` line — verified; MSVC 1.52 and Watcom C are equally strict).
    # TCC 3.1 and the 32-bit profiles accept both, so ``/* */`` would also
    # work there — but keep ``//`` (the long-standing convention) for them.
    use_block_comment = profile in C89_STRICT_PROFILES
    if use_block_comment:
        lines = [f"/* {marker}: {cfg_marker} 0x{va:08x} */\n"]
    else:
        lines = [f"// {marker}: {cfg_marker} 0x{va:08x}\n"]
    if xref_context:
        lines.append(f"{xref_context}\n")
    if decomp_code and decomp_body:
        # Use the decompiled C as the implementation — a real GA seed, not a
        # comment.  Rename its function to the marker's name so the GA can
        # find the symbol in the compiled object.
        from rebrew.c_parser import extract_function_name_and_proto

        body = decomp_code.strip()
        result = extract_function_name_and_proto(body)
        if result and result[0] != func_name:
            body = body.replace(result[0], func_name, 1)
        lines.append(f"{body}\n")
    elif decomp_code:
        lines.append(f"/* === Decompilation ({decomp_backend}) === */\n")
        lines.append(f"{decomp_code}\n")
        lines.append("/* === End decompilation === */\n")
    else:
        if convention_stub is not None and convention_stub.startswith("#ifdef REBREW_ALLOW_NAKED"):
            # Fenced naked/fallback stub: each branch needs its own body —
            # a naked function cannot contain C statements.
            _parts = convention_stub.split("\n")
            _naked_sig, _fallback_sig = _parts[1], _parts[3]
            lines.append("#ifdef REBREW_ALLOW_NAKED\n")
            lines.append(f"{_naked_sig}\n{{\n")
            lines.append("    /* TODO: naked body — inline asm (this in ecx),")
            if convention_note:
                lines.append(f"       {convention_note} */")
            else:
                lines.append("       end with `ret N` */")
            lines.append("}\n")
            lines.append("#else\n")
            lines.append(f"{_fallback_sig}\n{{\n")
            lines.append("    /* TODO: idiomatic C89 fallback for the comparison build */\n")
            lines.append("    return 0;\n")
            lines.append("}\n")
            lines.append("#endif\n")
        elif convention_stub is not None:
            signature = convention_stub
        elif profile in (
            "tc20",
            "tc16",
            "borlandc55",
            "watcom",
            "watcom16",
            "gcc",
            "gcc-pe",
            "clang",
        ):
            # TCC/bcc32/wcc/gcc: cdecl is the default convention; __cdecl is
            # a syntax error in TCC 3.1 ("Declaration syntax error").
            signature = f"int {func_name}(void)"
        else:
            # MSVC profiles and the historical default: __cdecl.
            signature = f"int __cdecl {func_name}(void)"
        if not convention_stub or not convention_stub.startswith("#ifdef REBREW_ALLOW_NAKED"):
            lines.append(f"{signature}\n")
            lines.append("{\n")
            if todo_text:
                lines.append(f"    /* TODO: {todo_text} */\n")
                if convention_note:
                    lines.append(f"    /* {convention_note} */\n")
                lines.append(f"    /* Ghidra name: {c_comment_safe(ghidra_name)} */\n")
            else:
                lines.append(
                    f"    /* TODO: Implement — Ghidra name: {c_comment_safe(ghidra_name)} */\n"
                )
            lines.append("    return 0;\n")
            lines.append("}\n")
    return "".join(lines)


def generate_skeleton(
    cfg: ProjectConfig,
    va: int,
    ghidra_name: str,
    module: str = "",
    custom_name: str | None = None,
    xref_context: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
    decomp_body: bool = False,
    func_lookup: FuncLookup | None = None,
) -> str:
    """Generate the .c file content.

    Args:
        cfg: Project configuration containing settings and marker rules.
        va: Virtual address of the target function.
        ghidra_name: Name of the function imported from Ghidra.
        module: Module name used for the marker line.
        custom_name: Optional override name for the function.
        xref_context: Optional string containing fetched caller cross-references.
        decomp_code: Optional decompilation output to embed as a comment block.
        decomp_backend: Name of the decompiler backend (for the header comment).
        decomp_body: Embed the decompiled body as the initial implementation.
        func_lookup: Optional prebuilt VA→(name, status) map for tail-call
            resolution; batch callers share one instance across functions.

    """
    lib_modules = cfg.library_modules or set()
    marker = marker_for_module(module, "RELOC", lib_modules)

    # Determine symbol name
    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    todo = "Implement based on Ghidra decompilation"

    # Calling-convention-aware stub: the skeleton signature should match the
    # target's convention (rebrew asm's inference), not always `int __cdecl
    # f(void)` — for MFC-heavy binaries most functions are thiscall, and a
    # wrong starting signature costs a rewrite per function.
    signature, conv_note = _convention_stub(cfg, va, func_name, func_lookup)

    return _render_annotation_block(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        profile=str(getattr(cfg, "compiler_profile", "")),
        func_name=func_name,
        ghidra_name=ghidra_name,
        xref_context=xref_context,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
        todo_text=todo,
        decomp_body=decomp_body,
        convention_stub=signature,
        convention_note=conv_note,
    )


def _convention_stub(
    cfg: ProjectConfig, va: int, func_name: str, func_lookup: FuncLookup | None = None
) -> tuple[str | None, str | None]:
    """Return a (signature_line, note) stub for *va* based on its calling
    convention, or ``(None, None)`` to keep the plain ``int __cdecl f(void)``
    default.  Best-effort: returns the default on any disassembly failure.
    Also returns ``(None, note)`` for thunk kinds the skeleton cannot
    reproduce as C — the note is written, the default signature kept.

    Emits:
    - ``void __fastcall f(void *self)`` for thiscall with no stack args
      (ecx=this, plain ``ret``).
    - a naked-asm template for thiscall with stack args (MSVC 5.0 has no
      ``__thiscall`` keyword — the body must be hand-written asm).
    - ``int __stdcall f(int a1, ...)`` for stdcall with N args.
    - the plain default for cdecl, with a note for ctor/EH-guard thunks.
    """
    arch = getattr(cfg, "arch", "")
    if arch not in ("x86_32", "x86_16"):
        return None, None
    try:
        from rebrew.asm import calling_convention, disassembled_extent_window

        # The shared extent-based window (asm.disassembled_extent_window)
        # keeps the epilogue's `ret` visible so inference works; we
        # disassemble once here and reuse the insns for the epilogue's
        # arg count.
        insns, _kind = disassembled_extent_window(cfg, va)
        if not insns:
            return None, None
        conv = calling_convention(insns)
    except Exception:  # best-effort stub shape
        logger.debug("stub-shape probe failed at 0x%08x", va, exc_info=True)
        return None, None

    # 16-bit targets: word-sized stack args (2 bytes) and the Borland
    # `pascal` keyword for callee-pop (MSVC/Watcom 16-bit use __stdcall).
    word_size = 4 if arch == "x86_32" else 2
    if arch == "x86_16":
        if conv == "stdcall":
            n = _ret_arg_count(insns, word_size)
            args = ", ".join(f"int a{i}" for i in range(1, n + 1))
            profile = str(getattr(cfg, "compiler_profile", ""))
            keyword = "pascal" if profile in ("tc16", "tc20", "borlandc55") else "__stdcall"
            return (
                f"int {keyword} {func_name}({args or 'void'})",
                None if keyword == "pascal" else f"{n} word arg(s) popped by callee (__stdcall)",
            )
        return None, None

    if conv == "thiscall (no stack args)":
        return f"int __fastcall {func_name}(void *self)", None
    if conv == "thiscall":
        n = _ret_arg_count(insns)
        args = ", ".join(f"int a{i}" for i in range(1, n + 1))
        retn = n * 4
        # MSVC 5.0 has no __thiscall — the ONLY way to express thiscall is
        # __declspec(naked) + inline asm (this in ecx).  Fence it: the naked
        # branch is used by round-trip verification builds (REBREW_ALLOW_NAKED),
        # the fallback keeps the comparison build compiling.
        sig = f"int {func_name}(void *self{', ' + args if args else ''})"
        return (
            f"#ifdef REBREW_ALLOW_NAKED\n__declspec(naked) {sig}\n#else\n{sig}\n#endif",
            f"thiscall + {n} stack arg(s) — MSVC 5.0 has no __thiscall; "
            f"write the body as inline asm (this in ecx) and end with `ret {retn}`",
        )
    if conv == "stdcall":
        n = _ret_arg_count(insns)
        args = ", ".join(f"int a{i}" for i in range(1, n + 1))
        return f"int __stdcall {func_name}({args or 'void'})", None
    if conv == "tail call":
        # Forwarding function: the terminating jmp reuses the caller's
        # frame, so the callee's decorated name (@N = bytes of args) gives
        # THIS function's stack-arg count (the stdcall/fastcall forwarding
        # pattern).  Best-effort — falls back to a plain signature + note.
        n, callee = _tail_call_arg_count(insns, cfg, func_lookup)
        if n:
            args = ", ".join(f"int a{i}" for i in range(1, n + 1))
            return (
                f"int __stdcall {func_name}({args})",
                f"ends in a tail call to {callee} ({n} stack arg(s) forwarded)",
            )
        return (
            None,
            "ends in a tail call — write the body; match the callee's "
            "signature if it takes args (forwarding pattern)",
        )
    if conv in ("thiscall (ctor thunk)", "thiscall (EH-guard thunk)", "tail-call thunk"):
        return None, f"{conv} — implement as a naked asm tail-jump"
    return None, None


FuncLookup = dict[int, tuple[str, str]]


def _tail_call_arg_count(
    insns: list[Any], cfg: ProjectConfig, func_lookup: FuncLookup | None = None
) -> tuple[int, str]:
    """Stack-arg count + callee name for a tail-calling function, if the
    jmp target's decorated name (``name@N``) resolves — ``(0, "")`` when
    unknown.  The @N is the callee's argument bytes (stdcall/fastcall), so
    for a frame-forwarding tail jmp it equals the caller's own stack args.
    Scans jmps backward (the window may include the next function's code);
    accepts the first one whose target resolves to a decorated name.

    *func_lookup* may carry a prebuilt VA→(name, status) map (see
    ``rebrew.asm.build_function_lookup``); building it scans the whole
    source tree, so batch callers pass one shared instance instead of
    paying a tree scan per instruction."""
    import re

    lazy_lookup = func_lookup
    for insn in reversed(insns):
        if insn.mnemonic != "jmp":
            continue
        m = re.search(r"0x([0-9a-fA-F]+)", insn.op_str)
        if m is None:
            continue
        target = int(m.group(1), 16)
        if lazy_lookup is None:
            try:
                from rebrew.asm import build_function_lookup

                lazy_lookup = build_function_lookup(cfg)
            except Exception:  # best-effort resolution
                logger.debug("function lookup build failed", exc_info=True)
                return 0, ""
        name, _status = lazy_lookup.get(target, ("", ""))
        dm = re.search(r"@(\d+)\s*$", name)
        if dm is not None:
            return max(0, int(dm.group(1)) // 4), name
    return 0, ""


def _ret_arg_count(insns: list[Any], word_size: int = 4) -> int:
    """Number of stack args implied by the function's ``ret N`` epilogue.

    *word_size* is 4 for x86-32 targets, 2 for 16-bit DOS/NE targets
    (word-sized stack args).
    """
    from rebrew.asm import ret_pop_count

    for insn in reversed(insns):
        if insn.mnemonic.startswith("ret"):
            n = ret_pop_count(insn.op_str)
            return max(0, n // word_size) if n else 0
    return 0


def generate_annotation_block(
    cfg: ProjectConfig,
    va: int,
    ghidra_name: str,
    module: str = "",
    custom_name: str | None = None,
    xref_context: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
    decomp_body: bool = False,
) -> str:
    """Generate an annotation block + stub body for appending to an existing file.

    Produces a compact block suitable for appending after existing code.
    """
    lib_modules = cfg.library_modules or set()
    marker = marker_for_module(module, "RELOC", lib_modules)

    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    # Same calling-convention-aware stub as generate_skeleton: append mode is
    # the common multi-function path, so thiscall/stdcall shapes must not
    # silently degrade to `int __cdecl f(void)` here (drift fixed — the
    # convention work was single-file-only before).
    signature, conv_note = _convention_stub(cfg, va, func_name)

    return _render_annotation_block(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        profile=str(getattr(cfg, "compiler_profile", "")),
        func_name=func_name,
        ghidra_name=ghidra_name,
        xref_context=xref_context,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
        decomp_body=decomp_body,
        convention_stub=signature,
        convention_note=conv_note,
    )


def fetch_xref_context(
    endpoint: str,
    program_path: str,
    va: int,
    *,
    max_callers: int = 5,
) -> str | None:
    """Fetch cross-reference context from Ghidra via ReVa MCP.

    Calls find-cross-references to get callers, then get-decompilation
    on the top callers to provide calling context.

    Returns a formatted comment block string, or None if MCP is unavailable.
    """
    _sync_mod = importlib.import_module("rebrew.ghidra.client")
    _fetch_mcp_tool_raw = _sync_mod.fetch_mcp_tool_raw
    _init_mcp_session = _sync_mod.init_mcp_session

    try:
        with httpx.Client(timeout=_sync_mod.MCP_REQUEST_TIMEOUT_S) as client:
            session_id = _init_mcp_session(client, endpoint)
            xrefs = _fetch_mcp_tool_raw(
                client,
                endpoint,
                "find-cross-references",
                {
                    "programPath": program_path,
                    "location": f"0x{va:08X}",
                    "direction": "to",
                    "includeFlow": True,
                    "includeData": True,
                    "includeContext": True,
                    "contextLines": 3,
                    "limit": max_callers * 2,
                },
                request_id=1,
                session_id=session_id,
            )

            if not isinstance(xrefs, dict):
                return None
            refs_raw = xrefs.get("referencesTo")
            if not isinstance(refs_raw, list) or not refs_raw:
                return None

            caller_rows: list[tuple[str, str, str]] = []
            seen_callers: set[tuple[str, str]] = set()
            data_rows: list[tuple[str, str, str]] = []
            for ref in refs_raw:
                if not isinstance(ref, dict):
                    continue
                from_address = ref.get("fromAddress")
                if not isinstance(from_address, str) or not from_address:
                    continue

                from_function = ref.get("fromFunction")
                from_symbol = ref.get("fromSymbol")
                function_name = "unknown"
                context = ""
                if isinstance(from_function, dict):
                    name_raw = from_function.get("name")
                    if isinstance(name_raw, str) and name_raw:
                        function_name = name_raw
                    context_raw = from_function.get("context")
                    if isinstance(context_raw, str):
                        context = context_raw.strip()
                if function_name == "unknown" and isinstance(from_symbol, dict):
                    name_raw = from_symbol.get("name")
                    if isinstance(name_raw, str) and name_raw:
                        function_name = name_raw

                if ref.get("isCall") is True:
                    key = (function_name, from_address)
                    if key in seen_callers:
                        continue
                    seen_callers.add(key)
                    caller_rows.append((function_name, from_address, context))
                    continue

                if ref.get("isData") is True:
                    ref_kind = ref.get("referenceType")
                    ref_type = ref_kind if isinstance(ref_kind, str) and ref_kind else "DATA"
                    data_rows.append((function_name, from_address, ref_type))

            if not caller_rows and not data_rows:
                return None

            callers = caller_rows[:max_callers]
            decomp_by_address: dict[str, str] = {}
            request_id = 2
            for _, caller_addr, _ in callers:
                decomp = _fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-decompilation",
                    {
                        "programPath": program_path,
                        "functionNameOrAddress": caller_addr,
                        "limit": 30,
                    },
                    request_id=request_id,
                    session_id=session_id,
                )
                request_id += 1

                decomp_text = ""
                if isinstance(decomp, str):
                    decomp_text = decomp.strip()
                elif isinstance(decomp, dict):
                    for d_key in ("decompilation", "text", "code"):
                        candidate = decomp.get(d_key)
                        if isinstance(candidate, str) and candidate.strip():
                            decomp_text = candidate.strip()
                            break
                if decomp_text:
                    decomp_by_address[caller_addr] = decomp_text

            lines: list[str] = [f"/* === Cross-references ({len(callers)} callers) ===", " *"]
            for idx, (caller_name, caller_addr, caller_context) in enumerate(callers, start=1):
                lines.append(f" * Caller {idx}: {c_comment_safe(caller_name)} ({caller_addr})")
                if caller_context:
                    lines.extend(
                        f" *   {c_comment_safe(ctx_line.strip())}"
                        for ctx_line in caller_context.splitlines()
                        if ctx_line.strip()
                    )
                else:
                    lines.append(" *   (no call-site context)")
                lines.append(" *")

            if data_rows:
                lines.append(f" * Data references: {len(data_rows)}")
                for data_name, data_addr, data_type in data_rows:
                    lines.append(
                        f" *   {c_comment_safe(data_name)} ({data_addr}) [{c_comment_safe(data_type)}]"
                    )
                lines.append(" *")

            for caller_name, caller_addr, _ in callers:
                ctext = decomp_by_address.get(caller_addr)
                if not ctext:
                    continue
                lines.append(
                    f" * === Caller: {c_comment_safe(caller_name)} ({caller_addr}) - decompilation ==="
                )
                lines.extend(f" * {c_comment_safe(dec_line)}" for dec_line in ctext.splitlines())
                lines.append(" *")

            lines.append(" * === End cross-references ===")
            lines.append(" */")
            return "\n".join(lines)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
        # Sibling decompiler.py warns for the identical failure; a silent
        # None hides "why does my skeleton lack xref context" from the user.
        warnings.warn(
            f"Ghidra MCP cross-reference fetch failed for 0x{va:08x}: {exc}", stacklevel=2
        )
        return None


def generate_test_command(filepath: str, symbol: str, va: int, size: int, cflags: str) -> str:
    """Generate the rebrew test command to verify this function."""
    return f'rebrew test {filepath} --symbol {symbol} --va 0x{va:08x} --size {size} --cflags "{cflags}"'


def _stale_size_note(cfg: ProjectConfig, va: int, size: int) -> str | None:
    """Return a warning string when the resolved *size* looks stale — the
    disassembly extent runs past it, so the first `rebrew test --size N`
    would fail with SIZE_MISMATCH (a stale functions.txt entry truncates
    mid-code), or the entry spans SEVERAL merged functions.  None when the
    size is fine or cannot be cross-checked.  x86-32 only — the extent
    walker is an x86 disassembler."""
    if getattr(cfg, "arch", "") != "x86_32" or not cfg.target_binary.exists():
        return None
    from rebrew.binary_loader import function_extent_from_disasm

    # Merged-region check: an entry spanning several functions (a bad
    # functions.txt boundary) has multiple ret-terminated epilogues within
    # its declared size — the user should split it, not treat it as one.
    try:
        from rebrew.binary_loader import extract_raw_bytes

        raw = extract_raw_bytes(cfg.target_binary, va, min(size, 512))
        if raw:
            import capstone

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            insns = list(md.disasm(raw, va))
            # A ret that is the target of a conditional jump is an early
            # return (if/switch exit), NOT a function end — counting every
            # linear ret flagged single functions with early returns as
            # "merged" (sync-review F9).  Only rets that are not jcc targets
            # count as epilogues: a merged discovery entry has >= 2 such
            # epilogues, a single function with early returns exactly 1.
            jcc_targets: set[int] = set()
            for ins in insns:
                mnemonic = ins.mnemonic
                if mnemonic.startswith("j") and not mnemonic.startswith("jmp"):
                    for op in ins.operands:
                        if op.type == capstone.x86.X86_OP_IMM:
                            jcc_targets.add(op.imm)
            epilogues = {
                ins.address for ins in insns if ins.mnemonic.startswith("ret")
            } - jcc_targets
            if len(epilogues) >= 2:
                return (
                    f"declared size {size}B spans multiple functions "
                    f"({len(epilogues)} ret-terminated epilogues) — a merged discovery "
                    "entry; split into per-function files (each has its own VA/size)"
                )
    except Exception:  # best-effort advisory
        logger.debug("merged-region check failed at 0x%08x", va, exc_info=True)

    try:
        extent = function_extent_from_disasm(cfg.target_binary, va)
    except Exception:  # best-effort advisory
        logger.debug("extent disassembly failed at 0x%08x", va, exc_info=True)
        return None
    if extent is not None and size < extent:
        return (
            f"declared size {size}B is stale — code continues to at least {extent}B; "
            "run `rebrew asm --size <extent>` to see the real function, or "
            "`rebrew test --fix-size` once the body is written"
        )
    return None


def generate_diff_command(filepath: str, symbol: str, cflags: str) -> str:
    """Generate the rebrew diff command for byte-level comparison."""
    return f'rebrew diff {filepath} --symbol "{symbol}" --cflags "{cflags}"'


#: First-2-byte prefixes that plausibly start a real x86-32 function.  A
#: discovery entry whose first bytes match NONE of these is likely a data
#: region or a misaligned fragment (a bad function-list boundary), not
#: decompilable code — batch skeleton generation can skip those.
_POSSIBLE_FUNCTION_STARTS: set[int] = {
    0x55,
    0x56,
    0x53,
    0x57,
    0x54,
    0x5A,
    0x5B,
    0x5D,
    0x5E,
    0x5F,  # push/pop reg
    0x6A,
    0x68,
    0xE8,
    0xE9,
    0xEB,
    0xEA,
    0xC3,
    0xC2,
    0xCC,  # imm push / call/jmp/ret
    0xB0,
    0xB1,
    0xB2,
    0xB3,
    0xB4,
    0xB5,
    0xB6,
    0xB7,  # mov r8, imm8
    0xB8,
    0xB9,
    0xBA,
    0xBB,
    0xBC,
    0xBD,
    0xBE,
    0xBF,  # mov r32, imm32
    0x33,
    0x31,
    0x29,
    0x2B,
    0x03,
    0x01,
    0x39,
    0x3B,  # xor/sub/add/cmp
    0x85,
    0x84,
    0x80,
    0x81,
    0x82,
    0x83,
    0xC7,
    0xC6,  # test/cmp/mov mem
    0x8B,
    0x89,
    0x88,
    0x8A,
    0x8D,
    0x8F,
    0x8C,
    0x8E,  # mov/lea
    0x9C,
    0x9D,
    0x9E,
    0x9F,  # pushf/popf/etc
    0xA1,
    0xA0,
    0xA2,
    0xA3,
    0xA4,
    0xA5,
    0xA6,
    0xA7,  # moffs/string
    0x0F,
    0xF7,
    0xF6,
    0xFF,
    0xF8,
    0xF9,
    0xFA,
    0xFB,
    0xFC,
    0xFD,  # ext/test/inc/call/dec
    0x66,
    0x2E,
    0x3E,
    0x26,
    0x64,
    0x65,
    0x36,
    0x90,  # prefixes/nop
    0x75,
    0x74,
    0x76,
    0x77,
    0x72,
    0x73,
    0x70,
    0x71,
    0x7C,
    0x7D,
    0x7E,
    0x7F,
    0x78,
    0x79,
    0x7A,
    0x7B,  # jcc short
    0x50,
    0x51,
    0x52,
    0x5C,
    0x3C,
    0x3D,
    0x48,
    0x49,
    0x4A,
    0x4B,
    0x4C,
    0x4D,
    0x4E,
    0x4F,  # misc
}


def _looks_like_fragment(cfg: ProjectConfig, va: int) -> bool:
    """True when the entry at *va* likely is NOT real code: its first bytes
    match none of the common function-start prefixes (a data region or a
    misaligned discovery fragment).  Best-effort heuristic — a real
    function with an unusual start is misflagged, which is why this is
    opt-in.  32-bit PE only."""
    if getattr(cfg, "arch", "") != "x86_32" or not cfg.target_binary.exists():
        return False
    try:
        from rebrew.binary_loader import extract_raw_bytes

        raw = extract_raw_bytes(cfg.target_binary, va, 2)
    except Exception:  # best-effort
        logger.debug("prologue byte probe failed at 0x%08x", va, exc_info=True)
        return False
    if len(raw) < 2:
        return False
    return raw[0] not in _POSSIBLE_FUNCTION_STARTS


def _is_thunk(cfg: ProjectConfig, va: int) -> bool:
    """True when the function at *va* is a jump/import/call thunk — a single
    ``jmp`` (IAT or relative) or ``call X; jmp Y`` stub — rather than real
    code.  Batch skeleton generation skips these: they have no decompilable
    body.  32-bit PE only (16-bit NE disassembly needs the 16-bit decoder)."""
    if getattr(cfg, "arch", "") != "x86_32":
        return False
    try:
        import capstone

        from rebrew.binary_loader import extract_raw_bytes

        raw = extract_raw_bytes(cfg.target_binary, va, 16)
        if len(raw) < 2:
            return False
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        insns = list(md.disasm(raw, va, count=3))
        if not insns:
            return False
        i0 = insns[0]
        if i0.mnemonic == "jmp":
            return True  # import thunk / jump thunk
        if i0.mnemonic == "call" and len(insns) > 1 and insns[1].mnemonic == "jmp":
            return True  # call thunk (hotpatch / chained stub)
    except Exception:  # best-effort filter
        logger.debug("thunk probe failed at 0x%08x", va, exc_info=True)
        return False
    return False


def list_uncovered(
    ghidra_funcs: list[FunctionEntry],
    existing_vas: dict[int, str],
    cfg: ProjectConfig,
    min_size: int = 10,
    max_size: int = 9999,
    skip_fragments: bool = False,
) -> list[tuple[int, int, str]]:
    """List uncovered functions. Returns [(va, size, name)].

    With *skip_fragments*, entries whose first bytes match none of the
    common function-start prefixes (data regions / misaligned discovery
    fragments) are excluded — batch skeleton slots are not wasted on
    non-code.  Opt-in: the heuristic can misflag an unusual real function.
    """
    ignored_syms = set(
        cfg.ignored_symbols or []
    )  # Ghidra cache first (preferred sizes), then function-list-only functions
    # (r2/radare2) — the cache often misses recently added / CRT functions,
    # and batch mode must still be able to skeletonize them.
    funcs_by_va: dict[int, tuple[int, str]] = {}
    for func in ghidra_funcs:
        name = func.name if func.name else f"FUN_{func.va:08x}"
        funcs_by_va[func.va] = (func.size, name)
    func_list_path = getattr(cfg, "function_list", "")
    # ProjectConfig.function_list defaults to Path() — truthy and resolves to
    # "." — so guard on is_file(); never parse an unset/missing list.
    if func_list_path and Path(func_list_path).is_file():
        try:
            from rebrew.catalog import build_function_registry, parse_function_list

            reg = build_function_registry(
                parse_function_list(Path(func_list_path)),
                cfg,
                None,
                getattr(cfg, "target_binary", None),
            )
            for va, entry in reg.items():
                if entry["canonical_size"] <= 0 or va in funcs_by_va:
                    continue  # ghidra size wins on conflict
                funcs_by_va[va] = (
                    entry["canonical_size"],
                    entry.get("list_name") or entry.get("ghidra_name") or f"FUN_{va:08x}",
                )
        except (OSError, ValueError, KeyError):
            pass  # no usable function list — ghidra-only batch

    uncovered: list[tuple[int, int, str]] = []
    for va, (size, name) in funcs_by_va.items():
        if va in existing_vas:
            continue
        if size < min_size or size > max_size:
            continue
        if name in ignored_syms:
            continue
        if _is_thunk(cfg, va):
            continue  # no decompilable body — don't waste a skeleton slot
        if skip_fragments and _looks_like_fragment(cfg, va):
            continue  # data region / misaligned entry — not real code

        uncovered.append((va, size, name))

    uncovered.sort(key=lambda x: x[1])  # Sort by size
    return uncovered


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew skeleton 0x10003da0 · · · · · · · · Generate skeleton for one function\n\n"
    "  rebrew skeleton 0x10003da0 --name my_func · Custom function name\n\n"
    "  rebrew skeleton 0x10003da0 --append crt_env.c  Append to existing multi-function file\n\n"
    "  rebrew skeleton --batch 10 · · · · · · · · Generate 10 skeletons at once\n\n"
    "[bold]What it creates:[/bold]\n\n"
    "  A .c file with a FUNCTION marker and placeholder body. All volatile metadata "
    "(STATUS, SIZE, CFLAGS, BLOCKER) is written to rebrew-functions.toml, not into "
    "the file itself. With --append, the marker block is appended to an existing "
    ".c file for multi-function compilation units.\n\n"
    "[dim]See also: 'rebrew todo' for a prioritized action list with ROI scoring. "
    "Reads ghidra_functions.json and existing .c files to determine what's uncovered.[/dim]"
)

app = typer.Typer(
    help="Generate .c skeleton files for uncovered functions in the target binary.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _fetch_extras(
    cfg: ProjectConfig,
    va: int,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
) -> tuple[str | None, str, str | None]:
    """Fetch optional decompilation and cross-reference context for a VA.

    Returns (decomp_code, decomp_backend_name, xref_context).
    """
    d_code: str | None = None
    d_backend = ""
    xref_context_val: str | None = None
    if decomp:
        d_code, d_backend = fetch_decompilation(
            decomp_backend,
            cfg.target_binary,
            va,
            cfg.root,
            endpoint=endpoint,
        )
    if xrefs:
        _sync_mod = importlib.import_module("rebrew.ghidra.commands")
        _resolve = _sync_mod.resolve_program_path
        resolved_path = _resolve(cfg)
        xref_context_val = fetch_xref_context(
            endpoint,
            resolved_path,
            va,
        )
        if xref_context_val:
            console.print("  [dim]XREFs:[/] fetched caller context")
        else:
            console.print("  [dim]XREFs:[/] unavailable (MCP unreachable or no callers)")
    return d_code, d_backend, xref_context_val


def _run_batch_mode(
    cfg: ProjectConfig,
    ghidra_funcs: list[FunctionEntry],
    existing_vas: dict[int, str],
    batch: int,
    min_size: int,
    max_size: int,
    force: bool,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
    json_output: bool,
    dry_run: bool = False,
    decomp_body: bool = False,
    skip_fragments: bool = False,
) -> None:
    """Generate skeleton files in batch for the smallest uncovered functions."""
    root = cfg.root
    src_dir = cfg.reversed_dir
    uncovered = list_uncovered(
        ghidra_funcs, existing_vas, cfg, min_size, max_size, skip_fragments=skip_fragments
    )
    if not uncovered:
        if json_output:
            json_print(
                {
                    "action": "none",
                    "created": [],
                    "count": 0,
                    "dry_run": dry_run,
                    "message": "No uncovered functions found matching criteria.",
                }
            )
        else:
            console.print("No uncovered functions found matching criteria.")
        return

    count = min(batch, len(uncovered))
    created: list[dict[str, Any]] = []
    # Tail-call resolution needs a VA→(name, status) map; building it scans
    # the whole source tree, so build ONE instance for the whole batch.
    from rebrew.asm import build_function_lookup

    batch_func_lookup: FuncLookup = build_function_lookup(cfg)
    for va_val, size_val, name_val in uncovered[:count]:
        filename = make_filename(name_val, cfg=cfg)
        filepath = src_dir / filename
        rel_path = rel_display_path(filepath, root)

        if filepath.exists() and not force:
            console.print(f"[yellow]SKIP[/] {rel_path} (already exists)")
            continue

        d_code, d_backend, xref_context_val = _fetch_extras(
            cfg,
            va_val,
            decomp,
            decomp_backend,
            xrefs,
            endpoint,
        )
        content = generate_skeleton(
            cfg,
            va_val,
            name_val,
            xref_context=xref_context_val,
            decomp_code=d_code,
            decomp_backend=d_backend,
            decomp_body=decomp_body,
            func_lookup=batch_func_lookup,
        )
        if dry_run:
            console.print(f"[dim]Would create[/dim] {rel_path} ({size_val}B)")
        else:
            atomic_write_text(filepath, content, encoding="utf-8")
            _write_skeleton_metadata(cfg, va_val, size_val, cfg.marker)

        symbol_val = "_" + sanitize_name(name_val)
        # User-facing cflags only — base_cflags (/nologo /c /MT) are prepended by compile_to_obj.
        # resolve_cflags keeps the suggested TEST command in sync with what
        # test/verify actually compile with (no MSVC fallback on posix profiles).
        cflags_val = resolve_cflags(cfg, "")
        test_cmd = generate_test_command(rel_path, symbol_val, va_val, size_val, cflags_val)
        size_warning = _stale_size_note(cfg, va_val, size_val)

        if not dry_run:
            console.print(f"[bold green]CREATED[/] {rel_path} ({size_val}B)")
        console.print(f"  [dim]TEST:[/] {test_cmd}")
        if size_warning:
            console.print(f"  [yellow]warning:[/yellow] {size_warning}")
        created.append(
            {
                "file": str(rel_path),
                "va": f"0x{va_val:08x}",
                "size": size_val,
                "size_warning": size_warning,
                "symbol": symbol_val,
                "test_command": test_cmd,
            }
        )

    if json_output:
        key = "would_create" if dry_run else "created"
        json_print(
            {
                "action": key,
                key: created,
                "count": len(created),
                "dry_run": dry_run,
            }
        )
    else:
        label = "Dry run:" if dry_run else "Created"
        console.print(f"\n[bold]{label} {len(created)} skeleton files.[/]")


def _write_skeleton_metadata(cfg: ProjectConfig, va_int: int, size: int, module_val: str) -> None:
    """Record SIZE for a freshly created skeleton when metadata lacks it.

    Without SIZE the function shows MISSING_SIZE and cannot be verified
    (rebrew test / verify need it to extract target bytes).  Only fills
    the gap — never overwrites an existing SIZE or touches STATUS.
    """
    from rebrew.metadata import get_entry, update_field

    existing = get_entry(cfg.metadata_dir, va_int, module_val)
    if "size" not in existing:
        update_field(cfg.metadata_dir, va_int, "size", size, module=module_val)


def _run_append_mode(
    cfg: ProjectConfig,
    va_int: int,
    size: int,
    ghidra_name: str,
    module_val: str,
    append: str,
    name: str | None,
    force: bool,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
    json_output: bool,
    dry_run: bool = False,
    decomp_body: bool = False,
) -> None:
    """Append a function annotation block to an existing .c file."""
    root = cfg.root
    src_dir = cfg.reversed_dir
    append_path = Path(append)
    if not append_path.is_absolute():
        append_path = src_dir / append_path
    if not append_path.exists():
        error_exit(f"--append target does not exist: {append_path}", json_mode=json_output)

    if not force:
        existing_in_file = parse_c_file_multi(
            append_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
        )
        for entry in existing_in_file:
            if entry.va == va_int:
                error_exit(
                    f"VA 0x{va_int:08x} already in {append_path.name} — "
                    f"re-run with --force to append anyway (nothing was written)",
                    json_mode=json_output,
                )

    decomp_code_val, decomp_backend_name, xref_context_val = _fetch_extras(
        cfg,
        va_int,
        decomp,
        decomp_backend,
        xrefs,
        endpoint,
    )

    block = generate_annotation_block(
        cfg,
        va_int,
        ghidra_name,
        module_val,
        name,
        xref_context=xref_context_val,
        decomp_code=decomp_code_val,
        decomp_backend=decomp_backend_name,
        decomp_body=decomp_body,
    )

    # Ensure there's a blank line separator before the new block.  Read with
    # the tolerant reader and write back in the file's own encoding so
    # legacy-encoded sources (cp1252/shift_jis) survive the append.
    existing_text, encoding = read_source_text(append_path)
    separator = (
        "" if existing_text.endswith("\n\n") else "\n" if existing_text.endswith("\n") else "\n\n"
    )
    if dry_run:
        console.print(f"[dim]Would append[/dim] to {rel_display_path(append_path, root)}")
    else:
        atomic_write_text(append_path, existing_text + separator + block, encoding=encoding)
        _write_skeleton_metadata(cfg, va_int, size, module_val)

    rel_path_val = rel_display_path(append_path, root)
    symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
    if not dry_run:
        console.print(f"[bold green]APPENDED[/] to {rel_path_val}:")
    console.print(f"  VA:     [cyan]0x{va_int:08x}[/]")
    console.print(f"  Size:   {size}B")
    console.print(f"  Symbol: [magenta]{symbol_val}[/]")
    console.print()
    console.print("Test all functions in this file:")
    console.print(f"  [dim]rebrew test {rel_path_val}[/]")
    if json_output:
        json_print(
            {
                "action": "would_append" if dry_run else "appended",
                "dry_run": dry_run,
                "file": str(rel_path_val),
                "va": f"0x{va_int:08x}",
                "size": size,
                "symbol": symbol_val,
                "test_command": f"rebrew test {rel_path_val}",
            }
        )


def _run_single_va_mode(
    cfg: ProjectConfig,
    va_int: int,
    size: int,
    ghidra_name: str,
    module_val: str,
    name: str | None,
    output: str | None,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
    json_output: bool,
    dry_run: bool = False,
    decomp_body: bool = False,
) -> None:
    """Create a new single-function .c skeleton file."""
    root = cfg.root
    src_dir = cfg.reversed_dir
    filename_val = make_filename(ghidra_name, name, cfg=cfg)
    filepath_val = Path(output) if output else src_dir / filename_val
    rel_path_val = rel_display_path(filepath_val, root)

    decomp_code_val, decomp_backend_name, xref_context_val = _fetch_extras(
        cfg,
        va_int,
        decomp,
        decomp_backend,
        xrefs,
        endpoint,
    )
    if decomp and decomp_code_val:
        console.print(f"  [dim]Decompiler:[/] {decomp_backend_name}")
    elif decomp:
        console.print("  [dim]Decompiler:[/] no output (backend unavailable or failed)")

    content_val = generate_skeleton(
        cfg,
        va_int,
        ghidra_name,
        module_val,
        name,
        xref_context=xref_context_val,
        decomp_code=decomp_code_val,
        decomp_backend=decomp_backend_name,
        decomp_body=decomp_body,
    )
    if dry_run:
        console.print(f"[dim]Would create[/dim] {rel_path_val}")
    else:
        atomic_write_text(filepath_val, content_val, encoding="utf-8")
        _write_skeleton_metadata(cfg, va_int, size, module_val)

    # Compute test commands
    symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
    # User-facing cflags only — base_cflags (/nologo /c /MT) are prepended by compile_to_obj.
    # resolve_cflags keeps the suggested TEST/DIFF commands in sync with what
    # test/verify actually compile with (no MSVC fallback on posix profiles).
    cflags_val = resolve_cflags(cfg, "")

    test_cmd = generate_test_command(str(rel_path_val), symbol_val, va_int, size, cflags_val)
    diff_cmd = generate_diff_command(str(rel_path_val), symbol_val, cflags_val)

    if json_output:
        json_print(
            {
                "action": "would_create" if dry_run else "created",
                "dry_run": dry_run,
                "file": str(rel_path_val),
                "va": f"0x{va_int:08x}",
                "size": size,
                "size_warning": _stale_size_note(cfg, va_int, size),
                "symbol": symbol_val,
                "test_command": test_cmd,
                "diff_command": diff_cmd,
            }
        )
    else:
        size_warning = _stale_size_note(cfg, va_int, size)
        if not dry_run:
            console.print(f"[bold green]Created:[/] {rel_path_val}")
        console.print(f"  VA:     [cyan]0x{va_int:08x}[/]")
        console.print(f"  Size:   {size}B")
        if size_warning:
            console.print(f"  [yellow]warning:[/yellow] {size_warning}")
        console.print(f"  Symbol: [magenta]{symbol_val}[/]")
        console.print()
        console.print("[bold]Test command:[/]")
        console.print(f"  [dim]{test_cmd}[/]")
        console.print()
        console.print("[bold]Diff command:[/]")
        console.print(f"  [dim]{diff_cmd}[/]")
        console.print()
        console.print("[bold]Next steps:[/]")
        console.print(f"  1. Get Ghidra decompilation for [cyan]0x{va_int:08x}[/]")
        console.print("  2. Replace the TODO placeholder with actual C89 code")
        console.print(
            "  3. Ensure C89 compliance: vars at block top, no // comments in body, no for(int ...)"
        )
        console.print("  4. Run the test command above to check match")
        console.print("  5. Run 'rebrew test' which auto-promotes STATUS based on result")
        console.print("  6. If NEAR_MATCHING, add BLOCKER metadata explaining the difference")


@app.callback(invoke_without_command=True)
def main(
    va: str | None = typer.Argument(None, help="Function VA in hex (e.g. 0x10003da0)"),
    name: str | None = typer.Option(None, "--name", help="Custom function name"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    batch: int | None = typer.Option(None, "--batch", help="Generate N skeletons (smallest first)"),
    skip_fragments: bool = typer.Option(
        False,
        "--skip-fragments",
        help="(batch) Exclude entries whose first bytes look like data/fragments "
        "(no common function-start prefix) — don't waste skeleton slots on non-code",
    ),
    min_size: int = typer.Option(10, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(9999, "--max-size", help="Maximum function size"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing files"),
    append: str | None = typer.Option(
        None,
        "--append",
        help="Append function to an existing .c file (multi-function file)",
    ),
    decomp: bool = typer.Option(False, "--decomp", help="Embed decompilation in skeleton"),
    decomp_body: bool = typer.Option(
        False,
        "--decomp-body",
        help="With --decomp: write the decompiled C as the function BODY (a real "
        "GA seed) instead of a comment block",
    ),
    decomp_backend: str = typer.Option(
        "auto",
        "--decomp-backend",
        help="Decompiler backend: auto, r2ghidra, r2dec, ghidra",
    ),
    xrefs: bool = typer.Option(
        False,
        "--xrefs",
        help="Fetch cross-references from Ghidra and embed in skeleton",
    ),
    endpoint: str = typer.Option(
        "http://localhost:8080/mcp/message",
        "--endpoint",
        help="ReVa MCP endpoint URL",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate .c skeleton files for uncovered target binary functions."""
    # --decomp-body is meaningless without --decomp: the body option only
    # changes how the decompiled C is embedded, and without a decompiler
    # pass the user gets a silent no-op stub (previously an accepted-but-
    # inert flag).  Fail loudly instead of pretending the option applied.
    if decomp_body and not decomp:
        # Flag-combination usage error — exit 2, not "needs code work" (1).
        error_exit(
            "--decomp-body requires --decomp (it selects how the decompiled "
            "C is written into the skeleton)",
            json_mode=json_output,
            code=EXIT_ERROR,
        )
    va_str = va
    cfg = require_config(target=target, json_mode=json_output)
    src_dir = cfg.reversed_dir

    ghidra_json = src_dir / FUNCTION_STRUCTURE_JSON
    try:
        ghidra_funcs = load_function_structure(ghidra_json)
    except ValueError as exc:
        # Corrupt cache — exit with a clear error rather than a raw traceback.
        # (An empty/missing cache is handled by load_function_structure and
        # falls through to the function-list path below.)
        error_exit(f"Corrupt {FUNCTION_STRUCTURE_JSON}: {exc}", json_mode=json_output)
    existing_vas = load_existing_vas(src_dir, cfg=cfg)

    # --batch mode
    if batch:
        _run_batch_mode(
            cfg,
            ghidra_funcs,
            existing_vas,
            batch,
            min_size,
            max_size,
            force,
            decomp,
            decomp_backend,
            xrefs,
            endpoint,
            json_output,
            dry_run=dry_run,
            decomp_body=decomp_body,
            skip_fragments=skip_fragments,
        )
        return

    # Single VA or append — both require a VA argument
    if not va_str:
        error_exit("VA required for single mode.", json_mode=json_output)

    va_int = parse_va(va_str, json_mode=json_output)

    # Find in Ghidra functions
    ghidra_entry = None
    for func in ghidra_funcs:
        if func.va == va_int:
            ghidra_entry = func
            break

    size: int
    ghidra_name: str
    if ghidra_entry is not None:
        size = ghidra_entry.size
        ghidra_name = ghidra_entry.name if ghidra_entry.name else f"FUN_{va_int:08x}"
    else:
        # Fall back to the function list (r2/radare2) — many real functions
        # (e.g. recently added CRT ones) exist only there, not in the Ghidra
        # cache.  Use the registry's canonical size when available.
        from rebrew.catalog import build_function_registry, parse_function_list

        func_list_path = getattr(cfg, "function_list", "")
        try:
            list_funcs = (
                parse_function_list(Path(func_list_path))
                if func_list_path and Path(func_list_path).is_file()
                else []
            )
            reg_entry = build_function_registry(
                list_funcs,
                cfg,
                None,
                getattr(cfg, "target_binary", None),
            ).get(va_int)
        except (OSError, ValueError, KeyError):
            reg_entry = None  # no usable function list — fall through to not-found
        if reg_entry and reg_entry["canonical_size"] > 0:
            size = reg_entry["canonical_size"]
            ghidra_name = (
                reg_entry.get("list_name") or reg_entry.get("ghidra_name") or f"FUN_{va_int:08x}"
            )
        else:
            error_exit(
                f"VA 0x{va_int:08x} not found in {FUNCTION_STRUCTURE_JSON} or the function list",
                json_mode=json_output,
            )

    # Check if already covered
    if va_int in existing_vas and not force and not append:
        covered_by = existing_vas[va_int]
        if json_output:
            json_print(
                {
                    "action": "none",
                    "va": f"0x{va_int:08x}",
                    "covered_by": covered_by,
                    "message": "Already covered by an existing source file; use --force to overwrite.",
                }
            )
        else:
            console.print(f"Already covered by: {covered_by}")
            console.print("Use [cyan]--force[/] to overwrite.")
        raise typer.Exit(code=0)

    module_val = cfg.marker  # Use the project marker as module name

    # --append mode: add marker block to an existing file
    if append:
        _run_append_mode(
            cfg,
            va_int,
            size,
            ghidra_name,
            module_val,
            append,
            name,
            force,
            decomp,
            decomp_backend,
            xrefs,
            endpoint,
            json_output,
            dry_run=dry_run,
            decomp_body=decomp_body,
        )
        return

    # Default: single VA mode — create a new skeleton file
    _run_single_va_mode(
        cfg,
        va_int,
        size,
        ghidra_name,
        module_val,
        name,
        output,
        decomp,
        decomp_backend,
        xrefs,
        endpoint,
        json_output,
        dry_run=dry_run,
        decomp_body=decomp_body,
    )


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
