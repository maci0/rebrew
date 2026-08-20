"""prove.py — Symbolic equivalence prover for rebrew.

Uses angr's symbolic execution and Z3 constraint solving to mathematically
prove that a compiled function is semantically equivalent to the original
binary, even when byte-level comparison fails due to different register
allocation, instruction reordering, or loop unrolling.

Architecture
~~~~~~~~~~~~
1. Extract target bytes from the DLL and compiled bytes from the .obj
2. Load both into separate angr Projects using the ``blob`` backend
3. Read the ``PROTOTYPE`` field from rebrew-function.toml metadata for calling convention + arg count
4. Hook IAT-indirect calls with Win32 API-aware SimProcedures (constrained
   return values) to prevent path explosion from API calls.  Falls back to
   ``ReturnUnconstrained`` for unknown APIs.
5. Apply user-specified argument constraints from ``prove_constraints``
   metadata (e.g. "arg3 is a pointer to a 24-byte struct")
6. Run symbolic execution on both with ``LoopSeer`` and timeout limits
7. Compare EAX (return register) formulas via Z3 — if no satisfying
   assignment makes them differ, the functions are proven equivalent

angr is an optional dependency.  Import is guarded with a clear error
message directing users to ``uv pip install -e ".[prove]"``.
"""

from __future__ import annotations

import logging
import re
import shutil
import struct
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console

if TYPE_CHECKING:
    import angr  # noqa: F401  # only for annotations; runtime import is lazy

from rebrew.annotation import parse_c_file_multi, resolve_symbol
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    EXIT_OK,
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    parse_va,
    require_config,
    resolve_source_arg,
    target_marker,
)
from rebrew.compile import compile_to_obj
from rebrew.config import ProjectConfig
from rebrew.core import build_iat_region, build_name_to_va, smart_reloc_compare
from rebrew.matcher.parsers import parse_obj_relocs_full, parse_obj_symbol_bytes
from rebrew.utils import safe_shlex_split

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Guarded angr import
# ---------------------------------------------------------------------------

_ANGR_MISSING_MSG = (
    "angr is required for 'rebrew prove'.  Install it with:\n  uv pip install -e \".[prove]\""
)


def _require_angr() -> None:
    """Raise a clear error if angr is not installed."""
    try:
        import angr  # noqa: F401
    except ImportError:
        raise ImportError(_ANGR_MISSING_MSG)


# ---------------------------------------------------------------------------
# Win32 API SimProcedures
# ---------------------------------------------------------------------------
#
# Common Win32 APIs that cause path explosion when symbolically executed.
# Each is modelled with an appropriate return value (symbolic, zero, or void).
# Memory-writing APIs (memcpy, memset) are modelled to update symbolic memory.

_WIN32_SIMPROCS: dict[str, type] | None = None  # lazily populated


def _cached_verify_status(cfg: Any, va: int) -> str | None:
    """Return the verify-cache status for *va* (target-guarded), or None.

    Mirrors status.py/todo.py's overlay: the metadata STATUS can lag the
    measured verify result, and prove's NEAR_MATCHING gate must accept the
    measured truth rather than refuse a function the verifier already
    classified as nearly matching.
    """
    import json

    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if not cache_path.exists():
        return None
    try:
        from rebrew.verify import VerifyCache

        data = VerifyCache.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError, ValueError, AttributeError, ImportError):
        return None
    if data.version != 1:
        return None
    if data.target and data.target != getattr(cfg, "target_name", None):
        return None
    entry = data.entries.get(f"0x{va:08x}")
    return entry.result.status if entry is not None else None


def _get_win32_simprocs() -> dict[str, type]:
    """Build and cache the Win32 SimProcedure registry (requires angr)."""
    global _WIN32_SIMPROCS  # noqa: PLW0603
    if _WIN32_SIMPROCS is not None:
        return _WIN32_SIMPROCS

    import angr
    import claripy

    class ReturnSymbolicDword(angr.SimProcedure):
        """Generic: return a fresh unconstrained 32-bit symbolic value."""

        def run(self, *args: Any, **kwargs: Any) -> Any:
            return self.state.solver.BVS("api_retval", 32)  # type: ignore[no-untyped-call]

    class ReturnSymbolicHandle(angr.SimProcedure):
        """Return a symbolic HANDLE (non-zero, non-INVALID_HANDLE_VALUE)."""

        def run(self, *args: Any, **kwargs: Any) -> Any:
            h = self.state.solver.BVS("handle", 32)  # type: ignore[no-untyped-call]
            self.state.solver.add(h != 0)
            self.state.solver.add(h != 0xFFFFFFFF)
            return h

    class ReturnSymbolicBool(angr.SimProcedure):
        """Return 0 or 1 (symbolic BOOL)."""

        def run(self, *args: Any, **kwargs: Any) -> Any:
            b = self.state.solver.BVS("bool_ret", 32)  # type: ignore[no-untyped-call]
            self.state.solver.add(claripy.ULE(b, 1))
            return b

    class ReturnVoid(angr.SimProcedure):
        """Void return — no value, no side effects."""

        def run(self, *args: Any, **kwargs: Any) -> None:
            return

    class SimLocalAlloc(angr.SimProcedure):
        def run(self, *args: Any, **kwargs: Any) -> Any:
            ptr = self.state.heap.allocate(256)  # type: ignore[attr-defined]
            for i in range(256):
                self.state.memory.store(ptr + i, claripy.BVV(0, 8))  # type: ignore[no-untyped-call]
            return ptr

    class SimGlobalLock(angr.SimProcedure):
        def run(self, *args: Any, **kwargs: Any) -> Any:
            ptr = self.state.heap.allocate(256)  # type: ignore[attr-defined]
            for i in range(256):
                self.state.memory.store(ptr + i, claripy.BVV(0, 8))  # type: ignore[no-untyped-call]
            return ptr

    class SimMemcpy(angr.SimProcedure):
        """Model memcpy: copy src→dst symbolically, return dst."""

        def run(self, dst: Any, src: Any, n: Any) -> Any:
            # Concretise length to avoid explosion; cap at 1024.  If the
            # solver cannot concretise n, let the exception propagate — angr
            # marks the state errored and it is excluded from the terminal
            # states, so the proof fails closed instead of silently treating
            # the memcpy as a no-op (which could fake an equivalence).
            length = min(self.state.solver.eval(n), 1024)
            if length > 0:
                data = self.state.memory.load(src, length)  # type: ignore[no-untyped-call]
                self.state.memory.store(dst, data)  # type: ignore[no-untyped-call]
            return dst

    class SimMemset(angr.SimProcedure):
        """Model memset: fill dst with byte value, return dst."""

        def run(self, dst: Any, val: Any, n: Any) -> Any:
            # Same fail-closed policy as SimMemcpy: a solver failure on the
            # length propagates and errors the state rather than no-op'ing
            # the memset on both sides (which could fake equivalence).
            length = min(self.state.solver.eval(n), 1024)
            if length > 0:
                byte_val = claripy.Extract(7, 0, val)
                for i in range(length):
                    self.state.memory.store(dst + i, byte_val)  # type: ignore[no-untyped-call]
            return dst

    class SimStrlen(angr.SimProcedure):
        """Model strlen: return symbolic non-negative length."""

        def run(self, s: Any) -> Any:
            result = self.state.solver.BVS("strlen_ret", 32)  # type: ignore[no-untyped-call]
            self.state.solver.add(claripy.ULE(result, 0x10000))  # bound to 64K
            return result

    # Registry: map Win32/CRT names to SimProcedure classes
    _WIN32_SIMPROCS = {}

    # --- CRT functions with semantic models ---
    for name in ("memcpy", "_memcpy"):
        _WIN32_SIMPROCS[name] = SimMemcpy
    for name in ("memset", "_memset"):
        _WIN32_SIMPROCS[name] = SimMemset
    for name in ("strlen", "_strlen", "lstrlenA"):
        _WIN32_SIMPROCS[name] = SimStrlen

    # --- File I/O ---
    for name in ("CreateFileA", "CreateFileW", "_lopen", "_lcreat"):
        _WIN32_SIMPROCS[name] = ReturnSymbolicHandle
    for name in (
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "FlushFileBuffers",
        "SetEndOfFile",
        "SetFilePointer",
        "DeleteFileA",
        "DeleteFileW",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicBool

    # --- Memory allocation ---
    for name in (
        "HeapAlloc",
        "HeapReAlloc",
        "GlobalAlloc",
        "LocalReAlloc",
        "GlobalReAlloc",
        "VirtualAlloc",
        "malloc",
        "_malloc",
        "calloc",
        "_calloc",
        "realloc",
        "_realloc",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicHandle  # non-zero pointer
    for name in ("HeapFree", "LocalFree", "GlobalFree", "VirtualFree", "free", "_free"):
        _WIN32_SIMPROCS[name] = ReturnVoid

    # --- Window / GDI ---
    for name in ("GetDC", "CreateCompatibleDC", "GetWindowDC"):
        _WIN32_SIMPROCS[name] = ReturnSymbolicHandle
    for name in (
        "ReleaseDC",
        "DeleteDC",
        "InvalidateRect",
        "UpdateWindow",
        "ShowWindow",
        "EnableWindow",
        "DestroyWindow",
        "PostMessageA",
        "PostMessageW",
        "IsWindow",
        "IsWindowVisible",
        "IsWindowEnabled",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicBool
    for name in (
        "SendMessageA",
        "SendMessageW",
        "SendDlgItemMessageA",
        "SendDlgItemMessageW",
        "DefWindowProcA",
        "DefWindowProcW",
        "CallWindowProcA",
        "CallWindowProcW",
        "GetDlgItem",
        "GetDlgItemInt",
        "GetDlgItemTextA",
        "GetDlgItemTextW",
        "SetDlgItemTextA",
        "SetDlgItemTextW",
        "SetDlgItemInt",
        "DialogBoxParamA",
        "DialogBoxParamW",
        "GetDlgCtrlID",
        "ChildWindowFromPoint",
        "GetCursorPos",
        "ScreenToClient",
        "WinHelpA",
        "WinHelpW",
        "GetSaveFileNameA",
        "GetSaveFileNameW",
        "MessageBoxA",
        "MessageBoxW",
        "CreateDCW",
        "GlobalUnlock",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicDword

    # --- Registry ---
    for name in (
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "RegQueryValueExA",
        "RegQueryValueExW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCloseKey",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegDeleteKeyA",
        "RegDeleteValueA",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicDword  # LONG error code

    # --- String ---
    for name in ("lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW"):
        _WIN32_SIMPROCS[name] = ReturnSymbolicDword
    for name in (
        "lstrcmpA",
        "lstrcmpW",
        "lstrcmpiA",
        "lstrcmpiW",
        "CompareStringA",
        "CompareStringW",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicDword
    for name in ("lstrlenW", "wcslen", "_wcslen"):
        _WIN32_SIMPROCS[name] = SimStrlen

    # --- Synchronisation ---
    for name in (
        "EnterCriticalSection",
        "LeaveCriticalSection",
        "InitializeCriticalSection",
        "DeleteCriticalSection",
    ):
        _WIN32_SIMPROCS[name] = ReturnVoid

    # --- Misc OS ---
    for name in (
        "GetLastError",
        "SetLastError",
        "GetTickCount",
        "GetCurrentThreadId",
        "GetCurrentProcessId",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryW",
        "FreeLibrary",
        "LoadCursorA",
        "LoadCursorW",
        "LoadIconA",
        "LoadIconW",
        "GetStockObject",
        "GetSystemMetrics",
        "GetDeviceCaps",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicDword

    # --- Format / print (avoid deep execution) ---
    for name in (
        "wsprintfA",
        "wsprintfW",
        "sprintf",
        "_sprintf",
        "wvsprintfA",
        "wvsprintfW",
        "_snprintf",
    ):
        _WIN32_SIMPROCS[name] = ReturnSymbolicDword

    _WIN32_SIMPROCS["GlobalLock"] = SimGlobalLock
    _WIN32_SIMPROCS["LocalAlloc"] = SimLocalAlloc
    return _WIN32_SIMPROCS


# ---------------------------------------------------------------------------
# Argument constraint support
# ---------------------------------------------------------------------------


def _apply_arg_constraints(
    state: Any,
    sym_args: list[Any],
    constraints: dict[str, Any],
) -> None:
    """Apply user-specified constraints to symbolic function arguments.

    Constraint spec is a dict like::

        {"arg0": {"type": "pointer", "struct_size": 24},
         "arg1": {"type": "range", "min": 0, "max": 255}}

    Supported types:
        - ``pointer``: Allocate a concrete region and point the arg at it.
          Optional ``struct_size`` (default 32 bytes).  When a ``fields``
          dict is present, specific offsets within the allocated struct are
          initialised to constrained symbolic values (overriding the generic
          fill).  Field types:

          - ``handle``: Non-zero, non-INVALID_HANDLE_VALUE 32-bit symbolic.
          - ``pointer``: Concrete pointer to a secondary allocated region
            filled with symbolic bytes (``size`` subkey, default 32).
          - ``dword``: Unconstrained 32-bit symbolic (already handled by
            the generic fill — listed for completeness).
          - ``word``: Unconstrained 16-bit symbolic (stored as 32-bit LE).
          - ``byte``: Unconstrained 8-bit symbolic (stored as 32-bit LE).
          - ``zero``: Concrete zero (32-bit).
          - ``nonzero``: Non-zero 32-bit symbolic.
          - ``range``: Constrained to [min, max] (unsigned).
          - ``concrete``: A specific concrete value (``value`` subkey).

        - ``range``: Constrain to unsigned [min, max].
        - ``bitmask``: Only bits in ``mask`` may be set.
        - ``null``: Force arg == 0.
        - ``nonzero``: Force arg != 0.
    """
    import claripy

    for key, spec in constraints.items():
        m = re.match(r"arg(\d+)", key)
        if not m or int(m.group(1)) >= len(sym_args):
            continue
        idx = int(m.group(1))
        arg = sym_args[idx]

        if not isinstance(spec, dict):
            continue
        constraint_type = spec.get("type", "unconstrained")

        if constraint_type == "pointer":
            struct_size = int(spec.get("struct_size", 32))
            alloc_base = 0xA000_0000 + idx * 0x1000
            state.solver.add(arg == alloc_base)
            # Fill the pointed-to region with symbolic bytes
            for off in range(0, struct_size, 4):
                sym_field = claripy.BVS(f"arg{idx}_field_{off:#x}", 32)
                state.memory.store(alloc_base + off, sym_field, endness="Iend_LE")

            # Deep field initialization — override specific offsets with
            # constrained symbolic values when a "fields" dict is present.
            fields = spec.get("fields")
            if fields and isinstance(fields, dict):
                for off_str, field_spec in fields.items():
                    off = int(str(off_str), 0)  # parse "0x04" or "4"
                    if not isinstance(field_spec, dict):
                        continue
                    ftype = field_spec.get("type", "dword")
                    addr = alloc_base + off

                    if ftype == "handle":
                        h = claripy.BVS(f"arg{idx}_handle_{off:#x}", 32)
                        state.solver.add(h != 0)
                        state.solver.add(h != 0xFFFFFFFF)
                        state.memory.store(addr, h, endness="Iend_LE")
                    elif ftype == "pointer":
                        # Allocate a secondary region for nested pointer
                        nested_base = 0xB000_0000 + idx * 0x1000 + off * 0x100
                        p = claripy.BVV(nested_base, 32)
                        state.memory.store(addr, p, endness="Iend_LE")
                        # Fill nested region with symbolic bytes
                        nested_size = int(field_spec.get("size", 32))
                        for noff in range(0, nested_size, 4):
                            sym_nested = claripy.BVS(f"arg{idx}_nested_{off:#x}_{noff:#x}", 32)
                            state.memory.store(nested_base + noff, sym_nested, endness="Iend_LE")
                    elif ftype == "word":
                        w = claripy.BVS(f"arg{idx}_word_{off:#x}", 16)
                        state.memory.store(addr, w.zero_extend(16), endness="Iend_LE")
                    elif ftype == "byte":
                        b = claripy.BVS(f"arg{idx}_byte_{off:#x}", 8)
                        state.memory.store(addr, b.zero_extend(24), endness="Iend_LE")
                    elif ftype == "zero":
                        state.memory.store(addr, claripy.BVV(0, 32), endness="Iend_LE")
                    elif ftype == "nonzero":
                        nz = claripy.BVS(f"arg{idx}_nz_{off:#x}", 32)
                        state.solver.add(nz != 0)
                        state.memory.store(addr, nz, endness="Iend_LE")
                    elif ftype == "range":
                        r = claripy.BVS(f"arg{idx}_range_{off:#x}", 32)
                        lo = int(field_spec.get("min", 0))
                        hi = int(field_spec.get("max", 0xFFFF_FFFF))
                        state.solver.add(claripy.UGE(r, lo))
                        state.solver.add(claripy.ULE(r, hi))
                        state.memory.store(addr, r, endness="Iend_LE")
                    elif ftype == "concrete":
                        val = int(str(field_spec.get("value", 0)), 0)
                        state.memory.store(addr, claripy.BVV(val, 32), endness="Iend_LE")
                    # "dword" is already handled by the generic fill above

        elif constraint_type == "range":
            lo = int(spec.get("min", 0))
            hi = int(spec.get("max", 0xFFFF_FFFF))
            state.solver.add(claripy.UGE(arg, lo))
            state.solver.add(claripy.ULE(arg, hi))

        elif constraint_type == "bitmask":
            mask = int(str(spec.get("mask", "0xFFFFFFFF")), 0)
            state.solver.add((arg & ~mask) == 0)

        elif constraint_type == "null":
            state.solver.add(arg == 0)

        elif constraint_type == "nonzero":
            state.solver.add(arg != 0)


# ---------------------------------------------------------------------------
# Prototype parsing
# ---------------------------------------------------------------------------

# Matches prototypes like:
#   int __cdecl func(int, char*)
#   void __thiscall CClass::Method(int a, float b)
#   int func(void)
_PROTO_RE = re.compile(
    r"^\s*(?P<ret>\w[\w\s\*]*?)\s+"
    r"(?:(?P<cc>__cdecl|__stdcall|__thiscall|__fastcall)\s+)?"
    r"(?:[\w:]+)\s*"  # function name (may include class::)
    r"\((?P<args>[^)]*)\)"
)


def _parse_prototype(proto: str) -> tuple[str, int, int]:
    """Parse a C prototype string into (calling_convention, arg_count, return_width_bits).

    Returns ("cdecl", 0, 32) as default if parsing fails.

    ``return_width_bits`` is 64 when the return type is a 64-bit integer
    (``long long``, ``__int64``, ``int64_t``, ``uint64_t``, or
    ``long double`` — conservative), 32 otherwise.
    """
    m = _PROTO_RE.match(proto.strip())
    if not m:
        return "cdecl", 0, 32

    cc = (m.group("cc") or "__cdecl").lstrip("_").lower()
    args_str = m.group("args").strip()
    ret_type = (m.group("ret") or "").strip()

    # Detect 64-bit return types
    _64BIT_RETURN_TOKENS = ("long long", "__int64", "int64_t", "uint64_t", "long double")
    return_width = 64 if any(tok in ret_type for tok in _64BIT_RETURN_TOKENS) else 32

    if not args_str or args_str.lower() == "void":
        return cc, 0, return_width

    # Count args by splitting on commas (handles pointer types with *)
    args = [a.strip() for a in args_str.split(",") if a.strip()]
    return cc, len(args), return_width


# ---------------------------------------------------------------------------
# Core equivalence prover
# ---------------------------------------------------------------------------


def _mem_value(state: Any, va: int) -> Any:
    """Load a 32-bit value at *va* from *state*, or ``None`` if unmapped.

    ``None`` means "this state does not map that address", which the
    comparison treats as a difference when only one side maps it.
    """
    try:
        return state.memory.load(va, 4)
    except Exception:  # noqa: BLE001 — SimMemoryMissingError and concretization failures
        return None


def _compare_state_pairs(
    states_orig: list[Any],
    states_comp: list[Any],
    check_edx: bool,
    watched_vas: list[int],
) -> tuple[bool, str]:
    """Check return registers (EAX, optionally EDX) and watched memory equal.

    For each (orig, comp) terminal-state pair, a solver is built from the
    union of both states' constraints plus the disjunction "something
    differs" (registers and/or any watched-VA memory).  A satisfiable solver
    means that pair *can* differ → not equivalent.  Watched VAs compare 4
    bytes of memory at the same address on both sides; an address unmapped in
    both states is skipped (nothing to compare), unmapped in exactly one is a
    real difference.
    """
    import claripy

    regs_label = "EAX+EDX" if check_edx else "EAX"
    mem_label = f"+mem({len(watched_vas)} VA)" if watched_vas else ""

    for s_orig in states_orig:
        eax_orig = s_orig.regs.eax
        edx_orig = s_orig.regs.edx
        mem_orig = [_mem_value(s_orig, va) for va in watched_vas]
        can_differ = False
        diff_desc = ""
        for s_comp in states_comp:
            eax_comp = s_comp.regs.eax
            edx_comp = s_comp.regs.edx
            mem_comp = [_mem_value(s_comp, va) for va in watched_vas]

            diff_terms: list[Any] = []
            if check_edx:
                diff_terms.append(claripy.Or(eax_orig != eax_comp, edx_orig != edx_comp))
            else:
                diff_terms.append(eax_orig != eax_comp)
            for m_orig, m_comp in zip(mem_orig, mem_comp, strict=True):
                if m_orig is None and m_comp is None:
                    continue  # unmapped on both sides — nothing to compare
                if m_orig is None or m_comp is None:
                    diff_terms.append(claripy.BoolV(True))  # mapped on one side only
                    break
                diff_terms.append(m_orig != m_comp)

            solver = claripy.Solver()  # type: ignore[no-untyped-call]
            for expr in s_orig.solver.constraints:
                solver.add(expr)  # type: ignore[no-untyped-call]
            for expr in s_comp.solver.constraints:
                solver.add(expr)  # type: ignore[no-untyped-call]
            solver.add(claripy.Or(*diff_terms))  # type: ignore[no-untyped-call]

            if solver.satisfiable():  # type: ignore[no-untyped-call]
                can_differ = True
                try:
                    # One batch_eval call, one model: all counterexample values
                    # come from a single satisfying assignment, so the message
                    # is internally consistent (no independent solves).
                    mem_pairs = list(zip(watched_vas, mem_orig, mem_comp, strict=True))
                    exprs: list[Any] = [eax_orig, eax_comp]
                    if check_edx:
                        exprs += [edx_orig, edx_comp]
                    for _va, m_o, m_c in mem_pairs:
                        if m_o is not None:
                            exprs.append(m_o)
                        if m_c is not None:
                            exprs.append(m_c)
                    vals = solver.batch_eval(exprs, 1)[0]  # type: ignore[no-untyped-call]
                    it = iter(vals)
                    eax_o, eax_c = next(it), next(it)
                    if check_edx:
                        edx_o, edx_c = next(it), next(it)
                        regs_same = eax_o == eax_c and edx_o == edx_c
                        reg_part = f"EAX={eax_o} vs {eax_c}, EDX={edx_o} vs {edx_c}"
                    else:
                        regs_same = eax_o == eax_c
                        reg_part = f"EAX={eax_o} vs {eax_c}"
                    if regs_same and watched_vas:
                        # Registers agree — the difference is in memory; show the
                        # first watched VA that differs under the model.
                        mem_part = ""
                        for va, m_o, m_c in mem_pairs:
                            if m_o is None and m_c is None:
                                continue  # unmapped on both sides — not a difference
                            if m_o is None or m_c is None:
                                mem_part = f", mem[0x{va:x}] mapped on one side only"
                                break
                            v_o, v_c = next(it), next(it)
                            if v_o != v_c:
                                mem_part = f", mem[0x{va:x}]={v_o} vs {v_c}"
                                break
                        diff_desc = f"; {reg_part}{mem_part}"
                    else:
                        diff_desc = f"; {reg_part}"
                except Exception:  # noqa: BLE001 — model extraction is best-effort
                    diff_desc = ""
                break

        if can_differ:
            return False, (
                f"Z3 found a satisfying assignment where {regs_label}{mem_label} differs "
                f"(checked {len(states_orig)} x {len(states_comp)} state pairs){diff_desc}"
            )

    return True, (
        f"Proven equivalent ({regs_label}{mem_label}; {len(states_orig)} original state(s), "
        f"{len(states_comp)} compiled state(s))"
    )


def _run_simulation(
    proj: angr.Project,
    state: angr.SimState[Any, Any],
    *,
    loop_bound: int,
    timeout: int,
) -> list[Any]:
    """Run symbolic execution and return satisfiable terminal states.

    Module-level so tests can patch it with crafted states and exercise the
    real comparison logic (:func:`_compare_state_pairs`).
    """
    import angr  # noqa: F401  # lazy import (angr is an optional extra)

    sm = proj.factory.simgr(state, save_unconstrained=True)  # type: ignore[no-untyped-call]
    sm.use_technique(angr.exploration_techniques.LoopSeer(bound=loop_bound))  # type: ignore[no-untyped-call]

    # Step-based timeout — angr's broad except handlers swallow SIGALRM,
    # so we step manually and check wall-clock time each iteration.

    deadline = time.monotonic() + timeout
    timed_out = False

    while sm.active:
        if time.monotonic() > deadline:
            timed_out = True
            break
        sm.step()

    if timed_out:
        warnings.warn(
            "Symbolic execution timed out — using partial states",
            stacklevel=2,
        )
    # Prefer fully-terminated states (PathTerminator at RETURN_SENTINEL);
    # fall back to unconstrained (if sentinel hook missed) or active.
    terminal = list(sm.deadended)
    if not terminal:
        terminal = list(sm.unconstrained) or list(sm.active)
    return terminal


def prove_equivalence(
    original_bytes: bytes,
    compiled_bytes: bytes,
    reloc_offsets: dict[int, str] | None,
    prototype: str,
    *,
    timeout: int = 60,
    loop_bound: int = 10,
    binary_path: Path | None = None,
    arg_constraints: dict[str, Any] | None = None,
    start_offset: int = 0,
    end_offset: int = 0,
    check_edx: bool = False,
    watched_vas: list[int] | None = None,
    dir32_watched: dict[int, int] | None = None,
) -> tuple[bool, str]:
    """Prove semantic equivalence of two function byte blobs via symbolic execution.

    Args:
        original_bytes: Raw bytes from the target binary.
        compiled_bytes: Raw bytes from the compiled .obj.
        reloc_offsets: Relocation offsets in the compiled blob (offset → symbol name).
        prototype: C prototype string for argument setup.
        timeout: Seconds before giving up.
        loop_bound: Max loop iterations for angr's LoopSeer.
        binary_path: Path to the target PE binary (for IAT-based API hooking).
        arg_constraints: Per-argument constraints from metadata (see _apply_arg_constraints).
        start_offset: Start byte offset within the function (for block-level proving).
        end_offset: End byte offset within the function (for block-level proving).
        check_edx: Also compare EDX register in addition to EAX.  Auto-enabled
            when the prototype's return type is 64-bit (``long long``, ``__int64``,
            ``int64_t``, ``uint64_t``, ``long double``).
        watched_vas: Optional list of virtual addresses whose first 4 bytes must
            also compare equal across state pairs (memory side effects).  VAs
            unmapped in both states are skipped; unmapped in one is a difference.
        dir32_watched: DIR32 relocation offsets in the compiled blob that must be
            patched to absolute target VAs (offsets whose symbol resolved into
            ``watched_vas``).  Patching both blobs makes the compiled side read
            and write the same watched globals as the original.

    Returns:
        (proven, message) — proven is True if semantic equivalence was proved.

    """
    import angr
    import claripy

    # Build IAT address → stub address map from LIEF import data (if binary_path given).
    # This seeds concrete call targets for the original binary's IAT-indirect calls,
    # preventing angr from creating 256+ symbolic successors.
    STUB_BASE = 0xDEAD0000
    RETURN_SENTINEL = 0xBAADF00D  # Concrete return address pushed on stack
    iat_stub_map_orig: dict[int, int] = {}  # IAT_addr -> stub_addr
    iat_api_names: dict[int, str] = {}  # stub_addr -> API name (for smart hooks)
    if binary_path is not None:
        try:
            import lief

            pe = lief.PE.parse(str(binary_path))
            if pe is not None:
                for entry in pe.imports:
                    for fn in entry.entries:
                        iat_va = fn.iat_address + pe.optional_header.imagebase
                        stub_addr = (STUB_BASE + len(iat_stub_map_orig) * 4) & 0xFFFFFFFF
                        iat_stub_map_orig[iat_va] = stub_addr
                        if fn.name:
                            iat_api_names[stub_addr] = str(fn.name)
        except Exception:  # noqa: BLE001
            log.debug("LIEF import scan failed (best-effort)", exc_info=True)

    cc, arg_count, return_width = _parse_prototype(prototype)

    # Auto-enable EDX check when the return type is 64-bit (EDX:EAX pair)
    check_edx = check_edx or (return_width == 64)

    # Create symbolic arguments
    sym_args = [claripy.BVS(f"arg_{i}", 32) for i in range(arg_count)]

    def _setup_state(proj: angr.Project) -> angr.SimState[Any, Any]:
        """Create an initial state with symbolic arguments placed per calling convention.

        Initialises ESP to a fake stack, pushes a concrete return address so
        ``ret`` pops a known value instead of unconstrained memory.  Enables
        zero-fill for uninitialized memory and registers to prevent symbolic
        pollution from globals, statics, and scratch registers.
        """
        state: angr.SimState[Any, Any] = proj.factory.blank_state(  # type: ignore[no-untyped-call]
            addr=0,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        # Set up a fake stack frame with a concrete return address.
        # Layout: [ret_addr] [arg0] [arg1] ...  at ESP.
        STACK_TOP = 0x7FFF0000
        state.regs.esp = STACK_TOP
        state.regs.ebp = STACK_TOP

        # Push return address — 'ret' will pop this, ending execution cleanly
        state.memory.store(STACK_TOP, claripy.BVV(RETURN_SENTINEL, 32), endness="Iend_LE")  # type: ignore[no-untyped-call]

        # Arguments sit above the return address on the stack
        ARG_OFFSET = 4  # first arg at ESP+4 (after ret addr)

        if cc == "thiscall" and sym_args:
            # ECX = this pointer (first arg)
            state.regs.ecx = sym_args[0]
            # Remaining args on stack (right-to-left)
            for i, arg in enumerate(sym_args[1:]):
                state.memory.store(STACK_TOP + ARG_OFFSET + (i * 4), arg, endness="Iend_LE")  # type: ignore[no-untyped-call]
        elif cc == "fastcall":
            # ECX = arg0, EDX = arg1, rest on stack
            if len(sym_args) >= 1:
                state.regs.ecx = sym_args[0]
            if len(sym_args) >= 2:
                state.regs.edx = sym_args[1]
            for i, arg in enumerate(sym_args[2:]):
                state.memory.store(STACK_TOP + ARG_OFFSET + (i * 4), arg, endness="Iend_LE")  # type: ignore[no-untyped-call]
        else:
            # cdecl / stdcall — all args on stack
            for i, arg in enumerate(sym_args):
                state.memory.store(STACK_TOP + ARG_OFFSET + (i * 4), arg, endness="Iend_LE")  # type: ignore[no-untyped-call]

        return state

    def _make_project(blob: bytes) -> angr.Project:
        import io

        return angr.Project(
            io.BytesIO(blob),
            main_opts={"backend": "blob", "arch": "x86", "base_addr": 0, "entry_point": 0},
            auto_load_libs=False,
        )

    # Stub region: stubs for LIEF-derived IAT entries come first,
    # followed by stubs for COFF reloc call targets in the compiled blob.
    stub_offset_base = len(iat_stub_map_orig)  # reloc stubs start here
    stub_hooks: list[int] = list(iat_stub_map_orig.values())

    # For COFF IMAGE_REL_I386_REL32 relocations, the 4 bytes at each reloc
    # offset are a near-call REL32 displacement.  When angr executes the raw
    # (unrelocated) blob, those displacements resolve to arbitrary addresses
    # that may fall inside the blob or outside — causing path explosion.
    #
    # Fix: patch each displacement in BOTH blobs so calls resolve to the same
    # unique stub address in a harmless region (STUB_BASE + i*4), then hook
    # those stubs as ReturnUnconstrained on both projects.  This neutralises
    # relocation-only differences so structural near-matches can be proven.
    patched_comp = bytearray(compiled_bytes)
    patched_orig = bytearray(original_bytes)

    if reloc_offsets:
        for i, (offset, _sym_name) in enumerate(sorted(reloc_offsets.items())):
            if 0 <= offset <= len(compiled_bytes) - 4:
                stub_addr = (STUB_BASE + (stub_offset_base + i) * 4) & 0xFFFFFFFF
                # REL32: target = (offset + 4) + displacement
                # => displacement = stub_addr - (offset + 4)  (mod 2^32)
                disp = (stub_addr - (offset + 4)) & 0xFFFFFFFF
                patched_comp[offset : offset + 4] = struct.pack("<I", disp)
                # Also patch the original blob at the same offset so both
                # sides call the same stub — neutralises reloc-site differences.
                if offset <= len(original_bytes) - 4:
                    patched_orig[offset : offset + 4] = struct.pack("<I", disp)
                stub_hooks.append(stub_addr)

    # DIR32 data references whose symbol resolved into watched_vas must point
    # at the real target VA (memory side effects).  Apply after the stub pass
    # above so watched sites override the neutralisation.  The original blob's
    # native operand already holds the same VA, so the patch is a no-op there.
    if dir32_watched:
        for offset, va in sorted(dir32_watched.items()):
            if 0 <= offset <= len(compiled_bytes) - 4:
                patched_comp[offset : offset + 4] = struct.pack("<I", va)
                if offset <= len(original_bytes) - 4:
                    patched_orig[offset : offset + 4] = struct.pack("<I", va)

    # Slice to target range if specified
    if end_offset > 0:
        if start_offset >= len(patched_orig) or end_offset > len(patched_orig):
            return (
                False,
                f"Slice [{start_offset}:{end_offset}] out of range for original ({len(patched_orig)}B)",
            )
        if start_offset >= len(patched_comp) or end_offset > len(patched_comp):
            return (
                False,
                f"Slice [{start_offset}:{end_offset}] out of range for compiled ({len(patched_comp)}B)",
            )
        patched_orig = bytearray(patched_orig[start_offset:end_offset])
        patched_comp = bytearray(patched_comp[start_offset:end_offset])
        # Filter and adjust reloc_offsets to only include relocations within the slice
        if reloc_offsets:
            adjusted_relocs: dict[int, str] = {}
            for off, sym in reloc_offsets.items():
                if start_offset <= off < end_offset:
                    adjusted_relocs[off - start_offset] = sym
            reloc_offsets = adjusted_relocs if adjusted_relocs else None
        # Stub hooks all point at the external STUB_BASE region (never inside
        # the blob), so none are sliced away — keep them all.

    try:
        proj_orig = _make_project(bytes(patched_orig))
        proj_comp = _make_project(bytes(patched_comp))
    except Exception as e:
        return False, f"Failed to create angr projects: {e}"

    # Shared registry of return-value symbols per stub address. Both
    # projects' SimProcedures look up the same BV when hitting the
    # same stub, so external call returns are constrained-equal
    # across the equivalence check. Without this, ReturnUnconstrained
    # creates fresh symbols per project, and Z3 finds counterexamples
    # where two wrappers return "different" nondet values for the same
    # external call — making RELOC wrapper functions unprovable.
    shared_stub_returns: dict[int, Any] = {}

    class SharedReturnStub(angr.SimProcedure):
        """SimProcedure that returns a shared 32-bit BV per stub address.

        Looks up the stub_addr in *shared_stub_returns*. If unseen,
        creates a new claripy BVS and stores it. Returns the stored BV.
        Both projects' invocations at the same stub_addr therefore
        return the same symbol — Z3 then deduces external-call return
        equivalence.
        """

        ARGS_MISMATCH = True

        def run(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ARG002
            stub_addr = self.addr
            assert stub_addr is not None  # angr sets addr before invoking run()
            bv = shared_stub_returns.get(stub_addr)
            if bv is None:
                bv = claripy.BVS(f"shared_ret_0x{stub_addr:x}", 32)
                shared_stub_returns[stub_addr] = bv
            return bv

    # Hook all stub addresses on both blobs.  Prefer specific Win32
    # SimProcedures (constrained return values) over generic ReturnUnconstrained
    # to reduce path explosion from API calls.
    _ret_unc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
    win32_procs = _get_win32_simprocs()
    for stub_addr in stub_hooks:
        api_name = iat_api_names.get(stub_addr, "")
        if api_name and api_name in win32_procs:
            simproc_cls = win32_procs[api_name]
            ret_proc_orig = simproc_cls()
            ret_proc_comp = simproc_cls()
        else:
            # Use shared-return stub so both projects see equal returns
            ret_proc_orig = SharedReturnStub()
            ret_proc_comp = SharedReturnStub()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                proj_comp.hook(stub_addr, ret_proc_comp, length=1)
                proj_orig.hook(stub_addr, ret_proc_orig, length=1)
            except Exception:  # noqa: BLE001
                log.debug("Failed to hook stub at 0x%x (%s)", stub_addr, api_name, exc_info=True)

    # Hook the return sentinel address so states that reach it land in
    # deadended (clean termination) instead of unconstrained.
    _path_terminator = angr.SIM_PROCEDURES["stubs"]["PathTerminator"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            proj_comp.hook(RETURN_SENTINEL, _path_terminator(), length=0)
            proj_orig.hook(RETURN_SENTINEL, _path_terminator(), length=0)
        except Exception:  # noqa: BLE001
            log.debug("Failed to hook return sentinel", exc_info=True)

    # Seed IAT slot memory in the original blob's initial state so
    # indirect calls (via register or memory) resolve to our stubs.
    state_orig = _setup_state(proj_orig)
    for iat_addr, stub_addr in iat_stub_map_orig.items():
        state_orig.memory.store(iat_addr, claripy.BVV(stub_addr, 32), endness="Iend_LE")  # type: ignore[no-untyped-call]

    state_comp = _setup_state(proj_comp)

    # Apply user-specified argument constraints to reduce path explosion
    if arg_constraints:
        _apply_arg_constraints(state_orig, sym_args, arg_constraints)
        _apply_arg_constraints(state_comp, sym_args, arg_constraints)

    try:
        states_orig = _run_simulation(proj_orig, state_orig, loop_bound=loop_bound, timeout=timeout)
        states_comp = _run_simulation(proj_comp, state_comp, loop_bound=loop_bound, timeout=timeout)
    except Exception as e:
        return False, f"Symbolic execution failed: {e}"

    if not states_orig:
        return False, (
            "No terminal states reached for original binary (timeout or path explosion) — "
            "try --timeout higher or --loop-bound higher; batch mode cannot slice, "
            "so for slice proving run rebrew prove <va> --start-offset/--end-offset"
        )
    if not states_comp:
        return False, (
            "No terminal states reached for compiled code (timeout or path explosion) — "
            "try --timeout higher or --loop-bound higher; batch mode cannot slice, "
            "so for slice proving run rebrew prove <va> --start-offset/--end-offset"
        )

    # Compare return register(s) and (optionally) watched-VA memory across all
    # terminal state pairs — see _compare_state_pairs for the equivalence rule.
    watched = list(watched_vas or [])
    return _compare_state_pairs(states_orig, states_comp, check_edx, watched)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew prove src/mygame/calculate_physics.c · Prove equivalence\n\n"
    "  rebrew prove 0x01006364 · · · · · · · · · · · Find by VA\n\n"
    "  rebrew prove my_func · · · · · · · · · · · · · Find by symbol name\n\n"
    "  rebrew prove src/mygame/func.c --dry-run · · · Don't update annotations\n\n"
    "  rebrew prove src/mygame/func.c --watch · · · · Re-prove on every save\n\n"
    "  rebrew prove --all · · · · · · · · · · · · · · Prove all eligible functions\n\n"
    "  rebrew prove my_func --start-offset 0 --end-offset 48  Prove a specific block\n\n"
    "[bold]How it works:[/bold]\n\n"
    "  1. Validates the function status is NEAR_MATCHING/SIZE_MISMATCH — the gate\n"
    "     checks the effective status (metadata or the verify cache)\n\n"
    "  2. Extracts target bytes from the DLL and compiles the C source\n\n"
    "  3. Verifies bytes still differ post-compile (matched bytes belong as RELOC, not PROVEN)\n\n"
    "  4. Loads both byte blobs into angr's symbolic execution engine\n\n"
    "  5. Proves EAX equivalence via Z3 constraint solving\n\n"
    "  6. If proven: updates STATUS from NEAR_MATCHING/SIZE_MISMATCH \u2192 PROVEN\n\n"
    "[dim]angr is a heavy optional dependency (~500 MB). "
    'Install with: uv pip install -e ".[prove]"[/dim]'
)

app = typer.Typer(
    help="Prove semantic equivalence of NEAR_MATCHING/SIZE_MISMATCH functions via symbolic execution.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)

console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(None, help="C source file, symbol name, or VA (hex)"),
    all_sources: bool = typer.Option(
        False, "--all", help="Prove all NEAR_MATCHING/SIZE_MISMATCH functions"
    ),
    max_delta: int | None = typer.Option(
        None,
        "--max-delta",
        help="With --all: only prove NEAR_MATCHING/SIZE_MISMATCH functions whose recorded "
        "byte delta (blocker_delta) is at most this — focus Z3 time on the closest matches",
    ),
    timeout: int = typer.Option(60, "--timeout", help="Seconds before giving up"),
    loop_bound: int = typer.Option(10, "--loop-bound", help="Max loop iterations for angr"),
    start_offset: int = typer.Option(
        0, "--start-offset", help="Start byte offset within the function (0-based)"
    ),
    end_offset: int = typer.Option(
        0, "--end-offset", help="End byte offset within the function (0 = full function)"
    ),
    check_edx: bool = typer.Option(
        False,
        "--check-edx",
        help="Also compare EDX register (forced on when return type is 64-bit)",
    ),
    watch_va: list[str] | None = typer.Option(
        None,
        "--watch-va",
        help="Also compare 4 bytes of memory at this VA (repeatable). Values are decimal unless 0x-prefixed — unlike most other rebrew tools, bare digits are NOT hex (adds to prove_constraints.watched_vas)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    watch: bool = typer.Option(
        False, "--watch", help="Watch the source file and re-prove on every change"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Prove semantic equivalence of a NEAR_MATCHING/SIZE_MISMATCH function via symbolic execution."""
    # angr logs an ERROR about its optional unicorn engine at import; prove
    # is the only tool that legitimately imports angr, and its own status
    # messages are the meaningful output — silence angr's logger so every
    # run (even one rejected by the status guard) does not leak that line.
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    # Guard angr import early
    try:
        _require_angr()
    except ImportError as e:
        error_exit(str(e), json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)

    # --watch-va accepts hex (0x...) or plain decimal VAs; normalize once
    # up front.  int(v, 0) keeps both semantics (parse_va is base-16 only).
    watch_va_ints: list[int] | None = None
    if watch_va:
        watch_va_ints = []
        for _v in watch_va:
            try:
                _va = int(_v.strip(), 0)
            except ValueError:
                error_exit(f"Invalid watch VA: {_v!r}", json_mode=json_output)
            if not (0 <= _va <= 0xFFFFFFFF):
                error_exit(
                    f"Invalid watch VA: {_v!r} (expected 0..0xFFFFFFFF)",
                    json_mode=json_output,
                    code=EXIT_ERROR,
                )
            watch_va_ints.append(_va)

    if all_sources:
        if watch:
            error_exit("--watch cannot be combined with --all", json_mode=json_output)
        _run_all_batch(
            cfg,
            timeout,
            loop_bound,
            dry_run,
            json_output,
            check_edx=check_edx,
            watch_va=watch_va_ints,
            max_delta=max_delta,
        )
        return

    if source is None:
        error_exit("Either provide a source file or use --all", json_mode=json_output)
    was_va_arg = source.strip().lower().startswith("0x")
    source_path = resolve_source_arg(cfg, source)

    if not source_path.exists():
        error_exit(f"Source file not found: {source_path}", json_mode=json_output)

    if watch:
        from rebrew.utils import watch_files

        def _retest() -> None:
            # Re-run the full single-function prove path; --watch must not nest.
            main(
                source=source,
                all_sources=all_sources,
                timeout=timeout,
                loop_bound=loop_bound,
                start_offset=start_offset,
                end_offset=end_offset,
                check_edx=check_edx,
                watch_va=watch_va,
                dry_run=dry_run,
                watch=False,
                json_output=json_output,
                target=target,
            )

        watch_files([source_path], _retest)
        return

    # Parse annotation — use multi-parser with metadata_dir so STATUS/CFLAGS/SIZE
    # are read from rebrew-function.toml (where volatile metadata lives).
    annotations = parse_c_file_multi(
        source_path,
        target_name=target_marker(cfg),
        metadata_dir=cfg.metadata_dir,
    )
    ann = None
    if was_va_arg:
        # `rebrew prove 0x<va>` on a multi-function file must target THAT
        # function — the first-NEAR_MATCHING fallback would prove a different
        # function's bytes (workflow bug fixed for diff/match).  A VA the
        # resolved file does not annotate errors instead of silently proving
        # the wrong function (same rule as diff/match/near-diag).
        try:
            want_va = parse_va(source, json_mode=json_output)
        except typer.Exit:
            want_va = None
        if want_va is not None:
            ann = next((a for a in annotations if a.va == want_va), None)
            if ann is None:
                error_exit(
                    f"No annotation for VA {source} in {source_path.name} — the "
                    "resolved file covers different functions",
                    json_mode=json_output,
                )
    if ann is None:
        for a in annotations:
            if a.status == "NEAR_MATCHING":
                ann = a
                break
    if ann is None and annotations:
        ann = annotations[0]  # fallback to first for error reporting
    if ann is None:
        error_exit(f"No metadata found in {source_path}", json_mode=json_output)

    # Effective-status overlay: the metadata STATUS can lag the verify cache
    # (e.g. a flag-sweep that found the gap but did not promote).  A cached
    # NEAR_MATCHING/SIZE_MISMATCH is the measured truth — prove must not
    # refuse a function the verifier already classified as nearly matching.
    effective_status = ann.status
    if effective_status not in ("NEAR_MATCHING", "SIZE_MISMATCH"):
        cached = _cached_verify_status(cfg, ann.va)
        if cached in ("NEAR_MATCHING", "SIZE_MISMATCH"):
            effective_status = cached

    if effective_status not in ("NEAR_MATCHING", "SIZE_MISMATCH"):
        error_exit(
            f"Status is '{ann.status}', expected NEAR_MATCHING or SIZE_MISMATCH. "
            "PROVEN is reserved for functions whose bytes differ structurally "
            "but are semantically equivalent. RELOC/EXACT functions already match "
            "byte-for-byte — symbolic prove adds no information.",
            json_mode=json_output,
        )

    try:
        inputs = _prepare_prove_inputs(
            cfg,
            source_path,
            ann,
            watch_va_ints,
            start_offset=start_offset,
            end_offset=end_offset,
            check_edx=check_edx,
        )
    except _AlreadyMatched as m:
        from rebrew.metadata import update_source_status

        new_status = m.new_status
        if not dry_run:
            update_source_status(cfg.metadata_dir, new_status, ann.module, ann.va)
        early: dict[str, Any] = {
            "schema_version": 1,
            "source": str(source_path),
            "symbol": resolve_symbol(ann, source_path),
            "va": f"0x{ann.va:08x}",
            "size": ann.size,
            "previous_status": ann.status,
            "proven": False,
            "already_matched": True,
            "message": (
                f"Bytes already match after reloc accounting — "
                f"{'would set' if dry_run else 'set'} STATUS → {new_status}"
            ),
            "action": "would_update" if dry_run else "updated",
            "new_status": new_status,
        }
        if json_output:
            json_print(early)
        else:
            console.print(
                f"[green]Bytes already match[/green] — "
                f"{'would set' if dry_run else 'STATUS →'} "
                f"[bold]{new_status}[/bold] (not PROVEN). "
                f"Symbolic prove not needed."
            )
        raise typer.Exit(code=EXIT_OK)
    except _ProveError as e:
        error_exit(str(e), json_mode=json_output)

    symbol = inputs.symbol
    va = inputs.va
    size = inputs.size
    target_bytes = inputs.target_bytes
    obj_bytes = inputs.obj_bytes
    effective_check_edx = inputs.effective_check_edx
    edx_auto_detected = inputs.edx_auto_detected
    arg_constraints = inputs.arg_constraints
    prototype = inputs.prototype

    # Run the prover
    if not json_output:
        console.print(
            f"[bold]Proving equivalence:[/bold] {source_path.name} "
            f"(0x{va:08x}, {len(target_bytes)}B vs {len(obj_bytes)}B)"
        )
        console.print(f"  Prototype: {prototype or '(none — assuming void f(void))'}")
        console.print(f"  Timeout: {timeout}s, loop bound: {loop_bound}")
        if effective_check_edx:
            note = " [dim](auto-detected 64-bit return)[/dim]" if edx_auto_detected else ""
            console.print(f"  Registers: EAX+EDX{note}")
        if start_offset or end_offset:
            console.print(f"  Slice: [{start_offset}:{end_offset}] ({end_offset - start_offset}B)")
        if arg_constraints:
            console.print(f"  Constraints: {', '.join(arg_constraints.keys())}")

    proven, message = prove_equivalence(
        target_bytes,
        obj_bytes,
        inputs.reloc_offsets,
        prototype,
        timeout=timeout,
        loop_bound=loop_bound,
        binary_path=cfg.target_binary,
        arg_constraints=arg_constraints,
        start_offset=start_offset,
        end_offset=end_offset,
        check_edx=check_edx,
        watched_vas=inputs.watched_vas,
        dir32_watched=inputs.dir32_watched,
    )

    # Build result
    result: dict[str, Any] = {
        "schema_version": 1,
        "source": str(source_path),
        "symbol": symbol,
        "va": f"0x{va:08x}",
        "size": size,
        "previous_status": ann.status,
        "proven": proven,
        "message": message,
        "target_bytes_len": len(target_bytes),
        "compiled_bytes_len": len(obj_bytes),
        "check_edx": effective_check_edx,
    }
    if edx_auto_detected:
        result["auto_detected"] = True
    if start_offset or end_offset:
        result["slice"] = {"start": start_offset, "end": end_offset}

    if proven and not dry_run:
        from rebrew.metadata import update_source_status

        update_source_status(cfg.metadata_dir, "PROVEN", ann.module, va)
        result["action"] = "updated"
        result["new_status"] = "PROVEN"
    elif proven and dry_run:
        result["action"] = "would_update"
        result["new_status"] = "PROVEN"
    else:
        result["action"] = "none"
        result["new_status"] = ann.status
        if not dry_run:
            _record_prove_counterexample(cfg, ann, message)

    if json_output:
        json_print(result)
    else:
        if proven:
            console.print(f"[green bold]PROVEN:[/green bold] {message}")
            if dry_run:
                console.print("[dim]--dry-run: STATUS not updated[/dim]")
            else:
                console.print(f"[green]STATUS updated: {ann.status} → PROVEN[/green]")
        else:
            console.print(f"[yellow bold]NOT PROVEN:[/yellow bold] {message}")
            console.print(f"[dim]STATUS unchanged — function remains {ann.status}[/dim]")

    if not proven:
        if message.startswith("Slice [") and "out of range" in message:
            # Argument error, not a legitimate mismatch — report as EXIT_ERROR.
            error_exit(message, json_mode=json_output, code=EXIT_ERROR)
        raise typer.Exit(code=EXIT_MISMATCH)


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


def _resolve_watched_dir32(
    obj_path: str | Path, symbol: str, cfg: ProjectConfig, watched_set: set[int]
) -> dict[int, int]:
    """Map DIR32 reloc offsets whose symbol resolves into *watched_set* → that VA.

    Only DIR32 (IMAGE_REL_I386_DIR32, 0x06) absolute data references can point
    at watched globals.  Symbol lookup tolerates the MSVC leading underscore.
    Best-effort: any failure yields ``{}`` (no watching, current behaviour).
    """
    if not watched_set:
        return {}
    try:
        name_to_va = build_name_to_va(cfg)
    except Exception:  # noqa: BLE001 — best-effort; no resolution → no watching
        return {}
    out: dict[int, int] = {}
    try:
        records = parse_obj_relocs_full(obj_path, symbol)
    except Exception:  # noqa: BLE001 — best-effort
        return {}
    for rec in records:
        if rec.type != 0x06:  # IMAGE_REL_I386_DIR32
            continue
        va = name_to_va.get(rec.symbol)
        if va is None and rec.symbol.startswith("_"):
            va = name_to_va.get(rec.symbol[1:])
        if va in watched_set:
            out[rec.offset] = va
    return out


class _ProveError(Exception):
    """Preparation failed (compile, extraction, missing symbol) — not a proof result."""


class _AlreadyMatched(Exception):
    """Bytes match after relocation accounting — RELOC/EXACT, prove not needed."""

    def __init__(self, new_status: str) -> None:
        super().__init__(new_status)
        self.new_status = new_status


@dataclass
class _ProveInputs:
    """Prepared inputs shared by the single-file CLI path and batch mode."""

    symbol: str
    va: int
    size: int
    target_bytes: bytes
    obj_bytes: bytes
    reloc_offsets: dict[int, str] | None
    dir32_watched: dict[int, int] | None
    prototype: str
    arg_constraints: dict[str, Any] | None
    effective_check_edx: bool
    edx_auto_detected: bool
    watched_vas: list[int]


def _prepare_prove_inputs(
    cfg: ProjectConfig,
    source_path: Path,
    ann: Any,
    watch_va: list[int] | None,
    *,
    start_offset: int = 0,
    end_offset: int = 0,
    check_edx: bool = False,
    name_to_va: dict[str, int] | None = None,
) -> _ProveInputs:
    """Extract target bytes, compile the source, and detect early matches.

    Raises ``_ProveError`` on prep failure or ``_AlreadyMatched`` when the
    compiled bytes already match after relocation accounting (callers then
    promote to RELOC/EXACT instead of proving).
    """
    symbol = resolve_symbol(ann, source_path)
    va = ann.va
    size = ann.size

    if not size:
        raise _ProveError(f"SIZE metadata is missing or zero in {source_path}")

    target_bytes = extract_raw_bytes(cfg.target_binary, va, size)
    if not target_bytes:
        raise _ProveError(f"Failed to extract target bytes at VA 0x{va:08x} (size {size})")

    from rebrew.cli import resolve_compile_overrides

    toolchain, cflags_str = resolve_compile_overrides(
        cfg,
        Path(source_path).resolve().parent,
        getattr(ann, "toolchain", ""),
        getattr(ann, "cflags", ""),
        getattr(ann, "module", ""),
    )
    cflags_list = safe_shlex_split(cflags_str)

    # Watched VAs for memory side-effect checking: CLI flags + metadata.
    watched_vas: list[int] = list(watch_va or [])
    meta_vas = ann.prove_constraints.get("watched_vas") if ann.prove_constraints else None
    if isinstance(meta_vas, list):
        for _v in meta_vas:
            try:
                _va = int(_v, 0) if not isinstance(_v, int) else _v
            except (ValueError, TypeError):
                raise _ProveError(
                    f"Invalid prove_constraints.watched_vas metadata value {_v!r} in "
                    f"{source_path} — fix or remove it (expected int or hex/decimal string)"
                )
            if not (0 <= _va <= 0xFFFFFFFF):
                raise _ProveError(
                    f"prove_constraints.watched_vas value {_va!r} in {source_path} is "
                    f"outside 0..0xFFFFFFFF"
                )
            watched_vas.append(_va)

    from rebrew.utils import writable_temp_dir

    workdir = writable_temp_dir("rebrew_prove_")
    try:
        obj_path, err = compile_to_obj(
            cfg,
            source_path,
            cflags_list,
            workdir,
            toolchain=toolchain,
        )
        if obj_path is None:
            raise _ProveError(f"Compile error: {err}")

        obj_bytes, reloc_offsets = parse_obj_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            raise _ProveError(f"Symbol '{symbol}' not found in compiled .obj")
        dir32_watched = _resolve_watched_dir32(obj_path, symbol, cfg, set(watched_vas))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # Bytes already match → RELOC, not PROVEN. Slice proofs skip this gate.
    # Pass the same name_to_va DIR32 validation that test/verify use —
    # without it, a function whose compiled absolute addresses differ from
    # the target's globals would be wrongly promoted to RELOC (prove
    # reported ALREADY_MATCHED:RELOC for CreateListenSocket while
    # test/verify correctly classify it NEAR_MATCHING).
    if not (start_offset or end_offset):
        if name_to_va is None:
            name_to_va = build_name_to_va(cfg)
        matched, _mc, _tot, _vr, _ir = smart_reloc_compare(
            obj_bytes,
            target_bytes,
            reloc_offsets,
            name_to_va=name_to_va,
            section_va=va,
            iat_region=build_iat_region(cfg),
        )
        if matched:
            raise _AlreadyMatched("RELOC" if _vr else "EXACT")

    prototype = ann.prototype or ""
    arg_constraints = ann.prove_constraints if ann.prove_constraints else None

    # Determine whether EDX will be checked — also detect from prototype.
    _cc, _nargs, return_width = _parse_prototype(prototype)
    edx_auto_detected = (return_width == 64) and not check_edx
    effective_check_edx = check_edx or (return_width == 64)

    return _ProveInputs(
        symbol=symbol,
        va=va,
        size=size,
        target_bytes=target_bytes,
        obj_bytes=obj_bytes,
        reloc_offsets=reloc_offsets,
        dir32_watched=dir32_watched,
        prototype=prototype,
        arg_constraints=arg_constraints,
        effective_check_edx=effective_check_edx,
        edx_auto_detected=edx_auto_detected,
        watched_vas=watched_vas,
    )


def _prove_single(
    cfg: ProjectConfig,
    source_path: Path,
    ann: Any,
    timeout: int,
    loop_bound: int,
    dry_run: bool,
    *,
    start_offset: int = 0,
    end_offset: int = 0,
    check_edx: bool = False,
    watched_vas: list[int] | None = None,
    name_to_va: dict[str, int] | None = None,
) -> tuple[bool, str]:
    """Prove a single function and return (proven, message)."""
    try:
        inputs = _prepare_prove_inputs(
            cfg,
            source_path,
            ann,
            watched_vas,
            start_offset=start_offset,
            end_offset=end_offset,
            check_edx=check_edx,
            name_to_va=name_to_va,
        )
    except _AlreadyMatched as m:
        # Bytes already match → promote to RELOC/EXACT instead of PROVEN.
        if not dry_run:
            from rebrew.metadata import update_source_status

            update_source_status(cfg.metadata_dir, m.new_status, ann.module, ann.va)
        # Sentinel prefix so batch mode can count this separately from failures.
        return False, f"ALREADY_MATCHED:{m.new_status}"
    except _ProveError as e:
        return False, str(e)

    proven, message = prove_equivalence(
        inputs.target_bytes,
        inputs.obj_bytes,
        inputs.reloc_offsets,
        inputs.prototype,
        timeout=timeout,
        loop_bound=loop_bound,
        binary_path=cfg.target_binary,
        arg_constraints=inputs.arg_constraints,
        start_offset=start_offset,
        end_offset=end_offset,
        check_edx=inputs.effective_check_edx,
        watched_vas=inputs.watched_vas,
        dir32_watched=inputs.dir32_watched,
    )

    if proven and not dry_run:
        from rebrew.metadata import update_source_status

        update_source_status(cfg.metadata_dir, "PROVEN", ann.module, ann.va)
    elif not proven and not dry_run:
        _record_prove_counterexample(cfg, ann, message)

    return proven, message


def _record_prove_counterexample(cfg: Any, ann: Any, message: str) -> None:
    """Persist a failed prove's counterexample as a metadata NOTE.

    A Z3 counterexample ("EAX=0 vs 4") is the single most actionable signal
    for fixing a decompilation, but it was only printed to the terminal and
    lost.  Writing it into the function's metadata NOTE surfaces it in
    ``rebrew status`` / ``todo`` / ``describe`` so the reverser sees the
    concrete register difference when they open the function.  Only written
    when the message actually carries a register comparison and the function
    has no note yet (never clobbers a reverser's own note).
    """
    if not any(tok in message for tok in ("EAX", "EDX", "differs")):
        return  # timeout / path explosion / internal error — not a counterexample
    try:
        from rebrew.metadata import load_metadata, set_field

        existing = load_metadata(cfg.metadata_dir).get((ann.module, ann.va), {})
        if existing.get("note"):
            return
        set_field(cfg.metadata_dir, ann.va, "note", f"prove: {message}", module=ann.module)
    except Exception:  # noqa: BLE001 — best-effort; never fail the prove flow
        return


def _run_all_batch(
    cfg: ProjectConfig,
    timeout: int,
    loop_bound: int,
    dry_run: bool,
    json_output: bool,
    *,
    check_edx: bool = False,
    watch_va: list[int] | None = None,
    max_delta: int | None = None,
) -> None:
    """Batch-prove all NEAR_MATCHING/SIZE_MISMATCH functions.

    *max_delta* bounds the work to functions whose recorded byte delta
    (blocker_delta metadata) is at most the given value — Z3 time goes to
    the closest matches first.
    """
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    tm = target_marker(cfg)

    # Collect all eligible annotations
    candidates: list[tuple[Path, Any]] = []
    for src in sources:
        try:
            annos = parse_c_file_multi(src, target_name=tm, metadata_dir=cfg.metadata_dir)
        except Exception:  # noqa: BLE001
            log.debug("Skipping %s: annotation parse failed", src, exc_info=True)
            continue
        for a in annos:
            if a.status not in ("NEAR_MATCHING", "SIZE_MISMATCH") or not a.size:
                continue
            if max_delta is not None:
                delta = getattr(a, "blocker_delta", None)
                if delta is not None and delta > max_delta:
                    continue  # too far from EXACT — don't burn Z3 time yet
            candidates.append((src, a))

    if not candidates:
        if json_output:
            json_print({"total": 0, "proven": 0, "failed": 0, "results": []})
        else:
            console.print("[dim]No NEAR_MATCHING/SIZE_MISMATCH functions found to prove.[/dim]")
        return

    # Build the DIR32 validation map once for the whole batch — per-candidate
    # rebuilds would re-scan every source for every function (O(F×S)).
    name_to_va = build_name_to_va(cfg)

    if not json_output:
        console.print(
            f"\n[bold]Batch proving {len(candidates)} NEAR_MATCHING/SIZE_MISMATCH function(s)[/bold]"
            + (" [dim](--dry-run)[/dim]" if dry_run else "")
            + "\n"
        )

    proven_count = 0
    failed_count = 0
    already_matched_count = 0
    results_list: list[dict[str, Any]] = []

    for i, (src, ann) in enumerate(candidates, 1):
        symbol = resolve_symbol(ann, src)
        if not json_output:
            console.print(f"[bold][{i}/{len(candidates)}][/bold] {symbol} (0x{ann.va:08x})")

        try:
            proven, message = _prove_single(
                cfg,
                src,
                ann,
                timeout,
                loop_bound,
                dry_run,
                start_offset=0,
                end_offset=0,
                check_edx=check_edx,
                watched_vas=watch_va,
                name_to_va=name_to_va,
            )
        except Exception as e:  # noqa: BLE001
            log.debug("Prove failed for %s", src, exc_info=True)
            proven, message = False, f"Error: {e}"

        already = isinstance(message, str) and message.startswith("ALREADY_MATCHED:")
        if proven:
            proven_count += 1
            if not json_output:
                action = "would update" if dry_run else "STATUS → PROVEN"
                console.print(f"  [green bold]PROVEN[/green bold] — {action}")
        elif already:
            already_matched_count += 1
            new_st = message.split(":", 1)[1]
            if not json_output:
                action = "would set" if dry_run else "STATUS →"
                console.print(
                    f"  [green]bytes match[/green] — {action} [bold]{new_st}[/bold] (not PROVEN)"
                )
        else:
            failed_count += 1
            if not json_output:
                console.print(f"  [yellow]NOT PROVEN:[/yellow] {message}")

        results_list.append(
            {
                "source": str(src),
                "symbol": symbol,
                "va": f"0x{ann.va:08x}",
                "proven": proven,
                "already_matched": already,
                "message": message,
            }
        )

    if json_output:
        json_print(
            {
                "schema_version": 1,
                "total": len(candidates),
                "proven": proven_count,
                "already_matched": already_matched_count,
                "failed": failed_count,
                "results": results_list,
            }
        )
    else:
        console.print()
        console.print("[bold]━━━ Prove Summary ━━━[/bold]")
        matching = sum(1 for _, a in candidates if a.status == "NEAR_MATCHING")
        console.print(f"  [bold]{matching} NEAR_MATCHING[/bold] functions tested")
        if proven_count:
            console.print(f"  [green bold]{proven_count}[/green bold] proven equivalent")
        if already_matched_count:
            console.print(
                f"  [green]{already_matched_count}[/green] already matched "
                f"(promoted to RELOC/EXACT)"
            )
        if failed_count:
            console.print(f"  [yellow]{failed_count}[/yellow] not proven")
        if dry_run:
            console.print("  [dim]--dry-run: no STATUS updates written[/dim]")
        console.print()


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
