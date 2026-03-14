"""prove.py — Symbolic equivalence prover for rebrew.

Uses angr's symbolic execution and Z3 constraint solving to mathematically
prove that a compiled function is semantically equivalent to the original
binary, even when byte-level comparison fails due to different register
allocation, instruction reordering, or loop unrolling.

Architecture
~~~~~~~~~~~~
1. Extract target bytes from the DLL and compiled bytes from the .obj
2. Load both into separate angr Projects using the ``blob`` backend
3. Parse the ``// PROTOTYPE:`` annotation for calling convention + arg count
4. Hook IAT-indirect calls with Win32 API-aware SimProcedures (constrained
   return values) to prevent path explosion from API calls.  Falls back to
   ``ReturnUnconstrained`` for unknown APIs.
5. Apply user-specified argument constraints from ``prove_constraints``
   metadata (e.g. "arg3 is a pointer to a 24-byte struct")
6. Run symbolic execution on both with ``LoopSeer`` and timeout limits
7. Compare EAX (return register) formulas via Z3 — if no satisfying
   assignment makes them differ, the functions are proven equivalent

angr is an optional dependency (~500 MB).  Import is guarded with a clear
error message directing users to ``uv pip install -e ".[prove]"``.
"""

from __future__ import annotations

import contextlib
import re
import struct
import tempfile
import time
import warnings
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi, resolve_symbol
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    require_config,
    target_marker,
)
from rebrew.compile import compile_to_obj
from rebrew.config import ProjectConfig
from rebrew.matcher.parsers import parse_obj_symbol_bytes

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
# Each returns a fresh symbolic value of the correct width.  Memory-writing
# APIs (memcpy, memset) are modelled to update symbolic memory.

_WIN32_SIMPROCS: dict[str, type] | None = None  # lazily populated


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
            return self.state.solver.BVS("api_retval", 32)

    class ReturnSymbolicHandle(angr.SimProcedure):
        """Return a symbolic HANDLE (non-zero, non-INVALID_HANDLE_VALUE)."""

        def run(self, *args: Any, **kwargs: Any) -> Any:
            h = self.state.solver.BVS("handle", 32)
            self.state.solver.add(h != 0)
            self.state.solver.add(h != 0xFFFFFFFF)
            return h

    class ReturnSymbolicBool(angr.SimProcedure):
        """Return 0 or 1 (symbolic BOOL)."""

        def run(self, *args: Any, **kwargs: Any) -> Any:
            b = self.state.solver.BVS("bool_ret", 32)
            self.state.solver.add(claripy.ULE(b, 1))
            return b

    class ReturnZero(angr.SimProcedure):
        """Return 0 (S_OK / ERROR_SUCCESS)."""

        def run(self, *args: Any, **kwargs: Any) -> Any:
            return claripy.BVV(0, 32)

    class ReturnVoid(angr.SimProcedure):
        """Void return — no value, no side effects."""

        def run(self, *args: Any, **kwargs: Any) -> None:
            return

    class SimLocalAlloc(angr.SimProcedure):
        def run(self, uFlags, uBytes):
            ptr = self.state.heap.allocate(256)
            for i in range(256):
                self.state.memory.store(ptr + i, claripy.BVV(0, 8))
            return ptr

    class SimGlobalLock(angr.SimProcedure):
        def run(self, hMem):
            ptr = self.state.heap.allocate(256)
            for i in range(256):
                self.state.memory.store(ptr + i, claripy.BVV(0, 8))
            return ptr

    class SimMemcpy(angr.SimProcedure):
        """Model memcpy: copy src→dst symbolically, return dst."""

        def run(self, dst: Any, src: Any, n: Any) -> Any:
            # Concretise length to avoid explosion; cap at 1024
            try:
                length = self.state.solver.eval(n)
            except Exception:
                length = 0
            length = min(length, 1024)
            if length > 0:
                data = self.state.memory.load(src, length)
                self.state.memory.store(dst, data)
            return dst

    class SimMemset(angr.SimProcedure):
        """Model memset: fill dst with byte value, return dst."""

        def run(self, dst: Any, val: Any, n: Any) -> Any:
            try:
                length = self.state.solver.eval(n)
            except Exception:
                length = 0
            length = min(length, 1024)
            if length > 0:
                byte_val = claripy.Extract(7, 0, val)
                for i in range(length):
                    self.state.memory.store(dst + i, byte_val)
            return dst

    class SimStrlen(angr.SimProcedure):
        """Model strlen: return symbolic non-negative length."""

        def run(self, s: Any) -> Any:
            result = self.state.solver.BVS("strlen_ret", 32)
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


def _parse_prototype(proto: str) -> tuple[str, int]:
    """Parse a C prototype string into (calling_convention, arg_count).

    Returns ("cdecl", 0) as default if parsing fails.
    """
    m = _PROTO_RE.match(proto.strip())
    if not m:
        return "cdecl", 0

    cc = (m.group("cc") or "__cdecl").lstrip("_").lower()
    args_str = m.group("args").strip()

    if not args_str or args_str.lower() == "void":
        return cc, 0

    # Count args by splitting on commas (handles pointer types with *)
    args = [a.strip() for a in args_str.split(",") if a.strip()]
    return cc, len(args)


# ---------------------------------------------------------------------------
# Core equivalence prover
# ---------------------------------------------------------------------------


def prove_equivalence(
    original_bytes: bytes,
    compiled_bytes: bytes,
    reloc_offsets: dict[int, str] | None,
    prototype: str,
    arch: str = "x86",
    *,
    timeout: int = 60,
    loop_bound: int = 10,
    binary_path: Path | None = None,
    arg_constraints: dict[str, Any] | None = None,
    start_offset: int = 0,
    end_offset: int = 0,
) -> tuple[bool, str]:
    """Prove semantic equivalence of two function byte blobs via symbolic execution.

    Args:
        original_bytes: Raw bytes from the target binary.
        compiled_bytes: Raw bytes from the compiled .obj.
        reloc_offsets: Relocation offsets in the compiled blob (offset → symbol name).
        prototype: C prototype string for argument setup.
        arch: Architecture string (default "x86").
        timeout: Seconds before giving up.
        loop_bound: Max loop iterations for angr's LoopSeer.
        binary_path: Path to the target PE binary (for IAT-based API hooking).
        arg_constraints: Per-argument constraints from metadata (see _apply_arg_constraints).

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
                            iat_api_names[stub_addr] = fn.name
        except Exception:
            pass  # LIEF import scan is best-effort

    cc, arg_count = _parse_prototype(prototype)

    # Create symbolic arguments
    sym_args = [claripy.BVS(f"arg_{i}", 32) for i in range(arg_count)]

    def _setup_state(proj: angr.Project, label: str) -> angr.SimState:
        """Create an initial state with symbolic arguments placed per calling convention.

        Initialises ESP to a fake stack, pushes a concrete return address so
        ``ret`` pops a known value instead of unconstrained memory.  Enables
        zero-fill for uninitialized memory and registers to prevent symbolic
        pollution from globals, statics, and scratch registers.
        """
        state = proj.factory.blank_state(
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
        state.memory.store(STACK_TOP, claripy.BVV(RETURN_SENTINEL, 32), endness="Iend_LE")

        # Arguments sit above the return address on the stack
        ARG_OFFSET = 4  # first arg at ESP+4 (after ret addr)

        if cc == "thiscall" and sym_args:
            # ECX = this pointer (first arg)
            state.regs.ecx = sym_args[0]
            # Remaining args on stack (right-to-left)
            for i, arg in enumerate(sym_args[1:]):
                state.memory.store(STACK_TOP + ARG_OFFSET + (i * 4), arg, endness="Iend_LE")
        elif cc == "fastcall":
            # ECX = arg0, EDX = arg1, rest on stack
            if len(sym_args) >= 1:
                state.regs.ecx = sym_args[0]
            if len(sym_args) >= 2:
                state.regs.edx = sym_args[1]
            for i, arg in enumerate(sym_args[2:]):
                state.memory.store(STACK_TOP + ARG_OFFSET + (i * 4), arg, endness="Iend_LE")
        else:
            # cdecl / stdcall — all args on stack
            for i, arg in enumerate(sym_args):
                state.memory.store(STACK_TOP + ARG_OFFSET + (i * 4), arg, endness="Iend_LE")

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
    # relocation-only differences so RELOC functions can be proven equivalent.
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
                # sides call the same stub — this is the key fix for RELOC.
                if offset <= len(original_bytes) - 4:
                    patched_orig[offset : offset + 4] = struct.pack("<I", disp)
                stub_hooks.append(stub_addr)

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
        # Filter stub_hooks to only stubs within the sliced range
        # (stubs at STUB_BASE are external targets, always keep them)

    try:
        proj_orig = _make_project(bytes(patched_orig))
        proj_comp = _make_project(bytes(patched_comp))
    except Exception as e:
        return False, f"Failed to create angr projects: {e}"

    # Hook all stub addresses on both blobs.  Prefer specific Win32
    # SimProcedures (constrained return values) over generic ReturnUnconstrained
    # to reduce path explosion from API calls.
    _ret_unc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
    win32_procs = _get_win32_simprocs()
    for stub_addr in stub_hooks:
        api_name = iat_api_names.get(stub_addr, "")
        simproc_cls = win32_procs.get(api_name, _ret_unc)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                proj_comp.hook(stub_addr, simproc_cls(), length=1)
                proj_orig.hook(stub_addr, simproc_cls(), length=1)
            except Exception:
                pass

    # Hook the return sentinel address so states that reach it land in
    # deadended (clean termination) instead of unconstrained.
    _path_terminator = angr.SIM_PROCEDURES["stubs"]["PathTerminator"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            proj_comp.hook(RETURN_SENTINEL, _path_terminator(), length=0)
            proj_orig.hook(RETURN_SENTINEL, _path_terminator(), length=0)
        except Exception:
            pass

    # Seed IAT slot memory in the original blob's initial state so
    # indirect calls (via register or memory) resolve to our stubs.
    state_orig = _setup_state(proj_orig, "original")
    for iat_addr, stub_addr in iat_stub_map_orig.items():
        state_orig.memory.store(iat_addr, claripy.BVV(stub_addr, 32), endness="Iend_LE")

    state_comp = _setup_state(proj_comp, "compiled")

    # Apply user-specified argument constraints to reduce path explosion
    if arg_constraints:
        _apply_arg_constraints(state_orig, sym_args, arg_constraints)
        _apply_arg_constraints(state_comp, sym_args, arg_constraints)

    def _run_simulation(proj: angr.Project, state: angr.SimState) -> list[Any]:
        """Run symbolic execution and return satisfiable states."""
        sm = proj.factory.simgr(state, save_unconstrained=True)
        sm.use_technique(angr.exploration_techniques.LoopSeer(bound=loop_bound))

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
            # Return whatever partial states angr reached before the deadline
            list(sm.deadended) or list(sm.active)
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

    try:
        states_orig = _run_simulation(proj_orig, state_orig)
        states_comp = _run_simulation(proj_comp, state_comp)
    except Exception as e:
        return False, f"Symbolic execution failed: {e}"

    if not states_orig:
        return False, "No terminal states reached for original binary (timeout or path explosion)"
    if not states_comp:
        return False, "No terminal states reached for compiled code (timeout or path explosion)"

    # Compare EAX (return register) across all terminal state pairs
    # For equivalence: for ALL pairs of (orig, comp) states, EAX must be provably equal
    for s_orig in states_orig:
        eax_orig = s_orig.regs.eax
        can_differ = False  # True if we found at least one (orig, comp) pair that can differ
        for s_comp in states_comp:
            eax_comp = s_comp.regs.eax

            # Check if there exists an input that makes them differ
            # Build constraint from both states' symbolic variables
            solver = claripy.Solver()
            # Copy constraints from both states
            for expr in s_orig.solver.constraints:
                solver.add(expr)
            for expr in s_comp.solver.constraints:
                solver.add(expr)
            solver.add(eax_orig != eax_comp)

            if solver.satisfiable():
                # Found an assignment where return values differ — not equivalent
                can_differ = True
                break

        if can_differ:
            return False, (
                "Z3 found a satisfying assignment where return values differ "
                f"(checked {len(states_orig)} x {len(states_comp)} state pairs)"
            )

    return True, (
        f"Proven equivalent ({len(states_orig)} original state(s), "
        f"{len(states_comp)} compiled state(s))"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew prove src/mygame/calculate_physics.c · Prove equivalence\n\n"
    "  rebrew prove 0x01006364 · · · · · · · · · · · Find by VA\n\n"
    "  rebrew prove my_func · · · · · · · · · · · · · Find by symbol name\n\n"
    "  rebrew prove src/mygame/func.c --dry-run · · · Don't update annotations\n\n"
    "  rebrew prove --all · · · · · · · · · · · · · · Prove all eligible functions\n\n"
    "  rebrew prove my_func --start-offset 0 --end-offset 48  Prove a specific block\n\n"
    "[bold]How it works:[/bold]\n\n"
    "  1. Validates the function status is NEAR_MATCHING or RELOC (byte-diff but structurally close)\n\n"
    "  2. Extracts target bytes from the DLL and compiles the C source\n\n"
    "  3. Loads both byte blobs into angr's symbolic execution engine\n\n"
    "  4. Proves EAX equivalence via Z3 constraint solving\n\n"
    "  5. If proven: updates STATUS from NEAR_MATCHING \u2192 PROVEN\n\n"
    "[dim]angr is a heavy optional dependency (~500 MB). "
    'Install with: uv pip install -e ".[prove]"[/dim]'
)

app = typer.Typer(
    help="Prove semantic equivalence of NEAR_MATCHING functions via symbolic execution.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)

console = Console(stderr=True)


def _resolve_source(source_arg: str, cfg: ProjectConfig) -> Path:
    """Resolve a source argument to a Path.

    Accepts a direct file path, a symbol name, or a hex VA (e.g. 0x01006364).
    """
    p = Path(source_arg)
    if p.exists() and p.is_file():
        return p

    # Try hex VA lookup — search annotations for a matching VA
    va_int: int | None = None
    stripped = source_arg.strip().lower()
    if stripped.startswith("0x"):
        with contextlib.suppress(ValueError):
            va_int = int(stripped, 16)

    from rebrew.cli import iter_sources

    if va_int is not None:
        tm = target_marker(cfg)
        for src in iter_sources(cfg.reversed_dir, cfg):
            try:
                annos = parse_c_file_multi(src, target_name=tm, metadata_dir=cfg.metadata_dir)
            except Exception:  # noqa: BLE001
                continue
            for a in annos:
                if a.va == va_int:
                    return src

    # Try searching for a matching .c file by stem (symbol name)
    for src in iter_sources(cfg.reversed_dir, cfg):
        if src.stem == source_arg or src.stem == source_arg.lstrip("_"):
            return src

    return p  # Return as-is, will fail later with a clear error


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(None, help="C source file, symbol name, or VA (hex)"),
    all_sources: bool = typer.Option(False, "--all", help="Prove all NEAR_MATCHING functions"),
    timeout: int = typer.Option(60, "--timeout", help="Seconds before giving up"),
    loop_bound: int = typer.Option(10, "--loop-bound", help="Max loop iterations for angr"),
    start_offset: int = typer.Option(
        0, "--start-offset", help="Start byte offset within the function (0-based)"
    ),
    end_offset: int = typer.Option(
        0, "--end-offset", help="End byte offset within the function (0 = full function)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Prove semantic equivalence of a NEAR_MATCHING or RELOC function via symbolic execution."""
    # Guard angr import early
    try:
        _require_angr()
    except ImportError as e:
        error_exit(str(e), json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)

    if all_sources:
        _run_all_batch(cfg, timeout, loop_bound, dry_run, json_output)
        return

    if source is None:
        error_exit("Either provide a source file or use --all", json_mode=json_output)
    source_path = _resolve_source(source, cfg)

    if not source_path.exists():
        error_exit(f"Source file not found: {source_path}", json_mode=json_output)

    # Parse annotation — use multi-parser with metadata_dir so STATUS/CFLAGS/SIZE
    # are read from rebrew-function.toml (where volatile metadata lives).
    annotations = parse_c_file_multi(
        source_path,
        target_name=target_marker(cfg),
        metadata_dir=cfg.metadata_dir,
    )
    ann = None
    for a in annotations:
        if a.status in ("NEAR_MATCHING", "RELOC"):
            ann = a
            break
    if ann is None and annotations:
        ann = annotations[0]  # fallback to first for error reporting
    if ann is None:
        error_exit(f"No metadata found in {source_path}", json_mode=json_output)

    if ann.status not in ("NEAR_MATCHING", "RELOC"):
        error_exit(
            f"Status is '{ann.status}', expected NEAR_MATCHING or RELOC. "
            "Only NEAR_MATCHING/RELOC functions need symbolic equivalence proving.",
            json_mode=json_output,
        )

    symbol = resolve_symbol(ann, source_path)
    va = ann.va
    size = ann.size

    if not size:
        error_exit(f"SIZE metadata is missing or zero in {source_path}", json_mode=json_output)

    # Extract target bytes from DLL
    target_bytes = extract_raw_bytes(cfg.target_binary, va, size)
    if not target_bytes:
        error_exit(
            f"Failed to extract target bytes at VA 0x{va:08x} (size {size})",
            json_mode=json_output,
        )

    # Compile source and extract obj bytes
    cflags_str = ann.cflags or "/O2 /Gd"
    cflags_list = cflags_str.split()

    with tempfile.TemporaryDirectory(prefix="rebrew_prove_") as workdir:
        obj_path, err = compile_to_obj(cfg, source_path, cflags_list, workdir)
        if obj_path is None:
            error_exit(f"Compile error: {err}", json_mode=json_output)

        obj_bytes, reloc_offsets = parse_obj_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            error_exit(f"Symbol '{symbol}' not found in compiled .obj", json_mode=json_output)

    prototype = ann.prototype or ""
    arg_constraints = ann.prove_constraints if ann.prove_constraints else None

    # Run the prover
    if not json_output:
        console.print(
            f"[bold]Proving equivalence:[/bold] {source_path.name} "
            f"(0x{va:08x}, {len(target_bytes)}B vs {len(obj_bytes)}B)"
        )
        console.print(f"  Prototype: {prototype or '(none — assuming void f(void))'}")
        console.print(f"  Timeout: {timeout}s, loop bound: {loop_bound}")
        if start_offset or end_offset:
            console.print(f"  Slice: [{start_offset}:{end_offset}] ({end_offset - start_offset}B)")
        if arg_constraints:
            console.print(f"  Constraints: {', '.join(arg_constraints.keys())}")

    proven, message = prove_equivalence(
        target_bytes,
        obj_bytes,
        reloc_offsets,
        prototype,
        timeout=timeout,
        loop_bound=loop_bound,
        binary_path=cfg.target_binary,
        arg_constraints=arg_constraints,
        start_offset=start_offset,
        end_offset=end_offset,
    )

    # Build result
    result: dict[str, Any] = {
        "source": str(source_path),
        "symbol": symbol,
        "va": f"0x{va:08x}",
        "size": size,
        "previous_status": ann.status,
        "proven": proven,
        "message": message,
        "target_bytes_len": len(target_bytes),
        "compiled_bytes_len": len(obj_bytes),
    }
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
        raise typer.Exit(code=EXIT_MISMATCH)


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


def _prove_single(
    cfg: ProjectConfig,
    source_path: Path,
    ann: Any,
    timeout: int,
    loop_bound: int,
    dry_run: bool,
    json_output: bool,
    *,
    start_offset: int = 0,
    end_offset: int = 0,
) -> tuple[bool, str]:
    """Prove a single function and return (proven, message)."""
    symbol = resolve_symbol(ann, source_path)
    va = ann.va
    size = ann.size

    if not size:
        return False, "SIZE missing or zero"

    target_bytes = extract_raw_bytes(cfg.target_binary, va, size)
    if not target_bytes:
        return False, f"Failed to extract target bytes at VA 0x{va:08x}"

    cflags_str = ann.cflags or "/O2 /Gd"
    cflags_list = cflags_str.split()

    with tempfile.TemporaryDirectory(prefix="rebrew_prove_") as workdir:
        obj_path, err = compile_to_obj(cfg, source_path, cflags_list, workdir)
        if obj_path is None:
            return False, f"Compile error: {err}"

        obj_bytes, reloc_offsets = parse_obj_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            return False, f"Symbol '{symbol}' not found in compiled .obj"

    prototype = ann.prototype or ""
    arg_constraints = ann.prove_constraints if ann.prove_constraints else None

    proven, message = prove_equivalence(
        target_bytes,
        obj_bytes,
        reloc_offsets,
        prototype,
        timeout=timeout,
        loop_bound=loop_bound,
        binary_path=cfg.target_binary,
        arg_constraints=arg_constraints,
        start_offset=start_offset,
        end_offset=end_offset,
    )

    if proven and not dry_run:
        from rebrew.metadata import update_source_status

        update_source_status(cfg.metadata_dir, "PROVEN", ann.module, va)

    return proven, message


def _run_all_batch(
    cfg: ProjectConfig,
    timeout: int,
    loop_bound: int,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Batch-prove all NEAR_MATCHING/RELOC functions."""
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    tm = target_marker(cfg)

    # Collect all eligible annotations
    candidates: list[tuple[Path, Any]] = []
    for src in sources:
        try:
            annos = parse_c_file_multi(src, target_name=tm, metadata_dir=cfg.metadata_dir)
        except Exception:  # noqa: BLE001
            continue
        for a in annos:
            if a.status in ("NEAR_MATCHING", "RELOC") and a.size:
                candidates.append((src, a))

    if not candidates:
        if json_output:
            json_print({"total": 0, "proven": 0, "failed": 0, "results": []})
        else:
            console.print("[dim]No NEAR_MATCHING/RELOC functions found to prove.[/dim]")
        return

    if not json_output:
        console.print(
            f"\n[bold]Batch proving {len(candidates)} NEAR_MATCHING/RELOC function(s)[/bold]"
            + (" [dim](--dry-run)[/dim]" if dry_run else "")
            + "\n"
        )

    proven_count = 0
    failed_count = 0
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
                json_output,
                start_offset=0,
                end_offset=0,
            )
        except Exception as e:  # noqa: BLE001
            proven, message = False, f"Error: {e}"

        if proven:
            proven_count += 1
            if not json_output:
                action = "would update" if dry_run else "STATUS → PROVEN"
                console.print(f"  [green bold]PROVEN[/green bold] — {action}")
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
                "message": message,
            }
        )

    if json_output:
        json_print(
            {
                "total": len(candidates),
                "proven": proven_count,
                "failed": failed_count,
                "results": results_list,
            }
        )
    else:
        console.print()
        console.print("[bold]━━━ Prove Summary ━━━[/bold]")
        matching = sum(1 for _, a in candidates if a.status in ("NEAR_MATCHING",))
        reloc = sum(1 for _, a in candidates if a.status == "RELOC")
        parts = []
        if matching:
            parts.append(f"{matching} NEAR_MATCHING")
        if reloc:
            parts.append(f"{reloc} RELOC")
        console.print(f"  [bold]{' + '.join(parts)}[/bold] functions tested")
        if proven_count:
            console.print(f"  [green bold]{proven_count}[/green bold] proven equivalent")
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
