"""prove_simprocs.py — Win32 SimProcedure models for the equivalence prover.

The symbolic models for the Win32 APIs prove.py simulates (heap allocation,
string/memory copies, path calls), plus the bounded-copy helpers that keep a
symbolic length sound: a copy the model cannot cover fails closed instead of
comparing only a prefix.  Imported lazily by prove.py because angr is optional.
"""

from __future__ import annotations

import logging
import threading
lazy from collections.abc import Callable
lazy from typing import Any, Never, override

_WIN32_SIMPROCS: dict[str, type] | None = None  # lazily populated
_SIMPROCS_LOCK = threading.Lock()


_MEMCPY_MAX_LEN = 1024

log = logging.getLogger(__name__)


def _copy_length_or_none(solver: Any, n: Any) -> int | None:
    """Bounded copy length for a symbolic ``memcpy``/``memset`` length.

    Returns ``None`` when the copy cannot be modelled in full — either *n* is
    symbolic and unconstrained above the copy cap, or *n* is a concrete value
    above the cap — because copying only the admissible prefix then silently
    dropping the rest would prove the compared prefix (P0: claiming PROVEN for
    bytes that differ past the cap is unsound).  Otherwise returns the length
    the SimProc may copy, at most ``_MEMCPY_MAX_LEN``: a concrete length at or
    below the cap is honoured exactly, and a solver-bounded symbolic length is
    honoured at its maximum (the bound is in the path constraints on both
    sides, so proving the max-length copy proves every admissible length).
    """
    from angr import claripy

    if not n.symbolic:
        length = int(solver.eval(n, 1)[0])
        if length > _MEMCPY_MAX_LEN:
            # Only the prefix fits the model; the tail would be left
            # unconstrained on both sides (the unsound-prefix case).
            return None
        return length
    try:
        hi = int(solver.max(n))
    except Exception as exc:
        # A solver blow-up must not read as the modelled "unbounded" case:
        # both fail closed, but only one of them is a proof-time bug.
        log.warning("solver cannot bound the copy length: %s", exc, exc_info=True)
        return None
    if hi > _MEMCPY_MAX_LEN and solver.satisfiable(
        extra_constraints=(claripy.UGT(n, _MEMCPY_MAX_LEN),)
    ):
        return None
    return min(hi, _MEMCPY_MAX_LEN)


def _raise_unbounded_copy() -> Never:
    """Abort the state on a copy length the model cannot cover (fail closed).

    Raises so angr marks the state errored and excludes it from the terminal
    states: the proof then reports no/incomplete states (INCONCLUSIVE)
    instead of equating two prefixes.
    """
    raise RuntimeError(
        f"memcpy/memset length exceeds the {_MEMCPY_MAX_LEN}B copy cap "
        "(symbolic and unbounded, or a concrete value above it) — cannot prove "
        "equivalence over the whole copy (bound the length via "
        "prove_constraints or refactor to a bounded copy)"
    )


def get_win32_simprocs() -> dict[str, type]:
    """Build and cache the Win32 SimProcedure registry (requires angr)."""
    global _WIN32_SIMPROCS
    if _WIN32_SIMPROCS is not None:
        return _WIN32_SIMPROCS
    with _SIMPROCS_LOCK:
        if _WIN32_SIMPROCS is not None:
            return _WIN32_SIMPROCS
        _WIN32_SIMPROCS = _build_win32_simprocs()
        return _WIN32_SIMPROCS


def _build_win32_simprocs() -> dict[str, type]:
    import angr
    from angr import claripy

    class _SharedSymbolicReturn(angr.SimProcedure):
        """Parameterized SimProcedure returning a constrained 32-bit BVS.

        When *shared_returns* is supplied (by :func:`rebrew.prove.prove_equivalence`),
        both the original and compiled projects reuse one BVS per
        ``(stub_addr, per_state_call_index)`` so identical Win32 API calls
        return the same symbolic value instead of generating spurious Z3
        counterexamples, while distinct calls to the same API still get
        distinct variables.  Constraints are added to every executing state's
        solver on both hits and misses.
        """

        _bvs_prefix: str = "api_retval"
        _constraint_fn: Callable[[Any, Any], None] | None = None
        _supports_shared_returns: bool = True

        def __init__(
            self,
            *args: Any,
            shared_returns: dict[tuple[int | None, int], Any] | None = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(*args, **kwargs)
            self._shared_returns = shared_returns

        @override
        def run(self, *args: Any, **kwargs: Any) -> Any:
            stub_addr = getattr(self, "addr", None)
            call_idx_key = ("_rebrew_simproc_call", stub_addr)
            state_globals: Any = self.state.globals
            idx = int(state_globals.get(call_idx_key, 0))
            state_globals[call_idx_key] = idx + 1
            if self._shared_returns is not None:
                key = (stub_addr, idx)
                bv = self._shared_returns.get(key)
                if bv is None:
                    addr_tag = f"0x{stub_addr:x}" if isinstance(stub_addr, int) else "none"
                    bv = claripy.BVS(f"{self._bvs_prefix}_{addr_tag}_{idx}", 32)
                    self._shared_returns[key] = bv
            else:
                bv = self.state.solver.BVS(self._bvs_prefix, 32)  # type: ignore[no-untyped-call]
            if self._constraint_fn is not None:
                self._constraint_fn(self.state.solver, bv)
            return bv

    def _make_symbolic_return(
        name: str,
        bvs_prefix: str,
        *,
        constraint_fn: Callable[[Any, Any], None] | None = None,
        doc: str = "",
    ) -> type:
        return type(
            name,
            (_SharedSymbolicReturn,),
            {
                "__doc__": doc,
                "_bvs_prefix": bvs_prefix,
                "_constraint_fn": staticmethod(constraint_fn)
                if constraint_fn is not None
                else None,
            },
        )

    def _constrain_handle(solver: Any, h: Any) -> None:
        solver.add(h != 0)
        solver.add(h != 0xFFFFFFFF)

    def _constrain_bool(solver: Any, b: Any) -> None:
        solver.add(claripy.ULE(b, 1))

    def _constrain_strlen(solver: Any, result: Any) -> None:
        solver.add(claripy.ULE(result, 0x10000))  # bound to 64K

    ReturnSymbolicDword = _make_symbolic_return(
        "ReturnSymbolicDword",
        "api_retval",
        doc="Generic: return a 32-bit symbolic value.",
    )
    ReturnSymbolicHandle = _make_symbolic_return(
        "ReturnSymbolicHandle",
        "handle",
        constraint_fn=_constrain_handle,
        doc="Return a symbolic HANDLE (non-zero, non-INVALID_HANDLE_VALUE).",
    )
    ReturnSymbolicBool = _make_symbolic_return(
        "ReturnSymbolicBool",
        "bool_ret",
        constraint_fn=_constrain_bool,
        doc="Return 0 or 1 (symbolic BOOL).",
    )
    SimStrlen = _make_symbolic_return(
        "SimStrlen",
        "strlen_ret",
        constraint_fn=_constrain_strlen,
        doc="Model strlen: return symbolic non-negative length.",
    )

    class ReturnVoid(angr.SimProcedure):
        """Void return — no value, no side effects."""

        @override
        def run(self, *args: Any, **kwargs: Any) -> None:
            return

    class SimAllocZeroed(angr.SimProcedure):
        """LocalAlloc/GlobalLock: return a freshly zeroed 256-byte block."""

        @override
        def run(self, *args: Any, **kwargs: Any) -> Any:
            ptr = self.state.heap.allocate(256)  # type: ignore[attr-defined]
            self.state.memory.store(ptr, claripy.BVV(0, 256 * 8))  # type: ignore[no-untyped-call]
            return ptr

    class SimMemcpy(angr.SimProcedure):
        """Model memcpy: copy src→dst symbolically, return dst."""

        @override
        def run(self, dst: Any, src: Any, n: Any) -> Any:
            # Copy the full admissible length, capped at _MEMCPY_MAX_LEN.
            # A symbolic length unbounded above the cap refuses the proof
            # (fail closed): copying one concretised length would only prove
            # the compared prefix while claiming the whole copy.
            length = _copy_length_or_none(self.state.solver, n)
            if length is None:
                _raise_unbounded_copy()
            if length > 0:
                data = self.state.memory.load(src, length)  # type: ignore[no-untyped-call]
                self.state.memory.store(dst, data)  # type: ignore[no-untyped-call]
            return dst

    class SimMemset(angr.SimProcedure):
        """Model memset: fill dst with byte value, return dst."""

        @override
        def run(self, dst: Any, val: Any, n: Any) -> Any:
            # Same fail-closed policy as SimMemcpy: an unbounded symbolic
            # length errors the state rather than no-op'ing the memset on
            # both sides (which could fake equivalence).
            length = _copy_length_or_none(self.state.solver, n)
            if length is None:
                _raise_unbounded_copy()
            if length > 0:
                byte_val = claripy.Extract(7, 0, val)
                for i in range(length):
                    self.state.memory.store(dst + i, byte_val)  # type: ignore[no-untyped-call]
            return dst

    # Registry: map Win32/CRT names to SimProcedure classes
    procs: dict[str, type] = {}

    # --- CRT functions with semantic models ---
    for name in ("memcpy", "_memcpy"):
        procs[name] = SimMemcpy
    for name in ("memset", "_memset"):
        procs[name] = SimMemset
    for name in ("strlen", "_strlen", "lstrlenA"):
        procs[name] = SimStrlen

    # --- File I/O ---
    for name in ("CreateFileA", "CreateFileW", "_lopen", "_lcreat"):
        procs[name] = ReturnSymbolicHandle
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
        procs[name] = ReturnSymbolicBool

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
        procs[name] = ReturnSymbolicHandle  # non-zero pointer
    for name in ("HeapFree", "LocalFree", "GlobalFree", "VirtualFree", "free", "_free"):
        procs[name] = ReturnVoid

    # --- Window / GDI ---
    for name in ("GetDC", "CreateCompatibleDC", "GetWindowDC"):
        procs[name] = ReturnSymbolicHandle
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
        procs[name] = ReturnSymbolicBool
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
        procs[name] = ReturnSymbolicDword

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
        procs[name] = ReturnSymbolicDword  # LONG error code

    # --- String ---
    for name in ("lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW"):
        procs[name] = ReturnSymbolicDword
    for name in (
        "lstrcmpA",
        "lstrcmpW",
        "lstrcmpiA",
        "lstrcmpiW",
        "CompareStringA",
        "CompareStringW",
    ):
        procs[name] = ReturnSymbolicDword
    for name in ("lstrlenW", "wcslen", "_wcslen"):
        procs[name] = SimStrlen

    # --- Synchronisation ---
    for name in (
        "EnterCriticalSection",
        "LeaveCriticalSection",
        "InitializeCriticalSection",
        "DeleteCriticalSection",
    ):
        procs[name] = ReturnVoid

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
        procs[name] = ReturnSymbolicDword

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
        procs[name] = ReturnSymbolicDword

    for name in ("GlobalLock", "LocalAlloc"):
        procs[name] = SimAllocZeroed
    return procs
