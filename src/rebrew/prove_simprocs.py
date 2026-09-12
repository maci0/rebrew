"""prove_simprocs.py — Win32 SimProcedure models for the equivalence prover.

The symbolic models for the Win32 APIs prove.py simulates (heap allocation,
string/memory copies, path calls), plus the bounded-copy helpers that keep a
symbolic length sound: a copy the model cannot cover fails closed instead of
comparing only a prefix.  Imported lazily by prove.py because angr is optional.
"""

from __future__ import annotations

from typing import Any

_WIN32_SIMPROCS: dict[str, type] | None = None  # lazily populated


_MEMCPY_MAX_LEN = 1024


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
    import claripy

    if not n.symbolic:
        length = int(solver.eval(n, 1)[0])
        if length > _MEMCPY_MAX_LEN:
            # Only the prefix fits the model; the tail would be left
            # unconstrained on both sides (the unsound-prefix case).
            return None
        return length
    try:
        hi = int(solver.max(n))
    except Exception:
        return None
    if hi > _MEMCPY_MAX_LEN and solver.satisfiable(
        extra_constraints=(claripy.UGT(n, _MEMCPY_MAX_LEN),)
    ):
        return None
    return min(hi, _MEMCPY_MAX_LEN)


def _raise_unbounded_copy(solver: Any, n: Any) -> None:
    """Abort the state on a copy length the model cannot cover (fail closed).

    Raises so angr marks the state errored and excludes it from the terminal
    states: the proof then reports no/incomplete states (INCONCLUSIVE)
    instead of equating two prefixes.  The bound travels in the message.
    """
    raise RuntimeError(
        f"memcpy/memset length exceeds the {_MEMCPY_MAX_LEN}B copy cap "
        "(symbolic and unbounded, or a concrete value above it) — cannot prove "
        "equivalence over the whole copy (bound the length via "
        "prove_constraints or refactor to a bounded copy)"
    )


def _get_win32_simprocs() -> dict[str, type]:
    """Build and cache the Win32 SimProcedure registry (requires angr)."""
    global _WIN32_SIMPROCS
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

    class SimAllocZeroed(angr.SimProcedure):
        """LocalAlloc/GlobalLock: return a freshly zeroed 256-byte block."""

        def run(self, *args: Any, **kwargs: Any) -> Any:
            ptr = self.state.heap.allocate(256)  # type: ignore[attr-defined]
            for i in range(256):
                self.state.memory.store(ptr + i, claripy.BVV(0, 8))  # type: ignore[no-untyped-call]
            return ptr

    class SimMemcpy(angr.SimProcedure):
        """Model memcpy: copy src→dst symbolically, return dst."""

        def run(self, dst: Any, src: Any, n: Any) -> Any:
            # Copy the full admissible length, capped at _MEMCPY_MAX_LEN.
            # A symbolic length unbounded above the cap refuses the proof
            # (fail closed): copying one concretised length would only prove
            # the compared prefix while claiming the whole copy.
            length = _copy_length_or_none(self.state.solver, n)
            if length is None:
                _raise_unbounded_copy(self.state.solver, n)
                return dst  # unreachable; keeps mypy's flow analysis honest
            if length > 0:
                data = self.state.memory.load(src, length)  # type: ignore[no-untyped-call]
                self.state.memory.store(dst, data)  # type: ignore[no-untyped-call]
            return dst

    class SimMemset(angr.SimProcedure):
        """Model memset: fill dst with byte value, return dst."""

        def run(self, dst: Any, val: Any, n: Any) -> Any:
            # Same fail-closed policy as SimMemcpy: an unbounded symbolic
            # length errors the state rather than no-op'ing the memset on
            # both sides (which could fake equivalence).
            length = _copy_length_or_none(self.state.solver, n)
            if length is None:
                _raise_unbounded_copy(self.state.solver, n)
                return dst  # unreachable; keeps mypy's flow analysis honest
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

    for name in ("GlobalLock", "LocalAlloc"):
        _WIN32_SIMPROCS[name] = SimAllocZeroed
    return _WIN32_SIMPROCS
