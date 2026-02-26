"""decompiler.py - Pluggable decompiler backend for skeleton generation.

Provides a unified interface to fetch pseudo-C decompilation from multiple
backends (r2ghidra, r2dec, Ghidra headless). Used by rebrew-skeleton when
the ``--decomp`` flag is set.

Usage (internal)::

    from rebrew.decompiler import fetch_decompilation

    code = fetch_decompilation("auto", binary_path, va, root)
    if code:
        print(code)
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

# ANSI escape code stripper
_ANSI_RE = re.compile(r"\x1B\[[0-9;]*[a-zA-Z]")

# Known backends in auto-probe order (ghidra excluded — not yet implemented)
BACKENDS = ("r2ghidra", "r2dec")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_RE.sub("", text)


def _clean_output(text: str) -> str | None:
    """Strip ANSI codes and trim blank leading/trailing lines."""
    text = _strip_ansi(text)
    lines = text.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines) if lines else None


def _run_r2(binary: Path, va: int, cmd: str, root: Path) -> str | None:
    """Run an r2 command and return cleaned output."""
    try:
        full_cmd = f'r2 -q -c "aaa; s 0x{va:08x}; af; {cmd}" "{binary}"'
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=root,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout:
            return _clean_output(result.stdout)
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        pass
    return None


def fetch_r2ghidra(binary: Path, va: int, root: Path) -> str | None:
    """Fetch decompilation using r2ghidra (``pdg`` command).

    Requires: ``r2`` on PATH with the r2ghidra plugin installed.
    """
    if not shutil.which("r2"):
        return None
    if not binary.exists():
        return None
    return _run_r2(binary, va, "pdg", root)


def fetch_r2dec(binary: Path, va: int, root: Path) -> str | None:
    """Fetch decompilation using r2dec (``pdd`` command).

    Requires: ``r2`` on PATH with r2dec plugin (often bundled by default).
    """
    if not shutil.which("r2"):
        return None
    if not binary.exists():
        return None
    return _run_r2(binary, va, "pdd", root)


def fetch_ghidra(binary: Path, va: int, root: Path) -> str | None:
    """Fetch decompilation using Ghidra's analyzeHeadless.

    Not yet implemented — requires analyzeHeadless + a Ghidra script.
    Returns None with a stderr hint.
    """
    print(
        "decompiler: ghidra backend not yet implemented (requires analyzeHeadless + export script)",
        file=sys.stderr,
    )
    return None


_BACKEND_MAP = {
    "r2ghidra": fetch_r2ghidra,
    "r2dec": fetch_r2dec,
    "ghidra": fetch_ghidra,
}


def fetch_decompilation(
    backend: str,
    binary_path: Path,
    va: int,
    root: Path,
) -> tuple[str | None, str]:
    """Fetch pseudo-C decompilation from the specified backend.

    Args:
        backend: One of ``"r2ghidra"``, ``"r2dec"``, ``"ghidra"``, or ``"auto"``.
        binary_path: Absolute path to the target binary.
        va: Virtual address of the function.
        root: Project root directory.

    Returns:
        A tuple of ``(decompiled_code, backend_name)`` where backend_name is
        the name of the backend that produced the output (useful for ``auto``).
        If decompilation failed, ``(None, backend_name)`` is returned.
    """
    if backend == "auto":
        for name in BACKENDS:
            fn = _BACKEND_MAP[name]
            result = fn(binary_path, va, root)
            if result:
                return result, name
        return None, "auto"

    fn = _BACKEND_MAP.get(backend)
    if fn is None:
        print(
            f"decompiler: unknown backend '{backend}'. "
            f"Available: {', '.join(_BACKEND_MAP.keys())}, auto",
            file=sys.stderr,
        )
        return None, backend

    return fn(binary_path, va, root), backend
