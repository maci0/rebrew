"""decompiler.py - Pluggable decompiler backend for skeleton generation.

Provides a unified interface to fetch pseudo-C decompilation from multiple
backends (r2ghidra/rz-ghidra, r2dec/rz-dec, Ghidra via ReVa MCP).  Used by
rebrew skeleton when the ``--decomp`` flag is set.

Both radare2 (``r2``) and rizin (``rz``) are supported transparently —
the first one found on PATH is used.  The ``ghidra`` backend connects to a
running Ghidra instance through the ReVa MCP bridge.

Usage (internal)::

    from rebrew.decompiler import fetch_decompilation

    code, backend = fetch_decompilation("auto", binary_path, va, root)
    if code:
        print(code)
"""

import importlib
import logging
import re
import shutil
import subprocess
import sys
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from rebrew.registry import RegistryError

# ANSI escape code stripper
_ANSI_RE = re.compile(r"\x1B\[[0-9;]*[a-zA-Z]")

# Auto-probe order when backend="auto" (ghidra is available for explicit
# use but not auto-probed; use backend='ghidra' with MCP configuration).
# kuna (the agent-first Ghidra-port decompiler) is probed last — a separate
# binary, slower to start than r2's in-process plugins.
BACKENDS = ("r2ghidra", "r2dec", "kuna")

_DEFAULT_MCP_ENDPOINT = "http://localhost:8080/mcp/message"
_MCP_TIMEOUT_S = 30.0


def _clean_output(text: str) -> str | None:
    """Strip ANSI codes and trim blank leading/trailing lines."""
    text = _ANSI_RE.sub("", text)
    lines = text.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines) if lines else None


def _find_re_tool() -> str | None:
    """Return the radare2/rizin binary name available on PATH.

    Prefers rizin (``rz``) over radare2 (``r2``); the ``rizin`` name (the
    upstream binary on Debian/Ubuntu and some distros) is probed too.
    Returns ``None`` if none is installed.
    """
    for name in ("rz", "r2", "rizin"):
        if shutil.which(name):
            return name
    return None


_ALLOWED_RE_CMDS = frozenset({"pdg", "pdd"})


def _run_re(binary: Path, va: int, cmd: str, root: Path) -> str | None:
    """Run a radare2/rizin command and return cleaned output.

    Automatically detects whether ``rz`` or ``r2`` is on PATH.
    ``cmd`` must be one of the allowed radare2 commands (pdg, pdd).
    """
    if cmd not in _ALLOWED_RE_CMDS:
        raise ValueError(f"disallowed radare2 command: {cmd!r}")
    tool = _find_re_tool()
    if tool is None:
        return None
    try:
        result = subprocess.run(
            [tool, "-q", "-c", f"aaa; s 0x{va:08x}; af; {cmd}", str(binary)],
            capture_output=True,
            text=True,
            cwd=root,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout:
            return _clean_output(result.stdout)
    except subprocess.TimeoutExpired:
        warnings.warn(f"{tool} timed out decompiling 0x{va:08x}", stacklevel=2)
    except (OSError, subprocess.SubprocessError) as e:
        warnings.warn(f"{tool} failed decompiling 0x{va:08x}: {e}", stacklevel=2)
    return None


def fetch_r2ghidra(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
    """Fetch decompilation using the ghidra decompiler plugin (``pdg``).

    Works with both r2ghidra (radare2) and rz-ghidra (rizin).
    Requires ``r2`` or ``rz`` on PATH with the ghidra plugin installed.
    """
    if not binary.exists():
        return None
    return _run_re(binary, va, "pdg", root)


def fetch_r2dec(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
    """Fetch decompilation using the jsdec plugin (``pdd``).

    Works with both r2dec (radare2) and rz-dec (rizin).
    Requires ``r2`` or ``rz`` on PATH with the jsdec/dec plugin installed.
    """
    if not binary.exists():
        return None
    return _run_re(binary, va, "pdd", root)


def fetch_kuna(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
    """Fetch decompilation from the Kuna decompiler (agent-first Ghidra port).

    Requires the ``kuna`` binary on PATH (github.com/Noelo-Lab/kuna — a
    single Rust binary).  Runs ``kuna decompile <binary> 0x<va> --addr``
    (Kuna's CLI takes an address with ``--addr``) and returns the cleaned C
    printed to stdout.  Returns ``None`` when kuna is unavailable or fails,
    exactly like the other optional backends.
    """
    if not binary.exists():
        return None
    kuna = shutil.which("kuna")
    if kuna is None:
        return None
    try:
        result = subprocess.run(
            [kuna, "decompile", str(binary), f"0x{va:x}", "--addr"],
            capture_output=True,
            text=True,
            cwd=root,
            timeout=180,
        )
        if result.returncode == 0 and result.stdout:
            return _clean_output(result.stdout)
    except subprocess.TimeoutExpired:
        warnings.warn(f"kuna timed out decompiling 0x{va:08x}", stacklevel=2)
    except (OSError, subprocess.SubprocessError) as e:
        warnings.warn(f"kuna failed decompiling 0x{va:08x}: {e}", stacklevel=2)
    return None


def fetch_ghidra(
    binary: Path,
    va: int,
    **kwargs: Any,
) -> str | None:
    """Fetch decompilation from Ghidra via ReVa MCP ``get-decompilation`` tool.

    Requires a running ReVa MCP server connected to Ghidra.
    """
    endpoint: str = kwargs.get("endpoint") or _DEFAULT_MCP_ENDPOINT
    program_path: str | None = kwargs.get("program_path")

    _sync_mod = importlib.import_module("rebrew.ghidra.client")
    _fetch_raw = _sync_mod.fetch_mcp_tool_raw
    _init_session = _sync_mod.init_mcp_session

    if program_path is None:
        program_path = f"/{binary.name}"

    try:
        with httpx.Client(timeout=_MCP_TIMEOUT_S) as client:
            session_id = _init_session(client, endpoint)
            result = _fetch_raw(
                client,
                endpoint,
                "get-decompilation",
                {
                    "programPath": program_path,
                    "functionNameOrAddress": f"0x{va:08X}",
                },
                request_id=1,
                session_id=session_id,
            )

            if isinstance(result, str):
                return _clean_output(result)
            if isinstance(result, dict):
                for key in ("decompilation", "text", "code"):
                    candidate = result.get(key)
                    if isinstance(candidate, str) and candidate.strip():
                        return _clean_output(candidate)
            return None
    except (OSError, ValueError, KeyError, TypeError, httpx.HTTPError) as e:
        # Bare ConnectionError() has an empty str — include the type name so logs
        # and pytest warnings stay actionable.
        detail = str(e).strip() or type(e).__name__
        warnings.warn(
            f"Ghidra MCP decompilation failed for 0x{va:08x}: {detail}",
            stacklevel=2,
        )
        return None


def kuna_seed_source(binary: Path, va: int, root: Path) -> str | None:
    """Fetch Kuna's decompilation of *va* and make it compilable (rebrew fix).

    Returns the fixup'd C — a GA seed candidate — or ``None`` when kuna is
    unavailable, fails, or the output is not valid C.
    """
    raw = fetch_kuna(binary, va, root)
    if not raw:
        return None
    from rebrew.fixup import sanitize_tokens
    from rebrew.llm_seed import valid_c_source

    fixed, _ = sanitize_tokens(raw)
    return fixed if valid_c_source(fixed) else None


# Backends share the (binary, va, root) core plus optional keyword args;
# fetch_ghidra ignores root (the MCP server holds its own project).
_BACKEND_MAP: dict[str, Callable[..., str | None]] = {
    "r2ghidra": fetch_r2ghidra,
    "r2dec": fetch_r2dec,
    "ghidra": fetch_ghidra,
    "kuna": fetch_kuna,
}

#: setuptools entry-point group whose members register extra decompiler
#: backends.  A member is a callable with the backend signature — ``fn(
#: binary, va, root, **kwargs) -> str | None`` — keyed by its entry-point
#: name.  Discovered backends are selectable by name but never join the
#: ``BACKENDS`` auto-probe order (that is a curated built-in list).
DECOMPILER_ENTRY_POINT_GROUP = "rebrew.decompiler_backends"


logger = logging.getLogger(__name__)


def _merge_entry_point_backends() -> tuple[dict[str, Callable[..., str | None]], tuple[str, ...]]:
    """The backend map + auto-probe order: packaged + ``rebrew.decompiler_backends``.

    Merging order: packaged backends first, then entry-point providers in
    discovery order.  An optional registry: a broken or conflicting plugin
    backend is skipped with a warning (backends degrade to the packaged
    set) instead of bricking ``rebrew skeleton --decomp``.

    The second element is the ``--auto`` probe order: the curated packaged
    ``BACKENDS`` plus every plugin backend whose callable carries the
    ``__rebrew_auto_probe__ = True`` marker (a plugin backend may opt into
    auto-probing; without the marker it stays name-selectable only)."""
    from rebrew.registry import (
        entry_point_registrations,
        load_registration_optional,
        merge_into,
    )

    merged = dict(_BACKEND_MAP)
    auto_probe: list[str] = []
    for reg in entry_point_registrations(DECOMPILER_ENTRY_POINT_GROUP):
        backend_fn = load_registration_optional(reg, logger)
        if backend_fn is None:
            continue
        if not callable(backend_fn):
            logger.warning(
                "skipping %s registration %r: expected a callable backend, got %s",
                reg.group,
                reg.name,
                type(backend_fn).__name__,
            )
            continue
        try:
            merge_into(merged, reg.name, backend_fn, reg.origin, group=reg.group)
        except RegistryError as exc:
            logger.warning("skipping %s registration %r: %s", reg.group, reg.name, exc)
            continue
        if getattr(backend_fn, "__rebrew_auto_probe__", False):
            auto_probe.append(reg.name)
    return merged, (*BACKENDS, *auto_probe)


_BACKEND_MAP, _AUTO_PROBE_BACKENDS = _merge_entry_point_backends()


def refresh_backends() -> dict[str, Callable[..., str | None]]:
    """Re-run discovery and refresh the :data:`_BACKEND_MAP` snapshot.

    Long-lived processes can pick up decompiler backends installed after
    startup without a restart."""
    global _BACKEND_MAP, _AUTO_PROBE_BACKENDS

    _BACKEND_MAP, _AUTO_PROBE_BACKENDS = _merge_entry_point_backends()
    return _BACKEND_MAP


def fetch_decompilation(
    backend: str,
    binary_path: Path,
    va: int,
    root: Path,
    *,
    endpoint: str | None = None,
    program_path: str | None = None,
) -> tuple[str | None, str]:
    """Fetch pseudo-C decompilation from the specified backend.

    Args:
        backend: One of ``"r2ghidra"``, ``"r2dec"``, ``"ghidra"``, or ``"auto"``.
        binary_path: Absolute path to the target binary.
        va: Virtual address of the function.
        root: Project root directory.
        endpoint: ReVa MCP endpoint URL (used by ``ghidra`` backend only).
        program_path: Ghidra project path for the binary within ReVa MCP.

    Returns:
        A tuple of ``(decompiled_code, backend_name)`` where backend_name is
        the name of the backend that produced the output (useful for ``auto``).
        If decompilation failed, ``(None, backend_name)`` is returned — where
        backend_name is ``"auto"`` when no auto-mode backend succeeded, or
        the requested backend name when a specific backend was requested.

    """
    if backend == "auto":
        for name in _AUTO_PROBE_BACKENDS:
            fn = _BACKEND_MAP[name]
            try:
                result = fn(
                    binary_path, va, root=root, endpoint=endpoint, program_path=program_path
                )
            except Exception:
                # A raising backend must not abort the probe — degrade to
                # the next one (a plugin backend is optional; the packaged
                # backends return None on failure).
                logger.debug(
                    "auto-probe backend %r raised for %s", name, binary_path, exc_info=True
                )
                result = None
            if result:
                return result, name
        return None, "auto"

    backend_fn = _BACKEND_MAP.get(backend)
    if backend_fn is None:
        print(
            f"decompiler: unknown backend '{backend}'. Available: {', '.join(_BACKEND_MAP)}, auto",
            file=sys.stderr,
        )
        return None, backend

    return (
        backend_fn(binary_path, va, root=root, endpoint=endpoint, program_path=program_path),
        backend,
    )
