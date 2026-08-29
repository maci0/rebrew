"""decompiler.py - Pluggable decompiler backend for skeleton generation.

Provides a unified interface to fetch pseudo-C decompilation from multiple
backends (r2ghidra/rz-ghidra, r2dec/rz-dec, Ghidra via ReVa MCP, and m2c for
MIPS/PPC/ARM/SH targets).  Used by rebrew skeleton when the ``--decomp``
flag is set.

Both radare2 (``r2``) and rizin (``rz``) are supported transparently —
the first one found on PATH is used.  The ``ghidra`` backend connects to a
running Ghidra instance through the ReVa MCP bridge.  The ``m2c`` backend
decompiles console-era MIPS/PPC/ARM/SH assembly (optional dependency, see
:func:`fetch_m2c`).

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
# kuna (the agent-first Ghidra-port decompiler) is probed before m2c; m2c is
# last — an optional dependency that only serves MIPS/PPC/ARM/SH binaries
# (it degrades to None fast on x86 or when not installed).
BACKENDS = ("r2ghidra", "r2dec", "kuna", "m2c")

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


# ---------------------------------------------------------------------------
# m2c backend (multi-arch P2) — MIPS/PPC/ARM/SH decompilation
# ---------------------------------------------------------------------------

#: m2c (github.com/matt-kempster/m2c) decompiles GNU-as assembly into C that
#: byte-matches the original compiler (IDO for N64, MWCC for GC/Wii).  It is
#: installed from git, not PyPI (``pip install "m2c @ git+..."``) — hence the
#: ``find_spec`` guard below rather than a hard dependency.
_M2C_RUN_CMD = "from m2c.main import main; main()"

#: m2c ``--target`` per rebrew arch.  PPC in m2c is always big-endian;
#: MIPS big-endian is IDO by default (little-endian MIPS — PlayStation — is
#: selected from the binary's own endianness in :func:`_m2c_target`).
_M2C_TARGETS: dict[str, str] = {
    "mips64": "mipsee-gcc-c",  # m2c's only 64-bit MIPS target (eabi64, LE)
    "ppc32": "ppc-mwcc-c",
    "ppc64": "ppc-mwcc-c",
    "arm32": "arm-gcc-c",
    "sh2": "sh2-gcc-c",
}

#: Call mnemonics whose target operand is an immediate address.  Branch/jump
#: mnemonics are caught generically via the capstone ``CS_GRP_JUMP`` group
#: (universal across arches); calls are NOT in that group on every arch
#: (MIPS ``jal`` is group 137, not ``CS_GRP_CALL``=2 — that id is x86-only),
#: so they are listed here per-arch-invariant.  Register-indirect calls
#: (``jalr $t9``, ``blr``, ...) have no immediate operand and are skipped by
#: the operand scan regardless.
_M2C_CALL_MNEMONICS = frozenset({"jal", "jalrc", "bl", "blx", "bsr", "jsr", "bcl", "bctrl"})


def _m2c_target(info: Any) -> str | None:
    """m2c ``--target`` string for the binary's arch/endianness, or ``None``.

    ``None`` means m2c has no target for the arch (x86 — use r2ghidra/kuna).
    """
    arch = getattr(info, "arch", "") or ""
    if arch == "mips32":
        if getattr(info, "endian", "") == "little":
            return "mipsel-gcc-c"
        return "mips-ido-c"
    return _M2C_TARGETS.get(arch)


def _m2c_fn_name(va: int) -> str:
    """The ``func_<hex>`` label used for the function (matches decomp.me)."""
    return f"func_{va:x}"


def _m2c_is_ctrl_flow(insn: Any) -> bool:
    """True for branch/jump/call instructions (those with a target operand).

    Branches/jumps carry the universal ``CS_GRP_JUMP`` group in capstone 5
    (group id 1 on every arch); calls are arch-specific (MIPS ``jal`` is
    group 137, not ``CS_GRP_CALL``=2), so their mnemonics are listed in
    :data:`_M2C_CALL_MNEMONICS`.
    """
    return bool(insn.group(1)) or insn.mnemonic in _M2C_CALL_MNEMONICS


def _render_m2c_asm(info: Any, va: int, raw: bytes) -> str | None:
    """Render a function's bytes as m2c's expected GNU-as text.

    Capstone disassembly (arch-aware via
    ``rebrew.binary_loader.capstone_config_for``) is re-rendered with
    symbolic labels: branch/jump/call targets inside the function become
    ``loc_<addr>`` labels, external call/tail targets become ``func_<addr>``
    symbols (m2c emits their prototypes under ``--globals=used``).  MIPS
    functions are prefixed with ``.set noreorder`` so branch delay slots are
    honored.  Returns ``None`` when the region does not cleanly disassemble.
    """
    import capstone

    from rebrew.binary_loader import capstone_config_for

    cs_arch, mode = capstone_config_for(info)
    md = capstone.Cs(cs_arch, mode)
    md.detail = True
    md.skipdata = False
    insns = list(md.disasm(raw, va))
    if not insns:
        return None

    # Collect jump/branch/call targets that land inside the function — those
    # become labels; anything else stays a literal or an external symbol.
    end = va + len(raw)
    targets: set[int] = set()
    for insn in insns:
        if _m2c_is_ctrl_flow(insn):
            for op in insn.operands:
                if op.type == capstone.CS_OP_IMM and va <= op.imm < end:
                    targets.add(op.imm)

    labels = {addr: f"loc_{addr:x}" for addr in sorted(targets)}
    lines: list[str] = []
    if getattr(info, "arch", "") in ("mips32", "mips64"):
        lines += [".set noat", ".set noreorder"]
    lines.append(f"{_m2c_fn_name(va)}:")
    for insn in insns:
        if insn.address in labels:
            lines.append(f"{labels[insn.address]}:")
        ops = insn.op_str
        if _m2c_is_ctrl_flow(insn):
            parts = [part.strip() for part in ops.split(",")]
            for i in range(len(parts) - 1, -1, -1):
                try:
                    val = int(parts[i], 0)
                except ValueError:
                    continue
                if val in labels:
                    parts[i] = labels[val]
                else:
                    # A jump/call to an address outside this function is an
                    # external call or tail target — a bare immediate would
                    # be treated as a literal, so name it like a function.
                    parts[i] = _m2c_fn_name(val)
                break
            ops = ", ".join(parts)
        lines.append(f"    {insn.mnemonic} {ops}".rstrip())
    return "\n".join(lines) + "\n"


def fetch_m2c(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
    """Fetch decompilation from m2c — MIPS/PPC/ARM/SH targets (multi-arch P2).

    The function is disassembled arch-aware, rendered in m2c's GNU-as format
    (``func_<va>``/``loc_<va>`` labels), and piped to m2c on stdin with the
    ``rebrew context`` output as ``--context`` when a ``ctx.c`` exists in the
    project root (run ``rebrew context`` first to populate it).

    Requires the ``m2c`` package — extra ``pip install 'rebrew[m2c]'`` (the
    real decompiler is installed from git, not PyPI).  Returns ``None`` when
    m2c is unavailable, the arch has no m2c target (x86), the function does
    not cleanly disassemble, or m2c fails.  PPC currently also returns
    ``None``: capstone 5 ships no working PPC engine, so there is no
    disassembler to feed m2c yet (Phase 3).
    """
    if not binary.exists():
        return None
    if importlib.util.find_spec("m2c") is None:
        return None
    from rebrew.binary_loader import (
        extract_bytes_at_va,
        function_extent_from_disasm,
        load_binary,
    )

    info = load_binary(binary)
    target = _m2c_target(info)
    if target is None:
        return None
    extent = function_extent_from_disasm(binary, va)
    if not extent:
        return None
    raw = extract_bytes_at_va(info, va, extent)
    if not raw:
        return None
    asm = _render_m2c_asm(info, va, raw)
    if not asm:
        return None

    args = [
        "--target",
        target,
        "--valid-syntax",
        "--no-cache",
        "-f",
        _m2c_fn_name(va),
        "-",
    ]
    ctx = Path(root) / "ctx.c"
    if ctx.exists():
        args += ["--context", str(ctx)]
    try:
        result = subprocess.run(
            [sys.executable, "-c", _M2C_RUN_CMD] + args,
            input=asm,
            capture_output=True,
            text=True,
            cwd=root,
            timeout=180,
        )
        if result.returncode == 0 and result.stdout:
            return _clean_output(result.stdout)
    except subprocess.TimeoutExpired:
        warnings.warn(f"m2c timed out decompiling 0x{va:08x}", stacklevel=2)
    except (OSError, subprocess.SubprocessError) as e:
        warnings.warn(f"m2c failed decompiling 0x{va:08x}: {e}", stacklevel=2)
    return None


# Backends share the (binary, va, root) core plus optional keyword args;
# fetch_ghidra ignores root (the MCP server holds its own project).
_BACKEND_MAP: dict[str, Callable[..., str | None]] = {
    "r2ghidra": fetch_r2ghidra,
    "r2dec": fetch_r2dec,
    "ghidra": fetch_ghidra,
    "kuna": fetch_kuna,
    "m2c": fetch_m2c,
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
