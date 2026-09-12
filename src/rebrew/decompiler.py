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

import atexit
import hashlib
import importlib
import logging
import re
import shutil
import subprocess
import sys
import tempfile
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

#: Per-process rizin/radare2 project dirs, keyed by
#: ``(resolved binary path, tool)``.  The first ``_run_re`` call for a binary
#: pays the full ``aaa`` analysis (the 120s timeout exists for that), then
#: stores the analyzed project ``dir``; later calls reopen the project
#: (``-p``) so analysis runs once per binary per process instead of once per
#: function.  Entries are removed when the project export fails or the tool
#: vanishes, so a later call retries from scratch.
_RE_PROJECT_DIRS: dict[tuple[str, str], str] = {}


def _re_project_key(binary: Path, tool: str) -> tuple[str, str]:
    """Cache key for the session dir: resolved binary path + tool name."""
    try:
        resolved = str(binary.resolve())
    except OSError:
        resolved = str(binary)
    return (resolved, tool)


def _re_analysis_key(tool: str) -> str:
    """Hash of the tool binary, so a tool upgrade invalidates stale projects."""
    exe = shutil.which(tool)
    if exe is None:
        return ""
    try:
        digest = hashlib.sha256(Path(exe).read_bytes()).hexdigest()[:16]
    except OSError:
        return ""
    return digest


def _re_init_project(binary: Path, tool: str, root: Path) -> str | None:
    """Run full ``aaa`` analysis once and persist the project; return its dir."""
    digest = _re_analysis_key(tool)
    try:
        proj_dir = tempfile.mkdtemp(prefix="rebrew_re_")
    except OSError as e:
        warnings.warn(f"{tool} could not create project dir: {e}", stacklevel=3)
        return None
    try:
        result = subprocess.run(
            [
                tool,
                "-q",
                "-c",
                f"aaa; Ps {proj_dir}; q",
                str(binary),
            ],
            capture_output=True,
            text=True,
            cwd=root,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        warnings.warn(f"{tool} timed out analyzing {binary.name}", stacklevel=3)
        shutil.rmtree(proj_dir, ignore_errors=True)
        return None
    except (OSError, subprocess.SubprocessError) as e:
        warnings.warn(f"{tool} failed analyzing {binary.name}: {e}", stacklevel=3)
        shutil.rmtree(proj_dir, ignore_errors=True)
        return None
    if result.returncode != 0:
        shutil.rmtree(proj_dir, ignore_errors=True)
        return None
    try:
        Path(proj_dir, "rebrew_tool.sha256").write_text(f"{tool}\n{digest}\n", encoding="utf-8")
    except OSError:
        shutil.rmtree(proj_dir, ignore_errors=True)
        return None
    return proj_dir


def _re_cached_digest_ok(proj_dir: str, tool: str) -> bool:
    """True when a cached project's recorded tool digest is still current.

    The marker (``rebrew_tool.sha256``) records the tool name + a hash of the
    tool binary; writing it without ever reading it back meant a tool upgrade
    kept serving the old ``aaa`` results.  A missing or single-line marker (an
    older format) is treated as stale.
    """
    try:
        lines = Path(proj_dir, "rebrew_tool.sha256").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    if len(lines) != 2 or lines[0] != tool:
        return False
    return lines[1] == _re_analysis_key(tool)


def _re_cached_project(binary: Path, tool: str, root: Path) -> str | None:
    """Return the analyzed project dir for (*binary*, *tool*), creating it once."""
    key = _re_project_key(binary, tool)
    cached = _RE_PROJECT_DIRS.get(key)
    if cached is not None:
        if _re_cached_digest_ok(cached, tool):
            return cached
        # A tool upgrade invalidates the analysis; remove the old project dir
        # (a full rizin database) instead of orphaning it — only the entries
        # still in the map get cleaned at exit.
        shutil.rmtree(cached, ignore_errors=True)
        del _RE_PROJECT_DIRS[key]
    proj_dir = _re_init_project(binary, tool, root)
    if proj_dir is None:
        return None
    _RE_PROJECT_DIRS[key] = proj_dir
    return proj_dir


def _re_drop_project(binary: Path, tool: str) -> None:
    """Forget the cached project dir (analysis failed — retry fresh next call)."""
    proj_dir = _RE_PROJECT_DIRS.pop(_re_project_key(binary, tool), None)
    if proj_dir is not None:
        # The dir was created by mkdtemp and is not tracked anywhere else once
        # popped, so it must be removed here or it leaks for the process
        # lifetime (every decompile of a failing project would add one).
        shutil.rmtree(proj_dir, ignore_errors=True)


def _clear_re_projects() -> None:
    """Remove every cached rizin/radare2 project dir (test hook + atexit)."""
    for proj_dir in _RE_PROJECT_DIRS.values():
        shutil.rmtree(proj_dir, ignore_errors=True)
    _RE_PROJECT_DIRS.clear()


atexit.register(_clear_re_projects)


def _run_re(binary: Path, va: int, cmd: str, root: Path) -> str | None:
    """Run a radare2/rizin command and return cleaned output.

    Automatically detects whether ``rz`` or ``r2`` is on PATH.
    ``cmd`` must be one of the allowed radare2 commands (pdg, pdd).

    Full ``aaa`` analysis runs once per binary per process (cached project
    dir); each call reopens the analyzed project and only seeks + decompiles,
    so batch decompilation of many functions pays analysis once.
    """
    if cmd not in _ALLOWED_RE_CMDS:
        raise ValueError(f"disallowed radare2 command: {cmd!r}")
    tool = _find_re_tool()
    if tool is None:
        return None
    proj_dir = _re_cached_project(binary, tool, root)
    if proj_dir is None:
        return None
    try:
        result = subprocess.run(
            [tool, "-q", "-p", proj_dir, "-c", f"s 0x{va:08x}; af; {cmd}", str(binary)],
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
    else:
        if result.returncode != 0:
            # The cached project may be stale (tool upgrade, truncated export);
            # drop it so the next call re-analyzes instead of failing forever.
            _re_drop_project(binary, tool)
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


def _kuna_spec_dirs() -> list[Path]:
    """Candidate SLEIGH spec dirs for kuna, best first.

    Kuna resolves specs from ``KUNA_SPECS`` (else ``/specs/``, which rarely
    exists), and the rizin-bundled ``.sla`` files are XML debug format that
    kuna's loader rejects ("Missing SLA format header").  The binary-format
    specs shipped inside pypcode installs work — prefer those, then the
    rizin dir as a fallback.  Only dirs containing ``x86.sla`` qualify so a
    partial tree never shadows a working one.
    """
    candidates = []
    try:
        import pypcode

        candidates.append(Path(pypcode.__file__).parent / "processors/x86/data/languages")
    except ImportError:
        pass
    for uv_tool in ("rebrew", "angr"):
        candidates.append(
            Path.home()
            / ".local/share/uv/tools"
            / uv_tool
            / "lib/python3.13/site-packages/pypcode/processors/x86/data/languages"
        )
        candidates.append(
            Path.home()
            / ".local/share/uv/tools"
            / uv_tool
            / "lib/python3.12/site-packages/pypcode/processors/x86/data/languages"
        )
    candidates.append(Path("/usr/lib/rizin/plugins/rz_ghidra_sleigh"))
    return [d for d in candidates if (d / "x86.sla").is_file()]


def fetch_kuna(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
    """Fetch decompilation from the Kuna decompiler (agent-first Ghidra port).

    Requires the ``kuna`` binary on PATH (github.com/Noelo-Lab/kuna — a
    single Rust binary).  Runs ``kuna decompile <binary> 0x<va> --addr``
    (Kuna's CLI takes an address with ``--addr``) and returns the cleaned C
    printed to stdout.  Returns ``None`` when kuna is unavailable or fails,
    exactly like the other optional backends.

    Kuna reads SLEIGH specs from ``KUNA_SPECS`` (default ``/specs/``); an
    explicit ``KUNA_SPECS`` is honored, otherwise the first working spec dir
    from :func:`_kuna_spec_dirs` is injected so ``--seed-kuna`` works without
    manual env setup.
    """
    if not binary.exists():
        return None
    kuna = shutil.which("kuna")
    if kuna is None:
        return None
    import os

    env = None
    if "KUNA_SPECS" not in os.environ:
        for spec_dir in _kuna_spec_dirs():
            env = {**os.environ, "KUNA_SPECS": str(spec_dir)}
            break
    try:
        result = subprocess.run(
            [kuna, "decompile", str(binary), f"0x{va:x}", "--addr"],
            capture_output=True,
            text=True,
            cwd=root,
            timeout=180,
            env=env,
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


#: Kuna renders every address as a label it never declares: ``s_<hex>`` for a
#: string/rodata base, ``dat_<hex>`` for a data global, ``sub_<hex>`` for a
#: callee.  Without a declaration the seed fails to compile and the GA drops
#: it, so ``--seed-kuna`` silently contributes nothing.
_KUNA_LABEL_RE = re.compile(r"\b((?:s|dat|sub)_[0-9a-f]{6,})\b")
_KUNA_DECL_FOR = {
    "s": "extern char {name}[];",
    "dat": "extern int {name};",
    "sub": "int {name}();",
}
_KUNA_BOOL_RE = re.compile(r"\bbool\b")
_KUNA_BOOL_LITERAL_RE = re.compile(r"\b(true|false)\b")
_KUNA_NULL_RE = re.compile(r"\bNULL\b")

#: Kuna renders a call through a computed function pointer as
#: ``(int)(**(void **)(EXPR))(args)`` — an int cast applied to a dereferenced
#: pointer and then called, which no compiler accepts (and the second ``*``
#: dereferences a ``void *``).  The intended shape is a cast to a function
#: pointer over a single dereference, followed by the call.
_KUNA_INDIRECT_CALL_RE = re.compile(
    r"\(\s*(?P<ret>[A-Za-z_]\w*(?:\s*\*)*)\s*\)\s*"
    r"\(\s*\*\*\(\s*void\s*\*\*\s*\)\s*"
    r"\((?P<expr>(?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)\s*\)\s*\("
)


def _kuna_indirect_calls(source: str) -> str:
    """Rewrite Kuna's indirect-call rendering into a callable cast."""
    return _KUNA_INDIRECT_CALL_RE.sub(
        lambda m: f"(({m.group('ret')} (*)())(*(void **)({m.group('expr')})))( ",
        source,
    )


def _kuna_declarations(source: str) -> list[str]:
    """Declarations for the address labels *source* references.

    Only names with no declaration already present are emitted, so a snippet
    that defines its own label is left alone.
    """
    out: list[str] = []
    for name in sorted(set(_KUNA_LABEL_RE.findall(source))):
        # A declaration needs a type before the name; an assignment like
        # `dat_1003543c = ...` must not be mistaken for one.
        declared = re.search(
            rf"\b(?:extern|static|typedef)\b[^;\n]*\b{re.escape(name)}\b", source
        ) or re.search(
            rf"^[ \t]*(?!(?:return|if|else|while|for|do|switch|goto|case|sizeof|break|continue)\b)"
            rf"(?:[A-Za-z_]\w*[ \t]+)+\**[ \t]*{re.escape(name)}\b",
            source,
            re.MULTILINE,
        )
        if declared:
            continue
        prefix = name.split("_", 1)[0]
        out.append(_KUNA_DECL_FOR[prefix].format(name=name))
    return out


def kuna_seed_source(binary: Path, va: int, root: Path) -> str | None:
    """Fetch Kuna's decompilation of *va* and make it compilable (rebrew fix).

    Two repairs beyond :func:`sanitize_tokens` are needed for Kuna output: its
    address labels (``s_``/``dat_``/``sub_``) must be declared, and its C99-isms
    (``bool``, ``NULL``, ``true``/``false``) must be spelled for msvc6's C89.
    Without them the seed never compiles and is discarded from the GA.

    Returns the fixup'd C — a GA seed candidate — or ``None`` when kuna is
    unavailable, fails, or the output is not valid C.
    """
    raw = fetch_kuna(binary, va, root)
    if not raw:
        return None
    from rebrew.fixup import sanitize_tokens
    from rebrew.llm_seed import valid_c_source

    fixed, _ = sanitize_tokens(raw)
    fixed = _KUNA_BOOL_RE.sub("int", fixed)
    fixed = _KUNA_BOOL_LITERAL_RE.sub(lambda m: "1" if m.group(1) == "true" else "0", fixed)
    fixed = _KUNA_NULL_RE.sub("0", fixed)
    fixed = _kuna_indirect_calls(fixed)
    declarations = _kuna_declarations(fixed)
    if declarations:
        fixed = "\n".join(declarations) + "\n\n" + fixed
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
    arch = getattr(info, "arch", "") or ""
    if arch in ("ppc32", "ppc64"):
        # capstone 5 ships no working PPC engine (it misdecodes `blr`), so
        # there is no disassembler to feed m2c yet (Phase 3).  Fail fast
        # instead of feeding m2c garbage disassembly.
        warnings.warn(
            f"m2c decompilation unsupported for PPC ({arch}): "
            "capstone 5 ships no working PPC engine",
            stacklevel=2,
        )
        return None
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
