"""Unified MSVC compilation helper for rebrew.

Provides a single, consistent interface for compiling C source to .obj files
using MSVC under Wine. All tools (rebrew test, rebrew match, rebrew verify)
use these functions instead of building compile commands independently.

Architecture
~~~~~~~~~~~~
Entry points in order of abstraction:

``resolve_cl_command(cfg)``
    Lowest level — builds the ``["wine", "/path/CL.EXE"]`` prefix list
    from the config's ``compiler_command`` string.

``compile_to_obj(cfg, source_path, cflags, workdir)``
    Mid-level — copies source to a Wine-compatible workdir and produces
    a ``.obj`` file. Returns ``(obj_path, error_msg)``.

``compile_and_compare(cfg, source_path, symbol, target_bytes, cflags)``
    High-level — compile, extract symbol bytes, compare to *target_bytes*,
    and return a :class:`CompareResult`.

``classify_compare_result(matched, msg, target_bytes, obj_bytes, reloc_offsets, inv_reloc_offsets=None)``
    Pure helper — classifies raw comparison outputs into a :class:`CompareResult`
    (status string, match %, delta).  Used internally by ``compile_and_compare``.

:class:`CompareResult`
    Structured return type returned by ``compile_and_compare`` and consumed by
    verify/test tools.  Fields: ``matched``, ``status``, ``match_percent``,
    ``delta``, ``obj_bytes``, ``reloc_offsets``, ``inv_reloc_offsets``, ``message``.

Configuration
~~~~~~~~~~~~~
All functions read from ``cfg`` (a ``ProjectConfig`` instance):

- ``cfg.compiler_command`` — e.g. ``"wine tools/MSVC600/bin/CL.EXE"``
- ``cfg.compiler_includes`` — path to MSVC include directory
- ``cfg.base_cflags`` — always-on flags (e.g. ``/nologo /c /MT``)
- ``cfg.compile_timeout`` — seconds before subprocess is killed
- ``msvc_env_from_config(cfg)`` — environment dict with ``LIB`` / ``INCLUDE`` etc.
"""

import contextlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from rebrew.cli import NEAR_MATCH_THRESHOLD
from rebrew.compile_cache import CompileCache, compile_cache_key, get_compile_cache
from rebrew.config import ProjectConfig
from rebrew.core import msvc_env_from_config, smart_reloc_compare
from rebrew.matcher.parsers import parse_obj_relocs_full, parse_obj_symbol_bytes
from rebrew.utils import safe_shlex_split

# ---------------------------------------------------------------------------
# Shared result type
# ---------------------------------------------------------------------------


@dataclass
class CompareResult:
    """Result of a compile-and-compare operation.

    Returned by :func:`compile_and_compare` and consumed by both
    ``rebrew test`` and ``rebrew verify`` so that status/delta/match_percent
    classification is done in one place rather than duplicated.

    Attributes:
        matched: ``True`` when compiled bytes equal target after reloc masking.
        status: One of ``EXACT``, ``RELOC``, ``NEAR_MATCHING``, ``STUB``,
            ``SIZE_MISMATCH``, ``COMPILE_ERROR``, ``MISSING_SIZE``, ``MISSING_FILE``.
        match_percent: Percentage of bytes that match (0–100).  On mismatch,
            computed as a raw byte-by-byte comparison without reloc masking.
        delta: Absolute byte difference (mismatch count + size delta).
        obj_bytes: Compiled bytes extracted from the ``.obj`` file, or ``None``
            on compile/extract failure.
        reloc_offsets: Relocation start offsets (4-byte spans each),
            or ``None`` on failure.
        inv_reloc_offsets: Invalid/mismatched relocation offsets found during
            comparison (empty list by default).
        message: Human-readable detail string (compiler error, mismatch counts, …).

    """

    matched: bool
    status: str
    match_percent: float
    delta: int
    obj_bytes: bytes | None
    reloc_offsets: list[int] | None
    message: str = ""
    inv_reloc_offsets: list[int] = field(default_factory=list)


def classify_compare_result(
    matched: bool,
    msg: str,
    target_bytes: bytes | None,
    obj_bytes: bytes | None,
    reloc_offsets: list[int] | None,
    inv_reloc_offsets: list[int] | None = None,
    *,
    size_mismatch: bool = False,
) -> CompareResult:
    """Classify a raw compile-and-compare outcome into a :class:`CompareResult`.

    Centralises the EXACT / RELOC / NEAR_MATCHING / STUB / SIZE_MISMATCH /
    COMPILE_ERROR / MISSING_SIZE / MISSING_FILE classification
    and the ``match_percent`` / ``delta`` calculations that were previously
    duplicated in ``test.py`` and ``verify.py``.

    Classification precedence:
    - ``matched=True`` → EXACT (no relocs) or RELOC (with relocs).
    - ``obj_bytes is None`` or ``"COMPILE_ERROR"`` in *msg* → COMPILE_ERROR.
    - ``"MISSING"`` in *msg* → MISSING_SIZE or MISSING_FILE (by substring).
    - ``size_mismatch=True`` or ``"SIZE_MISMATCH"`` in *msg* → SIZE_MISMATCH
      (still reports match% over the common prefix).
    - Otherwise → NEAR_MATCHING or STUB (by match percentage threshold).

    Args:
        matched: Whether the byte comparison succeeded after reloc masking.
        msg: Raw message from the compare step.
        target_bytes: Ground-truth bytes (may be ``None`` on compile failure).
        obj_bytes: Compiled bytes (may be ``None`` on compile failure).
        reloc_offsets: Relocation start offsets.
        inv_reloc_offsets: Invalid relocation offsets (mismatched relocs).
        size_mismatch: True when compiled length differs from target length.

    Returns:
        A fully-populated :class:`CompareResult`.

    """
    inv = inv_reloc_offsets or []
    relocs = reloc_offsets or []

    if matched:
        status = "RELOC" if relocs else "EXACT"
        return CompareResult(
            matched=True,
            status=status,
            match_percent=100.0,
            delta=0,
            obj_bytes=obj_bytes,
            reloc_offsets=relocs,
            message=msg,
            inv_reloc_offsets=inv,
        )

    if "COMPILE_ERROR" in msg or obj_bytes is None:
        return CompareResult(
            matched=False,
            status="COMPILE_ERROR",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message=msg,
        )

    if "MISSING" in msg:
        return CompareResult(
            matched=False,
            status="MISSING_SIZE" if "SIZE" in msg else "MISSING_FILE",
            match_percent=0.0,
            delta=0,
            obj_bytes=obj_bytes,
            reloc_offsets=relocs,
            message=msg,
        )

    # Compute delta and match_percent for partial matches.
    # Use target length as the denominator and mask known relocation
    # slots so size mismatches don't unfairly drop match% below the
    # NEAR_MATCHING threshold (60%) — matches rebrew test's truncation
    # behavior and treats reloc bytes as matches.
    match_percent = 0.0
    delta = 0
    if target_bytes and obj_bytes:
        target_len = len(target_bytes)
        cmp_len = min(target_len, len(obj_bytes))
        t_arr = np.frombuffer(target_bytes[:cmp_len], dtype=np.uint8)
        o_arr = np.frombuffer(obj_bytes[:cmp_len], dtype=np.uint8)
        diff_mask = t_arr != o_arr
        # Mask reloc slots (4-byte windows) as matches so they don't
        # count against match%
        if relocs and cmp_len > 0:
            reloc_mask = np.zeros(cmp_len, dtype=bool)
            for r in relocs:
                if 0 <= r < cmp_len:
                    end = min(r + 4, cmp_len)
                    reloc_mask[r:end] = True
            diff_mask = diff_mask & ~reloc_mask
        mismatches = int(np.count_nonzero(diff_mask))
        # Treat any bytes beyond cmp_len in target as mismatches too
        # (so a short obj is penalized for missing bytes).
        missing = target_len - cmp_len
        match_percent = ((cmp_len - mismatches) / target_len) * 100 if target_len else 0.0
        delta = abs(len(target_bytes) - len(obj_bytes)) + mismatches + missing

    if size_mismatch or "SIZE_MISMATCH" in msg:
        status = "SIZE_MISMATCH"
    elif match_percent >= NEAR_MATCH_THRESHOLD * 100:
        status = "NEAR_MATCHING"
    else:
        status = "STUB"

    return CompareResult(
        matched=False,
        status=status,
        match_percent=match_percent,
        delta=delta,
        obj_bytes=obj_bytes,
        reloc_offsets=relocs,
        message=msg,
        inv_reloc_offsets=inv,
    )


# ---------------------------------------------------------------------------
# Command resolution
# ---------------------------------------------------------------------------

_WINE_NOISE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^wine: .*\n?", re.MULTILINE),
    re.compile(r"^[0-9a-f]+:err:.*\n?", re.MULTILINE),
    re.compile(r"^[0-9a-f]+:fixme:.*\n?", re.MULTILINE),
    re.compile(r"^[0-9a-f]+:warn:.*\n?", re.MULTILINE),
    re.compile(r"^Application tried to create a window.*\n?", re.MULTILINE),
    re.compile(r"^Fontconfig.*\n?", re.MULTILINE),
    re.compile(r"^wineserver:.*\n?", re.MULTILINE),
    re.compile(r"^Could not find Wine Gecko.*\n?", re.MULTILINE),
    re.compile(r"^err:.*\n?", re.MULTILINE),
]


def filter_wine_stderr(text: str) -> str:
    """Strip Wine/wibo diagnostic noise from compiler stderr output.

    Removes ``wine:``, ``err:``, ``fixme:``, ``warn:``, ``wineserver:``,
    Fontconfig, and Gecko warning lines that obscure actual compiler errors.
    """
    for pat in _WINE_NOISE_PATTERNS:
        text = pat.sub("", text)
    return text.strip()


def resolve_cl_command(cfg: ProjectConfig) -> list[str]:
    """Build the base CL.EXE command list from config.

    Handles both runner-prefixed (``cfg.compiler_runner``) and bare ``cl.exe``
    formats.  If the runner appears as the first element of
    ``cfg.compiler_command``, it is stripped and re-prepended to avoid
    duplication.  Relative compiler paths are resolved against ``cfg.root``.

    Returns:
        List of command parts, e.g. ``["wine", "/abs/path/CL.EXE"]``.

    """
    cmd_parts = safe_shlex_split(cfg.compiler_command)

    runner = str(getattr(cfg, "compiler_runner", "")).strip()
    if runner and cmd_parts and cmd_parts[0].lower() == runner.lower() and len(cmd_parts) > 1:
        cmd_parts = cmd_parts[1:]
    if not runner and cmd_parts and cmd_parts[0] in {"wine", "wibo"} and len(cmd_parts) > 1:
        runner = cmd_parts[0]
        cmd_parts = cmd_parts[1:]

    cl_rel = Path(cmd_parts[0]) if cmd_parts else Path("CL.EXE")
    cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
    command = [cl_abs, *cmd_parts[1:]]
    if runner:
        return [runner, *command]
    return command


def resolve_compiler_env(
    cfg: ProjectConfig,
) -> tuple[str, str, dict[str, str] | None, CompileCache | None]:
    """Resolve compiler command, include dir, MSVC env, and compile cache from config.

    Returns ``(cl_cmd, inc_dir, msvc_env, compile_cache)`` — the four values
    typically needed for compilation workflows.

    Args:
        cfg: ProjectConfig instance from the project root.

    Returns:
        Tuple of (cl_cmd, inc_dir, msvc_env, compile_cache) where compile_cache
        may be None if the cache database cannot be opened.

    """
    cl_parts = safe_shlex_split(cfg.compiler_command)
    cl_res: list[str] = []
    for part in cl_parts:
        p = cfg.root / part
        cl_res.append(str(p) if p.exists() else part)
    cl_cmd = " ".join(cl_res)
    if not cl_cmd:
        cl_cmd = " ".join(str(p) for p in resolve_cl_command(cfg))

    inc_dir = str(cfg.compiler_includes)
    inc_path = cfg.root / inc_dir
    if inc_path.exists():
        inc_dir = str(inc_path)

    env = msvc_env_from_config(cfg)

    cc: CompileCache | None = None
    with contextlib.suppress(OSError):
        cc = get_compile_cache(cfg.root)

    return cl_cmd, inc_dir, env, cc


# ---------------------------------------------------------------------------
# Object file compilation
# ---------------------------------------------------------------------------


def _resolve_include_flags(flags: list[str], src_parent: Path, cfg_root: Path) -> list[str]:
    """Resolve relative /I include paths against src_parent then cfg_root.

    The source file is copied into a Wine-compatible workdir, so relative /I
    paths must be made absolute before passing to the compiler.
    """
    resolved: list[str] = []
    for flag in flags:
        if flag.startswith(("/I", "-I")):
            prefix = flag[:2]
            inc_dir = flag[2:].strip('"').strip("'")
            p = Path(inc_dir)
            if not p.is_absolute():
                from_src = (src_parent / p).resolve()
                from_root = (cfg_root / p).resolve()
                if from_src.is_dir():
                    resolved.append(f"{prefix}{from_src}")
                elif from_root.is_dir():
                    resolved.append(f"{prefix}{from_root}")
                else:
                    resolved.append(flag)
            else:
                resolved.append(flag)
        else:
            resolved.append(flag)
    return resolved


def compile_to_obj(
    cfg: ProjectConfig,
    source_path: str | Path,
    cflags: list[str],
    workdir: str | Path,
    *,
    cache: CompileCache | None = None,
    use_cache: bool = True,
) -> tuple[str | None, str]:
    """Compile a .c file to .obj using the project compiler.

    The source file is copied into ``workdir`` before compilation so that
    Wine's path mapping works correctly (Wine cannot see paths outside of
    its configured drives).

    The timeout is taken from ``cfg.compile_timeout``.

    When *use_cache* is ``True`` (the default), a persistent disk cache is
    consulted before invoking the compiler subprocess.  On cache hit the
    ``.obj`` bytes are written directly to *workdir*, skipping the 200-500 ms
    Wine/wibo startup overhead entirely.

    Args:
        cfg: ProjectConfig with compiler settings.
        source_path: Path to the .c source file.
        cflags: List of compiler flag strings (e.g. ["/O2", "/Gd"]).
        workdir: Working directory for compilation.
        cache: Explicit ``CompileCache`` instance to use.  When ``None``
            and *use_cache* is True, a shared instance is obtained
            automatically from the project root.
        use_cache: Set to ``False`` to bypass the cache entirely.

    Returns:
        (obj_path, error_msg) — obj_path is ``None`` on failure;
        error_msg is an empty string on success.

    """
    source_path = Path(source_path)
    workdir = Path(workdir)

    # Copy source to workdir for Wine compatibility
    src_name = source_path.name
    local_src = workdir / src_name
    try:
        shutil.copy2(source_path, local_src)
    except OSError as e:
        return None, f"Failed to copy source into workdir: {e}"

    obj_name = source_path.stem + ".obj"
    inc_path = str(cfg.compiler_includes)

    # Prepend base_cflags from config (e.g. /nologo /c /MT).
    # This ensures every compile invocation has consistent core flags
    # without requiring callers to remember them.
    base_flags = safe_shlex_split(cfg.base_cflags)
    use_timeout = cfg.compile_timeout

    # Resolve relative /I paths in BOTH base_cflags and user cflags.
    # The source file is copied into a temp workdir for Wine, so any
    # relative /I paths (e.g. -Isrc/NP) would resolve against the wrong
    # directory.  Try the source file's parent first, then the project root.
    src_parent = source_path.resolve().parent

    base_flags = _resolve_include_flags(base_flags, src_parent, cfg.root)
    resolved_cflags = _resolve_include_flags(cflags, src_parent, cfg.root)

    # --- Compile cache lookup ---
    cc = cache
    if cc is None and use_cache:
        try:
            cc = get_compile_cache(cfg.root)
        except OSError:
            cc = None

    cache_key: str | None = None
    if cc is not None:
        source_content = local_src.read_text(encoding="utf-8", errors="replace")
        cl_parts = resolve_cl_command(cfg)
        toolchain_id = " ".join(cl_parts)
        include_dirs = [inc_path, str(src_parent)]
        source_ext = source_path.suffix or ".c"

        cache_key = compile_cache_key(
            source_content=source_content,
            source_filename=src_name,
            cflags=base_flags + resolved_cflags,
            include_dirs=include_dirs,
            toolchain_id=toolchain_id,
            source_ext=source_ext,
        )
        cached_obj = cc.get(cache_key)
        if cached_obj is not None:
            obj_file = workdir / obj_name
            obj_file.write_bytes(cached_obj)
            return str(obj_file), ""

    # --- Cache miss: compile via subprocess ---

    # Build full command: [wine, cl.exe] + base + user flags + includes + output + source file
    # Include the source file's original parent dir so that relative
    # #include "../../..." paths still resolve after the copy.
    cmd = (
        resolve_cl_command(cfg)
        + base_flags
        + resolved_cflags
        + [
            f"/I{inc_path}",
            f"/I{str(src_parent)}",
            f"/Fo{obj_name}",
            src_name,
        ]
    )

    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            cwd=str(workdir),
            env=msvc_env_from_config(cfg),
            timeout=use_timeout,
        )
    except subprocess.TimeoutExpired:
        return None, f"Compile timed out after {use_timeout}s"
    except FileNotFoundError as e:
        return None, f"Compiler not found: {e}"
    except OSError as e:
        return None, f"Failed to run compiler: {e}"

    obj_file = workdir / obj_name
    if r.returncode != 0 or not obj_file.exists():
        err = filter_wine_stderr((r.stdout + b"\n" + r.stderr).decode("utf-8", errors="replace"))
        return None, err

    if cc is not None and cache_key is not None:
        with contextlib.suppress(OSError):
            cc.put(cache_key, obj_file.read_bytes())

    return str(obj_file), ""


# ---------------------------------------------------------------------------
# Compile-and-compare convenience wrapper
# ---------------------------------------------------------------------------


def compile_and_compare(
    cfg: ProjectConfig,
    source_path: str | Path,
    symbol: str,
    target_bytes: bytes,
    cflags: str | list[str],
    *,
    cache: CompileCache | None = None,
    use_cache: bool = True,
    name_to_va: dict[str, int] | None = None,
    section_va: int | None = None,
) -> CompareResult:
    """Compile source, extract COFF symbol, compare against target bytes with reloc masking.

    This is the shared compile→extract→compare flow used by both ``rebrew test``
    and ``rebrew verify``.  Timeout is taken from ``cfg.compile_timeout``.

    Returns a :class:`CompareResult` dataclass.  Use :func:`classify_compare_result`
    if you already have raw ``(matched, msg, obj_bytes, reloc_offsets)`` values.

    Args:
        cfg: ProjectConfig with compiler settings.
        source_path: Path to the .c source file.
        symbol: COFF symbol name to extract (e.g. ``_my_func``).
        target_bytes: Expected bytes from the target binary.
        cflags: Compiler flags (string or list).
        cache: Optional explicit CompileCache instance.
        use_cache: If True, check and populate the compile cache.
        name_to_va: Optional symbol → VA map for DIR32 absolute validation
            (same catalog used by ``rebrew test``).
        section_va: Optional function start VA for precise REL32 validation.

    Returns:
        :class:`CompareResult` with status, metrics, and byte data.

    """
    cflags_list = safe_shlex_split(cflags) if isinstance(cflags, str) else list(cflags)

    try:
        with tempfile.TemporaryDirectory(prefix="rebrew_cmp_") as workdir:
            obj_path, err = compile_to_obj(
                cfg,
                source_path,
                cflags_list,
                workdir,
                cache=cache,
                use_cache=use_cache,
            )
            if obj_path is None:
                return classify_compare_result(
                    False, f"COMPILE_ERROR: {err[:200]}", target_bytes, None, None
                )

            obj_bytes, reloc_dict = parse_obj_symbol_bytes(obj_path, symbol)
            if obj_bytes is None:
                return classify_compare_result(
                    False,
                    f"COMPILE_ERROR: Symbol '{symbol}' not found in .obj",
                    target_bytes,
                    None,
                    None,
                )

            # Prefer typed reloc records when available (DIR32 vs REL32).
            full_relocs = parse_obj_relocs_full(obj_path, symbol)
            coff_relocs = full_relocs if full_relocs else reloc_dict

            size_mismatch = len(obj_bytes) != len(target_bytes)
            orig_obj_len = len(obj_bytes)
            orig_tgt_len = len(target_bytes)
            if size_mismatch:
                # Truncate longer side so smart_reloc_compare can still
                # compute a reloc-aware match% over the common prefix.
                if len(obj_bytes) > len(target_bytes):
                    obj_bytes = obj_bytes[: len(target_bytes)]
                else:
                    target_bytes = target_bytes[: len(obj_bytes)]

            matched, _match_count, _total, relocs, inv_relocs = smart_reloc_compare(
                obj_bytes,
                target_bytes,
                coff_relocs,
                name_to_va=name_to_va,
                section_va=section_va,
            )
            if size_mismatch:
                # Length differs even if the common prefix matches — never EXACT/RELOC.
                return classify_compare_result(
                    False,
                    (
                        f"SIZE_MISMATCH: Size {orig_obj_len}B vs {orig_tgt_len}B "
                        f"({_total - _match_count} byte diffs in common prefix)"
                    ),
                    target_bytes,
                    obj_bytes,
                    relocs,
                    inv_relocs,
                    size_mismatch=True,
                )
            msg = (
                f"RELOC-NORM MATCH ({len(relocs)} relocs)"
                if (matched and relocs)
                else (
                    "EXACT MATCH"
                    if matched
                    else f"NEAR_MATCHING/STUB: {_total - _match_count} byte diffs"
                )
            )
            return classify_compare_result(
                matched, msg, target_bytes, obj_bytes, relocs, inv_relocs
            )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as exc:
        return classify_compare_result(False, f"COMPILE_ERROR: {exc}", target_bytes, None, None)
