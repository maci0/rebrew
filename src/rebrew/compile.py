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

- ``cfg.compiler_command`` — e.g. ``"wine toolchain/msvc/6.0-win32/bin/CL.EXE"``
- ``cfg.compiler_includes`` — path to MSVC include directory
- ``cfg.base_cflags`` — always-on flags (e.g. ``/nologo /c /MT``)
- ``cfg.compile_timeout`` — seconds before subprocess is killed
- ``msvc_env_from_config(cfg)`` — environment dict with ``LIB`` / ``INCLUDE`` etc.
"""

import contextlib
import os
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
from rebrew.core import (
    build_iat_region,
    msvc_env_from_config,
    resolve_runner_path,
    smart_reloc_compare,
)
from rebrew.headless import ensure_xvfb
from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
from rebrew.toolchain import TOOLCHAINS, ToolchainError, run_toolchain
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
        full_obj_size: Full compiled ``.obj`` size when ``obj_bytes`` was
            truncated to the target length for comparison (SIZE_MISMATCH
            path), else ``None``.  ``rebrew test --fix-size`` uses this to
            correct a stale SIZE annotation with the definitive compiled
            size instead of re-deriving it by hand.
        full_obj_bytes: Full compiled ``.obj`` bytes (untruncated) on the
            SIZE_MISMATCH path, else ``None``.  Let's ``--fix-size`` verify
            the bytes beyond the annotated slice before declaring the SIZE
            annotation stale — a false fix would otherwise write a size
            that hides unreproduced code.
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
    full_obj_size: int | None = None
    full_obj_bytes: bytes | None = None
    #: Number of differing disassembly lines between the compiled and target
    #: bytes (``None`` when not computed).  Populated by ``rebrew verify`` for
    #: unmatched functions so the recoverage-consumed ``verify_results``
    #: ``diff_lines`` column carries real data instead of NULL (db-review F2).
    diff_lines: int | None = None


def classify_compare_result(
    matched: bool,
    msg: str,
    target_bytes: bytes | None,
    obj_bytes: bytes | None,
    reloc_offsets: list[int] | None,
    inv_reloc_offsets: list[int] | None = None,
    *,
    size_mismatch: bool = False,
    size_delta: int = 0,
    full_obj_size: int | None = None,
    full_obj_bytes: bytes | None = None,
    full_target_size: int | None = None,
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
        size_delta: Pre-truncation length difference (see the SIZE_MISMATCH
            caller in :func:`_extract_and_compare`).
        full_obj_size: Full compiled ``.obj`` size before truncation, when
            the SIZE_MISMATCH caller truncated ``obj_bytes`` for comparison.

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
            # Thread through for --fix-size reclassification: the caller
            # rebuilds a matched result from a truncated SIZE_MISMATCH view
            # and needs the full size preserved for reporting.
            full_obj_size=full_obj_size,
            full_obj_bytes=full_obj_bytes,
        )

    if "EXTRACT_ERROR" in msg:
        return CompareResult(
            matched=False,
            status="EXTRACT_ERROR",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message=msg,
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
        # abs(len diff) already counts every missing/extra byte — adding
        # `missing` again would double-count short objects (skewing delta,
        # and with it verify/status/todo metrics).
        match_percent = ((cmp_len - mismatches) / target_len) * 100 if target_len else 0.0
        # abs(len diff) counts every missing/extra byte at THIS call's lengths.
        # The SIZE_MISMATCH caller truncates both sides before classifying, so
        # it passes the pre-truncation length difference via size_delta —
        # otherwise a 10B vs 5B mismatch with 1 byte diff would report
        # delta=1 instead of 6, skewing verify/todo regression metrics.
        delta = abs(len(target_bytes) - len(obj_bytes)) + mismatches + size_delta

    if size_mismatch or "SIZE_MISMATCH" in msg:
        # A minimal candidate against a much larger target is an
        # UNIMPLEMENTED stub (a freshly generated skeleton's default
        # `return 0` body, ~3-8 bytes), not a size mismatch to puzzle over
        # — name it STUB with a clear message instead of a bare
        # SIZE_MISMATCH.  Genuinely tiny functions match byte-for-byte and
        # never reach here (EXACT/RELOC above).  The caller truncates the
        # LONGER side before classifying, so the original lengths arrive via
        # full_obj_size / full_target_size.
        orig_cand = full_obj_size if full_obj_size is not None else len(obj_bytes or b"")
        if full_target_size is not None:
            orig_tgt = full_target_size
        elif size_delta > 0:
            # Candidate was the shorter side → target was truncated.
            orig_tgt = len(target_bytes or b"") + size_delta
        else:
            orig_tgt = len(target_bytes or b"")
        if (
            obj_bytes is not None
            and orig_cand <= _STUB_BODY_MAX_BYTES
            and orig_tgt >= _STUB_TARGET_MIN_BYTES
            and orig_tgt > orig_cand * 2
        ):
            status = "STUB"
            msg = (
                f"candidate is a minimal {orig_cand}B stub body — the target is "
                f"{orig_tgt}B; the skeleton default was never implemented"
            )
        else:
            status = "SIZE_MISMATCH"
    elif match_percent >= NEAR_MATCH_THRESHOLD * 100:
        status = "NEAR_MATCHING"
        if msg and not msg.startswith("NEAR_MATCHING"):
            msg = f"{msg} - run 'rebrew match <file> --flag-sweep-only' to try flag variants"
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
        full_obj_size=full_obj_size,
        full_obj_bytes=full_obj_bytes,
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
    # Display/GL init noise from headless Xvfb compiles (no [hex]: prefix —
    # emitted by Mesa/wine's EGL probe when DRI3 is unavailable).  These
    # lines drown the real compiler error, e.g. "libEGL warning: DRI3 error:
    # Could not get DRI3 device" + "Ensure your X server supports DRI3...".
    re.compile(r"^libEGL warning:.*\n?", re.MULTILINE),
    re.compile(r"^libGL warning:.*\n?", re.MULTILINE),
    re.compile(r"^MESA:.*\n?", re.MULTILINE),
]


def filter_wine_stderr(text: str) -> str:
    """Strip Wine/wibo diagnostic noise from compiler stderr output.

    Removes ``wine:``, ``err:``, ``fixme:``, ``warn:``, ``wineserver:``,
    Fontconfig, and Gecko warning lines that obscure actual compiler errors.
    """
    for pat in _WINE_NOISE_PATTERNS:
        text = pat.sub("", text)
    return text.strip()


#: A candidate body this small against a much larger target is an
#: unimplemented skeleton stub (see classify_compare_result).
_STUB_BODY_MAX_BYTES = 8
_STUB_TARGET_MIN_BYTES = 12


# Wine prefixes configured with "Emulate a virtual desktop" (winecfg) pop a
# window on every compiler invocation, and bare `wine` fails outright under
# CI with no DISPLAY.  We point wine at a persistent Xvfb (headless.py) —
# invisible AND cheap: xvfb-run's wrapper costs ~3 s per invocation, a
# persistent server pays ~200 ms once and amortizes over a whole batch.
_XVFB_SERVER_ARGS = "-screen 0 1280x1024x24"


def maybe_headless_wine(
    cmd: list[str], env: dict[str, str] | None
) -> tuple[list[str], dict[str, str] | None]:
    """Run a ``wine`` invocation headlessly (no window, works without DISPLAY).

    When the first command token is ``wine`` (or a path to it), the
    ``DISPLAY`` env is pointed at a persistent ``Xvfb`` (see
    ``rebrew.headless.ensure_xvfb``) so the compile runs on an invisible
    virtual display.  ``wibo`` is already headless and is left untouched.
    Set ``REBREW_WINE_HEADLESS=0`` in the environment to force bare wine
    (e.g. when you genuinely want the window).

    Falls back to wrapping the command in ``xvfb-run`` when no ``Xvfb``
    binary is available, then to bare wine when neither exists.

    Returns the (possibly wrapped) command and the env dict (a copy with
    ``DISPLAY`` set when headless was applied).
    """
    if not cmd or Path(cmd[0]).name != "wine":
        return cmd, env
    if env is not None and env.get("REBREW_WINE_HEADLESS", "") == "0":
        return cmd, env
    display = ensure_xvfb()
    if display is not None:
        env = dict(env) if env is not None else {**os.environ}
        env["DISPLAY"] = display
        return cmd, env
    if shutil.which("xvfb-run") is not None:
        return ["xvfb-run", "-a", "-s", _XVFB_SERVER_ARGS, *cmd], env
    return cmd, env


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
    if (
        cmd_parts
        and not cl_rel.is_absolute()
        and "/" not in cmd_parts[0]
        and "\\" not in cmd_parts[0]
        and not runner
    ):
        # Bare executable name (e.g. a gcc-pe/mingw toolchain on PATH) —
        # resolve via PATH instead of the project root.
        found = shutil.which(cmd_parts[0])
        cl_abs = found or str(cfg.root / cl_rel)
    else:
        cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
        if not cl_rel.is_absolute():
            cl_path = Path(cl_abs)
            if not cl_path.exists():
                # Project-local tools/ absent (no --link-tools-from)?  Fall
                # back to the rebrew install's own vendored tree so fresh
                # projects compile out of the box.
                from rebrew.utils import find_install_tool

                alt = find_install_tool(cl_rel)
                if alt is not None:
                    cl_abs = str(alt)
    command = [cl_abs, *cmd_parts[1:]]
    if runner:
        return [resolve_runner_path(runner, cfg.root), *command]
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
    cl_cmd = " ".join(resolve_cl_command(cfg))

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


def _dedupe_flags(flags: list[str]) -> list[str]:
    """Drop duplicate flags, keeping first occurrence (identical flags are
    interchangeable, so this is semantics-preserving).

    Base + per-function cflags often repeat (``/O2 /Gd /O2 /Gd /Oy-``) —
    dedup keeps compile lines readable without changing the result.
    """
    seen: set[str] = set()
    out: list[str] = []
    for flag in flags:
        if flag not in seen:
            seen.add(flag)
            out.append(flag)
    return out


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
    obj_name: str | None = None,
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

    # Workdir source name for Wine compatibility (a copy of the source is
    # only needed when the compiler subprocess actually runs — a cache hit
    # skips the copy entirely, saving one write + one read-back per warm
    # compile; the cache key is computed from the original file, whose
    # bytes are identical to the copy).
    src_name = source_path.name
    if src_name.startswith(("@", "-")):
        # MSVC interprets a leading '@' as a response file and a leading '-'
        # as an option — a source named e.g. "@x.c" would have its contents
        # parsed as compiler directives.  Prefix './' to make it a plain
        # filename.
        src_name = "./" + src_name
    local_src = workdir / src_name

    obj_name = obj_name or (source_path.stem + ".obj")
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

    # Dedupe identical flags (base + per-function cflags often repeat e.g.
    # /O2 /Gd).  Identical flags are interchangeable, so keeping the first
    # occurrence is semantics-preserving and keeps compile lines readable.
    all_flags = _dedupe_flags(base_flags + resolved_cflags)

    # --- Compile cache lookup ---
    cc = cache
    if cc is None and use_cache:
        try:
            cc = get_compile_cache(cfg.root)
        except OSError:
            cc = None

    cache_key: str | None = None
    if cc is not None:
        # Hash the raw bytes (via surrogateescape, which is lossless) — a
        # plain utf-8/errors=replace decode would give two sources differing
        # only in legacy-encoded bytes the same cache key.  Read from the
        # ORIGINAL source (not the workdir copy): on a cache hit no copy has
        # been made, and copy2 is byte-identical anyway.
        source_content = source_path.read_bytes().decode("utf-8", errors="surrogateescape")
        cl_parts = resolve_cl_command(cfg)
        toolchain_id = " ".join(cl_parts)
        include_dirs = [inc_path, str(src_parent)]
        source_ext = source_path.suffix or ".c"

        cache_key = compile_cache_key(
            source_content=source_content,
            source_filename=src_name,
            cflags=all_flags,
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
    # The compiler is the only consumer of the workdir source copy, so it
    # is made here (miss path only) — a cache hit above never needs it.
    try:
        shutil.copy2(source_path, local_src)
    except OSError as e:
        return None, f"Failed to copy source into workdir: {e}"

    # Build full command: [wine, cl.exe] + base + user flags + includes + output + source file
    # Include the source file's original parent dir so that relative
    # #include "../../..." paths still resolve after the copy.
    # POSIX-style compilers (gcc-pe/mingw, clang) use -I/-o/-c; MSVC uses /I//Fo;
    # toolchain-backed profiles (watcom, msvc1.52) go through rebrew.toolchain's
    # standardized runner (docker image or vendored host binary).
    profile = getattr(cfg, "compiler_profile", "")
    # Use the config's single source of truth (ProjectConfig.posix_style) —
    # the old local profile tuple duplicated it, so adding a POSIX profile to
    # one list but not the other silently switched flag routing and broke
    # compiles (config-review F6).
    is_posix_style = bool(getattr(cfg, "posix_style", False))

    # The toolchain-runner profiles.  gcc-pe/msvc6 stay on their
    # specialized posix/msvc paths (well-tested); the abstraction serves
    # them via `rebrew toolchain`.
    if profile in ("watcom", "watcom16", "msvc1.52", "tc16", "tc20", "borlandc55"):
        spec = TOOLCHAINS[profile]
        if profile in ("watcom", "watcom16"):
            inc_flags = [f"-I{inc_path}"] if inc_path else []
            args = (
                all_flags + inc_flags + [f"-I{str(src_parent)}", f"-fo={obj_name}", "-zq", src_name]
            )
        elif profile == "borlandc55":
            # bcc32: `-c` compiles only; the object name follows the source
            # stem (add.c → add.obj), which matches obj_name.  `-o` alone is
            # compile-only in Borland's flag dialect, so the generic posix
            # `-o obj` invocation would misparse obj as an input file.
            inc_flags = [f"-I{inc_path}"] if inc_path else []
            args = all_flags + inc_flags + [f"-I{str(src_parent)}", "-c", src_name]
        elif profile in ("msvc1.52", "tc16", "tc20"):
            # Prefer the docker image (cl16/tcc wrapper) when pulled; fall
            # back to the host DOSBox sandbox.  The 16-bit compilers stage
            # the source under a short 8.3-safe name, so source-name length
            # is not our problem here.
            from rebrew.toolchain import _image_present

            if spec.image is not None and _image_present(spec.image):
                args = [src_name, *all_flags]
            else:
                if profile == "msvc1.52":
                    from rebrew.msvc16 import Msvc16Error
                    from rebrew.msvc16 import compile_c as msvc_compile_c

                    try:
                        res16 = msvc_compile_c(
                            local_src,
                            workdir,
                            # /IC:\INCLUDE — the vendored include tree is
                            # staged as C:\INCLUDE inside the DOSBox sandbox;
                            # the host inc_path would not resolve there.
                            cflags=[*all_flags, "/IC:\\INCLUDE"],
                            timeout=use_timeout,
                        )
                    except Msvc16Error as exc:
                        return None, str(exc)
                else:
                    from rebrew.tc16 import Tc16Error
                    from rebrew.tc16 import compile_c as tc_compile_c

                    try:
                        res_tc = tc_compile_c(
                            local_src,
                            workdir,
                            cflags=all_flags,
                            timeout=use_timeout,
                            version="2.0" if profile == "tc20" else "3.1",
                        )
                    except Tc16Error as exc:
                        return None, str(exc)
                obj_file = (res16 if profile == "msvc1.52" else res_tc).obj_path
                if cc is not None and cache_key is not None:
                    with contextlib.suppress(OSError):
                        cc.put(cache_key, obj_file.read_bytes())
                return str(obj_file), ""
        try:
            tr = run_toolchain(spec, args, workdir=workdir, timeout=use_timeout)
        except ToolchainError as exc:
            return None, str(exc)
        obj_file = workdir / obj_name
        if profile in ("msvc1.52", "tc16", "tc20") and not obj_file.exists():
            # The DOSBox wrappers FAT-uppercase the object (T.OBJ).
            stem = Path(obj_name).stem
            obj_file = next(
                (
                    p
                    for p in workdir.iterdir()
                    if p.suffix.upper() == ".OBJ" and p.stem.upper() == stem.upper()
                ),
                obj_file,
            )
        if tr.returncode != 0 or not obj_file.exists():
            err = (tr.stdout + "\n" + tr.stderr).strip()
            return None, err
        if cc is not None and cache_key is not None:
            with contextlib.suppress(OSError):
                cc.put(cache_key, obj_file.read_bytes())
        return str(obj_file), ""

    if is_posix_style:
        inc_flags = [f"-I{inc_path}"] if inc_path else []
        cmd = (
            resolve_cl_command(cfg)
            + all_flags
            + inc_flags
            + [f"-I{str(src_parent)}", "-c", "-o", obj_name, src_name]
        )
    else:
        cmd = (
            resolve_cl_command(cfg)
            + all_flags
            + [
                f"/I{inc_path}",
                f"/I{str(src_parent)}",
                f"/Fo{obj_name}",
                src_name,
            ]
        )

    env: dict[str, str] | None = msvc_env_from_config(cfg)
    cmd, env = maybe_headless_wine(cmd, env)

    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            cwd=str(workdir),
            env=env,
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


def _extract_and_compare(
    obj_path: str,
    symbol: str,
    target_bytes: bytes,
    *,
    name_to_va: dict[str, int] | None = None,
    section_va: int | None = None,
    iat_region: set[int] | None = None,
) -> CompareResult:
    """Extract *symbol* from a compiled .obj and compare against *target_bytes*.

    Post-compile stage of :func:`compile_and_compare`, isolated so a failure
    here is labeled EXTRACT_ERROR instead of masquerading as a compile error.
    """
    # Single LIEF parse for both the symbol bytes and the typed relocs
    # (previously two lief.COFF.parse calls on the same .obj).
    obj_bytes, reloc_dict, full_relocs = parse_obj_symbol_and_relocs(obj_path, symbol)
    if obj_bytes is None:
        # Post-compile extraction failure: the .obj compiled fine but the
        # symbol is absent (wrong --symbol, optimized-away function).  Must
        # NOT masquerade as COMPILE_ERROR — downstream (rebrew test, verify)
        # would blame the .c source and hard-exit with EXIT_ERROR.
        return classify_compare_result(
            False, f"EXTRACT_ERROR: Symbol '{symbol}' not found in .obj", target_bytes, None, None
        )

    coff_relocs = full_relocs if full_relocs else reloc_dict

    size_mismatch = len(obj_bytes) != len(target_bytes)
    orig_obj_len = len(obj_bytes)
    orig_obj_bytes = obj_bytes  # full bytes — the truncated view loses the tail
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
        iat_region=iat_region,
    )
    if size_mismatch:
        # Length differs even if the common prefix matches — never EXACT/RELOC.
        # The hint uses the VA when known (rebrew diff resolves VAs);
        # otherwise the generic source placeholder.
        va_hint = f"0x{section_va:08x}" if section_va else "<source>"
        return classify_compare_result(
            False,
            (
                f"SIZE_MISMATCH: Size {orig_obj_len}B vs {orig_tgt_len}B "
                f"({_total - _match_count} byte diffs in common prefix) — "
                f"run 'rebrew diff {va_hint}' to see the byte differences"
            ),
            target_bytes,
            obj_bytes,
            relocs,
            inv_relocs,
            size_mismatch=True,
            size_delta=abs(orig_obj_len - orig_tgt_len),
            full_obj_size=orig_obj_len,
            full_obj_bytes=orig_obj_bytes,
            full_target_size=orig_tgt_len,
        )
    msg = (
        f"RELOC-NORM MATCH ({len(relocs)} relocs)"
        if (matched and relocs)
        else (
            "EXACT MATCH" if matched else f"NEAR_MATCHING/STUB: {_total - _match_count} byte diffs"
        )
    )
    return classify_compare_result(matched, msg, target_bytes, obj_bytes, relocs, inv_relocs)


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

            try:
                return _extract_and_compare(
                    obj_path,
                    symbol,
                    target_bytes,
                    name_to_va=name_to_va,
                    section_va=section_va,
                    iat_region=build_iat_region(cfg),
                )
            except (ValueError, OSError) as exc:
                # Post-compile object extraction/compare failure — the source
                # compiled fine, so this is NOT a COMPILE_ERROR.  Label the
                # stage so downstream (todo, verify, GA) does not blame the
                # .c file for a malformed .obj / toolchain issue.
                return classify_compare_result(
                    False, f"EXTRACT_ERROR: {exc}", target_bytes, None, None
                )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as exc:
        return classify_compare_result(False, f"COMPILE_ERROR: {exc}", target_bytes, None, None)
