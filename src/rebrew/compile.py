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
from rebrew.toolchain import TOOLCHAINS, ToolchainError, ToolchainSpec, run_toolchain
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
    if not cmd_parts:
        # Docker-only configs (empty host command; the image is the
        # compiler) — nothing to resolve.
        return []

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


def _is_vendored_toolchain_tree(p: Path) -> bool:
    """True when *p* lives under the repo's vendored ``toolchain/`` dir.

    Those trees are baked into the docker images byte-identical, so the
    container needs no bind mount for them — CL/wcc resolve their own
    includes inside the image."""
    root = Path(__file__).resolve().parents[2] / "toolchain"
    try:
        p.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _docker_include_rewrite(
    flags: list[str], workdir: Path
) -> tuple[list[str], list[tuple[str, str]]]:
    """Rewrite /I and -I flags for a docker container invocation.

    The container only sees the workdir (mounted at /work) plus explicit
    bind mounts.  Include dirs under the workdir become relative paths
    (they resolve inside /work).  Absolute host dirs are bind-mounted at
    their **absolute host path** (same-path mount) and the flag is left
    untouched: a relative ``#include "../../x.h"`` then resolves exactly
    as it does on the host (wine's Z: mapping did this implicitly) — a
    container-root mount (``/incN``) would let ``../..`` escape to ``/``.
    Returns ``(rewritten_flags, mounts)``."""
    mounts: list[tuple[str, str]] = []
    out: list[str] = []
    for flag in flags:
        if flag.startswith(("/I", "-I")) and len(flag) > 2:
            d = flag[2:].strip('"').strip("'")
            p = Path(d)
            try:
                rel = p.resolve().relative_to(workdir.resolve())
                out.append(flag[:2] + str(rel))
            except ValueError:
                host = str(p.resolve())
                if host not in [m[0] for m in mounts]:
                    mounts.append((host, host))
                out.append(flag)
        else:
            out.append(flag)
    return out, mounts





_toolchain_digest_cache: dict[str, str] = {}


def _toolchain_cache_id(spec: "ToolchainSpec") -> str:
    """The compile-cache toolchain id: the image tag, extended with the
    image's content id when docker can report it cheaply (cached per
    process).  Rebuilding an image under a stable tag (`rebrew toolchain
    update --apply`) changes the content id, so objects compiled with the
    OLD image are never served as if they came from the new one.  Falls
    back to the bare tag when docker is unavailable or the inspect fails.
    """
    digest = _toolchain_digest_cache.get(spec.image)
    if digest is None:
        digest = ""
        try:
            r = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", spec.image],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                digest = r.stdout.strip().removeprefix("sha256:")[:12]
        except (OSError, subprocess.TimeoutExpired):
            digest = ""
        _toolchain_digest_cache[spec.image] = digest
    return f"{spec.image}@{digest}" if digest else spec.image


def compile_to_obj(
    cfg: ProjectConfig,
    source_path: str | Path,
    cflags: list[str],
    workdir: str | Path,
    *,
    cache: CompileCache | None = None,
    use_cache: bool = True,
    obj_name: str | None = None,
    toolchain: str | None = None,
    extra_include_dirs: list[str] | None = None,
) -> tuple[str | None, str]:
    """Compile a .c file to .obj through the toolchain's docker image.

    Execution is docker-only for every Windows/DOS toolchain (all MSVC
    versions, Borland, Watcom, the 16-bit DOS compilers): the image
    encapsulates the runtime (wine / DOSBox) and the host never calls
    CL.EXE / DCC.EXE / TCC.EXE / bcc32.exe directly — there is no host
    wine/wibo/dosbox fallback.  Native-Linux toolchains without an image
    (gcc-pe, watcom16 wcc) run through the standardized native backend.

    The source file is copied into ``workdir`` (mounted at /work in the
    container).  Relative /I flags are rewritten to container paths;
    absolute host include dirs are bind-mounted at /inc<N>.

    When *use_cache* is ``True`` (the default), a persistent disk cache is
    consulted before invoking the compiler subprocess.  On cache hit the
    ``.obj`` bytes are written directly to *workdir*, skipping the docker
    startup overhead entirely.

    Args:
        cfg: ProjectConfig with compiler settings.
        source_path: Path to the .c source file.
        cflags: List of compiler flag strings (e.g. ["/O2", "/Gd"]).
        workdir: Working directory for compilation (mounted at /work).
        cache: Explicit ``CompileCache`` instance to use.  When ``None``
            and *use_cache* is True, a shared instance is obtained
            automatically from the project root.
        use_cache: Set to ``False`` to bypass the cache entirely.
        toolchain: Per-function toolchain override (metadata TOOLCHAIN) —
            compile with THAT toolchain's docker image.
        extra_include_dirs: Additional absolute include dirs (e.g. the GA/
            diff source's parent, for relative #include resolution) —
            same-path mounted into the container like the other /I dirs.

    Returns:
        (obj_path, error_msg) — obj_path is ``None`` on failure;
        error_msg is an empty string on success."""
    source_path = Path(source_path)
    workdir = Path(workdir)

    src_name = source_path.name
    if src_name.startswith(("@", "-")):
        src_name = "./" + src_name
    local_src = workdir / src_name

    obj_name = obj_name or (source_path.stem + ".obj")
    if obj_name != Path(obj_name).name:
        # A separator would write the object outside the workdir (and the
        # docker mount) — reject it instead of silently losing the output.
        return None, f"obj_name must be a plain filename, got {obj_name!r}"
    inc_path = str(cfg.compiler_includes)
    profile = getattr(cfg, "compiler_profile", "")
    # Per-function toolchain override (metadata TOOLCHAIN, e.g. "msvc5"):
    # compile with THAT toolchain's image.  Every compile runs through the
    # standardized runner — there is no host wine path.
    tc_spec = None
    if toolchain:
        tc_spec = TOOLCHAINS.get(toolchain)
        if tc_spec is None or (tc_spec.image is None and tc_spec.runtime != "native"):
            return None, (
                f"per-function toolchain {toolchain!r} has no docker image — "
                "all compiles run through their docker images; "
                f"run `rebrew toolchain build {toolchain}` first"
            )
    spec = tc_spec if tc_spec is not None else (TOOLCHAINS.get(profile) if profile else None)

    base_flags = safe_shlex_split(cfg.base_cflags)
    use_timeout = cfg.compile_timeout

    src_parent = source_path.resolve().parent

    base_flags = _resolve_include_flags(base_flags, src_parent, cfg.root)
    resolved_cflags = _resolve_include_flags(cflags, src_parent, cfg.root)
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
        source_content = source_path.read_bytes().decode("utf-8", errors="surrogateescape")
        if spec is not None and spec.image is not None:
            toolchain_id = _toolchain_cache_id(spec)
        else:
            toolchain_id = " ".join(resolve_cl_command(cfg))
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

    # The compiler is the only consumer of the workdir source copy, so it
    # is made here (miss path only) — a cache hit above never needs it.
    # A source already inside the workdir (compile in place) is not copied:
    # copy2 would fail with "same file".  The docker mount / workdir then
    # serves the source directly.
    try:
        if local_src.resolve() != source_path.resolve():
            shutil.copy2(source_path, local_src)
    except OSError as e:
        return None, f"Failed to copy source into workdir: {e}"

    if spec is not None and (spec.image is not None or spec.runtime == "native"):
        """The standardized runner: docker images for every Windows/DOS
        toolchain, native execution for Linux compilers without an image
        (gcc-pe, watcom16 wcc).  There is no host wine/dosbox path."""
        mounts: list[tuple[str, str]] = []
        if spec.image is not None:
            # --- docker: rewrite include flags for the container ---
            # The project root is same-path mounted: relative
            # `#include "../.."` paths in a project tree resolve exactly as
            # on the host (the source copy in /work is flat, so only /I
            # flags + the root mount can reach the original tree).
            root_dir = getattr(cfg, "root", None)
            if root_dir is not None:
                root_p = Path(root_dir).resolve()
                if root_p.exists():
                    mounts.append((str(root_p), str(root_p)))
            all_flags, extra_mounts = _docker_include_rewrite(all_flags, workdir)
            mounts += extra_mounts
            # The source's own dir (../../ includes) and any custom include dir
            # outside the vendored toolchain trees are bind-mounted; the
            # toolchain's own include tree ships inside the image (byte-identical
            # to the vendored tree it was built from) and needs no mount.  The
            # 16-bit DOSBox wrappers stage their own include tree — follow the
            # ACTIVE spec (a per-function TOOLCHAIN override may swap in a
            # 16-bit toolchain under a 32-bit project profile).
            if spec.name not in ("msvc1.52", "msvc15", "msvc10", "tc16", "tc20"):
                extra_inc: list[str] = []
                if src_parent.resolve() != workdir.resolve():
                    extra_inc.append(str(src_parent))
                if inc_path and not _is_vendored_toolchain_tree(Path(inc_path)):
                    extra_inc.append(str(inc_path))
                # The GA / diff paths compile from a temp source copy and
                # pass the original source's parent (for relative includes)
                # — mount those dirs too.
                extra_inc.extend(d for d in (extra_include_dirs or []) if d)
                prefix = "/I" if spec.flags_style == "msvc" else "-I"
                for d in extra_inc:
                    rewritten, extra_mounts = _docker_include_rewrite([f"{prefix}{d}"], workdir)
                    mounts += extra_mounts
                    all_flags += rewritten
                # Same-path mounts may repeat across dirs — docker rejects
                # duplicate -v targets.
                mounts = list(dict.fromkeys(mounts))
        if spec.name in ("msvc1.52", "msvc15", "msvc10", "tc16", "tc20"):
            # 16-bit DOSBox wrappers stage their own include tree.
            args = [src_name, *all_flags]
        elif spec.name == "borlandc55":
            # bcc32: `-c` compiles only; the object name follows the source
            # stem (add.c → add.obj), which matches obj_name.
            args = all_flags + ["-c", src_name]
        elif spec.name in ("watcom", "watcom16"):
            args = all_flags + [f"-fo={obj_name}", "-zq", src_name]
        elif spec.flags_style == "posix":
            # Native posix compilers (gcc-pe): -I/-c/-o, no MSVC /Fo.
            inc_flags = [f"-I{inc_path}"] if inc_path else []
            args = all_flags + inc_flags + [f"-I{str(src_parent)}", "-c", "-o", obj_name, src_name]
        else:
            args = all_flags + [f"/Fo{obj_name}", src_name]
        try:
            tr = run_toolchain(spec, args, workdir=workdir, timeout=use_timeout, mounts=mounts)
        except ToolchainError as exc:
            return None, str(exc)
        obj_file = workdir / obj_name
        if spec.name in ("msvc1.52", "msvc15", "msvc10", "tc16", "tc20") and not obj_file.exists():
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
            if not err:
                err = f"compiler produced no object ({obj_name}) and no output"
            return None, err
        if cc is not None and cache_key is not None:
            with contextlib.suppress(OSError):
                cc.put(cache_key, obj_file.read_bytes())
        return str(obj_file), ""

    # Unknown/unregistered profile: nothing to run.  Execution is docker-
    # (or native-runner-)only; a plain command string cannot be exec'd.
    return None, (
        f"profile {profile!r} is not a docker/native toolchain — every compile "
        "runs through the standardized runner; "
        "run `rebrew toolchain list` for the available profiles"
    )


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
    toolchain: str | None = None,
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

    workdir: Path | None = None
    try:
        # A real-disk, container-visible workdir (writable_temp_dir) — the
        # docker runner mounts it at /work, so a system-temp sandbox
        # (tmpfs / docker-invisible under sandboxed environments) would
        # compile an empty dir.  Cleaned up in finally.
        from rebrew.utils import writable_temp_dir

        workdir = writable_temp_dir("rebrew_cmp_")
        obj_path, err = compile_to_obj(
            cfg,
            source_path,
            cflags_list,
            workdir,
            cache=cache,
            use_cache=use_cache,
            toolchain=toolchain,
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
            return classify_compare_result(False, f"EXTRACT_ERROR: {exc}", target_bytes, None, None)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as exc:
        return classify_compare_result(False, f"COMPILE_ERROR: {exc}", target_bytes, None, None)
    finally:
        if workdir is not None:
            with contextlib.suppress(OSError):
                shutil.rmtree(workdir)
