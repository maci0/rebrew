"""compiler.py – MSVC compilation and Wine execution for GA matching.

Provides build_candidate_obj_only(), build_candidate(), flag_sweep(),
and generate_flag_combinations() for compiling C source with MSVC6 under Wine
and extracting function bytes from the resulting object/executable.
"""

import contextlib
import functools
import itertools
import logging
import math
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path
from typing import Any

from rebrew.compile_cache import CompileCache, compile_cache_key
from rebrew.config import _POSIX_PROFILES
from rebrew.utils import safe_shlex_split

from .core import BuildResult
from .flag_data import (
    BORLAND_FLAGS,
    BORLAND_SWEEP_TIERS,
    COMMON_MSVC_FLAGS,
    MSVC6_FLAGS,
    MSVC152_FLAGS,
    MSVC152_SWEEP_TIERS,
    MSVC_SWEEP_TIERS,
    WATCOM_FLAGS,
    WATCOM_SWEEP_TIERS,
)
from .flags import Checkbox, Flags, FlagSet
from .parsers import extract_function_from_binary, parse_obj_symbol_bytes

log = logging.getLogger(__name__)


def _filter_wine_stderr(text: str) -> str:
    """Filter Wine noise from stderr text (lazy-imported from rebrew.compile).

    Imported lazily because rebrew.compile imports rebrew.core, which imports
    rebrew.matcher — a module-level import here would be circular.
    """
    from rebrew.compile import filter_wine_stderr

    return filter_wine_stderr(text)


def _maybe_headless_wine(
    cmd: list[str], env: dict[str, str] | None
) -> tuple[list[str], dict[str, str] | None]:
    """Wrap a ``wine`` command under xvfb-run (lazy-imported, see above)."""
    from rebrew.compile import maybe_headless_wine

    return maybe_headless_wine(cmd, env)


# Fallback function size (in bytes) when both LIEF symbol table and MAP
# heuristics fail to determine the actual size.  1000 bytes is a conservative
# upper bound that covers most MSVC6 game functions without reading too far
# past the function boundary — excess bytes are trimmed later by
# trim_trailing_padding() in catalog/sections.py.
_DEFAULT_SYMBOL_SIZE = 1000

# Warn when flag sweep produces more than this many combinations
_MAX_SWEEP_COMBOS = 100_000

# Pre-compiled regex for MAP file symbol parsing
_MAP_SYM_RE = re.compile(
    r"^\s*\d+:[0-9a-fA-F]+\s+\S+\s+([0-9a-fA-F]+)",
    re.MULTILINE,
)


@functools.lru_cache(maxsize=256)
def _map_symbol_re(symbol: str) -> re.Pattern[str]:
    """Return a compiled regex for looking up *symbol* in a MAP file."""
    return re.compile(
        r"^\s*\d+:[0-9a-fA-F]+\s+" + re.escape(symbol) + r"\s+([0-9a-fA-F]+)",
        re.MULTILINE,
    )


# Map of profiles → synced Flags lists
_FLAGS_MAP: dict[str, Flags] = {
    "msvc": COMMON_MSVC_FLAGS,
    "msvc7": COMMON_MSVC_FLAGS,
    "msvc6": MSVC6_FLAGS,  # excludes MSVC 7.x+ only flags (/fp:*, /GS-)
    "msvc1.52": MSVC152_FLAGS,
    "watcom": WATCOM_FLAGS,
    "watcom16": WATCOM_FLAGS,  # same wcc flag family (16-bit wcc)
    "tc16": BORLAND_FLAGS,
    "tc20": BORLAND_FLAGS,
    "borlandc55": BORLAND_FLAGS,
}


def _ensure_wine_env(env: dict[str, str] | None, cmd: list[str]) -> dict[str, str]:
    """Return an env dict with WINEDEBUG=-all when running under Wine/wibo.

    If *env* is already provided, returns it unchanged.  Otherwise copies
    ``os.environ`` and suppresses Wine diagnostic noise when the first
    command token is ``wine`` or ``wibo``.
    """
    if env is not None:
        return env
    env = {**os.environ}
    cmd_head = Path(cmd[0]).name.lower() if cmd else ""
    if cmd_head in {"wine", "wibo"}:
        env["WINEDEBUG"] = "-all"
    return env


#: Profiles whose compiler runs ONLY through its docker image.  Derived from
#: the toolchain registry at import time (all specs with an image); the raw
#: subprocess path is reserved for native Linux compilers (gcc-pe).
def _docker_backed_profiles() -> frozenset[str]:
    try:
        from rebrew.toolchain import TOOLCHAINS

        return frozenset(n for n, s in TOOLCHAINS.items() if s.image is not None)
    except Exception:
        return frozenset()


_DOCKER_BACKED_PROFILES = _docker_backed_profiles()


def _compiler_cmd_parts(cl_cmd: str, env: dict[str, str] | None) -> list[str]:

    parts = safe_shlex_split(cl_cmd)
    runner = ""
    if env is not None:
        runner = env.get("REBREW_COMPILER_RUNNER", "").strip()
    if runner and (not parts or parts[0].lower() != runner.lower()):
        parts = [runner, *parts]
    return parts


def _flags_to_axes(flags: Flags, tier_ids: list[str] | None = None) -> list[list[str]]:
    """Convert FlagSet/Checkbox list to list of axes (each axis = list of options).

    FlagSet  → [flag1, flag2, ..., ""]  (mutually exclusive + none)
    Checkbox → [flag, ""]              (on or off)
    """
    axes = []
    for item in flags:
        if tier_ids is not None and item.id not in tier_ids:
            continue
        if isinstance(item, FlagSet):
            axes.append(list(item.flags) + [""])
        elif isinstance(item, Checkbox):
            axes.append([item.flag, ""])
    return axes


def _get_pe_symbol_size(exe_path: Path, symbol: str) -> int | None:
    """Get function size from PE symbol table via LIEF.

    Looks up the symbol in the PE's COFF symbol table and returns the
    distance to the next symbol in the same section. Returns None if
    the symbol cannot be found, the section is unresolvable, or LIEF
    is not available.
    """
    try:
        import lief

        pe = lief.PE.parse(str(exe_path))
        if pe is None:
            return None

        # Find symbol in COFF symbol table (present in debug/MAP-linked PEs)
        target_sym = None
        for sym in pe.symbols:
            if sym.name == symbol:
                target_sym = sym
                break

        if target_sym is None:
            return None

        # Find next symbol in the same section with a higher offset
        section_number = getattr(target_sym, "section_number", None)
        sym_value = target_sym.value
        if section_number is None:
            return None
        next_offset = None
        for sym in pe.symbols:
            if (
                getattr(sym, "section_number", None) == section_number
                and sym.value > sym_value
                and (next_offset is None or sym.value < next_offset)
            ):
                next_offset = sym.value

        if next_offset is not None:
            size = next_offset - sym_value
            if 0 < size <= 10000:
                return int(size)

        return None
    except (ImportError, OSError, AttributeError, ValueError):
        return None


def generate_flag_combinations(tier: str = "targeted", profile: str = "msvc6") -> list[str]:
    """Generate flag combinations for the given compiler profile.

    Args:
        tier: Sweep effort level — "quick", "targeted", "normal", "thorough", or "full".
              Controls how many flag axes are included.
        profile: Compiler profile name — "msvc6", "msvc7", or "msvc".

    """
    # Use synced Flags for this profile, falling back to msvc6
    flags = _FLAGS_MAP.get(profile, _FLAGS_MAP["msvc6"])
    if profile in ("watcom", "watcom16"):
        tiers = WATCOM_SWEEP_TIERS
    elif profile == "msvc1.52":
        tiers = MSVC152_SWEEP_TIERS
    elif profile in ("tc16", "tc20", "borlandc55"):
        tiers = BORLAND_SWEEP_TIERS
    else:
        tiers = MSVC_SWEEP_TIERS
    if tier not in tiers:
        raise ValueError(f"Unknown sweep tier {tier!r}, valid: {list(tiers)}")
    tier_ids = tiers[tier]  # None = all axes
    axes = _flags_to_axes(flags, tier_ids)

    # The Cartesian product of all axes can be enormous (full ≈ 2.5M combos,
    # ~400MB materialized as a set).  Deterministically stride-sample the
    # product stream down to the cap instead of building the whole set first;
    # under the cap the behavior is identical to before (full set + sort).
    total = math.prod(len(a) for a in axes)
    if total > _MAX_SWEEP_COMBOS:
        step = max(1, math.ceil(total / _MAX_SWEEP_COMBOS))
        combos = set()
        for combo in itertools.islice(itertools.product(*axes), None, None, step):
            flags_str = " ".join(f for f in combo if f)
            combos.add(flags_str)
        warnings.warn(
            f"Flag sweep tier '{tier}' produces {total:,} combinations; "
            f"sampling every {step}th combination down to {len(combos):,} "
            f"(memory bound {_MAX_SWEEP_COMBOS:,}). Consider 'quick' or "
            f"'targeted' tier for exhaustive sweeps.",
            stacklevel=2,
        )
    else:
        combos = set()
        for combo in itertools.product(*axes):
            flags_str = " ".join(f for f in combo if f)
            combos.add(flags_str)

    return sorted(combos)


def build_candidate_obj_only(
    source_code: str,
    cl_cmd: str,
    inc_dir: str,
    cflags: str,
    symbol: str,
    env: dict[str, str] | None = None,
    source_ext: str = ".c",
    cache: CompileCache | None = None,
    timeout: int = 60,
    extra_include_dirs: list[str] | None = None,
    posix_style: bool = False,
    profile: str = "",
    cfg: Any = None,
) -> BuildResult:
    """Compile source to .obj and extract symbol bytes (no linking).

    When *cache* is provided, the raw ``.obj`` bytes are cached on disk
    keyed by ``(source_content, source_filename, cflags, include_dirs,
    toolchain_id, source_ext)``.  On cache hit only the fast LIEF symbol
    extraction runs, skipping the 200-500 ms Wine/wibo subprocess entirely.

    Every image-backed profile (all MSVC versions, Watcom, Borland, the
    16-bit DOS compilers) routes through the shared ``compile_to_obj``
    runner (docker image — there is no host wine/dosbox fallback) instead
    of the raw subprocess path.  The raw subprocess path below serves only
    native Linux compilers without an image (gcc-pe and friends).
    """
    if profile in _DOCKER_BACKED_PROFILES:
        if cfg is None:
            from types import SimpleNamespace

            cfg = SimpleNamespace(
                root=Path.cwd(),
                compiler_profile=profile,
                compiler_command=cl_cmd,
                compiler_includes=inc_dir,
                base_cflags="",
                compile_timeout=timeout,
            )
        from rebrew.compile import compile_to_obj

        # The docker workdir must live on a real, container-visible disk:
        # under sandboxed homes the system temp dir is invisible to docker
        # and the bind mount silently loses the source (the image wrapper
        # then reports "no readable source file").  writable_temp_dir
        # prefers the workspace .cache for exactly this reason.
        from rebrew.utils import writable_temp_dir

        base = writable_temp_dir("matcher_")
        try:
            # Write the source into a *sibling* dir of the compile workdir:
            # compile_to_obj copies source_path -> workdir, which fails when
            # they are already the same path.
            src_dir = base / "src"
            src_dir.mkdir()
            src_path = src_dir / f"cand{source_ext}"
            src_path.write_text(source_code, encoding="utf-8")
            workdir = base / "work"
            workdir.mkdir()
            obj_file, err = compile_to_obj(
                cfg,
                src_path,
                shlex.split(cflags),
                workdir,
                use_cache=cache is not None,
                cache=cache,
                obj_name="cand.obj",
                # The source is compiled from a temp copy; the original
                # source's parent dir must reach the container for relative
                # #include resolution (rebrew diff / flag sweep).
                extra_include_dirs=extra_include_dirs,
                # A --sweep-toolchain run swaps the compiler per iteration —
                # the profile must drive the image, not the project default.
                toolchain=profile,
            )
            if obj_file is None:
                return BuildResult(ok=False, error_msg=f"Compile failed: {err}")
            code, relocs = parse_obj_symbol_bytes(str(obj_file), symbol)
            if code is None:
                return BuildResult(ok=False, error_msg=f"Symbol {symbol} not found in .obj")
            return BuildResult(ok=True, obj_bytes=code, reloc_offsets=relocs)
        finally:
            shutil.rmtree(base, ignore_errors=True)

    src_name = f"cand{source_ext}"
    all_flags = shlex.split(cflags)
    # Per-target version defines (targets.<name>.defines) — the raw
    # subprocess path must compile with the same flags compile_to_obj
    # applies, or GA/diff results diverge from verify for shared
    # multi-version sources.  (Docker-backed profiles get them inside
    # compile_to_obj; this path serves native compilers like gcc-pe.)
    for define in getattr(cfg, "defines", None) or []:
        all_flags.append(f"{'-D' if posix_style else '/D'}{define}")
    extra_inc = extra_include_dirs or []

    # Resolve relative /I paths in the flags (base_cflags often carry e.g.
    # /Ireferences/zlib-1.1.3). The raw subprocess path compiles from a temp
    # workdir, so a relative include path would resolve against the wrong
    # directory and fail on functions that #include those headers. Mirror the
    # resolution compile_to_obj performs for toolchain-backed profiles.
    if extra_inc and any(f.startswith(("/I", "-I")) for f in all_flags):
        from rebrew.compile import _resolve_include_flags

        src_parent = Path(extra_inc[0])
        cfg_root = getattr(cfg, "root", Path.cwd()) if cfg is not None else Path.cwd()
        all_flags = _resolve_include_flags(all_flags, src_parent, cfg_root)

    cache_key: str | None = None
    if cache is not None:
        from rebrew.compile import _extract_include_dirs

        cmd_parts = _compiler_cmd_parts(cl_cmd, env)
        toolchain_id = " ".join(cmd_parts)
        cache_key = compile_cache_key(
            source_content=source_code,
            source_filename=src_name,
            cflags=all_flags + ["/c"],
            # The /I dirs carried by the flags join the search set so their
            # headers participate in the per-source dependency fingerprints.
            include_dirs=[inc_dir, *extra_inc, *_extract_include_dirs(all_flags)],
            toolchain_id=toolchain_id,
            source_ext=source_ext,
        )
        cached_obj = cache.get(cache_key)
        if cached_obj is not None:
            with tempfile.TemporaryDirectory(prefix="matcher_hit_") as _td:
                obj_path = Path(_td) / "cand.obj"
                obj_path.write_bytes(cached_obj)
                code, relocs = parse_obj_symbol_bytes(str(obj_path), symbol)
                if code is None:
                    return BuildResult(ok=False, error_msg=f"Symbol {symbol} not found in .obj")
                return BuildResult(ok=True, obj_bytes=code, reloc_offsets=relocs)

    with tempfile.TemporaryDirectory(prefix="matcher_") as _td:
        workdir = Path(_td)
        obj_name = "cand.obj"
        (workdir / src_name).write_text(source_code, encoding="utf-8")

        cmd = (
            _compiler_cmd_parts(cl_cmd, env)
            + all_flags
            + (
                ["-c"]
                + ([f"-I{inc_dir}"] if inc_dir else [])
                + [f"-I{d}" for d in extra_inc]
                + ["-o", obj_name, src_name]
                if posix_style
                else ["/c"]
                + ([f"/I{inc_dir}"] if inc_dir else [])
                + [f"/I{d}" for d in extra_inc]
                + [f"/Fo{obj_name}", src_name]
            )
        )
        env = _ensure_wine_env(env, cmd)
        cmd, env = _maybe_headless_wine(cmd, env)

        try:
            r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return BuildResult(ok=False, error_msg=f"Compile timed out after {timeout}s")
        except FileNotFoundError as e:
            return BuildResult(ok=False, error_msg=f"Compiler not found: {e}")
        except OSError as e:
            return BuildResult(ok=False, error_msg=f"Failed to run compiler: {e}")

        obj_path = workdir / obj_name

        if r.returncode != 0 or not obj_path.exists():
            err_output = _filter_wine_stderr((r.stdout + b"\n" + r.stderr).decode(errors="replace"))
            detailed_err = f"Command: {' '.join(cmd)}\nReturn code: {r.returncode}\nObj Exists: {obj_path.exists()}\nOutput: {err_output}"
            return BuildResult(ok=False, error_msg=detailed_err)

        if cache is not None and cache_key is not None:
            with contextlib.suppress(OSError):
                cache.put(cache_key, obj_path.read_bytes())

        code, relocs = parse_obj_symbol_bytes(str(obj_path), symbol)
        if code is None:
            return BuildResult(ok=False, error_msg=f"Symbol {symbol} not found in .obj")

        return BuildResult(ok=True, obj_bytes=code, reloc_offsets=relocs)


def build_candidate(
    source_code: str,
    cl_cmd: str,
    inc_dir: str,
    lib_dir: str,
    cflags: str,
    ldflags: str,
    symbol: str,
    extra_sources: list[str] | None = None,
    link_cmd: str | None = None,
    env: dict[str, str] | None = None,
    source_ext: str = ".c",
    timeout: int = 120,
) -> BuildResult:
    """Compile and link source to .exe, then extract symbol bytes.

    *link_cmd* (when provided) overrides the MSVC linker invocation — e.g.
    ``"link /SUBSYSTEM:WINDOWS"`` — replacing the default ``/link`` switch;
    the base *ldflags* and ``/LIBPATH``/``/OUT``/``/MAP`` still follow.
    """
    with tempfile.TemporaryDirectory(prefix="matcher_") as _td:
        workdir = Path(_td)
        src_name = f"cand{source_ext}"
        exe_name = "cand.exe"
        map_name = "cand.map"
        (workdir / src_name).write_text(source_code, encoding="utf-8")

        cmd = _compiler_cmd_parts(cl_cmd, env) + shlex.split(cflags) + [f"/I{inc_dir}", src_name]
        if extra_sources:
            for es in extra_sources:
                shutil.copy2(es, workdir)
                cmd.append(Path(es).name)

        link_head = shlex.split(link_cmd) if link_cmd else ["/link"]
        cmd += (
            link_head
            + shlex.split(ldflags)
            + [f"/LIBPATH:{lib_dir}", f"/OUT:{exe_name}", f"/MAP:{map_name}"]
        )

        env = _ensure_wine_env(env, cmd)
        cmd, env = _maybe_headless_wine(cmd, env)
        try:
            r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return BuildResult(ok=False, error_msg=f"Compile+link timed out after {timeout}s")
        except FileNotFoundError as e:
            return BuildResult(ok=False, error_msg=f"Compiler not found: {e}")
        except OSError as e:
            return BuildResult(ok=False, error_msg=f"Failed to run compiler: {e}")

        exe_path = workdir / exe_name
        map_path = workdir / map_name

        if r.returncode != 0 or not exe_path.exists() or not map_path.exists():
            err_output = _filter_wine_stderr(
                (r.stdout + b"\n" + r.stderr).decode(errors="replace")
            )[:400]
            return BuildResult(ok=False, error_msg=err_output)

        map_text = map_path.read_text(encoding="utf-8")

        # MSVC MAP format: "  SSSS:OOOOOOOO  _symbol  VVVVVVVV  f  obj"
        m = _map_symbol_re(symbol).search(map_text)
        if not m:
            return BuildResult(ok=False, error_msg=f"Symbol {symbol} not found in MAP")

        va = int(m.group(1), 16)

        size = _get_pe_symbol_size(exe_path, symbol)
        if size is None:
            size = _DEFAULT_SYMBOL_SIZE
            for m_next in _MAP_SYM_RE.finditer(map_text, m.end()):
                next_va = int(m_next.group(1), 16)
                estimated = next_va - va
                if 0 < estimated <= 10000:
                    size = estimated
                    break

        code = extract_function_from_binary(exe_path, va, size)
        if code is None:
            return BuildResult(ok=False, error_msg="Failed to extract from PE")

        return BuildResult(ok=True, obj_bytes=code)


def flag_sweep(
    source_code: str,
    target_bytes: bytes,
    cl_cmd: str,
    inc_dir: str,
    base_cflags: str,
    symbol: str,
    n_jobs: int = 4,
    tier: str = "targeted",
    env: dict[str, str] | None = None,
    source_ext: str = ".c",
    cache: CompileCache | None = None,
    timeout: int = 60,
    extra_include_dirs: list[str] | None = None,
    posix_style: bool = False,
    profile: str = "",
    cfg: Any = None,
) -> list[tuple[float, str]]:
    """Sweep compiler flags to find the best match.

    Args:
        source_code: C source to compile.
        target_bytes: The target byte sequence to match against.
        cl_cmd: Path or command to the compiler.
        inc_dir: Base include directory.
        base_cflags: Minimum flags required.
        symbol: Symbol name to extract.
        n_jobs: Thread count.
        tier: Sweep effort level — "quick", "targeted", "normal", "thorough", or "full".
        env: MSVC environment.
        source_ext: Extension of the source file.
        cache: Optional ``CompileCache`` for cross-run persistence.
        timeout: Subprocess timeout in seconds.
        profile: Compiler profile id ("msvc6", "watcom", "msvc1.52", ...) —
            selects the flag set and (for toolchain-backed profiles) the
            compile runner.
        cfg: Optional project config for toolchain-backed compile routing.

    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from .scoring import precompute_target, score_candidate

    if posix_style or profile in _POSIX_PROFILES:
        # The sweep explores MSVC flag combos (/O1, /MT, /Gd...); a posix
        # compiler (gcc-pe/mingw, watcom, tc16/20, borland) treats /flags as
        # files and every combo would fail — and there is no posix flag
        # database to sweep.  Refuse loudly instead of silently wasting
        # compiles (a sweep on gcc-pe only ever "matched" via the empty
        # extra-flag combo, which the plain GA already tries).
        raise ValueError(
            f"flag sweep is MSVC-only (profile {profile!r} uses posix-style "
            "flags) — run the GA without --flag-sweep-only"
        )

    combos = generate_flag_combinations(tier=tier, profile=profile)
    log.info("Sweeping %d flag combinations (tier=%s)...", len(combos), tier)

    # Pre-compute target normalization and mnemonics once for all workers
    pre_norm_target, pre_target_mnems = precompute_target(target_bytes)

    # First compiler error(s) collected from workers — surfaced when the whole
    # sweep fails so a broken toolchain is visible, not a silent empty result.
    _compile_errors: list[str] = []

    def _eval_flags(flags: str) -> tuple[float, str]:
        full_flags = f"{base_cflags} {flags}"
        res = build_candidate_obj_only(
            source_code,
            cl_cmd,
            inc_dir,
            full_flags,
            symbol,
            env=env,
            source_ext=source_ext,
            cache=cache,
            timeout=timeout,
            extra_include_dirs=extra_include_dirs,
            posix_style=posix_style,
            profile=profile,
            cfg=cfg,
        )
        if res.ok and res.obj_bytes:
            score = score_candidate(
                target_bytes,
                res.obj_bytes,
                res.reloc_offsets,
                _pre_norm_target=pre_norm_target,
                _pre_target_mnems=pre_target_mnems,
            )
            return score.total, flags
        if res.error_msg and len(_compile_errors) < 3:
            _compile_errors.append(res.error_msg.strip()[:300])
        return float("inf"), flags

    with ThreadPoolExecutor(max_workers=n_jobs) as executor:
        # Bounded submission: submitting every combo up front (thorough =
        # 258k, full = 6.2M combos) builds one Future + one queued task per
        # combo — hundreds of MB to GBs of memory before the first compile.
        # Submit n_jobs batches and drain via as_completed.
        results = []
        worker_errors = 0
        pending = set()
        combo_iter = iter(combos)
        for _ in range(min(n_jobs, len(combos))):
            pending.add(executor.submit(_eval_flags, next(combo_iter)))
        while pending:
            for fut in as_completed(pending):
                pending.remove(fut)
                try:
                    score, flags = fut.result()
                except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
                    # Environmental failures (missing compiler, cache corruption,
                    # LIEF parse of a bad .obj).  Never silently swallowed: count
                    # them so a fully-failed sweep can't masquerade as "no match".
                    worker_errors += 1
                    if worker_errors <= 3:
                        log.warning("Flag sweep worker failed: %s", exc)
                except Exception:
                    # Unexpected exception (e.g. TypeError from scoring pipeline bug):
                    # log at DEBUG so it surfaces in --verbose or CI runs without crashing the sweep.
                    worker_errors += 1
                    log.debug("Unexpected error in flag_sweep worker", exc_info=True)
                else:
                    if score < float("inf"):
                        results.append((score, flags))
                with contextlib.suppress(StopIteration):
                    pending.add(executor.submit(_eval_flags, next(combo_iter)))

    # A sweep where EVERY combo failed is indistinguishable from "no flags
    # matched" without this: surface the first compiler error so a broken
    # toolchain / bad source is visible instead of a silent empty result.
    if not results and (_compile_errors or worker_errors):
        log.warning(
            "Flag sweep produced no matches (%d worker failure(s)); first compiler error(s):\n%s",
            worker_errors,
            "\n".join(_compile_errors) if _compile_errors else "(none — see warnings above)",
        )

    results.sort(key=lambda x: x[0])
    return results
