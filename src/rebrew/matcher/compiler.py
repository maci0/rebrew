"""compiler.py — compile backend for GA matching.

Provides build_candidate_obj_only(), build_candidate(), flag_sweep(),
and generate_flag_combinations().  Every compile routes through the shared
``rebrew.compile.compile_to_obj`` runner (local docker images, or the
recompile service when configured) — there is no host-compiler path.
"""

import contextlib
import itertools
import logging
import math
import shlex
import shutil
import warnings
from pathlib import Path
from typing import Any

from rebrew.compile_cache import CacheBackend
from rebrew.config import POSIX_PROFILES

from .core import BuildResult
from .flag_data import (
    BORLAND_FLAGS,
    BORLAND_SWEEP_TIERS,
    COMMON_MSVC_FLAGS,
    GCC_FLAGS,
    GCC_SWEEP_TIERS,
    MSVC6_FLAGS,
    MSVC152_FLAGS,
    MSVC152_SWEEP_TIERS,
    MSVC_SWEEP_TIERS,
    WATCOM_FLAGS,
    WATCOM_SWEEP_TIERS,
)
from .flags import Checkbox, Flags, FlagSet
from .parsers import parse_obj_symbol_bytes

log = logging.getLogger(__name__)


# Warn when flag sweep produces more than this many combinations
_MAX_SWEEP_COMBOS = 100_000


# Map of profiles → synced Flags lists (the packaged base; entry-point
# providers in rebrew.flag_sets extend/override per profile — see
# _merged_flag_sets below).
_FLAGS_MAP: dict[str, Flags] = {
    "msvc": COMMON_MSVC_FLAGS,
    "msvc7": COMMON_MSVC_FLAGS,  # deprecated alias of msvc710
    "msvc700": COMMON_MSVC_FLAGS,
    "msvc710": COMMON_MSVC_FLAGS,
    "msvc800": COMMON_MSVC_FLAGS,
    "msvc6": MSVC6_FLAGS,  # excludes MSVC 7.x+ only flags (/fp:*, /GS-)
    "msvc1.52": MSVC152_FLAGS,
    "watcom": WATCOM_FLAGS,
    "watcom16": WATCOM_FLAGS,  # same wcc flag family (16-bit wcc)
    "tc16": BORLAND_FLAGS,
    "tc20": BORLAND_FLAGS,
    "borlandc55": BORLAND_FLAGS,
    "gcc": GCC_FLAGS,
    "gcc-pe": GCC_FLAGS,  # MinGW accepts the same GCC flag family
    "clang": GCC_FLAGS,
}

#: Packaged sweep-tier dispatch: profile → {tier: [flag-axis ids]}.  Profiles
#: without an entry fall back to MSVC_SWEEP_TIERS (the historic default).
_PACKAGED_FLAG_TIERS: dict[str, dict[str, list[str] | None]] = {
    "gcc": GCC_SWEEP_TIERS,
    "gcc-pe": GCC_SWEEP_TIERS,
    "clang": GCC_SWEEP_TIERS,
    "watcom": WATCOM_SWEEP_TIERS,
    "watcom16": WATCOM_SWEEP_TIERS,
    "msvc1.52": MSVC152_SWEEP_TIERS,
    "tc16": BORLAND_SWEEP_TIERS,
    "tc20": BORLAND_SWEEP_TIERS,
    "borlandc55": BORLAND_SWEEP_TIERS,
}

#: setuptools entry-point group whose members register sweep flag sets.  A
#: member is a zero-arg callable returning ``dict[profile, (Flags, tiers)]``
#: where *tiers* is ``{tier: [axis ids]}`` (``"full": None`` = all axes).
#: Flag sets are tuning data, not identity-critical components: unlike
#: toolchains/decompilers (where a duplicate name is a RegistryError), a
#: provider may override a packaged profile's axes — that is the point of a
#: sweep-tuning plugin.
FLAG_SET_ENTRY_POINT_GROUP = "rebrew.flag_sets"


def _merged_flag_sets() -> tuple[dict[str, Flags], dict[str, dict[str, list[str] | None]]]:
    """The (flags, tiers) registries: packaged defs + ``rebrew.flag_sets``.

    Packaged profiles are the base; entry-point providers override per
    profile name in discovery order (last provider wins).  An optional
    registry: a broken provider is skipped with a warning (the packaged
    sweep axes stand)."""
    from rebrew.registry import entry_point_registrations, load_registration_optional

    flags = dict(_FLAGS_MAP)
    tiers = dict(_PACKAGED_FLAG_TIERS)
    for reg in entry_point_registrations(FLAG_SET_ENTRY_POINT_GROUP):
        provider = load_registration_optional(reg, log)
        if provider is None:
            continue
        try:
            provided = provider()
        except Exception as exc:
            log.warning(
                "skipping %s provider %r: %s: %s",
                reg.group,
                reg.name,
                type(exc).__name__,
                exc,
            )
            continue
        if not isinstance(provided, dict):
            log.warning(
                "skipping %s provider %r: expected dict[profile, (Flags, tiers)], got %s",
                reg.group,
                reg.name,
                type(provided).__name__,
            )
            continue
        for name, (profile_flags, profile_tiers) in provided.items():
            flags[name] = profile_flags
            tiers[name] = profile_tiers
    return flags, tiers


_FLAGS_MAP, _TIERS_MAP = _merged_flag_sets()


def refresh_flag_sets() -> tuple[dict[str, Flags], dict[str, dict[str, list[str] | None]]]:
    """Re-run discovery and refresh the ``_FLAGS_MAP``/``_TIERS_MAP`` snapshots.

    Long-lived processes can pick up sweep-flag plugins installed after
    startup without a restart."""
    global _FLAGS_MAP, _TIERS_MAP

    _FLAGS_MAP, _TIERS_MAP = _merged_flag_sets()
    return _FLAGS_MAP, _TIERS_MAP


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


def generate_flag_combinations(tier: str = "targeted", profile: str = "msvc6") -> list[str]:
    """Generate flag combinations for the given compiler profile.

    Args:
        tier: Sweep effort level — "quick", "targeted", "normal", "thorough", or "full".
              Controls how many flag axes are included.
        profile: Compiler profile name — "msvc6", "msvc7", or "msvc".

    """
    # Use synced Flags for this profile, falling back to msvc6.  Sweep tiers
    # come from the merged registry (packaged dispatch + rebrew.flag_sets
    # providers); an unknown profile falls back to the MSVC tiers.
    flags = _FLAGS_MAP.get(profile, _FLAGS_MAP["msvc6"])
    tiers = _TIERS_MAP.get(profile, MSVC_SWEEP_TIERS)
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
        # A fixed stride over the lexicographic product is biased: with an
        # even stride, a 2-option trailing axis (e.g. /Op on/off) is only
        # ever sampled at one parity, silently dropping one of its values
        # (e.g. MSVC6 `full`: total ≈ 6.19M → step 62 → /Op never tried).
        # Adjust the step to be coprime to every axis length so all values
        # of every axis appear in the sample.
        axis_lcm = 1
        for _axis in axes:
            axis_lcm = axis_lcm * len(_axis) // math.gcd(axis_lcm, len(_axis))
        while math.gcd(step, axis_lcm) != 1:
            step += 1
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
    cache: CacheBackend | None = None,
    timeout: int = 60,
    extra_include_dirs: list[str] | None = None,
    posix_style: bool = False,
    profile: str = "",
    cfg: Any = None,
) -> BuildResult:
    """Compile source to .obj and extract symbol bytes (no linking).

    Every profile routes through the shared ``compile_to_obj`` runner —
    local docker images, or the recompile service when configured — which
    owns caching, include resolution, and per-target defines.  There is no
    host-compiler path: native-Linux toolchains (gcc-pe and friends) execute
    inside their container image or on the service, never as a host
    subprocess.
    """
    if cfg is None:
        from types import SimpleNamespace

        cfg = SimpleNamespace(
            root=Path.cwd(),
            compiler_profile=profile,
            compiler_command=cl_cmd,
            compiler_includes=inc_dir,
            base_cflags="",
            compile_timeout=timeout,
            # build_name_to_va / scan_globals read these — without them
            # DIR32 reloc validation degrades to a silent no-op warning.
            reversed_dir=Path.cwd(),
            metadata_dir=Path.cwd(),
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

    Retired: link-then-extract ran a host compiler+linker subprocess, which
    no longer exists (every compile routes through container images or the
    recompile service, and neither exposes a link-then-extract path).
    Kept as a stub so old imports fail loudly at call time instead of at
    import time; the linked-exe GA mode in match.py is removed alongside.
    """
    return BuildResult(
        ok=False,
        error_msg=(
            "build_candidate (linked-exe compare) is retired: compiles run "
            "through container images or the recompile service; use "
            "build_candidate_obj_only instead"
        ),
    )


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
    cache: CacheBackend | None = None,
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
        cache: Optional ``CacheBackend`` for cross-run persistence.
        timeout: Subprocess timeout in seconds.
        profile: Compiler profile id ("msvc6", "watcom", "msvc1.52", ...) —
            selects the flag set and (for toolchain-backed profiles) the
            compile runner.
        cfg: Optional project config for toolchain-backed compile routing.

    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from .scoring import precompute_target, score_candidate

    if (posix_style or profile in POSIX_PROFILES) and profile not in _TIERS_MAP:
        # The sweep needs a flag database for the profile.  Posix profiles
        # WITHOUT one (a plugin toolchain that declared no flag sets) would
        # get the MSVC fallback — every combo invalid for the compiler, so
        # refuse loudly instead of silently wasting compiles.  Profiles with
        # posix tiers (watcom, msvc1.52, tc16/20, borlandc55, gcc, clang)
        # sweep normally.
        raise ValueError(
            f"flag sweep: profile {profile!r} uses posix-style flags but has no "
            "registered flag set (rebrew.flag_sets) — run the GA without "
            "--flag-sweep-only, or provide flag axes for the profile"
        )

    combos = generate_flag_combinations(tier=tier, profile=profile)
    log.info("Sweeping %d flag combinations (tier=%s)...", len(combos), tier)

    # Pre-compute target normalization and mnemonics once for all workers
    pre_norm_target, pre_target_mnems = precompute_target(target_bytes)

    # First compiler error(s) collected from workers — surfaced when the whole
    # sweep fails so a broken toolchain is visible, not a silent empty result.
    import threading as _thr

    _compile_errors: list[str] = []
    _compile_errors_lock = _thr.Lock()

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
        if res.error_msg:
            with _compile_errors_lock:
                if len(_compile_errors) < 3:
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
                except (OSError, ValueError, RuntimeError) as exc:
                    # Environmental failures (missing image, cache corruption,
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
