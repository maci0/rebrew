"""compiler.py – MSVC compilation and Wine execution for GA matching.

Provides build_candidate_obj_only(), build_candidate(), flag_sweep(),
and generate_flag_combinations() for compiling C source with MSVC6 under Wine
and extracting function bytes from the resulting object/executable.
"""

import itertools
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path

from .core import BuildResult
from .flag_data import COMMON_MSVC_FLAGS, MSVC6_FLAGS, MSVC_SWEEP_TIERS
from .flags import Checkbox, Flags, FlagSet
from .parsers import extract_function_from_pe, parse_coff_obj_symbol_bytes

# Compiler flag axes (default to MSVC6, override via function params)
_COMPILER_PROFILE = "msvc6"

# Pre-compiled regex for MAP file symbol parsing
_MAP_SYM_RE = re.compile(
    r"^\s*\d+:[0-9a-fA-F]+\s+\S+\s+([0-9a-fA-F]+)",
    re.MULTILINE,
)

# Legacy dict-based axes (kept for backward compatibility)
MSVC6_FLAG_AXES = {
    "opt": ["/O1", "/O2", "/Os", "/Ot", "/Ox", "/Od", ""],
    "fp": ["/Oy", "/Oy-", ""],
    "cpu": ["/G5", "/G6", ""],
    "call": ["/Gd", "/Gr", "/Gz", ""],
    "link": ["/Gy", ""],
    "intrinsics": ["/Oi", ""],
}


# Map of profiles → synced Flags lists
_FLAGS_MAP: dict[str, Flags] = {
    "msvc": COMMON_MSVC_FLAGS,
    "msvc7": COMMON_MSVC_FLAGS,
    "msvc6": MSVC6_FLAGS,  # excludes MSVC 7.x+ only flags (/fp:*, /GS-)
}

# Legacy dict-based map (for backward compat with generate_flag_combinations fallback)
_FLAG_AXES_MAP: dict[str, dict[str, list[str]]] = {
    "msvc6": MSVC6_FLAG_AXES,
}


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
    the symbol cannot be found or LIEF is not available.
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
        section_number = target_sym.section_number
        sym_value = target_sym.value
        next_offset = None
        for sym in pe.symbols:
            if (
                sym.section_number == section_number
                and sym.value > sym_value
                and (next_offset is None or sym.value < next_offset)
            ):
                next_offset = sym.value

        if next_offset is not None:
            size = next_offset - sym_value
            if 0 < size <= 10000:
                return size

        return None
    except (ImportError, OSError, AttributeError, ValueError):
        return None


def generate_flag_combinations(tier: str = "quick") -> list[str]:
    """Generate flag combinations for the active compiler profile.

    Args:
        tier: Sweep effort level — "quick", "normal", "thorough", or "full".
              Controls how many flag axes are included.
    """
    profile = _COMPILER_PROFILE

    # Use synced Flags if available for this profile
    if profile in _FLAGS_MAP:
        flags = _FLAGS_MAP[profile]
        if tier not in MSVC_SWEEP_TIERS:
            raise ValueError(f"Unknown sweep tier {tier!r}, valid: {list(MSVC_SWEEP_TIERS)}")
        tier_ids = MSVC_SWEEP_TIERS[tier]  # None = all axes
        axes = _flags_to_axes(flags, tier_ids)
    else:
        # Fall back to legacy dict-based axes
        axes_dict = _FLAG_AXES_MAP.get(profile, MSVC6_FLAG_AXES)
        axes = list(axes_dict.values())

    combos = set()
    for combo in itertools.product(*axes):
        flags_str = " ".join(f for f in combo if f)
        combos.add(flags_str)

    if len(combos) > 50_000:
        warnings.warn(
            f"Flag sweep tier '{tier}' produces {len(combos):,} combinations. "
            f"Consider using 'quick' or 'normal' tier, or use sampling.",
            stacklevel=2,
        )

    return sorted(combos)


def build_candidate_obj_only(
    source_code: str,
    cl_cmd: str,
    inc_dir: str,
    cflags: str,
    symbol: str,
    env: dict[str, str] | None = None,
    source_ext: str = ".c",
) -> BuildResult:
    """Compile source to .obj and extract symbol bytes (no linking)."""
    workdir = tempfile.mkdtemp(prefix="matcher_")
    try:
        src_name = f"cand{source_ext}"
        obj_name = "cand.obj"
        src_path = os.path.join(workdir, src_name)
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)

        # MSVC6 under Wine sometimes dislikes absolute Unix paths for source files
        # We use relative paths since we are running in workdir
        cmd = (
            shlex.split(cl_cmd)
            + shlex.split(cflags)
            + ["/c", f"/I{inc_dir}", f"/Fo{obj_name}", src_name]
        )
        if env is None:
            env = {**os.environ, "WINEDEBUG": "-all"}

        try:
            r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env, timeout=60)
        except subprocess.TimeoutExpired:
            return BuildResult(ok=False, error_msg="Compile timed out after 60s")
        except FileNotFoundError as e:
            return BuildResult(ok=False, error_msg=f"Compiler not found: {e}")
        except OSError as e:
            return BuildResult(ok=False, error_msg=f"Failed to run compiler: {e}")

        obj_path = os.path.join(workdir, obj_name)

        if r.returncode != 0 or not os.path.exists(obj_path):
            err_output = (r.stdout + r.stderr).decode(errors="replace")[:400]
            detailed_err = f"Command: {' '.join(cmd)}\nReturn code: {r.returncode}\nObj Exists: {os.path.exists(obj_path)}\nOutput: {err_output}"
            return BuildResult(ok=False, error_msg=detailed_err)

        code, relocs = parse_coff_obj_symbol_bytes(obj_path, symbol)
        if code is None:
            return BuildResult(ok=False, error_msg=f"Symbol {symbol} not found in .obj")

        return BuildResult(ok=True, obj_bytes=code, reloc_offsets=relocs)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def build_candidate(
    source_code: str,
    cl_cmd: str,
    link_cmd: str,
    inc_dir: str,
    lib_dir: str,
    cflags: str,
    ldflags: str,
    symbol: str,
    extra_sources: list[str] | None = None,
    env: dict[str, str] | None = None,
    source_ext: str = ".c",
) -> BuildResult:
    """Compile and link source to .exe, then extract symbol bytes."""
    workdir = tempfile.mkdtemp(prefix="matcher_")
    try:
        src_name = f"cand{source_ext}"
        exe_name = "cand.exe"
        map_name = "cand.map"
        src_path = os.path.join(workdir, src_name)
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)

        cmd = shlex.split(cl_cmd) + shlex.split(cflags) + [f"/I{inc_dir}", src_name]
        if extra_sources:
            for es in extra_sources:
                shutil.copy2(es, workdir)
                cmd.append(os.path.basename(es))

        cmd += (
            ["/link"]
            + shlex.split(ldflags)
            + [f"/LIBPATH:{lib_dir}", f"/OUT:{exe_name}", f"/MAP:{map_name}"]
        )

        if env is None:
            env = {**os.environ, "WINEDEBUG": "-all"}
        try:
            r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env, timeout=120)
        except subprocess.TimeoutExpired:
            return BuildResult(ok=False, error_msg="Compile+link timed out after 120s")
        except FileNotFoundError as e:
            return BuildResult(ok=False, error_msg=f"Compiler not found: {e}")
        except OSError as e:
            return BuildResult(ok=False, error_msg=f"Failed to run compiler: {e}")

        exe_path = os.path.join(workdir, exe_name)
        map_path = os.path.join(workdir, map_name)

        if r.returncode != 0 or not os.path.exists(exe_path) or not os.path.exists(map_path):
            return BuildResult(
                ok=False, error_msg=(r.stdout + r.stderr).decode(errors="replace")[:400]
            )

        with open(map_path, encoding="utf-8") as f:
            map_text = f.read()

        # MSVC MAP format: "  SSSS:OOOOOOOO  _symbol  VVVVVVVV  f  obj"
        # Match segment:offset, then symbol name, then capture the Rva+Base hex VA.
        sym_re = re.compile(
            r"^\s*\d+:[0-9a-fA-F]+\s+" + re.escape(symbol) + r"\s+([0-9a-fA-F]+)",
            re.MULTILINE,
        )
        m = sym_re.search(map_text)
        if not m:
            return BuildResult(ok=False, error_msg=f"Symbol {symbol} not found in MAP")

        va = int(m.group(1), 16)

        # Try to get symbol size from LIEF (more reliable than MAP adjacency)
        size = _get_pe_symbol_size(Path(exe_path), symbol)
        if size is None:
            # Fall back to MAP file: find the next symbol's VA after ours
            size = 1000
            for m_next in _MAP_SYM_RE.finditer(map_text, m.end()):
                next_va = int(m_next.group(1), 16)
                estimated = next_va - va
                if 0 < estimated <= 10000:
                    size = estimated
                    break

        code = extract_function_from_pe(Path(exe_path), va, size)
        if code is None:
            return BuildResult(ok=False, error_msg="Failed to extract from PE")

        return BuildResult(ok=True, obj_bytes=code)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def flag_sweep(
    source_code: str,
    target_bytes: bytes,
    cl_cmd: str,
    inc_dir: str,
    base_cflags: str,
    symbol: str,
    n_jobs: int = 4,
    tier: str = "quick",
    env: dict[str, str] | None = None,
    source_ext: str = ".c",
) -> list[tuple[float, str]]:
    """Sweep compiler flags to find the best match.

    Args:
        tier: Sweep effort level — "quick", "normal", "thorough", or "full".
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from .scoring import score_candidate

    combos = generate_flag_combinations(tier=tier)
    print(f"Sweeping {len(combos)} flag combinations (tier={tier})...")

    results = []

    def _eval_flags(flags: str) -> tuple[float, str]:
        full_flags = f"{base_cflags} {flags}"
        res = build_candidate_obj_only(
            source_code, cl_cmd, inc_dir, full_flags, symbol, env=env, source_ext=source_ext
        )
        if res.ok and res.obj_bytes:
            score = score_candidate(target_bytes, res.obj_bytes, res.reloc_offsets)
            return score.total, flags
        return float("inf"), flags

    with ThreadPoolExecutor(max_workers=n_jobs) as executor:
        futures = [executor.submit(_eval_flags, f) for f in combos]
        for fut in as_completed(futures):
            try:
                score, flags = fut.result()
            except (OSError, subprocess.SubprocessError, ValueError, RuntimeError):
                continue
            if score < float("inf"):
                results.append((score, flags))

    results.sort(key=lambda x: x[0])
    return results
