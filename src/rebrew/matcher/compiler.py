import os
import subprocess
import tempfile
import shutil
import itertools
from typing import List, Optional, Tuple, Dict
from .core import BuildResult
from .parsers import parse_coff_obj_symbol_bytes

# Compiler flag axes (from config / fallback to MSVC6)
try:
    from rebrew.config import cfg as _cfg
    _COMPILER_PROFILE = _cfg.compiler_profile
except Exception:
    _cfg = None  # type: ignore[assignment]
    _COMPILER_PROFILE = "msvc6"

MSVC6_FLAG_AXES = {
    "opt": ["/O1", "/O2", "/Os", "/Ot", "/Ox", "/Od", ""],
    "fp": ["/Oy", "/Oy-", ""],
    "cpu": ["/G5", "/G6", ""],
    "call": ["/Gd", "/Gr", "/Gz", ""],
    "link": ["/Gy", ""],
    "intrinsics": ["/Oi", ""],
}

GCC_FLAG_AXES = {
    "opt": ["-O0", "-O1", "-O2", "-O3", "-Os", ""],
    "fp": ["-fomit-frame-pointer", "-fno-omit-frame-pointer", ""],
    "tuning": ["-mtune=i686", "-mtune=pentium", ""],
    "call": [""],
    "link": ["-ffunction-sections", ""],
    "intrinsics": [""],
}

_FLAG_AXES_MAP = {
    "msvc6": MSVC6_FLAG_AXES,
    "gcc": GCC_FLAG_AXES,
    "clang": GCC_FLAG_AXES,  # Clang accepts GCC flags
}

def _get_flag_axes() -> Dict[str, List[str]]:
    return _FLAG_AXES_MAP.get(_COMPILER_PROFILE, MSVC6_FLAG_AXES)

def generate_flag_combinations() -> List[str]:
    """Generate all valid combinations of MSVC6 compiler flags."""
    axes_dict = _get_flag_axes()
    axes = list(axes_dict.values())
    combos = []
    for combo in itertools.product(*axes):
        flags = [f for f in combo if f]
        combos.append(" ".join(flags))
    return list(set(combos))

def build_candidate_obj_only(
    source_code: str,
    cl_cmd: str,
    inc_dir: str,
    cflags: str,
    symbol: str,
    extra_sources: Optional[List[str]] = None,
) -> BuildResult:
    """Compile source to .obj and extract symbol bytes (no linking)."""
    workdir = tempfile.mkdtemp(prefix="matcher_")
    try:
        src_name = "cand.c"
        obj_name = "cand.obj"
        src_path = os.path.join(workdir, src_name)
        with open(src_path, "w") as f:
            f.write(source_code)

        # MSVC6 under Wine sometimes dislikes absolute Unix paths for source files
        # We use relative paths since we are running in workdir
        cmd = cl_cmd.split() + cflags.split() + [f"/I{inc_dir}", f"/Fo{obj_name}", src_name]
        try:
            from rebrew.config import cfg
            env = cfg.msvc_env()
        except Exception:
            env = {**os.environ, "WINEDEBUG": "-all"}

        r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env)
        obj_path = os.path.join(workdir, obj_name)
        
        if r.returncode != 0 or not os.path.exists(obj_path):
            return BuildResult(ok=False, error_msg=r.stderr.decode()[:200])

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
    extra_sources: Optional[List[str]] = None,
) -> BuildResult:
    """Compile and link source to .exe, then extract symbol bytes."""
    workdir = tempfile.mkdtemp(prefix="matcher_")
    try:
        src_name = "cand.c"
        exe_name = "cand.exe"
        map_name = "cand.map"
        src_path = os.path.join(workdir, src_name)
        with open(src_path, "w") as f:
            f.write(source_code)

        cmd = (
            cl_cmd.split()
            + cflags.split()
            + [f"/I{inc_dir}", src_name]
        )
        if extra_sources:
            for es in extra_sources:
                shutil.copy2(es, workdir)
                cmd.append(os.path.basename(es))

        cmd += (
            ["/link"]
            + ldflags.split()
            + [f"/LIBPATH:{lib_dir}", f"/OUT:{exe_name}", f"/MAP:{map_name}"]
        )

        env = {**os.environ, "WINEDEBUG": "-all"}
        r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env)
        
        exe_path = os.path.join(workdir, exe_name)
        map_path = os.path.join(workdir, map_name)

        if r.returncode != 0 or not os.path.exists(exe_path) or not os.path.exists(map_path):
            return BuildResult(ok=False, error_msg=r.stderr.decode()[:200])

        with open(map_path, "r") as f:
            map_text = f.read()

        import re
        sym_re = re.compile(r"^\s*\d+:\d+\s+([0-9a-fA-F]+)\s+" + re.escape(symbol) + r"\s+", re.MULTILINE)
        m = sym_re.search(map_text)
        if not m:
            return BuildResult(ok=False, error_msg=f"Symbol {symbol} not found in MAP")
        
        lines = map_text.splitlines()
        sym_idx = -1
        for i, line in enumerate(lines):
            if symbol in line and m.group(1) in line:
                sym_idx = i
                break
        
        size = 1000
        if sym_idx != -1 and sym_idx + 1 < len(lines):
            next_line = lines[sym_idx + 1]
            m_next = re.search(r"^\s*\d+:\d+\s+([0-9a-fA-F]+)\s+", next_line)
            if m_next:
                size = int(m_next.group(1), 16) - int(m.group(1), 16)
                if size <= 0 or size > 10000:
                    size = 1000

        va = int(m.group(1), 16)
        from .parsers import extract_function_from_pe
        from pathlib import Path
        
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
) -> List[Tuple[float, str]]:
    """Sweep compiler flags to find the best match."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from .scoring import score_candidate

    combos = generate_flag_combinations()
    print(f"Sweeping {len(combos)} flag combinations...")

    results = []
    
    def _eval_flags(flags: str) -> Tuple[float, str]:
        full_flags = f"{base_cflags} {flags}"
        res = build_candidate_obj_only(
            source_code, cl_cmd, inc_dir, full_flags, symbol
        )
        if res.ok and res.obj_bytes:
            score = score_candidate(target_bytes, res.obj_bytes, res.reloc_offsets)
            return score.total, flags
        return float("inf"), flags

    with ThreadPoolExecutor(max_workers=n_jobs) as executor:
        futures = {executor.submit(_eval_flags, f): f for f in combos}
        for fut in as_completed(futures):
            score, flags = fut.result()
            if score < float("inf"):
                results.append((score, flags))

    results.sort(key=lambda x: x[0])
    return results
