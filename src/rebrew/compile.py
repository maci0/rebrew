"""Unified MSVC compilation helper for rebrew.

Provides a single, consistent interface for compiling C source to .obj files
using MSVC under Wine. All tools (rebrew test, rebrew match, rebrew verify)
should use these functions instead of building compile commands independently.

Architecture
~~~~~~~~~~~~
Three entry points exist, in order of abstraction:

``resolve_cl_command(cfg)``
    Lowest level — builds the ``["wine", "/path/CL.EXE"]`` prefix list
    from the config's ``compiler_command`` string.

``compile_to_obj(cfg, source_path, cflags, workdir)``
    Mid-level — copies source to a Wine-compatible workdir and produces
    a ``.obj`` file. Returns ``(obj_path, error_msg)``.

Configuration
~~~~~~~~~~~~~
All functions read from ``cfg`` (a ``ProjectConfig`` instance):

- ``cfg.compiler_command`` — e.g. ``"wine tools/MSVC600/bin/CL.EXE"``
- ``cfg.compiler_includes`` — path to MSVC include directory
- ``cfg.base_cflags`` — always-on flags (e.g. ``/nologo /c /MT``)
- ``cfg.compile_timeout`` — seconds before subprocess is killed
- ``cfg.msvc_env()`` — environment dict with ``LIB`` / ``INCLUDE`` etc.
"""

import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from rebrew.config import ProjectConfig
from rebrew.matcher.parsers import parse_obj_symbol_bytes

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
    for pat in _WINE_NOISE_PATTERNS:
        text = pat.sub("", text)
    return text.strip()


def resolve_cl_command(cfg: ProjectConfig) -> list[str]:
    """Build the base CL.EXE command list from config.

    Handles both runner-prefixed and bare ``cl.exe`` formats,
    resolving relative paths against the project root.

    Returns:
        List of command parts, e.g. ``["wine", "/abs/path/CL.EXE"]``.
    """
    try:
        cmd_parts = shlex.split(cfg.compiler_command)
    except ValueError:
        cmd_parts = cfg.compiler_command.split()

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


# ---------------------------------------------------------------------------
# Object file compilation
# ---------------------------------------------------------------------------


def compile_to_obj(
    cfg: ProjectConfig,
    source_path: str | Path,
    cflags: list[str],
    workdir: str | Path,
) -> tuple[str | None, str]:
    """Compile a .c file to .obj using the project compiler.

    The source file is copied into ``workdir`` before compilation so that
    Wine's path mapping works correctly (Wine cannot see paths outside of
    its configured drives).

    The timeout is taken from ``cfg.compile_timeout``.

    Args:
        cfg: ProjectConfig with compiler settings.
        source_path: Path to the .c source file.
        cflags: List of compiler flag strings (e.g. ["/O2", "/Gd"]).
        workdir: Working directory for compilation.

    Returns:
        (obj_path, error_msg) — obj_path is None on failure.
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
    try:
        base_flags = shlex.split(cfg.base_cflags)
    except ValueError:
        base_flags = cfg.base_cflags.split()
    use_timeout = cfg.compile_timeout

    # Resolve relative /I paths in user cflags.  The source file is copied
    # into a temp workdir for Wine, so any relative /I paths from CFLAGS
    # annotations (e.g. /I..\..\references\zlib) would resolve against the
    # wrong directory.  Try the source file's parent first (annotations are
    # typically relative to the source), then the project root.
    src_parent = source_path.resolve().parent
    resolved_cflags = []
    for flag in cflags:
        if flag.startswith(("/I", "-I")):
            prefix = flag[:2]
            inc_dir = flag[2:].strip('"').strip("'")
            p = Path(inc_dir)
            if not p.is_absolute():
                from_src = (src_parent / p).resolve()
                from_root = (cfg.root / p).resolve()
                if from_src.is_dir():
                    resolved_cflags.append(f"{prefix}{from_src}")
                elif from_root.is_dir():
                    resolved_cflags.append(f"{prefix}{from_root}")
                else:
                    resolved_cflags.append(flag)
            else:
                resolved_cflags.append(flag)
        else:
            resolved_cflags.append(flag)

    # Build full command: [wine, cl.exe] + base + user flags + includes + output + source
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
            env=cfg.msvc_env(),
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
        err = filter_wine_stderr((r.stdout + r.stderr).decode("utf-8", errors="replace"))[:400]
        return None, err

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
) -> tuple[bool, str, bytes | None, dict[int, str] | None]:
    """Compile source, extract COFF symbol, compare against target bytes with reloc masking.

    This is the shared compile→extract→compare flow used by both ``rebrew test``
    and ``rebrew verify``.  Timeout is taken from ``cfg.compile_timeout``.

    Args:
        cfg: ProjectConfig with compiler settings.
        source_path: Path to the .c source file.
        symbol: COFF symbol name to extract (e.g. ``_my_func``).
        target_bytes: Expected bytes from the target binary.
        cflags: Compiler flags (string or list).

    Returns:
        (matched, message, obj_bytes, reloc_offsets)
        matched is True if bytes match after reloc masking.
    """
    cflags_list = cflags.split() if isinstance(cflags, str) else list(cflags)

    try:
        with tempfile.TemporaryDirectory(prefix="rebrew_cmp_") as workdir:
            obj_path, err = compile_to_obj(
                cfg,
                source_path,
                cflags_list,
                workdir,
            )
            if obj_path is None:
                return False, f"COMPILE_ERROR: {filter_wine_stderr(err)[:200]}", None, None

            obj_bytes, reloc_offsets = parse_obj_symbol_bytes(obj_path, symbol)
            if obj_bytes is None:
                return False, f"COMPILE_ERROR: Symbol '{symbol}' not found in .obj", None, None

            if len(obj_bytes) != len(target_bytes):
                return (
                    False,
                    f"MISMATCH: Size {len(obj_bytes)}B vs {len(target_bytes)}B",
                    obj_bytes,
                    reloc_offsets,
                )

            reloc_set: set[int] = set()
            pointer_size = cfg.pointer_size
            if reloc_offsets:
                for ro in reloc_offsets:
                    for j in range(pointer_size):
                        if 0 <= ro + j < len(obj_bytes):
                            reloc_set.add(ro + j)

            mismatches: list[int] = []
            for i in range(len(obj_bytes)):
                if i in reloc_set:
                    continue
                if obj_bytes[i] != target_bytes[i]:
                    mismatches.append(i)

            if not mismatches:
                if reloc_offsets:
                    return (
                        True,
                        f"RELOC-NORM MATCH ({len(reloc_offsets)} relocs)",
                        obj_bytes,
                        reloc_offsets,
                    )
                else:
                    return True, "EXACT MATCH", obj_bytes, reloc_offsets
            else:
                return (
                    False,
                    f"MISMATCH: {len(mismatches)} byte diffs at {mismatches[:5]}",
                    obj_bytes,
                    reloc_offsets,
                )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as exc:
        return False, f"COMPILE_ERROR: {exc}", None, None
