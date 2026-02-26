"""Unified MSVC compilation helper for rebrew.

Provides a single, consistent interface for compiling C source to .obj files
using MSVC under Wine. All tools (rebrew-test, rebrew-match, rebrew-verify)
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

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from rebrew.config import ProjectConfig
from rebrew.matcher.parsers import parse_coff_symbol_bytes

# ---------------------------------------------------------------------------
# Command resolution
# ---------------------------------------------------------------------------


def resolve_cl_command(cfg: ProjectConfig) -> list[str]:
    """Build the base CL.EXE command list from config.

    Handles both ``wine path/to/cl.exe`` and bare ``cl.exe`` formats,
    resolving relative paths against the project root.

    Returns:
        List of command parts, e.g. ``["wine", "/abs/path/CL.EXE"]``.
    """
    try:
        cmd_parts = shlex.split(cfg.compiler_command)
    except ValueError:
        cmd_parts = cfg.compiler_command.split()
    if len(cmd_parts) > 1 and cmd_parts[0] == "wine":
        # "wine tools/MSVC600/bin/CL.EXE" → ["wine", "<root>/tools/MSVC600/bin/CL.EXE"]
        cl_rel = Path(cmd_parts[1])
        cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
        return ["wine", cl_abs]
    else:
        # Bare "CL.EXE" or absolute path
        cl_rel = Path(cmd_parts[0]) if cmd_parts else Path("CL.EXE")
        cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
        return [cl_abs]


# ---------------------------------------------------------------------------
# Object file compilation
# ---------------------------------------------------------------------------


def compile_to_obj(
    cfg: ProjectConfig,
    source_path: str | Path,
    cflags: list[str],
    workdir: str | Path,
    *,
    timeout: int = 60,
) -> tuple[str | None, str]:
    """Compile a .c file to .obj using the project compiler.

    The source file is copied into ``workdir`` before compilation so that
    Wine's path mapping works correctly (Wine cannot see paths outside of
    its configured drives).

    Args:
        cfg: ProjectConfig with compiler settings.
        source_path: Path to the .c source file.
        cflags: List of compiler flag strings (e.g. ["/O2", "/Gd"]).
        workdir: Working directory for compilation.
        timeout: Maximum seconds for the compile process.

    Returns:
        (obj_path, error_msg) — obj_path is None on failure.
    """
    source_path = Path(source_path)
    workdir = Path(workdir)

    # Copy source to workdir for Wine compatibility
    src_name = source_path.name
    local_src = workdir / src_name
    shutil.copy2(source_path, local_src)

    obj_name = source_path.stem + ".obj"
    inc_path = str(cfg.compiler_includes)

    # Prepend base_cflags from config (e.g. /nologo /c /MT).
    # This ensures every compile invocation has consistent core flags
    # without requiring callers to remember them.
    base_flags = getattr(cfg, "base_cflags", "/nologo /c /MT").split()
    use_timeout = getattr(cfg, "compile_timeout", timeout)

    # Build full command: [wine, cl.exe] + base + user flags + includes + output + source
    cmd = (
        resolve_cl_command(cfg)
        + base_flags
        + cflags
        + [
            f"/I{inc_path}",
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

    obj_path = str(workdir / obj_name)
    if r.returncode != 0 or not os.path.exists(obj_path):
        err = (r.stdout + r.stderr).decode("utf-8", errors="replace")[:400]
        return None, err

    return obj_path, ""


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
    timeout: int = 60,
) -> tuple[bool, str, bytes | None, list[int] | None]:
    """Compile source, extract COFF symbol, compare against target bytes with reloc masking.

    This is the shared compile→extract→compare flow used by both ``rebrew-test``
    and ``rebrew-verify``.

    Args:
        cfg: ProjectConfig with compiler settings.
        source_path: Path to the .c source file.
        symbol: COFF symbol name to extract (e.g. ``_my_func``).
        target_bytes: Expected bytes from the target binary.
        cflags: Compiler flags (string or list).
        timeout: Maximum seconds for compilation.

    Returns:
        (matched, message, obj_bytes, reloc_offsets)
        matched is True if bytes match after reloc masking.
    """
    cflags_list = cflags.split() if isinstance(cflags, str) else list(cflags)

    workdir = tempfile.mkdtemp(prefix="rebrew_cmp_")
    try:
        use_timeout = getattr(cfg, "compile_timeout", timeout)
        obj_path, err = compile_to_obj(
            cfg,
            source_path,
            cflags_list,
            workdir,
            timeout=use_timeout,
        )
        if obj_path is None:
            return False, f"COMPILE_ERROR: {err[:200]}", None, None

        obj_bytes, reloc_offsets = parse_coff_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            return False, f"COMPILE_ERROR: Symbol '{symbol}' not found in .obj", None, None

        if len(obj_bytes) != len(target_bytes):
            return (
                False,
                f"MISMATCH: Size {len(obj_bytes)}B vs {len(target_bytes)}B",
                obj_bytes,
                reloc_offsets,
            )

        # Compare with reloc masking
        reloc_set: set[int] = set()
        pointer_size = getattr(cfg, "pointer_size", 4)
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
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
