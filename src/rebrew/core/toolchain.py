"""MSVC environment setup for rebrew compiler invocation under Wine/wibo.

Provides ``msvc_env_from_config()`` to construct subprocess environment
variables (INCLUDE, LIB, PATH, WINEPATH, WINEDEBUG) from a project
configuration.
"""

import os
import shlex
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig


def msvc_env_from_config(cfg: "ProjectConfig") -> dict[str, str]:
    """Return a subprocess env dict with MSVC6 VCVARS-equivalent variables.

    Derives INCLUDE, LIB, PATH, and WINEPATH from the compiler configuration.
    Sets WINEDEBUG=-all when the runner is Wine/wibo, and
    REBREW_COMPILER_RUNNER to the detected/configured runner name.
    Approximates ``VCVARS32.BAT`` for invoking CL.EXE under Wine.
    """
    env = {**os.environ}
    runner = cfg.compiler_runner
    if not runner:
        try:
            parts = shlex.split(cfg.compiler_command)
        except ValueError:
            parts = cfg.compiler_command.split()
        if parts and parts[0] in {"wine", "wibo"}:
            runner = parts[0]
    if runner.lower() in {"wine", "wibo"}:
        env["WINEDEBUG"] = "-all"
    if runner:
        env["REBREW_COMPILER_RUNNER"] = runner

    # Derive bin_dir from the compiler command path.
    # e.g. "wine tools/MSVC600/VC98/Bin/CL.EXE" → "tools/MSVC600/VC98/Bin"
    try:
        parts = shlex.split(cfg.compiler_command)
    except ValueError:
        parts = cfg.compiler_command.split()
    # Skip the runner prefix (wine/wibo) to find the CL.EXE path
    cl_parts = [p for p in parts if p.lower() not in {"wine", "wibo"}]
    if cl_parts:
        cl_path = Path(cl_parts[0])
        if not cl_path.is_absolute():
            cl_path = cfg.root / cl_path
        bin_dir = str(cl_path.parent)
    else:
        bin_dir = ""
    inc_dir = str(cfg.compiler_includes)
    lib_dir = str(cfg.compiler_libs)

    # Windows-style env vars consumed by CL.EXE
    env["INCLUDE"] = inc_dir
    env["LIB"] = lib_dir

    # Ensure Wine can find C1.DLL, C2.DLL etc. alongside CL.EXE
    existing_path = env.get("WINEPATH", "")
    env["WINEPATH"] = f"{bin_dir};{existing_path}" if existing_path else bin_dir
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

    return env
