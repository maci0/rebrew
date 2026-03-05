"""Toolchain environment construction and resolution for rebrew compilers."""

import os
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig


def msvc_env_from_config(cfg: "ProjectConfig") -> dict[str, str]:
    """Return a subprocess env dict with MSVC6 VCVARS-equivalent variables.

    Sets INCLUDE, LIB, PATH (for DLL resolution), and WINEDEBUG=-all.
    This is the equivalent of running ``BIN/VCVARS32.BAT x86`` before
    invoking CL.EXE under Wine.
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

    # Resolve paths relative to project root
    bin_dir = str(cfg.root / "tools" / "MSVC600" / "VC98" / "Bin")
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
