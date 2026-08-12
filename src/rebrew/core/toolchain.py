"""MSVC environment setup for rebrew compiler invocation under Wine/wibo.

Provides ``msvc_env_from_config()`` to construct subprocess environment
variables (INCLUDE, LIB, PATH, WINEPATH, WINEDEBUG) from a project
configuration.
"""

import os
from pathlib import Path
from typing import TYPE_CHECKING

from rebrew.utils import safe_shlex_split

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig


def resolve_runner_path(runner: str, root: Path) -> str:
    """Resolve a relative runner path (e.g. ``tools/wibo``) against *root*.

    Bare names (``wine``, ``wibo``) and absolute paths pass through
    unchanged — they resolve via PATH or are already absolute.  Path-like
    relative runners break under ``subprocess(cwd=workdir)`` because the
    compile workdir is a temp dir, so they must be anchored to the project
    root (this is the config shape ``rebrew init --install-wibo`` writes).
    """
    rp = Path(runner)
    if rp.is_absolute() or "/" not in runner and "\\" not in runner:
        return runner
    return str(root / rp)


def msvc_env_from_config(cfg: "ProjectConfig") -> dict[str, str]:
    """Return a subprocess env dict with MSVC6 VCVARS-equivalent variables.

    Derives INCLUDE, LIB, PATH, and WINEPATH from the compiler configuration.
    Sets WINEDEBUG=-all when the runner is Wine/wibo, and
    REBREW_COMPILER_RUNNER to the detected/configured runner name.
    Approximates ``VCVARS32.BAT`` for invoking CL.EXE under Wine.
    """
    env = {**os.environ}
    parts = safe_shlex_split(cfg.compiler_command)
    runner = cfg.compiler_runner
    if not runner and parts and parts[0] in {"wine", "wibo"}:
        runner = parts[0]
    # Basename match ("tools/wibo" is still wibo) so WINEDEBUG applies to
    # the --install-wibo config shape.
    if runner and Path(runner).name.lower() in {"wine", "wibo"}:
        env["WINEDEBUG"] = "-all"
    if runner:
        env["REBREW_COMPILER_RUNNER"] = resolve_runner_path(runner, cfg.root)
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
