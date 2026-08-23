"""cmake_tc.py — CMake toolchain bridge for docker-based toolchains.

The rebrew toolchain images (e.g. ``rebrew/msvc:6.0-win32``) encapsulate the
command-line tools, but CMake needs three separate executables —
``CMAKE_C_COMPILER`` / ``CMAKE_LINKER`` / ``CMAKE_AR`` — invoked with plain
argv.  These console scripts (``rebrew-cmake-cl`` / ``rebrew-cmake-link`` /
``rebrew-cmake-lib``) translate CMake's invocations into ``docker run`` calls
against the toolchain image: the same backend the rebrew compile pipeline
uses, reusable from any project's CMake build:

- the project root (found by walking up from the cwd for
  ``rebrew-project.toml``) is same-path mounted, so absolute paths in the
  arguments resolve identically inside the container;
- wine's ``Z:`` drive maps them the way the old host-wine wrapper did;
- a shared per-toolchain wineprefix is flock-initialized and the runs are
  serialized on it (concurrent wineservers on one prefix corrupt it —
  MSVC6 dies with C1900/C1083 otherwise);
- ``INCLUDE``/``LIB`` point at the image's own toolchain tree, so the image
  is self-contained.

``rebrew cmake-toolchain --toolchain msvc6`` writes the CMake toolchain file
that points ``CMAKE_C_COMPILER/LINKER/AR`` at these scripts.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.toolchain import TOOLCHAINS, ToolchainSpec

try:
    import fcntl
except ImportError:  # non-POSIX (no advisory file locks)
    fcntl = None  # type: ignore[assignment]

console = Console(stderr=True)

app = typer.Typer(
    help="Write a CMake toolchain file that drives a docker toolchain via rebrew-cmake-*.",
    rich_markup_mode="rich",
)

#: console-script basename -> tool mode
_TOOL_MODES = {
    "rebrew-cmake-cl": "cl",
    "rebrew-cmake-link": "link",
    "rebrew-cmake-lib": "lib",
}

_TOOL_EXES = {"cl": "CL.EXE", "link": "LINK.EXE", "lib": "LIB.EXE"}

#: CMake's if(MSVC_VERSION) needs a version string; per-toolchain.
_CMAKE_C_COMPILER_VERSION = {"msvc6": "12.00.8168"}

_WINE = "/usr/bin/wine"  # the rebrew base image installs wine here


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    """Advisory cross-process lock around a wineprefix/docker critical section.

    Falls back to no locking on platforms without ``flock`` (same discipline
    as :func:`rebrew.utils.metadata_write_lock`).
    """
    if fcntl is None:
        yield
        return
    with open(lock_path, "w", encoding="utf-8") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _docker_user_args() -> list[str]:
    """``--user uid:gid`` on hosts that expose unix ids (POSIX).

    Capability probe rather than an OS-name check: docker desktop hosts
    without unix uid/gid just omit the flag and use the daemon default.
    """
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        return ["--user", f"{os.getuid()}:{os.getgid()}"]
    return []


def _find_project_root(cwd: Path) -> Path | None:
    """Walk up from *cwd* for ``rebrew-project.toml`` (the mount root)."""
    for p in (cwd, *cwd.parents):
        if (p / "rebrew-project.toml").is_file():
            return p
    return None


def _load_profile(root: Path) -> str:
    try:
        with open(root / "rebrew-project.toml", "rb") as f:
            cfg = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        error_exit(f"cannot read {root}/rebrew-project.toml: {exc}")
    return str(cfg.get("compiler", {}).get("profile", "msvc6"))


def _resolve_spec(name: str) -> ToolchainSpec:
    spec = TOOLCHAINS.get(name)
    if spec is None:
        error_exit(f"unknown toolchain {name!r} (known: {sorted(TOOLCHAINS)})")
    if spec.image is None:
        error_exit(f"toolchain {name!r} has no docker image — nothing to bridge")
    if spec.tool_root is None:
        error_exit(
            f"toolchain {name!r} has no tool_root in its spec — the CMake "
            "bridge needs the container dir that holds the tools"
        )
    return spec


# ---------------------------------------------------------------------------
# Path translation + argv rewriting (ported from the project's wine wrapper)
# ---------------------------------------------------------------------------


def _to_w(p: str) -> str:
    """Absolute unix path -> wine ``Z:\\`` form; relative paths pass through."""
    if p.startswith("/"):
        return "Z:" + p.replace("/", "\\")
    return p


def _rewrite_args(mode: str, args: list[str]) -> list[str]:
    out: list[str] = []
    for arg in args:
        if mode == "cl":
            if arg.startswith("/I") and len(arg) > 2:
                d = arg[2:]
                out.append("/I" + _to_w(d) if d.startswith("/") else arg)
                continue
            if arg.startswith("/Fo"):
                p = arg[3:]
                if ".obj" in p:
                    if p.startswith("/"):
                        p = _to_w(p)
                    elif p.endswith(".obj"):
                        p = _to_w(str(Path.cwd() / p))
                out.append("/Fo" + p)
                continue
            if arg.startswith("/Fd"):
                p = arg[3:]
                if p.startswith("/"):
                    p = _to_w(p)
                elif p and p != "-":
                    p = _to_w(str(Path.cwd() / p))
                out.append("/Fd" + p)
                continue
            if arg.startswith("/Fe"):
                p = arg[3:]
                out.append("/Fe" + _to_w(p) if p.startswith("/") else arg)
                continue
            if arg.startswith("/Fp"):
                p = arg[3:]
                out.append("/Fp" + _to_w(p) if p.startswith("/") else arg)
                continue
            if arg.startswith(("/*.c", "/*.cpp", "/*.cc", "/*.cxx")):
                out.append(_to_w(arg))
                continue
            if arg.startswith(("/home/", "/tmp/", "/gamatcher/")):
                out.append(_to_w(arg))
                continue
            out.append(arg)
        elif mode == "link":
            for flag, name in (
                ("/OUT:", "OUT"),
                ("/DEF:", "DEF"),
                ("/LIBPATH:", "LIBPATH"),
                ("/IMPLIB:", "IMPLIB"),
                ("/PDB:", "PDB"),
                ("/MAP:", "MAP"),
            ):
                upper = arg.upper()
                if upper.startswith(flag.upper()) and ":" in arg:
                    out.append(f"/{name}:" + _to_w(arg.split(":", 1)[1]))
                    break
            else:
                if arg.startswith(("/home/", "/tmp/", "/gamatcher/")) or arg.startswith(
                    ("/*.obj", "/*.lib")
                ):
                    out.append(_to_w(arg))
                else:
                    out.append(arg)
        else:  # lib
            if arg.upper().startswith("/OUT:/"):
                out.append("/OUT:" + _to_w(arg[len("/OUT:") :]))
                continue
            if arg.startswith(("/home/", "/tmp/", "/gamatcher/")) or arg.startswith(
                ("/*.obj", "/*.lib")
            ):
                out.append(_to_w(arg))
                continue
            out.append(arg)
    return out


# ---------------------------------------------------------------------------
# wineprefix + docker run (same guarantees as the project wrapper)
# ---------------------------------------------------------------------------


def _wineprefix(spec: ToolchainSpec) -> Path:
    env = os.environ.get("REBREW_WINEPREFIX")
    if env:
        return Path(env)
    return Path.home() / ".cache" / f"rebrew-{spec.name}-wineprefix"


def _ensure_wineprefix(prefix: Path, spec: ToolchainSpec) -> None:
    """Initialize the shared prefix exactly once (parallel builds race)."""
    if (prefix / ".update-timestamp").exists():
        return
    prefix.mkdir(parents=True, exist_ok=True)
    assert spec.image is not None  # _resolve_spec validated it
    lock_path = prefix / ".init.lock"
    with _exclusive_lock(lock_path):
        if (prefix / ".update-timestamp").exists():
            return
        try:
            r = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none",  # wineboot needs no network
                    *_docker_user_args(),
                    "-e",
                    f"WINEPREFIX={prefix}",
                    "-v",
                    f"{prefix}:{prefix}",
                    "--entrypoint",
                    _WINE,
                    spec.image,
                    "wineboot",
                    "-u",
                ],
                capture_output=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired as exc:
            error_exit(f"wineprefix init timed out after 300s ({prefix}): {exc}")
        if r.returncode != 0:
            # A half-initialized prefix makes every later compile fail with
            # confusing wine errors — fail here where the cause is visible.
            stderr = r.stderr.decode(errors="replace")[-400:].strip()
            error_exit(f"wineprefix init failed (rc={r.returncode}) at {prefix}: {stderr}")


def _docker_run(spec: ToolchainSpec, mode: str, args: list[str]) -> int:
    root = _find_project_root(Path.cwd())
    if root is None:
        error_exit(
            "rebrew-cmake-*: no rebrew-project.toml found above the cwd — run "
            "CMake from inside the project (build dir under the project root)"
        )
    prefix = _wineprefix(spec)
    _ensure_wineprefix(prefix, spec)

    tool_root = Path(spec.tool_root)  # type: ignore[arg-type]  # validated above
    assert spec.image is not None  # _resolve_spec validated it
    inc = "Z:" + str(tool_root.parent / "Include").replace("/", "\\")
    lib = "Z:" + str(tool_root.parent / "Lib").replace("/", "\\")

    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",  # compile-only containers — no egress needed
        *_docker_user_args(),
        "-e",
        f"WINEPREFIX={prefix}",
        "-e",
        f"XDG_CACHE_HOME={prefix}/xdg-cache",
        "-e",
        f"INCLUDE={inc}",
        "-e",
        f"LIB={lib}",
        "-v",
        f"{root}:{root}",
        "-v",
        f"{prefix}:{prefix}",
        "-w",
        str(Path.cwd()),
        "--entrypoint",
        _WINE,
        spec.image,
        str(tool_root / _TOOL_EXES[mode]),
        *_rewrite_args(mode, args),
    ]

    with _exclusive_lock(prefix / ".run.lock"):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    sys.stdout.write((r.stdout + r.stderr).replace("\r", ""))
    sys.stdout.flush()
    return r.returncode


def tc_main() -> None:
    """Console-script entry: dispatch by argv[0] basename (cl/link/lib)."""
    mode = _TOOL_MODES.get(Path(sys.argv[0]).name)
    if mode is None:
        error_exit(f"rebrew-cmake-*: unknown invocation name {Path(sys.argv[0]).name!r}")
    root = _find_project_root(Path.cwd())
    if root is None:
        error_exit(
            "rebrew-cmake-*: no rebrew-project.toml found above the cwd — run "
            "CMake from inside the project (build dir under the project root)"
        )
    name = os.environ.get("REBREW_TOOLCHAIN") or _load_profile(root)
    spec = _resolve_spec(name)
    sys.exit(_docker_run(spec, mode, sys.argv[1:]))


# ---------------------------------------------------------------------------
# `rebrew cmake-toolchain` — generate the CMake toolchain file
# ---------------------------------------------------------------------------


def generate_toolchain_file(spec: ToolchainSpec, out_dir: Path) -> Path:
    """Write ``toolchain-<name>-docker.cmake`` pointing at rebrew-cmake-*."""
    version = _CMAKE_C_COMPILER_VERSION.get(spec.name, "12.00.8168")
    name = spec.name
    text = f"""# CMake toolchain file for {name} via the rebrew docker image (wine inside).
# Generated by `rebrew cmake-toolchain --toolchain {name}` — do not hand-edit.
#
# The rebrew-cmake-{{cl,link,lib}} console scripts (from the rebrew CLI on
# PATH) translate CMake invocations into docker runs against {spec.image}.
# Build the image first:  rebrew toolchain build {name}
#
# Usage:
#   cmake -B build --toolchain cmake/toolchain-{name}-docker.cmake -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j8

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86)

set(CMAKE_C_COMPILER "rebrew-cmake-cl")
set(CMAKE_LINKER "rebrew-cmake-link")
set(CMAKE_AR "rebrew-cmake-lib")

set(CMAKE_C_COMPILER_ID "MSVC" CACHE STRING "" FORCE)
set(CMAKE_C_COMPILER_VERSION "{version}" CACHE STRING "" FORCE)
set(CMAKE_C_COMPILER_FORCED TRUE)
set(CMAKE_C_COMPILER_WORKS TRUE CACHE BOOL "" FORCE)

set(CMAKE_SIZEOF_VOID_P 4 CACHE STRING "" FORCE)

set(CMAKE_C_OUTPUT_EXTENSION ".obj")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".lib")
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
set(CMAKE_IMPORT_LIBRARY_PREFIX "")
set(CMAKE_IMPORT_LIBRARY_SUFFIX ".lib")
set(CMAKE_EXECUTABLE_SUFFIX ".exe")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
"""
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"toolchain-{name}-docker.cmake"
    out.write_text(text, encoding="utf-8")
    return out


@app.callback(invoke_without_command=True)
def main(
    toolchain: str = typer.Option("msvc6", "--toolchain", "-t", help="Toolchain name"),
    out: Path = typer.Option(
        Path("cmake"), "--out", "-o", help="Output dir for the toolchain file"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Write a CMake toolchain file for a docker-based toolchain.

    The generated file sets CMAKE_C_COMPILER/LINKER/AR to the
    ``rebrew-cmake-{cl,link,lib}`` console scripts, which run the tools
    inside the toolchain image (see the module docstring).
    """
    spec = _resolve_spec(toolchain)
    written = generate_toolchain_file(spec, out)
    if json_output:
        json_print({"toolchain": toolchain, "written": str(written)})
    else:
        console.print(f"[green]cmake-toolchain:[/] wrote {written}")
        console.print(
            f"  use it with: cmake -B build --toolchain {written} -DCMAKE_BUILD_TYPE=Release"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
