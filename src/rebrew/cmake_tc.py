"""cmake_tc.py — CMake toolchain bridge for image-backed toolchains.

The rebrew toolchain images (e.g. ``rebrew/msvc:6.0-win32``) encapsulate the
command-line tools, but CMake needs three tool commands —
``CMAKE_C_COMPILER`` / ``CMAKE_LINKER`` / ``CMAKE_AR`` — invoked with plain
argv. ``rebrew build driver <cl|link|lib> -- <arguments>`` translates
CMake's invocations into image-backed calls using the project compiler
execution_backend (Docker/Podman or opt-in native unshare):

- the project root (found by walking up from the cwd for
  ``rebrew-project.toml``) is same-path mounted, so absolute paths in the
  arguments resolve identically inside the container;
- wine's ``Z:`` drive maps them the way the old host-wine wrapper did;
- Docker/Podman use a shared per-toolchain wineprefix, flock-initialized and the runs are
  serialized on it (concurrent wineservers on one prefix corrupt it —
  MSVC6 dies with C1900/C1083 otherwise); unshare uses a private image overlay;
- ``INCLUDE``/``LIB`` point at the image's own toolchain tree, so the image
  is self-contained.

``rebrew build cmake-toolchain --toolchain msvc-6.0`` writes the CMake toolchain file
that points ``CMAKE_C_COMPILER/LINKER/AR`` at the single rebrew executable.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
lazy import os
lazy import re
lazy import subprocess
lazy import sys
lazy import tempfile
lazy import tomllib
lazy import uuid
lazy from dataclasses import replace
lazy from typing import Any

import typer

lazy from rebrew.cli import console, error_exit, json_print, option_default, require_config
lazy from rebrew.compiler.temp_dirs import xdg_cache_home
lazy from rebrew.compiler.toolchain import ToolchainSpec, bind_mount, kill_container
lazy from rebrew.config import ConfigError, check_env_wineprefix, source_date_epoch
lazy from rebrew.utils import (
    atomic_write_text,
    container_runtime,
    file_lock,
    load_tomllib,
    read_compile_source,
)
lazy from rebrew.workspace import walk_up_to_root

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  # Write cmake/toolchain-msvc-6.0-docker.cmake\n"
    "  rebrew build cmake-toolchain --toolchain msvc-6.0\n\n"
    "  # Choose the output directory\n"
    "  rebrew build cmake-toolchain --toolchain gcc-14.2.0 --output cmake/\n\n"
    "  cmake -B build --toolchain cmake/toolchain-msvc-6.0-docker.cmake\n\n"
    "[dim]Then configure and build as usual; the file routes cl/link/lib through rebrew build driver cl/link/lib.[/dim]\n"
)


app = typer.Typer(
    help="Write a CMake toolchain file that drives a docker toolchain via rebrew.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


class ToolMode(StrEnum):
    """Compiler, linker, or archiver selection for the CMake bridge."""

    CL = "cl"
    LINK = "link"
    LIB = "lib"


_TOOL_EXES = {"cl": "CL.EXE", "link": "LINK.EXE", "lib": "LIB.EXE"}

#: CMake's if(MSVC_VERSION) needs a version string; per-toolchain, derived
#: from the detection tables (linker era + Rich-header compiler build) so
#: every MSVC profile stamps its own compiler version instead of msvc-6.0's.
#: Unknown (non-MSVC) profiles stamp "0.0.0" — the generated file already
#: hardcodes CMAKE_C_COMPILER_ID MSVC, and the bridge rejects non-wine
#: profiles before generation (see _resolve_spec).
_CMAKE_C_COMPILER_VERSION_FALLBACK = "0.0.0"


def _cmake_c_compiler_versions() -> dict[str, str]:
    """Per-toolchain ``CMAKE_C_COMPILER_VERSION`` from the version tables.

    ``{M}.{mm:02d}.{build}`` (the CL file-version shape, e.g. msvc-6.0's
    ``12.00.8168``); era-only when no Rich build is known for the profile
    (e.g. msvc-2.0 → ``9.00``).
    """
    from rebrew.toolchain_detect import detection_tables

    # One snapshot: a profile must not be era-only to this reader and
    # build-pinned to the next line.
    tables = detection_tables()
    era_of: dict[str, tuple[int, int]] = {}
    for mm, profiles in tables.linker_era_profiles.items():
        for p in profiles:
            era_of.setdefault(p, mm)
    build_of: dict[str, int] = {}
    for build, profiles in tables.rich_build_profiles.items():
        for p in profiles:
            build_of.setdefault(p, build)
    out: dict[str, str] = {}
    for profile, mm in era_of.items():
        base = f"{mm[0]}.{mm[1]:02d}"
        out[profile] = f"{base}.{build_of[profile]}" if profile in build_of else base
    return out


_WINE = "/usr/bin/wine"  # the rebrew base image installs wine here


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _docker_user_args() -> list[str]:
    """``--user uid:gid`` on hosts that expose unix ids (POSIX).

    Capability probe rather than an OS-name check: docker desktop hosts
    without unix uid/gid just omit the flag and use the daemon default.
    """
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        return ["--user", f"{os.getuid()}:{os.getgid()}"]
    return []


def _load_profile(root: Path) -> str:
    try:
        cfg = load_tomllib(root / "rebrew-project.toml")
    except (OSError, tomllib.TOMLDecodeError) as exc:
        error_exit(f"cannot read {root}/rebrew-project.toml: {exc}")
    # A target may override the project compiler profile.  CMake fixes one
    # compiler for the whole tree and has no Rebrew target identity, so fall
    # back to the project's default target: building with the project-level
    # profile there emits the wrong code generator for any target that
    # overrides it (a Processor-Pack target compiled as plain SP5 produces the
    # non-PP x87 compare idiom).
    project = cfg.get("project", {})
    default_target = project.get("default_target") if isinstance(project, dict) else None
    targets = cfg.get("targets", {})
    if isinstance(default_target, str) and isinstance(targets, dict):
        target = targets.get(default_target)
        if isinstance(target, dict):
            target_compiler = target.get("compiler")
            if isinstance(target_compiler, dict) and target_compiler.get("profile"):
                return str(target_compiler["profile"])
    return str(cfg.get("compiler", {}).get("profile", "msvc-6.0"))


def _resolve_spec(name: str, *, json_mode: bool = False) -> ToolchainSpec:
    from rebrew.compiler import toolchain

    registry, _origins = toolchain.registry_snapshot()
    spec = registry.get(name)
    if spec is None:
        error_exit(f"unknown toolchain {name!r} (known: {sorted(registry)})", json_mode=json_mode)
    if spec.image is None:
        error_exit(
            f"toolchain {name!r} has no docker image — nothing to bridge", json_mode=json_mode
        )
    if spec.runtime != "wine":
        error_exit(
            f"toolchain {name!r} runs through a {spec.runtime} image ({spec.image}) — "
            "the CMake bridge drives wine-runnable CL.EXE/LINK.EXE/LIB.EXE only; "
            f"{spec.runtime}-encapsulated images expose entrypoint wrappers, not "
            "separate link/lib tools. Use a wine-based MSVC profile "
            "(e.g. --toolchain msvc-6.0) for CMake builds",
            json_mode=json_mode,
        )
    if spec.tool_root is None:
        error_exit(
            f"toolchain {name!r} has no tool_root in its spec — the CMake "
            "bridge needs the container dir that holds the tools "
            f"(image {spec.image}). Plugin toolchains must declare tool_root",
            json_mode=json_mode,
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


def _is_host_path(arg: str) -> bool:
    """True when *arg* is an absolute POSIX path wine must see as ``Z:\\``.

    Capability probe rather than a hardcoded directory list (/home, /tmp,
    ...): any second slash after the leading one marks a multi-segment path,
    while MSVC option flags (``/O2``, ``/Gd``, ``/nologo``) are a single
    slash plus one flag word and never contain another.  A root-level
    ``/name`` counts only when it exists on the host.
    """
    if not arg.startswith("/") or len(arg) < 2:
        return False
    rest = arg[1:]
    return "/" in rest or os.path.exists(arg)


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
            out.append(_to_w(arg) if _is_host_path(arg) else arg)
        elif mode == "link":
            if arg.upper().startswith("/ORDER:@"):
                out.append("/ORDER:@" + _to_w(arg[len("/ORDER:@") :]))
                continue
            for flag, name in (
                ("/OUT:", "OUT"),
                ("/DEF:", "DEF"),
                ("/STUB:", "STUB"),
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
                if _is_host_path(arg) or arg.startswith(("/*.obj", "/*.lib")):
                    out.append(_to_w(arg))
                else:
                    out.append(arg)
        else:  # lib
            for flag in ("/OUT:", "/DEF:", "/LIST:", "/LIBPATH:"):
                if arg.upper().startswith(flag):
                    out.append(flag + _to_w(arg[len(flag) :]))
                    break
            else:
                host_path = _is_host_path(arg) or arg.startswith(("/*.obj", "/*.lib"))
                out.append(_to_w(arg) if host_path else arg)
    return out


# ---------------------------------------------------------------------------
# wineprefix + docker run (same guarantees as the project wrapper)
# ---------------------------------------------------------------------------


def _wineprefix(spec: ToolchainSpec) -> Path:
    """``REBREW_WINEPREFIX`` (must be absolute), else the per-toolchain XDG cache dir.

    A relative prefix would resolve against CMake's per-target build dir and
    reach ``docker -v`` as a named volume instead of a bind mount.
    """
    env = os.environ.get("REBREW_WINEPREFIX", "").strip()
    if env:
        try:
            check_env_wineprefix(env)
        except ConfigError as exc:
            error_exit(str(exc))
        return Path(env).expanduser()
    return xdg_cache_home() / f"rebrew-{spec.name}-wineprefix"


def _ensure_wineprefix(prefix: Path, spec: ToolchainSpec, *, runtime: str | None = None) -> None:
    """Initialize the shared prefix exactly once (parallel builds race)."""
    runtime_options: dict[str, Any] = {"runtime": runtime} if runtime else {}
    if (prefix / ".update-timestamp").exists():
        return
    prefix.mkdir(parents=True, exist_ok=True)
    assert spec.image is not None  # _resolve_spec validated it
    lock_path = prefix / ".init.lock"
    with file_lock(lock_path):
        if (prefix / ".update-timestamp").exists():
            return
        name = f"rebrew-{spec.name}-wineboot-{uuid.uuid4().hex[:12]}"
        try:
            r = subprocess.run(
                [
                    container_runtime(runtime) if runtime else container_runtime(),
                    "run",
                    "--rm",
                    "--network=none",  # wineboot needs no network
                    "--security-opt=no-new-privileges",  # no setuid escalation inside the image
                    "--name",
                    name,
                    *_docker_user_args(),
                    "-e",
                    f"WINEPREFIX={prefix}",
                    "-v",
                    bind_mount(prefix, prefix),
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
            kill_container(name, **runtime_options)
            error_exit(f"wineprefix init timed out after 300s ({prefix}): {exc}")
        except BaseException:
            # Ctrl+C kills the docker CLI but leaves the container running.
            kill_container(name, **runtime_options)
            raise
        if r.returncode != 0:
            # A half-initialized prefix makes every later compile fail with
            # confusing wine errors — fail here where the cause is visible.
            stderr = r.stderr.decode("utf-8", errors="replace")[-400:].strip()
            error_exit(f"wineprefix init failed (rc={r.returncode}) at {prefix}: {stderr}")
        # Stamp the initialized prefix while the lock is still held, so the
        # two guards above actually mean "exactly once".  Without it every
        # rebrew build driver invocation serialized on this lock behind another
        # wineboot against the same live prefix.
        (prefix / ".update-timestamp").write_text("", encoding="utf-8")


def _rewrite_response_files(mode: str, args: list[str], directory: Path) -> list[str]:
    """Copy response files with POSIX paths translated for Wine; keep originals."""
    active: set[Path] = set()

    def copy_arg(arg: str) -> str:
        if not arg.startswith("@"):
            return arg
        source = Path(arg[1:].strip('"')).resolve()
        if source in active:
            raise ValueError(f"Recursive response file: {source}")
        active.add(source)
        # CMake writes response files in the host encoding; the locale default
        # raises or mojibakes a non-ASCII path.  surrogateescape on both sides
        # copies every byte through unchanged.
        content = read_compile_source(source)

        # Rewrite whole quoted/unquoted tokens, retaining response-file quoting.
        def rewrite(match: re.Match[str]) -> str:
            token = match.group(0)
            quoted = token.startswith('"')
            value = token[1:-1] if quoted else token
            value = copy_arg(value) if value.startswith("@") else _rewrite_args(mode, [value])[0]
            return '"' + value + '"' if quoted else value

        content = re.sub(r'"[^"\r\n]*"|[^\s"]+', rewrite, content)
        active.remove(source)
        dest = directory / (uuid.uuid4().hex + ".rsp")
        dest.write_text(content, encoding="utf-8", errors="surrogateescape")
        return "@" + _to_w(str(dest))

    return [copy_arg(arg) for arg in args]


def _docker_run(
    spec: ToolchainSpec, mode: str, args: list[str], *, runtime: str | None = None
) -> int:
    runtime_options: dict[str, Any] = {"runtime": runtime} if runtime else {}
    root = walk_up_to_root(Path.cwd())
    if root is None:
        error_exit(
            "rebrew build driver: no rebrew-project.toml found above the cwd — run "
            "CMake from inside the project (build dir under the project root)"
        )
    prefix = _wineprefix(spec)
    _ensure_wineprefix(prefix, spec, **runtime_options)

    assert spec.tool_root is not None  # _resolve_spec validated it
    tool_root = Path(spec.tool_root)
    assert spec.image is not None  # _resolve_spec validated it
    inc = "Z:" + str(tool_root.parent / "Include").replace("/", "\\")
    lib = "Z:" + str(tool_root.parent / "Lib").replace("/", "\\")
    epoch = source_date_epoch()

    cmd = [
        container_runtime(runtime) if runtime else container_runtime(),
        "run",
        "--rm",
        "--network=none",  # compile-only containers — no egress needed
        "--security-opt=no-new-privileges",  # no setuid escalation inside the image
        "--name",
        f"rebrew-{spec.name}-{mode}-{uuid.uuid4().hex[:12]}",
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
        bind_mount(root, root),
        "-v",
        bind_mount(prefix, prefix),
        "-w",
        str(Path.cwd()),
        "--entrypoint",
        "/usr/local/bin/rebrew-clock" if epoch is not None else _WINE,
        spec.image,
    ]
    if epoch is not None:
        position = cmd.index("--entrypoint")
        cmd[position:position] = ["-e", f"SOURCE_DATE_EPOCH={epoch}"]
        cmd.append(_WINE)
    cmd.append(str(tool_root / _TOOL_EXES[mode]))

    with tempfile.TemporaryDirectory(prefix="rebrew-rsp-", dir=root) as rsp_dir:
        cmd.extend(_rewrite_args(mode, _rewrite_response_files(mode, args, Path(rsp_dir))))
        with file_lock(prefix / ".run.lock"):
            try:
                r = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=3600,
                )
            except OSError:
                # The docker CLI could not start, so there is nothing to kill.
                raise
            except BaseException:
                # Timeout/Ctrl+C kills the CLI; dockerd may still be running
                # Wine. Clean up before releasing the shared prefix lock.
                kill_container(str(cmd[cmd.index("--name") + 1]), **runtime_options)
                raise
    sys.stdout.write((r.stdout + r.stderr).replace("\r", ""))
    sys.stdout.flush()
    return r.returncode


def _unshare_run(
    spec: ToolchainSpec, mode: str, args: list[str], *, image_id: str | None = None
) -> int:
    """Run CMake tools in a private image overlay, retaining host project paths."""
    from rebrew.compiler.toolchain import cached_image_digest, run_toolchain

    root = walk_up_to_root(Path.cwd())
    assert root is not None  # driver_main validated the project root
    assert spec.image is not None and spec.tool_root is not None
    epoch = source_date_epoch()
    entrypoint = "/usr/local/bin/rebrew-clock" if epoch is not None else _WINE
    command = ([_WINE] if epoch is not None else []) + [
        str(Path(spec.tool_root) / _TOOL_EXES[mode])
    ]
    with tempfile.TemporaryDirectory(prefix="rebrew-rsp-", dir=root) as rsp_dir:
        command.extend(_rewrite_args(mode, _rewrite_response_files(mode, args, Path(rsp_dir))))
        result = run_toolchain(
            replace(spec, image_entrypoint=entrypoint),
            command,
            workdir=root,
            project_cwd=Path.cwd(),
            image_id=image_id or cached_image_digest(spec.image),
            execution_backend="unshare",
            timeout=3600,
        )
    sys.stdout.write((result.stdout + result.stderr).replace("\r", ""))
    sys.stdout.flush()
    return result.returncode


def driver_main(
    mode: ToolMode = typer.Argument(..., metavar="MODE", help="Tool to invoke: cl, link, or lib"),
    args: list[str] = typer.Argument(None, help="Tool arguments (place flags after --)"),
) -> None:
    """Run a CMake tool: rebrew build driver <cl|link|lib> -- <arguments>."""
    root = walk_up_to_root(Path.cwd())
    if root is None:
        error_exit(
            "rebrew build driver: no rebrew-project.toml found above the cwd — run "
            "CMake from inside the project (build dir under the project root)"
        )
    # Per-file compiler selection.  CMake fixes one compiler for the whole
    # target through the toolchain file, and COMPILE_FLAGS is the only per-file
    # lever it has -- so accept the toolchain as a pseudo-flag and strip it
    # before the real command line is built.  Without this a per-function
    # toolchain pin could only ever affect `rebrew test`, never the linked
    # bytes (guild-rebrew round 224 measured a real +11 byte gain that was
    # unreachable for exactly this reason).
    argv = []
    pinned: str | None = None
    # The generated default comes first; a later per-file pin overrides it.
    for a in args or []:
        if a.startswith(("/REBREW_TOOLCHAIN:", "-REBREW_TOOLCHAIN:")):
            pinned = a.split(":", 1)[1]
        else:
            argv.append(a)
    name = pinned or os.environ.get("REBREW_TOOLCHAIN", "").strip() or _load_profile(root)
    spec = _resolve_spec(name)
    from rebrew.compiler.toolchain import ToolchainError

    # CMake has a profile pin, but no Rebrew target identity: use the project backend.
    backend = (
        load_tomllib(root / "rebrew-project.toml").get("compiler", {}).get("execution_backend", "")
    )
    if backend not in ("", "docker", "podman", "unshare"):
        error_exit("compiler.execution_backend must be docker, podman, or unshare")
    try:
        if backend == "unshare":
            if mode == ToolMode.CL:
                from rebrew.cmake_cache import run_cached_cl

                rc = run_cached_cl(
                    root,
                    spec,
                    argv,
                    lambda image: _unshare_run(
                        spec, mode.value, argv, **({"image_id": image} if image else {})
                    ),
                )
            else:
                rc = _unshare_run(spec, mode.value, argv)
        else:
            rc = _docker_run(spec, mode.value, argv, **({"runtime": backend} if backend else {}))
    except ToolchainError as exc:
        error_exit(str(exc))
    except subprocess.TimeoutExpired:
        # A hung wine build must exit with a clean message, not a raw
        # traceback polluting CMake's error output.
        error_exit(f"rebrew build driver {mode.value}: toolchain command timed out (3600s)")
    sys.exit(rc)


# ---------------------------------------------------------------------------
# `rebrew build cmake-toolchain` — generate the CMake toolchain file
# ---------------------------------------------------------------------------


def generate_toolchain_file(spec: ToolchainSpec, out_dir: Path) -> Path:
    """Write a CMake toolchain and rule overrides using the rebrew executable."""
    version = _cmake_c_compiler_versions().get(spec.name, _CMAKE_C_COMPILER_VERSION_FALLBACK)
    name = spec.name
    text = f"""# CMake toolchain file for {name} via the rebrew docker image (wine inside).
# Generated by `rebrew build cmake-toolchain --toolchain {name}` — do not hand-edit.
#
# rebrew build driver cl/link/lib translates CMake invocations into
# docker runs against {spec.image}.
# Build the image first:  rebrew toolchain build {name}
#
# Usage:
#   cmake -B build --toolchain cmake/toolchain-{name}-docker.cmake -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j8

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86)

# Re-resolve on configure; a previous uv environment may no longer exist.
unset(_REBREW_EXECUTABLE CACHE)
unset(_REBREW_EXECUTABLE)
if(DEFINED ENV{{REBREW_EXECUTABLE}} AND NOT "$ENV{{REBREW_EXECUTABLE}}" STREQUAL "")
  set(_REBREW_EXECUTABLE "$ENV{{REBREW_EXECUTABLE}}")
  if(NOT IS_ABSOLUTE "${{_REBREW_EXECUTABLE}}" OR NOT EXISTS "${{_REBREW_EXECUTABLE}}" OR IS_DIRECTORY "${{_REBREW_EXECUTABLE}}")
    message(FATAL_ERROR "REBREW_EXECUTABLE must name an existing absolute executable path; activate the Rebrew environment and reconfigure")
  endif()
else()
  find_program(_REBREW_EXECUTABLE NAMES rebrew)
endif()
if(NOT _REBREW_EXECUTABLE)
  message(FATAL_ERROR "rebrew not found on PATH; activate the Rebrew environment")
endif()
set(CMAKE_C_COMPILER "${{_REBREW_EXECUTABLE}}")
set(CMAKE_C_COMPILER_ARG1 "build driver cl -- /REBREW_TOOLCHAIN:{name}")
set(CMAKE_LINKER "${{_REBREW_EXECUTABLE}}")
set(CMAKE_AR "${{_REBREW_EXECUTABLE}}")
set(REBREW_CMAKE_AR_COMMAND "${{_REBREW_EXECUTABLE}}" build driver lib -- /REBREW_TOOLCHAIN:{name})
set(CMAKE_USER_MAKE_RULES_OVERRIDE_C "${{CMAKE_CURRENT_LIST_DIR}}/rules-{name}-docker.cmake")

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
    rules = out_dir / f"rules-{name}-docker.cmake"
    atomic_write_text(
        rules,
        "# Generated by rebrew build cmake-toolchain; preserves CMake's MSVC rules.\n"
        "foreach(rule CREATE_SHARED_LIBRARY CREATE_SHARED_MODULE LINK_EXECUTABLE)\n"
        f'  string(REPLACE "<CMAKE_LINKER>" "<CMAKE_LINKER> build driver link -- /REBREW_TOOLCHAIN:{name}"\n'
        '    CMAKE_C_${rule} "${CMAKE_C_${rule}}")\n'
        "endforeach()\n"
        "foreach(rule CREATE_STATIC_LIBRARY CREATE_STATIC_LIBRARY_IPO)\n"
        f'  string(REPLACE "<CMAKE_AR>" "<CMAKE_AR> build driver lib -- /REBREW_TOOLCHAIN:{name}"\n'
        '    CMAKE_C_${rule} "${CMAKE_C_${rule}}")\n'
        "endforeach()\n",
        encoding="utf-8",
    )
    out = out_dir / f"toolchain-{name}-docker.cmake"
    atomic_write_text(out, text, encoding="utf-8")
    return out


@app.callback(invoke_without_command=True)
def main(
    toolchain: str | None = typer.Option(
        None,
        "--toolchain",
        help="Toolchain profile (default: project profile, or msvc-6.0 outside a project)",
    ),
    output: Path = typer.Option(
        Path("cmake"), "--output", "-o", help="Output dir for the toolchain file"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Write a CMake toolchain file for a docker-based toolchain.

    The generated file sets CMAKE_C_COMPILER/LINKER/AR to the
    rebrew build driver cl/link/lib commands, which run the tools
    inside the toolchain image (see the module docstring).
    """
    toolchain = option_default(toolchain, None)
    if toolchain is None:
        project_root = walk_up_to_root(Path.cwd())
        toolchain = (
            require_config(root=project_root, json_mode=json_output).compiler_profile
            if project_root is not None
            else "msvc-6.0"
        )
    spec = _resolve_spec(toolchain, json_mode=json_output)
    planned = output / f"toolchain-{spec.name}-docker.cmake"
    if dry_run:
        if json_output:
            json_print({"toolchain": toolchain, "output": str(planned), "dry_run": True})
        else:
            console.print(
                f"[cyan]dry-run:[/cyan] would write the {toolchain} toolchain file to {planned}"
            )
        return
    written = generate_toolchain_file(spec, output)
    if json_output:
        json_print({"toolchain": toolchain, "output": str(written), "dry_run": False})
    else:
        console.print(f"[green]cmake-toolchain:[/] wrote {written}")
        console.print(
            f"  use it with: cmake -B build --toolchain {written} -DCMAKE_BUILD_TYPE=Release"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
