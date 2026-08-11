"""toolchain.py — standardized toolchain invocation (docker-first, host fallback).

Modeled on Godbolt / Compiler Explorer's convention: **one container image
per toolchain-version**, with the compiler behind a wrapper inside the image
so the host invocation is uniform — ``docker run <image> <compiler> <args>``.
The image encapsulates the runtime quirks (MSVC under wine, DCC under
DOSBox), so the host-side code never needs per-toolchain runner glue.

Rebrew adds a **host-path fallback**: a spec may resolve to a vendored
directory (``tools/MSVC600`` etc.) or a PATH binary instead of an image, so
the same profile works whether or not docker is available.  The runner picks
the backend in order: docker image → host path → PATH.

A :class:`ToolchainSpec` describes how to invoke one compiler version:
its image tag, the compiler executable (and any wrapper), and the flag
style/object-format conventions the rest of rebrew needs to drive it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_RUN_TIMEOUT = 300

_docker_available_cache: bool | None = None


class ToolchainError(RuntimeError):
    """The toolchain cannot be invoked (missing image/path/binary)."""


@dataclass(frozen=True)
class ToolchainSpec:
    """How to invoke one compiler version."""

    name: str  # e.g. "msvc6", "delphi16", "watcom"
    image: str | None  # docker image tag, e.g. "rebrew/msvc6:latest"; None = host-only
    binary: str = ""  # host executable name (vendored dir / PATH)
    image_binary: str | None = None  # entry binary inside the container (a shim,
    # e.g. "dcc" wrapping DCC.EXE); defaults to *binary*
    runtime: str = "native"  # "native" | "wine" | "dosbox" — informational; the
    # image wrapper encapsulates it, host fallback uses it for env setup
    flags_style: str = "msvc"  # "msvc" | "posix"
    obj_ext: str = ".obj"
    host_path: str | Path | None = None  # vendored dir (host fallback)
    host_bin: str = "Bin"  # subdir of host_path holding the compiler (Bin for
    # MSVC, binl for Watcom, "" for the root — Delphi)
    description: str = ""


@dataclass
class RunResult:
    """Outcome of a toolchain invocation."""

    returncode: int
    stdout: str
    stderr: str
    backend: str  # "docker" | "host"

    @property
    def ok(self) -> bool:
        return self.returncode == 0


# ---------------------------------------------------------------------------
# Registry — the canonical toolchain list.  Profiles in config.py map to
# these by name; `rebrew toolchain list` shows them.
# ---------------------------------------------------------------------------

_REPO_TOOLS = Path(__file__).resolve().parents[2] / "tools"


def _vendored(sub: str) -> Path:
    return _REPO_TOOLS / sub


TOOLCHAINS: dict[str, ToolchainSpec] = {
    "msvc6": ToolchainSpec(
        name="msvc6",
        image="rebrew/msvc6:latest",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("MSVC600") if _vendored("MSVC600").exists() else None,
        description="MSVC 6.0 (32-bit PE, C89) — wine or wibo",
    ),
    "delphi16": ToolchainSpec(
        name="delphi16",
        image="rebrew/delphi16:latest",
        binary="DCC.EXE",
        image_binary="dcc",
        runtime="dosbox",
        flags_style="msvc",
        obj_ext=".exe",  # DCC emits a linked NE, not an object
        host_path=_vendored("DELPHI10"),
        description="Borland Delphi 1.0 (16-bit NE) — DOSBox",
    ),
    "gcc-pe": ToolchainSpec(
        name="gcc-pe",
        image=None,
        binary="i686-w64-mingw32-gcc",
        runtime="native",
        flags_style="posix",
        obj_ext=".o",
        description="MinGW GCC / Zig (PE/x86_32) — native PATH binary",
    ),
    "watcom": ToolchainSpec(
        name="watcom",
        image="rebrew/watcom:latest",
        binary="wcc386",
        runtime="native",
        flags_style="posix",
        obj_ext=".o",  # wcc386 emits OMF (8086 relocatable) — see OMF note
        host_path=_vendored("WATCOM") if _vendored("WATCOM").exists() else None,
        host_bin="binl",
        description="Open Watcom 2.0 (x86 32-bit) — native Linux wcc386",
    ),
    "msvc1.52": ToolchainSpec(
        name="msvc1.52",
        image="rebrew/msvc152:latest",
        binary="CL.EXE",
        image_binary="cl16",
        runtime="dosbox",
        flags_style="msvc",
        obj_ext=".obj",  # 16-bit OMF — see docs/OMF_NOTES.md
        host_path=_vendored("MSVC152") if _vendored("MSVC152").exists() else None,
        description="MSVC 1.52 (16-bit, Windows 3.x) — DOSBox via rebrew.msvc16",
    ),
}


def get_toolchain(name: str) -> ToolchainSpec:
    """Look up a toolchain by name (profile id)."""
    try:
        return TOOLCHAINS[name]
    except KeyError:
        raise ToolchainError(f"unknown toolchain {name!r} (known: {sorted(TOOLCHAINS)})") from None


def docker_available() -> bool:
    """True when docker is installed and its daemon responds (cached)."""
    global _docker_available_cache
    if _docker_available_cache is None:
        try:
            r = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            _docker_available_cache = r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            _docker_available_cache = False
    return _docker_available_cache


_image_presence: dict[str, bool] = {}


def _image_present(tag: str) -> bool:
    """True when a docker image for *tag* is present locally (cached)."""
    if tag in _image_presence:
        return _image_presence[tag]
    if not docker_available():
        return False
    r = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
        text=True,
        timeout=30,
    )
    _image_presence[tag] = r.returncode == 0
    return _image_presence[tag]


def _resolve_binary(spec: ToolchainSpec) -> str:
    """The host-side compiler path for a spec (host fallback): vendored dir /
    PATH binary.  Raises ToolchainError when nothing resolvable exists."""
    if spec.host_path is not None:
        host = Path(spec.host_path)
        candidates = [host / spec.binary, host / spec.host_bin / spec.binary]
        for c in candidates:
            if c.exists():
                return str(c)
    found = shutil.which(spec.binary)
    if found:
        return found
    raise ToolchainError(
        f"toolchain {spec.name!r}: no docker image ({spec.image or 'n/a'}) pulled and no "
        f"host binary ({spec.binary}) found — run `rebrew toolchain pull {spec.name}` "
        "or vendor the toolchain under tools/"
    )


def run_toolchain(
    spec: ToolchainSpec,
    args: list[str],
    *,
    workdir: str | Path | None = None,
    timeout: int = _RUN_TIMEOUT,
) -> RunResult:
    """Invoke a toolchain's compiler uniformly.

    Backends, in order:
    1. **docker** — ``docker run --rm -v <workdir>:/work -w /work <image> <binary> <args>``
       when the spec has an image and docker is available.
    2. **host** — the vendored / PATH binary with runner env (wine for
       MSVC-style, dosbox handled by the caller via the delphi16 module).

    Args:
        spec: The toolchain to run.
        args: Compiler arguments (flags, source, output).
        workdir: Host directory mounted into the container (docker) or the
            process cwd (host).  Required for docker.
        timeout: Subprocess timeout.

    Raises:
        ToolchainError: no usable backend (no image pulled, no host binary).
    """
    workdir = Path(workdir) if workdir is not None else Path.cwd()
    workdir.mkdir(parents=True, exist_ok=True)

    if spec.image is not None and _image_present(spec.image):
        entry = spec.image_binary or spec.binary
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{workdir.resolve()}:/work",
            "-w",
            "/work",
            spec.image,
            entry,
            *args,
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolchainError(f"docker invocation failed: {exc}") from exc
        return RunResult(r.returncode, r.stdout, r.stderr, backend="docker")

    # Host fallback.
    binary = _resolve_binary(spec)
    env = dict(os.environ)
    if spec.runtime == "wine":
        env.setdefault("WINEDEBUG", "-all")
    cmd = [binary, *args]
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=str(workdir),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolchainError(f"toolchain invocation failed: {exc}") from exc
    return RunResult(r.returncode, r.stdout, r.stderr, backend="host")


def list_toolchains() -> list[dict[str, Any]]:
    """Registry view for `rebrew toolchain list --json`."""
    return [
        {
            "name": s.name,
            "image": s.image,
            "binary": s.binary,
            "runtime": s.runtime,
            "flags_style": s.flags_style,
            "obj_ext": s.obj_ext,
            "host_path": str(s.host_path) if s.host_path else None,
            "description": s.description,
            "docker": docker_available(),
        }
        for s in TOOLCHAINS.values()
    ]


def pull_toolchain(name: str, timeout: int = 1200) -> str:
    """Pull a toolchain's docker image (docker backend)."""
    spec = get_toolchain(name)
    if spec.image is None:
        raise ToolchainError(f"toolchain {name!r} has no docker image (host-only)")
    if not docker_available():
        raise ToolchainError("docker is not available — cannot pull images")
    r = subprocess.run(
        ["docker", "pull", spec.image],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if r.returncode != 0:
        raise ToolchainError(f"docker pull {spec.image} failed: {r.stderr[-400:]}")
    return spec.image


__all__ = [
    "RunResult",
    "ToolchainError",
    "ToolchainSpec",
    "TOOLCHAINS",
    "docker_available",
    "get_toolchain",
    "list_toolchains",
    "pull_toolchain",
    "run_toolchain",
]
