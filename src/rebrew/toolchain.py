"""toolchain.py — standardized toolchain invocation (docker-first, host fallback).

Modeled on Godbolt / Compiler Explorer's convention: **one container image
per toolchain-version**, with the compiler behind a wrapper inside the image
so the host invocation is uniform — ``docker run <image> <compiler> <args>``.
The image encapsulates the runtime quirks (MSVC under wine, DCC under
DOSBox), so the host-side code never needs per-toolchain runner glue.

Rebrew adds a **host-path fallback**: a spec may resolve to a vendored
directory (``toolchain/msvc/6.0-win32`` etc.) or a PATH binary instead of an image, so
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
    image: str | None  # docker image tag, e.g. "rebrew/msvc:6.0-win32"; None = host-only
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

    @property
    def family(self) -> str:
        """Unversioned compiler family — the toolchain/ top-level dir.

        Derived from the image repository basename (``rebrew/msvc:…`` ->
        ``msvc``) so the folder layout and the image tag can never drift.
        Host-only specs have no image: fall back to the name (gcc-pe).
        """
        if self.image and ":" in self.image:
            repo = self.image.rsplit(":", 1)[0]
            return repo.rsplit("/", 1)[-1]
        return self.name


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

_REPO_TOOLS = Path(__file__).resolve().parents[2] / "toolchain"


def _vendored(sub: str) -> Path:
    return _REPO_TOOLS / sub


@dataclass(frozen=True)
class ToolchainSource:
    """Pinned assembly source for one toolchain.

    Either an in-repo tarball (``in_repo`` — the deterministic option, no
    network) or a remote download verified by ``sha256``.  ``host_dir`` is
    the ``toolchain/<family>/<version>-<arch>`` directory the vendored host
    tree is assembled into; ``layout`` drives the extraction.
    """

    url: str = ""
    sha256: str = ""
    in_repo: str = ""  # repo-relative path to a committed tarball
    layout: str = "tar"  # tar | tar-strip1 | zip-installshield
    host_dir: str = ""  # toolchain/<family>/<version>-<arch> (host tree target)
    vc98_wrap: bool = False  # wrap the extracted tree in a VC98/ subdir (MSVC 6
    # classic master layout — Bin/Include/Lib/CRT live under VC98, matching the
    # canonical config paths and every legacy tools/MSVC600/VC98/... reference)

    def is_in_repo(self) -> bool:
        return bool(self.in_repo)


#: Pinned sources for assembling each toolchain (used by ``rebrew toolchain
#: vendor`` and mirrored in the Dockerfiles).  Same sha256 as the images
#: download, so host trees and containers are byte-identical.
_SOURCES: dict[str, ToolchainSource] = {
    "msvc6": ToolchainSource(
        url="https://github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/msvc6.0.tar.gz",
        sha256="5c81e9c2ab0ac5545022c1418a23392cb514db950cf6dcb1f48327270403fcd3",
        layout="tar",
        host_dir="msvc/6.0-win32",
        vc98_wrap=True,
    ),
    "msvc1.52": ToolchainSource(
        in_repo="toolchain/msvc/1.52-win16/msvc152.tar.xz",
        layout="tar",
        host_dir="msvc/1.52-win16",
    ),
    "delphi16": ToolchainSource(
        in_repo="toolchain/delphi/1.0-win16/delphi10.tar.xz",
        layout="tar",
        host_dir="delphi/1.0-win16",
    ),
    "borlandc55": ToolchainSource(
        url="https://archive.org/download/BorlandC55/Borland%20C%2B%2B%205.5.zip",
        sha256="12affb942db2b9823292697faaa6f465b18c381ba347f9f4bf8efae6ff34cca1",
        layout="zip-installshield",
        host_dir="borland/5.5-win32",
    ),
    "tc20": ToolchainSource(
        in_repo="toolchain/borland/2.0-win16/tc20.tar.xz",
        # Assembled from the archive.org turboc20 item (floppy disk images:
        # TCC.EXE 2.0/TLINK.EXE/CPP.EXE + runtime libs + headers), then
        # vendored in-repo for deterministic builds.
        layout="tar",
        host_dir="borland/2.0-win16",
    ),
    "tc16": ToolchainSource(
        in_repo="toolchain/borland/3.1-win16/tc31.tar.xz",
        # Original download (sha256-verified once, then vendored in-repo for
        # deterministic builds): archive.org item turboc3.1_202112 (TC.zip),
        # sha256 9cf53cd5d229633c2cf60c6fe2b24dba43b40a0ff2ca71e90279fa8649b622e4.
        layout="tar",
        host_dir="borland/3.1-win16",
    ),
    "watcom": ToolchainSource(
        url="https://github.com/open-watcom/open-watcom-v2/releases/download/Last-CI-build/ow-snapshot.tar.xz",
        sha256="984ff0d9a3f36bdb7596d8751299b3630cc259560c8386fb3337caa0037f3b4c",
        layout="tar-strip1",
        host_dir="watcom/2.0-win32",
    ),
    "msvc420": ToolchainSource(
        # archaic-msvc snapshot — the vendored toolchain/msvc/4.2-win32 tree
        # is a byte-identical extraction of this repo tarball (verified: file
        # list + CL.EXE match).  Previously vendored but NOT pinned, so a
        # fresh clone could not reproduce it via `rebrew toolchain vendor`.
        url="https://codeload.github.com/archaic-msvc/msvc420/tar.gz/refs/heads/master",
        sha256="651db241202416be7e870ff8d98928179b94515068e7895008b8a82cb0b7001c",
        layout="tar-strip1",
        host_dir="msvc/4.2-win32",
    ),
    "msvc5": ToolchainSource(
        # archaic-msvc snapshot — vendored toolchain/msvc/5.0-win32 is a
        # byte-identical extraction (verified).  Same sha256 the doctor hint
        # for the 5.0 layout already pointed at (codeload archaic-msvc/msvc500).
        url="https://codeload.github.com/archaic-msvc/msvc500/tar.gz/refs/heads/master",
        sha256="46745771c0805310212415450f097134f3871d1786434e86c080e0b8cb9a38fb",
        layout="tar-strip1",
        host_dir="msvc/5.0-win32",
    ),
    "msvc400": ToolchainSource(
        # itsmattkc/MSVC400 — the classic MSVC 4.0 (1995) tree; BIN/CL.EXE
        # at the repo root.  Completes the msvc4x/5/6/7 profile set (config,
        # init, and the detector already knew msvc400; only the toolchain
        # registry lacked it).
        url="https://codeload.github.com/itsmattkc/MSVC400/tar.gz/refs/heads/master",
        sha256="c076ab51bb5a52c805c85603d565ac406beec1a0accf3829127369294f1aff11",
        layout="tar-strip1",
        host_dir="msvc/4.0-win32",
    ),
}


TOOLCHAINS: dict[str, ToolchainSpec] = {
    "msvc400": ToolchainSpec(
        name="msvc400",
        image="rebrew/msvc:4.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/4.0-win32") if _vendored("msvc/4.0-win32").exists() else None,
        description="MSVC 4.0 (32-bit PE, C89) — wine or wibo",
    ),
    "msvc420": ToolchainSpec(
        name="msvc420",
        image="rebrew/msvc:4.2-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/4.2-win32") if _vendored("msvc/4.2-win32").exists() else None,
        description="MSVC 4.2 (32-bit PE, C89) — wine or wibo",
    ),
    "msvc5": ToolchainSpec(
        name="msvc5",
        image="rebrew/msvc:5.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/5.0-win32") if _vendored("msvc/5.0-win32").exists() else None,
        description="MSVC 5.0 (32-bit PE, C89) — wine or wibo",
    ),
    "msvc6": ToolchainSpec(
        name="msvc6",
        image="rebrew/msvc:6.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/6.0-win32") if _vendored("msvc/6.0-win32").exists() else None,
        description="MSVC 6.0 (32-bit PE, C89) — wine or wibo",
    ),
    "delphi16": ToolchainSpec(
        name="delphi16",
        image="rebrew/delphi:1.0-win16",
        binary="DCC.EXE",
        image_binary=None,  # the image ENTRYPOINT is the dcc wrapper
        runtime="dosbox",
        flags_style="msvc",
        obj_ext=".exe",  # DCC emits a linked NE, not an object
        host_path=_vendored("delphi/1.0-win16"),
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
        image="rebrew/watcom:2.0-win32",
        binary="wcc386",
        image_binary=None,  # the image ENTRYPOINT is wcc386
        runtime="native",
        flags_style="posix",
        obj_ext=".o",  # wcc386 emits OMF (8086 relocatable) — see OMF note
        host_path=_vendored("watcom/2.0-win32") if _vendored("watcom/2.0-win32").exists() else None,
        host_bin="binl",
        description="Open Watcom 2.0 (x86 32-bit) — native Linux wcc386",
    ),
    "msvc1.52": ToolchainSpec(
        name="msvc1.52",
        image="rebrew/msvc:1.52-win16",
        binary="CL.EXE",
        image_binary=None,  # the image ENTRYPOINT is the cl16 wrapper
        runtime="dosbox",
        flags_style="msvc",
        obj_ext=".obj",  # 16-bit OMF — see docs/OMF_NOTES.md
        host_path=_vendored("msvc/1.52-win16") if _vendored("msvc/1.52-win16").exists() else None,
        description="MSVC 1.52 (16-bit, Windows 3.x) — DOSBox via rebrew.msvc16",
    ),
    "tc20": ToolchainSpec(
        name="tc20",
        image="rebrew/borland:2.0-win16",
        binary="TCC.EXE",
        runtime="dosbox",
        flags_style="posix",
        obj_ext=".obj",  # Borland 16-bit OMF — parses via rebrew.matcher.omf16
        host_path=_vendored("borland/2.0-win16")
        if _vendored("borland/2.0-win16").exists()
        else None,
        host_bin="BIN",
        description="Turbo C 2.0 (16-bit DOS) — DOSBox via rebrew.tc16 (version=2.0)",
    ),
    "tc16": ToolchainSpec(
        name="tc16",
        image="rebrew/borland:3.1-win16",
        binary="TCC.EXE",
        runtime="dosbox",
        flags_style="posix",
        obj_ext=".obj",  # Borland 16-bit OMF — parses via rebrew.matcher.omf16
        host_path=_vendored("borland/3.1-win16")
        if _vendored("borland/3.1-win16").exists()
        else None,
        host_bin="BIN",
        description="Turbo C++ 3.1 (16-bit DOS) — DOSBox via rebrew.tc16",
    ),
    "borlandc55": ToolchainSpec(
        name="borlandc55",
        image="rebrew/borland:5.5-win32",
        binary="bcc32.exe",
        runtime="wine",
        flags_style="posix",
        obj_ext=".obj",
        host_path=_vendored("borland/5.5-win32")
        if _vendored("borland/5.5-win32").exists()
        else None,
        description="Borland C++ 5.5 (32-bit PE, C89) — wine or wibo (free command-line tools)",
    ),
    "watcom16": ToolchainSpec(
        name="watcom16",
        image=None,  # host-only: wcc runs natively from the watcom snapshot
        binary="wcc",
        runtime="native",
        flags_style="posix",
        obj_ext=".obj",  # 16-bit OMF — parses via omf16/objconv
        host_path=_vendored("watcom/2.0-win32") if _vendored("watcom/2.0-win32").exists() else None,
        host_bin="binl",
        description="Open Watcom 2.0 wcc (16-bit DOS, OMF) — native Linux wcc",
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


def _match_binary(dir: Path, binary: str) -> Path | None:
    """Case-insensitive match of *binary* in *dir*, tolerating a ``.exe``
    suffix (vendored Windows trees store ``CL.EXE`` / ``cl.exe`` while specs
    name the binary ``cl``)."""
    want = {binary.lower(), (binary + ".exe").lower()}
    try:
        for entry in dir.iterdir():
            if entry.is_file() and entry.name.lower() in want:
                return entry
    except OSError:
        pass
    return None


def _vendored_binary(spec: ToolchainSpec) -> Path | None:
    """Locate the spec's compiler inside its vendored host tree.

    Case-insensitive on both the ``host_bin`` subdir (``Bin`` vs ``BIN`` —
    MSVC400's tree is all-caps, MSVC 4.2/5.0's is lowercase) and the binary
    name (``cl`` matches ``CL.EXE``).  Returns ``None`` when the spec has
    no ``host_path`` or nothing matches — the PATH fallback is the caller's
    decision (``_resolve_binary`` uses it; the vendor guard must not).
    """
    if spec.host_path is None:
        return None
    host = Path(spec.host_path)
    hit = _match_binary(host, spec.binary)
    if hit is not None:
        return hit
    # The compiler usually lives in a subdir (Bin for MSVC, binl for
    # Watcom); DOS-era vendored trees are uppercase (BIN, not Bin) —
    # match the host_bin subdir case-insensitively before giving up
    # (MSVC 1.52's toolchain/msvc/1.52-win16/BIN/CL.EXE would otherwise never
    # resolve).
    if spec.host_bin:
        try:
            for entry in host.iterdir():
                if entry.is_dir() and entry.name.lower() == spec.host_bin.lower():
                    hit = _match_binary(entry, spec.binary)
                    if hit is not None:
                        return hit
        except OSError:
            pass
    return None


def _resolve_binary(spec: ToolchainSpec) -> str:
    """The host-side compiler path for a spec (host fallback): vendored dir /
    PATH binary.  Raises ToolchainError when nothing resolvable exists."""
    hit = _vendored_binary(spec)
    if hit is not None:
        return str(hit)
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
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{workdir.resolve()}:/work",
            "-w",
            "/work",
            spec.image,
        ]
        if spec.image_binary is not None:
            cmd.append(spec.image_binary)
        cmd.extend(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolchainError(f"docker invocation failed: {exc}") from exc
        return RunResult(r.returncode, r.stdout, r.stderr, backend="docker")

    # Host fallback.
    if spec.runtime == "dosbox":
        # A DOS binary cannot be exec'd natively; the DOSBox sandbox lives
        # in the toolchain modules (rebrew.msvc16.compile_c for msvc1.52,
        # rebrew.delphi16.compile_ne for delphi16) — compile_to_obj routes
        # there already.  A direct run_toolchain call has no DOSBox glue,
        # so fail clearly instead of exec'ing a DOS executable.
        raise ToolchainError(
            f"toolchain {spec.name!r} is dosbox-runtime: no host fallback in run_toolchain "
            f"(image {spec.image or 'n/a'} not pulled). Use rebrew.msvc16.compile_c / "
            f"rebrew.delphi16.compile_ne for host-side compilation."
        )
    binary = _resolve_binary(spec)
    env = dict(os.environ)
    if spec.runtime == "wine":
        env.setdefault("WINEDEBUG", "-all")
    cmd = [binary, *args]
    if spec.runtime == "wine":
        # Wine-runtime binaries (CL.EXE, bcc32.exe) are Windows PEs — exec'ing
        # the vendored file directly on Linux fails with EACCES/EINVAL.  Prefix
        # the wine loader (the host fallback previously could never run a
        # wine spec without an image, e.g. msvc420/msvc5).
        cmd = ["wine", *cmd]
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


def pull_toolchain(name: str, timeout: int = 1200) -> tuple[str, bool]:
    """Pull a toolchain's docker image (docker backend).

    Locally-built images (via ``rebrew toolchain build``) are already
    present and have no registry to pull from — treat that as a successful
    no-op instead of a confusing "pull access denied" failure.

    Returns ``(image_tag, was_already_present)``.
    """
    spec = get_toolchain(name)
    if spec.image is None:
        raise ToolchainError(f"toolchain {name!r} has no docker image (host-only)")
    if not docker_available():
        raise ToolchainError("docker is not available — cannot pull images")
    if _image_present(spec.image):
        return spec.image, True
    r = subprocess.run(
        ["docker", "pull", spec.image],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if r.returncode != 0:
        raise ToolchainError(
            f"docker pull {spec.image} failed: {r.stderr[-400:]}.  "
            f"rebrew images are BUILT from pinned sources, not pushed to a "
            f"registry — run `rebrew toolchain build {name}` instead"
        )
    return spec.image, False


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
