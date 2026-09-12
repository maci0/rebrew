"""toolchain_spec.py — the value types for one toolchain.

ToolchainSpec describes how to invoke a compiler version; ToolchainSource
pins the assembly source for its host tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

#: Flag syntax a toolchain takes: MSVC's ``/I``/``/Fo``/``/c`` or POSIX's
#: ``-I``/``-o``/``-c``.  Drives config's ``posix_style`` and the default
#: flag axes an unlisted profile sweeps.
FlagsStyle = Literal["msvc", "posix"]


def flags_style_from_str(value: object) -> FlagsStyle:
    """Validate a declared ``flags_style``.

    Raises ``ValueError`` on anything but the two supported syntaxes so a
    misdeclared toolchain fails loud at load instead of silently taking MSVC
    flag axes."""
    style = str(value or "msvc")
    if style not in ("msvc", "posix"):
        raise ValueError(f"flags_style must be 'msvc' or 'posix', got {style!r}")
    return cast(FlagsStyle, style)


#: How a compiler takes its input and emits its object, beyond flag syntax:
#: ``msvc`` (``/Fo<obj> <src>``), ``posix`` (``-c -o <obj> <src>``), ``dos``
#: (``<src> <flags>`` with a FAT-uppercased object), ``borland``
#: (``<flags> -c <src>``, object named after the source stem), ``watcom``
#: (``<flags> -fo=<obj> -zq <src>``).
ArgStyle = Literal["msvc", "posix", "dos", "borland", "watcom"]

ARG_STYLES: frozenset[str] = frozenset({"msvc", "posix", "dos", "borland", "watcom"})


def arg_style_from_str(value: object) -> ArgStyle:
    """Validate a declared ``arg_style``; ``None`` leaves it derived."""
    style = str(value)
    if style not in ARG_STYLES:
        raise ValueError(f"arg_style must be one of {sorted(ARG_STYLES)}, got {style!r}")
    return cast(ArgStyle, style)


@dataclass(frozen=True)
class ToolchainSpec:
    """How to invoke one compiler version."""

    name: str  # e.g. "msvc-6.0", "delphi-1.0", "watcom-2.0-win32"
    image: str | None  # docker image tag, e.g. "rebrew/msvc:6.0-win32"; None = host-only
    binary: str = ""  # host executable name (vendored dir / PATH)
    image_binary: str | None = None  # entry binary inside the container (a shim,
    # e.g. "dcc" wrapping DCC.EXE); defaults to *binary*
    runtime: str = "native"  # "native" | "wine" | "dosbox" — informational; the
    # image wrapper encapsulates it, host fallback uses it for env setup
    flags_style: FlagsStyle = "msvc"  # flag syntax: /I,/Fo,/c vs -I,-o,-c
    arg_style: ArgStyle | None = None  # input/output argument dialect; None =
    # derive from flags_style (posix or msvc).  A DOS/borland/watcom compiler
    # declares its own dialect, so no profile-name list is needed to pick the
    # argument order.
    obj_ext: str = ".obj"
    host_path: str | Path | None = None  # vendored dir (host fallback)
    host_bin: str = "Bin"  # subdir of host_path holding the compiler (Bin for
    # MSVC, binl for Watcom, "" for the root — Delphi)
    tool_root: str | None = None  # container dir holding the command-line tools
    # (e.g. "/opt/msvc6.0/VC98/Bin"); the CMake toolchain wrapper
    # (rebrew-cmake-cl/link/lib) calls the tools there directly via `wine`, and
    # both it and the compile runner derive the Include/Lib dirs from it
    # (rebrew.toolchain.image_msvc_env)
    bits: int | None = None  # target code model: 16 / 32 / 64; None = unknown
    # (assumed 32-bit by detection's arch-alignment check).  A toolchain
    # registered with bits=16 is allowed on x86_16 DOS/NE targets instead of
    # being flagged as a 32/64-bit compiler.
    description: str = ""

    @property
    def effective_arg_style(self) -> ArgStyle:
        """The argument dialect to invoke this compiler with.

        Explicit ``arg_style`` wins; otherwise POSIX-style flag syntax implies
        POSIX argument order and everything else MSVC's."""
        return self.arg_style or ("posix" if self.flags_style == "posix" else "msvc")

    @property
    def family(self) -> str:
        """Unversioned compiler family — the toolchain/ top-level dir.

        Derived from the image repository basename (``rebrew/msvc:…`` ->
        ``msvc``) so the folder layout and the image tag can never drift.
        Host-only specs have no repository to derive from: fall back to the
        name.
        """
        if self.image and ":" in self.image:
            repo = self.image.rsplit(":", 1)[0]
            return repo.rsplit("/", 1)[-1]
        return self.name


@dataclass(frozen=True)
class ToolchainSource:
    """Pinned assembly source for one toolchain.

    Either a pinned tarball in the rebrew-toolchains checkout (``in_repo``
    — the deterministic option, no network) or a remote download verified
    by ``sha256``.  ``host_dir`` is the ``<family>/<version>-<arch>`` dir
    in that checkout that the vendored host tree is assembled into;
    ``layout`` drives the extraction.
    """

    url: str = ""
    sha256: str = ""
    in_repo: str = ""  # path relative to the rebrew-toolchains checkout
    # (the 16-bit media tarballs — user-supplied next to the Dockerfile,
    # not committed to git)
    layout: str = "tar"  # tar | tar-strip1 | zip-installshield
    host_dir: str = ""  # <family>/<version>-<arch> (host tree target)
    vc98_wrap: bool = False  # wrap the extracted tree in a VC98/ subdir (MSVC 6
    # classic master layout — Bin/Include/Lib/CRT live under VC98, matching the
    # canonical config paths and every legacy tools/MSVC600/VC98/... reference)
    commit: str = ""  # GitHub default-branch commit sha the pin was taken from
    # (codeload URLs).  `rebrew toolchain check-updates` compares the live
    # branch sha against this to detect upstream drift cheaply (no download).

    def is_in_repo(self) -> bool:
        return bool(self.in_repo)
