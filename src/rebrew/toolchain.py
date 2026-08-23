"""toolchain.py — standardized toolchain invocation (docker-only for Windows/DOS).

Modeled on Godbolt / Compiler Explorer's convention: **one container image
per toolchain-version**, with the compiler behind a wrapper inside the image
so the host invocation is uniform — ``docker run <image> <compiler> <args>``.
The image encapsulates the runtime quirks (MSVC under wine, DCC/TCC under
DOSBox), so the host-side code never needs per-toolchain runner glue.

Execution is **docker-only for every Windows/DOS toolchain** (all wine- and
dosbox-runtime specs): the host never calls CL.EXE / DCC.EXE / TCC.EXE /
bcc32.exe directly, and there is no wine/wibo host fallback.  The docker
build source (Dockerfiles, wrapper scripts, the shared ``base``) lives in
the standalone **rebrew-toolchains** checkout — the sibling repo
(overridable via ``REBREW_TOOLCHAINS_DIR``) — so rebrew no longer vendors
build files in-repo; ``rebrew toolchain build``/``vendor`` read them from
there, and the smoke gate verifies the image output is byte-reproducible.
Native-Linux toolchains without an image (gcc-pe, the wcc 16-bit binary)
exec their vendored/PATH binary directly; they are not Windows binaries, so
no wine is involved.

A :class:`ToolchainSpec` describes how to invoke one compiler version:
its image tag, the compiler executable (and any wrapper), and the flag
style/object-format conventions the rest of rebrew needs to drive it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import uuid
from collections.abc import Callable
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
    tool_root: str | None = None  # container dir holding the command-line tools
    # (e.g. "/opt/msvc6.0/VC98/Bin"); the CMake toolchain wrapper
    # (rebrew-cmake-cl/link/lib) calls the tools there directly via `wine` and
    # derives the Include/Lib dirs from it
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
    backend: str  # "docker" | "native" (host wine/dosbox execution removed)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


# ---------------------------------------------------------------------------
# Registry — the canonical toolchain list.  Profiles in config.py map to
# these by name; `rebrew toolchain list` shows them.
# ---------------------------------------------------------------------------

_TOOLCHAINS_REPO_URL = "https://github.com/maci0/rebrew-toolchains"


def _toolchains_repo() -> Path:
    """Root of the standalone rebrew-toolchains docker build source.

    Defaults to the sibling checkout (same workspace as this repo),
    overridable via REBREW_TOOLCHAINS_DIR for other layouts.  The external
    repo is the canonical source of the docker-image build files
    (Dockerfiles, the shared base, wrapper scripts); the 16-bit media
    tarballs are expected next to their Dockerfile there.  rebrew no
    longer vendors any of it in-repo."""
    env = os.environ.get("REBREW_TOOLCHAINS_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2].parent / "rebrew-toolchains"


_REPO_TOOLS = _toolchains_repo()


def _require_toolchains_repo() -> Path:
    """The rebrew-toolchains checkout, or an actionable error when missing.

    Only commands that actually consume the build source (``rebrew
    toolchain build``/``vendor``/``update``) call this — plain
    registry/status commands never touch the checkout."""
    repo = _toolchains_repo()
    if not repo.is_dir():
        raise ToolchainError(
            f"rebrew-toolchains checkout not found at {repo} — the docker "
            f"build source lives there now (clone {_TOOLCHAINS_REPO_URL} "
            "next to this repo, or set REBREW_TOOLCHAINS_DIR=<path>)"
        )
    return repo


def _vendored(sub: str) -> Path:
    return _REPO_TOOLS / sub


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


#: Pinned sources for assembling each toolchain (used by ``rebrew toolchain
#: vendor`` and mirrored in the Dockerfiles).  Same sha256 as the images
#: download, so host trees and containers are byte-identical.
_SOURCES: dict[str, ToolchainSource] = {
    "msvc6": ToolchainSource(
        # archaic-msvc/msvc600 — the flagship MSVC 6.0 base (VC98/Bin/CL.EXE,
        # 12.00.8168).  Byte-reproducible with the old decomp.me msvc6.0
        # source (masked-object sha256 identical), now pinned to the
        # archaic-msvc org per the "get everything from archaic-msvc" rule.
        url="https://codeload.github.com/archaic-msvc/msvc600/tar.gz/refs/heads/master",
        sha256="19b72020c8225f91d7345b16aa0acf1b31a4608ae1299693021491e7338d0ee8",
        commit="34d4fc4004e880b8d5c44ae5babd7229eeaad993",
        layout="tar-strip1",
        host_dir="msvc/6.0-win32",
    ),
    "msvc200": ToolchainSource(
        # archaic-msvc/msvc200 — VC 2.0 (1994), the first 32-bit compiler; bin/cl.exe.
        url="https://codeload.github.com/archaic-msvc/msvc200/tar.gz/refs/heads/master",
        sha256="0b058f103fe6b615987a85d518d7fd23389fab67c9df3cadfae22f5a70d5d000",
        commit="6bf022c590fdea0526dc94975f3d91add444ac1a",
        layout="tar-strip1",
        host_dir="msvc/2.0-win32",
    ),
    "msvc410": ToolchainSource(
        # archaic-msvc/msvc410 — VC 4.1 (1996); bin/CL.EXE (10.10.6038).
        url="https://codeload.github.com/archaic-msvc/msvc410/tar.gz/refs/heads/master",
        sha256="21486aecd108397bdced6e2cf6a5170a3cc30280a3eba97a4a8f92985a9cc5c4",
        commit="373f5e621ac8fb7b219873b37334ef1d0a2149e6",
        layout="tar-strip1",
        host_dir="msvc/4.1-win32",
    ),
    "msvc500sp1": ToolchainSource(
        # archaic-msvc/msvc500sp1 — VC 5.0 SP1 (CL.EXE identical to base 11.00.7022).
        url="https://codeload.github.com/archaic-msvc/msvc500sp1/tar.gz/refs/heads/master",
        sha256="f41e9e5a05bd7a4da97fdcc9d168aaac7898e5bfec11791c630735a7da13d303",
        commit="401174749393c9991a6b91425a795e04e8bdeedb",
        layout="tar-strip1",
        host_dir="msvc/5.0-sp1-win32",
    ),
    "msvc500sp2": ToolchainSource(
        # archaic-msvc/msvc500sp2 — VC 5.0 SP2.
        url="https://codeload.github.com/archaic-msvc/msvc500sp2/tar.gz/refs/heads/master",
        sha256="551137506a6a98ca890bfe20df7d5833bc475cf7e2279d959eccce0485525c8e",
        commit="4ebf02022705b4c9e9108d3ed3f286ed80ba2ed9",
        layout="tar-strip1",
        host_dir="msvc/5.0-sp2-win32",
    ),
    "msvc500sp3": ToolchainSource(
        # archaic-msvc/msvc500sp3 — VC 5.0 SP3.
        url="https://codeload.github.com/archaic-msvc/msvc500sp3/tar.gz/refs/heads/master",
        sha256="cdba2878eaacd07cb289b73f08250e2c39596fc9b31a2ad7a4fd887879be1e38",
        commit="259a03f0bc863de5baf657ec064cb60cb20a2cdc",
        layout="tar-strip1",
        host_dir="msvc/5.0-sp3-win32",
    ),
    "msvc600sp1": ToolchainSource(
        # archaic-toolchains/msvc600_sp1 — VC 6.0 SP1 (1998).  The full RTM
        # product tree (archaic-msvc msvc600 + VS6 Enterprise CD1 CRT/debug/
        # redist) plus the files SP1 is documented to have fixed (strftime.c,
        # MFC sources) taken in cumulative state from the official SP2 payload
        # the standalone SP1 payload (VSE600SP1.EXE) is not preserved in any
        # public archive.  CL.EXE 12.00.8168 (the RTM..SP3 driver, byte-identical
        # to the base 6.0 compiler).
        url="https://codeload.github.com/archaic-toolchains/msvc600_sp1/tar.gz/refs/heads/main",
        sha256="2c3d1a6d2e7d6248f1bcb5e46a54cd2bea94704df032056abef53828b0b79888",
        commit="6d9787482473ca46a1e6fb70be020755951eb16a",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp1-win32",
    ),
    "msvc600sp2": ToolchainSource(
        # archaic-toolchains/msvc600_sp2 — VC 6.0 SP2 (1999).  The full RTM
        # tree plus the entire official SP2 payload (crt/src, debug, lib,
        # mfc/src, mfc/lib from the MSDN Disc 18 VS6SP2 CABs) and the SP2
        # redistributable runtimes.  SP2 changed no compiler binaries and no
        # headers — CL.EXE stays 12.00.8168 (byte-identical to the base).
        url="https://codeload.github.com/archaic-toolchains/msvc600_sp2/tar.gz/refs/heads/main",
        sha256="088cd189ce0ae3c7ff96a71bb3f364a397b2fe6c19e6a8f252cc575be3783574",
        commit="79157a87dec5e5ff014178f817f27a70098fd862",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp2-win32",
    ),
    "msvc600sp4": ToolchainSource(
        # archaic-toolchains/msvc600_sp4 — VC 6.0 SP4 (2000) full tree with
        # Bin: the archaic-msvc msvc600_sp4 headers/libs plus the decomp.me
        # msvc6.4 Bin (CL.EXE 12.00.8804 — the SP4+ driver; sha-verified
        # byte-identical to the official SP4 CD's cl/c1/c1xx/link/cvtres).
        url="https://codeload.github.com/archaic-toolchains/msvc600_sp4/tar.gz/refs/heads/main",
        sha256="7aeb03f65858000bb6988a64cc066a4a2aec9fc591400db400ffe6fc99ae2dbc",
        commit="0ca69bae9e3ca739c5ce38c8cf39ffc51582080d",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp4-win32",
    ),
    "msvc600sp3": ToolchainSource(
        # OmniBlade decomp.me msvc6.3 — VC 6.0 SP3 (CL.EXE 12.00.8168, the
        # RTM..SP3 build; identical to the flagship msvc6 compiler).  The
        # archaic-msvc msvc600_sp3 repo carries no Bin/, so the decomp.me
        # mirror (which matches the vendored tree byte-for-byte) is pinned.
        url="https://github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/msvc6.3.tar.gz",
        sha256="84f73e718b3671bfd5de3b7764622b07633b572ee826ca3b77602d224c128608",
        layout="tar",
        host_dir="msvc/6.0-sp3-win32",
    ),
    "msvc600sp5": ToolchainSource(
        # archaic-msvc/msvc600_sp5 — VC 6.0 SP5 full product tree (VC98/Bin,
        # CL.EXE 12.00.8804).  The archaic sp3/sp4 repos carry no Bin/, and
        # decomp.me's msvc6.4/6.5 mislabel the SP6 compiler, so SP5 is the
        # earliest real SP with its own preserved compiler binary.
        url="https://codeload.github.com/archaic-msvc/msvc600_sp5/tar.gz/refs/heads/master",
        sha256="a95a9c17cbcbe0d97a3e80ef9596f12404eb28f36bab24e89aabcbe37acbbef6",
        commit="b0b07e29108e2695eb0274c2a377a7b7d7326150",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp5-win32",
    ),
    "msvc600sp6": ToolchainSource(
        # archaic-msvc/msvc600_sp6 — VC 6.0 SP6 full product tree
        # (VC98/Bin/CL.EXE, 12.00.8804 — the same compiler the SP4 CD and
        # SP5 carry).  The repo stashes mspdb60.dll under Common/MSDev98/Bin
        # (the vendor + Dockerfile relocate it — CL imports it in-dir).
        url="https://codeload.github.com/archaic-msvc/msvc600_sp6/tar.gz/refs/heads/master",
        sha256="7c2aa3dd4c56b8054cc1ae0e00cd976005dd5b9b43ea8c33b22798a15c9c15c3",
        commit="1f4223a77122220d28e8670788b3f9fd6bb2c4d1",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp6-win32",
    ),
    "msvc7": ToolchainSource(
        # archaic-msvc/msvc710 — the legacy "msvc7" profile's compiler is
        # cl.exe 13.10.3077 (the .NET 2003 build); archaic-msvc carries it
        # in msvc710 (Vc7/bin layout).  The vendored 7.0-win32 host tree
        # keeps its flat Bin/ layout (established config); the image builds
        # from the archaic source.
        url="https://codeload.github.com/archaic-msvc/msvc710/tar.gz/refs/heads/master",
        sha256="618e876bc06431498fa98e71a408d822a5fad979219ce3253318d099a6917b27",
        commit="2932d76fe417b0bc49010b26d4be2e5b743cc4be",
        layout="tar-strip1",
        host_dir="msvc/7.0-win32",
    ),
    "msvc700": ToolchainSource(
        # archaic-msvc/msvc700 — the true VC 7.0 (2002) compiler (13.00.9466;
        # 7.0-SP1 shipped the identical binary).  Vc7/bin/cl.exe layout; the
        # canonical 7.0-win32 dir stays with the established msvc7 profile.
        url="https://codeload.github.com/archaic-msvc/msvc700/tar.gz/refs/heads/master",
        sha256="5f75462fb6134ad56c3ae28cf8b1e3b2869578d4171568b7a1fcdfb0bf97830b",
        commit="97fe4cdeaeb0bb934591d4b05eb52c2e8ab3e34b",
        layout="tar-strip1",
        host_dir="msvc/7.0-rtm-win32",
    ),
    "msvc700sp1": ToolchainSource(
        # archaic-msvc/msvc700_sp1 — VC 7.0 SP1 (same 13.00.9466 compiler,
        # updated headers/libs).
        url="https://codeload.github.com/archaic-msvc/msvc700_sp1/tar.gz/refs/heads/master",
        sha256="bc1300625c89e855e1c0160b43c6fe2576ad68426483bd73c3cde2682165ba8a",
        commit="8bd9502d74274667de198247a459d63dbd431068",
        layout="tar-strip1",
        host_dir="msvc/7.0-sp1-win32",
    ),
    "msvc710": ToolchainSource(
        # archaic-msvc/msvc710 — VC 7.1 (.NET 2003; cl.exe 13.10.3077, the
        # same build the legacy msvc7 profile carries).  Vc7/bin/cl.exe.
        url="https://codeload.github.com/archaic-msvc/msvc710/tar.gz/refs/heads/master",
        sha256="618e876bc06431498fa98e71a408d822a5fad979219ce3253318d099a6917b27",
        commit="2932d76fe417b0bc49010b26d4be2e5b743cc4be",
        layout="tar-strip1",
        host_dir="msvc/7.1-win32",
    ),
    "msvc710sp1": ToolchainSource(
        # archaic-msvc/msvc710_sp1 — VC 7.1 SP1 (cl.exe 13.10.6030).
        url="https://codeload.github.com/archaic-msvc/msvc710_sp1/tar.gz/refs/heads/master",
        sha256="44246ff2980d715c2d05eaed505344a0b87850a04606482c13ba4832ddf5ec70",
        commit="cf62606064633dd8441aa2feffe34792099cc366",
        layout="tar-strip1",
        host_dir="msvc/7.1-sp1-win32",
    ),
    "msvc800": ToolchainSource(
        # archaic-msvc/msvc800 — VC 8.0 (2005; cl.exe 14.00.50727).  VC/bin.
        url="https://codeload.github.com/archaic-msvc/msvc800/tar.gz/refs/heads/master",
        sha256="ab819164ebd9e9d367c1178a86eb9c3337b1a8d85d1357322a3252b63ad64453",
        commit="00ddaf58d09788f0b12e475dae5fb5674dd32578",
        layout="tar-strip1",
        host_dir="msvc/8.0-win32",
    ),
    "msvc800sp1": ToolchainSource(
        # archaic-msvc/msvc800_sp1 — VC 8.0 SP1 (cl.exe 14.00.50727.762).
        url="https://codeload.github.com/archaic-msvc/msvc800_sp1/tar.gz/refs/heads/master",
        sha256="9b53b515d79839c7404944c29cdae862d3a8c1ff0d0a27a202bfc37a31f587c5",
        commit="4b1bafba636f67eb76f548f0f0e7f38864091a4a",
        layout="tar-strip1",
        host_dir="msvc/8.0-sp1-win32",
    ),
    "msvc900": ToolchainSource(
        # archaic-msvc/msvc900 — VC 9.0 (2008; cl.exe 15.00.21022).  VC/bin;
        # the repo carries no SP1 tarball (VC 2008 SP1's 15.00.30729 compiler
        # is not preserved publicly) — the base 9.0 profile is the matchable
        # target for VS2008-era binaries.
        url="https://codeload.github.com/archaic-msvc/msvc900/tar.gz/refs/heads/master",
        sha256="9121d184d9cb88c13b95d3d2e770c8d8ae9d2531a5d8ea90c53a14f765e3f904",
        commit="c9d710cef9a3dec08d7d2dca78a3b494335a5baa",
        layout="tar-strip1",
        host_dir="msvc/9.0-win32",
    ),
    "msvc900sp1": ToolchainSource(
        # archaic-toolchains/msvc900_sp1 — VC 9.0 SP1 (2008): the msvc900 base
        # plus the 15.00.30729.01 compiler (cl/c1/c1xx/c2/link/mspdb80,
        # Professional-edition series) and 122 SP1 headers/libs, extracted
        # from the official VS2008 SP1 DVD (VS90sp1-KB945140-X86-ENU.msp).
        # Closes the "VC 2008 SP1 compiler has no public tarball" gap.
        url="https://codeload.github.com/archaic-toolchains/msvc900_sp1/tar.gz/refs/heads/main",
        sha256="33a66c779da39ab40518f24b75656f1f93cb1837a3d65a9b79188f41c2f2bd97",
        commit="cebb3c9740c92de36937a401a3a3141358c8ac29",
        layout="tar-strip1",
        host_dir="msvc/9.0-sp1-win32",
    ),
    "msvc1100": ToolchainSource(
        # archaic-msvc/msvc1100 — VC 11.0 / VS 2012 (cl.exe 17.00.50522.1).
        # VC/bin + Windows Kits + a wine/ runner dir; the newest compiler the
        # archaic-msvc org carries.
        url="https://codeload.github.com/archaic-msvc/msvc1100/tar.gz/refs/heads/master",
        sha256="adba1882eb076cb774b7a5d0f2b1067544da7cd2f0bf0b12f284361516cbc825",
        commit="89087a636aea5e6f9450ee7e840ea71e08740ee1",
        layout="tar-strip1",
        host_dir="msvc/11.0-win32",
    ),
    "msvc1000": ToolchainSource(
        # archaic-msvc/msvc1000 — VC 10.0 (2010; cl.exe 16.00.30319).  VC/bin.
        url="https://codeload.github.com/archaic-msvc/msvc1000/tar.gz/refs/heads/master",
        sha256="5f0b4486eb68e0069bb11506bcc8834710ac92ac1e7f311b3e4400a9d5d9409f",
        commit="f8977e2cacbe6cab4f9e73eb2c05695a88519bfe",
        layout="tar-strip1",
        host_dir="msvc/10.0-win32",
    ),
    "msvc1000sp1": ToolchainSource(
        # archaic-msvc/msvc1000_sp1 — VC 10.0 SP1 (cl.exe 16.00.40219).
        url="https://codeload.github.com/archaic-msvc/msvc1000_sp1/tar.gz/refs/heads/master",
        sha256="2e5fbb9b71ed8cb2673594484d6a8fad7484c809ecefffaf3319e0164af6f89b",
        commit="09a53c11f781ec9ab5e66772ba720b9d85e4c2a4",
        layout="tar-strip1",
        host_dir="msvc/10.0-sp1-win32",
    ),
    "msvc15": ToolchainSource(
        # Committed tree extracted from the archive.org en_vc152 item
        # (VC 1.5, 1993, 16-bit) — RAR SFX extracts cleanly for 1.5 (the
        # 1.52 SFX corrupts), so the verified tree is vendored under the
        # rebrew-toolchains checkout (msvc15.tar.xz next to its Dockerfile).
        in_repo="msvc/1.5-win16/msvc15.tar.xz",
        layout="tar",
        host_dir="msvc/1.5-win16",
    ),
    "msvc10": ToolchainSource(
        # Assembled from the WinWorldPC "Microsoft Visual C++ 1.0
        # Professional" 3.5" floppy set (20×1.44MB, SZDD-compressed payload;
        # 7z-extracted + renamed), then vendored under the rebrew-toolchains
        # checkout as msvc10.tar.xz.  CL.EXE is a Phar Lap TNT DOS-extender
        # (PE32) like 1.5/1.52 — runs headless under DOSBox and produces
        # 16-bit OMF (verified).
        in_repo="msvc/1.0-win16/msvc10.tar.xz",
        layout="tar",
        host_dir="msvc/1.0-win16",
    ),
    "msvc1.52": ToolchainSource(
        in_repo="msvc/1.52-win16/msvc152.tar.xz",
        layout="tar",
        host_dir="msvc/1.52-win16",
    ),
    "delphi16": ToolchainSource(
        in_repo="delphi/1.0-win16/delphi10.tar.xz",
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
        in_repo="borland/2.0-win16/tc20.tar.xz",
        # Assembled from the archive.org turboc20 item (floppy disk images:
        # TCC.EXE 2.0/TLINK.EXE/CPP.EXE + runtime libs + headers), then
        # vendored under the rebrew-toolchains checkout for deterministic
        # builds.
        layout="tar",
        host_dir="borland/2.0-win16",
    ),
    "tc16": ToolchainSource(
        in_repo="borland/3.1-win16/tc31.tar.xz",
        # Original download (sha256-verified once, then vendored under the
        # rebrew-toolchains checkout for deterministic builds): archive.org
        # item turboc3.1_202112 (TC.zip), sha256
        # 9cf53cd5d229633c2cf60c6fe2b24dba43b40a0ff2ca71e90279fa8649b622e4.
        layout="tar",
        host_dir="borland/3.1-win16",
    ),
    "watcom": ToolchainSource(
        url="https://github.com/open-watcom/open-watcom-v2/releases/download/Last-CI-build/ow-snapshot.tar.xz",
        sha256="99e494d9a3871f58a6398268e8f04003affa73421ca5fb49e3815a8ef1bb7b1f",
        commit="",
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
        commit="b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50",
        layout="tar-strip1",
        host_dir="msvc/4.2-win32",
    ),
    "msvc5": ToolchainSource(
        # archaic-msvc snapshot — vendored toolchain/msvc/5.0-win32 is a
        # byte-identical extraction (verified).  Same sha256 the doctor hint
        # for the 5.0 layout already pointed at (codeload archaic-msvc/msvc500).
        url="https://codeload.github.com/archaic-msvc/msvc500/tar.gz/refs/heads/master",
        sha256="46745771c0805310212415450f097134f3871d1786434e86c080e0b8cb9a38fb",
        commit="8abf95ce980161ad87b0b02402269cce76988953",
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
        commit="821e942fd95bd16d01649401de7943ef87ae9f54",
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
        description="MSVC 4.0 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc420": ToolchainSpec(
        name="msvc420",
        image="rebrew/msvc:4.2-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/4.2-win32") if _vendored("msvc/4.2-win32").exists() else None,
        description="MSVC 4.2 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc5": ToolchainSpec(
        name="msvc5",
        image="rebrew/msvc:5.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/5.0-win32") if _vendored("msvc/5.0-win32").exists() else None,
        description="MSVC 5.0 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc6": ToolchainSpec(
        name="msvc6",
        image="rebrew/msvc:6.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0/VC98/Bin",
        host_path=_vendored("msvc/6.0-win32") if _vendored("msvc/6.0-win32").exists() else None,
        description="MSVC 6.0 (32-bit PE, C89) — docker image (wine inside)",
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
    "msvc200": ToolchainSpec(
        name="msvc200",
        image="rebrew/msvc:2.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/2.0-win32") if _vendored("msvc/2.0-win32").exists() else None,
        host_bin="bin",
        description="MSVC 2.0 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc410": ToolchainSpec(
        name="msvc410",
        image="rebrew/msvc:4.1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/4.1-win32") if _vendored("msvc/4.1-win32").exists() else None,
        host_bin="bin",
        description="MSVC 4.1 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc500sp1": ToolchainSpec(
        name="msvc500sp1",
        image="rebrew/msvc:5.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/5.0-sp1-win32")
        if _vendored("msvc/5.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 5.0 SP1 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc500sp2": ToolchainSpec(
        name="msvc500sp2",
        image="rebrew/msvc:5.0-sp2-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/5.0-sp2-win32")
        if _vendored("msvc/5.0-sp2-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 5.0 SP2 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc500sp3": ToolchainSpec(
        name="msvc500sp3",
        image="rebrew/msvc:5.0-sp3-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/5.0-sp3-win32")
        if _vendored("msvc/5.0-sp3-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 5.0 SP3 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc600sp3": ToolchainSpec(
        name="msvc600sp3",
        image="rebrew/msvc:6.0-sp3-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/6.0-sp3-win32")
        if _vendored("msvc/6.0-sp3-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP3 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc600sp1": ToolchainSpec(
        name="msvc600sp1",
        image="rebrew/msvc:6.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/6.0-sp1-win32")
        if _vendored("msvc/6.0-sp1-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP1 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc600sp2": ToolchainSpec(
        name="msvc600sp2",
        image="rebrew/msvc:6.0-sp2-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/6.0-sp2-win32")
        if _vendored("msvc/6.0-sp2-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP2 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc600sp4": ToolchainSpec(
        name="msvc600sp4",
        image="rebrew/msvc:6.0-sp4-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/6.0-sp4-win32")
        if _vendored("msvc/6.0-sp4-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP4 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc600sp5": ToolchainSpec(
        name="msvc600sp5",
        image="rebrew/msvc:6.0-sp5-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/6.0-sp5-win32")
        if _vendored("msvc/6.0-sp5-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP5 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc600sp6": ToolchainSpec(
        name="msvc600sp6",
        image="rebrew/msvc:6.0-sp6-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/6.0-sp6-win32")
        if _vendored("msvc/6.0-sp6-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP6 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc7": ToolchainSpec(
        name="msvc7",
        image="rebrew/msvc:7.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/7.0-win32") if _vendored("msvc/7.0-win32").exists() else None,
        host_bin="Bin",
        description="MSVC 7.0 (32-bit PE, C89) — docker image (wine inside) (13.10.3077 build)",
    ),
    "msvc700": ToolchainSpec(
        name="msvc700",
        image="rebrew/msvc:7.0-rtm-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/7.0-rtm-win32")
        if _vendored("msvc/7.0-rtm-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 7.0 RTM (32-bit PE, C89, 13.00.9466) — docker image (wine inside)",
    ),
    "msvc700sp1": ToolchainSpec(
        name="msvc700sp1",
        image="rebrew/msvc:7.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/7.0-sp1-win32")
        if _vendored("msvc/7.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 7.0 SP1 (32-bit PE, C89, 13.00.9466) — docker image (wine inside)",
    ),
    "msvc710": ToolchainSpec(
        name="msvc710",
        image="rebrew/msvc:7.1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/7.1-win32") if _vendored("msvc/7.1-win32").exists() else None,
        host_bin="bin",
        description="MSVC 7.1 (32-bit PE, C89, 13.10.3077) — docker image (wine inside)",
    ),
    "msvc710sp1": ToolchainSpec(
        name="msvc710sp1",
        image="rebrew/msvc:7.1-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/7.1-sp1-win32")
        if _vendored("msvc/7.1-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 7.1 SP1 (32-bit PE, C89, 13.10.6030) — docker image (wine inside)",
    ),
    "msvc800": ToolchainSpec(
        name="msvc800",
        image="rebrew/msvc:8.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/8.0-win32") if _vendored("msvc/8.0-win32").exists() else None,
        host_bin="bin",
        description="MSVC 8.0 (32-bit PE, C89, 14.00.50727) — docker image (wine inside)",
    ),
    "msvc800sp1": ToolchainSpec(
        name="msvc800sp1",
        image="rebrew/msvc:8.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/8.0-sp1-win32")
        if _vendored("msvc/8.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 8.0 SP1 (32-bit PE, C89, 14.00.50727.762) — docker image (wine inside)",
    ),
    "msvc900": ToolchainSpec(
        name="msvc900",
        image="rebrew/msvc:9.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/9.0-win32") if _vendored("msvc/9.0-win32").exists() else None,
        host_bin="bin",
        description="MSVC 9.0 (32-bit PE, C89, 15.00.21022) — docker image (wine inside)",
    ),
    "msvc900sp1": ToolchainSpec(
        name="msvc900sp1",
        image="rebrew/msvc:9.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/9.0-sp1-win32")
        if _vendored("msvc/9.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 9.0 SP1 (32-bit PE, C89, 15.00.30729) — docker image (wine inside)",
    ),
    "msvc1100": ToolchainSpec(
        name="msvc1100",
        image="rebrew/msvc:11.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/11.0-win32") if _vendored("msvc/11.0-win32").exists() else None,
        host_bin="bin",
        description="MSVC 11.0 (32-bit PE, C++, 17.00.50522) — docker image (wine inside)",
    ),
    "msvc1000": ToolchainSpec(
        name="msvc1000",
        image="rebrew/msvc:10.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/10.0-win32") if _vendored("msvc/10.0-win32").exists() else None,
        host_bin="bin",
        description="MSVC 10.0 (32-bit PE, C89, 16.00.30319) — docker image (wine inside)",
    ),
    "msvc1000sp1": ToolchainSpec(
        name="msvc1000sp1",
        image="rebrew/msvc:10.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        host_path=_vendored("msvc/10.0-sp1-win32")
        if _vendored("msvc/10.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 10.0 SP1 (32-bit PE, C89, 16.00.40219) — docker image (wine inside)",
    ),
    "msvc15": ToolchainSpec(
        name="msvc15",
        image="rebrew/msvc:1.5-win16",
        binary="CL.EXE",
        image_binary=None,  # the image ENTRYPOINT is the cl15 wrapper
        runtime="dosbox",
        flags_style="msvc",
        obj_ext=".obj",  # 16-bit OMF — parses via rebrew.matcher.omf16
        host_path=_vendored("msvc/1.5-win16") if _vendored("msvc/1.5-win16").exists() else None,
        host_bin="BIN",
        description="MSVC 1.5 (16-bit, Windows 3.x) — DOSBox via rebrew.msvc16 (version=1.5-win16)",
    ),
    "msvc10": ToolchainSpec(
        name="msvc10",
        image="rebrew/msvc:1.0-win16",
        binary="CL.EXE",
        image_binary=None,  # the image ENTRYPOINT is the cl10 wrapper
        runtime="dosbox",
        flags_style="msvc",
        obj_ext=".obj",  # 16-bit OMF — parses via rebrew.matcher.omf16
        host_path=_vendored("msvc/1.0-win16") if _vendored("msvc/1.0-win16").exists() else None,
        host_bin="BIN",
        description="MSVC 1.0 (16-bit, Windows 3.x) — DOSBox via rebrew.msvc16 (version=1.0-win16)",
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
        description="Borland C++ 5.5 (32-bit PE, C89) — docker image (wine inside) (free command-line tools)",
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


def _kill_container(name: str, timeout: int = 30) -> None:
    """Best-effort ``docker kill`` of a timed-out run container.

    The container was started with ``--rm``, so killing it also removes it.
    All errors are suppressed: this is cleanup on an error path — losing the
    kill race must not mask the original timeout with a secondary failure.
    """
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=timeout)


def _image_present(tag: str) -> bool:
    """True when a docker image for *tag* is present locally (cached)."""
    if tag in _image_presence:
        return _image_presence[tag]
    if not docker_available():
        return False
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        # A hung daemon must surface as ToolchainError (callers catch that),
        # not a raw TimeoutExpired escaping into the compile/GA path — and
        # not a silent False, which would misreport a present image as
        # "not built".
        raise ToolchainError(f"docker image inspect {tag} failed: {exc}") from exc
    _image_presence[tag] = r.returncode == 0
    return _image_presence[tag]


def _image_id(tag: str) -> str | None:
    """Full docker image id for *tag* (``sha256:...``), or ``None`` when the
    tag does not resolve or docker is unavailable.  Uncached — the swap
    primitive calls it around image changes where freshness matters."""
    if not docker_available():
        return None
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolchainError(f"docker image inspect {tag} failed: {exc}") from exc
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return r.stdout.strip()


def _retag_image(src: str, dst: str) -> None:
    """Point the *dst* tag at *src* (an image id or tag)."""
    r = subprocess.run(["docker", "tag", src, dst], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise ToolchainError(f"docker tag {src} -> {dst} failed: {r.stderr[-300:]}")


def swap_toolchain_image(tag: str, op: Callable[[], None]) -> str:
    """Transactionally replace the docker image under *tag* (backup→swap→rollback).

    Records the current image id under *tag* (the backup), runs *op* — which
    must build or pull the replacement; docker's tag-on-success is the swap —
    then verifies *tag* still resolves.  If *op* raises, or the tag ends up
    unresolvable, the previous image is re-tagged under *tag* (rollback), so a
    failed build/pull never leaves the toolchain half-registered (a pin or
    cache entry pointing at a dangling tag).

    Returns the image id *tag* resolves to after a successful swap.
    """
    backup = _image_id(tag)
    try:
        op()
    except Exception:
        # Rollback: restore the previous image under the tag.  A normal
        # build/pull failure leaves the old tag in place (docker only re-tags
        # on success), so the restore is a no-op check in that case; it only
        # acts when the tag was left dangling or repointed at something else.
        if backup is not None:
            with contextlib.suppress(ToolchainError):
                if _image_id(tag) != backup:
                    _retag_image(backup, tag)
        raise
    current = _image_id(tag)
    if current is None:
        if backup is not None:
            with contextlib.suppress(ToolchainError):
                _retag_image(backup, tag)
        raise ToolchainError(
            f"image tag {tag!r} does not resolve after the swap"
            + (" — previous image restored" if backup is not None else " (no previous image)")
        )
    return current


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
    # Canonical layout: the actual toolchain lives one level deep under
    # ``source/`` (<family>/<ver>-<arch>/source/... — vendored into the
    # rebrew-toolchains checkout) so every vendored tree has the same shape.
    if (host / "source").is_dir():
        host = host / "source"
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
            # Product trees nest the compiler one level deeper (VC98/Bin for
            # the MSVC 6 master and SP5, Vc7/bin for 7.0/7.1, VC/bin for
            # 8.0+): look for <top>/<wrapper>/<host_bin>/<binary> so those
            # resolve too (msvc6's wrapped layout previously never did).
            for wrapper in host.iterdir():
                if not wrapper.is_dir():
                    continue
                for entry in wrapper.iterdir():
                    if entry.is_dir() and entry.name.lower() == spec.host_bin.lower():
                        hit = _match_binary(entry, spec.binary)
                        if hit is not None:
                            return hit
        except OSError:
            pass
    return None


def _resolve_binary(spec: ToolchainSpec) -> str:
    """The host-side compiler path for a native-runtime spec (no image):
    vendored dir / PATH binary.  Raises ToolchainError when nothing
    resolvable exists.  Only native-Linux toolchains (gcc-pe, watcom16
    wcc) reach this — wine/dosbox toolchains are docker-only."""
    hit = _vendored_binary(spec)
    if hit is not None:
        return str(hit)
    found = shutil.which(spec.binary)
    if found:
        return found
    raise ToolchainError(
        f"toolchain {spec.name!r}: no native binary ({spec.binary}) found — "
        "run `rebrew toolchain vendor <name>` into the rebrew-toolchains "
        "checkout or install it on PATH"
    )


def run_toolchain(
    spec: ToolchainSpec,
    args: list[str],
    *,
    workdir: str | Path | None = None,
    timeout: int = _RUN_TIMEOUT,
    mounts: list[tuple[str, str]] | None = None,
) -> RunResult:
    """Invoke a toolchain's compiler through its docker image (uniform backend).

    Execution is docker-only for every Windows/DOS toolchain: the images
    encapsulate the runtime (MSVC under wine, DCC/TCC under DOSBox) and the
    host never calls CL.EXE / DCC.EXE / TCC.EXE / bcc32.exe directly.  A
    missing image is a hard error (run `rebrew toolchain build <name>`) —
    there is deliberately no wine/wibo/dosbox host fallback anymore.

    Native-Linux toolchains without an image (gcc-pe, watcom16 wcc) exec the
    vendored/PATH binary directly — they are not Windows binaries, so no
    wine glue is involved.

    The container runs with ``--network=none`` — compilation is strictly
    local (source in, object out), and the toolchain image needs no egress
    (a malformed image cannot reach the network during a build).

    Args:
        spec: The toolchain to run.
        args: Compiler arguments (flags, source, output).
        workdir: Host directory mounted into the container (docker) or the
            process cwd (native).  Required for docker.
        mounts: Extra ``(host_dir, container_dir)`` bind mounts, used to
            expose project include trees to the container (each host dir is
            mounted read-write at the container path).
        timeout: Subprocess timeout.

    Raises:
        ToolchainError: no docker daemon/image for a docker toolchain, or no
            native binary for a native-runtime toolchain.
    """
    workdir = Path(workdir) if workdir is not None else Path.cwd()
    try:
        workdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # An un-creatable workdir must surface as a ToolchainError (callers
        # catch that), not a raw OSError escaping into the GA/flag-sweep path.
        raise ToolchainError(f"cannot create workdir {workdir}: {exc}") from exc

    if spec.image is not None:
        if not docker_available():
            raise ToolchainError("docker is not available — cannot run toolchain images")
        if not _image_present(spec.image):
            raise ToolchainError(
                f"toolchain {spec.name!r}: docker image {spec.image} not built — "
                f"run `rebrew toolchain build {spec.name}`"
            )
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network=none",  # compile-only containers — no egress needed
            # A stable name lets the timeout path kill the container: when the
            # docker CLI is killed, dockerd keeps the (attached) container
            # running, so a hung compile would linger forever and accumulate
            # one orphan per timed-out invocation.
            "--name",
            f"rebrew-{uuid.uuid4().hex[:12]}",
            "-v",
            f"{workdir.resolve()}:/work",
            "-w",
            "/work",
        ]
        for host_dir, container_dir in mounts or []:
            cmd += ["-v", f"{Path(host_dir).resolve()}:{container_dir}"]
        cmd.append(spec.image)
        if spec.image_binary is not None:
            cmd.append(spec.image_binary)
        cmd.extend(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _kill_container(str(cmd[cmd.index("--name") + 1]))
            raise ToolchainError(f"docker invocation failed: {exc}") from exc
        except OSError as exc:
            raise ToolchainError(f"docker invocation failed: {exc}") from exc
        return RunResult(r.returncode, r.stdout, r.stderr, backend="docker")

    if spec.runtime == "native":
        # Native-Linux compiler (gcc-pe, watcom16 wcc) — vendored/PATH binary
        # executed directly.  These are NOT Windows binaries; no wine glue.
        binary = _resolve_binary(spec)
        env = dict(os.environ)
        try:
            r = subprocess.run(
                [binary, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=str(workdir),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolchainError(f"toolchain invocation failed: {exc}") from exc
        return RunResult(r.returncode, r.stdout, r.stderr, backend="native")

    raise ToolchainError(
        f"toolchain {spec.name!r} ({spec.runtime}) has no docker image — every "
        "Windows/DOS toolchain runs only through its docker image; "
        f"run `rebrew toolchain build {spec.name}`"
    )


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

    The pull runs through :func:`swap_toolchain_image` (backup→swap→rollback):
    a failed pull leaves the previously registered image under the tag.

    Returns ``(image_tag, was_already_present)``.
    """
    spec = get_toolchain(name)
    if spec.image is None:
        raise ToolchainError(f"toolchain {name!r} has no docker image (host-only)")
    image = spec.image  # narrowed local — mypy does not narrow into the closure
    if not docker_available():
        raise ToolchainError("docker is not available — cannot pull images")
    if _image_present(image):
        return image, True

    def _pull() -> None:
        r = subprocess.run(
            ["docker", "pull", image],
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

    swap_toolchain_image(image, _pull)
    return image, False


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
    "swap_toolchain_image",
]
