"""tc16.py — Borland 16-bit DOS TCC compile support (Turbo C 2.0 / Turbo C++ 3.1).

The command-line compilers ``TCC.EXE`` (Turbo C 2.0, 1988) and ``TCC.EXE``
(Turbo C++ 3.1, 1992) are 16-bit DOS programs — they run headless under
DOSBox via the shared :mod:`rebrew.dosbox` runner, mirroring the MSVC 1.52
path (:mod:`rebrew.msvc16`).  The vendored trees (``borland/2.0-win16``,
``borland/3.1-win16`` under the rebrew-toolchains checkout) have
BIN/INCLUDE/LIB at the top after the floppy/``TC/`` wrapper is stripped by
``rebrew toolchain vendor``.

``TCC`` produces Borland 16-bit OMF objects, which rebrew parses via
``rebrew.omf16`` (verified: cdecl prologue + rel16/disp16 slots).

The two compiler generations emit different codegen — a binary built with
Turbo C 2.0 (e.g. 1989-91 games like Commander Keen) will not byte-match a
Turbo C++ 3.1 build, so the version is selectable per compile (``borland-2.0``
vs ``borland-3.1`` profiles).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rebrew.dosbox import (
    STAGED_SOURCE_NAME,
    DosboxError,
    find_staged_object,
    make_sandbox_dir,
    read_uppercase,
    run_dosbox,
    stage_tree_source,
)
from rebrew.errors import RebrewError

__all__ = ["Tc16Error", "Tc16Result", "compile_c"]

#: Vendored tree name per compiler version.
_TREES = {
    "2.0": "borland/2.0-win16",
    "3.1": "borland/3.1-win16",
}
_DISPLAY = {"2.0": "Turbo C 2.0", "3.1": "Turbo C++ 3.1"}


class Tc16Error(RebrewError, RuntimeError):
    """Turbo C toolchain/DOSBox missing, compile failure, or no object."""


@dataclass
class Tc16Result:
    obj_path: Path
    log: str


def _find_tc16(version: str = "3.1") -> Path:
    """Locate the vendored Borland 16-bit TCC tree (BIN/TCC.EXE present)."""
    from rebrew.toolchain_paths import toolchains_repo

    tree = _TREES.get(version)
    if tree is None:
        raise Tc16Error(f"unknown Borland TCC version {version!r} (known: {sorted(_TREES)})")
    root = toolchains_repo() / tree / "source"
    tcc = root / "BIN" / "TCC.EXE"
    if not tcc.exists():
        raise Tc16Error(
            f"{_DISPLAY[version]} not vendored — run `rebrew toolchain vendor` "
            f"(expected {tcc} under the rebrew-toolchains checkout)"
        )
    return root


def compile_c(
    c_source: str | Path,
    workdir: str | Path | None = None,
    *,
    cflags: list[str] | None = None,
    timeout: int = 240,
    version: str = "3.1",
) -> Tc16Result:
    """Compile a C file to a 16-bit Borland OMF object with TCC.EXE.

    Stages a DOSBox sandbox with the vendored BIN/INCLUDE/LIB symlinked in,
    runs ``TCC -c -I\\INCLUDE`` headless, and returns the produced ``.OBJ``
    (FAT-uppercased name) plus the log.

    Args:
        c_source: Path to the C source (or source text).
        workdir: Sandbox dir (default: this thread's reused
            :func:`rebrew.dosbox.make_sandbox_dir` dir on real disk, since DOSBox
            breaks on tmpfs mounts; removed at process exit).
        cflags: Extra TCC flags (default ``["-c"]``).
        timeout: DOSBox subprocess timeout.
        version: Borland profile under the vendored tree (``"3.1"``,
            ``"2.0"``) — selects which TCC/INCLUDE/LIB set is staged.

    Raises:
        Tc16Error: toolchain/DOSBox missing, compile failure, or no object.
    """
    tree = _find_tc16(version)

    sandbox = Path(workdir) if workdir is not None else make_sandbox_dir("tc16-")
    staged_name = STAGED_SOURCE_NAME
    src_name = stage_tree_source(sandbox, tree, c_source, staged_name)

    flags = cflags if cflags is not None else ["-c"]
    cmd = (
        "C:\\BIN\\TCC.EXE "
        + " ".join(flags)
        + f" -I\\INCLUDE -oSRC.OBJ {staged_name} > C:\\tcout.txt"
    )
    try:
        run_dosbox(sandbox, [cmd], timeout=timeout)
    except DosboxError as exc:
        raise Tc16Error(str(exc)) from exc

    log = read_uppercase(sandbox, "tcout.txt")
    obj = find_staged_object(sandbox, staged_name)
    if obj is None:
        raise Tc16Error(
            f"TCC {version} produced no object for {src_name} "
            f"(staged as {staged_name}, flags={flags!r}; log below):\n"
            f"{log.strip()}"
        )
    return Tc16Result(obj_path=obj, log=log)
