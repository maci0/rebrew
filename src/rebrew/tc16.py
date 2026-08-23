"""tc16.py — Borland 16-bit DOS TCC compile support (Turbo C 2.0 / Turbo C++ 3.1).

The command-line compilers ``TCC.EXE`` (Turbo C 2.0, 1988) and ``TCC.EXE``
(Turbo C++ 3.1, 1992) are 16-bit DOS programs — they run headless under
DOSBox via the shared :mod:`rebrew.dosbox` runner, mirroring the MSVC 1.52
path (:mod:`rebrew.msvc16`).  The vendored trees (``borland/2.0-win16``,
``borland/3.1-win16`` under the rebrew-toolchains checkout) have
BIN/INCLUDE/LIB at the top after the floppy/``TC/`` wrapper is stripped by
``rebrew toolchain vendor``.

``TCC`` produces Borland 16-bit OMF objects, which rebrew parses via
``rebrew.matcher.omf16`` (verified: cdecl prologue + rel16/disp16 slots).

The two compiler generations emit different codegen — a binary built with
Turbo C 2.0 (e.g. 1989-91 games like Commander Keen) will not byte-match a
Turbo C++ 3.1 build, so the version is selectable per compile (``tc20``
vs ``tc16`` profiles).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rebrew.dosbox import DosboxError, read_uppercase, run_dosbox

__all__ = ["Tc16Error", "Tc16Result", "compile_c"]

#: Vendored tree name per compiler version.
_TREES = {
    "2.0": "borland/2.0-win16",
    "3.1": "borland/3.1-win16",
}
_DISPLAY = {"2.0": "Turbo C 2.0", "3.1": "Turbo C++ 3.1"}


class Tc16Error(RuntimeError):
    """Turbo C toolchain/DOSBox missing, compile failure, or no object."""


@dataclass
class Tc16Result:
    obj_path: Path
    log: str


def _find_tc16(version: str = "3.1") -> Path:
    """Locate the vendored Borland 16-bit TCC tree (BIN/TCC.EXE present)."""
    from rebrew.toolchain import toolchains_repo

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


def _default_workdir() -> Path:
    from rebrew.dosbox import make_sandbox_dir

    return make_sandbox_dir("tc16-")


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
        workdir: Sandbox dir (default: a fresh dir under the user home —
            DOSBox breaks on tmpfs mounts).
        cflags: Extra TCC flags (default ``["-c"]``).
        timeout: DOSBox subprocess timeout.

    Raises:
        Tc16Error: toolchain/DOSBox missing, compile failure, or no object.
    """
    tree = _find_tc16(version)

    src_path = Path(c_source) if Path(c_source).exists() else None
    if src_path is not None:
        src_text = src_path.read_text(encoding="utf-8", errors="replace")
        src_name = src_path.name
    else:
        src_text = str(c_source)
        src_name = "probe.c"

    # DOSBox 8.3-truncates long names — stage under a fixed short name.
    staged_name = "SRC.C"
    sandbox = Path(workdir) if workdir is not None else _default_workdir()
    sandbox.mkdir(parents=True, exist_ok=True)
    for sub in ("BIN", "INCLUDE", "LIB"):
        link = sandbox / sub
        target = tree / sub
        # Replace a stale symlink when the sandbox is reused with a different
        # compiler version (a workdir staged for 3.1 must not silently keep
        # compiling with 3.1 when version="2.0" is requested).
        if link.is_symlink() and link.resolve() != target.resolve():
            link.unlink()
        if not link.exists():
            link.symlink_to(target, target_is_directory=True)
    (sandbox / staged_name).write_text(src_text, encoding="utf-8")

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
    obj = next(
        (p for p in sandbox.iterdir() if p.suffix.upper() == ".OBJ" and p.stem.upper() == "SRC"),
        None,
    )
    if obj is None:
        raise Tc16Error(
            f"TCC {version} produced no object for {src_name} "
            f"(staged as {staged_name}, flags={flags!r}; log below):\n"
            f"{log.strip()}"
        )
    return Tc16Result(obj_path=obj, log=log)
