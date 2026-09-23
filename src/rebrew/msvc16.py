"""msvc16.py — 16-bit MSVC (1.5 / 1.52) compilation support.

Wraps the vendored 16-bit Microsoft Visual C++ command-line compilers
(``rebrew-toolchains/msvc/1.52-win16``, ``rebrew-toolchains/msvc/1.5-win16``): the CL.EXE
drivers are Phar Lap TNT DOS-extender PEs that run headless under DOSBox
(wine's DOS-memory allocation fails for them).  Produces 16-bit OMF
objects — the OMF parser (docs/OMF_NOTES.md) is the enabling piece for
byte matching.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rebrew.dosbox import DosboxError, make_sandbox_dir, read_uppercase, run_dosbox
from rebrew.errors import RebrewError


class Msvc16Error(RebrewError, RuntimeError):
    """Compilation failed (toolchain missing, DOSBox absent, or CL error)."""


@dataclass
class Msvc16Result:
    """Outcome of an MSVC 1.52 compile."""

    obj_path: Path
    log: str = ""


def _find_vc152(version: str = "1.52-win16") -> Path:
    from rebrew.toolchain_paths import toolchains_repo

    vc = toolchains_repo() / "msvc" / version / "source"
    if (vc / "BIN" / "CL.EXE").exists():
        return vc
    raise Msvc16Error(
        f"vendored MSVC {version} not found under "
        f"rebrew-toolchains/msvc/{version}/source (BIN/INCLUDE/LIB "
        "required — run `rebrew toolchain vendor msvc-1.52`/`msvc-1.5` with "
        "the media tarball next to the Dockerfile)"
    )


def compile_c(
    c_source: str | Path,
    workdir: str | Path | None = None,
    *,
    cflags: list[str] | None = None,
    timeout: int = 240,
    version: str = "1.52-win16",
) -> Msvc16Result:
    """Compile a C file to a 16-bit OMF object with the vendored 16-bit MSVC.

    Stages a DOSBox sandbox (on a non-tmpfs filesystem) with the vendored
    BIN/INCLUDE/LIB symlinked in, runs ``CL /nologo /c`` headless, and
    returns the produced ``.OBJ`` (FAT-uppercased name) plus the log.

    Args:
        c_source: Path to the C source (or source text).
        workdir: Sandbox dir (default: a fresh dir under the user home —
            DOSBox breaks on tmpfs mounts).
        cflags: Extra CL flags (default ``["/c", "/nologo"]``).
        timeout: DOSBox subprocess timeout.

    Raises:
        Msvc16Error: toolchain/DOSBox missing, compile failure, or no object.
    """
    vc = _find_vc152(version)

    # Stage by raw bytes: a UTF-8 errors="replace" → write_text round-trip
    # permanently turns legacy bytes (Shift-JIS / CP1252 string literals in
    # Japanese-era TUs) into U+FFFD, so the DOS compiler never sees the
    # original encoding.  Path sources are copied byte-for-byte; in-memory
    # text is written as UTF-8 + surrogateescape (read_compile_source inverse).
    src_path = Path(c_source) if Path(c_source).exists() else None
    if src_path is not None:
        src_name = src_path.name
        staged_bytes = src_path.read_bytes()
    else:
        src_name = "probe.c"
        staged_bytes = str(c_source).encode("utf-8", errors="surrogateescape")

    # CL.EXE 1.52 is a 16-bit Phar Lap DOS program — it cannot open long
    # filenames (DOSBox 8.3-truncates them, C1083).  Stage the source under
    # a fixed short 8.3-safe name; the produced object keeps that stem.
    staged_name = "SRC.C"

    sandbox = Path(workdir) if workdir is not None else make_sandbox_dir("msvc16-")
    sandbox.mkdir(parents=True, exist_ok=True)

    # Symlink the read-only toolchain tree into the sandbox (DOSBox follows
    # symlinks on the mounted host dir); only the source is copied.
    for sub in ("BIN", "INCLUDE", "LIB"):
        link = sandbox / sub
        target = vc / sub
        # Replace a stale symlink when the sandbox is reused with a different
        # compiler version (a workdir staged for 1.52 must not silently keep
        # compiling with 1.52 when version="1.5-win16" is requested).
        if link.is_symlink() and link.resolve() != target.resolve():
            link.unlink()
        if not link.exists():
            link.symlink_to(target, target_is_directory=True)
    (sandbox / staged_name).write_bytes(staged_bytes)

    flags = cflags if cflags is not None else ["/c", "/nologo"]
    cmd = "C:\\BIN\\CL.EXE " + " ".join(flags) + f" {staged_name} > C:\\clout.txt"
    # A reused caller-supplied workdir keeps the PREVIOUS run's object, so a
    # failed compile still "found" output and was reported as success; drop any
    # file the search below would match before running.
    stem_upper = Path(staged_name).stem.upper()
    for stale in sandbox.iterdir():
        if stale.suffix.upper() == ".OBJ" and stale.stem.upper() == stem_upper:
            stale.unlink()
    try:
        run_dosbox(
            sandbox,
            ["set INCLUDE=C:\\INCLUDE", "set LIB=C:\\LIB", cmd],
            timeout=timeout,
        )
    except DosboxError as exc:
        raise Msvc16Error(str(exc)) from exc

    log = read_uppercase(sandbox, "clout.txt")
    stem = Path(staged_name).stem
    obj = next(
        (
            p
            for p in sandbox.iterdir()
            if p.suffix.upper() == ".OBJ" and p.stem.upper() == stem.upper()
        ),
        None,
    )
    if obj is None:
        raise Msvc16Error(
            f"CL produced no object for {src_name} (staged as {staged_name}; log below):\n{log.strip()}"
        )
    return Msvc16Result(obj_path=obj, log=log)


__all__ = ["Msvc16Error", "Msvc16Result", "compile_c"]
