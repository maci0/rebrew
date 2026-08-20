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

from rebrew.dosbox import DosboxError, read_uppercase, run_dosbox


class Msvc16Error(RuntimeError):
    """Compilation failed (toolchain missing, DOSBox absent, or CL error)."""


@dataclass
class Msvc16Result:
    """Outcome of an MSVC 1.52 compile."""

    obj_path: Path
    log: str = ""


def _find_vc152(version: str = "1.52-win16") -> Path:
    from rebrew.toolchain import _toolchains_repo

    vc = _toolchains_repo() / "msvc" / version / "source"
    if (vc / "BIN" / "CL.EXE").exists():
        return vc
    raise Msvc16Error(
        f"vendored MSVC {version} not found under "
        f"rebrew-toolchains/msvc/{version}/source (BIN/INCLUDE/LIB "
        "required — run `rebrew toolchain vendor msvc1.52`/`msvc15` with "
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

    src_path = Path(c_source) if Path(c_source).exists() else None
    if src_path is not None:
        src_text = src_path.read_text(encoding="utf-8", errors="replace")
        src_name = src_path.name
    else:
        src_text = str(c_source)
        src_name = "probe.c"

    # CL.EXE 1.52 is a 16-bit Phar Lap DOS program — it cannot open long
    # filenames (DOSBox 8.3-truncates them, C1083).  Stage the source under
    # a fixed short 8.3-safe name; the produced object keeps that stem.
    staged_name = "SRC.C"

    sandbox = Path(workdir) if workdir is not None else _default_workdir()
    sandbox.mkdir(parents=True, exist_ok=True)

    # Symlink the read-only toolchain tree into the sandbox (DOSBox follows
    # symlinks on the mounted host dir); only the source is copied.
    for sub in ("BIN", "INCLUDE", "LIB"):
        link = sandbox / sub
        if not link.exists():
            link.symlink_to(vc / sub, target_is_directory=True)
    (sandbox / staged_name).write_text(src_text, encoding="utf-8")

    flags = cflags if cflags is not None else ["/c", "/nologo"]
    cmd = "C:\\BIN\\CL.EXE " + " ".join(flags) + f" {staged_name} > C:\\clout.txt"
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


def _default_workdir() -> Path:
    from rebrew.dosbox import make_sandbox_dir

    return make_sandbox_dir("msvc16-")


__all__ = ["Msvc16Error", "Msvc16Result", "compile_c"]
