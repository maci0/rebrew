"""compiler/msvc16.py — 16-bit MSVC (1.0 / 1.5 / 1.52) compilation support.

Wraps the vendored 16-bit Microsoft Visual C++ command-line compilers
(``recompile-toolchains/msvc/1.0-win16``, ``recompile-toolchains/msvc/1.5-win16``,
``recompile-toolchains/msvc/1.52-win16``): the CL.EXE drivers are Phar Lap TNT
DOS-extender PEs that run headless under DOSBox (wine's DOS-memory
allocation fails for them).  Produces 16-bit OMF objects — the OMF parser
(docs/OMF_NOTES.md) is the enabling piece for byte matching.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rebrew.errors import RebrewError
lazy from rebrew.compiler.dosbox import (
    STAGED_SOURCE_NAME,
    compile_staged_source,
)


class Msvc16Error(RebrewError, RuntimeError):
    """Compilation failed (toolchain missing, DOSBox absent, or CL error)."""


@dataclass
class Msvc16Result:
    """Outcome of a 16-bit MSVC compile."""

    obj_path: Path
    log: str = ""


def _find_vc152(version: str = "1.52-win16") -> Path:
    from rebrew.compiler.toolchain_paths import toolchains_repo

    vc = toolchains_repo() / "msvc" / version / "source"
    if (vc / "BIN" / "CL.EXE").exists():
        return vc
    profile = {
        "1.0-win16": "msvc-1.0",
        "1.5-win16": "msvc-1.5",
        "1.52-win16": "msvc-1.52",
    }.get(version, version)
    raise Msvc16Error(
        f"vendored MSVC {version} not found under "
        f"recompile-toolchains/msvc/{version}/source (BIN/INCLUDE/LIB "
        f"required — run `rebrew toolchain vendor {profile}`, which "
        "downloads the pinned archaic-toolchains tarball)"
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
        workdir: Sandbox dir (default: this thread's reused
            :func:`rebrew.compiler.dosbox.make_sandbox_dir` dir on real disk, since DOSBox
            breaks on tmpfs mounts; removed at process exit).
        cflags: Extra CL flags (default ``["/c", "/nologo"]``).
        timeout: DOSBox subprocess timeout.
        version: Vendored tree under ``recompile-toolchains/msvc/<version>/source``
            (``1.0-win16``, ``1.5-win16``, or ``1.52-win16``).

    Raises:
        Msvc16Error: toolchain/DOSBox missing, compile failure, or no object.
    """
    vc = _find_vc152(version)

    flags = cflags if cflags is not None else ["/c", "/nologo"]
    cmd = "C:\\BIN\\CL.EXE " + " ".join(flags) + f" {STAGED_SOURCE_NAME} > C:\\clout.txt"
    obj, log, src_name = compile_staged_source(
        vc,
        c_source,
        workdir,
        sandbox_prefix="msvc16-",
        autoexec=["set INCLUDE=C:\\INCLUDE", "set LIB=C:\\LIB", cmd],
        timeout=timeout,
        log_name="clout.txt",
        error_type=Msvc16Error,
    )
    if obj is None:
        raise Msvc16Error(
            f"CL produced no object for {src_name} (staged as {STAGED_SOURCE_NAME}; log below):\n{log.strip()}"
        )
    return Msvc16Result(obj_path=obj, log=log)


__all__ = ["Msvc16Error", "Msvc16Result", "compile_c"]
