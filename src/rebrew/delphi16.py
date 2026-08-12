"""delphi16.py — Delphi 1.0 (16-bit NE) compilation support.

Wraps the vendored 16-bit Borland Delphi 1.0 compiler (``DCC.EXE``, a DOS
DPMI app, run headless under DOSBox per the proven recipe in
``toolchain/delphi/1.0-win16/README.md``) and parses the resulting 16-bit NE
executable with the native NE loader.

Used for research (compile + NE parse) on Delphi targets.  Note: 16-bit
matching in rebrew is implemented via the separate ``msvc1.52`` profile
(DOSBox CL.EXE → OMF objects); Delphi's Borland ABI has no matchable
rebrew profile, so its functions are documented as blockers.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rebrew.ne_loader import NeFunction

_DCC_FILES = ("DCC.EXE", "DELPHI.DSL", "DPMI16BI.OVL", "RTM.EXE")


class Delphi16Error(RuntimeError):
    """Compilation failed (toolchain missing, DOSBox absent, or DCC error)."""


@dataclass
class Delphi16Result:
    """Outcome of a Delphi 1.0 compile + parse."""

    exe_path: Path
    funcs: list[NeFunction] = field(default_factory=list)
    log: str = ""


def _find_dcc() -> Path:
    """Locate the vendored DCC.EXE (repo toolchain/delphi/1.0-win16)."""
    repo_tools = Path(__file__).resolve().parents[2] / "toolchain"
    dcc = repo_tools / "delphi" / "1.0-win16" / "DCC.EXE"
    if dcc.exists():
        return dcc
    raise Delphi16Error(
        "vendored Delphi 1.0 toolchain not found under toolchain/delphi/1.0-win16 "
        "(DCC.EXE + DELPHI.DSL + DPMI16BI.OVL are required)"
    )


def _is_83_safe(name: str) -> bool:
    """True when *name* fits the DOS 8.3 filename convention (<=8 chars
    before the first dot, <=3 after, no spaces or DOS-special chars)."""
    base, dot, ext = name.partition(".")
    if dot and "." in ext:  # more than one dot
        return False
    if not base or len(base) > 8 or len(ext) > 3:
        return False
    return all(33 <= ord(c) < 127 and c not in '*?<>|"\\/' for c in name)


def _default_workdir() -> Path:
    """A fresh sandbox dir on a NON-tmpfs filesystem.

    DOSBox 0.74-3 misbehaves when the mounted drive sits on tmpfs (e.g.
    ``/tmp``): the shell treats autoexec commands as ``cd`` and DCC never
    runs.  The user home is used instead (btrfs/ext4 here).
    """
    return Path(tempfile.mkdtemp(prefix="delphi16-", dir=Path.home()))


def compile_ne(
    dpr_source: str | Path,
    workdir: str | Path | None = None,
    *,
    timeout: int = 180,
    units_dir: str | Path | None = None,
) -> Delphi16Result:
    """Compile a ``.dpr``/``.pas`` source into a 16-bit NE executable.

    Stages a self-contained DOSBox sandbox: the compiler trio (DCC.EXE,
    DELPHI.DSL, DPMI16BI.OVL), the RTL/VCL units (when available), and the
    source are copied into a temp directory mounted as the DOSBox ``C:``
    drive; DCC runs headless with a staged ``DCC.CFG`` unit path; and the
    resulting ``.EXE`` is parsed with the native NE loader.

    Args:
        dpr_source: Path to the Pascal source (or the source text).
        workdir: Optional working directory (default: a fresh temp dir that
            is created and left in place for inspection).
        timeout: DOSBox subprocess timeout.
        units_dir: Directory of extracted RTL/VCL units (``UNITS.PAK`` +
            ``LIB.PAK`` output, e.g. ``DELPHI/LIB``).  Defaults to the
            known location from the holiday.exe mission
            (``~/.wine/drive_c/DELPHI/LIB``) when present; DELPHI.DSL-only
            programs compile without units.

    Returns:
        Delphi16Result with the produced ``.exe`` path, its enumerated NE
        functions, and the compiler log.

    Raises:
        Delphi16Error: toolchain/DOSBox missing, compile failure, or the
            output is not a parseable NE.
    """
    dcc = _find_dcc()

    src_path = Path(dpr_source) if Path(dpr_source).exists() else None
    if src_path is not None:
        src_text = src_path.read_text(encoding="utf-8", errors="replace")
        src_name = src_path.name
    else:
        src_text = str(dpr_source)
        src_name = "probe.dpr"

    # DCC.EXE is a 16-bit DOS program — it cannot open long filenames
    # inside DOSBox (8.3-truncated, "Error 15: File not found").  Stage a
    # short 8.3-safe name when the source basename exceeds 8.3.
    staged_name = src_name if _is_83_safe(src_name) else "SRC.dpr"

    sandbox = Path(workdir) if workdir is not None else _default_workdir()
    sandbox.mkdir(parents=True, exist_ok=True)

    # Stage the compiler trio + source into the sandbox (the DOSBox C:).
    for fname in _DCC_FILES:
        shutil.copy2(dcc.parent / fname, sandbox / fname)
    (sandbox / staged_name).write_text(src_text, encoding="utf-8")

    # Stage the RTL/VCL units + a DCC.CFG that points at them, when found.
    # The mission (toolchain/delphi/1.0-win16/README.md) established DCC.CFG's unit path
    # is required for unit-using programs; DELPHI.DSL alone suffices for the
    # built-in units (System, WinTypes, WinProcs).
    lib_dir: Path | None = None
    if units_dir is not None:
        lib_dir = Path(units_dir)
    else:
        home_lib = Path.home() / ".wine/drive_c/DELPHI/LIB"
        if home_lib.is_dir():
            lib_dir = home_lib
        elif (dcc.parent / "DELPHI/LIB").is_dir():
            lib_dir = dcc.parent / "DELPHI/LIB"
    if lib_dir is not None and lib_dir.is_dir():
        shutil.copytree(lib_dir, sandbox / "DELPHI" / "LIB", dirs_exist_ok=True)
        (sandbox / "DCC.CFG").write_text(
            "/m\n/cw\n/rC:\\DELPHI\\LIB\n/uC:\\DELPHI\\LIB\n/iC:\\DELPHI\\LIB\n",
            encoding="utf-8",
        )

    from rebrew.dosbox import DosboxError, read_uppercase, run_dosbox

    cmd = f"C:\\DCC.EXE {staged_name} > C:\\dccout.txt"
    try:
        run_dosbox(sandbox, [cmd], timeout=timeout)
    except DosboxError as exc:
        raise Delphi16Error(str(exc)) from exc

    log = read_uppercase(sandbox, "dccout.txt")
    # DOSBox writes FAT-uppercased filenames (HELLO.EXE, not hello.EXE).
    stem = Path(staged_name).stem
    exe = next(
        (
            p
            for p in sandbox.iterdir()
            if p.suffix.upper() == ".EXE" and p.stem.upper() == stem.upper()
        ),
        None,
    )
    if exe is None:
        raise Delphi16Error(f"DCC produced no executable (compiler log below):\n{log.strip()}")

    # Parse the freshly-compiled NE with the native loader.
    from rebrew.binary_loader import is_ne, load_binary
    from rebrew.ne_loader import enumerate_ne_functions

    if not is_ne(exe):
        raise Delphi16Error(f"compiled output is not a 16-bit NE executable: {exe}")
    info = load_binary(exe)
    funcs = list(enumerate_ne_functions(info))
    return Delphi16Result(exe_path=exe, funcs=funcs, log=log)


__all__ = [
    "Delphi16Error",
    "Delphi16Result",
    "compile_ne",
]
