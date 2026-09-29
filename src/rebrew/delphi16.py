"""delphi16.py — Delphi 1.0 (16-bit NE) compilation support.

Wraps the vendored 16-bit Borland Delphi 1.0 compiler (``DCC.EXE``, a DOS
DPMI app, run headless under DOSBox per the proven recipe in the
``rebrew-toolchains/delphi/1.0-win16`` tree) and parses the resulting 16-bit
NE executable with the native NE loader.

Used for research (compile + NE parse) on Delphi targets.  Note: 16-bit
matching in rebrew is implemented via the separate ``msvc-1.52`` profile
(DOSBox CL.EXE → OMF objects); Delphi's Borland ABI has no matchable
rebrew profile, so its functions are documented as blockers.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rebrew.dosbox import make_sandbox_dir
from rebrew.errors import RebrewError

if TYPE_CHECKING:
    from rebrew.ne_loader import NeFunction

_DCC_FILES = ("DCC.EXE", "DELPHI.DSL", "DPMI16BI.OVL", "RTM.EXE")

#: Default DCC.CFG: the RTL/VCL unit, include and resource paths inside the
#: sandbox.  `/u` is what makes `uses Classes, Forms, …` resolve.
_DCC_CFG = "/m\n/cw\n/rC:\\DELPHI\\LIB\n/uC:\\DELPHI\\LIB\n/iC:\\DELPHI\\LIB\n"

#: Sibling files staged next to the main source so a whole-program build
#: resolves its `uses` clauses.  A DPR's units, their compiled DCUs, the
#: linked form resources and `{$I}` include files all live in that
#: directory; staging only the .dpr made every multi-unit program fail with
#: the compiler's "File not found".
#:
#: `.dpr` is deliberately absent: a program cannot `uses` another program, and
#: staging a sibling .dpr made an unrelated one trip the 8.3 check (a directory
#: holding two probe programs could not compile either of them).
_UNIT_SUFFIXES = (".pas", ".dcu", ".dfm", ".res", ".inc")


class Delphi16Error(RebrewError, RuntimeError):
    """Compilation failed (toolchain missing, DOSBox absent, or DCC error)."""


@dataclass
class Delphi16Result:
    """Outcome of a Delphi 1.0 compile + parse."""

    exe_path: Path
    funcs: list[NeFunction] = field(default_factory=list)
    log: str = ""


def find_dcc() -> Path:
    """Locate the vendored DCC.EXE (rebrew-toolchains/delphi/1.0-win16)."""
    from rebrew.toolchain_paths import toolchains_repo

    dcc = toolchains_repo() / "delphi" / "1.0-win16" / "source" / "DCC.EXE"
    if dcc.exists():
        return dcc
    raise Delphi16Error(
        "vendored Delphi 1.0 toolchain not found under "
        "rebrew-toolchains/delphi/1.0-win16/source (DCC.EXE + DELPHI.DSL + "
        "DPMI16BI.OVL are required) — run `rebrew toolchain vendor delphi-1.0`, "
        "which downloads the pinned archaic-toolchains/delphi10 tarball"
    )


def _wine_prefix() -> Path:
    """The Wine prefix holding the extracted ``DELPHI/LIB`` units.

    ``REBREW_WINEPREFIX`` (rebrew's own override, same field the cmake
    bridge binds mounts with) wins over Wine's own ``WINEPREFIX``, and Wine's
    default ``~/.wine`` is the last resort.  A user who installed the units
    into a non-default prefix — a second prefix, or any setup where
    ``~/.wine`` is not the prefix — otherwise gets no units staged and every
    ``uses`` clause fails in the sandbox.
    """
    for var in ("REBREW_WINEPREFIX", "WINEPREFIX"):
        value = os.environ.get(var, "").strip()
        # A relative prefix resolves against the caller's cwd, which is the
        # sandbox; only an absolute one names a real prefix.
        candidate = Path(value).expanduser() if value else None
        if candidate is not None and candidate.is_absolute():
            return candidate
    return Path.home() / ".wine"


def _is_83_safe(name: str) -> bool:
    """True when *name* fits the DOS 8.3 filename convention (<=8 chars
    before the first dot, <=3 after, no spaces or DOS-special chars).

    The COMMAND.COM metacharacters join the DOS-special set: the name reaches
    an ``[autoexec]`` line (see :func:`rebrew.dosbox._build_dosbox_conf`), and
    ``A&B.C`` would run a second DOS command beside the compile.
    """
    base, dot, ext = name.partition(".")
    if dot and "." in ext:  # more than one dot
        return False
    if not base or len(base) > 8 or len(ext) > 3:
        return False
    return all(33 <= ord(c) < 127 and c not in '*?<>|"\\/&|^%!();,=' for c in name)


def _stage_unit_sources(src: Path, sandbox: Path, main_name: str) -> list[str]:
    """Copy the main source's sibling Pascal units into the sandbox.

    A DPR is a whole-program compilation unit: its ``uses`` clauses resolve
    against the units sitting next to it.  Staging only the .dpr meant DCC
    failed with "File not found" for every unit but the main one.  Files whose
    basename DOSBox would 8.3-truncate are refused by name rather than staged
    under a wrong name, which would surface as a confusing linker error.
    """
    staged: list[str] = []
    for sibling in sorted(src.parent.iterdir()):
        if not sibling.is_file() or sibling.name == src.name:
            continue
        if sibling.suffix.lower() not in _UNIT_SUFFIXES:
            continue
        if not _is_83_safe(sibling.name):
            raise Delphi16Error(
                f"unit {sibling.name} has a basename DOSBox would 8.3-truncate; "
                "rename it to 8.3 before compiling"
            )
        if sibling.name == main_name:  # e.g. a .pas main source staged as SRC.dpr
            continue
        shutil.copy2(sibling, sandbox / sibling.name)
        staged.append(sibling.name)
    return staged


def compile_ne(
    dpr_source: str | Path,
    workdir: str | Path | None = None,
    *,
    timeout: int = 180,
    units_dir: str | Path | None = None,
    extra_args: Sequence[str] = (),
    dcc_cfg: str | None = None,
    stage_siblings: bool = True,
) -> Delphi16Result:
    """Compile a ``.dpr``/``.pas`` source into a 16-bit NE executable.

    Stages a self-contained DOSBox sandbox: the compiler trio (DCC.EXE,
    DELPHI.DSL, DPMI16BI.OVL), the RTL/VCL units (when available), the source
    and its sibling units are copied into a temp directory mounted as the
    DOSBox ``C:`` drive; DCC runs headless with a staged ``DCC.CFG`` unit
    path; and the resulting ``.EXE`` is parsed with the native NE loader.

    Args:
        dpr_source: Path to the Pascal source (or the source text).
        workdir: Optional working directory (default: this thread's reused
            :func:`rebrew.dosbox.make_sandbox_dir` dir, removed at process
            exit; pass an explicit directory to keep the sandbox for
            inspection).
        timeout: DOSBox subprocess timeout.
        units_dir: Directory of extracted RTL/VCL units (``UNITS.PAK`` +
            ``LIB.PAK`` output, e.g. ``DELPHI/LIB``).  Defaults to
            ``<wine prefix>/drive_c/DELPHI/LIB`` (``REBREW_WINEPREFIX``,
            then ``WINEPREFIX``, then ``~/.wine``) when present;
            DELPHI.DSL-only programs compile without units.
        extra_args: Extra DCC switches (e.g. ``("-$R+", "$Q+")``) placed
            before the source name.  A byte-matching rebuild has to pin the
            project's switches; without them the caller can only take DCC's
            defaults.
        dcc_cfg: Full ``DCC.CFG`` text to stage.  Defaults to the built-in
            RTL/VCL paths; pass a project's file to reproduce its unit,
            include and resource search paths exactly.
        stage_siblings: Copy the main source's sibling units (``.pas``,
            ``.dcu``, ``.dfm``, ``.res``, ``.inc``) into the sandbox so the
            program's ``uses`` clauses resolve.

    Returns:
        Delphi16Result with the produced ``.exe`` path, its enumerated NE
        functions, and the compiler log.

    Raises:
        Delphi16Error: toolchain/DOSBox missing, compile failure, or the
            output is not a parseable NE.
    """
    dcc = find_dcc()

    # Stage by raw bytes so legacy-encoded units reach DCC unchanged
    # (UTF-8 errors="replace" → write_text would inject U+FFFD).
    src_path = Path(dpr_source) if Path(dpr_source).exists() else None
    if src_path is not None:
        src_name = src_path.name
        staged_bytes = src_path.read_bytes()
    else:
        src_name = "probe.dpr"
        staged_bytes = str(dpr_source).encode("utf-8", errors="surrogateescape")

    # DCC.EXE is a 16-bit DOS program — it cannot open long filenames
    # inside DOSBox (8.3-truncated, "Error 15: File not found").  Stage a
    # short 8.3-safe name when the source basename exceeds 8.3.
    staged_name = src_name if _is_83_safe(src_name) else "SRC.dpr"

    sandbox = Path(workdir) if workdir is not None else make_sandbox_dir("delphi16-")
    sandbox.mkdir(parents=True, exist_ok=True)

    # Stage the compiler trio + source into the sandbox (the DOSBox C:).
    for fname in _DCC_FILES:
        shutil.copy2(dcc.parent / fname, sandbox / fname)
    (sandbox / staged_name).write_bytes(staged_bytes)
    if stage_siblings and src_path is not None:
        _stage_unit_sources(src_path, sandbox, staged_name)

    # Stage the RTL/VCL units + a DCC.CFG that points at them, when found.
    # The mission (rebrew-toolchains/delphi/1.0-win16 tree) established
    # DCC.CFG's unit path is required for unit-using programs; DELPHI.DSL
    # alone suffices for the built-in units (System, WinTypes, WinProcs).
    lib_dir: Path | None = None
    if units_dir is not None:
        lib_dir = Path(units_dir)
    else:
        home_lib = _wine_prefix() / "drive_c" / "DELPHI" / "LIB"
        if home_lib.is_dir():
            lib_dir = home_lib
        elif (dcc.parent / "DELPHI/LIB").is_dir():
            lib_dir = dcc.parent / "DELPHI/LIB"
    if lib_dir is not None and lib_dir.is_dir():
        shutil.copytree(lib_dir, sandbox / "DELPHI" / "LIB", dirs_exist_ok=True)
    # A caller-supplied DCC.CFG replaces the built-in one outright: the
    # project's search paths are part of what a byte-matching rebuild pins.
    if dcc_cfg is not None:
        (sandbox / "DCC.CFG").write_text(dcc_cfg, encoding="utf-8")
    elif lib_dir is not None and lib_dir.is_dir():
        (sandbox / "DCC.CFG").write_text(_DCC_CFG, encoding="utf-8")

    from rebrew.dosbox import DosboxError, read_uppercase, run_dosbox

    extra = " " + " ".join(extra_args) if extra_args else ""
    cmd = f"C:\\DCC.EXE{extra} {staged_name} > C:\\dccout.txt"
    # A reused caller-supplied workdir keeps the PREVIOUS run's executable, so a
    # failed compile still "found" output and was reported as success (stale NE
    # bytes then fed to the matcher); drop any file the search below would match.
    stem_upper = Path(staged_name).stem.upper()
    for stale in sandbox.iterdir():
        if stale.suffix.upper() == ".EXE" and stale.stem.upper() == stem_upper:
            stale.unlink()
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
    "find_dcc",
]
