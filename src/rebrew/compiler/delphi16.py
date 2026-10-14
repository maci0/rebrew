"""Compile Delphi 1.0 Pascal programs through the shipped Docker toolchain."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rebrew.compiler.dosbox import make_sandbox_dir, read_uppercase
from rebrew.compiler.toolchain import ToolchainError, get_toolchain, run_toolchain
from rebrew.errors import RebrewError

if TYPE_CHECKING:
    from rebrew.formats.ne_loader import NeFunction

_UNIT_SUFFIXES = {".pas", ".dcu", ".dfm", ".res", ".inc"}


class Delphi16Error(RebrewError, RuntimeError):
    """The Delphi image is unavailable or compilation did not produce valid NE output."""


@dataclass
class Delphi16Result:
    """Artifacts from one fresh whole-program compilation."""

    exe_path: Path
    funcs: list[NeFunction] = field(default_factory=list)
    log: str = ""
    map_path: Path | None = None
    compiler_args: list[str] = field(default_factory=list)


def _is_83_safe(name: str) -> bool:
    base, dot, extension = name.partition(".")
    return bool(
        base
        and len(base) <= 8
        and len(extension) <= 3
        and (not dot or "." not in extension)
        and all(ch.isascii() and (ch.isalnum() or ch in "_.-") for ch in name)
    )


def _stage_unit_sources(source: Path, sandbox: Path) -> None:
    """Stage current sibling units, refusing DOS filename collisions and truncation."""
    staged = {source.name.casefold()}
    for sibling in sorted(source.parent.iterdir()):
        if (
            not sibling.is_file()
            or sibling == source
            or sibling.suffix.lower() not in _UNIT_SUFFIXES
        ):
            continue
        if not _is_83_safe(sibling.name):
            raise Delphi16Error(f"unit {sibling.name} has a basename DOSBox would 8.3-truncate")
        name = sibling.name.casefold()
        if name in staged:
            raise Delphi16Error(f"unit {sibling.name} collides with another DOS filename")
        staged.add(name)
        shutil.copy2(sibling, sandbox / sibling.name)


def compile_ne(
    dpr_source: str | Path,
    workdir: str | Path | None = None,
    *,
    timeout: int = 180,
    units_dir: str | Path | None = None,
    extra_args: Sequence[str] = (),
    dcc_cfg: str | bytes | None = None,
    stage_siblings: bool = True,
    map_file: bool = False,
) -> Delphi16Result:
    """Compile a complete Pascal program in the delphi-1.0 Docker image.

    Sources retain their bytes and 8.3 basename; longer program names use
    SRC.DPR. Current sibling units/resources are staged by default. Compiler
    and standard RTL/VCL files come from the image, never a host DOSBox/Wine
    install. An explicit units_dir replaces its library tree.

    Each call gets a fresh input/output directory below workdir, so old
    executables, maps and compiled units cannot satisfy a failed build. The
    default sandbox is cleaned at process exit; pass workdir to retain it.
    -B always rebuilds source units. map_file adds -GS to the same invocation,
    preserving every other switch and requiring a newly produced map.

    Returns the executable, optional map, compiler log and discovered native
    NE functions. Compilation alone does not establish a byte-match verdict.
    """
    if isinstance(extra_args, str):
        raise Delphi16Error("extra_args must be a sequence of individual compiler arguments")
    for arg in extra_args:
        if not arg or any(ord(ch) < 32 or ch in '&|<>^%"' for ch in arg):
            raise Delphi16Error(
                "DCC argument contains DOS command separators or control characters"
            )
    source = Path(dpr_source)
    try:
        source_exists = source.is_file()
    except OSError:
        source_exists = False
    if isinstance(dpr_source, Path) and not source_exists:
        raise Delphi16Error(f"source not found: {dpr_source}")
    name = source.name if source_exists else "PROBE.DPR"
    staged_name = name if _is_83_safe(name) else "SRC.DPR"
    payload = (
        source.read_bytes()
        if source_exists
        else str(dpr_source).encode("utf-8", errors="surrogateescape")
    )
    if workdir is None:
        base = make_sandbox_dir("delphi16-")
    else:
        base = Path(workdir)
        base.mkdir(parents=True, exist_ok=True)
    sandbox = Path(tempfile.mkdtemp(prefix="build-", dir=base))
    (sandbox / staged_name).write_bytes(payload)
    if stage_siblings and source_exists:
        _stage_unit_sources(source, sandbox)
    if units_dir is not None:
        library = Path(units_dir)
        if not library.is_dir():
            raise Delphi16Error(f"units directory not found: {library}")
        shutil.copytree(library, sandbox / "DELPHI" / "LIB")
    if dcc_cfg is not None:
        (sandbox / "DCC.CFG").write_bytes(
            dcc_cfg if isinstance(dcc_cfg, bytes) else dcc_cfg.encode("utf-8")
        )
    flags = ["-B", *(arg for arg in extra_args if arg != "-B")]
    if map_file and "-GS" not in flags:
        flags.append("-GS")
    try:
        spec = get_toolchain("delphi-1.0")
        if not spec.image:
            raise Delphi16Error("delphi-1.0 requires a Docker image")
        result = run_toolchain(
            spec,
            [*flags, staged_name],
            workdir=sandbox,
            timeout=timeout,
        )
    except ToolchainError as exc:
        raise Delphi16Error(str(exc)) from exc
    log = read_uppercase(sandbox, "dccout.txt") or result.stdout
    if result.returncode != 0:
        raise Delphi16Error(f"DCC failed:\n{log}\n{result.stderr}")
    stem = Path(staged_name).stem.upper()
    executable = next((p for p in sandbox.iterdir() if p.name.upper() == f"{stem}.EXE"), None)
    if executable is None:
        raise Delphi16Error(f"DCC produced no executable:\n{log}")
    map_path = None
    if map_file:
        map_path = next((p for p in sandbox.iterdir() if p.name.upper() == f"{stem}.MAP"), None)
        if map_path is None:
            raise Delphi16Error(f"DCC produced no requested map:\n{log}")
    from rebrew.formats.binary_loader import is_ne, load_binary
    from rebrew.formats.ne_loader import enumerate_ne_functions

    if not is_ne(executable):
        raise Delphi16Error(f"compiled output is not an NE executable: {executable}")
    functions = list(enumerate_ne_functions(load_binary(executable)))
    return Delphi16Result(executable, functions, log, map_path, [*flags, staged_name])


__all__ = ["Delphi16Error", "Delphi16Result", "compile_ne"]
