"""rebrew pdb-info — extract compiler version, flags, and function names from a PDB.

When a target binary ships a sibling ``.pdb``, the PDB's debug info is the
most authoritative offline source of the *exact* build configuration:

- ``S_COMPILE3`` record — compiler frontend/backend versions and (for MSVC
  PDBs with real debug info) the actual command-line flags, i.e. the exact
  ``CFLAGS`` that will byte-match.
- ``S_GPROC32``/``S_LPROC32`` records — function names (and best-effort
  addresses/sizes) for ``functions.txt``.
- module list — a ``.zig-cache`` path identifies a Zig build.

Parsing goes through ``llvm-pdbutil`` (LLVM's PDB dumper).  Note llvm-pdbutil
supports PDB 7.0+ (VC7+ and modern compilers); classic VC2–6 PDBs are a
different format it cannot read, and it has a known crash on some VC7 PDBs —
both are handled gracefully (reported as unsupported, never an exception).

Usage::

    rebrew pdb-info original/game.exe
    rebrew pdb-info game.exe --write-cflags   # set [compiler] cflags from S_COMPILE3
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print

console = Console(stderr=True)

app = typer.Typer(help="Extract compiler version, flags, and function names from a PDB.")

#: S_COMPILE3 frontend version prefix -> MSVC family hint (best effort).
_MSVC_VERSION_HINTS = {
    "13.10": "MSVC 7.1",
    "14.00": "MSVC 8.0",
    "15.00": "MSVC 9.0",
    "16.00": "MSVC 10.0",
}


@dataclass
class PdbInfo:
    """Parsed PDB facts."""

    pdb: Path
    frontend: str = ""
    backend: str = ""
    flags: list[str] = field(default_factory=list)
    toolchain: str = ""  # "msvc" | "zig" | ""
    functions: list[dict[str, object]] = field(default_factory=list)
    error: str = ""


def _find_pdb(binary: Path) -> Path | None:
    """Locate a sibling .pdb: next to the binary, then original/<stem>.pdb.

    (The second candidate used to be the same expression as the first —
    `with_suffix(".pdb")` and `parent / f"{stem}.pdb"` are identical, so the
    documented `original/` fallback never existed — infra-review F7.)
    """
    candidates = [
        binary.with_suffix(".pdb"),
        binary.parent / "original" / f"{binary.stem}.pdb",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _run_pdbutil(args: list[str], pdb: Path, timeout: int = 30) -> str:
    """Run llvm-pdbutil; returns combined output, '' on any failure (incl. crashes)."""
    if shutil.which("llvm-pdbutil") is None:
        return ""
    try:
        r = subprocess.run(
            ["llvm-pdbutil", *args, str(pdb)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (r.stdout or "") + (r.stderr or "")


def _parse_compile3(text: str) -> tuple[str, str, list[str]]:
    """Extract frontend/backend versions + flags from an S_COMPILE3 block."""
    m = re.search(r"S_COMPILE3.*?(?=\n\s*S_|\Z)", text, re.S)
    if not m:
        return "", "", []
    block = m.group(0)
    frontend = backend = ""
    flags: list[str] = []
    fm = re.search(r"frontend\s*=\s*([^\n,]+)", block)
    if fm:
        frontend = fm.group(1).strip()
    bm = re.search(r"backend\s*=\s*([^\n,]+)", block)
    if bm:
        backend = bm.group(1).strip()
    fl = re.search(r"flags\s*=\s*([^\n,]+)", block)
    if fl and fl.group(1).strip().lower() not in ("none", ""):
        flags = [f.strip() for f in fl.group(1).split() if f.strip()]
    return frontend, backend, flags


def _parse_procs(text: str) -> list[dict[str, object]]:
    """Best-effort function-name extraction from S_GPROC32/S_LPROC32 records.

    llvm-pdbutil prints ``S_GPROC32 [size = N]`` followed by detail lines
    (``type = ..., debug start = ..., debug end = ..., flags = ..., name = 'x'``).
    Some builds name the record inline: ``S_LPROC32 [size = N] `name```.
    """
    out: list[dict[str, object]] = []
    # Detail-block form (name = '...' inside the record block).
    for m in re.finditer(
        r"S_(?:G|L)PROC32 \[size = \d+\](?:\s+`([^`]+)`)?(.*?)(?=\n[^\n]*S_(?:G|L)PROC32|\Z)",
        text,
        re.S,
    ):
        inline = m.group(1)
        block = m.group(2) or ""
        name = inline
        nm = re.search(r"name\s*=\s*'([^']+)'", block)
        if nm:
            name = nm.group(1)
        if not name:
            continue
        entry: dict[str, object] = {"name": name}
        sm = re.search(r"debug start\s*=\s*(0x[0-9a-fA-F]+|\d+)", block)
        em = re.search(r"debug end\s*=\s*(0x[0-9a-fA-F]+|\d+)", block)
        if sm:
            entry["start"] = sm.group(1)
        if em:
            entry["end"] = em.group(1)
        out.append(entry)
        if len(out) >= 500:
            break
    return out


def _frontend_hint(frontend: str) -> str:
    for prefix, hint in _MSVC_VERSION_HINTS.items():
        if frontend.startswith(prefix):
            return hint
    return "MSVC" if frontend else ""


def extract_pdb_info(binary: Path) -> PdbInfo | None:
    """Extract PDB facts for *binary*; None when no PDB or no usable tooling."""
    pdb = _find_pdb(binary)
    if pdb is None:
        return None
    info = PdbInfo(pdb=pdb)

    syms = _run_pdbutil(["dump", "-symbols"], pdb)
    if not syms:
        info.error = (
            "llvm-pdbutil unavailable or failed (classic VC2-6 PDBs unsupported; VC7 may crash it)"
        )
        return info
    info.frontend, info.backend, info.flags = _parse_compile3(syms)
    info.functions = _parse_procs(syms)

    mods = _run_pdbutil(["dump", "-modules"], pdb)
    if ".zig-cache" in mods:
        info.toolchain = "zig"
    elif info.frontend:
        info.toolchain = _frontend_hint(info.frontend) or "msvc"
    return info


@app.callback(invoke_without_command=True)
def main(
    binary: str = typer.Argument(..., help="Path to the binary whose sibling .pdb to read."),
    write_cflags: bool = typer.Option(
        False, "--write-cflags", help=r"Write the S_COMPILE3 flags into \[compiler] cflags."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Report compiler version, flags, and function names from the PDB."""
    bin_path = Path(binary)
    if not bin_path.exists():
        msg = f"binary not found: {bin_path}"
        error_exit(msg, json_mode=json_output)

    info = extract_pdb_info(bin_path)
    if info is None:
        error_exit("no sibling .pdb found", json_mode=json_output)

    payload = {
        "pdb": str(info.pdb),
        "toolchain": info.toolchain or "unknown",
        "frontend": info.frontend,
        "backend": info.backend,
        "flags": info.flags,
        "function_count": len(info.functions),
        "functions": info.functions[:20],
        "error": info.error,
    }

    if write_cflags and info.flags and not info.error:
        cfg_path = Path("rebrew-project.toml")
        if not cfg_path.exists():
            payload["cflags_write"] = "skipped: no rebrew-project.toml in cwd"
        else:
            from rebrew.cfg import load_toml, save_toml

            doc, toml_path = load_toml(cfg_path.parent)
            comp = doc.get("compiler")
            if isinstance(comp, dict):
                comp["cflags"] = " ".join(info.flags)
                save_toml(doc, toml_path)
                payload["cflags_write"] = " ".join(info.flags)

    if json_output:
        json_print(payload)
    else:
        console.print(f"[bold]PDB:[/bold] {info.pdb.name}")
        console.print(f"  toolchain: {info.toolchain or 'unknown'}")
        if info.frontend:
            console.print(f"  compiler: frontend {info.frontend} / backend {info.backend}")
        if info.flags:
            console.print(f"  flags: [green]{' '.join(info.flags)}[/green] (candidate CFLAGS)")
        console.print(f"  functions: {len(info.functions)}")
        for fn in info.functions[:10]:
            console.print(f"    - {fn['name']}")
        if info.error:
            console.print(f"  [yellow]{info.error}[/yellow]")


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
