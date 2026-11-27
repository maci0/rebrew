"""PDB compiler, flags, and function-name extraction via ``llvm-pdbutil``.

Pure format parser shared by :mod:`rebrew.pdb_info` (CLI command) and
:mod:`rebrew.toolchain_detect` (library detector).  Parsing goes through
``llvm-pdbutil``, which supports PDB 7.0+ (VC7+ and modern compilers).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
lazy import re
lazy import shutil
lazy import subprocess
lazy from collections.abc import Callable
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.utils import run_process_group

log = logging.getLogger(__name__)

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
    """Locate a sibling .pdb: next to the binary, then original/<stem>.pdb."""
    candidates = [
        binary.with_suffix(".pdb"),
        binary.parent / "original" / f"{binary.stem}.pdb",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _run_pdbutil(
    args: list[str],
    pdb: Path,
    timeout: int = 30,
    *,
    runner: Callable[..., Any] | None = None,
) -> str:
    """Run llvm-pdbutil; returns combined output, '' on any failure (incl. crashes)."""
    if shutil.which("llvm-pdbutil") is None:
        return ""
    run_fn = run_process_group if runner is None else runner
    try:
        r = run_fn(
            ["llvm-pdbutil", *args, str(pdb)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("llvm-pdbutil %s failed on %s: %s", " ".join(args), pdb, exc)
        return ""
    if r.returncode != 0:
        log.warning(
            "llvm-pdbutil %s exited %d on %s: %s",
            " ".join(args),
            r.returncode,
            pdb,
            (r.stderr or r.stdout or "").strip()[:200],
        )
        return ""
    return (r.stdout or "") + (r.stderr or "")


_COMPILE3_RE = re.compile(r"S_COMPILE3.*?(?=\n\s*S_|\Z)", re.S)
_FRONTEND_RE = re.compile(r"frontend\s*=\s*([^\n,]+)")
_BACKEND_RE = re.compile(r"backend\s*=\s*([^\n,]+)")
_FLAGS_RE = re.compile(r"flags\s*=\s*([^\n,]+)")


def parse_compile3(text: str) -> tuple[str, str, list[str]]:
    """Extract frontend/backend versions + flags from an S_COMPILE3 block."""
    m = _COMPILE3_RE.search(text)
    if not m:
        return "", "", []
    block = m.group(0)
    frontend = backend = ""
    flags: list[str] = []
    fm = _FRONTEND_RE.search(block)
    if fm:
        frontend = fm.group(1).strip()
    bm = _BACKEND_RE.search(block)
    if bm:
        backend = bm.group(1).strip()
    fl = _FLAGS_RE.search(block)
    if fl and fl.group(1).strip().lower() not in ("none", ""):
        flags = [tok for tok in re.split(r"[|\s]+", fl.group(1)) if tok]
    return frontend, backend, flags


_PROC_RE = re.compile(
    r"^[ \t]*(?:\d+[ \t]*\|[ \t]*)?S_(?:G|L)PROC32(?:_ID)? \[size = \d+\]"
    r"(?:[^\S\n]+`([^`]+)`)?(.*?)"
    r"(?=\n[ \t]*(?:\d+[ \t]*\|[ \t]*)?S_[A-Z0-9_]+ \[size = \d+\]|\Z)",
    re.S | re.M,
)
_NAME_RE = re.compile(r"name\s*=\s*'([^']+)'")
_DEBUG_START_RE = re.compile(r"debug start\s*=\s*(0x[0-9a-fA-F]+|\d+)")
_DEBUG_END_RE = re.compile(r"debug end\s*=\s*(0x[0-9a-fA-F]+|\d+)")


def parse_procs(text: str) -> list[dict[str, object]]:
    """Best-effort function-name extraction from S_GPROC32/S_LPROC32 records."""
    out: list[dict[str, object]] = []
    for m in _PROC_RE.finditer(text):
        inline = m.group(1)
        block = m.group(2) or ""
        name = inline
        nm = _NAME_RE.search(block)
        if nm:
            name = nm.group(1)
        if not name:
            continue
        entry: dict[str, object] = {"name": name}
        sm = _DEBUG_START_RE.search(block)
        em = _DEBUG_END_RE.search(block)
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


def extract_pdb_info(binary: Path, *, runner: Callable[..., Any] | None = None) -> PdbInfo | None:
    """Extract PDB facts for *binary*; None when no PDB or no usable tooling."""
    pdb = _find_pdb(binary)
    if pdb is None:
        return None
    info = PdbInfo(pdb=pdb)

    syms = _run_pdbutil(["dump", "-symbols"], pdb, runner=runner)
    if not syms:
        info.error = (
            "llvm-pdbutil unavailable or failed (classic VC2-6 PDBs unsupported; VC7 may crash it)"
        )
        return info
    info.frontend, info.backend, info.flags = parse_compile3(syms)
    info.functions = parse_procs(syms)

    mods = _run_pdbutil(["dump", "-modules"], pdb, runner=runner)
    if ".zig-cache" in mods:
        info.toolchain = "zig"
    elif info.frontend:
        info.toolchain = _frontend_hint(info.frontend) or "msvc"
    return info
