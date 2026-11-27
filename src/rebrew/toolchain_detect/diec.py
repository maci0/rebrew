"""Detect It Easy (diec) backend for toolchain detection."""

from __future__ import annotations

import logging
from pathlib import Path
lazy import json
lazy import os
lazy import shutil
lazy import subprocess

from rebrew.utils import SOURCE_CHECKOUT, run_process_group

from .tables import MSVC_VERSION_HINTS, ToolchainInfo, resolve_pkg_hook

logger = logging.getLogger(__name__)

#: Vendored Detect It Easy in a rebrew source checkout (tools/diec); None in a wheel install.
VENDORED_DIEC = SOURCE_CHECKOUT / "tools" / "diec" / "diec" if SOURCE_CHECKOUT is not None else None

#: The evidence line of a detection that had no Detect It Easy to run.
DIE_UNAVAILABLE = "Detect It Easy not available"


def find_diec() -> Path | None:
    """Locate a runnable ``diec``: PATH first, then the vendored copy."""
    found = shutil.which("diec")
    if found:
        return Path(found)
    if VENDORED_DIEC is not None and VENDORED_DIEC.exists():
        return VENDORED_DIEC
    return None


def diec_env(diec: Path) -> dict[str, str]:
    """Env for running a vendored diec (bundled Qt5/ICU in tools/diec/lib)."""
    env = {**os.environ}
    libdir = diec.parent / "lib"
    if libdir.is_dir():
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{libdir}:{existing}" if existing else str(libdir)
    return env


def run_diec(path: Path, diec: Path | None = None) -> list[dict[str, object]] | None:
    """Run diec and return its ``detects`` list, or None on any failure.

    A vendored diec may abort at startup on hosts with a mismatched Qt —
    that is treated as "diec unavailable" (return None), never an exception.
    """
    if diec is None:
        diec = resolve_pkg_hook(find_diec, _ORIG_FIND_DIEC, "_find_diec", "find_diec")()
    if diec is None:
        return None
    runner = resolve_pkg_hook(run_process_group, _ORIG_RUN_PROCESS_GROUP, "run_process_group")
    env_fn = resolve_pkg_hook(diec_env, _ORIG_DIEC_ENV, "_diec_env", "diec_env")
    try:
        # The resolved path: Detect It Easy 4.0 prints nothing, exit 0, for a path through a
        # symlinked directory.
        r = runner(
            [str(diec), "-j", "--heuristicscan", str(path.resolve())],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env=env_fn(diec),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        # None is also "diec ran and recognised nothing", so a detector that
        # could not start is logged: without it the era/PDB heuristics below
        # pin a profile on partial evidence with no record the primary
        # detector was skipped.
        logger.warning("diec failed on %s (%s); falling back to the other detectors", path, exc)
        return None
    if r.returncode != 0:
        logger.warning(
            "diec exited %d on %s: %s", r.returncode, path, (r.stderr or "").strip()[:200]
        )
        return None
    raw = (r.stdout or "") + (r.stderr or "")
    start = raw.find("{")
    if start < 0:
        # A diec that printed no JSON (abort banner, new output format) is not
        # the same as one that recognised nothing; both mean the primary
        # detector never contributed.
        logger.warning(
            "diec printed no JSON for %s: %s", path, raw.strip()[:200] or "(empty output)"
        )
        return None
    try:
        data = json.loads(raw[start:])
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("diec output for %s is not JSON: %s", path, exc)
        return None
    dets = data.get("detects") or []
    if not isinstance(dets, list) or any(not isinstance(det, dict) for det in dets):
        logger.warning("diec output for %s has invalid detection records", path)
        return None
    return dets


def linker_era_hint(ver: str) -> str:
    """MSVC era implied by the Microsoft Linker version (a fallback when
    diec misses the compiler record — e.g. explorer.exe on Win2K SP4, which
    only yields a Linker + Installer detection)."""
    if ver.startswith(("5.10", "5.11", "5.12")):
        return "MSVC 5.0"
    if ver.startswith("6."):
        return "MSVC 6.0"
    if ver.startswith("7.1"):
        return "MSVC 7.1"
    if ver.startswith("7."):
        return "MSVC 7.0"
    if ver.startswith("8."):
        return "MSVC 8.0"
    if ver.startswith("9."):
        return "MSVC 9.0"
    if ver.startswith("10."):
        return "MSVC 10.0"
    if ver.startswith("11."):
        return "MSVC 11.0"
    return ""


def diec_version_hint(dets: list[dict[str, object]]) -> str:
    """Derive a version hint from DIE's compiler/linker version strings."""
    for det in dets:
        values = det.get("values") or []
        if not isinstance(values, list):
            continue
        for v in values:
            if not isinstance(v, dict):
                continue
            name = str(v.get("name") or "")
            ver = str(v.get("version") or "")
            if "Visual C/C++" in name and ver:
                for prefix, hint in MSVC_VERSION_HINTS.items():
                    if ver.startswith(prefix):
                        return hint
                return f"MSVC {ver}"
            if "Delphi" in name and ver:
                return f"Borland Delphi {ver}"
            if ("Watcom" in name or "Open Watcom" in name) and ver:
                return f"Watcom C/C++ {ver}"
            if ("Borland C" in name or "Turbo C" in name) and ver:
                return f"Borland C/C++ {ver}"
            if "GNU C" in name or "MinGW" in name:
                if ver:
                    return f"GCC {ver}".strip()
                return "MinGW GCC" if "MinGW" in name else "GNU C"
    # No compiler record — fall back to the linker version, which still pins
    # the MSVC era.
    era_hint_fn = resolve_pkg_hook(
        linker_era_hint, _ORIG_LINKER_ERA_HINT, "_linker_era_hint", "linker_era_hint"
    )
    for det in dets:
        values = det.get("values") or []
        if not isinstance(values, list):
            continue
        for v in values:
            if not isinstance(v, dict):
                continue
            if str(v.get("name") or "") == "Microsoft Linker":
                ver = str(v.get("version") or "")
                if ver:
                    era = era_hint_fn(ver)
                    return f"{era or 'MSVC-era'} (linker {ver})"
    return ""


def detect_with_die(path: Path, diec: Path | None = None) -> ToolchainInfo | None:
    """Detect via Detect It Easy.

    Always returns a ToolchainInfo (never raises): a missing or broken diec
    yields ``family="unknown"`` with evidence explaining the diec status, so
    callers can tell "DIE ran but found nothing" apart from "no diec".
    """
    if diec is None:
        diec = resolve_pkg_hook(find_diec, _ORIG_FIND_DIEC, "_find_diec", "find_diec")()
    if diec is None:
        info = ToolchainInfo(detected_by="die")
        info.add(DIE_UNAVAILABLE)
        return info

    run_fn = resolve_pkg_hook(run_diec, _ORIG_RUN_DIEC, "_run_diec", "run_diec")
    dets = run_fn(path, diec)
    if not dets:
        info = ToolchainInfo(detected_by="die")
        info.add("Detect It Easy produced no scan result")
        return info

    info = ToolchainInfo(detected_by="die")
    for det in dets:
        values = det.get("values") or []
        if not isinstance(values, list):
            continue
        for v in values:
            if not isinstance(v, dict):
                continue
            vtype = str(v.get("type") or "")
            name = str(v.get("name") or "")
            string = str(v.get("string") or "")
            # Detect It Easy 4.0 spells the type in lowercase ("compiler", "linker").
            if vtype == "compiler":
                info.add(f"DIE: compiler {string or name}")
                low = name.lower()
                if "visual c/c++" in low or "visual c++" in low:
                    info.family = "msvc"
                elif "delphi" in low:
                    info.family = "delphi"
                elif "watcom" in low or "open watcom" in low:
                    info.family = "watcom"
                elif "borland c" in low or "turbo c" in low:
                    info.family = "borlandc"
                elif "gnu" in low or "mingw" in low or "gcc" in low:
                    info.family = "mingw"
            elif vtype == "linker":
                info.add(f"DIE: linker {string or name}")
                low = name.lower()
                if info.family == "unknown" and "turbo linker" in low and "delphi" in low:
                    info.family = "delphi"
                elif info.family == "unknown" and "microsoft linker" in low:
                    info.family = "msvc"

    if info.family != "unknown":
        info.confidence = "high"
        hint_fn = resolve_pkg_hook(
            diec_version_hint, _ORIG_DIEC_VERSION_HINT, "_diec_version_hint", "diec_version_hint"
        )
        info.version_hint = hint_fn(dets)
    else:
        # DIE ran but found no compiler/linker signature (e.g. MinGW GCC
        # PE builds have none) — report the scan but let lower backends
        # decide the family.
        info.add("DIE: no compiler/linker signature (scanned)")
        info.family = "unknown"
        info.confidence = "low"
    return info


_ORIG_FIND_DIEC = find_diec
_ORIG_DIEC_ENV = diec_env
_ORIG_RUN_DIEC = run_diec
_ORIG_LINKER_ERA_HINT = linker_era_hint
_ORIG_DIEC_VERSION_HINT = diec_version_hint
_ORIG_RUN_PROCESS_GROUP = run_process_group
