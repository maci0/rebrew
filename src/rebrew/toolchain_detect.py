"""Toolchain detection for target binaries.

Heuristically identifies which compiler family (and roughly which era) built
a target PE, so tools can warn when the configured compiler profile does not
align with what the binary actually is.  Detection is evidence-based: each
signal contributes evidence strings, and the family with the strongest
signals wins.  Nothing here is authoritative — every heuristic can be fooled —
so callers should treat a mismatch as a strong hint, not a verdict.

Families:

- ``msvc`` — MSVC 4.x–6.x classic CRT (static or dynamic).  Evidence: the
  ``Microsoft Visual C++ Runtime Library`` / ``Runtime Error!`` strings,
  MSVC-style ``8d 74 26 00`` alignment nops, ``cc cc`` padding, msvcrt.dll
  imports, no ``.buildid`` section.
- ``mingw`` — MinGW GCC (GNU ld).  Evidence: ``.buildid`` section, GNU
  multi-byte ``0f 1f`` nops, call-based ``___chkstk_ms`` stack probe, few or
  no imports.
- ``zig`` — Zig (``zig cc`` targeting MinGW-w64).  Indistinguishable from
  MinGW GCC by code shape; confirmed via a nearby PDB whose module path
  contains ``.zig-cache`` (requires ``llvm-pdbutil``).  Falls back to
  ``mingw`` with a note when no PDB is available.
- ``delphi`` — Borland Delphi.  Evidence: Delphi RTL strings
  (``ClassType``, ``InheritsFrom``, ``EOutOfMemory``, ...) and Borland-style
  ``CODE``/``DATA``/``BSS`` section names.
- ``borlandc`` — Borland C/C++ (Turbo C, C++Builder).  Same ``CODE``/``DATA``/
  ``BSS`` layout as Delphi but no Delphi RTL strings; runtime imports
  (``CW32.DLL``, ``CC3250MT.DLL``, ``BORLNDMM.DLL``) or Borland runtime strings.
- ``watcom`` — Watcom C/C++ (WATCOM 9.x–11.0, Open Watcom).  Evidence:
  underscore-prefixed ``_TEXT``/``_DATA``/``_BSS`` sections and Watcom runtime
  strings.  No rebrew profile can byte-match these (or borlandc/delphi) yet —
  ``rebrew doctor`` flags them as blockers; the OmniBlade mirror hosts wcc
  toolchains if a profile is ever added.

Usage::

    info = detect_toolchain(binary_path)
    print(info.family, info.version_hint, info.evidence)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from rebrew.binary_loader import load_binary

# ---------------------------------------------------------------------------
# Evidence markers
# ---------------------------------------------------------------------------

_DELPHI_MARKERS = (
    "ClassType",
    "InheritsFrom",
    "NewInstance",
    "FreeInstance",
    "ClassNameIs",
    "MethodAddress",
    "SOFTWARE\\Borland\\Delphi",
    "EOutOfMemory",
    "EInOutError",
)

_MSVC_MARKERS = (
    "Microsoft Visual C++ Runtime Library",
    "Runtime Error!",
    "__GLOBAL_HEAP_SELECTED",
    "abnormal program termination",
)

_BORLAND_SECTIONS = {"CODE", "DATA", "BSS"}

# Watcom C/C++ (Open Watcom / WATCOM 9.x-11.0) uses underscore-prefixed
# section names instead of MSVC's dotted or Borland's bare ones.
_WATCOM_SECTIONS = {"_TEXT", "_DATA", "_BSS"}
_WATCOM_MARKERS = ("Open Watcom", "Watcom C/C++", "Watcom Run-time Library", "WATCOM C/C++")

# Borland C/C++ (Turbo C, C++Builder) — distinct from Delphi: same CODE/DATA/
# BSS section layout but no Delphi RTL strings, and its own runtime imports.
_BORLANDC_MARKERS = ("Borland C++", "Borland C Runtime", "Turbo C", "BORLAND")
#: Compilers with no rebrew byte-matching profile yet — detected for the
#: dossier, documented as blockers (diec identifies them reliably).
_SYMANTEC_MARKERS = ("Symantec C++", "Symantec C/C++", "Symantec C++ Runtime")
_ZORTECH_MARKERS = ("Zortech C++", "Zortech C")
_ICC_MARKERS = ("Intel C++ Compiler", "Intel(R) C++ Compiler", "Intel C/C++")
_BORLANDC_IMPORTS = {
    "cw32.dll",
    "cc32.dll",
    "cc3250mt.dll",
    "cw3250mt.dll",
    "borlndmm.dll",
}

#: Where a vendored Detect It Easy lives inside the rebrew repo (tools/diec).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_VENDORED_DIEC = _REPO_ROOT / "tools" / "diec" / "diec"

#: MSVC version strings DIE reports (e.g. "12.00.9782" = MSVC 6.0) mapped to
#: the era rebrew profiles care about.  Only used to pick a version hint —
#: family detection comes from the name, not the number.
_MSVC_VERSION_HINTS = {
    "10.00": "MSVC 4.x",
    "11.00": "MSVC 5.0",
    "12.00": "MSVC 6.0",
    "13.10": "MSVC 7.1",
    "13.00": "MSVC 7.0",
    "14.00": "MSVC 8.0",
}


@dataclass
class ToolchainInfo:
    """Result of a toolchain detection pass."""

    family: str = "unknown"  # msvc | mingw | zig | delphi | unknown
    version_hint: str = ""  # e.g. "MSVC 6.0" / "pre-8 GCC (push-arg style)"
    confidence: str = "low"  # low | medium | high
    evidence: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)  # compiler flags (PDB-derived)
    detected_by: str = ""  # which backend found the family: die | pdb | heuristics
    arch: str = ""  # "x86_16" for NE binaries, "" when unknown (PE/ELF assumed 32/64)
    crt: str = ""  # CRT linkage name: "msvcrt.dll"/"crtdll.dll" (dynamic), "LIBCMT" (static)
    crt_linkage: str = ""  # "dynamic" | "static" | "" (unknown)
    base_cflags: str = ""  # suggested base_cflags: "/MD" or "/MT" for MSVC-family binaries

    def add(self, text: str) -> None:
        self.evidence.append(text)


# ---------------------------------------------------------------------------
# Backend 1: Detect It Easy (diec)
# ---------------------------------------------------------------------------


def _find_diec() -> Path | None:
    """Locate a runnable ``diec``: PATH first, then the vendored copy."""
    found = shutil.which("diec")
    if found:
        return Path(found)
    if _VENDORED_DIEC.exists():
        return _VENDORED_DIEC
    return None


def _diec_env(diec: Path) -> dict[str, str]:
    """Env for running a vendored diec (bundled Qt5/ICU in tools/diec/lib)."""
    env = {**os.environ}
    libdir = diec.parent / "lib"
    if libdir.is_dir():
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{libdir}:{existing}" if existing else str(libdir)
    return env


def _run_diec(path: Path, diec: Path | None = None) -> list[dict[str, object]] | None:
    """Run diec and return its ``detects`` list, or None on any failure.

    A vendored diec may abort at startup on hosts with a mismatched Qt —
    that is treated as "diec unavailable" (return None), never an exception.
    """
    if diec is None:
        diec = _find_diec()
    if diec is None:
        return None
    try:
        r = subprocess.run(
            [str(diec), "-j", "--heuristicscan", str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            env=_diec_env(diec),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    raw = (r.stdout or "") + (r.stderr or "")
    start = raw.find("{")
    if start < 0:
        return None
    try:
        data = json.loads(raw[start:])
    except (json.JSONDecodeError, ValueError):
        return None
    return data.get("detects") or []


def _linker_era_hint(ver: str) -> str:
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
    return ""


def _diec_version_hint(dets: list[dict[str, object]]) -> str:
    """Derive a version hint from DIE's compiler/linker version strings."""
    for det in dets:
        values = det.get("values") or []
        if not isinstance(values, list):
            continue
        for v in values:
            name = str(v.get("name") or "")
            ver = str(v.get("version") or "")
            if "Visual C/C++" in name and ver:
                for prefix, hint in _MSVC_VERSION_HINTS.items():
                    if ver.startswith(prefix):
                        return hint
                return f"MSVC {ver}"
            if "Delphi" in name and ver:
                return f"Borland Delphi {ver}"
            if "Watcom" in name or "Open Watcom" in name:
                return f"Watcom C/C++ {ver}".strip()
            if ("Borland C" in name or "Turbo C" in name) and ver:
                return f"Borland C/C++ {ver}"
            if "GNU C" in name or "MinGW" in name:
                if ver:
                    return f"GCC {ver}".strip()
                return "MinGW GCC" if "MinGW" in name else "GNU C"
    # No compiler record — fall back to the linker version, which still pins
    # the MSVC era.
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
                    era = _linker_era_hint(ver)
                    return f"{era or 'MSVC-era'} (linker {ver})"
    return ""


def detect_with_die(path: Path, diec: Path | None = None) -> ToolchainInfo | None:
    """Detect via Detect It Easy.

    Always returns a ToolchainInfo (never raises): a missing or broken diec
    yields ``family="unknown"`` with evidence explaining the diec status, so
    callers can tell "DIE ran but found nothing" apart from "no diec".
    """
    if diec is None:
        diec = _find_diec()
    if diec is None:
        info = ToolchainInfo(detected_by="die")
        info.add("DIE: diec not found (PATH or tools/diec) — install for stronger detection")
        return info

    dets = _run_diec(path, diec)
    if not dets:
        info = ToolchainInfo(detected_by="die")
        info.add(f"DIE: diec present at {diec} but did not produce a scan result")
        return info

    info = ToolchainInfo(detected_by="die")
    info.add(f"DIE: diec at {diec}")
    for det in dets:
        values = det.get("values") or []
        if not isinstance(values, list):
            continue
        for v in values:
            vtype = str(v.get("type") or "")
            name = str(v.get("name") or "")
            string = str(v.get("string") or "")
            if vtype == "Compiler":
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
            elif vtype == "Linker":
                info.add(f"DIE: linker {string or name}")
                low = name.lower()
                if info.family == "unknown" and "turbo linker" in low and "delphi" in low:
                    info.family = "delphi"
                elif info.family == "unknown" and "microsoft linker" in low:
                    info.family = "msvc"

    if info.family != "unknown":
        info.confidence = "high"
        info.version_hint = _diec_version_hint(dets)
    else:
        # DIE ran but found no compiler/linker signature (e.g. MinGW GCC
        # PE builds have none) — report the scan but let lower backends
        # decide the family.
        info.add("DIE: no compiler/linker signature (scanned)")
        info.family = "unknown"
        info.confidence = "low"
    return info


# ---------------------------------------------------------------------------
# Backend 2: PDB analysis (llvm-pdbutil)
# ---------------------------------------------------------------------------


def _scan_strings(path: Path, limit: int = 256) -> list[str]:
    """Return printable ASCII strings from the file (best effort, capped)."""
    try:
        data = path.read_bytes()
    except OSError:
        return []
    out: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
        out.append(m.group().decode("ascii", errors="replace"))
        if len(out) >= limit:
            break
    return out


def _gcc_era_hint(count_modern: int, count_old: int) -> str:
    """Classify MinGW codegen era from arg-passing style counts.

    Modern GCC (>= ~8) emits ``mov [esp+N], imm`` arg stores
    (accumulate-outgoing-args); older GCC pushes args.  A strong majority of
    one style hints at the era.
    """
    total = count_modern + count_old
    if total < 4:
        return ""
    if count_old >= total * 0.6:
        return "pre-8 GCC style (push-arg passing)"
    if count_modern >= total * 0.6:
        return "modern GCC style (accumulate-outgoing-args)"
    return "mixed GCC codegen styles"


def _pdb_compile_record(path: Path) -> dict[str, str] | None:
    """Parse the PDB's S_COMPILE3 record via llvm-pdbutil (best effort).

    Returns dict with keys like ``frontend``, ``backend``, ``flags``, or None
    when no PDB / no llvm-pdbutil / no record.  The record carries the
    compiler version and (for MSVC PDBs with full debug info) the exact
    compiler command-line flags — the only reliable off-the-shelf source of
    the author's real flags.
    """
    if shutil.which("llvm-pdbutil") is None:
        return None
    pdb = path.with_suffix(".pdb")
    if not pdb.exists():
        return None
    try:
        r = subprocess.run(
            ["llvm-pdbutil", "dump", "-symbols", str(pdb)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = r.stdout + r.stderr
    m = re.search(r"S_COMPILE3.*?(?=\n\s*S_|\Z)", text, re.S)
    out: dict[str, str] = {}
    if m:
        block = m.group(0)
        for key in ("frontend", "backend", "flags"):
            km = re.search(rf"{key}\s*=\s*([^\n,]+)", block)
            if km:
                out[key] = km.group(1).strip()

    # The Zig marker lives in the module list (.zig-cache paths), not the
    # compile record — check it whenever a PDB exists.
    zig = _pdb_zig_modules(pdb)
    if zig:
        out["zig"] = "1"
    if not out:
        return None
    return out


def _pdb_zig_modules(pdb: Path) -> dict[str, str] | None:
    """Check the PDB module list for a .zig-cache path (Zig marker)."""
    try:
        r = subprocess.run(
            ["llvm-pdbutil", "dump", "-modules", str(pdb)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if ".zig-cache" in (r.stdout + r.stderr):
        return {"zig": "1"}
    return None


def detect_with_pdb(path: Path) -> ToolchainInfo | None:
    """Detect via a sibling .pdb (compiler version + flags, Zig marker).

    Returns None when there is no PDB or no usable tooling.
    """
    record = _pdb_compile_record(path)
    if not record:
        return None

    info = ToolchainInfo(detected_by="pdb")
    frontend = record.get("frontend", "")
    backend = record.get("backend", "")
    flags = record.get("flags", "")
    if record.get("zig") or ".zig-cache" in flags or "zig" in (frontend + backend).lower():
        info.family = "zig"
        info.confidence = "high"
        info.version_hint = f"Zig/LLVM {frontend or backend}".strip()
        info.add("PDB module path names .zig-cache (Zig build)")
        return info
    info.add("PDB S_COMPILE3 record present")
    if frontend:
        info.family = "msvc"
        info.confidence = "medium"
        info.version_hint = f"MSVC frontend {frontend}"
        info.add(f"PDB compiler frontend {frontend}, backend {backend}")
    if flags and flags.lower() not in ("none", ""):
        info.flags = [f.strip() for f in flags.split() if f.strip()]
        info.add(f"PDB compiler flags: {flags}")
    if info.family == "unknown":
        return None
    return info


def detect_toolchain(path: Path | str) -> ToolchainInfo:
    """Detect the compiler family behind *path*.

    Backends run best-first and their evidence merges:
    DIE (``diec``) -> PDB (``llvm-pdbutil``) -> structural heuristics.
    A backend that fails or is unavailable is skipped silently; the family
    decision uses the first backend that identifies one, enriched by the
    version/flags evidence of the others.

    Never raises: an unreadable or unrecognized binary yields
    ``ToolchainInfo(family="unknown", confidence="low")``.
    """
    path = Path(path)
    info = ToolchainInfo()

    # --- Backend 1: DIE (strongest family/version signatures) ---
    die_info = detect_with_die(path)
    if die_info is not None:
        info.evidence.extend(die_info.evidence)
        if die_info.family != "unknown":
            info.family = die_info.family
            info.confidence = die_info.confidence
            info.version_hint = die_info.version_hint
            info.detected_by = "die"

    # --- Backend 2: PDB (version + exact flags; Zig marker) ---
    pdb_info = detect_with_pdb(path)
    if pdb_info is not None:
        info.evidence.extend(pdb_info.evidence)
        if pdb_info.flags:
            info.flags = pdb_info.flags
        if info.family == "unknown":
            info.family = pdb_info.family
            info.confidence = pdb_info.confidence
            info.version_hint = pdb_info.version_hint
            info.detected_by = "pdb"
        elif pdb_info.family == "zig" and info.family == "mingw":
            # Zig is only distinguishable from MinGW via the PDB
            info.family = "zig"
            info.confidence = "high"
            info.version_hint = pdb_info.version_hint
            info.detected_by = "pdb"

    # --- Backend 3: structural heuristics (always available) ---
    # String signals run FIRST — they decide the family for formats
    # load_binary cannot parse (e.g. 16-bit NE Delphi), where the
    # section/import/codegen signals below are unavailable.
    strings = _scan_strings(path)
    delphi_hits = [s for s in strings if s in _DELPHI_MARKERS]
    if not delphi_hits:
        # The capped string list can miss markers beyond the first 256
        # strings (16-bit NE files carry long header/name tables first).
        # A full-file byte scan catches them regardless of position.
        try:
            raw = path.read_bytes()
        except OSError:
            raw = b""
        if b"Borland Delphi" in raw:
            delphi_hits = ["Borland Delphi"]
        else:
            delphi_hits = [m for m in _DELPHI_MARKERS if m.encode() in raw][:3]
    msvc_hits = [s for s in strings if s in _MSVC_MARKERS]
    watcom_hits = [m for m in _WATCOM_MARKERS if any(m in s for s in strings)]
    borlandc_hits = [m for m in _BORLANDC_MARKERS if any(m in s for s in strings)]
    symantec_hits = [m for m in _SYMANTEC_MARKERS if any(m in s for s in strings)]
    zortech_hits = [m for m in _ZORTECH_MARKERS if any(m in s for s in strings)]
    icc_hits = [m for m in _ICC_MARKERS if any(m in s for s in strings)]
    if delphi_hits:
        info.add(f"Delphi RTL strings: {', '.join(delphi_hits[:3])}")
    if msvc_hits:
        info.add(f"MSVC CRT strings: {', '.join(msvc_hits[:2])}")
    if watcom_hits:
        info.add(f"Watcom runtime strings: {', '.join(watcom_hits[:2])}")
    if borlandc_hits and not delphi_hits:
        info.add(f"Borland C/C++ strings: {', '.join(borlandc_hits[:2])}")
    if symantec_hits:
        info.add(f"Symantec C++ strings: {', '.join(symantec_hits[:2])}")
    if zortech_hits:
        info.add(f"Zortech C++ strings: {', '.join(zortech_hits[:2])}")
    if icc_hits:
        info.add(f"Intel C++ strings: {', '.join(icc_hits[:2])}")

    try:
        binfo = load_binary(path)
    except Exception:
        # Unparseable format (16-bit NE, unknown) — string evidence still
        # identifies the family; only section/import/codegen signals are lost.
        if info.family == "unknown":
            if delphi_hits:
                info.family = "delphi"
                info.confidence = "medium"
                info.version_hint = "Delphi RTL strings present"
            elif borlandc_hits:
                info.family = "borlandc"
                info.confidence = "medium"
                info.version_hint = "Borland C/C++ runtime strings present"
        return info

    # --- 16-bit NE targets: the segment marker convention tells the family ---
    if getattr(binfo, "format", "") == "ne":
        from rebrew.ne_loader import has_borland_marker

        data = binfo.data
        ne_segments = getattr(binfo, "ne_segments", []) or []
        marker_segs = sum(
            1
            for seg in ne_segments
            if seg.length and has_borland_marker(data, seg.file_offset, seg.index)
        )
        ne_imports = getattr(binfo, "ne_imports", []) or []
        if ne_imports:
            info.add(f"NE imports: {', '.join(m.module for m in ne_imports[:6])}")
        if info.family == "unknown":
            # String evidence outranks the marker heuristic (a synthetic or
            # stripped NE may lack segment markers but still carry RTL strings).
            if delphi_hits:
                info.family = "delphi"
                info.confidence = "medium"
                info.version_hint = "Delphi RTL strings present"
            elif marker_segs:
                info.family = "delphi"
                info.confidence = "high"
                info.version_hint = "Borland (Delphi/Turbo Pascal) NE segment markers"
            elif borlandc_hits:
                info.family = "borlandc"
                info.confidence = "medium"
                info.version_hint = "Borland C/C++ runtime strings present"
            elif any(getattr(seg, "length", 0) for seg in ne_segments):
                # A real markerless NE with content is MSVC-style 16-bit
                # (entry code opens ``push ds/pop ax/nop/inc bp``); a
                # truncated/synthetic NE with no segments stays unknown.
                info.family = "msvc"
                info.confidence = "medium"
                info.version_hint = "16-bit MSVC-style NE (no Borland segment markers)"
            info.detected_by = "ne"
            # NE executables are 16-bit x86 — only 16-bit-capable profiles
            # (msvc1.52, watcom) can ever byte-match them.
            info.arch = "x86_16"
        return info

    sections = {s.name for s in binfo.sections.values()}
    imports: set[str] = set()
    # binfo.imports is not populated by every loader — use the dedicated
    # import-table parser (LIEF-backed) when the generic field is empty.
    bin_imports = getattr(binfo, "imports", None) or []
    for imp in bin_imports:
        dll = str(getattr(imp, "dll", "") or "")
        if dll:
            imports.add(dll.lower())
    if not imports and getattr(binfo, "format", "") == "pe":
        try:
            from rebrew.imports import parse_imports

            for entry in parse_imports(path):
                dll = str(entry.get("dll") or "").lower()
                if dll:
                    imports.add(dll)
        except Exception:
            pass  # import scan is best-effort — string evidence still applies

    # --- section-level signals ---
    has_buildid = any(n.lower() == ".buildid" for n in sections)
    borland_sections = bool(sections & _BORLAND_SECTIONS)
    watcom_sections = "_TEXT" in sections
    if has_buildid:
        info.add(".buildid section present (GNU ld signature)")
    if borland_sections:
        info.add(f"Borland-style sections: {sorted(sections & _BORLAND_SECTIONS)}")
    if watcom_sections:
        info.add("_TEXT section present (Watcom-style layout)")

    # --- import signals ---
    if "msvcrt.dll" in imports or any(i.startswith("msvcp") for i in imports):
        info.add("msvcrt.dll imported (MSVC dynamic CRT)")
        info.crt = "msvcrt.dll"
        info.crt_linkage = "dynamic"
        info.base_cflags = "/MD"
    elif "crtdll.dll" in imports:
        info.add("crtdll.dll imported (MSVC 4.x dynamic CRT)")
        info.crt = "crtdll.dll"
        info.crt_linkage = "dynamic"
        info.base_cflags = "/MD"
    elif imports and info.family == "msvc" and not imports <= {"kernel32.dll"}:
        # No CRT DLL import but MSVC family with real imports → statically
        # linked CRT (/MT).  Weak signal; only asserted when the family is
        # already established by a stronger backend.
        info.crt = "LIBCMT"
        info.crt_linkage = "static"
        info.base_cflags = "/MT"
    if not imports:
        info.add("no imports (standalone build)")
    elif imports <= {"kernel32.dll"}:
        info.add(f"minimal imports: {sorted(imports)}")
    borlandc_imports = imports & _BORLANDC_IMPORTS
    if borlandc_imports:
        info.add(f"Borland C/C++ runtime imports: {sorted(borlandc_imports)}")

    # --- codegen style in .text (byte-level encodings) ---
    gnu_nops = 0
    msvc_nops = 0
    int3_pads = 0
    old_push_calls = 0
    modern_mov_calls = 0
    try:
        from rebrew.binary_loader import extract_bytes_at_va

        text_bytes = (
            extract_bytes_at_va(binfo, binfo.text_va, binfo.text_size)
            if binfo.text_size
            else binfo.data
        )
        if not text_bytes:
            text_bytes = b""
        gnu_nops = text_bytes.count(bytes.fromhex("0f 1f 00")) + text_bytes.count(
            bytes.fromhex("0f 1f 40 00")
        )
        msvc_nops = text_bytes.count(bytes.fromhex("8d 74 26 00")) + text_bytes.count(
            bytes.fromhex("8d a4 24")
        )
        int3_pads = text_bytes.count(bytes.fromhex("cc cc cc cc"))
        # arg-passing era: `mov dword ptr [esp], imm` (modern GCC) vs `push`
        # immediates (old GCC).  Byte-level approximation.
        modern_mov_calls = text_bytes.count(bytes.fromhex("c7 04 24")) + text_bytes.count(
            bytes.fromhex("89 04 24")
        )
        old_push_calls = text_bytes.count(bytes.fromhex("6a"))
    except Exception:
        pass

    if gnu_nops:
        info.add(f"{gnu_nops} GNU-style 0f 1f nops")
    if msvc_nops:
        info.add(f"{msvc_nops} MSVC-style alignment nops")
    if int3_pads > 10:
        info.add(f"{int3_pads} int3 pad runs (MSVC-style padding)")

    # --- decide the family (only if a better backend hasn't) ---
    if info.family != "unknown":
        # higher backends won; keep their decision but append era hints
        if info.family == "mingw" and not info.version_hint:
            info.version_hint = _gcc_era_hint(modern_mov_calls, old_push_calls)
        return info

    if delphi_hits and borland_sections:
        info.family = "delphi"
        info.confidence = "high"
        info.version_hint = "Borland Delphi (RTL identified)"
    elif delphi_hits:
        info.family = "delphi"
        info.confidence = "medium"
        info.version_hint = "Delphi RTL strings present"
    elif borlandc_hits and borland_sections:
        info.family = "borlandc"
        info.confidence = "high"
        info.version_hint = "Borland C/C++ (runtime strings + section layout)"
    elif borlandc_imports:
        info.family = "borlandc"
        info.confidence = "medium"
        info.version_hint = f"Borland C/C++ (runtime imports: {sorted(borlandc_imports)[0]})"
    elif watcom_sections and watcom_hits:
        info.family = "watcom"
        info.confidence = "high"
        info.version_hint = "Watcom C/C++ (section layout + runtime strings)"
    elif watcom_sections:
        info.family = "watcom"
        info.confidence = "medium"
        info.version_hint = "Watcom C/C++ (section layout)"
    elif symantec_hits:
        info.family = "symantec"
        info.confidence = "medium"
        info.version_hint = "Symantec C++ (runtime strings)"
    elif zortech_hits:
        info.family = "zortech"
        info.confidence = "medium"
        info.version_hint = "Zortech C++ (runtime strings)"
    elif icc_hits:
        info.family = "icc"
        info.confidence = "medium"
        info.version_hint = "Intel C++ (runtime strings)"
    elif has_buildid and gnu_nops:
        info.family = "mingw"
        info.confidence = "high"
        info.version_hint = _gcc_era_hint(modern_mov_calls, old_push_calls)
    elif has_buildid:
        info.family = "mingw"
        info.confidence = "medium"
        info.version_hint = _gcc_era_hint(modern_mov_calls, old_push_calls)
    elif msvc_hits and not gnu_nops:
        info.family = "msvc"
        info.confidence = "high"
        info.version_hint = "classic MSVC CRT"
    elif msvc_hits:
        info.family = "msvc"
        info.confidence = "medium"
        info.version_hint = "classic MSVC CRT"
    elif "msvcrt.dll" in imports:
        info.family = "msvc"
        info.confidence = "medium"
        info.version_hint = "MSVC (dynamic CRT)"
    elif int3_pads > 10 and msvc_nops:
        info.family = "msvc"
        info.confidence = "medium"
        info.version_hint = "MSVC-style codegen"
    else:
        info.family = "unknown"
        info.confidence = "low"
    info.detected_by = info.detected_by or "heuristics"

    return info


#: Compiler profiles that can byte-match each detected family.
#: ``None`` means no supported rebrew compiler can match that family.
_PROFILE_COMPAT: dict[str, set[str] | None] = {
    # msvc1.52 is the 16-bit profile — the detection hint distinguishes
    # "16-bit MSVC-style NE" from 32-bit targets.
    "msvc": {"msvc400", "msvc420", "msvc5", "msvc6", "msvc6.3", "msvc6.6", "msvc7", "msvc1.52"},
    "mingw": {"gcc-pe"},
    "zig": {"gcc-pe"},  # may match structurally only (LLVM vs GCC codegen)
    "watcom": {"watcom"},  # profile exists; byte matching needs the OMF parser (docs/OMF_NOTES.md)
    "delphi": None,
    "borlandc": None,
    "symantec": None,
    "zortech": None,
    "icc": None,
    "unknown": None,
}


def profile_matches_detection(profile: str, info: ToolchainInfo) -> tuple[bool, str | None]:
    """Return ``(aligned, explanation)`` for *profile* vs a detection.

    *aligned* is True when the configured profile can plausibly byte-match
    the detected family; *explanation* carries a fix hint when not.
    """
    compatible = _PROFILE_COMPAT.get(info.family)
    if compatible is None:
        if info.family == "unknown":
            return True, None  # unknown family: don't second-guess the user
        if info.family == "delphi":
            return (
                False,
                "Borland Delphi ABI — no rebrew compiler profile can match; document as blocker.",
            )
        return False, (
            f"{info.family} ABI — no rebrew compiler profile can match; document as blocker "
            "(no supported toolchain)."
        )
    if profile not in compatible:
        return (
            False,
            f"configured profile '{profile}' does not align with detected family '{info.family}' "
            f"({', '.join(sorted(compatible))} would fit) — see docs/TOOLCHAIN.md",
        )
    # Arch dimension: a 16-bit NE binary can only be byte-matched by
    # 16-bit-capable profiles; conversely msvc1.52 cannot match a 32/64-bit
    # PE/ELF.  This catches the "msvc6 profile on a 16-bit NE project"
    # misconfiguration that silently produces COMPILE_ERROR for every
    # function (skifree16-rebrew regression).
    # msvc1.52 is the only 16-bit-capable profile; watcom's wcc386 is a
    # 32-bit compiler (Open Watcom 2.0 x86-32) and must NOT be flagged as
    # 16-bit — a detected Watcom 32-bit binary would falsely fail doctor.
    _BITNESS_16 = {"msvc1.52"}
    if info.arch == "x86_16" and profile not in _BITNESS_16:
        return (
            False,
            f"detected 16-bit NE binary but profile '{profile}' is a 32/64-bit "
            f"compiler — switch to one of: {', '.join(sorted(_BITNESS_16))} "
            "(e.g. msvc1.52) or document the functions as blockers",
        )
    if info.arch and info.arch != "x86_16" and profile in _BITNESS_16:
        return (
            False,
            f"profile '{profile}' is a 16-bit compiler but the binary is "
            f"{info.arch} — use a 32/64-bit profile (e.g. msvc6)",
        )
    if info.family == "zig":
        return (
            True,
            "binary looks Zig-built (LLVM codegen) — gcc-pe may only match structurally; "
            "see docs/TOOLCHAIN.md",
        )
    return True, None
