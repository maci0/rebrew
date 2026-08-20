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
  Within the msvc family, a constant-caching fingerprint separates the
  classic compiler eras.  MSVC 4.x/5.0 hoist a loop-invariant constant into
  a callee-saved register and store it via that register (e.g. mov ebx,0x3e8
  then mov [eax],ebx / mov [eax+8],ebx).  MSVC 6.0 folds the constant and
  emits immediate stores instead (mov [eax],0x3e8 / mov [eax+8],0x3e8).  A
  strong mov ebx/ebp/esi/edi,small-imm32 signal therefore marks pre-6.0
  codegen even when DIE names the era as 12.00 (MSVC 6.0) - the compiler
  and the CRT/linker era are independent fingerprints.
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
  Byte-matching: ``tc16`` (Turbo C++ 3.1, 16-bit DOS) and ``borlandc55``
  (bcc32, 32-bit) both produce Borland-flavored objects rebrew can match.
- ``watcom`` — Watcom C/C++ (watcom-win32 9.x–11.0, Open Watcom).  Evidence:
  underscore-prefixed ``_TEXT``/``_DATA``/``_BSS`` sections and Watcom runtime
  strings.  Byte-matching: ``watcom`` (wcc386) and ``watcom16`` (wcc, 16-bit
  DOS) profiles exist; ``rebrew doctor`` no longer flags these as blockers.

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
from typing import Any

import lief

from rebrew.binary_loader import load_binary


def _rich_compiler_build(entries: list[Any]) -> int:
    """The compiler build from Rich-header entries: the most common build.

    The C1/C2 (front/back end) pair shares one build; the linker entry can
    carry a different (newer) one.  The mode picks the pair over a single
    differing linker entry."""
    from collections import Counter

    counts = Counter(e.build_id for e in entries)
    return counts.most_common(1)[0][0]


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

# Watcom C/C++ (Open Watcom / watcom-win32 9.x-11.0) uses underscore-prefixed
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

#: PE optional-header linker version ("major.minor") -> MSVC compiler
#: (major, minor).  The linker version is the strongest per-version signal
#: for the classic linkers, and combined with the Rich-header C1 build it
#: pins the exact compiler (e.g. linker 6.0 + C1 8168 = 12.00.8168 = VC 6.0).
#: Early linkers (2.50-4.20) write no Rich header, so the linker version
#: alone names the version (VC 2.0 .. 4.2).  Note MinGW's GNU ld also writes
#: a 2.x linker version — the Rich header (or the family evidence) must
#: disambiguate a bare 2.x.
_MSVC_LINKER_VERSIONS: dict[str, tuple[int, int]] = {
    "2.0": (9, 0),  # VC 2.0 (CL 9.00)
    "2.5": (9, 0),
    "2.50": (9, 0),
    "3.0": (10, 0),  # VC 4.0 (10.00.5270)
    "3.10": (10, 10),  # VC 4.1 (10.10.6038)
    "4.20": (10, 20),  # VC 4.2 (10.20.7022)
    "5.0": (11, 0),  # VC 5.0 (11.00.7022)
    "5.10": (11, 0),
    "5.12": (11, 0),
    "6.0": (12, 0),  # VC 6.0
    "7.0": (13, 0),  # VC 7.0 (2002)
    "7.10": (13, 10),  # VC 7.1 (.NET 2003)
    "8.0": (14, 0),  # VC 8.0 (2005)
    "9.0": (15, 0),  # VC 9.0 (2008)
    "10.0": (16, 0),  # VC 10.0 (2010)
}


#: Rich-header C1/C2 build numbers -> rebrew profiles carrying that exact
#: compiler build.  Empirically dumped from the rebrew toolchain images:
#: each image's linker records the front-end build, which for the VC 6.0
#: service packs is the C1.DLL build (8168 RTM, 8447 SP3, 8966 SP5, 9782
#: SP6 — SP builds are NOT the same compiler).  A tuple = profiles sharing
#: the same build; the linker version further narrows it
#: (13.10.3077 -> msvc7 vs msvc710).
_RICH_BUILD_PROFILES: dict[int, tuple[str, ...]] = {
    8168: ("msvc6",),  # 12.00.8168 (VC6 RTM)
    8447: ("msvc600sp3",),  # 12.00.8447
    8966: ("msvc600sp5",),  # 12.00.8966
    9782: ("msvc600sp6",),  # 12.00.9782
    9466: ("msvc700", "msvc700sp1"),  # 13.00.9466
    9955: ("msvc700sp1",),  # 13.00.9955 (7.0 SP1 C1)
    3077: ("msvc7", "msvc710"),  # 13.10.3077
    6030: ("msvc710sp1",),  # 13.10.6030
    50727: ("msvc800", "msvc800sp1"),  # 14.00.50727 (+.762 for SP1)
    21022: ("msvc900",),  # 15.00.21022
    30319: ("msvc1000",),  # 16.00.30319
    40219: ("msvc1000sp1",),  # 16.00.40219
}


#: Linker-era default profiles (used when the Rich-header build is unknown):
#: the linker version pins the compiler generation, so an unrecognized build
#: (e.g. a hotfix) still suggests the right family instead of the generic
#: default.  The Rich build table (_RICH_BUILD_PROFILES) overrides this when
#: the exact build is known.
_LINKER_ERA_PROFILES: dict[tuple[int, int], tuple[str, ...]] = {
    (9, 0): ("msvc200",),
    (10, 0): ("msvc400",),
    (10, 10): ("msvc410",),
    (10, 20): ("msvc420",),
    (11, 0): ("msvc5", "msvc500sp1", "msvc500sp2", "msvc500sp3"),
    (12, 0): ("msvc6", "msvc600sp3", "msvc600sp5", "msvc600sp6"),
    (13, 0): ("msvc700", "msvc700sp1"),
    (13, 10): ("msvc7", "msvc710", "msvc710sp1"),
    (14, 0): ("msvc800", "msvc800sp1"),
    (15, 0): ("msvc900",),
    (16, 0): ("msvc1000", "msvc1000sp1"),
}

#: CRT import names -> MSVC version binder (msvcp60.dll = VC 6.0, etc.).
#: The msvcpX.dll import is written by the /MD CRT of that toolchain; a
#: strong secondary signal when the Rich header is absent (some linkers
#: or post-processing strip it).
_MSVCP_IMPORT_VERSIONS: dict[str, str] = {
    "msvcp60.dll": "6.0",
    "msvcp70.dll": "7.0",
    "msvcp71.dll": "7.1",
    "msvcp80.dll": "8.0",
    "msvcp90.dll": "9.0",
    "msvcp100.dll": "10.0",
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
    opt_level: str = ""  # suggested optimization: "/O1" or "/O2" (MSVC codegen fingerprint)
    msvc_version: str = ""  # exact compiler version, e.g. "12.00.8168" (PE metadata)
    suggested_profiles: list[str] = field(default_factory=list)  # version-exact rebrew profiles
    packed: str = ""  # packer name/version when the binary is packed ("lzexe 0.91")

    def add(self, text: str) -> None:
        self.evidence.append(text)


#: User-facing names for the detection backends (doctor/analyze messages must
#: not leak the internal ids).
_BACKEND_DISPLAY: dict[str, str] = {
    "die": "Detect It Easy (diec)",
    "pdb": "PDB",
    "heuristics": "codegen heuristics",
    "pe-meta": "PE metadata (Rich header / linker version)",
}


def backend_display_name(detected_by: str) -> str:
    """Human-readable name for a detection backend id, or the id itself."""
    return _BACKEND_DISPLAY.get(detected_by, detected_by)


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


# pre-6.0 MSVC (4.x/5.0) hoists a loop-invariant constant into a
# callee-saved register and stores it via that register; MSVC 6.0 folds the
# constant into immediate stores.  A strong mov ebx/ebp/esi/edi, small-imm32
# signal marks pre-6.0 codegen even when the CRT/linker era is 6.0.
_HOIST_REGS = (0xBB, 0xBD, 0xBE, 0xBF)  # mov ebx/ebp/esi/edi, imm32


def _count_const_hoists(text: bytes) -> int:
    """Count pre-6.0 constant-caching fingerprints in raw code bytes.

    Pattern: ``mov ebx/ebp/esi/edi, imm32`` with a small (16-bit) immediate,
    followed within a short window by ``mov [mem], same-reg`` (89 /r with a
    memory destination).  That is how MSVC 4.x/5.0 cache a loop-invariant
    constant in a callee-saved register before storing it multiple times;
    MSVC 6.0 folds the constant and emits ``mov [mem], imm32`` (c7) instead.
    The window + same-reg + small-immediate tests keep loop counters and
    address loads out of the count (Win32 pointers have non-zero high bytes).
    """
    n = 0
    reg_field = {0xBB: 3, 0xBD: 5, 0xBE: 6, 0xBF: 7}  # opcode -> 89 /r reg field
    for i in range(len(text) - 5):
        op = text[i]
        reg = reg_field.get(op)
        if reg is None or text[i + 3] != 0 or text[i + 4] != 0:
            continue
        # look ahead for a `mov [mem], reg` (89) using this same register
        window = min(i + 5 + 32, len(text) - 1)
        for j in range(i + 5, window):
            if text[j] == 0x89:
                rm = text[j + 1]
                if (rm >> 6) != 3 and ((rm >> 3) & 7) == reg:
                    n += 1
                    break
    return n


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


def _msvc_version_hint(version: str, profiles: tuple[str, ...] | None) -> str:
    """ "MSVC 12.00.8168" (+ the rebrew profiles carrying that build)."""
    hint = f"MSVC {version}"
    if profiles:
        hint += f" — matches {', '.join(profiles)}"
    return hint


# ---------------------------------------------------------------------------
# Backend 2.5: PE metadata fingerprinting (Rich header, linker version, CRT)
# ---------------------------------------------------------------------------


def detect_with_pe_meta(path: Path) -> ToolchainInfo | None:
    """Per-version MSVC fingerprinting from PE metadata.

    LINK.EXE writes a **Rich header** into the DOS stub recording every tool
    (compiler front/back end, linker) with its build number; combined with
    the optional-header linker version this pins the exact compiler (e.g.
    linker 6.0 + C1 8168 -> MSVC 6.0 12.00.8168).  VC 2.0-4.2 linkers write
    no Rich header — their linker version alone names the version (2.50
    -> VC 2.0, 3.0 -> 4.0, 3.10 -> 4.1, 4.20 -> 4.2).  The msvcpX.dll CRT
    import is a secondary binder when the Rich header is stripped.

    The Rich header is proof of the MSVC linker (family=msvc, high); a bare
    2.x linker version is ambiguous with MinGW's GNU ld, so that case only
    fills version/suggested_profiles evidence and lets the heuristics pick
    the family.  Returns None for non-PE / unparseable binaries."""
    try:
        pe = lief.parse(str(path))
    except Exception:
        return None
    # PE-only: only PE binaries expose an optional_header (ELF/Mach-O do
    # not); duck-typing also keeps the backend testable with mocks.
    if pe is None or not hasattr(pe, "optional_header"):
        return None

    info = ToolchainInfo(detected_by="pe-meta")
    major = pe.optional_header.major_linker_version
    minor = pe.optional_header.minor_linker_version
    linker_ver = f"{major}.{minor}"
    rich_builds: list[int] = []
    rich = getattr(pe, "rich_header", None)
    if rich is not None:
        rich_builds = sorted({e.build_id for e in rich.entries})

    # CRT import binder: msvcp60.dll -> VC 6.0 etc.
    msvcp_version = ""
    try:
        for imp in pe.imports:
            name = str(getattr(imp, "name", "") or "").lower()
            if name in _MSVCP_IMPORT_VERSIONS:
                msvcp_version = _MSVCP_IMPORT_VERSIONS[name]
                break
    except Exception:
        pass
    if msvcp_version:
        info.add(f"msvcp import names MSVC {msvcp_version} CRT")

    linker_mm = _MSVC_LINKER_VERSIONS.get(linker_ver)
    if rich_builds:
        # Rich header present = the MSVC linker wrote it — family is proven.
        info.family = "msvc"
        info.confidence = "high"
        build = _rich_compiler_build(rich.entries)  # the C1/C2 pair (mode)
        profiles = _RICH_BUILD_PROFILES.get(build) or _LINKER_ERA_PROFILES.get(linker_mm or ())
        mm = linker_mm or (12, 0)  # unknown linker -> VC6-era fallback
        version = f"{mm[0]}.{mm[1]:02d}.{build}"
        info.msvc_version = version
        if profiles:
            info.suggested_profiles = list(profiles)
        info.add(f"Rich header: C1/C2 build {build}, linker {linker_ver}")
        info.version_hint = _msvc_version_hint(version, profiles)
        return info

    if linker_mm is None and not msvcp_version:
        return None  # not a classic MSVC linker and no CRT binder

    # No Rich header: VC 2.0-4.2 (or a stripped/other linker).  The linker
    # version names the era; a bare 2.x is ambiguous with MinGW's GNU ld,
    # so only evidence/version is filled — the heuristics decide the family.
    if linker_mm is not None:
        version = f"{linker_mm[0]}.{linker_mm[1]:02d}"
        info.msvc_version = version
        info.suggested_profiles = list(_LINKER_ERA_PROFILES.get(linker_mm, ()))
        if linker_mm == (9, 0):
            info.add(f"linker {linker_ver} (MSVC 2.0 or MinGW GNU ld)")
            if msvcp_version:
                info.family = "msvc"
                info.confidence = "medium"
        else:
            info.family = "msvc"
            info.confidence = "high" if linker_mm != (11, 0) else "medium"
            info.add(f"linker {linker_ver} -> MSVC {version}")
    else:
        # msvcp import only: the DLL name already names the version
        # (msvcp71.dll -> VC 7.1).
        version = msvcp_version
        info.msvc_version = version
        info.family = "msvc"
        info.confidence = "medium"
        info.add(f"msvcp {msvcp_version} CRT -> MSVC {version}")
    info.version_hint = _msvc_version_hint(
        info.msvc_version, tuple(info.suggested_profiles) or None
    )
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

    # --- Backend 2.5: PE metadata (Rich header / linker version / CRT) ---
    # Strongest per-version MSVC fingerprint: the Rich header proves the
    # MSVC linker and pins the exact compiler build (e.g. 12.00.8168).  Runs
    # before the codegen heuristics so a version-exact answer wins.
    pe_info = detect_with_pe_meta(path)
    if pe_info is not None:
        info.evidence.extend(pe_info.evidence)
        if info.family == "unknown":
            info.family = pe_info.family
            info.confidence = pe_info.confidence
            info.version_hint = pe_info.version_hint
            info.detected_by = "pe-meta"
        # Enrich with the exact version / suggested profiles even when
        # pe-meta left the family unknown (the bare 2.x linker case is
        # ambiguous with MinGW and only contributes evidence).
        if pe_info.msvc_version:
            info.msvc_version = pe_info.msvc_version
        if pe_info.suggested_profiles:
            info.suggested_profiles = pe_info.suggested_profiles
        if pe_info.family == "msvc":
            # The precise PE-meta hint ("MSVC 12.00.8168 — matches msvc6")
            # always beats a coarser DIE/PDB era hint ("MSVC 6.0").
            if pe_info.msvc_version:
                info.version_hint = pe_info.version_hint
            info.confidence = max(info.confidence, pe_info.confidence)

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

    # --- packer detection: LZEXE-compressed DOS executables ---
    # A packed MZ reveals nothing about the compiler (the visible code is
    # the decompressor stub); the detection must say so, or the family
    # gets misread from stub strings.  ``unpack-lzexe`` restores the image.
    try:
        from rebrew.lzexe import lzexe_version

        lz_ver = lzexe_version(path)
    except Exception:
        # Best-effort packer probe — a failure must not break detection,
        # but should be visible when debugging why packed: is absent.
        import logging

        logging.getLogger(__name__).debug("LZEXE probe failed for %s", path, exc_info=True)
        lz_ver = None
    if lz_ver is not None:
        info.packed = f"lzexe 0.{lz_ver}"
        info.add(f"packed with LZEXE 0.{lz_ver} — run `rebrew unpack-lzexe` before analysis")

    # PKLITE (PKWARE, 1990s): the stub carries its copyright banner near
    # the header; the visible strings are the packer's (or compressed
    # remnants), so a packed flag beats trusting the family detection.
    # No built-in unpacker — point the user at finding an unpacked copy.
    if info.packed == "":
        try:
            with open(path, "rb") as fh:
                head = fh.read(0x400)
        except OSError:
            head = b""
        if b"PKLITE" in head:
            info.packed = "pklite"
            info.add(
                "packed with PKLITE (PKWARE) — no built-in unpacker; find an "
                "unpacked copy before analysis"
            )

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

    # --- 16-bit DOS MZ targets: string evidence identifies the family ---
    # MZ executables have no PE-style sections, no import table, and 16-bit
    # codegen (the 32-bit byte patterns below never fire), so the string
    # hits are the only reliable signal.  Priority mirrors the NE branch:
    # Delphi RTL strings are the most specific, then Borland C (Turbo C is
    # the classic DOS-game compiler), then the remaining runtimes.  An MZ
    # executable is ALWAYS 16-bit x86 — the arch applies even when a
    # stronger backend (die/PDB) already named the family.
    if getattr(binfo, "format", "") == "mz":
        info.arch = "x86_16"
        if info.family == "unknown":
            if delphi_hits:
                info.family = "delphi"
                info.confidence = "medium"
                info.version_hint = "Delphi RTL strings present"
            elif borlandc_hits:
                info.family = "borlandc"
                info.confidence = "medium"
                info.version_hint = "Borland C/C++ runtime strings present"
            elif watcom_hits:
                info.family = "watcom"
                info.confidence = "medium"
                info.version_hint = "Watcom runtime strings present"
            elif zortech_hits:
                info.family = "zortech"
                info.confidence = "medium"
                info.version_hint = "Zortech C++ runtime strings present"
            elif symantec_hits:
                info.family = "symantec"
                info.confidence = "medium"
                info.version_hint = "Symantec C++ runtime strings present"
            elif msvc_hits:
                info.family = "msvc"
                info.confidence = "medium"
                info.version_hint = "MSVC CRT strings present"
            if info.family != "unknown":
                # Only claim the detection when the string evidence itself
                # named the family — a stronger backend (die/PDB) that ran
                # first keeps its detected_by.
                info.detected_by = "mz"
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
    # MSVC optimization fingerprint: /O2 passes arguments by loading them
    # first (`mov eax,[esp+4]; push eax` — 8b 44 24 04 50) and cleans the
    # stack with `add esp,N`; /O1 pushes the memory operand directly
    # (`push dword [esp+4]` — ff 74 24 04) and pops with `pop ecx`.  The two
    # styles are mutually exclusive per wrapper, so their relative counts
    # identify the optimization level — or flag a MIXED build (per-file /O
    # overrides, common in MS products) where the user must flag-sweep per
    # function instead of trusting one project-wide setting.
    o2_wrappers = 0
    o1_wrappers = 0
    const_hoists = 0
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
        # Load-first wrapper call signatures (1- and 2-arg).
        o2_wrappers += text_bytes.count(bytes.fromhex("8b 44 24 04 50 e8"))
        o2_wrappers += text_bytes.count(bytes.fromhex("8b 44 24 08 8b 4c 24 04"))
        # push-[mem] wrapper call signatures (1- and 2-arg).
        o1_wrappers += text_bytes.count(bytes.fromhex("ff 74 24 04 e8"))
        o1_wrappers += text_bytes.count(bytes.fromhex("ff 74 24 08 ff 74 24 04"))
        const_hoists = _count_const_hoists(text_bytes)
    except Exception:
        pass

    if gnu_nops:
        info.add(f"{gnu_nops} GNU-style 0f 1f nops")
    if msvc_nops:
        info.add(f"{msvc_nops} MSVC-style alignment nops")
    if int3_pads > 10:
        info.add(f"{int3_pads} int3 pad runs (MSVC-style padding)")

    # --- MSVC optimization-level fingerprint ---
    # Only asserted for the MSVC family (the byte patterns are MSVC-specific
    # argument-passing idioms, not GCC's stack layout).
    if info.family == "msvc" and (o2_wrappers or o1_wrappers):
        if o2_wrappers >= 3 and o2_wrappers >= o1_wrappers * 2:
            info.opt_level = "/O2"
            info.add(
                f"{o2_wrappers} load-first wrapper calls (`mov eax,[esp+4]; push eax`) → /O2-style"
            )
        elif o1_wrappers >= 3 and o1_wrappers >= o2_wrappers * 2:
            info.opt_level = "/O1"
            info.add(f"{o1_wrappers} push-[mem] wrapper calls (`push dword [esp+4]`) → /O1-style")
        elif o2_wrappers >= 3 and o1_wrappers >= 3:
            info.opt_level = "mixed (/O1 + /O2)"
            info.add(
                f"both wrapper styles present ({o1_wrappers} push-[mem], "
                f"{o2_wrappers} load-first) — per-file mixed optimization; "
                f"use per-function flag sweeps instead of one project-wide level"
            )

    # --- pre-6.0 constant-caching fingerprint ---
    # MSVC 4.x/5.0 hoist small loop-invariant constants into callee-saved
    # registers and store them via those registers; MSVC 6.0 folds them into
    # mov [mem],imm32 immediates.  Only asserted for the MSVC family.
    if info.family == "msvc" and const_hoists:
        info.add(
            f"{const_hoists} pre-6.0 constant-hoist sites "
            f"(mov ebx/ebp/esi/edi, small-imm32 -> store-via-reg)"
        )
        if const_hoists >= 5 and info.version_hint.startswith("MSVC 6.0"):
            info.version_hint = (
                f"{info.version_hint} (pre-6.0 constant-caching codegen; "
                "compiler may be MSVC 4.x/5.0)"
            )

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


#: 16-bit-capable profiles for byte-matching DOS/NE targets (used by
#: profile_matches_detection's arch alignment check).
_BITNESS_16_PROFILES = frozenset({"msvc1.52", "msvc15", "msvc10", "tc16", "tc20", "watcom16"})


#: Compiler profiles that can byte-match each detected family.
#: ``None`` means no supported rebrew compiler can match that family.
_PROFILE_COMPAT: dict[str, set[str] | None] = {
    # msvc1.52 is the 16-bit profile — the detection hint distinguishes
    # "16-bit MSVC-style NE" from 32-bit targets.
    "msvc": {
        "msvc400",
        "msvc420",
        "msvc410",
        "msvc200",
        "msvc5",
        "msvc500sp1",
        "msvc500sp2",
        "msvc500sp3",
        "msvc6",
        "msvc6.3",
        "msvc6.6",
        "msvc600sp3",
        "msvc600sp5",
        "msvc600sp6",
        "msvc7",
        "msvc700",
        "msvc700sp1",
        "msvc710",
        "msvc710sp1",
        "msvc800",
        "msvc800sp1",
        "msvc900",
        "msvc1000",
        "msvc1000sp1",
        "msvc1.52",
        "msvc15",
        "msvc10",
    },
    "mingw": {"gcc-pe"},
    "zig": {"gcc-pe"},  # may match structurally only (LLVM vs GCC codegen)
    "watcom": {"watcom", "watcom16"},  # wcc386 (32-bit) + wcc (16-bit DOS)
    "delphi": None,
    # Turbo C/C++ 3.1 (tc16, 16-bit DOS) and Borland C++ 5.5 (bcc32, 32-bit)
    # both emit Borland-flavored OMF/COFF that rebrew can byte-match.
    "borlandc": {"tc20", "tc16", "borlandc55"},
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
    # Version-exact check: when the PE metadata pinned the exact MSVC build
    # (Rich header / linker), a different-compiler profile cannot byte-match
    # — every MSVC version is a different codegen.  This catches e.g. an
    # msvc6 profile on a VC 8.0 binary (silent COMPILE_ERROR for every
    # function) before the first compile.
    if info.family == "msvc" and info.suggested_profiles and profile not in info.suggested_profiles:
        return (
            False,
            f"binary was built with MSVC {info.msvc_version} — profile '{profile}' is a "
            "different compiler build; switch to one of: "
            f"{', '.join(sorted(info.suggested_profiles))}",
        )
    # Arch dimension: a 16-bit DOS/NE binary can only be byte-matched by
    # 16-bit-capable profiles; conversely msvc1.52 cannot match a 32/64-bit
    # PE/ELF.  This catches the "msvc6 profile on a 16-bit project"
    # misconfiguration that silently produces COMPILE_ERROR for every
    # function (skifree16-rebrew regression).  The 16-bit-capable set is
    # explicit (msvc1.52 = NE/DOS, tc16/tc20/watcom16 = DOS); watcom's
    # wcc386 is a 32-bit compiler (Open Watcom 2.0 x86-32) and must NOT be
    # flagged as 16-bit.
    if info.arch == "x86_16" and profile not in _BITNESS_16_PROFILES:
        return (
            False,
            f"detected 16-bit binary but profile '{profile}' is a 32/64-bit "
            f"compiler — switch to one of: {', '.join(sorted(_BITNESS_16_PROFILES))} "
            "(e.g. msvc1.52 / tc16 / tc20) or document the functions as blockers",
        )
    if info.arch and info.arch != "x86_16" and profile in _BITNESS_16_PROFILES:
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


def _is_16bit_target(info: ToolchainInfo, binary: Path | None) -> bool:
    """True when the detected binary is 16-bit (NE x86_16 or a plain DOS MZ
    executable — the latter has no arch field in the detector)."""
    if info.arch == "x86_16":
        return True
    if binary is None:
        return False
    if isinstance(binary, str):
        binary = Path(binary)
    try:
        data = binary.read_bytes()
    except OSError:
        return False
    if len(data) < 2 or data[:2] != b"MZ":
        return False
    # A PE carries the "PE\0\0" signature at e_lfanew — it is NOT
    # 16-bit.  Only NE (16-bit Windows) and plain DOS MZ executables are.
    if len(data) >= 0x40:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if e_lfanew + 4 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            return False
    return True


def suggest_profile(info: ToolchainInfo, binary: Path | None = None) -> str | None:
    """Pick the best rebrew compiler profile for a detected toolchain family.

    The single source of truth for family→profile selection, used by
    ``rebrew init --guess-compiler``, ``rebrew intake``, and doctor.  Uses
    ``_PROFILE_COMPAT`` (the byte-match compatibility table) and prefers the
    16-bit profile when the binary is 16-bit (NE x86_16 or a plain DOS MZ
    executable).  Returns ``None`` when no rebrew profile can match.
    """
    compatible = _PROFILE_COMPAT.get(info.family)
    if not compatible:
        return None
    # Version-exact: the PE metadata pinned the compiler build — prefer a
    # profile carrying that build over the generic family default.
    if info.suggested_profiles:
        for p in info.suggested_profiles:
            if p in compatible and not _is_16bit_target(info, binary):
                return p
    if _is_16bit_target(info, binary):
        for p in ("msvc1.52", "tc16", "watcom16"):
            if p in compatible:
                return p
    for p in ("msvc6", "borlandc55", "watcom", "gcc-pe", "clang", "gcc"):
        if p in compatible:
            return p
    return sorted(compatible)[0]
