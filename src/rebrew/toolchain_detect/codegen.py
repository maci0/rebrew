"""Byte/string/codegen scanning, PDB, and PE-metadata detection helpers."""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any, cast
lazy import bisect
lazy from collections.abc import Iterator

from rebrew.formats.binary_loader import REAL_MODE_ADDRESS_MASK
from rebrew.utils import run_process_group

from .tables import (
    MSVC_LINKER_VERSIONS,
    MSVC_VERSION_HINTS,
    MSVCP_IMPORT_VERSIONS,
    CodegenSignals,
    ToolchainInfo,
    detection_tables,
    resolve_pkg_hook,
)

logger = logging.getLogger(__name__)

#: Printable-ASCII runs used by ``scan_strings`` (module-level so the
#: pattern compiles once, not per call site).
_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")


def rich_compiler_build(entries: list[Any]) -> int:
    """The compiler build from Rich-header entries: the most common build.

    The C1/C2 (front/back end) pair shares one build; the linker entry can
    carry a different (newer) one.  The mode picks the pair over a single
    differing linker entry."""
    from collections import Counter

    counts = Counter(e.build_id for e in entries)
    return int(counts.most_common(1)[0][0])


def scan_strings(data: bytes, limit: int = 256) -> list[str]:
    """Return printable ASCII strings from the bytes (best effort, capped)."""
    out: list[str] = []
    for m in _ASCII_RUN_RE.finditer(data):
        out.append(m.group().decode("ascii", errors="replace"))
        if len(out) >= limit:
            break
    return out


def gcc_era_hint(count_modern: int, count_old: int) -> str:
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


# --- byte-level codegen fingerprint patterns (verified — see docs/codegen/README.md) ---

#: VC 7.0+ loop-alignment nop `lea esp,[esp]` — verified inside optimized
#: function bodies for VC 7.0..11.0; VC 2.0-6.0 never emit it (their nop
#: ladder is 90 / 8d 74 26 00 / 8d a4 24, inter-function only).
LEA_ESP_NOP = bytes.fromhex("8d 64 24 00")

#: MSVC string-op inlining: memset/memcpy-shaped loops become rep stosd
#: (f3 ab), rep movsd (f3 a5), rep stosb (f3 aa) — every MSVC 2.0..11.0
#: version verified; GCC 16 and Borland bcc32 do NOT rep-stos the same
#: source (GCC calls memset), so presence is MSVC-family evidence.
REP_STRING_OPS = (
    bytes.fromhex("f3 ab"),  # rep stosd
    bytes.fromhex("f3 a5"),  # rep movsd
    bytes.fromhex("f3 aa"),  # rep stosb
    bytes.fromhex("f3 a4"),  # rep movsb
)

#: `rep ret` (f3 c3) — GCC's return-after-branch idiom.  Verified present
#: in real MinGW binaries (cpubench, test_sse2), absent in MSVC binaries.
REP_RET = bytes.fromhex("f3 c3")

#: Magic immediates for unsigned/signed division by small constants — the
#: MSVC 5.0+ / GCC divide-by-constant sequence (mov reg, magic; mul/imul).
#: MSVC 2.0/4.x, Borland and Watcom emit real div instead (see the doc).
DIV_MAGICS = tuple(
    bytes.fromhex(h)
    for h in (
        "aa aa aa ab",  # x/3u
        "24 92 49 25",  # x/7u
        "cd cc cc cc",  # x/10u
        "1f 85 eb 51",  # x/100u
        "93 24 49 92",  # x/7 (signed)
        "67 66 66 66",  # x/10 (signed)
    )
)

#: SSE2 FP ops (addsd f2 0f 58, subsd 5c, mulsd 59, divsd 5e) — VC 11.0
#: (VS2012) defaults x86 to SSE2; VC 2.0-10.0 emit pure x87.
SSE2_FP_OPS = tuple(bytes.fromhex(f"f2 0f {h}") for h in ("58", "59", "5c", "5e"))

#: x87 FP loads from the stack: fld qword/dword [esp+N] (dd/d9 44 24 /
#: dd/d9 54 24).  Presence = x87 FPU codegen (pre-SSE2 default).
X87_ESP_LOADS = tuple(bytes.fromhex(h) for h in ("dd 44 24", "d9 44 24", "dd 54 24", "d9 54 24"))

#: Frame-pointer prologue push ebp; mov ebp,esp — /Oy- or unoptimized
#: MSVC/Borland builds; absent at MSVC /O1//O2 and in Watcom.
FP_PROLOGUE = bytes.fromhex("55 8b ec")

#: 2-byte `mov edi,edi` nop — MSVC-style padding in linked VC6+ binaries
#: (VC5 corpus binaries show 0; VC6+ show ~10 per 15KB of .text).
MOV_EDI_EDI = bytes.fromhex("8b ff")

#: x87 compare idioms, each PREFIXED by `fnstsw ax` (df e0) so an unrelated
#: `test ah,N` never counts: the Processor Pack code generator (c2 13.00.9044)
#: rewrites every plain VC6 float compare to `test ah,0x44; jp` / `test ah,5`,
#: while the plain generators use `test ah,0x40` / `test ah,0x01`.  Verified
#: against nine registered VC6 code generators x nine flag sets; see
#: docs/general-knowledge.md in guild-rebrew and docs/codegen/ in this repo.
PP_COMPARES = tuple(bytes.fromhex(h) for h in ("df e0 f6 c4 44", "df e0 f6 c4 05"))
PLAIN_COMPARES = tuple(bytes.fromhex(h) for h in ("df e0 f6 c4 40", "df e0 f6 c4 01"))

#: Stack-probe / security-cookie symbol names -> (family, evidence).
#: These survive in COFF symbol tables, .drectve records and unstripped
#: binaries — the byte shapes alone cannot tell __chkstk from
#: ___chkstk_ms (both are `mov eax,size; call`).
PROBE_SYMBOLS: dict[str, tuple[str, str]] = {
    "__chkstk": ("msvc", "MSVC 32-bit stack probe __chkstk"),
    "___chkstk_ms": ("mingw", "MinGW stack probe ___chkstk_ms"),
    "__aNchkstk": ("msvc", "16-bit MSVC stack probe __aNchkstk"),
    "__CHK": ("watcom", "Watcom stack probe __CHK"),
    "__security_check_cookie": ("msvc", "MSVC /GS security-cookie check (VC 8.0+ default)"),
    "__security_cookie": ("msvc", "MSVC /GS security cookie (VC 8.0+ default)"),
}


def count_const_hoists(text: bytes) -> int:
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
    get_reg = reg_field.get
    # Precompute 89 store sites once; each hoist candidate then bisects its
    # 32-byte window instead of rescanning it (was O(n * window)).
    store_sites: list[tuple[int, int]] = []
    for j in range(len(text) - 1):
        if text[j] == 0x89:
            rm = text[j + 1]
            if (rm >> 6) != 3:
                store_sites.append((j, (rm >> 3) & 7))
    if not store_sites:
        return 0
    site_pos = [p for p, _ in store_sites]
    bisect_left = bisect.bisect_left
    for i in range(len(text) - 5):
        reg = get_reg(text[i])
        if reg is None or text[i + 3] != 0 or text[i + 4] != 0:
            continue
        lo = bisect_left(site_pos, i + 5)
        hi = bisect_left(site_pos, i + 5 + 32)
        for k in range(lo, hi):
            if store_sites[k][1] == reg:
                n += 1
                break
    return n


def mz_codegen_scan(data: bytes) -> dict[str, int]:
    """Disassemble a DOS MZ executable's entry code (16-bit, capstone).

    Returns counts of distinctive 16-bit codegen instructions: ``leave``
    epilogues (MSVC 1.5x — Borland TC emits ``pop bp; ret``), ``loop``
    instructions, far returns (``retf``) and ``push bp`` frame prologues.
    Best-effort: an unreadable entry point yields an empty dict.

    Entry file offset = e_cparhdr * 16 + (e_cs * 16 + e_ip, wrapped at 1 MiB): CS:IP is relative
    to the load module, which starts after the ``e_cparhdr`` header paragraphs.
    """
    if len(data) < 0x18 or data[:2] != b"MZ":
        return {}
    e_cparhdr = int.from_bytes(data[0x08:0x0A], "little")
    e_ip = int.from_bytes(data[0x14:0x16], "little")
    e_cs = int.from_bytes(data[0x16:0x18], "little")
    entry = e_cparhdr * 16 + ((e_cs * 16 + e_ip) & REAL_MODE_ADDRESS_MASK)
    if not 0 <= entry < len(data):
        return {}
    try:
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.skipdata = True
    except Exception:
        logger.debug("capstone 16-bit disassembler unavailable", exc_info=True)
        return {}
    counts = {"leave": 0, "loop": 0, "retf": 0, "fp_prologue": 0}
    prev_m: str | None = None
    prev_op: str = ""
    for insn in md.disasm(data[entry : entry + 4096], entry):
        m = insn.mnemonic
        if m == "leave":
            counts["leave"] += 1
        elif m in ("loop", "loope", "loopne", "jcxz", "jecxz"):
            counts["loop"] += 1
        elif m == "retf":
            counts["retf"] += 1
        if prev_m == "push" and prev_op == "bp":
            counts["fp_prologue"] += 1
        prev_m = m
        prev_op = insn.op_str
    return counts


# MSVC /O2 loads a wrapper argument, then pushes the register.
# MSVC /O1 pushes the stack slot directly. advance-by-length matches bytes.count.
# codegen_corpus.json publishes these patterns, OPT_MIN_SITES and the 2x
# dominance ratio as ``opt_level``; TestCodegenCorpusOptLevel keeps them equal.
O2_WRAPPERS: tuple[bytes, ...] = (
    bytes.fromhex("8b 44 24 04 50 e8"),
    bytes.fromhex("8b 44 24 08 8b 4c 24 04"),
)
O1_WRAPPERS: tuple[bytes, ...] = (
    bytes.fromhex("ff 74 24 04 e8"),
    bytes.fromhex("ff 74 24 08 ff 74 24 04"),
)
OPT_MIN_SITES = 3


def iter_masked(
    text: bytes, pattern: bytes, base_va: int, exclude: list[tuple[int, int]]
) -> Iterator[int]:
    """Yield each non-overlapping *pattern* hit in *text* whose VA is outside *exclude*.

    ``base_va`` is the VA of ``text[0]``; *exclude* holds ``(lo, hi)`` VA ranges
    a linked library occupies (``external_ranges``).  The cursor advances by the
    pattern length (one byte for an empty pattern) so the yield count matches
    the ``bytes.count`` fast path when nothing is excluded.
    """
    start = 0
    step = max(1, len(pattern))
    while start <= len(text):
        index = text.find(pattern, start)
        if index < 0:
            return
        va = base_va + index
        if not any(lo <= va <= hi for lo, hi in exclude):
            yield va
        start = index + step


def pattern_vas(
    text: bytes, base_va: int, patterns: tuple[bytes, ...], exclude: list[tuple[int, int]]
) -> list[int]:
    """VAs of non-overlapping *patterns* in *text* that fall outside *exclude*."""
    return [va for pattern in patterns for va in iter_masked(text, pattern, base_va, exclude)]


def opt_level_from_counts(o2: int, o1: int) -> str:
    """``/O2``, ``/O1``, ``mixed (/O1 + /O2)``, or empty when the counts are thin.

    One style has to show up at least three times and at least twice as often
    as the other. Both styles clearing that bar is a per-file mix.
    """
    if o2 >= OPT_MIN_SITES and o2 >= o1 * 2:
        return "/O2"
    if o1 >= OPT_MIN_SITES and o1 >= o2 * 2:
        return "/O1"
    if o2 >= OPT_MIN_SITES and o1 >= OPT_MIN_SITES:
        return "mixed (/O1 + /O2)"
    return ""


def opt_level_without_library(o2: int, o1: int, lib_o2: int, lib_o1: int) -> str | None:
    """Program opt level after static-library wrapper sites are removed.

    ``None`` means the library split did not explain the mix (no library
    sites, or the counts are impossible). An empty string means every
    counted site belongs to the library, so the program itself has no
    wrapper evidence.
    A single style left in the program is that style even below three
    sites: the other style was the library's, not a second compile of the
    program.
    """
    if lib_o2 < 0 or lib_o1 < 0 or lib_o2 > o2 or lib_o1 > o1:
        return None
    if lib_o2 == 0 and lib_o1 == 0:
        return None
    game_o2 = o2 - lib_o2
    game_o1 = o1 - lib_o1
    if game_o2 == 0 and game_o1 == 0:
        return ""
    if game_o1 == 0:
        return "/O2"
    if game_o2 == 0:
        return "/O1"
    return opt_level_from_counts(game_o2, game_o1) or "mixed (/O1 + /O2)"


def count_masked(
    text: bytes, patterns: tuple[bytes, ...], base_va: int, exclude: list[tuple[int, int]]
) -> int:
    """Count *patterns* in *text* at VAs outside every excluded band.

    *base_va* is the VA of ``text[0]``; *exclude* holds ``(lo, hi)`` VA ranges
    the project fills from a linked library (``external_ranges``).  Library
    objects were compiled with Microsoft's own settings, so they must not
    decide the GAME code's code-generator family.
    """
    if not exclude:
        return sum(text.count(p) for p in patterns)
    return sum(1 for pattern in patterns for _ in iter_masked(text, pattern, base_va, exclude))


def count_codegen_signals(
    text: bytes, base_va: int = 0, exclude: list[tuple[int, int]] | None = None
) -> CodegenSignals:
    """Count every byte-level codegen fingerprint in *text* (pure)."""
    s = CodegenSignals()
    s.lea_esp_nops = text.count(LEA_ESP_NOP)
    s.rep_stosd = text.count(REP_STRING_OPS[0])
    s.rep_movsd = text.count(REP_STRING_OPS[1])
    s.rep_stosb = text.count(REP_STRING_OPS[2])
    s.rep_movsb = text.count(REP_STRING_OPS[3])
    s.rep_ret = text.count(REP_RET)
    s.magic_divs = sum(text.count(m) for m in DIV_MAGICS)
    s.sse2_fp = sum(text.count(p) for p in SSE2_FP_OPS)
    s.x87_fp = sum(text.count(p) for p in X87_ESP_LOADS)
    s.fp_prologues = text.count(FP_PROLOGUE)
    s.mov_edi_edi = text.count(MOV_EDI_EDI)
    s.pp_compares = count_masked(text, PP_COMPARES, base_va, exclude or [])
    s.plain_compares = count_masked(text, PLAIN_COMPARES, base_va, exclude or [])
    return s


def x87_codegen_family(signals: CodegenSignals) -> str:
    """``"processor-pack"`` | ``"plain"`` | ``"mixed"`` | ``"unknown"``.

    The VC6 Processor Pack replaced the code generator (c2.dll 13.00.9044) and
    that replacement is visible in the x87 compare idiom: the pack emits
    ``fnstsw ax; test ah,0x44; jp`` / ``test ah,5``, while every plain VC6
    generator emits ``test ah,0x40`` / ``test ah,0x01`` — verified across nine
    registered VC6 code generators and nine flag sets, and independent of
    ``/Od``..``/Ox``.  Both counts are taken AFTER ``fnstsw ax``: a bare
    ``f6 c4 40`` is usually the integer ``test eax,0x4000`` strength reduction,
    which every generator emits.

    A binary that contains both idioms is ``mixed`` (a project that switched
    generators mid-build, or hand-written asm); one that contains neither is
    ``unknown`` — the profile cannot be narrowed from this signal alone.
    """
    pp = signals.pp_compares
    plain = signals.plain_compares
    if pp and plain:
        return "mixed"
    if pp:
        return "processor-pack"
    if plain:
        return "plain"
    return "unknown"


# ---------------------------------------------------------------------------
# Backend 2: PDB analysis (llvm-pdbutil)
# ---------------------------------------------------------------------------


def detect_with_pdb(path: Path) -> ToolchainInfo | None:
    """Detect via a sibling .pdb (compiler version + flags, Zig marker).

    Delegates ``llvm-pdbutil`` execution and ``S_COMPILE3`` / module parsing to
    :func:`rebrew.formats.pdb.extract_pdb_info`.  Returns None when there is no
    PDB or no usable tooling.
    """
    from rebrew.formats.pdb import extract_pdb_info

    runner = resolve_pkg_hook(run_process_group, _ORIG_RUN_PROCESS_GROUP, "run_process_group")
    pdb_info = extract_pdb_info(path, runner=runner)
    if pdb_info is None or pdb_info.error:
        return None

    info = ToolchainInfo(detected_by="pdb")
    frontend = pdb_info.frontend
    backend = pdb_info.backend
    flags_str = " ".join(pdb_info.flags)
    if (
        pdb_info.toolchain == "zig"
        or ".zig-cache" in flags_str
        or "zig" in (frontend + backend).lower()
    ):
        info.family = "zig"
        info.confidence = "high"
        info.version_hint = f"Zig/LLVM {frontend or backend}".strip()
        info.add("PDB module path names .zig-cache (Zig build)")
        return info
    if not frontend and not pdb_info.flags:
        return None
    info.add("PDB S_COMPILE3 record present")
    if frontend:
        info.family = "msvc"
        info.confidence = "medium"
        info.version_hint = f"MSVC frontend {frontend}"
        info.add(f"PDB compiler frontend {frontend}, backend {backend}")
    if pdb_info.flags:
        info.flags = list(pdb_info.flags)
        info.add(f"PDB compiler flags: {flags_str}")
    if info.family == "unknown":
        return None
    return info


def msvc_version_hint(version: str, profiles: tuple[str, ...] | None) -> str:
    """Return "MSVC 5.0 (cl 11.00.7022)" (+ the rebrew profiles carrying that
    build).  The version is CL's own version string, whose scheme is NOT the
    product-era number (cl 11.00 = VC 5.0, cl 17.00 = VC 11.0) — prefix the
    era name so "MSVC 11.00.0" never reads as VS2012 when it means VC 5.0."""
    era = next((h for p, h in MSVC_VERSION_HINTS.items() if version.startswith(p)), "")
    hint = f"{era} (cl {version})" if era else f"MSVC {version}"
    if profiles:
        hint += f": matches {', '.join(profiles)}"
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
    pkg = sys.modules.get(__package__ or "")
    if pkg is not None:
        lief_mod: Any = cast("Any", pkg).lief
    else:
        import lief as lief_mod
    try:
        pe = lief_mod.parse(str(path))
    except Exception:
        logger.debug("LIEF parse failed for %s", path, exc_info=True)
        return None
    # PE-only: only PE binaries expose an optional_header (ELF/Mach-O do
    # not); duck-typing also keeps the backend testable with mocks.
    if pe is None or not hasattr(pe, "optional_header"):
        return None

    info = ToolchainInfo(detected_by="pe-meta")
    # Only PE binaries reach here (guarded by the hasattr above); cast so
    # mypy knows pe exposes the PE-only attributes (imports, optional_header)
    # while preserving the duck-typing that keeps mock-based tests working.
    # Any (not lief.PE.Binary): `lief` is lazily imported and mock-patched,
    # so no statically resolvable name exists here.
    pe = cast("Any", pe)
    major = pe.optional_header.major_linker_version
    minor = pe.optional_header.minor_linker_version
    linker_ver = f"{major}.{minor}"
    rich_builds: list[int] = []
    rich_entries: list[Any] = []
    rich = getattr(pe, "rich_header", None)
    if rich is not None:
        rich_entries = list(rich.entries)
        rich_builds = sorted({e.build_id for e in rich_entries})

    # CRT import binder: msvcp60.dll -> VC 6.0 etc.
    msvcp_version = ""
    try:
        for imp in pe.imports:
            name = str(getattr(imp, "name", "") or "").lower()
            if name in MSVCP_IMPORT_VERSIONS:
                msvcp_version = MSVCP_IMPORT_VERSIONS[name]
                break
    except Exception:
        logger.debug("msvcp import scan failed for %s", path, exc_info=True)
    if msvcp_version:
        info.add(f"msvcp import names MSVC {msvcp_version} CRT")

    hint_fn = resolve_pkg_hook(
        msvc_version_hint, _ORIG_MSVC_VERSION_HINT, "_msvc_version_hint", "msvc_version_hint"
    )
    linker_mm = MSVC_LINKER_VERSIONS.get(linker_ver)
    if rich_builds:
        # Rich header present = the MSVC linker wrote it — family is proven.
        info.family = "msvc"
        info.confidence = "high"
        build = rich_compiler_build(rich_entries)  # the C1/C2 pair (mode)
        # One snapshot: the build table and the era table are one component.
        tables = detection_tables()
        profiles = tables.rich_build_profiles.get(build) or tables.linker_era_profiles.get(
            linker_mm or (12, 0)
        )
        mm = linker_mm or (12, 0)  # unknown linker -> VC6-era fallback
        version = f"{mm[0]}.{mm[1]:02d}.{build}"
        info.msvc_version = version
        if profiles:
            info.suggested_profiles = list(profiles)
        info.add(f"Rich header: C1/C2 build {build}, linker {linker_ver}")
        info.version_hint = hint_fn(version, profiles)
        return info

    if linker_mm is None and not msvcp_version:
        return None  # not a classic MSVC linker and no CRT binder

    # No Rich header: VC 2.0-4.2 (or a stripped/other linker).  The linker
    # version names the era; a bare 2.x is ambiguous with MinGW's GNU ld,
    # so only evidence/version is filled — the heuristics decide the family.
    if linker_mm is not None:
        version = f"{linker_mm[0]}.{linker_mm[1]:02d}"
        info.msvc_version = version
        info.suggested_profiles = list(detection_tables().linker_era_profiles.get(linker_mm, ()))
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
    info.version_hint = hint_fn(info.msvc_version, tuple(info.suggested_profiles) or None)
    return info


def is_16bit_target(info: ToolchainInfo, binary: Path | None) -> bool:
    """True when the detected binary is 16-bit (NE x86_16 or a plain DOS MZ
    executable — the latter has no arch field in the detector)."""
    if info.arch == "x86_16":
        return True
    if binary is None:
        return False
    if isinstance(binary, str):
        binary = Path(binary)
    try:
        with binary.open("rb") as handle:
            head = handle.read(0x40)
            if len(head) < 2 or head[:2] != b"MZ":
                return False
            if len(head) < 0x40:
                # Too short for e_lfanew: a truncated DOS image, not a PE.
                return True
            e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
            handle.seek(e_lfanew)
            signature = handle.read(4)
    except OSError as exc:
        # Reporting an unreadable binary as "not 16-bit" recommends a 32-bit
        # profile for a 16-bit target and init --guess-compiler writes it.
        logger.warning("cannot read %s, 16-bit detection skipped: %s", binary, exc)
        return False
    # A PE carries the "PE\0\0" signature at e_lfanew — it is NOT
    # 16-bit.  Only NE (16-bit Windows) and plain DOS MZ executables are.
    return signature != b"PE\x00\x00"


_ORIG_RUN_PROCESS_GROUP = run_process_group
_ORIG_MSVC_VERSION_HINT = msvc_version_hint
