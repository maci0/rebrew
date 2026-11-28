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
  Byte-matching: ``borland-3.1`` (Turbo C++ 3.1, 16-bit DOS) and ``borland-5.5``
  (bcc32, 32-bit) both produce Borland-flavored objects rebrew can match.
- ``watcom`` — Watcom C/C++ (watcom-win32 9.x–11.0, Open Watcom).  Evidence:
  underscore-prefixed ``_TEXT``/``_DATA``/``_BSS`` sections and Watcom runtime
  strings.  Byte-matching: ``watcom-2.0-win32`` (wcc386) and ``watcom-2.0-win16`` (wcc, 16-bit
  DOS) profiles exist; ``rebrew doctor`` no longer flags these as blockers.

Usage::

    info = detect_toolchain(binary_path)
    print(info.family, info.version_hint, info.evidence)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from rebrew.formats.binary_loader import REAL_MODE_ADDRESS_MASK, load_binary
from rebrew.toolchain_detect.codegen import (
    O1_WRAPPERS,
    O2_WRAPPERS,
    OPT_MIN_SITES,
    PROBE_SYMBOLS,
    count_codegen_signals,
    count_const_hoists,
    count_masked,
    detect_with_pdb,
    detect_with_pe_meta,
    gcc_era_hint,
    is_16bit_target,
    iter_masked,
    msvc_version_hint,
    mz_codegen_scan,
    opt_level_from_counts,
    opt_level_without_library,
    pattern_vas,
    rich_compiler_build,
    scan_strings,
    x87_codegen_family,
)
from rebrew.toolchain_detect.diec import (
    DIE_UNAVAILABLE,
    VENDORED_DIEC,
    detect_with_die,
    diec_env,
    diec_version_hint,
    find_diec,
    linker_era_hint,
    run_diec,
)
from rebrew.toolchain_detect.tables import (
    BACKEND_DISPLAY,
    BINARY_DETECTOR_ENTRY_POINT_GROUP,
    BORLAND_SECTIONS,
    BORLANDC_IMPORTS,
    BORLANDC_MARKERS,
    CONFIDENCE_RANK,
    DELPHI_MARKERS,
    DETECTION_TABLES,
    ICC_MARKERS,
    LINKER_ERA_PROFILES,
    LINKER_ERA_PROFILES_ALL,
    MSVC_LINKER_VERSIONS,
    MSVC_MARKERS,
    MSVC_VERSION_ENTRY_POINT_GROUP,
    MSVC_VERSION_HINTS,
    MSVCP_IMPORT_VERSIONS,
    PLUGIN_DETECTORS,
    PROFILE_COMPAT,
    PROFILE_COMPAT_ALL,
    RICH_BUILD_PROFILES,
    RICH_BUILD_PROFILES_ALL,
    SYMANTEC_MARKERS,
    TOOLCHAIN_DETECTOR_ENTRY_POINT_GROUP,
    WATCOM_MARKERS,
    ZORTECH_MARKERS,
    CodegenSignals,
    DetectionTables,
    ToolchainInfo,
    backend_display_name,
    bitness16_profiles,
    detection_tables,
    discover_binary_detectors,
    merged_msvc_version_tables,
    merged_profile_compat,
    processor_pack_profiles,
    refresh_detection_tables,
)
from rebrew.utils import SOURCE_CHECKOUT, fold_ident, run_process_group

logger = logging.getLogger(__name__)

# Read by this module, or by name through ``resolve_pkg_hook`` and the
# detection-table refresh in ``tables`` (``_DETECTION_TABLES``, ``_PLUGIN_DETECTORS``).
_DELPHI_MARKERS = DELPHI_MARKERS
_MSVC_MARKERS = MSVC_MARKERS
_BORLAND_SECTIONS = BORLAND_SECTIONS
_WATCOM_MARKERS = WATCOM_MARKERS
_BORLANDC_MARKERS = BORLANDC_MARKERS
_SYMANTEC_MARKERS = SYMANTEC_MARKERS
_ZORTECH_MARKERS = ZORTECH_MARKERS
_ICC_MARKERS = ICC_MARKERS
_BORLANDC_IMPORTS = BORLANDC_IMPORTS
_PLUGIN_DETECTORS = PLUGIN_DETECTORS
_DETECTION_TABLES = DETECTION_TABLES
_CONFIDENCE_RANK = CONFIDENCE_RANK
_find_diec = find_diec
_diec_env = diec_env
_run_diec = run_diec
_linker_era_hint = linker_era_hint
_diec_version_hint = diec_version_hint
_scan_strings = scan_strings
_gcc_era_hint = gcc_era_hint
_count_const_hoists = count_const_hoists
_mz_codegen_scan = mz_codegen_scan
_O2_WRAPPERS = O2_WRAPPERS
_O1_WRAPPERS = O1_WRAPPERS
_PROBE_SYMBOLS = PROBE_SYMBOLS
_pattern_vas = pattern_vas
_count_codegen_signals = count_codegen_signals
_msvc_version_hint = msvc_version_hint
_is_16bit_target = is_16bit_target


def __getattr__(name: str) -> Any:
    """Lazily import LIEF on first external attribute use (148ms native load).

    This is what makes ``monkeypatch.setattr("rebrew.toolchain_detect.lief…")``
    work in the version-table tests: the setattr target resolves through here
    instead of failing as a missing submodule import.
    """
    if name == "lief":
        return _lief()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _lief() -> Any:
    """The LIEF module, imported on first detection (148ms native load).

    Module-global (not function-local) so ``rebrew.toolchain_detect.lief``
    stays patchable — the version-table tests mock ``lief.parse`` here.
    Eager ``import lief`` is pointless: this module loads at CLI startup
    regardless, but detection itself runs only on demand.
    """
    import lief as _lief

    globals()["lief"] = _lief
    return _lief


def _detect_toolchain_core(
    path: Path | str, exclude_ranges: list[tuple[int, int]] | None = None
) -> ToolchainInfo:
    """The packaged detection pipeline (DIE/PDB/PE-meta/heuristics).

    Public entry is :func:`detect_toolchain`, which runs the plugin binary
    detectors on top of this when the packaged backends leave the family
    unknown."""
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
            # The precise PE-meta hint ("MSVC 6.0 (cl 12.00.8168): matches msvc-6.0")
            # always beats a coarser DIE/PDB era hint ("MSVC 6.0").
            if pe_info.msvc_version:
                info.version_hint = pe_info.version_hint
            if _CONFIDENCE_RANK.get(pe_info.confidence, 0) > _CONFIDENCE_RANK.get(
                info.confidence, 0
            ):
                info.confidence = pe_info.confidence

    # --- Backend 3: structural heuristics (always available) ---
    # Read the file once: the capped string list and the full-file marker
    # scan below both need the same bytes, and reading it twice copied a
    # large binary twice.
    try:
        raw = path.read_bytes()
    except OSError as exc:
        logger.warning("cannot read %s for string evidence: %s", path, exc)
        raw = b""
    # String signals run FIRST — they decide the family for formats
    # load_binary cannot parse (e.g. 16-bit NE Delphi), where the
    # section/import/codegen signals below are unavailable.
    strings = _scan_strings(raw)
    delphi_hits = [s for s in strings if s in _DELPHI_MARKERS]
    if not delphi_hits:
        # The capped string list can miss markers beyond the first 256
        # strings (16-bit NE files carry long header/name tables first).
        # The full bytes caught above find them regardless of position.
        if b"Borland Delphi" in raw:
            delphi_hits = ["Borland Delphi"]
        else:
            delphi_hits = [m for m in _DELPHI_MARKERS if m.encode() in raw][:3]
    # One joined haystack for every marker family: each marker was
    # any-marker-in-each-string, i.e. markers x strings substring scans.
    joined_strings = "\x00".join(strings)
    has_ms_chkstk_ms = "___chkstk_ms" in joined_strings
    msvc_hits = [m for m in _MSVC_MARKERS if m in joined_strings]
    watcom_hits = [m for m in _WATCOM_MARKERS if m in joined_strings]
    borlandc_hits = [m for m in _BORLANDC_MARKERS if m in joined_strings]
    symantec_hits = [m for m in _SYMANTEC_MARKERS if m in joined_strings]
    zortech_hits = [m for m in _ZORTECH_MARKERS if m in joined_strings]
    icc_hits = [m for m in _ICC_MARKERS if m in joined_strings]
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

    # --- stack-probe / security-cookie symbol names ---
    # These survive in COFF symbol tables, .drectve records and unstripped
    # binaries (PE executables strip them).  Each name pins a family:
    # __chkstk (MSVC 32-bit), ___chkstk_ms (MinGW), __aNchkstk (16-bit
    # MSVC), __CHK (Watcom), __security_check_cookie (VC 8.0+ /GS).
    probe_hits: list[str] = []
    for sym in _PROBE_SYMBOLS:
        if sym in joined_strings:
            # "___chkstk_ms" also contains "__chkstk" — prefer the longer,
            # more specific name when both match.
            if sym == "__chkstk" and has_ms_chkstk_ms:
                continue
            probe_hits.append(sym)
    for sym in probe_hits:
        info.add(f"{_PROBE_SYMBOLS[sym][1]}")

    # --- packer detection: LZEXE-compressed DOS executables ---
    # A packed MZ reveals nothing about the compiler (the visible code is
    # the decompressor stub); the detection must say so, or the family
    # gets misread from stub strings.  ``unpack-lzexe`` restores the image.
    lz_scanned = True
    try:
        from rebrew.formats.lzexe import lzexe_version

        lz_ver = lzexe_version(path)
    except Exception:
        # Best-effort packer probe — a failure must not break detection,
        # but should be visible when debugging why packed: is absent.
        logger.debug("LZEXE probe failed for %s", path, exc_info=True)
        lz_ver = None
        lz_scanned = False
    if lz_ver is not None:
        info.packed, info.packer = True, f"lzexe 0.{lz_ver}"
        info.add(
            f"packed with LZEXE 0.{lz_ver} (unpack it with `rebrew binary unpack-lzexe`"
            " before analysis)"
        )

    # PKLITE (PKWARE, 1990s): the stub carries its copyright banner near
    # the header; the visible strings are the packer's (or compressed
    # remnants), so a packed flag beats trusting the family detection.
    # No built-in unpacker — point the user at finding an unpacked copy.
    # Packed stays None (not determined) when a probe could not read the file.
    if not info.packed:
        head: bytes | None
        try:
            with open(path, "rb") as fh:
                head = fh.read(0x400)
        except OSError:
            head = None
        if head is not None and b"PKLITE" in head:
            info.packed, info.packer = True, "pklite"
            info.add(
                "packed with PKLITE (PKWARE): rebrew has no unpacker for it, so "
                "analysis needs an unpacked copy"
            )
        elif head is not None and lz_scanned:
            info.packed = False

    try:
        binfo = load_binary(path)
    except Exception as exc:
        # Unparseable format (16-bit NE, unknown) — string evidence still
        # identifies the family; only section/import/codegen signals are lost.
        # The result is printed like a complete analysis, so the missing
        # signals have to be on the record.
        logger.warning(
            "binary parse failed for %s (%s); detection uses string evidence only", path, exc
        )
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
        from rebrew.formats.ne_loader import has_borland_marker

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
            if info.family != "unknown":
                # Only claim the detection when the NE evidence itself named
                # the family — a stronger backend (die/PDB) that ran first
                # keeps its detected_by.
                info.detected_by = "ne"
        # An NE executable is ALWAYS 16-bit x86 — the arch applies even when a
        # stronger backend (die/PDB) already named the family, mirroring the MZ
        # branch below.  Only 16-bit-capable profiles (msvc-1.52, watcom) can
        # ever byte-match it, so skipping this leaves a 32-bit profile free to
        # pass profile_matches_detection on a 16-bit target.
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
            elif "__aNchkstk" in probe_hits or "__chkstk" in probe_hits:
                info.family = "msvc"
                info.confidence = "medium"
                info.version_hint = "MSVC (16-bit stack probe symbol)"
            elif "__CHK" in probe_hits:
                info.family = "watcom"
                info.confidence = "medium"
                info.version_hint = "Watcom (stack probe __CHK)"
            elif msvc_hits:
                info.family = "msvc"
                info.confidence = "medium"
                info.version_hint = "MSVC CRT strings present"
            if info.family != "unknown":
                # Only claim the detection when the string evidence itself
                # named the family — a stronger backend (die/PDB) that ran
                # first keeps its detected_by.
                info.detected_by = "mz"

        # 16-bit codegen scan: confirms the family from the entry code
        # (evidence only — the string evidence above stays the decider).
        mz_cg = _mz_codegen_scan(getattr(binfo, "data", b""))
        if mz_cg.get("leave", 0) >= 3:
            info.add(f"{mz_cg['leave']} leave epilogues in entry code (MSVC 1.5x style)")
        if mz_cg.get("loop", 0) >= 2:
            info.add(
                f"{mz_cg['loop']} loop instructions in entry code (Borland/Watcom 16-bit style)"
            )
        if mz_cg.get("retf", 0):
            info.add(f"{mz_cg['retf']} far returns (retf) in entry code (far-model 16-bit)")
        if mz_cg.get("fp_prologue", 0) >= 2:
            info.add(f"{mz_cg['fp_prologue']} push bp frame prologues (16-bit codegen)")
        return info

    # The loader reads the arch from the image header (a PE's Machine field).
    if info.arch is None:
        info.arch = getattr(binfo, "arch", "") or None
    sections = {s.name for s in binfo.sections.values()}
    imports: set[str] = set()
    # binfo.imports is not populated by every loader — use the dedicated
    # import-table parser (LIEF-backed) when the generic field is empty.
    bin_imports = getattr(binfo, "imports", None) or []
    for imp in bin_imports:
        dll = str(getattr(imp, "dll", "") or "")
        if dll:
            imports.add(fold_ident(dll))
    if not imports and getattr(binfo, "format", "") == "pe":
        try:
            from rebrew.formats.import_table import parse_imports

            for entry in parse_imports(path):
                dll = str(entry.get("dll") or "")
                if dll:
                    imports.add(fold_ident(dll))
        except Exception:
            logger.debug("import-table scan failed for %s", path, exc_info=True)
            # import scan is best-effort — string evidence still applies

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
        # No CRT DLL import but MSVC family with real imports -> statically
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
    signals = CodegenSignals()
    try:
        from rebrew.formats.binary_loader import extract_bytes_at_va

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
        # Wrapper sites outside linked-library bands. Those objects keep
        # the /O they were built with and must not decide the program's level.
        text_base = binfo.text_va if binfo.text_size else 0
        excluded = exclude_ranges or []
        info.o2_wrapper_sites = _pattern_vas(text_bytes, text_base, _O2_WRAPPERS, excluded)
        info.o1_wrapper_sites = _pattern_vas(text_bytes, text_base, _O1_WRAPPERS, excluded)
        o2_wrappers = len(info.o2_wrapper_sites)
        o1_wrappers = len(info.o1_wrapper_sites)
        const_hoists = _count_const_hoists(text_bytes)
        signals = _count_codegen_signals(
            text_bytes, binfo.text_va if binfo.text_size else 0, exclude_ranges
        )
    except Exception:
        logger.debug("codegen scan failed for %s", path, exc_info=True)

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
        info.opt_level = opt_level_from_counts(o2_wrappers, o1_wrappers) or None
        if info.opt_level == "/O2":
            info.add(
                f"{o2_wrappers} load-first wrapper calls (`mov eax,[esp+4]; push eax`) -> /O2-style"
            )
        elif info.opt_level == "/O1":
            info.add(f"{o1_wrappers} push-[mem] wrapper calls (`push dword [esp+4]`) -> /O1-style")
        elif info.opt_level is not None and info.opt_level.startswith("mixed"):
            info.add(
                f"both wrapper styles present ({o1_wrappers} push-[mem], "
                f"{o2_wrappers} load-first): optimization is mixed per file, so "
                f"per-function flag sweeps fit better than one project-wide level"
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

    # --- additional codegen fingerprints (verified patterns — see
    # docs/codegen/README.md).  Raw whole-file counts are unreliable
    # (resource data contains coincidental pattern bytes); these run on
    # .text only. ---
    if signals.lea_esp_nops >= 2:
        info.add(f"{signals.lea_esp_nops} lea esp,[esp] loop-alignment nops (VC 7.0+ codegen)")
    if signals.rep_string_ops:
        info.add(f"{signals.rep_string_ops} rep movs/stos string ops (MSVC-style inlining)")
    if signals.rep_ret:
        info.add(f"{signals.rep_ret} rep-ret idioms (GCC-style)")
    if signals.magic_divs:
        info.add(f"{signals.magic_divs} magic-number division sites (MSVC 5.0+ / GCC)")
    if signals.sse2_fp:
        info.add(f"{signals.sse2_fp} SSE2 FP ops (VC 11.0+ or /arch:SSE2)")
    if signals.x87_fp:
        info.add(f"{signals.x87_fp} x87 FPU loads ([esp+N])")
    if signals.fp_prologues:
        info.add(
            f"{signals.fp_prologues} frame-pointer prologues "
            "(push ebp; mov ebp,esp): /Oy- or unoptimized"
        )
    if signals.mov_edi_edi >= 2:
        info.add(f"{signals.mov_edi_edi} mov edi,edi 2-byte nops (MSVC-style padding)")
    # --- VC6 code-generator family (Processor Pack vs plain) ---
    # The pack replaces c2.dll and rewrites every x87 compare; the two idiom
    # sets are disjoint across all nine registered VC6 generators and all nine
    # flag sets probed, so this narrows a VC6 target to one generator family
    # even though the cl.exe version is identical (12.00.8804).
    if info.family == "msvc":
        codegen = x87_codegen_family(signals)
        if codegen != "unknown":
            info.codegen = codegen
            info.add(
                f"{signals.pp_compares} Processor-Pack x87 compares "
                f"(fnstsw+test ah,0x44/0x05) vs {signals.plain_compares} plain "
                f"(fnstsw+test ah,0x40/0x01) -> {codegen} code generator"
            )

    # Codegen may pin a NEWER compiler than the CRT/linker era: the era
    # fingerprints (Rich header, DIE) name the build, but the codegen can
    # prove a different compiler compiled the code (a VC6-era binary whose
    # code is VC 7.0+ style, or vice versa).
    if info.family == "msvc" and info.version_hint.startswith("MSVC 6.0"):
        if signals.lea_esp_nops >= 2:
            info.version_hint += " (lea esp,[esp] loop-alignment nops; compiler may be VC 7.0+)"
        elif signals.sse2_fp:
            info.version_hint += " (SSE2 FP ops; compiler may be VC 11.0+ or built with /arch:SSE2)"

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
        info.version_hint = f"Borland C/C++ (runtime imports: {min(borlandc_imports)})"
    elif watcom_sections and watcom_hits:
        info.family = "watcom"
        info.confidence = "high"
        info.version_hint = "Watcom C/C++ (section layout + runtime strings)"
    elif watcom_sections:
        info.family = "watcom"
        info.confidence = "medium"
        info.version_hint = "Watcom C/C++ (section layout)"
    elif "__CHK" in probe_hits:
        info.family = "watcom"
        info.confidence = "medium"
        info.version_hint = "Watcom C/C++ (stack probe __CHK)"
    elif "__aNchkstk" in probe_hits or "__chkstk" in probe_hits:
        info.family = "msvc"
        info.confidence = "medium"
        info.version_hint = "MSVC (stack probe symbol)"
    elif "___chkstk_ms" in probe_hits:
        info.family = "mingw"
        info.confidence = "medium"
        info.version_hint = "MinGW GCC (stack probe ___chkstk_ms)"
    elif "__security_check_cookie" in probe_hits or "__security_cookie" in probe_hits:
        info.family = "msvc"
        info.confidence = "medium"
        info.version_hint = "MSVC (security-cookie /GS codegen, VC 8.0+ default)"
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
    elif signals.rep_ret and gnu_nops:
        # GCC return-after-branch idiom + GNU nops without a .buildid
        # section (stripped/renamed) — still MinGW codegen.
        info.family = "mingw"
        info.confidence = "medium"
        info.version_hint = _gcc_era_hint(modern_mov_calls, old_push_calls)
    elif signals.rep_string_ops and signals.fp_prologues:
        # rep movs/stos inlining + frame-pointer prologues with no CRT
        # strings or imports to lean on — MSVC-style codegen.
        info.family = "msvc"
        info.confidence = "low"
        info.version_hint = "MSVC-style codegen (rep string ops + frame prologues)"
    else:
        info.family = "unknown"
        info.confidence = "low"
    info.detected_by = info.detected_by or "heuristics"

    return info


def detect_toolchain(
    path: Path | str, exclude_ranges: list[tuple[int, int]] | None = None
) -> ToolchainInfo:
    """Detect the compiler family behind *path*.

    Backends run best-first and their evidence merges:
    DIE (``diec``) -> PDB (``llvm-pdbutil``) -> PE metadata -> structural
    heuristics.  A backend that fails or is unavailable is skipped silently;
    the family decision uses the first backend that identifies one, enriched
    by the version/flags evidence of the others.

    When every packaged backend leaves the family unknown, the
    ``rebrew.binary_detectors`` plugin detectors run in discovery order; the
    first non-None result supplies the family (``detected_by`` is recorded
    as ``plugin-<name>``).

    Never raises: an unreadable or unrecognized binary yields
    ``ToolchainInfo(family="unknown", confidence="low")``.
    """
    info = _detect_toolchain_core(path, exclude_ranges)
    detectors = detection_tables().detectors
    if info.family != "unknown" or not detectors:
        return info
    path = Path(path)
    for name, fn in detectors:
        try:
            plugin_info = fn(path)
        except Exception:
            logger.warning("plugin detector %r failed for %s", name, path, exc_info=True)
            continue
        if plugin_info is None:
            continue
        if not isinstance(plugin_info, ToolchainInfo):
            logger.warning(
                "plugin detector %r returned %s (expected ToolchainInfo | None)",
                name,
                type(plugin_info).__name__,
            )
            continue
        info.evidence.extend(plugin_info.evidence)
        if plugin_info.family and plugin_info.family != "unknown":
            info.family = plugin_info.family
            info.confidence = plugin_info.confidence or "medium"
            info.version_hint = plugin_info.version_hint
            info.arch = plugin_info.arch or info.arch
            info.detected_by = f"plugin-{name}"
            break
    return info


def profile_matches_detection(profile: str, info: ToolchainInfo) -> tuple[bool, str | None]:
    """Return ``(aligned, explanation)`` for *profile* vs a detection.

    *aligned* is True when the configured profile can plausibly byte-match
    the detected family; *explanation* carries a fix hint when not.
    """
    compatible = detection_tables().profile_compat.get(info.family)
    if compatible is None:
        if info.family == "unknown":
            return True, None  # unknown family: don't second-guess the user
        if info.family == "delphi":
            return (
                False,
                "Borland Delphi ABI: no rebrew compiler profile can match; document as blocker.",
            )
        return False, (
            f"{info.family} ABI: no rebrew compiler profile can match; document as blocker "
            "(no supported toolchain)."
        )
    if profile not in compatible:
        return (
            False,
            f"configured profile '{profile}' does not align with detected family '{info.family}' "
            f"({', '.join(sorted(compatible))} would fit); see the rebrew repo's"
            " docs/TOOLCHAIN.md",
        )
    # Version-exact check: when the PE metadata pinned the exact MSVC build
    # (Rich header / linker), a different-compiler profile cannot byte-match
    # every MSVC version is a different codegen.  This catches e.g. an
    # msvc-6.0 profile on a VC 8.0 binary (silent COMPILE_ERROR for every
    # function) before the first compile.
    if info.family == "msvc" and info.suggested_profiles and profile not in info.suggested_profiles:
        return (
            False,
            f"binary was built with MSVC {info.msvc_version}, and profile '{profile}' is a "
            "different compiler build; switch to one of: "
            f"{', '.join(sorted(info.suggested_profiles))}",
        )
    # Code-generator check: the VC6 service packs share cl.exe 12.00.8804 but
    # NOT the code generator, and the difference is visible in the x87 compare
    # idiom (Processor Pack vs plain).  Version-exact checks cannot see it —
    # every VC6 profile carries the same cl version — so a project whose
    # binary shows one family and configures the other compiles the whole tree
    # with the wrong generator and every FP-comparing function stops matching.
    if info.family == "msvc" and info.codegen in ("processor-pack", "plain"):
        pack_profiles = processor_pack_profiles()
        is_pack = profile in pack_profiles
        if info.codegen == "processor-pack" and not is_pack:
            return (
                False,
                f"binary's x87 compares are Processor-Pack codegen, but profile '{profile}' is a "
                f"plain VC6 generator; switch to {', '.join(sorted(pack_profiles))} "
                "(game code compiled with the pack cannot be reproduced by an SP6 profile)",
            )
        if info.codegen == "plain" and is_pack:
            return (
                False,
                f"binary's x87 compares are plain VC6 codegen, but profile '{profile}' carries the "
                "Processor Pack; switch to a plain VC6 profile "
                "(e.g. msvc-6.0-sp6) or the FP-comparing functions will not match",
            )
    # Arch dimension: a 16-bit DOS/NE binary can only be byte-matched by
    # 16-bit-capable profiles; conversely msvc-1.52 cannot match a 32/64-bit
    # PE/ELF.  This catches the "msvc-6.0 profile on a 16-bit project"
    # misconfiguration that silently produces COMPILE_ERROR for every
    # function (skifree16-rebrew regression).  The 16-bit-capable set is
    # explicit (msvc-1.52 = NE/DOS, borland-3.1/borland-2.0/watcom-2.0-win16 = DOS); watcom's
    # wcc386 is a 32-bit compiler (Open Watcom 2.0 x86-32) and must NOT be
    # flagged as 16-bit.
    if info.arch == "x86_16" and profile not in bitness16_profiles():
        return (
            False,
            f"detected 16-bit binary but profile '{profile}' is a 32/64-bit "
            f"compiler; switch to one of: {', '.join(bitness16_profiles())} "
            "(e.g. msvc-1.52 / borland-3.1 / borland-2.0) or document the functions as blockers",
        )
    if info.arch and info.arch != "x86_16" and profile in bitness16_profiles():
        return (
            False,
            f"profile '{profile}' is a 16-bit compiler but the binary is "
            f"{info.arch}; use a 32/64-bit profile (e.g. msvc-6.0)",
        )
    if info.family == "zig":
        return (
            True,
            "binary looks Zig-built (LLVM codegen): mingw-16.2.0 may only match structurally; "
            "see the rebrew repo's docs/TOOLCHAIN.md",
        )
    return True, None


def suggest_profile(info: ToolchainInfo, binary: Path | None = None) -> str | None:
    """Pick the best rebrew compiler profile for a detected toolchain family.

    The single source of truth for family->profile selection, used by
    ``rebrew init --guess-compiler``, ``rebrew intake``, and doctor.  Uses
    ``detection_tables().profile_compat`` (the byte-match compatibility table) and prefers the
    16-bit profile when the binary is 16-bit (NE x86_16 or a plain DOS MZ
    executable).  Version-exact ``suggested_profiles`` (Rich header / linker
    era, or plugin evidence) win over the generic preference lists, so e.g.
    an msvc-1.5/msvc-1.0/borland-2.0-pinned 16-bit target suggests that profile rather
    than the msvc-1.52 default.  Returns ``None`` when no rebrew profile can
    match.
    """
    compatible = detection_tables().profile_compat.get(info.family)
    if not compatible:
        return None
    is16 = _is_16bit_target(info, binary)
    # Version-exact: the metadata pinned the compiler build — prefer a
    # profile carrying that build over the generic family default.  The
    # suggestion must agree with the target bitness (a 32-bit suggestion on
    # a 16-bit binary, or vice versa, can never byte-match).
    if info.suggested_profiles:
        bit16 = set(bitness16_profiles())
        for p in info.suggested_profiles:
            if p not in compatible:
                continue
            if is16 != (p in bit16):
                continue
            return p
    if is16:
        # Prefer the established 16-bit profiles, then plugin-registered
        # bits=16 toolchains (sorted for determinism).
        for p in ("msvc-1.52", "borland-3.1", "watcom-2.0-win16"):
            if p in compatible:
                return p
        for p in bitness16_profiles():
            if p in compatible:
                return p
    for p in (
        "msvc-6.0",
        "borland-5.5",
        "watcom-2.0-win32",
        "mingw-16.2.0",
        "clang-18.1.8",
        "gcc-14.2.0",
    ):
        if p in compatible:
            return p
    return min(compatible)


__all__ = [
    "BACKEND_DISPLAY",
    "BINARY_DETECTOR_ENTRY_POINT_GROUP",
    "BORLANDC_IMPORTS",
    "BORLANDC_MARKERS",
    "BORLAND_SECTIONS",
    "CONFIDENCE_RANK",
    "DELPHI_MARKERS",
    "DETECTION_TABLES",
    "DIE_UNAVAILABLE",
    "ICC_MARKERS",
    "LINKER_ERA_PROFILES",
    "LINKER_ERA_PROFILES_ALL",
    "MSVCP_IMPORT_VERSIONS",
    "MSVC_LINKER_VERSIONS",
    "MSVC_MARKERS",
    "MSVC_VERSION_ENTRY_POINT_GROUP",
    "MSVC_VERSION_HINTS",
    "O1_WRAPPERS",
    "O2_WRAPPERS",
    "OPT_MIN_SITES",
    "PLUGIN_DETECTORS",
    "PROBE_SYMBOLS",
    "PROFILE_COMPAT",
    "PROFILE_COMPAT_ALL",
    "REAL_MODE_ADDRESS_MASK",
    "RICH_BUILD_PROFILES",
    "RICH_BUILD_PROFILES_ALL",
    "SOURCE_CHECKOUT",
    "SYMANTEC_MARKERS",
    "TOOLCHAIN_DETECTOR_ENTRY_POINT_GROUP",
    "VENDORED_DIEC",
    "WATCOM_MARKERS",
    "ZORTECH_MARKERS",
    "CodegenSignals",
    "DetectionTables",
    "ToolchainInfo",
    "backend_display_name",
    "bitness16_profiles",
    "count_codegen_signals",
    "count_const_hoists",
    "count_masked",
    "detect_toolchain",
    "detect_with_die",
    "detect_with_pdb",
    "detect_with_pe_meta",
    "detection_tables",
    "diec_env",
    "diec_version_hint",
    "discover_binary_detectors",
    "find_diec",
    "fold_ident",
    "gcc_era_hint",
    "is_16bit_target",
    "iter_masked",
    "linker_era_hint",
    "load_binary",
    "merged_msvc_version_tables",
    "merged_profile_compat",
    "msvc_version_hint",
    "mz_codegen_scan",
    "opt_level_from_counts",
    "opt_level_without_library",
    "pattern_vas",
    "processor_pack_profiles",
    "profile_matches_detection",
    "refresh_detection_tables",
    "rich_compiler_build",
    "run_diec",
    "run_process_group",
    "scan_strings",
    "suggest_profile",
    "x87_codegen_family",
]
