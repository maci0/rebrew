"""Compiler version tables, compatibility sets, and detection data structures."""

from __future__ import annotations

import logging
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, cast

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Evidence markers
# ---------------------------------------------------------------------------

DELPHI_MARKERS = (
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

MSVC_MARKERS = (
    "Microsoft Visual C++ Runtime Library",
    "Runtime Error!",
    "__GLOBAL_HEAP_SELECTED",
    "abnormal program termination",
)

BORLAND_SECTIONS = {"CODE", "DATA", "BSS"}

WATCOM_MARKERS = ("Open Watcom", "Watcom C/C++", "Watcom Run-time Library", "WATCOM C/C++")

# Borland C/C++ (Turbo C, C++Builder) — distinct from Delphi: same CODE/DATA/
# BSS section layout but no Delphi RTL strings, and its own runtime imports.
BORLANDC_MARKERS = ("Borland C++", "Borland C Runtime", "Turbo C", "BORLAND")
#: Compilers with no rebrew byte-matching profile yet — detected for the
#: dossier, documented as blockers (diec identifies them reliably).
SYMANTEC_MARKERS = ("Symantec C++", "Symantec C/C++", "Symantec C++ Runtime")
ZORTECH_MARKERS = ("Zortech C++", "Zortech C")
ICC_MARKERS = ("Intel C++ Compiler", "Intel(R) C++ Compiler", "Intel C/C++")
BORLANDC_IMPORTS = {
    "cw32.dll",
    "cc32.dll",
    "cc3250mt.dll",
    "cw3250mt.dll",
    "borlndmm.dll",
}

#: MSVC version strings DIE reports (e.g. "12.00.9782" = MSVC 6.0) mapped to
#: the era rebrew profiles care about.  Only used to pick a version hint —
#: family detection comes from the name, not the number.
MSVC_VERSION_HINTS = {
    "10.00": "MSVC 4.x",
    "11.00": "MSVC 5.0",
    "12.00": "MSVC 6.0",
    "13.10": "MSVC 7.1",
    "13.00": "MSVC 7.0",
    "14.00": "MSVC 8.0",
    "15.00": "MSVC 9.0",
    "16.00": "MSVC 10.0",
    "17.00": "MSVC 11.0",
}

#: PE optional-header linker version ("major.minor") -> MSVC compiler
#: (major, minor).  The linker version is the strongest per-version signal
#: for the classic linkers, and combined with the Rich-header C1 build it
#: pins the exact compiler (e.g. linker 6.0 + C1 8168 = 12.00.8168 = VC 6.0).
#: Early linkers (2.50-4.20) write no Rich header, so the linker version
#: alone names the version (VC 2.0 .. 4.2).  Note MinGW's GNU ld also writes
#: a 2.x linker version — the Rich header (or the family evidence) must
#: disambiguate a bare 2.x.
MSVC_LINKER_VERSIONS: dict[str, tuple[int, int]] = {
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
    "11.0": (17, 0),  # VC 11.0 (2012)
}

#: Rich-header C1/C2 build numbers -> rebrew profiles carrying that exact
#: compiler build.  Empirically dumped from the rebrew toolchain images:
#: each image's linker records the front-end build, which for the VC 6.0
#: service packs is the C1.DLL build (8168 RTM, 8447 SP3, 8966 SP5, 9782
#: SP6 — SP builds are NOT the same compiler).  A tuple = profiles sharing
#: the same build (e.g. 9466 is carried by msvc-7.0, msvc-7.0-rtm and msvc-7.0-sp1).
RICH_BUILD_PROFILES: dict[int, tuple[str, ...]] = {
    8168: ("msvc-6.0", "msvc-6.0-sp1", "msvc-6.0-sp2"),  # 12.00.8168 (VC6 RTM..SP3 driver)
    8447: ("msvc-6.0-sp3",),  # 12.00.8447
    8966: ("msvc-6.0-sp4", "msvc-6.0-sp5"),  # 12.00.8966 (SP4 = SP5 C1)
    9782: ("msvc-6.0-sp6",),  # 12.00.9782
    9466: ("msvc-7.0", "msvc-7.0-rtm", "msvc-7.0-sp1"),  # 13.00.9466
    9955: ("msvc-7.0-sp1",),  # 13.00.9955 (7.0 SP1 C1)
    3077: ("msvc-7.1",),  # 13.10.3077
    6030: ("msvc-7.1-sp1",),  # 13.10.6030
    50727: ("msvc-8.0", "msvc-8.0-sp1"),  # 14.00.50727 (+.762 for SP1)
    21022: ("msvc-9.0",),  # 15.00.21022
    30729: ("msvc-9.0-sp1",),  # 15.00.30729 (VC9 SP1 — the compiler the msvc-9.0 repo lacks)
    30319: ("msvc-10.0",),  # 16.00.30319
    40219: ("msvc-10.0-sp1",),  # 16.00.40219
    50522: ("msvc-11.0",),  # 17.00.50522 (VC11 / VS 2012)
}

#: Linker-era default profiles (used when the Rich-header build is unknown):
#: the linker version pins the compiler generation, so an unrecognized build
#: (e.g. a hotfix) still suggests the right family instead of the generic
#: default.  The Rich build table (RICH_BUILD_PROFILES) overrides this when
#: the exact build is known.
LINKER_ERA_PROFILES: dict[tuple[int, int], tuple[str, ...]] = {
    (9, 0): ("msvc-2.0",),
    (10, 0): ("msvc-4.0",),
    (10, 10): ("msvc-4.1",),
    (10, 20): ("msvc-4.2",),
    (11, 0): ("msvc-5.0", "msvc-5.0-sp1", "msvc-5.0-sp2", "msvc-5.0-sp3"),
    (12, 0): (
        "msvc-6.0",
        "msvc-6.0-sp1",
        "msvc-6.0-sp2",
        "msvc-6.0-sp3",
        "msvc-6.0-sp4",
        "msvc-6.0-sp5",
        "msvc-6.0-sp5-pp",
        "msvc-6.0-sp6",
    ),
    (13, 0): ("msvc-7.0", "msvc-7.0-rtm", "msvc-7.0-sp1"),
    (13, 10): ("msvc-7.1", "msvc-7.1-sp1"),
    (14, 0): ("msvc-8.0", "msvc-8.0-sp1"),
    (15, 0): ("msvc-9.0", "msvc-9.0-sp1"),
    (16, 0): ("msvc-10.0", "msvc-10.0-sp1"),
    (17, 0): ("msvc-11.0",),
}

#: Entry-point group whose members declare which exact MSVC builds/linker
#: eras their toolchains byte-match.  A member returns
#: ``dict[str, list[profile]]`` keyed ``"build:<n>"`` (Rich-header C1/C2
#: build, e.g. ``"build:8168"``) or ``"linker:<M>.<m>"`` (e.g.
#: ``"linker:12.0"``) -> profiles.  Merged into the packaged version tables
#: below (union per key — a build number is detection evidence, and a
#: plugin adds the profiles that match it, e.g. an MSVC-derivative plugin
#: declaring ``{"build:8168": ["mytc"]}`` so the version-exact check in
#: ``profile_matches_detection`` accepts it for that exact build).
MSVC_VERSION_ENTRY_POINT_GROUP = "rebrew.msvc_versions"

#: CRT import names -> MSVC version binder (msvcp60.dll = VC 6.0, etc.).
#: The msvcpX.dll import is written by the /MD CRT of that toolchain; a
#: strong secondary signal when the Rich header is absent (some linkers
#: or post-processing strip it).
MSVCP_IMPORT_VERSIONS: dict[str, str] = {
    "msvcp60.dll": "6.0",
    "msvcp70.dll": "7.0",
    "msvcp71.dll": "7.1",
    "msvcp80.dll": "8.0",
    "msvcp90.dll": "9.0",
    "msvcp100.dll": "10.0",
}

#: Ordering for ``ToolchainInfo.confidence``.  ``max()`` on the raw strings is
#: lexicographic ("high" < "low" < "medium"), so merging backends that way
#: demoted a high PE-meta result to "low" whenever DIE had said "low".
CONFIDENCE_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


def resolve_pkg_hook[T](current: T, original: T, *pkg_attrs: str) -> T:
    """Return a monkeypatched attribute from ``rebrew.toolchain_detect`` if overridden."""
    pkg = sys.modules.get(__package__ or "")
    if pkg is not None:
        for attr in pkg_attrs:
            val = getattr(pkg, attr, original)
            if val is not original:
                return cast("T", val)
    return current


def merged_msvc_version_tables() -> tuple[
    dict[int, tuple[str, ...]], dict[tuple[int, int], tuple[str, ...]]
]:
    """Version-exact tables: packaged + ``rebrew.msvc_versions`` providers.

    Packaged tuples keep their order; a provider appends its profiles after
    them (order matters — ``suggest_profile`` prefers earlier names).  An
    optional registry: a broken provider or a malformed key is skipped with
    a warning (the packaged tables stand)."""
    from rebrew.registry import iter_optional_provider_dicts

    rich = {k: tuple(v) for k, v in RICH_BUILD_PROFILES.items()}
    eras = {k: tuple(v) for k, v in LINKER_ERA_PROFILES.items()}
    for reg, provided in iter_optional_provider_dicts(
        MSVC_VERSION_ENTRY_POINT_GROUP,
        logger,
        expected="dict['build:<n>' | 'linker:<M>.<m>', list[profile]]",
    ):
        for key, profiles in provided.items():
            if not isinstance(profiles, (list, tuple, set)) or not profiles:
                logger.warning(
                    "skipping %s provider %r: %r must map to a non-empty list of profiles",
                    reg.group,
                    reg.name,
                    key,
                )
                continue
            names = tuple(str(p) for p in profiles)
            if key.startswith("build:"):
                try:
                    build = int(key.removeprefix("build:"))
                except ValueError:
                    logger.warning(
                        "skipping %s provider %r: %r is not 'build:<integer>'",
                        reg.group,
                        reg.name,
                        key,
                    )
                    continue
                existing = rich.get(build)
                rich[build] = existing + names if existing else names
            elif key.startswith("linker:"):
                try:
                    major, minor = (int(x) for x in key.removeprefix("linker:").split("."))
                except ValueError:
                    logger.warning(
                        "skipping %s provider %r: %r is not 'linker:<M>.<m>'",
                        reg.group,
                        reg.name,
                        key,
                    )
                    continue
                mm = (major, minor)
                existing = eras.get(mm)
                eras[mm] = existing + names if existing else names
            else:
                logger.warning(
                    "skipping %s provider %r: key %r must be 'build:<n>' or 'linker:<M>.<m>'",
                    reg.group,
                    reg.name,
                    key,
                )
                continue
    return rich, eras


RICH_BUILD_PROFILES_ALL, LINKER_ERA_PROFILES_ALL = merged_msvc_version_tables()


@dataclass
class ToolchainInfo:
    """Result of a toolchain detection pass."""

    family: str = "unknown"  # msvc | mingw | zig | delphi | unknown
    version_hint: str = ""  # e.g. "MSVC 6.0" / "pre-8 GCC (push-arg style)"
    confidence: str = "low"  # low | medium | high
    evidence: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)  # compiler flags (PDB-derived)
    detected_by: str = ""  # backend: die | pdb | pe-meta | heuristics | plugin-<name>
    # None in arch, opt_level, codegen, packed and packer: not determined.
    arch: str | None = None  # the loader's arch ("x86_32" from a PE header); "x86_16" for NE/MZ
    crt: str = ""  # CRT linkage name: "msvcrt.dll"/"crtdll.dll" (dynamic), "LIBCMT" (static)
    crt_linkage: str = ""  # "dynamic" | "static" | "" (unknown)
    base_cflags: str = ""  # suggested base_cflags: "/MD" or "/MT" for MSVC-family binaries
    opt_level: str | None = None  # "/O1", "/O2" or "mixed ..." (MSVC codegen fingerprint)
    # Wrapper-call sites that produced opt_level, already outside exclude_ranges.
    # Doctor uses them to set aside a statically linked CRT built at the other level.
    o2_wrapper_sites: list[int] = field(default_factory=list)
    o1_wrapper_sites: list[int] = field(default_factory=list)
    msvc_version: str = ""  # exact compiler version, e.g. "12.00.8168" (PE metadata)
    suggested_profiles: list[str] = field(default_factory=list)  # version-exact rebrew profiles
    packed: bool | None = None  # the packer scan's answer; False when it found none
    packer: str | None = None  # packer name/version when packed ("lzexe 0.91", "pklite")
    codegen: str | None = None  # VC6 code generator: processor-pack | plain | mixed

    def add(self, text: str) -> None:
        self.evidence.append(text)


@dataclass
class CodegenSignals:
    """Byte-level codegen fingerprint counts for one .text section.

    Every pattern is verified against real toolchain output — see
    docs/codegen/README.md for the provenance of each field.
    """

    lea_esp_nops: int = 0  # lea esp,[esp] — VC 7.0+ loop alignment
    rep_stosd: int = 0  # f3 ab — memset-style inlining (MSVC)
    rep_movsd: int = 0  # f3 a5 — memcpy-style inlining (MSVC)
    rep_stosb: int = 0  # f3 aa
    rep_movsb: int = 0  # f3 a4
    rep_ret: int = 0  # f3 c3 — GCC return-after-branch idiom
    magic_divs: int = 0  # divide-by-constant magic immediates (MSVC 5.0+/GCC)
    sse2_fp: int = 0  # addsd/mulsd/divsd/subsd — VC 11.0+ or /arch:SSE2
    x87_fp: int = 0  # fld [esp+N] — x87 FPU loads
    fp_prologues: int = 0  # push ebp; mov ebp,esp — /Oy- or unoptimized
    mov_edi_edi: int = 0  # 2-byte mov edi,edi nops (MSVC-style padding)
    pp_compares: int = 0  # df e0 f6 c4 44|05 — Processor Pack x87 compare
    plain_compares: int = 0  # df e0 f6 c4 40|01 — pre-Processor-Pack x87 compare

    @property
    def rep_string_ops(self) -> int:
        return self.rep_stosd + self.rep_movsd + self.rep_stosb + self.rep_movsb


#: User-facing names for the detection backends (doctor/analyze messages must
#: not leak the internal ids).
BACKEND_DISPLAY: dict[str, str] = {
    "die": "Detect It Easy (diec)",
    "pdb": "PDB",
    "heuristics": "codegen heuristics",
    "pe-meta": "PE metadata (Rich header / linker version)",
}


def backend_display_name(detected_by: str) -> str:
    """Human-readable name for a detection backend id, or the id itself."""
    return BACKEND_DISPLAY.get(detected_by, detected_by)


# ---------------------------------------------------------------------------
# Plugin binary detectors — compiler families the packaged backends don't know
# ---------------------------------------------------------------------------

#: setuptools entry-point group whose members detect compiler families the
#: packaged backends (DIE/PDB/PE-meta/heuristics) do not recognize.  A
#: member is a callable ``(path: Path) -> ToolchainInfo | None``; the first
#: non-None result supplies the family when the packaged pipeline left it
#: unknown, so a genuinely novel compiler becomes detectable end-to-end:
#: its family flows into ``PROFILE_COMPAT_ALL`` (extensible via
#: ``rebrew.toolchain_detectors``) for doctor/init profile alignment.
BINARY_DETECTOR_ENTRY_POINT_GROUP = "rebrew.binary_detectors"


def discover_binary_detectors() -> list[tuple[str, Any]]:
    """Every ``rebrew.binary_detectors`` entry-point member, as ``(name, fn)``.

    An optional registry: a broken or non-callable member is skipped with a
    warning (novel-family detection degrades to the packaged backends)."""
    from rebrew.registry import iter_optional_callables

    return [
        (reg.name, fn)
        for reg, fn in iter_optional_callables(
            BINARY_DETECTOR_ENTRY_POINT_GROUP, logger, expected="detector"
        )
    ]


PLUGIN_DETECTORS: list[tuple[str, Any]] = discover_binary_detectors()


#: Compiler profiles that can byte-match each detected family.
#: ``None`` means no supported rebrew compiler can match that family.
PROFILE_COMPAT: dict[str, set[str] | None] = {
    # msvc-1.52 is the 16-bit profile — the detection hint distinguishes
    # "16-bit MSVC-style NE" from 32-bit targets.
    "msvc": {
        "msvc-4.0",
        "msvc-4.2",
        "msvc-4.1",
        "msvc-2.0",
        "msvc-5.0",
        "msvc-5.0-sp1",
        "msvc-5.0-sp2",
        "msvc-5.0-sp3",
        "msvc-6.0",
        "msvc-6.0-sp1",
        "msvc-6.0-sp2",
        "msvc-6.0-sp3",
        "msvc-6.0-sp4",
        "msvc-6.0-sp5",
        "msvc-6.0-sp5-pp",
        "msvc-6.0-sp6",
        "msvc-7.0",
        "msvc-7.0-rtm",
        "msvc-7.0-sp1",
        "msvc-7.1",
        "msvc-7.1-sp1",
        "msvc-8.0",
        "msvc-8.0-sp1",
        "msvc-9.0",
        "msvc-9.0-sp1",
        "msvc-10.0",
        "msvc-10.0-sp1",
        "msvc-11.0",
        "msvc-1.52",
        "msvc-1.5",
        "msvc-1.0",
    },
    "mingw": {"mingw-16.2.0"},
    "zig": {"mingw-16.2.0"},  # may match structurally only (LLVM vs GCC codegen)
    "watcom": {"watcom-2.0-win32", "watcom-2.0-win16"},  # wcc386 (32-bit) + wcc (16-bit DOS)
    "delphi": None,
    # Turbo C/C++ 3.1 (borland-3.1, 16-bit DOS) and Borland C++ 5.5 (bcc32, 32-bit)
    # both emit Borland-flavored OMF/COFF that rebrew can byte-match.
    "borlandc": {"borland-2.0", "borland-3.1", "borland-5.5"},
    "symantec": None,
    "zortech": None,
    "icc": None,
    "unknown": None,
}

#: Entry-point group whose members declare which detected families their
#: toolchains can byte-match.  A member is a zero-arg callable returning
#: ``dict[family, list[profile_name]]`` — e.g. a plugin MSVC-derivative
#: toolchain declaring ``{"msvc": ["mytc"]}`` so detection, doctor, and
#: ``rebrew init --guess-compiler`` treat it as family-aligned.  Merged
#: into :data:`PROFILE_COMPAT` below; a family the packaged table marks
#: un-matchable (``None``) becomes matchable when a plugin declares
#: profiles for it.
TOOLCHAIN_DETECTOR_ENTRY_POINT_GROUP = "rebrew.toolchain_detectors"


def merged_profile_compat() -> dict[str, set[str] | None]:
    """The byte-match compatibility table: packaged + plugin declarations.

    Packaged family sets are the base; a provider extends a family's
    profile set (union).  An optional registry: a broken provider is
    skipped with a warning (the packaged table stands)."""
    from rebrew.registry import iter_optional_provider_dicts

    compat = {k: (set(v) if v is not None else None) for k, v in PROFILE_COMPAT.items()}
    for reg, provided in iter_optional_provider_dicts(
        TOOLCHAIN_DETECTOR_ENTRY_POINT_GROUP, logger, expected="dict[family, list[profile]]"
    ):
        for family, profiles in provided.items():
            if not isinstance(profiles, (set, list, tuple)) or not profiles:
                logger.warning(
                    "skipping %s provider %r: family %r must map to a non-empty list of profiles",
                    reg.group,
                    reg.name,
                    family,
                )
                continue
            names = {str(p) for p in profiles}
            existing = compat.get(family)
            compat[family] = names if existing is None else (existing | names)
    return compat


PROFILE_COMPAT_ALL: dict[str, set[str] | None] = merged_profile_compat()


@dataclass(frozen=True)
class DetectionTables:
    """One generation of the detection registries, published as a unit.

    The compat table and the two version-exact tables are ONE component: a
    profile a plugin adds to ``rebrew.msvc_versions`` and the family it adds
    to ``rebrew.toolchain_detectors`` must be visible to the same reader.  A
    reader that pulled two module globals across a refresh could mix the
    generations and report a profile as era-only (or the reverse).
    """

    profile_compat: dict[str, set[str] | None]
    rich_build_profiles: dict[int, tuple[str, ...]]
    linker_era_profiles: dict[tuple[int, int], tuple[str, ...]]
    detectors: list[tuple[str, Any]]


DETECTION_TABLES = DetectionTables(
    profile_compat=PROFILE_COMPAT_ALL,
    rich_build_profiles=RICH_BUILD_PROFILES_ALL,
    linker_era_profiles=LINKER_ERA_PROFILES_ALL,
    detectors=PLUGIN_DETECTORS,
)

#: One lock for the whole detection publication.  A refresh republishes four
#: tables, so two concurrent refreshes would otherwise interleave and leave a
#: reader with the tables of one discovery beside the tables of the other.
_DETECTION_REFRESH_LOCK = threading.Lock()


def detection_tables() -> DetectionTables:
    """The current generation of the detection registries.

    One reference, so a reader that needs more than one table gets a
    consistent set; :func:`refresh_detection_tables` replaces it whole."""
    with _DETECTION_REFRESH_LOCK:
        pkg = sys.modules.get(__package__ or "")
        tables = (
            getattr(pkg, "_DETECTION_TABLES", DETECTION_TABLES)
            if pkg is not None
            else DETECTION_TABLES
        )
        return DetectionTables(
            profile_compat={
                key: set(value) if value is not None else None
                for key, value in tables.profile_compat.items()
            },
            rich_build_profiles=dict(tables.rich_build_profiles),
            linker_era_profiles=dict(tables.linker_era_profiles),
            detectors=list(tables.detectors),
        )


def refresh_detection_tables() -> dict[str, int]:
    """Re-run discovery and refresh the detection registries.

    Refreshes :data:`PROFILE_COMPAT_ALL`, the MSVC version-exact tables
    (:data:`RICH_BUILD_PROFILES_ALL` / :data:`LINKER_ERA_PROFILES_ALL`),
    and :data:`PLUGIN_DETECTORS` — long-lived processes can pick up
    detection plugins installed after startup without a restart.  Returns
    the resulting entry counts keyed by entry-point group, for
    :func:`rebrew.registry.refresh_all`.

    Every value is built before anything is published, and the four globals
    are then rebound in one locked section: a reader must never see a profile
    in the version tables that the compat table of the same discovery does not
    know.  :func:`detection_tables` hands a reader the whole generation as one
    reference; writers must never mutate the published tables in place."""
    global PROFILE_COMPAT_ALL, RICH_BUILD_PROFILES_ALL
    global LINKER_ERA_PROFILES_ALL, PLUGIN_DETECTORS, DETECTION_TABLES

    compat = merged_profile_compat()
    rich, eras = merged_msvc_version_tables()
    detectors = discover_binary_detectors()
    new_tables = DetectionTables(
        profile_compat=compat,
        rich_build_profiles=rich,
        linker_era_profiles=eras,
        detectors=detectors,
    )
    with _DETECTION_REFRESH_LOCK:
        PROFILE_COMPAT_ALL = compat
        RICH_BUILD_PROFILES_ALL, LINKER_ERA_PROFILES_ALL = rich, eras
        PLUGIN_DETECTORS = detectors
        DETECTION_TABLES = new_tables
        pkg = sys.modules.get(__package__ or "")
        if pkg is not None:
            pkg.PROFILE_COMPAT_ALL = compat  # type: ignore[attr-defined]
            pkg.RICH_BUILD_PROFILES_ALL = rich  # type: ignore[attr-defined]
            pkg.LINKER_ERA_PROFILES_ALL = eras  # type: ignore[attr-defined]
            pkg._PLUGIN_DETECTORS = detectors  # type: ignore[attr-defined]
            pkg._DETECTION_TABLES = new_tables  # type: ignore[attr-defined]
    return {
        "binary_detectors": len(detectors),
        "toolchain_detectors": len(compat),
        "msvc_versions": len(rich) + len(eras),
    }


def processor_pack_profiles() -> set[str]:
    """Registered MSVC profile names whose code generator is the Processor Pack.

    Read from the toolchain registry (``TOOLCHAINS``) so a future pack
    variant is covered without a second list to keep in sync.
    """
    try:
        from rebrew.compiler.toolchain import TOOLCHAINS
    except Exception as exc:  # pragma: no cover - registry always importable
        logger.warning(
            "toolchain registry unavailable (%s); pack profiles fall back to defaults", exc
        )
        return {"msvc-6.0-sp5-pp"}
    return {str(name) for name in TOOLCHAINS if str(name).endswith("-pp")}


def bitness16_profiles() -> tuple[str, ...]:
    """Profiles registered with ``bits = 16``, for DOS/NE byte-matching.

    Comes straight from the toolchain registry, so a plugin toolchain
    declaring ``bits = 16`` (entry-point or ``REBREW_TOOLCHAIN_OVERLAY_DIR``
    TOML) is allowed on x86_16 targets instead of being flagged as a
    32/64-bit compiler."""
    from rebrew.compiler.toolchain import TOOLCHAINS

    return tuple(sorted(n for n, s in TOOLCHAINS.items() if s.bits == 16))
