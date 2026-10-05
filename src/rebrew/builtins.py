"""Packaged CLI components and their static domain membership.

Domain apps use the same CliComponent activation as the umbrella. Each domain
holds its context and scope for the app lifetime; retiring the umbrella mount
removes the whole domain without changing another component's registrations.
"""

from __future__ import annotations

import importlib

import typer

from rebrew.cli import console
from rebrew.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    CoeffectScope,
    Context,
    Panel,
    activate,
)

DOMAIN_COMPONENTS: dict[str, tuple[CliComponent, ...]] = {
    "source": (
        CliComponent(
            name="rename",
            module="rebrew.rename",
            help="Rename a function and update all cross-references.",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="migrate-markers",
            module="rebrew.migrate_markers",
            help=(
                "Move inline function and data markers into the metadata stores "
                "(ADR 023: pure-C sources)."
            ),
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="fix",
            module="rebrew.fixup",
            help="Make raw decompiler output compilable (DecBench-style fixup: sanitize + inject).",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="inline-strings",
            module="rebrew.inline_strings",
            help="Inline string-literal globals (s_<hint>_<0xADDR>) from the reference binary.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="document-unmatched",
            module="rebrew.document_unmatched",
            help="Document unmatched functions as STUB skeletons + blockers.",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="graph",
            module="rebrew.depgraph",
            help="Function dependency graph visualization (--cu-map for CU boundaries).",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="security",
            module="rebrew.security_scan",
            help="Scan C sources for unsafe API use (unbounded copies, format strings, command execution).",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="split",
            module="rebrew.split",
            help="Split multi-function C files into single-function files.",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="merge",
            module="rebrew.merge",
            help="Merge single-function C files into one multi-function file.",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="import-related",
            module="rebrew.cross_import",
            help="Import matched functions from another target (same code, different VAs).",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="import-splat",
            module="rebrew.splat_config",
            help="Seed a project from splat configuration (preview by default).",
            panel=Panel.PROJECT_SETUP,
        ),
    ),
    "types": (
        CliComponent(
            name="recover",
            module="rebrew.struct_recover",
            help="Recover struct definitions from decompiler output (offset evidence → typedefs).",
            panel=Panel.DEVELOPMENT,
        ),
    ),
    "build": (
        CliComponent(
            name="postlink",
            module="rebrew.postlink",
            help="Normalize a built binary's layout onto a reference (import records, .data/.reloc, PE stamps).",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="layout",
            module="rebrew.gen_layout",
            help="Generate linker-script scaffolding from the binary (.def, layout manifest, IAT seed).",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="cmake-toolchain",
            module="rebrew.cmake_tc",
            help="Write a CMake toolchain file that drives a docker toolchain via rebrew.",
            panel=Panel.PROJECT_SETUP,
        ),
        CliComponent(
            name="driver",
            module="rebrew.cmake_tc",
            attr="driver_main",
            help="Run the compiler, linker, or archiver for CMake.",
            panel=Panel.PROJECT_SETUP,
            epilog="Examples:\n\n  rebrew build driver cl -- /c src/f.c /Fooutput/f.obj\n\nArguments after -- go unchanged to the selected build tool.",
        ),
        CliComponent(
            name="objdiff-driver",
            module="rebrew.objdiff_project",
            attr="build_main",
            help="Rebuild an objdiff base object.",
            panel=Panel.MATCHING,
            epilog="Examples:\n\n  rebrew build objdiff-driver SERVER src/SERVER/f.obj\n\nInvoked by generated objdiff configuration; rebuilds the base object.",
        ),
        CliComponent(
            name="cmake-flags",
            module="rebrew.cmake_flags",
            help="Write the per-file CFLAGS from rebrew-functions.toml as a CMake include.",
            panel=Panel.PROJECT_SETUP,
        ),
        CliComponent(
            name="cmake-sources",
            module="rebrew.cmake_sources",
            help="Write the target's marker-selected source list as a CMake include.",
            panel=Panel.PROJECT_SETUP,
        ),
        CliComponent(
            name="check",
            module="rebrew.build_check",
            help="Verify build/ still matches what CMake generated (guards hand-edited build.make).",
            panel=Panel.PROJECT_SETUP,
        ),
        CliComponent(
            name="order-sources",
            module="rebrew.order_sources",
            help="Order source files by their first function's original VA (position-aligned .text).",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="calibrate-bss",
            module="rebrew.calibrate_bss",
            help="Calibrate a BSS tail pad so the raw link's .data VirtualSize matches the reference.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="link-stubs",
            module="rebrew.gen_link_stubs",
            help="Generate a link_stubs.c-style BSS placeholder TU from the data metadata.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="symbol-stubs",
            module="rebrew.gen_stubs",
            help="Generate a stub TU for unresolved linker symbols (LNK2001/LNK2019).",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="check-data-placement",
            module="rebrew.verify_placement",
            help="Compare .data symbol VAs of the current build against the data metadata.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="check-text-placement",
            module="rebrew.text_audit",
            help="Compare .text function VAs of the current build against the source markers.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="sweep-link-flags",
            module="rebrew.link_sweep",
            help="Sweep LINK options to reproduce the reference PE header (find stamp-only fields).",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="link-order",
            module="rebrew.link_order",
            help="Enforce VA-ordered sources into CMakeLists.txt SOURCES (drift gate).",
            panel=Panel.PROJECT_SETUP,
        ),
        CliComponent(
            name="check-exports",
            module="rebrew.verify_exports",
            help="Verify the recompiled binary's export table matches the original target.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="round-trip",
            module="rebrew.round_trip",
            help="Splice matched functions back into target PE and verify.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="residue",
            module="rebrew.residue",
            help="Section diffs plus per-function attribution of remaining .text bytes.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="layout-map",
            module="rebrew.layout_map",
            help="Dump reference-side layout measurements (sections, gaps, IAT, exports).",
            panel=Panel.ANALYSIS,
        ),
    ),
    "diagnose": (
        CliComponent(
            name="stack",
            module="rebrew.stack_cmp",
            help="Compare the compiled function's stack frame against the target binary.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="drift",
            module="rebrew.drift_cli",
            help="Localise where compiled bytes drift from the reference, from branch targets.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="config",
            module="rebrew.diagnose",
            help="Explain why a function compiles with its toolchain+flags (resolution trace).",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="probe",
            module="rebrew.probe",
            help="Measure one function against the reference without writing metadata.",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="near",
            module="rebrew.near_diag",
            help="Classify why a NEAR_MATCHING function does not byte-match.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="gap",
            module="rebrew.gap_trace",
            help="Trace length-gap drift between object and reference instruction streams.",
            panel=Panel.ANALYSIS,
        ),
    ),
    "binary": (
        CliComponent(
            name="asm",
            module="rebrew.asm",
            help="Disassemble a function (hex dump or NASM source).",
            panel=Panel.MATCHING,
            is_group=True,
        ),
        CliComponent(
            name="switches",
            module="rebrew.switch",
            help="Decode jump-table switch dispatches in a function (case → handler map).",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="pdb",
            module="rebrew.pdb_info",
            help="Extract compiler version, flags, and function names from a sibling PDB.",
            panel=Panel.ANALYSIS,
            is_group=True,
        ),
        CliComponent(
            name="functions",
            module="rebrew.discover",
            help="Enumerate functions: rizin aaa/aap + capstone sweep, sizes validated.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="unpack-lzexe",
            module="rebrew.lzexe_cli",
            help="Unpack an LZEXE 0.90/0.91 compressed DOS executable.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="imports",
            module="rebrew.imports",
            help="List import-table symbols (PE/ELF/NE) and detect import stubs.",
            panel=Panel.ANALYSIS,
            is_group=True,
        ),
        CliComponent(
            name="fingerprints",
            module="rebrew.fingerprints",
            help="Binary fingerprint bundle: hashes, imphash, rich-header hash, section entropy.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="pe",
            module="rebrew.pe_info",
            help="Dump PE metadata: identity, sections, security flags, debug, Rich header.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="crypto",
            module="rebrew.crypto_scan",
            help="Detect crypto constant tables, crypto imports, and crypto-named functions.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="strings",
            module="rebrew.strings",
            help="Extract printable strings from data sections with cross-references.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="xrefs",
            module="rebrew.xrefs",
            help="Cross-reference explorer: find code that references an address.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="function",
            module="rebrew.describe",
            help="Per-function recon dossier: callers, callees, strings, imports.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="analyze",
            module="rebrew.analyze",
            help="One-shot intelligence dossier: toolchain, strings, imports, dispatch, FLIRT.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="extract",
            module="rebrew.extract",
            help="Extract and disassemble functions from binary.",
            panel=Panel.MATCHING,
            is_group=True,
        ),
        CliComponent(
            name="resource",
            module="rebrew.resource",
            help="Compare / extract PE resource (.rsrc) sections.",
            panel=Panel.ANALYSIS,
            is_group=True,
        ),
    ),
    "library": (
        CliComponent(
            name="crt-match",
            module="rebrew.crt_match",
            help="CRT source cross-reference matcher.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="match",
            module="rebrew.lib_match",
            help="Byte-compare reversed functions against linked static libraries.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="scan-signatures",
            module="rebrew.flirt",
            help="FLIRT signature scanning.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="init-signatures",
            module="rebrew.flirt",
            attr="init_signatures",
            help="Copy shared signature files into the project without overwriting existing files.",
            panel=Panel.PROJECT_SETUP,
            epilog="Examples:\n\n  rebrew library init-signatures\n\n  rebrew library init-signatures --matched-only --json\n\nRequires the rebrew-flirt-sigs checkout; existing project files are retained.",
        ),
        CliComponent(
            name="identify",
            module="rebrew.identify_library",
            help="Identify library functions (FLIRT + imports + CRT) into library_*.h.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="signatures",
            module="rebrew.gen_flirt_pat",
            help="Generate FLIRT .pat files from COFF .lib and ELF .a archives.",
            panel=Panel.ANALYSIS,
        ),
    ),
    "coverage": (
        CliComponent(
            name="report",
            module="rebrew.report",
            help="Generate a static HTML documentation site for the project.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="build",
            module="rebrew.build_db",
            help="Build clear-text coverage documents from the project tree.",
            panel=Panel.EXPORT_SYNC,
        ),
        CliComponent(
            name="serve",
            module="rebrew.dashboard",
            help="Serve a read-only web dashboard over the coverage documents.",
            panel=Panel.EXPORT_SYNC,
        ),
        CliComponent(
            name="catalog",
            module="rebrew.catalog.cli",
            help="Build coverage catalog, data JSON, CSV/Ghidra exports, and DB.",
            panel=Panel.EXPORT_SYNC,
        ),
    ),
    "match": (
        CliComponent(
            name="solutions",
            module="rebrew.solutions_db",
            help="Query the GA solutions database (winning fingerprints + run history).",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="partitions",
            module="rebrew.merge_sweep",
            help="Deterministic TU-partition search over cu-map clusters.",
            panel=Panel.MATCHING,
        ),
        CliComponent(
            name="climb",
            module="rebrew.climb",
            help="Deterministic single-statement hill-climb for one function.",
            panel=Panel.DEVELOPMENT,
        ),
        CliComponent(
            name="qualifiers",
            module="rebrew.qual_sweep",
            help="Sweep declaration qualifiers over one function, keeping winners.",
            panel=Panel.DEVELOPMENT,
        ),
    ),
    "binsync": (
        CliComponent(
            name="export",
            module="rebrew.binsync.export",
            help="Export rebrew annotations to a BinSync state directory.",
            panel=Panel.EXPORT_SYNC,
        ),
        CliComponent(
            name="import",
            module="rebrew.binsync.importer",
            help="Import a BinSync state directory into rebrew metadata.",
            panel=Panel.EXPORT_SYNC,
        ),
    ),
    "similarity": (
        CliComponent(
            name="function",
            module="rebrew.similar",
            help="Find structurally similar functions in the target binary.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="binary",
            module="rebrew.binary_similarity",
            help="Whole-binary structural similarity vs another binary (versions/DLL+EXE).",
            panel=Panel.ANALYSIS,
        ),
    ),
    "dev": (
        CliComponent(
            name="refactor",
            module="rebrew.refactor",
            help="Analyse the source tree and suggest refactoring opportunities.",
            panel=Panel.ANALYSIS,
        ),
    ),
    "export": (
        CliComponent(
            name="symbols",
            module="rebrew.symbol_addrs",
            help="Export function symbols as a splat-style symbol_addrs.csv.",
            panel=Panel.EXPORT_SYNC,
        ),
        CliComponent(
            name="context",
            module="rebrew.context",
            help="Emit a universal C context file (types + signatures) for decompiler backends.",
            panel=Panel.ANALYSIS,
        ),
        CliComponent(
            name="objdiff",
            module="rebrew.objdiff_project",
            help="Generate an objdiff project (target objects + objdiff.json) for GUI diffing.",
            panel=Panel.EXPORT_SYNC,
        ),
        CliComponent(
            name="decompme",
            module="rebrew.decompme",
            help="Upload a function to decomp.me as a collaborative scratch (claim URL returned).",
            panel=Panel.EXPORT_SYNC,
        ),
    ),
}

_DOMAIN_SCOPES: dict[str, tuple[Context, CoeffectScope]] = {}

_DOMAIN_GUIDANCE = {
    "source": (
        "Organize, import, and inspect C sources.",
        "rebrew source rename 0x401000 UpdatePlayer --dry-run",
    ),
    "build": (
        "Generate build inputs and inspect linked artifacts.",
        "rebrew build cmake-toolchain --toolchain msvc-6.0 --output cmake/",
    ),
    "diagnose": (
        "Explain compiler configuration and locate byte mismatches.",
        "rebrew diagnose config src/game/f.c --json",
    ),
    "binary": (
        "Inspect binaries and extract functions or resources.",
        "rebrew binary pe original/game.exe --json",
    ),
    "coverage": (
        "Inspect the catalog, write coverage documents, and serve reports.",
        "rebrew coverage build",
    ),
    "similarity": (
        "Compare function structure within or between binaries.",
        "rebrew similarity function 0x401000 --limit 10 --json",
    ),
    "export": (
        "Generate exchange artifacts or upload a decomp.me scratch.",
        "rebrew export symbols --output symbols.csv",
    ),
    "dev": (
        "Inspect the Python repository for contributor maintenance.",
        "rebrew dev refactor --repository . --json",
    ),
}


def _domain_app(name: str, *, base: typer.Typer | None = None) -> typer.Typer:
    """Compose one declared domain through the ordinary component loader."""
    guidance = _DOMAIN_GUIDANCE.get(
        name, (f"{name.capitalize()} operations.", f"rebrew {name} --help")
    )
    app = (
        base
        if base is not None
        else typer.Typer(
            help=guidance[0],
            epilog=f"Examples:\n\n  {guidance[1]}\n\nUse rebrew {name} <operation> --help for inputs, output destinations, and preview options.",
        )
    )
    ctx = Context()
    ctx.provide(CLI_SERVICE, app)
    ctx.provide(CONSOLE_SERVICE, console)
    _DOMAIN_SCOPES[name] = (ctx, activate(DOMAIN_COMPONENTS[name], ctx))
    return app


source_app = _domain_app("source")
types_app = _domain_app("types", base=importlib.import_module("rebrew.types_cli").app)
build_app = _domain_app("build")
diagnose_app = _domain_app("diagnose")
binary_app = _domain_app("binary")
library_app = _domain_app("library", base=importlib.import_module("rebrew.library").app)
coverage_app = _domain_app("coverage")
match_app = _domain_app("match", base=importlib.import_module("rebrew.match").app)
binsync_app = _domain_app("binsync", base=importlib.import_module("rebrew.binsync.cli").app)
similarity_app = _domain_app("similarity")
dev_app = _domain_app("dev")
export_app = _domain_app("export")

BUILTIN_COMPONENTS: tuple[CliComponent, ...] = (
    CliComponent(
        name="test",
        module="rebrew.test",
        help="Compile, byte-compare, and auto-update STATUS annotation.",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="verify",
        module="rebrew.verify",
        help="Validate compiled bytes against target binary.",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="skeleton",
        module="rebrew.skeleton",
        help="Generate skeleton C files for matching.",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="sync",
        module="rebrew.ghidra.cli",
        help="Sync with Ghidra: BinSync state dir field sync + MCP structural ops.",
        panel=Panel.EXPORT_SYNC,
        is_group=True,
    ),
    CliComponent(
        name="lint", module="rebrew.lint", help="Lint C annotations.", panel=Panel.DEVELOPMENT
    ),
    CliComponent(
        name="decompile",
        module="rebrew.name_decomp",
        help="Decompile a function via kuna/r2ghidra/ghidra, optionally applying known struct names (--named).",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="diff",
        module="rebrew.diff",
        help="Compile and diff a reversed function against the target binary.",
        panel=Panel.MATCHING,
    ),
    CliComponent(
        name="init",
        module="rebrew.init",
        help="Initialize a new rebrew project.",
        panel=Panel.PROJECT_SETUP,
    ),
    CliComponent(
        name="intake",
        module="rebrew.intake",
        help="One-shot binary onboarding: init + toolchain detect + functions + document.",
        panel=Panel.PROJECT_SETUP,
    ),
    CliComponent(
        name="data",
        module="rebrew.data",
        help="Global data scanner for .data/.rdata/.bss sections.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="status",
        module="rebrew.status",
        help="At-a-glance reversing progress overview.",
        panel=Panel.ANALYSIS,
    ),
    CliComponent(
        name="todo",
        module="rebrew.todo",
        help="Prioritized action list: what to work on next.",
        panel=Panel.ANALYSIS,
    ),
    CliComponent(
        name="doctor",
        module="rebrew.doctor",
        help="Diagnostic checks for project health.",
        panel=Panel.PROJECT_SETUP,
    ),
    CliComponent(
        name="prove",
        module="rebrew.prove",
        help="Prove semantic equivalence via symbolic execution.",
        panel=Panel.MATCHING,
    ),
    CliComponent(
        name="recommend",
        module="rebrew.recommend",
        help="Deterministic project advice: TU layout, hygiene, next steps.",
        panel=Panel.ANALYSIS,
    ),
    CliComponent(
        name="blocker",
        module="rebrew.blocker",
        help="Manage BLOCKER metadata (set/clear/show) — programmatic only.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="orphans",
        module="rebrew.orphans",
        help="List or prune orphaned metadata blocks (no source marker).",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
    ),
    CliComponent(
        name="types",
        module="rebrew.builtins",
        help="Check declared struct layouts; apply types to signatures.",
        panel=Panel.ANALYSIS,
        is_group=True,
        attr="types_app",
    ),
    CliComponent(
        name="cfg",
        module="rebrew.cfg",
        help="Read and edit rebrew-project.toml programmatically.",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
    ),
    CliComponent(
        name="cache",
        module="rebrew.cache_cli",
        help="Manage the compile result cache.",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
    ),
    CliComponent(
        name="skills",
        module="rebrew.skills",
        help="Discover and display agent skills bundled with rebrew.",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
    ),
    CliComponent(
        name="library",
        module="rebrew.builtins",
        help="Per-library toolchain/flags overrides (rebrew-libraries.toml).",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
        attr="library_app",
    ),
    CliComponent(
        name="toolchain",
        module="rebrew.toolchain_cli",
        help="Manage toolchains (Windows/DOS profiles run in docker).",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
    ),
    CliComponent(
        name="binsync",
        module="rebrew.builtins",
        help="BinSync state sync: push/pull/summary plus init/diff/overlay.",
        panel=Panel.EXPORT_SYNC,
        is_group=True,
        attr="binsync_app",
    ),
    CliComponent(
        name="source",
        module="rebrew.builtins",
        attr="source_app",
        help="Source operations.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="build",
        module="rebrew.builtins",
        attr="build_app",
        help="Build operations.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="diagnose",
        module="rebrew.builtins",
        attr="diagnose_app",
        help="Diagnose operations.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="binary",
        module="rebrew.builtins",
        attr="binary_app",
        help="Binary operations.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="coverage",
        module="rebrew.builtins",
        attr="coverage_app",
        help="Coverage operations.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="match",
        module="rebrew.builtins",
        attr="match_app",
        help="Match operations.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="similarity",
        module="rebrew.builtins",
        attr="similarity_app",
        help="Similarity operations.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="dev",
        module="rebrew.builtins",
        attr="dev_app",
        help="Dev operations.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="export",
        module="rebrew.builtins",
        attr="export_app",
        help="Export operations.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
)
