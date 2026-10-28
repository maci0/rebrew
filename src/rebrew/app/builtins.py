"""Packaged CLI components and their static domain membership.

Domain apps use the same CliComponent activation as the umbrella. Each domain
holds its context and scope for the app lifetime; retiring the umbrella mount
removes the whole domain without changing another component's registrations.
"""

from __future__ import annotations

import importlib

lazy import typer

from rebrew.app.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    CoeffectScope,
    Context,
    Panel,
    activate,
)
lazy from rebrew.cli import console

DOMAIN_COMPONENTS: dict[str, tuple[CliComponent, ...]] = {
    "source": (
        CliComponent(
            name="consolidate",
            module="rebrew.source_consolidate",
            help="Fold source evidence into the format-3 function metadata store.",
            panel="",
        ),
        CliComponent(
            name="organize",
            module="rebrew.source_organize",
            is_group=True,
            help="Review target providers, TU contexts and native orders before reorganizing source.",
            panel="",
        ),
        CliComponent(
            name="units",
            module="rebrew.source_units",
            help="Inventory native source-path strings and bounded direct references.",
            panel="",
        ),
        CliComponent(
            name="findings",
            module="rebrew.findings",
            help="Find prior documented findings mentioning a native address or address range.",
            panel="",
        ),
        CliComponent(
            name="binding",
            module="rebrew.source_binding",
            is_group=True,
            help="Review and change source bindings while retaining native inventory and evidence.",
            panel="",
        ),
        CliComponent(
            name="register",
            module="rebrew.source_register",
            help="Register address-only source bindings, or a support file purpose, in metadata.",
            panel="",
        ),
        CliComponent(
            name="rename",
            module="rebrew.rename",
            help="Rename a function, global, type or struct member and update every reference.",
            panel="",
        ),
        CliComponent(
            name="fix",
            module="rebrew.fixup",
            help="Make raw decompiler output compilable (DecBench-style fixup).",
            panel="",
        ),
        CliComponent(
            name="inline-strings",
            module="rebrew.inline_strings",
            help="Inline string-literal globals (s_<hint>_<ADDR>) from the reference binary.",
            panel="",
        ),
        CliComponent(
            name="document-unmatched",
            module="rebrew.document_unmatched",
            help="Document unmatched functions as STUB skeletons + blockers.",
            panel="",
        ),
        CliComponent(
            name="graph",
            module="rebrew.depgraph",
            help="Generate function dependency graph from reversed .c files.",
            panel="",
        ),
        CliComponent(
            name="security",
            module="rebrew.security_scan",
            help="Scan C sources for unsafe API use (unbounded copies, format strings, command execution).",
            panel="",
        ),
        CliComponent(
            name="split",
            module="rebrew.split",
            help="Split multi-function C files into single-function files.",
            panel="",
        ),
        CliComponent(
            name="merge",
            module="rebrew.merge",
            help="Merge single-function C files into one multi-function file.",
            panel="",
        ),
        CliComponent(
            name="import-related",
            module="rebrew.cross_import",
            help="Import matched functions from another target (same code, different VAs).",
            panel="",
        ),
        CliComponent(
            name="import-splat",
            module="rebrew.splat_config",
            help="Seed a Rebrew project from splat YAML: names, layout, and metadata.",
            panel="",
        ),
        CliComponent(
            name="rehome",
            module="rebrew.rehome",
            help="Point function and data rows at the source file that now defines them.",
            panel="",
        ),
        CliComponent(
            name="symbolize",
            module="rebrew.symbolize",
            help="Rewrite raw (T *) 0xVA casts to the data symbols the reference relocates.",
            panel="",
        ),
        CliComponent(
            name="document-assembly",
            module="rebrew.document_assembly",
            help="Record target-scoped original assembly evidence for a named C definition.",
            panel="",
        ),
        CliComponent(
            name="clear-cflags",
            module="rebrew.source_cflags",
            help="Clear a saved per-function compiler flag override.",
            panel="",
        ),
    ),
    "types": (
        CliComponent(
            name="recover",
            module="rebrew.struct_recover",
            help="Recover struct definitions from decompiler output.",
            panel="",
        ),
    ),
    "build": (
        CliComponent(
            name="anchors",
            module="rebrew.link_anchors",
            help="Generate VA-ordered native function anchors and explicitly selected data anchors.",
            panel="",
        ),
        CliComponent(
            name="delphi",
            module="rebrew.delphi_build",
            help="Compile a complete Delphi 1.0 Pascal program through its Docker image.",
            panel="",
        ),
        CliComponent(
            name="postlink",
            module="rebrew.postlink",
            help="Normalize a built binary's layout onto a reference (post-link fixes).",
            panel="",
        ),
        CliComponent(
            name="layout",
            module="rebrew.gen_layout",
            help="Generate linker-script scaffolding (def, layout manifest, IAT seed, data restore).",
            panel="",
        ),
        CliComponent(
            name="cmake-toolchain",
            module="rebrew.cmake_tc",
            help="Write a CMake toolchain file that drives a docker toolchain via rebrew.",
            panel="",
        ),
        CliComponent(
            name="driver",
            module="rebrew.cmake_tc",
            attr="driver_main",
            help="Run a CMake tool: rebrew build driver <cl|link|lib> -- <arguments>.",
            panel="",
            epilog=(
                "[bold]Examples:[/bold]\n\n"
                "  rebrew build driver cl -- /c src/f.c /Fooutput/f.obj\n\n"
                "Arguments after -- go unchanged to the selected build tool."
            ),
        ),
        CliComponent(
            name="objdiff-driver",
            module="rebrew.objdiff_project",
            attr="build_main",
            help="Rebuild an objdiff base object using its source's toolchain and flags.",
            panel="",
            epilog=(
                "[bold]Examples:[/bold]\n\n"
                "  rebrew build objdiff-driver server src/SERVER/f.obj\n\n"
                "Invoked by generated objdiff configuration; rebuilds the base object."
            ),
        ),
        CliComponent(
            name="cmake-flags",
            module="rebrew.cmake_flags",
            help="Emit the per-file CFLAGS a CMake build must compile with.",
            panel="",
        ),
        CliComponent(
            name="cmake-sources",
            module="rebrew.cmake_sources",
            help="Emit the per-target source list a CMake build must compile.",
            panel="",
        ),
        CliComponent(
            name="check",
            module="rebrew.build_check",
            help="Check that build/ still holds what CMake generated (hand-edit drift).",
            panel="",
        ),
        CliComponent(
            name="order-sources",
            module="rebrew.order_sources",
            help="Order source files by their first function's original VA (position-aligned .text).",
            panel="",
        ),
        CliComponent(
            name="calibrate-bss",
            module="rebrew.calibrate_bss",
            help="Calibrate a BSS tail pad so the raw link's .data VirtualSize matches the reference.",
            panel="",
        ),
        CliComponent(
            name="link-stubs",
            module="rebrew.gen_link_stubs",
            help="Generate a link_stubs.c-style BSS placeholder TU from the data metadata.",
            panel="",
        ),
        CliComponent(
            name="symbol-stubs",
            module="rebrew.gen_stubs",
            help="Generate a stub TU for unresolved linker symbols (LNK2001/LNK2019).",
            panel="",
        ),
        CliComponent(
            name="check-data-placement",
            module="rebrew.verify_placement",
            help="Compare .data symbol VAs of the current build against the data metadata.",
            panel="",
        ),
        CliComponent(
            name="check-text-placement",
            module="rebrew.text_audit",
            help="Compare .text function VAs of the current build against metadata addresses.",
            panel="",
        ),
        CliComponent(
            name="sweep-link-flags",
            module="rebrew.link_sweep",
            help="Sweep LINK options to reproduce the reference PE header.",
            panel="",
        ),
        CliComponent(
            name="link-order",
            module="rebrew.link_order",
            help="Enforce VA-ordered sources into CMakeLists.txt SOURCES (drift gate).",
            panel="",
        ),
        CliComponent(
            name="check-exports",
            module="rebrew.verify_exports",
            help="Verify the recompiled binary's export table matches the original target.",
            panel="",
        ),
        CliComponent(
            name="round-trip",
            module="rebrew.round_trip",
            help="Splice every matched function back into the target PE and verify byte equality.",
            panel="",
        ),
        CliComponent(
            name="residue",
            module="rebrew.residue",
            help="Measure linked byte-identity residue after postlink fixers.",
            panel="",
        ),
        CliComponent(
            name="layout-map",
            module="rebrew.layout_map",
            help="Dump reference-side layout measurements (sections, gaps, IAT, exports).",
            panel="",
        ),
        CliComponent(
            name="check-tu-data",
            module="rebrew.tu_data_check",
            help="Flag linked objects whose .data/.rdata breaks the MSVC6 one-TU shape.",
            panel="",
        ),
    ),
    "diagnose": (
        CliComponent(
            name="stack",
            module="rebrew.stack_cmp",
            help="Compare the stack frame of a compiled function against the target binary.",
            panel="",
        ),
        CliComponent(
            name="drift",
            module="rebrew.drift_cli",
            help="Localize where compiled bytes drift from the reference, from branch targets.",
            panel="",
        ),
        CliComponent(
            name="config",
            module="rebrew.diagnose",
            help="Explain why a function compiles with its toolchain+flags (resolution trace).",
            panel="",
        ),
        CliComponent(
            name="probe",
            module="rebrew.probe",
            help="Measure one function against the reference without writing metadata.",
            panel="",
        ),
        CliComponent(
            name="near",
            module="rebrew.near_diag",
            help="Classify why a NEAR_MATCHING function does not byte-match.",
            panel="",
        ),
        CliComponent(
            name="gap",
            module="rebrew.gap_trace",
            help="Trace length-gap drift between object and reference instruction streams.",
            panel="",
        ),
    ),
    "binary": (
        CliComponent(
            name="ne-compare",
            module="rebrew.ne_compare",
            help="Compare NE file/segment bytes and report separate content overlap.",
            panel="",
        ),
        CliComponent(
            name="forms",
            module="rebrew.forms",
            help="Decode Delphi 1 form streams and verify lossless re-encoding.",
            panel="",
        ),
        CliComponent(
            name="asm",
            module="rebrew.asm",
            help="Inspect function assembly and export single or batch reconstruction artifacts.",
            panel="",
            is_group=True,
        ),
        CliComponent(
            name="switches",
            module="rebrew.switch",
            help="Decode jump-table switch dispatches in a function (case → handler map).",
            panel="",
        ),
        CliComponent(
            name="pdb",
            module="rebrew.pdb_info",
            help="Extract compiler version, flags, and function names from a PDB.",
            panel="",
            is_group=True,
        ),
        CliComponent(
            name="repair-extents",
            module="rebrew.inventory_repair",
            help="Repair native inventory extents or explicitly admit reviewed missing entries.",
            panel="",
        ),
        CliComponent(
            name="functions",
            module="rebrew.discover",
            help="Enumerate functions: rizin aaa/aap + capstone sweep, sizes validated.",
            panel="",
        ),
        CliComponent(
            name="unpack-lzexe",
            module="rebrew.lzexe_cli",
            help="Unpack an LZEXE 0.90/0.91 compressed DOS executable.",
            panel="",
        ),
        CliComponent(
            name="imports",
            module="rebrew.imports",
            help="List import-table symbols (PE IAT, ELF dynamic imports, or 16-bit NE modules) and detect import stubs.",
            panel="",
            is_group=True,
        ),
        CliComponent(
            name="fingerprints",
            module="rebrew.fingerprints",
            help="Fingerprint a binary: file hashes, imphash, export hash, Rich-header hash, section entropy.",
            panel="",
        ),
        CliComponent(
            name="pe",
            module="rebrew.pe_info",
            help="Dump PE metadata: identity, sections, security flags, loader directories, version info, debug, Rich header.",
            panel="",
        ),
        CliComponent(
            name="crypto",
            module="rebrew.crypto_scan",
            help="Detect crypto in a binary: constant tables, crypto imports, and function names.",
            panel="",
        ),
        CliComponent(
            name="strings",
            module="rebrew.strings",
            help="Extract strings from a binary, optionally with cross-references.",
            panel="",
        ),
        CliComponent(
            name="xrefs",
            module="rebrew.xrefs",
            help="Show cross-references to a target address.",
            panel="",
        ),
        CliComponent(
            name="function",
            module="rebrew.describe",
            help="Per-function recon dossier: callers, callees, strings, globals, imports.",
            panel="",
        ),
        CliComponent(
            name="analyze",
            module="rebrew.analyze",
            help="One-shot intelligence dossier for a target binary.",
            panel="",
        ),
        CliComponent(
            name="extract",
            module="rebrew.extract",
            help="Extract and disassemble functions from the target binary.",
            panel="",
            is_group=True,
        ),
        CliComponent(
            name="resource",
            module="rebrew.resource",
            help="Compare / extract PE resource (.rsrc) sections.",
            panel="",
            is_group=True,
        ),
        CliComponent(
            name="relocs",
            module="rebrew.reloc_diff",
            help="Compare PE base relocation sites of the reference and a built image.",
            panel="",
        ),
    ),
    "library": (
        CliComponent(
            name="crt-match",
            module="rebrew.crt_match",
            help="CRT source cross-reference matcher.",
            panel="",
        ),
        CliComponent(
            name="presence",
            module="rebrew.lib_presence",
            help="Locate one COFF object's function bodies in the reference binary and report present/absent per symbol.",
            panel="",
        ),
        CliComponent(
            name="match",
            module="rebrew.lib_match",
            help="Byte-compare reversed functions against linked static libraries (.lib/.a). Flags code the linker supplies, so it is not worth reversing.",
            panel="",
        ),
        CliComponent(
            name="scan-signatures",
            module="rebrew.flirt",
            help="FLIRT signature scanner for binaries.",
            panel="",
        ),
        CliComponent(
            name="init-signatures",
            module="rebrew.flirt",
            attr="init_signatures",
            help="Copy the shared signatures into flirt_sigs/; keep existing project files.",
            panel="",
            epilog=(
                "[bold]Examples:[/bold]\n\n"
                "  rebrew library init-signatures\n\n"
                "  rebrew library init-signatures --matched-only --json\n\n"
                "Requires the recondb checkout; existing project files are retained."
            ),
        ),
        CliComponent(
            name="identify",
            module="rebrew.identify_library",
            help="Identify library functions (FLIRT + imports + CRT) into library_*.h.",
            panel="",
        ),
        CliComponent(
            name="signatures",
            module="rebrew.gen_flirt_pat",
            help="Generate FLIRT .pat files from COFF .lib and ELF .a archives.",
            panel="",
        ),
        CliComponent(
            name="inspect",
            module="rebrew.lib_inspect",
            help="List COFF archive members: sections (size, alignment, COMDAT), defined, COMMON, and undefined symbols, and short import members.",
            panel="",
        ),
        CliComponent(
            name="vendor",
            module="rebrew.vendor",
            help="Check or regenerate vendored sources from pristine files plus ordered patches.",
            panel="",
        ),
    ),
    "coverage": (
        CliComponent(
            name="import-history",
            module="rebrew.coverage_history",
            help="Import status history from portable snapshots without changing verdicts.",
            panel="",
        ),
        CliComponent(
            name="report",
            module="rebrew.report",
            help="Generate a static HTML documentation site for a decomp project.",
            panel="",
        ),
        CliComponent(
            name="export",
            module="rebrew.build_db",
            help="Export portable coverage snapshots for offline viewing.",
            panel="",
        ),
        CliComponent(
            name="serve",
            module="rebrew.dashboard",
            help="Serve a read-only dashboard from live project metadata or portable snapshots.",
            panel="",
        ),
        CliComponent(
            name="catalog",
            module="rebrew.catalog.cli",
            help="Validate source bindings and summarize function catalog and coverage data.",
            panel="",
        ),
    ),
    "match": (
        CliComponent(
            name="solutions",
            module="rebrew.solutions_db",
            help="Query the GA solutions database (winning fingerprints + run history).",
            panel="",
        ),
        CliComponent(
            name="partitions",
            module="rebrew.merge_sweep",
            help="Deterministic TU-partition search over cu-map clusters.",
            panel="",
        ),
        CliComponent(
            name="climb",
            module="rebrew.climb",
            help="Deterministic single-statement hill-climb for one function.",
            panel="",
        ),
        CliComponent(
            name="qualifiers",
            module="rebrew.qual_sweep",
            help="Sweep declaration qualifiers over one function, keeping winners.",
            panel="",
        ),
    ),
    "binsync": (
        CliComponent(
            name="export",
            module="rebrew.binsync.export",
            help="Export Rebrew symbols and types to a BinSync state directory.",
            panel="",
        ),
        CliComponent(
            name="import",
            module="rebrew.binsync.importer",
            help="Import a BinSync state directory into rebrew metadata.",
            panel="",
        ),
    ),
    "similarity": (
        CliComponent(
            name="function",
            module="rebrew.similar",
            help="Find structurally similar functions in the target binary.",
            panel="",
        ),
        CliComponent(
            name="binary",
            module="rebrew.binary_similarity",
            help="Whole-binary structural similarity between the target and another binary.",
            panel="",
        ),
    ),
    "dev": (
        CliComponent(
            name="refactor",
            module="rebrew.refactor",
            help="Analyze the rebrew source tree and suggest refactoring opportunities.",
            panel="",
        ),
    ),
    "export": (
        CliComponent(
            name="symbols",
            module="rebrew.symbol_addrs",
            help="Export metadata symbols as a splat-style symbol_addrs file.",
            panel="",
        ),
        CliComponent(
            name="pdb",
            module="rebrew.pdb_export",
            help="Write a synthetic PDB for the target binary from rebrew's symbols.",
            panel="",
        ),
        CliComponent(
            name="context",
            module="rebrew.context",
            help="Emit a universal C context file (types + signatures) for decompiler backends.",
            panel="",
        ),
        CliComponent(
            name="objdiff",
            module="rebrew.objdiff_project",
            help="Generate an objdiff project (target objects + objdiff.json) for GUI diffing.",
            panel="",
        ),
        CliComponent(
            name="decompme",
            module="rebrew.decompme",
            help="Upload a function to decomp.me as a collaborative scratch.",
            panel="",
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
        "View live project coverage, export portable snapshots, and serve reports.",
        "rebrew coverage serve",
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
            rich_markup_mode="rich",
            epilog=f"[bold]Examples:[/bold]\n\n  {guidance[1]}\n\nUse rebrew {name} <operation> --help for inputs and examples.",
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
        help="Compile-and-compare for reversed functions (auto-updates STATUS by default).",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="verify",
        module="rebrew.verify",
        help="Rebrew verification pipeline: compile each .c and verify bytes match.",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="skeleton",
        module="rebrew.skeleton",
        help="Generate .c skeleton files for uncovered functions in the target binary.",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="sync",
        module="rebrew.ghidra.cli",
        help="Exchange metadata with Ghidra through BinSync and perform structural operations.",
        panel=Panel.EXPORT_SYNC,
        is_group=True,
    ),
    CliComponent(
        name="lint",
        module="rebrew.lint",
        help="Check C source bindings, metadata, and project conventions.",
        panel=Panel.DEVELOPMENT,
    ),
    CliComponent(
        name="decompile",
        module="rebrew.name_decomp",
        help="Decompile a function, optionally applying known struct names.",
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
        help="Initialize a new rebrew project directory.",
        panel=Panel.PROJECT_SETUP,
    ),
    CliComponent(
        name="intake",
        module="rebrew.intake",
        help="One-shot binary onboarding: init + detect + functions + document.",
        panel=Panel.PROJECT_SETUP,
    ),
    CliComponent(
        name="data",
        module="rebrew.data",
        help="Inspect global data, edit metadata, and generate declarations and layout repairs.",
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
        help="Prioritized actions by overall impact, then estimated effort.",
        panel=Panel.ANALYSIS,
    ),
    CliComponent(
        name="doctor",
        module="rebrew.doctor",
        help="Diagnostic checks for rebrew project health.",
        panel=Panel.PROJECT_SETUP,
    ),
    CliComponent(
        name="schema",
        module="rebrew.schema_cmd",
        help="Print the clispec 0.3 JSON document for this CLI.",
        panel=Panel.PROJECT_SETUP,
    ),
    CliComponent(
        name="prove",
        module="rebrew.prove",
        help="Prove semantic equivalence of NEAR_MATCHING/SIZE_MISMATCH functions via symbolic execution.",
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
        help="Record, inspect, and clear function blockers in dedicated metadata.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="orphans",
        module="rebrew.orphans",
        help="List or prune metadata rows without a live source binding.",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
    ),
    CliComponent(
        name="types",
        module="rebrew.app.builtins",
        help="Manage types, audit contracts, reconcile headers, and check layouts.",
        panel=Panel.ANALYSIS,
        is_group=True,
        attr="types_app",
    ),
    CliComponent(
        name="metadata",
        module="rebrew.metadata_cli",
        help="Manage metadata storage and preview backend transfers.",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
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
        help="Manage the compile result cache (.rebrew/compile_cache/).",
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
        module="rebrew.app.builtins",
        help="Identify libraries, compare code, and manage source providers and compiler settings.",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
        attr="library_app",
    ),
    CliComponent(
        name="toolchain",
        module="rebrew.toolchain_cli",
        help="Manage compiler profiles and Docker images for shipped toolchains.",
        panel=Panel.PROJECT_SETUP,
        is_group=True,
    ),
    CliComponent(
        name="binsync",
        module="rebrew.app.builtins",
        help="Synchronize Git-backed state or exchange raw BinSync artifacts.",
        panel=Panel.EXPORT_SYNC,
        is_group=True,
        attr="binsync_app",
    ),
    CliComponent(
        name="source",
        module="rebrew.app.builtins",
        attr="source_app",
        help="Organize, import, and inspect C sources.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="build",
        module="rebrew.app.builtins",
        attr="build_app",
        help="Generate build inputs and inspect linked artifacts.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="diagnose",
        module="rebrew.app.builtins",
        attr="diagnose_app",
        help="Explain compiler configuration and locate byte mismatches.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="binary",
        module="rebrew.app.builtins",
        attr="binary_app",
        help="Inspect binaries and extract functions or resources.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="coverage",
        module="rebrew.app.builtins",
        attr="coverage_app",
        help="View live project coverage, export portable snapshots, and serve reports.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="match",
        module="rebrew.app.builtins",
        attr="match_app",
        help="Search source mutations, compiler flags, and toolchains for byte matches.",
        panel=Panel.MATCHING,
        is_group=True,
    ),
    CliComponent(
        name="similarity",
        module="rebrew.app.builtins",
        attr="similarity_app",
        help="Compare function structure within or between binaries.",
        panel=Panel.ANALYSIS,
        is_group=True,
    ),
    CliComponent(
        name="dev",
        module="rebrew.app.builtins",
        attr="dev_app",
        help="Inspect the Python repository for contributor maintenance.",
        panel=Panel.DEVELOPMENT,
        is_group=True,
    ),
    CliComponent(
        name="export",
        module="rebrew.app.builtins",
        attr="export_app",
        help="Generate exchange artifacts or upload a decomp.me scratch.",
        panel=Panel.EXPORT_SYNC,
        is_group=True,
    ),
)
