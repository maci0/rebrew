"""check_layering.py — enforce the import-direction rules ``detect_cycles.py`` cannot see.

``detect_cycles.py`` answers "does the import graph fold back on itself?".
It says nothing about direction, so a module can stay cycle-free and still
reach the wrong way across the package.  Four rules are enforced here, all of
which the tree satisfies today:

**Leaf helpers stay leaves.**  Any module may import ``rebrew.utils``. Its
only allowed Rebrew dependency is ``rebrew.errors``.

**The composition layer is a sink.**  ``app.plugin``, ``app.builtins``,
``app.main`` and ``dashboard`` build the Typer app and know every command; nothing they import
depends on them back.  A module that imports one at *module scope* joins the
app's dependency graph and makes a leaf into a peer of the app, so only the
layer itself may do it; a PEP 810 `lazy` import defers the load but not that
edge. A ``TYPE_CHECKING`` re-export such as ``errors``' ``ComponentError``
is allowed because it loads nothing at runtime.

**A subpackage reaches outward only through its declared externals.**  Every
``src/rebrew/<package>/AGENTS.md`` states the externals that package may
import, and that line is what keeps ``matcher/`` from becoming a peer of the
CLI it drives.  Nothing read the line, so it drifted silently while the other
two rules kept passing.  The list below is transcribed from those nine files;
``tests/test_check_layering.py`` fails when a name in the tool is no longer
documented, so the two cannot diverge quietly.  Unlike the other rules this
one reads *every* import, not just the module-scope ones: the catalog's
deliberate deferred ``binary_loader`` import is still an edge.  A
``__getattr__`` loader that names its target as a string is not seen; the
packages that have one list their own submodule in the entry below.

**A library does not import a command.**  A module that builds a Typer app or
defines ``main_entry`` is a command, and a module that does neither is a
library.  A library reaching into a command inherits that command's console
surface, so the logic the two share belongs in a module the command imports
rather than the other way round: ``coverage_toml`` reads the normalizers from
``coverage_db`` and never from ``build_db``, which is now only the command.  A
command is detected from the tree (a ``main_entry`` or an ``app = typer.Typer``
assignment). This rule reads every import that runs, function bodies
included, and skips ``if TYPE_CHECKING:`` blocks: ``errors`` re-exports the
command modules' exception types for a type checker, which loads nothing.
``DEFERRED_LIBRARY_COMMAND_EDGES`` is the ratchet for this rule: it is empty
because the analysis ``match_ga`` and ``match_run`` need now lives in
``rebrew.compare.near_analysis``, a library the command also imports.  Adding an entry
back is a regression, not an exemption.

Run from the repo root::

    python tools/check_layering.py

Also importable for tests::

    from tools.check_layering import check_layering
    assert check_layering("src/rebrew") == []
"""

from dataclasses import dataclass
from typing import override
lazy import ast
lazy import os
lazy from collections.abc import Iterator
lazy from pathlib import Path

#: Modules that assemble the Typer app.  Nothing outside this set may import
#: them at module scope.
COMPOSITION_LAYER = frozenset(
    {"rebrew.app.plugin", "rebrew.app.builtins", "rebrew.app.main", "rebrew.coverage.dashboard"}
)

#: Modules allowed to import no other rebrew module beyond the error
#: hierarchy: ``rebrew.errors`` defines ``RebrewError`` and its subclasses
#: without importing anything from the package, so it sits below every leaf.
LEAF_MODULES = frozenset({"rebrew.utils"})
LEAF_ALLOWED_IMPORTS = frozenset({"rebrew.errors"})

#: What each subpackage may import outside itself, transcribed from the
#: "Externals" line of its ``AGENTS.md``.  Names are relative to ``rebrew``
#: and dotted: ``workspace`` covers ``workspace.status``, and
#: ``binsync.export`` names the one module of ``binsync/`` that ``ghidra/``
#: may read.  A package's own submodules are always allowed and are not
#: listed.
PACKAGE_EXTERNALS: dict[str, frozenset[str]] = {
    "app": frozenset(
        {
            "cli",
            "errors",
            "registry",
            "telemetry",
            "utils",
        }
    ),
    "binary": frozenset(
        {
            "buildsys.layout_meta",
            "c_syntax.float_const",
            "c_syntax.parser",
            "c_syntax.vtordisp",
            "catalog",
            "catalog.inventory",
            "cli",
            "compare.similar",
            "compiler.cache",
            "compiler.toolchain",
            "compiler.xtensa",
            "config",
            "data.layout",
            "data.ownership",
            "data.scan",
            "errors",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.dfm",
            "formats.import_table",
            "formats.lzexe",
            "formats.ne_analysis",
            "formats.ne_loader",
            "formats.pdb",
            "formats.pe_headers",
            "formats.pe_symbols",
            "init_profiles",
            "library.flirt",
            "library.identify",
            "metadata.anchors",
            "metadata.binding_history",
            "metadata.bindings",
            "metadata.data",
            "metadata.functions",
            "metadata.storage",
            "naming",
            "registry",
            "source.discovery",
            "source.rename_ops",
            "status_style",
            "symbol_addrs",
            "toolchain_detect",
            "utils",
        }
    ),
    "binsync": frozenset(
        {
            "c_syntax.parser",
            "c_syntax.struct_parser",
            "c_syntax.types",
            "catalog",
            "cli",
            "config",
            "cross_import",
            "data.scan",
            "formats.binary_loader",
            "metadata.bindings",
            "metadata.data",
            "metadata.document",
            "metadata.functions",
            "metadata.storage",
            "naming",
            "source.discovery",
            "source.rename_ops",
            "utils",
            "verify.hash",
            "workspace.names",
        }
    ),
    "buildsys": frozenset(
        {
            "binary.gate",
            "c_syntax.parser",
            "catalog.loaders",
            "catalog.registry",
            "cli",
            "compiler",
            "compiler.cache",
            "compiler.compile",
            "compiler.delphi16",
            "compiler.overrides",
            "compiler.temp_dirs",
            "compiler.toolchain",
            "compiler.unshare",
            "config",
            "cu_map",
            "errors",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.pe_headers",
            "formats.pe_image",
            "library.identify",
            "lint_cflags",
            "metadata.anchors",
            "metadata.bindings",
            "metadata.coordinated",
            "metadata.data",
            "metadata.functions",
            "metadata.locking",
            "metadata.storage",
            "naming",
            "skeleton",
            "source.c_rename",
            "source.discovery",
            "source.selection",
            "symbol_addrs",
            "toolchain_detect",
            "utils",
            "verify.cache",
            "verify.hash",
            "workspace",
        }
    ),
    "c_syntax": frozenset(
        {
            "binary.analysis",
            "cli",
            "compiler.compile",
            "compiler.overrides",
            "compiler.temp_dirs",
            "config",
            "data.ownership",
            "decompiler",
            "errors",
            "formats.binary_loader",
            "formats.relocations",
            "metadata.bindings",
            "metadata.coordinated",
            "metadata.data",
            "metadata.functions",
            "metadata.storage",
            "source.contracts",
            "source.discovery",
            "source.rename_ops",
            "utils",
            "verify.hash",
            "workspace.config",
        }
    ),
    "catalog": frozenset(
        {
            "binary.sections",
            "cli",
            "config",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.import_table",
            "function_providers",
            "metadata.bindings",
            "metadata.data",
            "metadata.document",
            "metadata.functions",
            "present",
            "source.discovery",
            "status",
            "utils",
            "verify.hash",
            "workspace",
        }
    ),
    "compare": frozenset(
        {
            "binary.analysis",
            "binary.asm",
            "binary.cfg_ged",
            "binary.similarity",
            "catalog",
            "cli",
            "compiler.compile",
            "compiler.overrides",
            "compiler.temp_dirs",
            "config",
            "data.ownership",
            "data.scan",
            "errors",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.relocations",
            "formats.xtensa",
            "function_providers",
            "matcher",
            "matcher.parsers",
            "matcher.scoring",
            "matching.semantics",
            "matching.sweep",
            "metadata.bindings",
            "metadata.data",
            "metadata.functions",
            "metadata.native_identity",
            "source.discovery",
            "source.rename_ops",
            "utils",
            "workspace.status",
        }
    ),
    "compiler": frozenset(
        {
            "compare.coff_reloc",
            "config",
            "errors",
            "flag_data",
            "flags",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.ne_loader",
            "formats.xtensa",
            "matcher.parsers",
            "metadata.functions",
            "registry",
            "source.discovery",
            "telemetry",
            "utils",
            "workspace",
        }
    ),
    "config": frozenset(
        {
            "buildsys.layout_meta",
            "compiler.cache",
            "compiler.toolchain",
            "compiler.toolchain_paths",
            "compiler.toolchain_spec",
            "errors",
            "formats.binary_loader",
            "formats.pe_headers",
            "metadata.storage",
            "registry",
            "utils",
            "workspace",
        }
    ),
    "coverage": frozenset(
        {
            "binary.analysis",
            "binary.sections",
            "catalog.loaders",
            "catalog.pipeline",
            "cli",
            "compression",
            "config",
            "data.ownership",
            "data.scan",
            "depgraph",
            "errors",
            "formats.binary_loader",
            "formats.import_table",
            "formats.ne_loader",
            "metadata.bindings",
            "metadata.data",
            "metadata.functions",
            "metadata.storage",
            "source.discovery",
            "source.rename_ops",
            "status",
            "status_style",
            "telemetry",
            "theme",
            "utils",
            "verify.cache",
            "verify.hash",
            "workspace",
        }
    ),
    "cross_import": frozenset(
        {
            "binary.analysis",
            "c_syntax.parser",
            "catalog",
            "catalog.loaders",
            "cli",
            "compare.coff_reloc",
            "compare.similar",
            "compiler.cache",
            "compiler.compile",
            "compiler.overrides",
            "config",
            "formats.binary_loader",
            "formats.relocations",
            "matcher.scoring",
            "metadata.anchors",
            "metadata.binding_history",
            "metadata.bindings",
            "metadata.coordinated",
            "metadata.data",
            "metadata.functions",
            "source.discovery",
            "source.layout",
            "source.split",
            "utils",
            "verify.cli",
            "workspace.status",
        }
    ),
    "data": frozenset(
        {
            "binary.sections",
            "buildsys.layout_meta",
            "c_syntax.cast_rewrite",
            "c_syntax.parser",
            "catalog",
            "cli",
            "config",
            "errors",
            "formats.archives",
            "formats.binary_loader",
            "formats.coff",
            "formats.ne_loader",
            "formats.pe_headers",
            "metadata.anchors",
            "metadata.binding_history",
            "metadata.bindings",
            "metadata.coordinated",
            "metadata.data",
            "metadata.functions",
            "metadata.storage",
            "object_evidence",
            "present",
            "source.discovery",
            "source.rename_ops",
            "status_style",
            "utils",
            "workspace",
        }
    ),
    "doctor": frozenset(
        {
            "binsync.git",
            "binsync.serial",
            "catalog",
            "cli",
            "compiler.cache",
            "compiler.compile",
            "compiler.toolchain",
            "config",
            "decompiler",
            "errors",
            "formats.binary_loader",
            "ghidra",
            "library.flirt",
            "library.match",
            "matching.prove",
            "metadata.bindings",
            "metadata.sqlite",
            "metadata.storage",
            "source.discovery",
            "toolchain_cli",
            "toolchain_detect",
            "utils",
            "wibo",
        }
    ),
    "formats": frozenset(
        {
            "errors",
            "registry",
            "utils",
        }
    ),
    "ghidra": frozenset(
        {
            "binsync.export",
            "binsync.importer",
            "binsync.serial",
            "binsync.state",
            "catalog",
            "cli",
            "config",
            "errors",
            "formats.binary_loader",
            "status_style",
            "utils",
        }
    ),
    "library": frozenset(
        {
            "binary.analysis",
            "c_syntax.parser",
            "catalog",
            "catalog.loaders",
            "cli",
            "compiler.toolchain",
            "compiler.toolchain_paths",
            "config",
            "data.layout",
            "errors",
            "formats.archives",
            "formats.binary_loader",
            "formats.coff",
            "formats.import_table",
            "metadata.binding_history",
            "metadata.bindings",
            "metadata.functions",
            "metadata.storage",
            "naming",
            "native_review",
            "source.binding",
            "source.discovery",
            "source.rename_ops",
            "toolchain_detect",
            "utils",
            "workspace.config",
        }
    ),
    "lint": frozenset(
        {
            "c_syntax.parser",
            "c_syntax.type_metadata",
            "catalog",
            "cli",
            "config",
            "data.layout",
            "formats.binary_loader",
            "init",
            "lint_cflags",
            "metadata.anchors",
            "metadata.binding_history",
            "metadata.bindings",
            "metadata.data",
            "metadata.document",
            "metadata.functions",
            "metadata.source_provenance",
            "metadata.source_schema",
            "metadata.storage",
            "source.discovery",
            "source.rename_ops",
            "utils",
            "workspace.config",
            "workspace.names",
            "workspace.status",
        }
    ),
    "matcher": frozenset(
        {
            "compare.coff_reloc",
            "compiler.cache",
            "compiler.compile",
            "compiler.temp_dirs",
            "compiler.toolchain",
            "compiler.toolchain_spec",
            "config",
            "errors",
            "flag_data",
            "flags",
            "formats.binary_loader",
            "formats.omf16",
            "formats.xtensa",
            "metadata.sqlite",
            "registry",
            "utils",
        }
    ),
    "matching": frozenset(
        {
            "binary.analysis",
            "binary.sections",
            "c_syntax.parser",
            "call_progress",
            "catalog",
            "cli",
            "compare.alignment",
            "compare.coff_reloc",
            "compare.near_analysis",
            "compiler",
            "compiler.cache",
            "compiler.compile",
            "compiler.overrides",
            "compiler.temp_dirs",
            "compiler.toolchain",
            "config",
            "decompiler",
            "errors",
            "flag_data",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.import_table",
            "formats.pe_headers",
            "limits",
            "matcher",
            "matcher.core",
            "matcher.mutator",
            "matcher.parsers",
            "matcher.scoring",
            "metadata.bindings",
            "metadata.data",
            "metadata.functions",
            "metadata.storage",
            "present",
            "source.c_rename",
            "source.discovery",
            "source.rename_ops",
            "status_style",
            "utils",
            "verify.cache",
            "verify.hash",
            "workspace.config",
            "workspace.status",
        }
    ),
    "metadata": frozenset(
        {
            "c_syntax.parser",
            "compiler.toolchain",
            "config",
            "errors",
            "registry",
            "source.rename_ops",
            "utils",
            "workspace",
        }
    ),
    "ops": frozenset(
        {
            "binary.analysis",
            "binary.analyze",
            "binary.asm",
            "binary.cfg_ged",
            "binary.crypto_scan",
            "binary.describe",
            "binary.discover",
            "binary.fingerprints",
            "binary.imports",
            "binary.pe_info",
            "binary.strings",
            "binary.xrefs",
            "buildsys.splat_config",
            "c_syntax.name_decomp",
            "c_syntax.parser",
            "c_syntax.struct_recover",
            "call_progress",
            "cli",
            "compare.instruction_diff",
            "compiler",
            "compiler.compile",
            "compiler.recompile_client",
            "compiler.temp_dirs",
            "compiler.toolchain",
            "config",
            "coverage.input_contract",
            "coverage.project",
            "coverage.report",
            "coverage.toml",
            "decompiler",
            "errors",
            "formats.archives",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.import_table",
            "formats.relocations",
            "ghidra",
            "library.flirt",
            "library.gen_flirt_pat",
            "library.identify",
            "matcher.scoring",
            "metadata.anchors",
            "metadata.bindings",
            "metadata.functions",
            "metadata.replication",
            "metadata.sqlite",
            "metadata.storage",
            "metadata_sets",
            "metadata_transfer",
            "naming",
            "project_archive",
            "security_scan",
            "skeleton",
            "source.c_rename",
            "source.discovery",
            "source.rename_ops",
            "telemetry",
            "toolchain_detect",
            "utils",
            "verify.cache",
            "verify.test",
            "workspace",
        }
    ),
    "source": frozenset(
        {
            "binary.analysis",
            "binary.gate",
            "blocker",
            "buildsys.link_order",
            "c_syntax.parser",
            "c_syntax.type_metadata",
            "c_syntax.types",
            "catalog",
            "catalog.loaders",
            "cli",
            "compare.coff_reloc",
            "compiler.cache",
            "compiler.compile",
            "compiler.image_headers",
            "compiler.overrides",
            "compiler.toolchain",
            "config",
            "cu_map",
            "data.layout",
            "errors",
            "formats.binary_loader",
            "formats.binary_model",
            "formats.pe_headers",
            "function_providers",
            "matcher.parsers",
            "metadata.anchors",
            "metadata.binding_history",
            "metadata.bindings",
            "metadata.coordinated",
            "metadata.data",
            "metadata.functions",
            "metadata.locking",
            "metadata.source_provenance",
            "metadata.storage",
            "utils",
            "workspace",
        }
    ),
    "status": frozenset(
        {
            "binary.sections",
            "catalog.loaders",
            "cli",
            "compiler.cache",
            "config",
            "data.layout",
            "formats.binary_loader",
            "formats.binary_model",
            "metadata.data",
            "metadata.document",
            "metadata.functions",
            "naming",
            "present",
            "source.discovery",
            "status_style",
            "utils",
            "verify.cache",
            "workspace.status",
        }
    ),
    "todo": frozenset(
        {
            "c_syntax.parser",
            "catalog",
            "cli",
            "compiler.compile",
            "config",
            "data.layout",
            "formats.binary_loader",
            "library.identify",
            "library.match",
            "matching.prove",
            "metadata.bindings",
            "metadata.data",
            "metadata.document",
            "metadata.functions",
            "naming",
            "present",
            "source.discovery",
            "status",
            "status_style",
            "utils",
            "verify.cache",
            "workspace.status",
        }
    ),
    "toolchain_cli": frozenset(
        {
            "cli",
            "compiler.temp_dirs",
            "compiler.toolchain",
            "compiler.toolchain_data",
            "config",
            "formats.coff",
            "toolchain_detect",
            "utils",
            "wibo",
        }
    ),
    "toolchain_detect": frozenset(
        {
            "compiler.toolchain",
            "formats.binary_loader",
            "formats.import_table",
            "formats.lzexe",
            "formats.ne_loader",
            "formats.pdb",
            "registry",
            "utils",
        }
    ),
    "verify": frozenset(
        {
            "binary.gate",
            "buildsys.check",
            "buildsys.linked_exact",
            "call_progress",
            "catalog",
            "catalog.loaders",
            "cli",
            "compare.alignment",
            "compare.coff_reloc",
            "compare.instruction_diff",
            "compiler.cache",
            "compiler.compile",
            "compiler.context",
            "compiler.overrides",
            "compiler.temp_dirs",
            "compiler.toolchain",
            "compiler.unshare",
            "compiler.xtensa",
            "config",
            "data.layout",
            "data.ownership",
            "data.placement",
            "data.verify",
            "errors",
            "formats.binary_loader",
            "formats.pe_headers",
            "function_providers",
            "matcher",
            "matcher.parsers",
            "matching.semantics",
            "metadata.bindings",
            "metadata.data",
            "metadata.document",
            "metadata.functions",
            "metadata.storage",
            "naming",
            "orphans",
            "present",
            "source.discovery",
            "source.rename_ops",
            "status_style",
            "text_audit",
            "toolchain_detect",
            "utils",
            "workspace",
        }
    ),
    "workspace": frozenset(
        {
            "errors",
        }
    ),
}


@dataclass(frozen=True)
class Violation:
    """One module breaking a direction rule, as ``module: rule -> target``."""

    module: str
    rule: str
    target: str
    line: int

    @override
    def __str__(self) -> str:
        return f"{self.module}:{self.line}: {self.rule}: imports {self.target}"


def _module_name(path: Path, package_root: str) -> str:
    """Fully-qualified module name for *path*, relative to the package root's parent."""
    rel = os.path.relpath(path, package_root)
    name = rel[:-3].replace(os.sep, ".")
    return name[: -len(".__init__")] if name.endswith(".__init__") else name


def _walk_modules(root: str) -> Iterator[tuple[str, Path, bool]]:
    """Yield ``(module name, path, is package)`` for every ``.py`` file under *root*."""
    root = os.path.normpath(root)
    package_root = os.path.dirname(root) or "."
    for dirpath, dirs, files in os.walk(root):
        dirs.sort()
        for file in sorted(files):
            if file.endswith(".py"):
                path = Path(dirpath) / file
                yield _module_name(path, package_root), path, file == "__init__.py"


def _rebrew_targets(
    module: str, is_package: bool, node: ast.Import | ast.ImportFrom, known: set[str]
) -> set[str]:
    """The in-tree modules an import statement reaches."""
    names: list[str] = []
    if isinstance(node, ast.Import):
        names = [alias.name for alias in node.names]
    elif node.level:
        # `.` names the enclosing package, so a package's own ``__init__`` keeps
        # one more segment than a plain module.
        parts = module.split(".")
        cut = len(parts) - node.level + 1 if is_package else len(parts) - node.level
        names = [".".join(parts[:cut] + (node.module.split(".") if node.module else []))]
    elif node.module:
        names = [node.module]

    targets: set[str] = set()
    for name in names:
        if name != "rebrew" and not name.startswith("rebrew."):
            continue
        rest = name
        while rest:
            if rest in known:
                targets.add(rest)
                break
            rest = rest.rsplit(".", 1)[0] if "." in rest else ""
    return targets


def _module_scope_imports(tree: ast.Module) -> Iterator[ast.Import | ast.ImportFrom]:
    """Yield module-scope imports, including PEP 810 ``lazy`` ones.

    Function bodies (including the ``__getattr__`` export loaders) and
    ``if TYPE_CHECKING:`` guards are skipped: a local import runs only when
    its function is called, so neither makes one module depend on another at
    load time.  A module-scope ``lazy import`` is deferred to first use too,
    but it stays in the module's static dependency graph, so an edge here
    still counts.
    """
    stack: list[list[ast.stmt]] = [list(tree.body)]
    while stack:
        for node in stack.pop():
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                yield node
            elif isinstance(node, (ast.If, ast.Try)):
                if (
                    isinstance(node, ast.If)
                    and isinstance(node.test, ast.Name)
                    and node.test.id == "TYPE_CHECKING"
                ):
                    continue
                stack.append(list(node.body))
                stack.append(list(getattr(node, "orelse", [])))
                for handler in getattr(node, "handlers", []):
                    stack.append(list(handler.body))
                stack.append(list(getattr(node, "finalbody", [])))
            elif isinstance(node, ast.ClassDef):
                stack.append(list(node.body))


def _owning_package(module: str) -> str | None:
    """The subpackage a module lives in, or ``None`` at the package root."""
    parts = module.split(".")
    return parts[1] if len(parts) > 2 else None


def _is_declared_external(package: str, target: str) -> bool:
    """Whether *package* lists *target* (a name relative to ``rebrew``) as an external."""
    allowed = PACKAGE_EXTERNALS[package]
    return any(target == name or target.startswith(name + ".") for name in allowed)


def _package_externals(
    module: str,
    path: Path,
    is_package: bool,
    known: set[str],
    *,
    tree: ast.Module | None = None,
) -> list[Violation]:
    """Imports that leave *module*'s subpackage for something it did not declare.

    Unlike the other two rules this reads every import in the file, lazy ones
    included: a function-body import is a coupling edge too, and catalog's
    ``binary_loader`` edge is deliberately lazy.  Imports of the package's own
    modules are the package's business, not an outward reach.
    """
    package = _owning_package(module)
    if package is None or package not in PACKAGE_EXTERNALS:
        return []
    if tree is None:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        for target in _rebrew_targets(module, is_package, node, known):
            # The package root loads before any submodule, so `from rebrew
            # import __version__` adds no edge the import did not already have.
            if target in (module, "rebrew"):
                continue
            rest = target[len("rebrew.") :]
            if rest.split(".")[0] == package:
                continue
            if not _is_declared_external(package, rest):
                violations.append(
                    Violation(module, "undeclared package external", target, node.lineno)
                )
    return violations


def _all_runtime_imports(tree: ast.Module) -> Iterator[ast.Import | ast.ImportFrom]:
    """Yield every import that runs, lazy ones inside function bodies included.

    ``if TYPE_CHECKING:`` blocks are skipped for the reason
    :func:`_module_scope_imports` gives: a type-only re-export never executes,
    so it cannot make one module depend on another at run time.
    """
    stack: list[list[ast.stmt]] = [list(tree.body)]
    while stack:
        for node in stack.pop():
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                yield node
            elif isinstance(node, (ast.If, ast.Try, ast.ClassDef, ast.FunctionDef, ast.With)):
                if (
                    isinstance(node, ast.If)
                    and isinstance(node.test, ast.Name)
                    and node.test.id == "TYPE_CHECKING"
                ):
                    continue
                if isinstance(node, ast.FunctionDef) and node.name == "main_entry":
                    continue
                stack.append(list(node.body))
                stack.append(list(getattr(node, "orelse", [])))
                for handler in getattr(node, "handlers", []):
                    stack.append(list(handler.body))
                stack.append(list(getattr(node, "finalbody", [])))


def _is_command_module(tree: ast.Module) -> bool:
    """Whether *tree* builds a command: a ``main_entry`` or a ``typer.Typer`` app.

    Derived from the tree rather than listed, so registering a console script
    or a ``builtins`` plugin is what makes a module a command, not a second
    inventory that can drift from ``pyproject.toml``.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "main_entry":
            return True
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if getattr(func, "attr", getattr(func, "id", "")) != "Typer":
                continue
            if any(isinstance(t, ast.Name) and t.id == "app" for t in node.targets) or any(
                isinstance(t, ast.Attribute) and t.attr == "app" for t in node.targets
            ):
                return True
    return False


#: Library modules reaching a command for a name the command does not own, one
#: edge each, named so the debt is visible rather than implied by a wildcard.
#: Empty: the last two edges, ``match_ga`` and ``match_run`` reaching into
#: ``near_diag`` for ``analyze`` and ``MUTATION_SUGGESTIONS``, were removed by
#: splitting the analysis into :mod:`rebrew.compare.near_analysis`, which the GA now
#: imports as a library.  A new edge here is a violation, not a new exemption.
DEFERRED_LIBRARY_COMMAND_EDGES: frozenset[tuple[str, str]] = frozenset()


def _library_imports_command(
    module: str,
    path: Path,
    is_package: bool,
    known: set[str],
    commands: set[str],
    *,
    tree: ast.Module | None = None,
) -> list[Violation]:
    """Imports from a module with no command of its own into one that has one.

    Every import counts, lazy ones included, for the reason
    :func:`_package_externals` gives.  A library that reaches into a command
    inherits that command's console-script surface, so the shared logic has to
    live somewhere the command can import rather than the other way round; that
    is why ``coverage_toml`` reads ``coverage_db`` and not ``build_db``.
    """
    if module in commands:
        return []
    if tree is None:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    violations: list[Violation] = []
    for node in _all_runtime_imports(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        for target in _rebrew_targets(module, is_package, node, known):
            if target not in commands or target == module:
                continue
            if (module, target) in DEFERRED_LIBRARY_COMMAND_EDGES:
                continue
            violations.append(Violation(module, "library imports a command", target, node.lineno))
    return violations


#: Command-handler submodules split out of :mod:`rebrew.ops` (a command).
#: Treating them as commands prevents non-command libraries from importing them
#: while letting the op worker dispatch command modules directly.
COMMAND_DISPATCH_MODULES = frozenset(
    {"rebrew.ops.handlers_analysis", "rebrew.ops.handlers_project"}
)


def check_layering(root: str) -> list[Violation]:
    """Return every import-direction violation under *root*.

    *root* is the package directory, e.g. ``"src/rebrew"``.
    """
    root = os.path.normpath(root)
    modules = list(_walk_modules(root))
    known = {name for name, _, _ in modules}
    commands = set()
    trees: dict[str, ast.Module] = {}
    for module, path, _ in modules:
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except SyntaxError:
            continue
        trees[module] = tree
        if _is_command_module(tree) or module in COMMAND_DISPATCH_MODULES:
            commands.add(module)

    violations: list[Violation] = []
    for module, path, is_package in modules:
        parsed = trees.get(module)
        if parsed is None:
            continue
        is_leaf = module in LEAF_MODULES
        for node in _module_scope_imports(parsed):
            for target in _rebrew_targets(module, is_package, node, known):
                if target == module:
                    continue
                if is_leaf and target not in LEAF_ALLOWED_IMPORTS:
                    violations.append(Violation(module, "leaf module", target, node.lineno))
                elif target in COMPOSITION_LAYER and module not in COMPOSITION_LAYER:
                    violations.append(
                        Violation(module, "composition-layer import", target, node.lineno)
                    )
        violations.extend(_package_externals(module, path, is_package, known, tree=parsed))
        violations.extend(
            _library_imports_command(module, path, is_package, known, commands, tree=parsed)
        )
    return sorted(violations, key=lambda v: (v.module, v.line, v.target))


def main() -> None:
    violations = check_layering("src/rebrew")
    if violations:
        print("Layering violations:")
        for violation in violations:
            print(violation)
        raise SystemExit(1)
    print("No layering violations found.")


if __name__ == "__main__":
    main()
