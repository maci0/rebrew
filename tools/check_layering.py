"""check_layering.py — enforce the import-direction rules ``detect_cycles.py`` cannot see.

``detect_cycles.py`` answers "does the import graph fold back on itself?".
It says nothing about direction, so a module can stay cycle-free and still
reach the wrong way across the package.  Three rules are enforced here, all of
which the tree satisfies today:

**Leaf helpers stay leaves.**  ``rebrew.utils`` is the module every other
module may import, and its docstring promises the freedom that buys: it holds
no rebrew imports, so it can never sit between a caller and a dependency.  The
first rebrew import in it is a layering regression.

**The composition layer is a sink.**  ``plugin``, ``builtins``, ``main`` and
``dashboard`` build the Typer app and know every command; nothing they import
depends on them back.  A module that imports one at *module scope* drags the
whole command graph in and makes a leaf into a peer of the app, so only the
layer itself may do it.  Two escapes stay legal because neither runs at
import time: a command registers itself with the umbrella inside its
``register()`` (``init``, ``recommend``), and ``errors`` re-exports
``ComponentError`` for type checkers under ``TYPE_CHECKING``.

**A subpackage reaches outward only through its declared externals.**  Every
``src/rebrew/<package>/AGENTS.md`` states the externals that package may
import, and that line is what keeps ``matcher/`` from becoming a peer of the
CLI it drives.  Nothing read the line, so it drifted silently while the other
two rules kept passing.  The list below is transcribed from those five files;
``tests/test_check_layering.py`` fails when a name in the tool is no longer
documented, so the two cannot diverge quietly.  Unlike the other rules this
one reads *every* import, not just the module-scope ones: the catalog's
``binary_loader`` is a deliberate lazy import, and a lazy edge is still an
edge.  A ``__getattr__`` loader that names its target as a string is not seen;
the packages that have one list their own submodule in the entry below.

Run from the repo root::

    python tools/check_layering.py

Also importable for tests::

    from tools.check_layering import check_layering
    assert check_layering("src/rebrew") == []
"""

import ast
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import override

#: Modules that assemble the Typer app.  Nothing outside this set may import
#: them at module scope.
COMPOSITION_LAYER = frozenset(
    {"rebrew.plugin", "rebrew.builtins", "rebrew.main", "rebrew.dashboard"}
)

#: Modules allowed to import no other rebrew module at all.
LEAF_MODULES = frozenset({"rebrew.utils"})

#: What each subpackage may import outside itself, transcribed from the
#: "Externals" line of its ``AGENTS.md``.  Names are relative to ``rebrew``
#: and dotted: ``workspace`` covers ``workspace.status``, and
#: ``binsync.export`` names the one module of ``binsync/`` that ``ghidra/``
#: may read.  A package's own submodules are always allowed and are not
#: listed.
PACKAGE_EXTERNALS: dict[str, frozenset[str]] = {
    "matcher": frozenset(
        {
            "binary_loader",
            "coff_reloc",
            "compile",
            "compile_cache",
            "config",
            "errors",
            "flag_data",
            "flags",
            "omf16",
            "registry",
            "temp_dirs",
            "toolchain",
            "toolchain_spec",
            "utils",
        }
    ),
    "catalog": frozenset(
        {
            "annotation",
            "binary_loader",
            "binary_model",
            "cli",
            "config",
            "data_metadata",
            "present",
            "sections",
            "sources",
            "status",
            "utils",
            "workspace",
        }
    ),
    "binsync": frozenset(
        {
            "annotation",
            "binary_loader",
            "c_parser",
            "catalog",
            "cli",
            "config",
            "cross_import",
            "data_metadata",
            "data_scan",
            "metadata",
            "naming",
            "rename_ops",
            "sources",
            "struct_parser",
            "types",
            "utils",
        }
    ),
    "ghidra": frozenset(
        {
            "binary_loader",
            "binsync.export",
            "binsync.importer",
            "catalog",
            "cli",
            "config",
            "errors",
            "sources",
            "status_style",
            "utils",
        }
    ),
    "workspace": frozenset({"errors"}),
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
    """Yield imports that run at import time.

    Function bodies (lazy imports and the ``__getattr__`` export loaders) and
    ``if TYPE_CHECKING:`` guards are skipped: neither executes on import, so
    neither can make one module depend on another at load time.
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
    module: str, path: Path, is_package: bool, known: set[str]
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
    tree = ast.parse(path.read_bytes(), filename=str(path))
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        for target in _rebrew_targets(module, is_package, node, known):
            if target == module:
                continue
            rest = target[len("rebrew.") :]
            if rest.split(".")[0] == package:
                continue
            if not _is_declared_external(package, rest):
                violations.append(
                    Violation(module, "undeclared package external", target, node.lineno)
                )
    return violations


def check_layering(root: str) -> list[Violation]:
    """Return every import-direction violation under *root*.

    *root* is the package directory, e.g. ``"src/rebrew"``.
    """
    root = os.path.normpath(root)
    known = {name for name, _, _ in _walk_modules(root)}
    violations: list[Violation] = []
    for module, path, is_package in _walk_modules(root):
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except SyntaxError:
            continue
        is_leaf = module in LEAF_MODULES
        for node in _module_scope_imports(tree):
            for target in _rebrew_targets(module, is_package, node, known):
                if target == module:
                    continue
                if is_leaf:
                    violations.append(Violation(module, "leaf module", target, node.lineno))
                elif target in COMPOSITION_LAYER and module not in COMPOSITION_LAYER:
                    violations.append(
                        Violation(module, "composition-layer import", target, node.lineno)
                    )
        violations.extend(_package_externals(module, path, is_package, known))
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
