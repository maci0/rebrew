"""check_layering.py — enforce the import-direction rules ``detect_cycles.py`` cannot see.

``detect_cycles.py`` answers "does the import graph fold back on itself?".
It says nothing about direction, so a module can stay cycle-free and still
reach the wrong way across the package.  Two rules are enforced here, both of
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
