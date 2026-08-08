"""detect_cycles.py — find import-time cycles within the ``rebrew`` package.

Parses every ``.py`` file under a package root for **module-level**
``import rebrew.*`` / ``from rebrew.* import ...`` references, builds a module
dependency graph, and runs Tarjan's strongly-connected-components algorithm to
report any cycles.

Only module-level imports count as edges: imports inside function bodies
(lazy imports) and ``if TYPE_CHECKING:`` guards are import-time-safe by
construction and do not create cycles that break loading.

Run from the repo root::

    python tools/detect_cycles.py

Also importable for tests::

    from tools.detect_cycles import detect_cycles
    assert detect_cycles("src/rebrew") == []
"""

import ast
import os
from collections import defaultdict


def _module_level_imports(stmts: list[ast.stmt]) -> list[ast.Import | ast.ImportFrom]:
    """Yield import nodes at module scope, skipping function/class bodies."""
    found: list[ast.Import | ast.ImportFrom] = []
    for node in stmts:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            found.append(node)
        elif isinstance(node, ast.If):
            # `if TYPE_CHECKING:` guards never execute at runtime.
            if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
                continue
            found.extend(_module_level_imports(node.body))
            found.extend(_module_level_imports(node.orelse))
        elif isinstance(node, ast.Try):
            found.extend(_module_level_imports(node.body))
            for handler in node.handlers:
                found.extend(_module_level_imports(handler.body))
            found.extend(_module_level_imports(node.orelse))
            found.extend(_module_level_imports(node.finalbody))
    return found


def _get_imports(filepath: str, package_prefix: str) -> list[str]:
    with open(filepath) as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except Exception:
            return []
    imports: list[str] = []
    for node in _module_level_imports(tree.body):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(package_prefix):
                    imports.append(alias.name)
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith(package_prefix)
        ):
            imports.append(node.module)
    return imports


def detect_cycles(root: str) -> list[list[str]]:
    """Return strongly-connected components (size > 1) of the import graph.

    *root* is the package directory, e.g. ``"src/rebrew"``.  Module names are
    derived from file paths relative to the repo root (``src/`` prefix).
    """
    edges: dict[str, list[str]] = defaultdict(list)
    for dirpath, _, files in os.walk(root):
        for file in files:
            if not file.endswith(".py"):
                continue
            path = os.path.join(dirpath, file)
            mod_name = path[4:-3].replace("/", ".")
            if path.endswith("__init__.py"):
                mod_name = path[4:-12].replace("/", ".")
            for imp in _get_imports(path, "rebrew"):
                edges[mod_name].append(imp)

    # Tarjan's strongly connected components algorithm
    index_counter = [0]
    index: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    cycles: list[list[str]] = []

    def strongconnect(node: str) -> None:
        index[node] = index_counter[0]
        lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack.add(node)

        for successor in edges.get(node, []):
            if successor not in index:
                strongconnect(successor)
                lowlink[node] = min(lowlink[node], lowlink[successor])
            elif successor in on_stack:
                lowlink[node] = min(lowlink[node], index[successor])

        if lowlink[node] == index[node]:
            scc: list[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.append(w)
                if w == node:
                    break
            if len(scc) > 1:
                cycles.append(scc)

    for node in list(edges.keys()):
        if node not in index:
            strongconnect(node)

    return cycles


def main() -> None:
    cycles = detect_cycles("src/rebrew")
    if cycles:
        print("Cycles found:")
        for c in cycles:
            print(c)
        raise SystemExit(1)
    print("No cycles found.")


if __name__ == "__main__":
    main()
