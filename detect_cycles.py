import ast
import os
from collections import defaultdict

edges = defaultdict(list)
in_degree = defaultdict(int)


def get_imports(filepath, package_prefix):
    with open(filepath) as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except Exception:
            return []
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name.startswith(package_prefix):
                    imports.append(name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.level > 0:
                filepath.split("/")
                # This is a bit naive, proper absolute resolution is better
                pass
            elif node.module.startswith(package_prefix):
                imports.append(node.module)
    return imports


for root, _, files in os.walk("src/rebrew"):
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            mod_name = path[4:-3].replace("/", ".")
            if path.endswith("__init__.py"):
                mod_name = path[4:-12].replace("/", ".")
            imports = get_imports(path, "rebrew")
            for imp in imports:
                edges[mod_name].append(imp)

# Tarjan's strongly connected components algorithm
index_counter = [0]
index = {}
lowlink = {}
onStack = set()
stack = []
cycles = []


def strongconnect(node):
    index[node] = index_counter[0]
    lowlink[node] = index_counter[0]
    index_counter[0] += 1
    stack.append(node)
    onStack.add(node)

    for successor in edges.get(node, []):
        if successor not in index:
            strongconnect(successor)
            lowlink[node] = min(lowlink[node], lowlink[successor])
        elif successor in onStack:
            lowlink[node] = min(lowlink[node], index[successor])

    if lowlink[node] == index[node]:
        scc = []
        while True:
            w = stack.pop()
            onStack.remove(w)
            scc.append(w)
            if w == node:
                break
        if len(scc) > 1:
            cycles.append(scc)


for node in list(edges.keys()):
    if node not in index:
        strongconnect(node)

if cycles:
    print("Cycles found:")
    for c in cycles:
        print(c)
else:
    print("No cycles found.")
