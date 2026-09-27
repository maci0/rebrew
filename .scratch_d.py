import ast, sys
# find functions whose params are typed non-Optional but body does `if X is None: return`
for f in sys.argv[1:]:
    full=open(f).read(); tree=ast.parse(full)
    for node in ast.walk(tree):
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
        ann={}
        for a in node.args.args+node.args.kwonlyargs:
            ann[a.arg]=ast.unparse(a.annotation) if a.annotation else None
        rt = ast.unparse(node.returns) if node.returns else None
        for st in ast.walk(node):
            if isinstance(st,ast.If) and len(st.body)==1 and isinstance(st.body[0],ast.Return):
                t=ast.unparse(st.test)
                if t.endswith(" is None") or t.endswith(" is not None") or t.endswith(" == None"):
                    tgt=t.split()[0]
                    if ann.get(tgt) and "None" not in ann[tgt] and "Optional" not in ann[tgt]:
                        print(f"{f}:{st.lineno}: {node.name} param {tgt}: {ann[tgt]}  guard: {t}")
