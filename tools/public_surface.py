"""public_surface.py — the public import surface of ``rebrew``, read from the AST.

CONTRIBUTING.md keeps the import surface unfrozen: a removal, move, or
signature change there ships in a minor with a ``**Breaking:**`` entry.  Nothing
in the tree could check that, so a moved helper reached a release unflagged
whenever the author forgot the prefix.  This module makes the surface
comparable, so ``tests/test_public_surface.py`` can diff two trees without
importing either (an import would need the optional extras, and would run the
package's own import-time work).

A name is part of the surface when it is

- a module-level function, class, or constant whose name does not start with
  ``_``,
- a public method or public class attribute of a public class, or
- an intra-package re-export (``from .x import y``, and every ``from x import y``
  in an ``__init__.py``) — the accidental public API path, since a name the
  module defines elsewhere is still importable from here.

Descriptors are compared as text, so a changed default, a dropped parameter, a
reordered argument, a new base class, and a changed constant all read as a
change rather than as the same name.

Run from the repo root::

    python tools/public_surface.py > /tmp/surface.json
    python tools/public_surface.py --diff v2.14.0        # delta against a tag

Also importable for tests::

    from tools.public_surface import diff_surfaces, public_surface
    removed, changed, added = diff_surfaces(public_surface("src/rebrew"), old)
"""

from __future__ import annotations

import argparse
import ast
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

PKG_ROOT = Path("src") / "rebrew"

#: Module name of a package's ``__init__.py``, which re-exports in the open.
_INIT = "__init__"

#: A literal is anything ``ast.literal_eval`` can turn into a constant; a
#: computed module-level binding has no stable text to compare.
_Literal = ast.Constant | ast.Tuple | ast.List | ast.Set | ast.Dict | ast.UnaryOp


# --- argument and descriptor rendering -----------------------------------


def _render_annotation(arg: ast.arg) -> str:
    """The declared type, except for a Typer option, which is a help string.

    ``typer.Option(False, '--flag', help=...)`` puts prose in the signature, and
    a help-text edit would then read as a signature change.
    """
    ann = arg.annotation
    if isinstance(ann, ast.Call) and _called_name(ann.func).rsplit(".", 1)[-1] in {
        "Option",
        "Argument",
    }:
        return f"{arg.arg}: Typer"
    return f"{arg.arg}: {_render_expr(ann)}" if ann else arg.arg


def _called_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _render_arg(arg: ast.arg, default: ast.expr | None = None) -> str:
    text = _render_annotation(arg)
    if default is None:
        return f"!{text}"
    typer_call = _as_typer_call(default)
    if typer_call is None:
        return f"{text}={_render_expr(default)}"
    # `typer.Option(False, '--flag', help=...)` hides the default in a call and
    # spends most of its text on help prose; keep the value and the flag names.
    literals = [a for a in typer_call.args if isinstance(a, ast.Constant)]
    required = (
        bool(literals) and isinstance(literals[0], ast.Constant) and (literals[0].value is Ellipsis)
    )
    rendered = ", ".join(repr(a.value) for a in literals)
    return f"{'!' if required else ''}{text}=typer({rendered})"


def _as_typer_call(node: ast.expr) -> ast.Call | None:
    if isinstance(node, ast.Call) and _called_name(node.func).rsplit(".", 1)[-1] in {
        "Option",
        "Argument",
    }:
        return node
    return None


def _render_expr(node: ast.expr | None) -> str:
    if node is None:
        return ""
    if isinstance(node, _Literal):
        try:
            return repr(ast.literal_eval(node))
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return ast.unparse(node)
    return ast.unparse(node)


def _render_positional(args: list[ast.arg], defaults: list[ast.expr]) -> list[str]:
    """Defaults bind to the trailing arguments, so pad from the end."""
    pad = len(args) - len(defaults)
    return [_render_arg(a) for a in args[:pad]] + [
        _render_arg(a, d) for a, d in zip(args[pad:], defaults, strict=True)
    ]


def _render_args(args: ast.arguments) -> list[str]:
    parts = _render_positional(list(args.posonlyargs), [])
    parts += _render_positional(list(args.args), list(args.defaults))
    if args.posonlyargs:
        parts.append("/")
    if args.vararg:
        parts.append(f"*{_render_arg(args.vararg)}")
    parts += [_render_arg(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True)]
    if args.kwarg:
        parts.append(f"**{_render_arg(args.kwarg)}")
    return parts


def _render_returns(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    if node.returns is None:
        return ""
    return f"-> {_render_expr(node.returns)}"


# --- module surface -------------------------------------------------------


def _public(name: str) -> bool:
    return not name.startswith("_")


def _function_descriptor(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return (f"{kind} {node.name}", *_render_args(node.args), _render_returns(node))


def _class_descriptor(node: ast.ClassDef) -> tuple[str, ...]:
    return (f"class {node.name}", *(ast.unparse(b) for b in node.bases))


def _body_functions(body: Iterable[ast.stmt]) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        n
        for n in body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and _public(n.name)
    ]


def _literal_constants(body: Iterable[ast.stmt]) -> dict[str, tuple[str, ...]]:
    out: dict[str, tuple[str, ...]] = {}
    for node in body:
        targets: list[ast.expr]
        if isinstance(node, ast.Assign) and isinstance(node.value, _Literal):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.value, _Literal):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and _public(target.id):
                out[target.id] = (_render_expr(node.value),)
    return out


def _module_names(tree: ast.Module, is_package: bool) -> dict[str, tuple[str, ...]]:
    """Every public name this module binds at module level, with its descriptor."""
    out: dict[str, tuple[str, ...]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _public(node.name):
            out[node.name] = _function_descriptor(node)
        elif isinstance(node, ast.ClassDef) and _public(node.name):
            out[node.name] = _class_descriptor(node)
            for member in _body_functions(node.body):
                out[f"{node.name}.{member.name}"] = _function_descriptor(member)
            for name, value in _literal_constants(node.body).items():
                out[f"{node.name}.{name}"] = value
        elif (
            isinstance(node, ast.ImportFrom)
            and _public(node.module or "")
            and (node.level > 0 or is_package)
        ):
            origin = "." * node.level + (node.module or "")
            for alias in node.names:
                if _public(alias.asname or alias.name):
                    out[alias.asname or alias.name] = (f"re-export from {origin}",)
    out.update(_literal_constants(tree.body))
    return out


def _module_name(path: Path, root: Path) -> str:
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    if rel.startswith("../"):
        raise ValueError(f"{path} is not under {root}")
    parts = rel[: -len(".py")].split("/")
    if parts[-1] == _INIT:
        parts.pop()
    return ".".join(parts)


def _surface_from_source(source: str, is_package: bool) -> dict[str, tuple[str, ...]]:
    return _module_names(ast.parse(source), is_package)


def public_surface(
    root: Path = PKG_ROOT, source: Mapping[Path, str] | None = None
) -> dict[str, dict[str, tuple[str, ...]]]:
    """Map ``rebrew.module`` to the public names it binds and their descriptors.

    ``source`` supplies the text per absolute path instead of reading the tree,
    so the same routine scores a tagged tree.
    """
    paths: list[Path] = []
    if source is not None:
        paths = sorted(p for p in source if p.suffix == ".py")
    else:
        paths = sorted(root.rglob("*.py"))
    return {
        _module_name(p, root): _surface_from_source(
            source[p] if source is not None else p.read_text(encoding="utf-8"),
            p.name == f"{_INIT}.py",
        )
        for p in paths
    }


# --- comparing two trees --------------------------------------------------

#: A surface delta, per module: what a consumer can no longer do, what changed
#: shape, and what is new.
Removed = dict[str, dict[str, tuple[str, ...]]]
Changed = dict[str, dict[str, tuple[tuple[str, ...], tuple[str, ...]]]]
Added = dict[str, dict[str, tuple[str, ...]]]

_RETURN = "-> "


def _appends_only_optional(before: tuple[str, ...], after: tuple[str, ...]) -> bool:
    """True when ``after`` only adds parameters, each carrying a default.

    A new keyword with a default is how a function grows: every existing call
    still resolves, wherever in the list it lands (a Typer callback takes its
    options in declaration order, so a flag added mid-list is normal).  Anything
    else — a dropped or reordered parameter, a changed default, a narrowed
    return type, a new required argument — can break the caller.
    """
    if before[0] != after[0] or before[-1] != after[-1]:
        return False
    old_params = list(before[1:-1])
    new_params = list(after[1:-1])
    if any(p.startswith("**") for p in old_params):
        return old_params == new_params
    rest = list(new_params)
    for param in old_params:
        if param not in rest:
            return False
        rest.remove(param)
    return all(not p.startswith("!") and "=" in p for p in rest)


def _is_breaking(before: tuple[str, ...], after: tuple[str, ...]) -> bool:
    if before == after:
        return False
    if before[0].startswith("def ") and after[0].startswith("def "):
        return not _appends_only_optional(before, after)
    return True


def diff_surfaces(
    old: Mapping[str, Mapping[str, tuple[str, ...]]],
    new: Mapping[str, Mapping[str, tuple[str, ...]]],
) -> tuple[Removed, Changed, Added]:
    """Classify a surface delta as removed, changed, or added names.

    A removed entry, or one whose shape no longer accepts the old call, breaks
    ``from rebrew.x import name``; an added entry, or a signature that only grew
    optional parameters, is a feature.  A name that moved is a removal plus an
    addition, which is the shape of a moved helper.
    """
    removed: Removed = {}
    changed: Changed = {}
    added: Added = {}
    for module in sorted(set(old) | set(new)):
        before = old.get(module, {})
        after = new.get(module, {})
        gone = {k: v for k, v in before.items() if k not in after}
        live = {
            k: (before[k], after[k])
            for k in set(before) & set(after)
            if _is_breaking(before[k], after[k])
        }
        fresh = {k: v for k, v in after.items() if k not in before}
        if gone:
            removed[module] = gone
        if live:
            changed[module] = live
        if fresh:
            added[module] = fresh
    return removed, changed, added


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, check=False, capture_output=True, text=True)


def surface_at_ref(
    ref: str, root: Path = PKG_ROOT, cwd: Path = Path(".")
) -> dict[str, dict[str, tuple[str, ...]]] | None:
    """The surface of ``root`` as of ``ref``, or ``None`` outside a checkout."""
    listing = _git("ls-tree", "-r", "--name-only", ref, "--", str(root), cwd=cwd)
    if listing.returncode != 0:
        return None
    source: dict[Path, str] = {}
    for line in listing.stdout.splitlines():
        name = line.strip()
        if not name.endswith(".py"):
            continue
        blob = _git("show", f"{ref}:{name}", cwd=cwd)
        if blob.returncode != 0:
            continue
        source[Path(name).resolve()] = blob.stdout
    return public_surface(root, source=source)


# --- CLI ------------------------------------------------------------------


def _render(descriptor: tuple[str, ...]) -> str:
    head, params, _, ret = descriptor[0], descriptor[1:-1], descriptor[-2:-1], descriptor[-1]
    return f"{head}({', '.join(params)}) {ret}".strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=PKG_ROOT, help="package root")
    parser.add_argument("--diff", metavar="REF", help="print the surface delta against a git ref")
    args = parser.parse_args(argv)

    current = public_surface(args.root)
    if args.diff is None:
        for module in sorted(current):
            for name, descriptor in sorted(current[module].items()):
                print(f"{module}.{name}\t{_render(descriptor)}")
        return 0

    old = surface_at_ref(args.diff, args.root)
    if old is None:
        print(f"cannot read {args.diff}: not a git checkout", file=sys.stderr)
        return 1
    removed, changed, added = diff_surfaces(old, current)
    for module, gone in sorted(removed.items()):
        for name, descriptor in sorted(gone.items()):
            print(f"removed  {module}.{name}  ({_render(descriptor)})")
    for module, reshaped in sorted(changed.items()):
        for name, (before, after) in sorted(reshaped.items()):
            print(f"changed  {module}.{name}\n  - {_render(before)}\n  + {_render(after)}")
    for module, fresh in sorted(added.items()):
        for name in sorted(fresh):
            print(f"added    {module}.{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
