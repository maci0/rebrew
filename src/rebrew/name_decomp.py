"""name_decomp.py — apply known struct names to decompiler output.

Decompilers (Kuna, Ghidra, ...) emit untyped pointers (``int a0``) with
cast-deref member access (``*(int *)(a0 + 0x14)``).  When the project
already declares a struct whose layout covers the accessed offsets, the
naming pass rewrites the decompilation to use it::

    unsigned int sub_1000d350(int a0)          ->  unsigned int sub_1000d350(command_s *a0)
    *(int *)(a0 + 0x14)                        ->  a0->field_14
    *(char *)(a0 + 0x10) == 1                  ->  a0->field_10 == 1
    sub_1000b1c0(a0 + 0x10)                    ->  sub_1000b1c0(&a0->field_10)
    *(unsigned int *)&v2[10]  (v2 = a0, short*) ->  v2->field_14   (array-index form)

This is the "feed the recovered structs back in" loop: ``rebrew
recover-structs`` recovers the layout as an anonymous candidate, the user
names the type (e.g. ``command_s``) in a header, and ``rebrew decompile
--named`` picks it up.  Matching is conservative: a variable is typed when
at least one of its accessed offsets is an exact (non-padding) field of a
declared struct and every access falls within the struct's span; offsets
that land in padding (``gap_*`` arrays) or on undeclared positions are
left as written.  ``vN = a0;`` aliases inherit the match, and the smallest
covering struct wins.  The pass never edits files — it only rewrites the
decompilation text.

Usage::

    rebrew decompile 0x1000d350 --named
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config
from rebrew.struct_recover import (
    PSEUDO_TYPES,
    TYPE_WIDTHS,
    offset_value,
    parse_decomp_for_structs,
    pointer_element_widths,
    type_width,
)

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Struct layout parsing
# ---------------------------------------------------------------------------

#: One field inside a typedef body: ``int flags;`` / ``char gap_0004[0x264260];``
#: / ``char field_0[0xc];`` / ``unsigned short tbl[2][4];`` / ``int *p;``.
_FIELD_LINE_RE = re.compile(
    r"^\s*(?P<mod>(?:unsigned|signed|const)\s+)?(?P<base>[A-Za-z_]\w*)\s*(?P<ptr>\*+)?\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*(?P<arr>(?:\[[^\]]*\])*)\s*;"
)
#: Strips ``/* */`` and ``//`` from a single line (for layout scanning only).
_LINE_COMMENT_RE = re.compile(r"//.*$")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)

#: Multi-dimensional array dims: ``[0x10]`` or ``[4]``.
_DIM_RE = re.compile(r"\[([^\]]*)\]")


def _dim_value(s: str) -> int | None:
    """Parse a C array dimension (hex ``0x10`` or decimal ``4``).

    Returns ``None`` for a non-numeric dimension (``[]`` or a symbolic
    ``[N]``), which the caller treats as unsized rather than crashing.
    """
    s = s.strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except ValueError:
        return None


@dataclass
class FieldLayout:
    """Offsets of a declared struct, for matching + rewriting.

    ``complete`` is False when the body contained something the parser
    cannot size (bitfields, embedded structs, ...) — such structs are never
    matched, because a partial layout would mis-attribute offsets.
    """

    fields: dict[int, tuple[str, int]] = field(default_factory=dict)  # off → (name, width)
    size: int = 0
    complete: bool = True


def struct_field_layout(definition: str, pointer_width: int = 4) -> FieldLayout:
    """Compute ``{offset: (field_name, width)}`` for a typedef struct body.

    Handles the guild/decomp conventions: typed primitives (``int flags``),
    pointer fields (``int *p`` → *pointer_width* on the target arch),
    explicit byte arrays (``char gap_0004[0x264260]`` → width 0x264260), and
    multi-dim arrays (``[2][4]`` → 8 elements).  Bitfields, embedded ``struct``
    members, or anything else unsized mark the layout ``complete = False`` so
    it is never matched against evidence.
    """
    body = _BLOCK_COMMENT_RE.sub(" ", definition)
    lay = FieldLayout()
    offset = 0
    for raw in body.splitlines():
        line = _LINE_COMMENT_RE.sub("", raw).strip()
        if not line:
            continue
        # ``typedef struct name {`` opener and ``} name;`` closer are not fields.
        if line.startswith("typedef struct") or line.startswith("}"):
            continue
        m = _FIELD_LINE_RE.match(line)
        if m is None:
            lay.complete = False
            continue
        base = m.group("base")
        width: int | None
        if m.group("ptr"):
            width = pointer_width
        elif base in TYPE_WIDTHS:
            width = TYPE_WIDTHS[base]
        else:
            width = None
        if width is None:
            lay.complete = False
            continue
        if m.group("arr"):
            count = 1
            unsized = False
            for dim in _DIM_RE.findall(m.group("arr")):
                dim_value = _dim_value(dim)
                if dim_value is None:
                    unsized = True
                    break
                count *= dim_value
            if unsized:
                # ``char x[]`` / ``[N]``: the field has no computable width, so
                # every later offset is unknown.  Mark incomplete (never
                # matched) instead of raising inside the parse.
                lay.complete = False
                continue
            width *= count
        lay.fields[offset] = (m.group("name"), width)
        offset += width
    lay.size = offset
    return lay


def struct_definitions_to_layouts(
    definitions: dict[str, str], pointer_width: int = 4
) -> dict[str, FieldLayout]:
    """Map struct name → parsed layout for every raw definition.

    Parses via the shared :mod:`rebrew.types` model (tree-sitter offsets
    with MSVC alignment); falls back to the legacy line parser for bodies
    the shared model cannot size, so existing behavior is preserved.
    *pointer_width* sizes pointer fields in the legacy fallback.
    """
    from rebrew.types import parse_structs, type_size

    layouts: dict[str, FieldLayout] = {}
    for name, definition in definitions.items():
        parsed = parse_structs(definition)
        struct = parsed.get(name) or next(iter(parsed.values()), None)
        if struct is not None and struct.fields:
            lay = FieldLayout()
            lay.complete = struct.complete
            ordered = sorted(struct.fields, key=lambda f: f[2])
            for idx, (field_name, spelling, off) in enumerate(ordered):
                end = ordered[idx + 1][2] if idx + 1 < len(ordered) else struct.size
                width = type_size(spelling) or max(0, end - off)
                lay.fields[off] = (field_name, width)
            lay.size = struct.size
            layouts[name] = lay
        else:
            layouts[name] = struct_field_layout(definition, pointer_width=pointer_width)
    return layouts


def _match_struct(var_offsets: set[int], layouts: dict[str, FieldLayout]) -> str | None:
    """Pick the smallest COMPLETE struct a variable's accesses plausibly use.

    Requires every evidence offset to fall within the struct's span AND at
    least one offset to be an exact, non-padding field start.  Offsets that
    fall inside padding (``gap_*`` arrays) are tolerated — decompilers emit
    misaligned reads — but are not rewritten.  Ties → alphabetically first.
    """
    candidates = [
        name
        for name, lay in layouts.items()
        if lay.complete
        and all(off < lay.size for off in var_offsets)
        and any(
            lay.fields.get(off) is not None and not lay.fields[off][0].startswith("gap_")
            for off in var_offsets
        )
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda n: (layouts[n].size, n))


# ---------------------------------------------------------------------------
# Rewriting
# ---------------------------------------------------------------------------

#: Access forms, longest first (single pass — the engine consumes each match
#: so the bare ``var + N`` alternative never re-matches inside a cast form).
_ACCESS_RE = re.compile(
    # *(T *)(var + N)
    r"\*\s*\(\s*(?P<cast>[A-Za-z_]\w*(?:\s+\w+)*?)\s*\*\s*\)\s*\(\s*(?P<cvar>[A-Za-z_]\w*)\s*\+\s*(?P<coff>0x[0-9a-fA-F]+|\d+)\s*\)"
    # *(T *)&var[i] / *(T *)var[i]
    r"|\*\s*\(\s*(?P<cast2>[A-Za-z_]\w*(?:\s+\w+)*?)\s*\*\s*\)\s*&?\s*(?P<avar>[A-Za-z_]\w*)\s*\[\s*(?P<aidx>\d+)\s*\]"
    # &var[i] / var[i]
    r"|&?\s*(?P<bvar>[A-Za-z_]\w*)\s*\[\s*(?P<bidx>\d+)\s*\]"
    # var + N (address arithmetic, e.g. passed to a call)
    r"|\b(?P<pvar>[A-Za-z_]\w*)\s*\+\s*(?P<poff>0x[0-9a-fA-F]+|\d+)\b"
)

#: Signature type prefix, first line only: ``int a0`` / ``unsigned int a1``
#: / ``short *a2`` → replaced wholesale when the variable matched.
_SIG_TYPE_RE = re.compile(
    r"\b(?P<mod>(?:unsigned|signed)\s+)?(?P<base>[A-Za-z_]\w*)\s+(?P<ptr>\*)?\s*(?P<var>[A-Za-z_]\w*)\b"
)

#: ``vN = a0;`` alias assignments (Kuna copies params into locals).
_ALIAS_RE = re.compile(r"\b(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<src>[A-Za-z_]\w*)\s*;")

#: ``(T *)var`` casts — pointer evidence for item 15's gate.
_CAST_PTR_RE = re.compile(r"\(\s*[A-Za-z_]\w*(?:\s+\w+)*?\s*\*\s*\)\s*(?P<var>[A-Za-z_]\w*)")

#: ``var[i]`` / ``&var[i]`` uses — pointer evidence for item 15's gate.
_INDEX_USE_RE = re.compile(r"&?\s*(?P<var>[A-Za-z_]\w*)\s*\[\s*\d+\s*\]")


def _pointer_vars(text: str) -> set[str]:
    """Vars with evidence of being a pointer: ``T *var`` decls/params,
    ``(T *)var`` casts, ``*(T *)(var + N)`` / ``*(T *)&var + N`` cast-derefs,
    ``*(T *)&var[i]`` derefs, or ``var[i]`` index uses.

    The anonymous rewrite pass only renames these; a plain ``int`` used in
    ``var + N`` arithmetic has no such evidence and a bare ``var + N`` on it
    is integer math, not a member access.
    """
    from rebrew.struct_recover import (
        _ARRAY_DEREF_RE,
        _ARRAY_IDX_RE,
        _CAST_DEREF_RE,
        _CAST_RE,
        _DECL_RE,
        _FIELD_ACCESS_RE,
    )

    out: set[str] = set()
    for m in _DECL_RE.finditer(text):
        out.add(m.group("var"))
    for m in _CAST_RE.finditer(text):
        out.add(m.group("var"))
    for m in _CAST_PTR_RE.finditer(text):
        out.add(m.group("var"))
    for m in _CAST_DEREF_RE.finditer(text):
        var = m.group("var1") or m.group("var2")
        if var is not None:
            out.add(var)
    for m in _ARRAY_DEREF_RE.finditer(text):
        out.add(m.group("var"))
    for m in _ARRAY_IDX_RE.finditer(text):
        out.add(m.group("var"))
    for m in _FIELD_ACCESS_RE.finditer(text):
        var = m.group("var")
        if var is not None:
            out.add(var)
    for m in _INDEX_USE_RE.finditer(text):
        out.add(m.group("var"))
    return out


@dataclass
class NamingResult:
    """Rewritten code plus what the pass applied."""

    code: str
    applied: list[dict[str, Any]]  # {var, struct, offsets: [...]}


def apply_known_names(
    text: str, definitions: dict[str, str], pointer_width: int = 4
) -> NamingResult:
    """Rewrite *text* to use known structs for anonymous pointer variables.

    *definitions* maps struct name → raw ``typedef struct ...`` text (e.g.
    ``rebrew.struct_recover.existing_structs``).  *pointer_width* is the
    target's pointer size in bytes (4 for 32-bit, 2 for 16-bit, 8 for 64-bit)
    — it sizes pointer fields in the legacy line parser.  Returns the
    rewritten code and the list of ``{var, struct, offsets}`` applications
    (empty when nothing matched).

    A variable is only rewritten when there is evidence it is a pointer:
    a ``T *var`` declaration/param, a ``(T *)var`` cast, or an array-index
    use (``var[i]``); a plain ``int`` variable with integer arithmetic
    (``a0 + 0x10`` where ``a0`` is never dereferenced as a pointer) is left
    alone, since a bare ``var + N`` is address arithmetic on an unknown base.
    """
    layouts = struct_definitions_to_layouts(definitions, pointer_width=pointer_width)
    elem_widths = pointer_element_widths(text)
    pointer_vars = _pointer_vars(text)

    # Anonymous pointer vars → evidence offsets (temps excluded already).
    # Only vars with pointer evidence are rewritten: a bare ``int`` loop
    # counter used in ``var + N`` address arithmetic must not be renamed.
    parsed = parse_decomp_for_structs(text)
    var_structs: dict[str, str] = {}
    for var, ev in parsed.anonymous.items():
        if var not in pointer_vars:
            continue
        struct = _match_struct(set(ev.offsets), layouts)
        if struct is not None:
            var_structs[var] = struct

    # ``vN = a0;`` aliases inherit the match (fixpoint for chains).
    changed = True
    while changed:
        changed = False
        for m in _ALIAS_RE.finditer(text):
            src = var_structs.get(m.group("src"))
            if src is not None and m.group("alias") not in var_structs:
                var_structs[m.group("alias")] = src
                changed = True

    if not var_structs:
        return NamingResult(code=text, applied=[])

    applied: list[dict[str, Any]] = []
    for var, struct in sorted(var_structs.items()):
        entry = parsed.anonymous.get(var)
        offsets = sorted(entry.offsets) if entry is not None else []
        applied.append({"var": var, "struct": struct, "offsets": [f"0x{o:x}" for o in offsets]})

    code = _ACCESS_RE.sub(
        lambda m: _rewrite_access(m, var_structs, layouts, elem_widths, pointer_vars), text
    )
    lines = code.split("\n")
    if lines:
        lines[0] = _SIG_TYPE_RE.sub(lambda m: _rewrite_sig_type(m, var_structs), lines[0], count=0)
    return NamingResult(code="\n".join(lines), applied=applied)


def _rewrite_sig_type(m: re.Match[str], var_structs: dict[str, str]) -> str:
    var = m.group("var")
    struct = var_structs.get(var)
    if struct is None:
        return m.group(0)
    base = m.group("base")
    # Only primitive/pseudo bases are renamed; a named struct param stays.
    if base not in TYPE_WIDTHS and base not in PSEUDO_TYPES:
        return m.group(0)
    return f"{struct} *{var}"


def _rewrite_access(
    m: re.Match[str],
    var_structs: dict[str, str],
    layouts: dict[str, FieldLayout],
    elem_widths: dict[str, int],
    pointer_vars: set[str] | None = None,
) -> str:
    if m.group("cvar") is not None:
        var, off, cast = m.group("cvar"), offset_value(m.group("coff")), m.group("cast")
        form = "deref"
    elif m.group("avar") is not None:
        var, cast = m.group("avar"), m.group("cast2")
        elem = elem_widths.get(var)
        if elem is None:
            return m.group(0)
        off = int(m.group("aidx")) * elem
        form = "deref"
    elif m.group("bvar") is not None:
        var = m.group("bvar")
        elem = elem_widths.get(var)
        if elem is None:
            return m.group(0)
        off = int(m.group("bidx")) * elem
        form = "bare_index"
    else:
        var, off = m.group("pvar"), offset_value(m.group("poff"))
        # A bare ``var + N`` on a non-pointer is integer arithmetic, not a
        # member access — never rewrite it.
        if pointer_vars is not None and var not in pointer_vars:
            return m.group(0)
        form = "bare"

    struct = var_structs.get(var)
    if struct is None:
        return m.group(0)
    field = layouts[struct].fields.get(off)
    if field is None:
        return m.group(0)
    name, width = field

    if form == "deref":
        cast_w = type_width(cast)
        if cast_w is None:  # named cast type — leave the access untouched
            return m.group(0)
        if cast_w == width:
            return f"{var}->{name}"
        return f"*({cast} *)&{var}->{name}"
    if form == "bare_index":
        elem = elem_widths.get(var) or 1
        if elem == width:
            return f"{var}->{name}"
        return f"*({_elem_type(elem)} *)&{var}->{name}"
    return f"&{var}->{name}"


def _elem_type(elem_width: int) -> str:
    """C type spelling for an array element of width *elem_width*."""
    return {1: "char", 2: "short", 4: "int", 8: "double"}.get(elem_width, "int")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Decompile a function, optionally applying known struct names.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    address: str = typer.Argument(..., help="Function VA (hex, e.g. 0x1000d350)"),
    decompiler: str = typer.Option(
        "kuna",
        "--decompiler",
        help="Decompiler backend: kuna, r2ghidra, r2dec, ghidra, auto",
    ),
    named: bool = typer.Option(False, "--named", help="Apply known struct names to the output"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Fetch one function's decompilation and print it (raw C, pipeable).

    ``--named`` additionally rewrites anonymous pointer variables to the
    project's declared structs (see module docstring); structs are read
    from the reversed sources and ``library_*.h`` headers.
    """
    cfg = require_config(target=target, json_mode=json_output)
    va = parse_va(address, json_mode=json_output)

    from rebrew.decompiler import fetch_decompilation

    code, backend = fetch_decompilation(decompiler, cfg.target_binary, va, cfg.root)
    if not code:
        error_exit(
            f"decompilation failed via '{decompiler}' for 0x{va:x} "
            f"(backend unavailable or unsupported address)",
            json_mode=json_output,
        )

    applied: list[dict[str, Any]] = []
    if named:
        from rebrew.sources import iter_library_headers, iter_sources
        from rebrew.struct_recover import existing_structs

        sources = list(iter_sources(cfg.reversed_dir, cfg))
        sources += list(iter_library_headers(cfg.reversed_dir, cfg))
        definitions = existing_structs(sources)
        pointer_width = int(getattr(cfg, "pointer_size", 4) or 4)
        result = apply_known_names(code, definitions, pointer_width=pointer_width)
        code = result.code
        applied = result.applied
        if not json_output:
            for a in applied:
                console.print(
                    f"[dim]named {a['var']} → {a['struct']} ({len(a['offsets'])} offset(s))[/dim]"
                )

    if json_output:
        json_print(
            {
                "va": f"0x{va:x}",
                "backend": backend,
                "named": bool(applied),
                "applied": applied,
                "code": code,
            }
        )
        return

    if named and not applied:
        console.print("[dim]no known struct matched this function's pointer accesses[/dim]")
    print(code)


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
