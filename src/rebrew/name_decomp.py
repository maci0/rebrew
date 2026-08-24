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


def _dim_value(s: str) -> int:
    """Parse a C array dimension (hex ``0x10`` or decimal ``4``)."""
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


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


def struct_field_layout(definition: str) -> FieldLayout:
    """Compute ``{offset: (field_name, width)}`` for a typedef struct body.

    Handles the guild/decomp conventions: typed primitives (``int flags``),
    pointer fields (``int *p`` → 4 on x86-32), explicit byte arrays
    (``char gap_0004[0x264260]`` → width 0x264260), and multi-dim arrays
    (``[2][4]`` → 8 elements).  Bitfields, embedded ``struct`` members, or
    anything else unsized mark the layout ``complete = False`` so it is
    never matched against evidence.
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
            width = 4  # x86-32 pointer
        elif base in TYPE_WIDTHS:
            width = TYPE_WIDTHS[base]
        else:
            width = None
        if width is None:
            lay.complete = False
            continue
        if m.group("arr"):
            count = 1
            for dim in _DIM_RE.findall(m.group("arr")):
                count *= _dim_value(dim)
            width *= count
        lay.fields[offset] = (m.group("name"), width)
        offset += width
    lay.size = offset
    return lay


def struct_definitions_to_layouts(definitions: dict[str, str]) -> dict[str, FieldLayout]:
    """Map struct name → parsed layout for every raw definition."""
    return {name: struct_field_layout(definition) for name, definition in definitions.items()}


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


@dataclass
class NamingResult:
    """Rewritten code plus what the pass applied."""

    code: str
    applied: list[dict[str, Any]]  # {var, struct, offsets: [...]}


def apply_known_names(text: str, definitions: dict[str, str]) -> NamingResult:
    """Rewrite *text* to use known structs for anonymous pointer variables.

    *definitions* maps struct name → raw ``typedef struct ...`` text (e.g.
    ``rebrew.struct_recover.existing_structs``).  Returns the rewritten code
    and the list of ``{var, struct, offsets}`` applications (empty when
    nothing matched).
    """
    layouts = struct_definitions_to_layouts(definitions)
    elem_widths = pointer_element_widths(text)

    # Anonymous pointer vars → evidence offsets (temps excluded already).
    parsed = parse_decomp_for_structs(text)
    var_structs: dict[str, str] = {}
    for var, ev in parsed.anonymous.items():
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

    code = _ACCESS_RE.sub(lambda m: _rewrite_access(m, var_structs, layouts, elem_widths), text)
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
        sources += list(iter_library_headers(cfg.reversed_dir))
        definitions = existing_structs(sources)
        result = apply_known_names(code, definitions)
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
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
