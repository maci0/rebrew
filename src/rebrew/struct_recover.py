"""struct_recover.py — recover struct definitions from decompiler output.

Decompilers (Kuna, Ghidra, r2ghidra, r2dec) emit member accesses at byte
offsets: ``this->field_8``, ``*(int *)(p + 0x10)``, ``(PlayerInfo *)p``
casts.  Collecting the offset → width evidence per named pointer base type
lets rebrew synthesize struct definitions the project can adopt — the
"recover more structs" workflow (e.g. for guild-rebrew's DieGildeAddOn
types).

Evidence sources parsed from decompiled C:

- ``->field_(0x)?N`` / ``->field_NNNN`` — Ghidra/Kuna-style auto-named
  members; the offset is the member name, the width defaults to 4 bytes
  (dword) because the name carries no width.
- ``*(T *)(p + 0xN)`` and ``*(T *)&p + 0xN`` — explicit casts; the
  width comes from *T* (int/undefined4/pointer → 4, short → 2, char → 1,
  double → 8, ...).  Offsets may be hex (``0x10``) or decimal (``3``) —
  decompilers disagree.
- ``*(T *)&p[10]`` / ``p[10]`` — Kuna indexes pointer params as arrays;
  the byte offset is index × element width of the declared base type.
- ``(T *)p`` casts and ``T *var`` declarations — they give the BASE TYPE a
  pointer is accessed through.

Named base types yield structs directly.  When a pointer has no usable type
(``int a0`` in Kuna output, Ghidra's ``undefined4 *param_1``) the offset
evidence is NOT lost: it is grouped by variable name as an *anonymous
candidate* (e.g. ``a0``), reported with its layout so the user can name the
type in Ghidra and re-run.  Candidates whose variable name is meaningful
(``pPlayer``, ``this``) get a synthesized type name with the Hungarian
pointer prefix stripped (``Player``); compiler temporaries (``v1``,
``local_8``, ``uVar2``) are noise and dropped.  Synthesized definitions
follow the guild convention::

    typedef struct name_s {
        int field_0;
        char gap_0004[0x10];
        ...
    } name;

The merge step compares against the project's existing structs (via
``rebrew.struct_parser``) and reports only NEW structs / new offsets beyond
the existing layout — never rewrites what is already declared.

Usage::

    rebrew recover-structs --all                      # every annotated function
    rebrew recover-structs --functions 0x401000,0x401100 --decompiler kuna
    rebrew recover-structs --all --apply src/common.h  # append new typedefs
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import (
    EXIT_ERROR,
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
)

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Evidence parsing
# ---------------------------------------------------------------------------

#: ``p->field_8`` / ``p->field_0x10`` / ``p->field_0008`` (Ghidra/Kuna);
#: the base pointer is optional — a cast may precede the access
#: (``((PlayerInfo *)raw)->field_8``), in which case there is no variable.
_FIELD_ACCESS_RE = re.compile(
    r"(?:(?P<var>[A-Za-z_]\w*)\s*->\s*)?field_0?x?(?P<off>[0-9a-fA-F]+)\b"
)
#: ``*(T *)(var + 0xN)`` / ``*(T *)(var + N)`` / ``*(T *)&var + 0xN`` — the
#: variable is captured so evidence can be attributed precisely, and the
#: offset accepts hex or decimal (Kuna emits both).
_CAST_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[A-Za-z_]\w*(?:\s+\w+)*?)\s*\*\s*\)\s*"
    r"(?:&?\s*(?P<var1>[A-Za-z_]\w*)\s*\+\s*(?P<off1>0x[0-9a-fA-F]+|\d+)"
    r"|\(\s*(?P<var2>[A-Za-z_]\w*)\s*\+\s*(?P<off2>0x[0-9a-fA-F]+|\d+)\s*\))"
)
#: ``(T *)p`` casts — base-type evidence; the variable is captured so
#: ``(PlayerInfo *)raw`` types later accesses through ``raw``.
_CAST_RE = re.compile(r"\(\s*(?P<type>[A-Za-z_]\w*)\s*\*\s*\)\s*(?P<var>[A-Za-z_]\w*)")
#: ``T *var`` declarations (incl. params) — base-type evidence.
_DECL_RE = re.compile(r"\b(?P<type>[A-Za-z_]\w*)\s*\*\s*(?P<var>[A-Za-z_]\w*)\b")
#: ``*(int *)&a0[10]`` — Kuna indexes pointer params as arrays; the byte
#: offset is index × element width of the declared base type.
_ARRAY_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[A-Za-z_]\w*(?:\s+\w+)*?)\s*\*\s*\)\s*&?\s*"
    r"(?P<var>[A-Za-z_]\w*)\s*\[\s*(?P<idx>\d+)\s*\]"
)
#: Bare ``a0[10]`` (no cast) — same evidence, element width only.  The
#: lookbehind keeps the ``&a0[10]`` cast-deref form from double-counting.
_ARRAY_IDX_RE = re.compile(r"(?<![\w&])(?P<var>[A-Za-z_]\w*)\s*\[\s*(?P<idx>\d+)\s*\]")

#: Pseudo-types that never name a recoverable struct.
PSEUDO_TYPES = frozenset(
    {
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
        "byte",
        "word",
        "dword",
        "qword",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "void",
        "bool",
        "uint",
        "ulong",
        "ushort",
        "uchar",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "size_t",
        "BOOL",
        "DWORD",
        "WORD",
        "BYTE",
        "LONG",
        "UINT",
        "ULONG",
    }
)

#: Cast type → access width in bytes.
TYPE_WIDTHS: dict[str, int] = {
    "char": 1,
    "uchar": 1,
    "unsigned char": 1,
    "byte": 1,
    "uint8": 1,
    "uint8_t": 1,
    "short": 2,
    "ushort": 2,
    "unsigned short": 2,
    "word": 2,
    "uint16": 2,
    "uint16_t": 2,
    "int": 4,
    "uint": 4,
    "unsigned int": 4,
    "long": 4,
    "ulong": 4,
    "unsigned long": 4,
    "undefined4": 4,
    "dword": 4,
    "uint32": 4,
    "uint32_t": 4,
    "int32": 4,
    "int32_t": 4,
    "float": 4,
    "BOOL": 4,
    "DWORD": 4,
    "WORD": 2,
    "BYTE": 1,
    "LONG": 4,
    "UINT": 4,
    "ULONG": 4,
    "double": 8,
    "undefined8": 8,
    "qword": 8,
    "uint64": 8,
    "uint64_t": 8,
    "int64": 8,
    "int64_t": 8,
    "long long": 8,
    "unsigned long long": 8,
}


def type_width(cast_type: str) -> int | None:
    """Width of *cast_type* when it is a primitive (None for named structs)."""
    t = cast_type.strip()
    if t in TYPE_WIDTHS:
        return TYPE_WIDTHS[t]
    # pointer-to-anything → 4 (x86-32)
    if t.endswith("*"):
        return 4
    return None


#: Compiler temporaries — never evidence of a struct base (Kuna ``v1``,
#: Ghidra ``local_8``/``uVar2``, r2ghidra ``var_10h``).
_TEMP_VAR_RE = re.compile(r"^(?:v\d+|(?:local|var)_[0-9a-fA-F_]+h?|[A-Za-z]{1,3}Var\d+)$")

#: Member offsets at or above this are absolute addresses (Kuna folds
#: ``global_base + index`` into ``var + 0xADDR``), not struct members.
_MAX_MEMBER_OFFSET = 0x1000000  # 16 MiB — far above any real x86-32 struct


def pointer_element_widths(text: str) -> dict[str, int]:
    """Map pointer variables to their element width when the declared base
    type is a primitive (``short *a0`` → 2, ``char *s`` → 1).

    Kuna types struct pointers as primitive arrays (``short *a0``) and
    indexes them (``a0[10]``); the byte offset is index × element width.
    ``rebrew.name_decomp`` uses this to rewrite array-index accesses.
    """
    out: dict[str, int] = {}
    for m in _DECL_RE.finditer(text):
        w = TYPE_WIDTHS.get(m.group("type"))
        if w is not None:
            out[m.group("var")] = w
    return out


#: Variable names meaningful enough to synthesize a type name from:
#: ``this``/``self``/``it``, Hungarian ``pPlayer``/``lpData``, or any
#: camelCase with an uppercase transition (``playerInfo``).
_SEMANTIC_VAR_RE = re.compile(
    r"^(?:this|self|it|(?:p|lp)[A-Z][A-Za-z0-9_]*|[a-z]+[A-Z][A-Za-z0-9_]*)$"
)


def _type_name_from_var(var: str) -> str:
    """Strip a Hungarian pointer prefix (``pX`` / ``lpX``) from *var*."""
    m = re.match(r"^(?:lp|p)(?=[A-Z])", var)
    return var[m.end() :] if m else var


def offset_value(off: str) -> int:
    """Parse a hex (``0x10``) or decimal (``3``) offset literal."""
    return int(off, 16) if off.lower().startswith("0x") else int(off, 10)


@dataclass
class StructEvidence:
    """Offset → (width, count) evidence for one named base type."""

    offsets: dict[int, dict[int, int]] = field(default_factory=dict)  # off → {width: count}


@dataclass
class ParseResult:
    """Evidence parsed from one decompilation.

    ``named`` maps a named base type to its offset evidence; ``anonymous``
    does the same for pointer variables whose type is unknown (grouped by
    variable name so offsets can be merged across functions).
    """

    named: dict[str, StructEvidence] = field(default_factory=dict)
    anonymous: dict[str, StructEvidence] = field(default_factory=dict)


def parse_decomp_for_structs(text: str, max_offset: int = _MAX_MEMBER_OFFSET) -> ParseResult:
    """Parse decompiled C into named + anonymous pointer evidence.

    The base type of a pointer is taken from its declaration/cast when it is
    a *named* type (not a pseudo-type); ``->field_N`` accesses and
    ``*(T *)(var + N)`` cast-derefs contribute offset/width evidence.  A
    type only yields evidence when its pointer appears BOTH in a
    declaration/cast AND with at least one member access — a bare
    declaration with no accesses tells us nothing about layout.

    Pointers with unknown or pseudo types are grouped by variable name into
    ``ParseResult.anonymous`` (compiler temporaries excluded); the caller
    decides what to synthesize from those.  *max_offset* filters out offsets
    that are really absolute addresses (pass the image base when known).
    """
    named: dict[str, StructEvidence] = {}
    anonymous: dict[str, StructEvidence] = {}

    # var → declared/cast base type; a NAMED type always wins over a
    # pseudo-type so ``(PlayerInfo *)raw`` overrides ``void *raw``.
    var_types: dict[str, str] = {}

    def _set_var_type(var: str, t: str) -> None:
        if t in PSEUDO_TYPES:
            var_types.setdefault(var, t)
        else:
            var_types[var] = t

    for m in _DECL_RE.finditer(text):
        _set_var_type(m.group("var"), m.group("type"))
    for m in _CAST_RE.finditer(text):
        _set_var_type(m.group("var"), m.group("type"))

    bases_with_pointers = {t for t in var_types.values() if t not in PSEUDO_TYPES}

    def _bump(container: dict[str, StructEvidence], base: str, offset: int, width: int) -> None:
        if offset >= max_offset:
            return
        ent = container.setdefault(base, StructEvidence())
        slots = ent.offsets.setdefault(offset, {})
        slots[width] = slots.get(width, 0) + 1

    def _record(var: str | None, offset: int, width: int) -> None:
        """Attribute one access: to a named base type, or an anonymous var."""
        if var:
            base = var_types.get(var)
            if base is not None and base not in PSEUDO_TYPES:
                _bump(named, base, offset, width)
                return
            if not _TEMP_VAR_RE.match(var):
                _bump(anonymous, var, offset, width)
            return
        # Var-less access (e.g. after a cast) — attribute to every named
        # base type known in this function (best approximation).
        for base in bases_with_pointers:
            _bump(named, base, offset, width)

    # Offset evidence from field accesses (offsets are always hex — the
    # ``field_10`` naming convention is hex; only cast-deref offsets vary).
    for m in _FIELD_ACCESS_RE.finditer(text):
        _record(m.group("var"), int(m.group("off"), 16), 4)

    # Width evidence from explicit casts.
    for m in _CAST_DEREF_RE.finditer(text):
        width = type_width(m.group("type"))
        if width is None:
            continue
        var = m.group("var1") or m.group("var2")
        off_str = m.group("off1") or m.group("off2")
        if var is None or off_str is None:
            continue
        _record(var, offset_value(off_str), width)

    # Array-index accesses (``*(int *)&a0[10]`` / ``v2[10]``) — Kuna types
    # struct pointers as primitive arrays; byte offset = index × element
    # width of the declared base type.
    for m in _ARRAY_DEREF_RE.finditer(text):
        width = type_width(m.group("type"))
        var = m.group("var")
        elem = TYPE_WIDTHS.get(var_types.get(var, ""))
        if width is None or elem is None:
            continue
        _record(var, int(m.group("idx")) * elem, width)
    for m in _ARRAY_IDX_RE.finditer(text):
        var = m.group("var")
        elem = TYPE_WIDTHS.get(var_types.get(var, ""))
        if elem is None:
            continue
        _record(var, int(m.group("idx")) * elem, elem)

    return ParseResult(named=named, anonymous=anonymous)


# ---------------------------------------------------------------------------
# Synthesis + merge
# ---------------------------------------------------------------------------


def _majority_width(slots: dict[int, int]) -> int:
    """The most-observed width at an offset (ties → largest)."""
    best = max(slots, key=lambda w: (slots[w], int(w)))
    return int(best)


def synthesize_struct(name: str, offsets: dict[int, dict[int, int]]) -> str:
    """Render ``typedef struct name_s { ... } name;`` for *offsets*.

    Fields are emitted at their offsets with the majority width; gaps are
    ``char gap_XXXX[0xN];`` padding (the guild/decomp convention).  The base
    is materialized from offset 0 via a gap when no evidence anchors it —
    never an invented field, which could overlap real evidence.
    """
    offsets = {int(k): v for k, v in offsets.items()}
    fields: list[str] = []
    prev_end = 0
    for offset, slots in sorted(offsets.items()):
        width = _majority_width(slots)
        if offset > prev_end:
            fields.append(f"\tchar gap_{prev_end:04X}[0x{offset - prev_end:x}];")
        fields.append(_field_line(offset, width))
        prev_end = offset + width
    return f"typedef struct {name}_s {{\n" + "\n".join(fields) + f"\n}} {name};\n"


def _field_line(offset: int, width: int) -> str:
    """Render one field line.  Known widths get typed fields; everything
    else stays an opaque byte array (safe for C89)."""
    type_for = {1: "char", 2: "short", 4: "int", 8: "double"}
    t = type_for.get(width)
    if t is None:
        return f"\tchar field_{offset:X}[0x{width:x}];"
    return f"\t{t} field_{offset:X};"


def existing_structs(sources: list[Path]) -> dict[str, str]:
    """Map existing struct name → raw definition text across *sources*."""
    from rebrew.struct_parser import extract_structs_from_file

    out: dict[str, str] = {}
    for src in sources:
        try:
            for definition in extract_structs_from_file(src):
                m = re.search(r"typedef struct\s+\w+\s*\{.*?\}\s*(\w+)\s*;", definition, re.S)
                if m:
                    out[m.group(1)] = definition
        except OSError:
            continue
    return out


def recover_structs(
    decompilations: list[tuple[int, str, str]],
    existing: dict[str, str] | None = None,
    max_offset: int = _MAX_MEMBER_OFFSET,
) -> list[dict[str, Any]]:
    """Aggregate evidence across decompilations and report recoverable structs.

    *decompilations* is ``[(va, symbol, decompiled_c), ...]``.  Returns a
    list of result dicts — one per named base type with offset evidence, plus
    one per anonymous pointer variable (``"anonymous": True``):

    - named: ``{"name", "anonymous": False, "new", "definition", "offsets",
      "evidence", "functions"}``; *new* = False when the project already
      declares a struct with that name (the definition is still offered, with
      only the new offsets called out when the existing layout is a prefix).
    - anonymous: ``{"name" (synthesized or the var), "anonymous": True,
      "semantic", "var", "new", "definition", "offsets", "evidence",
      "functions"}``; *semantic* = True when the variable name was meaningful
      enough to derive a type name from.
    """
    merged_named: dict[str, StructEvidence] = {}
    merged_anon: dict[str, tuple[StructEvidence, set[int]]] = {}
    total_evidence = 0
    for idx, (_va, _symbol, text) in enumerate(decompilations):
        parsed = parse_decomp_for_structs(text, max_offset=max_offset)
        for base, ev in parsed.named.items():
            if base not in merged_named:
                merged_named[base] = StructEvidence()
            for off, slots in ev.offsets.items():
                merged_named[base].offsets.setdefault(off, {})
                for w, c in slots.items():
                    merged_named[base].offsets[off][w] = (
                        merged_named[base].offsets[off].get(w, 0) + c
                    )
            total_evidence += sum(sum(s.values()) for s in ev.offsets.values())
        for var, ev in parsed.anonymous.items():
            ent, funcs = merged_anon.setdefault(var, (StructEvidence(), set()))
            for off, slots in ev.offsets.items():
                ent.offsets.setdefault(off, {})
                for w, c in slots.items():
                    ent.offsets[off][w] = ent.offsets[off].get(w, 0) + c
            funcs.add(idx)
            total_evidence += sum(sum(s.values()) for s in ev.offsets.values())

    existing = existing or {}
    results: list[dict[str, Any]] = []
    for name, ev in sorted(merged_named.items()):
        if not ev.offsets:
            continue
        definition = synthesize_struct(name, ev.offsets)
        results.append(
            {
                "name": name,
                "anonymous": False,
                "new": existing.get(name) is None,
                "definition": definition,
                "offsets": [f"0x{o:x}" for o in sorted(ev.offsets)],
                "evidence": sum(sum(s.values()) for s in ev.offsets.values()),
            }
        )
    for var, (ev, funcs) in sorted(merged_anon.items()):
        if not ev.offsets:
            continue
        semantic = bool(_SEMANTIC_VAR_RE.match(var))
        type_name = _type_name_from_var(var) if semantic else var
        definition = synthesize_struct(type_name, ev.offsets)
        results.append(
            {
                "name": type_name,
                "anonymous": True,
                "semantic": semantic,
                "var": var,
                "new": existing.get(type_name) is None,
                "definition": definition,
                "offsets": [f"0x{o:x}" for o in sorted(ev.offsets)],
                "evidence": sum(sum(s.values()) for s in ev.offsets.values()),
                "functions": len(funcs),
            }
        )
    results.sort(key=lambda r: (r["new"], r["name"]))
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Recover struct definitions from decompiler output.",
    rich_markup_mode="rich",
)


def _collect_functions(
    cfg: Any,
    functions: str | None,
    all_funcs: bool,
    filter_substr: str | None,
    json_output: bool,
) -> list[tuple[int, str]]:
    """Resolve the function set to decompile: explicit VAs, --all, or filtered."""
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import iter_sources, target_marker

    if functions:
        out: list[tuple[int, str]] = []
        for tok in functions.split(","):
            tok = tok.strip()
            if not tok:
                continue
            va = parse_va(tok, json_mode=json_output)
            out.append((va, f"0x{va:x}"))
        return out

    marker = target_marker(cfg)
    seen: set[int] = set()
    out = []
    for src in iter_sources(cfg.reversed_dir, cfg):
        annos = parse_c_file_multi(src, target_name=marker, metadata_dir=cfg.metadata_dir)
        for a in annos:
            if a.marker_type not in ("FUNCTION", "STUB", "LIBRARY"):
                continue
            if filter_substr and filter_substr.lower() not in (a.name or "").lower():
                continue
            if a.va in seen:
                continue
            seen.add(a.va)
            out.append((a.va, a.name or f"0x{a.va:x}"))
    if all_funcs is False and not functions and not out:
        error_exit(
            "pass --functions VA,VA, --all, or --filter SUBSTR to select functions",
            json_mode=json_output,
        )
    return sorted(out)


@app.callback(invoke_without_command=True)
def main(
    functions: str | None = typer.Option(
        None, "--functions", help="Comma-separated VAs to decompile"
    ),
    all_funcs: bool = typer.Option(False, "--all", help="Decompile every annotated function"),
    filter_substr: str | None = typer.Option(
        None, "--filter", help="Only functions whose name contains SUBSTR"
    ),
    decompiler: str = typer.Option(
        "kuna",
        "--decompiler",
        help="Decompiler backend: kuna, r2ghidra, r2dec, ghidra, auto",
    ),
    limit: int = typer.Option(
        0, "--limit", help="Cap the number of functions decompiled (0 = unlimited)"
    ),
    apply: Path | None = typer.Option(
        None, "--apply", help="Append new struct definitions to this file"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what --apply would write"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Recover struct definitions by decompiling functions and aggregating
    their member-access offsets per named pointer type."""
    cfg = require_config(target=target, json_mode=json_output)

    funcs = _collect_functions(cfg, functions, all_funcs, filter_substr, json_output)
    if limit and limit > 0:
        funcs = funcs[:limit]
    if not funcs:
        if json_output:
            json_print({"functions": 0, "structs": []})
        else:
            console.print("[dim]No functions selected.[/dim]")
        return

    from rebrew.decompiler import fetch_decompilation

    decompilations: list[tuple[int, str, str]] = []
    skipped = 0
    if not json_output:
        console.print(f"[bold]Decompiling {len(funcs)} function(s) via {decompiler}...[/bold]")
    for va, name in funcs:
        code, backend = fetch_decompilation(decompiler, cfg.target_binary, va, cfg.root)
        if not code:
            skipped += 1
            continue
        decompilations.append((va, name, code))

    if not decompilations:
        msg = (
            f"no decompilation obtained via '{decompiler}' ({skipped} function(s) skipped) — "
            "install the backend (kuna: github.com/Noelo-Lab/kuna; r2ghidra needs the "
            "ghidra plugin in rizin)"
        )
        if json_output:
            json_print({"error": msg, "decompiled": 0})
        else:
            console.print(f"[red]error:[/red] {msg}")
        raise typer.Exit(code=EXIT_ERROR)

    # Existing structs in the project, for the merge report.  Library headers
    # are included too — name_decomp.py scans them and recover_structs must
    # agree, or its "new" structs would duplicate ones already defined
    # (sync-review F15).
    from rebrew.sources import iter_library_headers, iter_sources

    sources = list(iter_sources(cfg.reversed_dir, cfg))
    sources += list(iter_library_headers(cfg.reversed_dir))
    existing = existing_structs(sources)
    # Offsets ≥ the image base are absolute addresses (Kuna folds
    # global_base + index into ``var + 0xADDR``) — never member offsets.
    max_offset = _MAX_MEMBER_OFFSET
    try:
        from rebrew.binary_loader import load_binary

        base = load_binary(cfg.target_binary).image_base
        if base > 0:
            max_offset = base
    except (OSError, ValueError):
        pass
    results = recover_structs(decompilations, existing=existing, max_offset=max_offset)

    # Anonymous candidates need a user-chosen name first — never auto-apply.
    new_structs = [r for r in results if r["new"] and not r["anonymous"]]
    if apply and new_structs and not dry_run:
        block = "\n\n".join(r["definition"] for r in new_structs)
        with apply.open("a", encoding="utf-8") as fh:
            fh.write("\n" + block)
        console.print(f"[green]Appended {len(new_structs)} struct(s) to {apply}[/green]")

    if json_output:
        json_print(
            {
                "decompiled": len(decompilations),
                "skipped": skipped,
                "structs": results,
                "applied": str(apply) if apply and new_structs and not dry_run else None,
            }
        )
        return

    console.print(
        f"\n[bold]{len(results)} recoverable struct(s)[/bold] "
        f"(from {len(decompilations)} decompiled function(s), {skipped} skipped):\n"
    )
    for r in results:
        if r["anonymous"]:
            hint = (
                "synthesized from var name — rename in Ghidra to stabilize"
                if r["semantic"]
                else "unnamed pointer — name the type in Ghidra, then re-run to synthesize"
            )
            console.print(
                f"[yellow]ANON[/yellow] {r['name']} (var {r['var']}) — "
                f"{len(r['offsets'])} offset(s), {r['evidence']} evidence, "
                f"{r['functions']} function(s)"
            )
            console.print(f"[dim]  {hint}[/dim]")
            console.print(r["definition"])
            continue
        tag = "[green]NEW[/green]" if r["new"] else "[dim]existing[/dim]"
        console.print(
            f"{tag} {r['name']} — {len(r['offsets'])} offset(s), {r['evidence']} evidence"
        )
        console.print(r["definition"])
    if dry_run and new_structs:
        console.print(
            f"[dim]--dry-run: {len(new_structs)} new struct(s) would be appended to {apply}[/dim]"
        )
    if not new_structs and results and not any(r["anonymous"] for r in results):
        console.print("[dim]No NEW structs — the recovered layouts are already declared.[/dim]")


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
