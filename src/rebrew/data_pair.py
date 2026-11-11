"""data_pair.py - Name a function's data operands alike in two targets that share its code.

Two binaries built from one source (a game's client variants) carry the same function at
different addresses, and its globals at different addresses too. A shared source that spells
a global as a raw address (``*(int *) 0x675170``) then matches only the target whose address
it spells. ``symbolize`` names such casts from base relocations, which most executables lack.

This pairs the two reference bodies instruction by instruction instead: every absolute data
operand (memory displacement or immediate inside a non-code section of each image) at the
same position gives one address pair. A named data row on one side yields the missing row on
the other side (same name, size, type and kind); disagreements are reported, never resolved.
``--rewrite`` then replaces the raw casts in the shared source with those names.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
lazy from pathlib import Path

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config


@dataclass(frozen=True)
class OperandPair:
    """One absolute data operand: its byte offset in the body and the address in each target."""

    offset: int
    a: int
    b: int


def pair_data_operands(
    code_a: bytes,
    va_a: int,
    code_b: bytes,
    va_b: int,
    is_data_a: Any,
    is_data_b: Any,
    cs_arch: int,
    cs_mode: int,
) -> list[OperandPair]:
    """Pair the absolute data operands of two bodies that are the same code.

    Raises ``ValueError`` when the bodies decode to different instruction streams.
    """
    import capstone
    from capstone import x86

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    ins_a = list(md.disasm(code_a, va_a))
    ins_b = list(md.disasm(code_b, va_b))
    if len(ins_a) != len(ins_b) or sum(i.size for i in ins_a) != len(code_a):
        raise ValueError("the two bodies decode to different instruction streams")
    out: list[OperandPair] = []
    for ia, ib in zip(ins_a, ins_b, strict=True):
        if ia.mnemonic != ib.mnemonic or ia.size != ib.size or len(ia.operands) != len(ib.operands):
            raise ValueError(
                f"bodies differ at +0x{ia.address - va_a:x}: {ia.mnemonic} / {ib.mnemonic}"
            )
        for oa, ob in zip(ia.operands, ib.operands, strict=True):
            if oa.type != ob.type:
                raise ValueError(f"bodies differ at +0x{ia.address - va_a:x}: operand kinds")
            if oa.type == x86.X86_OP_MEM and not (
                oa.mem.base or oa.mem.index or ob.mem.base or ob.mem.index
            ):
                a, b = oa.mem.disp & 0xFFFFFFFF, ob.mem.disp & 0xFFFFFFFF
            elif (
                oa.type == x86.X86_OP_IMM
                and ia.mnemonic not in ("call", "jmp")
                and not ia.mnemonic.startswith("j")
            ):
                a, b = oa.imm & 0xFFFFFFFF, ob.imm & 0xFFFFFFFF
            else:
                continue
            if is_data_a(a) and is_data_b(b):
                out.append(OperandPair(ia.address - va_a, a, b))
    return out


def _data_predicate(info: Any) -> Any:
    spans = [(s.va, s.va + s.size) for s in info.sections.values() if not s.is_code_section]
    return lambda va: any(lo <= va < hi for lo, hi in spans)


def _containing(
    rows: dict[int, dict[str, Any]], starts: list[int], va: int
) -> tuple[int, dict[str, Any]] | None:
    import bisect

    i = bisect.bisect_right(starts, va) - 1
    if i < 0:
        return None
    start = starts[i]
    row = rows[start]
    return (start, row) if va < start + max(int(row.get("size") or 1), 1) else None


def _create(row: dict[str, Any], action: str, occupied: Any, section: str | None) -> dict[str, Any]:
    """The missing side's row: the named side's identity, or a conflict when its start is taken."""
    return {
        "action": "conflict" if occupied else action,
        "name": row["name"],
        "size": row.get("size"),
        "type": row.get("type"),
        "kind": row.get("kind") or "GLOBAL",
        "section": section,
    }


def plan_pairs(
    pairs: list[OperandPair],
    rows_a: dict[int, dict[str, Any]],
    rows_b: dict[int, dict[str, Any]],
    sections_b: Any,
    sections_a: Any,
) -> list[dict[str, Any]]:
    """Classify each address pair: agree, conflict, create-a, create-b or unnamed."""
    starts_a, starts_b = sorted(rows_a), sorted(rows_b)
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for p in pairs:
        if (p.a, p.b) in seen:
            continue
        seen.add((p.a, p.b))
        ha, hb = _containing(rows_a, starts_a, p.a), _containing(rows_b, starts_b, p.b)
        ha = ha if ha is not None and ha[1].get("name") else None
        hb = hb if hb is not None and hb[1].get("name") else None
        rec: dict[str, Any] = {"offset": p.offset, "a": f"0x{p.a:08x}", "b": f"0x{p.b:08x}"}
        if ha is not None and hb is not None:
            same = ha[1]["name"] == hb[1]["name"] and p.a - ha[0] == p.b - hb[0]
            rec.update(
                action="agree" if same else "conflict",
                name=ha[1]["name"] if same else None,
                name_a=ha[1]["name"],
                name_b=hb[1]["name"],
                a_row=f"0x{ha[0]:08x}",
                b_row=f"0x{hb[0]:08x}",
            )
        elif ha is not None:
            new_start = p.b - (p.a - ha[0])
            rec.update(_create(ha[1], "create-b", rows_b.get(new_start), sections_b(new_start)))
            rec.update(a_row=f"0x{ha[0]:08x}", b_row=f"0x{new_start:08x}")
        elif hb is not None:
            new_start = p.a - (p.b - hb[0])
            rec.update(_create(hb[1], "create-a", rows_a.get(new_start), sections_a(new_start)))
            rec.update(a_row=f"0x{new_start:08x}", b_row=f"0x{hb[0]:08x}")
        else:
            rec["action"] = "unnamed"
        out.append(rec)
    return out


def _section_name(info: Any) -> Any:
    def name(va: int) -> str | None:
        for s in info.sections.values():
            if s.va <= va < s.va + s.size:
                return str(s.name)
        return None

    return name


def _module_rows(meta: Any, module: str) -> dict[int, dict[str, Any]]:
    from rebrew.metadata.data import load_data_metadata

    return {va: dict(r) for (m, va), r in load_data_metadata(meta).items() if m == module}


def pair(
    va_a: str = typer.Argument(..., help="Function VA in --from"),
    va_b: str = typer.Argument(..., help="Function VA in the selected --target"),
    from_target: str = typer.Option(
        ..., "--from", help="Target whose rows and addresses the shared source spells"
    ),
    size: int | None = typer.Option(
        None, "--size", help="Body size in bytes (default: the --from function row)"
    ),
    rewrite: Path | None = typer.Option(
        None, "--rewrite", help="Shared C source: replace raw --from address casts with the names"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Pair two targets' copies of one function and give their data operands one name."""
    from rebrew.config import target_module
    from rebrew.formats.binary_loader import capstone_config_for, extract_bytes_at_va, load_binary
    from rebrew.metadata.data import record_data_rows
    from rebrew.metadata.functions import load_metadata
    from rebrew.utils import parse_int_literal

    cfg_b = require_config(target=target, json_mode=json_output)
    cfg_a = require_config(target=from_target, json_mode=json_output)
    a_va, b_va = parse_int_literal(va_a), parse_int_literal(va_b)
    mod_a, mod_b = target_module(cfg_a), target_module(cfg_b)
    if size is None:
        size = int(load_metadata(cfg_a.metadata_dir).get((mod_a, a_va), {}).get("size") or 0)
    if size <= 0:
        error_exit(f"no size for {mod_a}.0x{a_va:08x}; pass --size", json_mode=json_output)
    info_a, info_b = load_binary(cfg_a.target_binary), load_binary(cfg_b.target_binary)
    code_a = extract_bytes_at_va(info_a, a_va, size, trim_padding=False)
    code_b = extract_bytes_at_va(info_b, b_va, size, trim_padding=False)
    if not code_a or not code_b or len(code_a) != size or len(code_b) != size:
        error_exit("cannot read both bodies at the given addresses", json_mode=json_output)
    try:
        pairs = pair_data_operands(
            code_a,
            a_va,
            code_b,
            b_va,
            _data_predicate(info_a),
            _data_predicate(info_b),
            *capstone_config_for(info_a),
        )
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    plan = plan_pairs(
        pairs,
        _module_rows(cfg_a.metadata_dir, mod_a),
        _module_rows(cfg_b.metadata_dir, mod_b),
        _section_name(info_b),
        _section_name(info_a),
    )
    writes = [
        {
            "module": mod_b if p["action"] == "create-b" else mod_a,
            "va": int(p["b_row" if p["action"] == "create-b" else "a_row"], 16),
            "identity": {"kind": p["kind"], "name": p["name"]},
            "fill": {k: p[k] for k in ("size", "type", "section") if p.get(k)},
        }
        for p in plan
        if p["action"] in ("create-a", "create-b")
    ]
    rewrites: list[dict[str, Any]] = []
    if rewrite is not None:
        rewrites = _rewrite_source(rewrite, plan, dry_run=dry_run)
    if not dry_run and writes:
        record_data_rows(cfg_a.metadata_dir, writes)
    report = {
        "from": mod_a,
        "target": mod_b,
        "dry_run": dry_run,
        "pairs": plan,
        "created": len(writes),
        "rewrites": rewrites,
    }
    if json_output:
        json_print(report)
        return
    verb = "Would create" if dry_run else "Created"
    console.print(f"{len(plan)} data operand pair(s); {verb} {len(writes)} row(s).")
    for p in plan:
        console.print(
            f"  {p['action']:9} {p['a']} <-> {p['b']} {p.get('name') or p.get('name_a') or ''}"
        )


def _rewrite_source(
    path: Path, plan: list[dict[str, Any]], *, dry_run: bool
) -> list[dict[str, Any]]:
    """Replace raw --from address casts with ``&name`` and declare the names."""
    from rebrew.c_parser import pointer_cast_literals
    from rebrew.cast_rewrite import declare_externs, rewrite_casts
    from rebrew.utils import atomic_write_text, is_safe_c_ident, read_source_text

    # Row starts only: an interior operand needs ``(char *) &name + off`` and is left for review.
    names = {
        int(p["a"], 16): p["name"]
        for p in plan
        if p["action"] in ("agree", "create-a", "create-b")
        and p.get("name")
        and is_safe_c_ident(p["name"])
        and p["a"] == p["a_row"]
    }
    text, _ = read_source_text(path)
    targets: dict[str, dict[int, str]] = {}
    for lit in pointer_cast_literals(text):
        if lit.value in names:
            targets.setdefault(lit.function, {})[lit.value] = "&" + names[lit.value]
    new_text, rows = rewrite_casts(text, targets, set())
    used = sorted({names[v] for fn in targets.values() for v in fn})
    new_text, declared = declare_externs(new_text, used)
    if not dry_run and new_text != text:
        atomic_write_text(path, new_text)
    return [*rows, *({"declared": d} for d in declared)]
