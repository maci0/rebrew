"""analyze.py — one-shot intelligence dossier for a target binary.

Combines the per-tool recon pieces into a single report: binary metadata
and sections, toolchain detection (DIE -> PDB -> heuristics), string census
with cross-references, import table + IAT stubs, a code-reference profile,
reversed-function coverage, dispatch-table detection, and (when the project
has FLIRT signatures) library identification.

Best-effort by design: every section is independently optional.  A binary
without PDB/flirt_sigs/function list still yields the sections that apply,
and one broken backend (e.g. diec missing) never aborts the others.

    rebrew analyze                       # project target
    rebrew analyze other.exe             # any binary on disk
    rebrew analyze --json                # machine-readable dossier
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import TargetOption, json_print
from rebrew.config import load_config

console = Console(stderr=True)

app = typer.Typer(
    help="One-shot intelligence dossier for a target binary.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew analyze · · · · · · · · · · · · Analyze the project target\n\n"
        "  rebrew analyze other.exe · · · · · · · Analyze a specific binary\n\n"
        "  rebrew analyze --json · · · · · · · · · Machine-readable dossier\n\n"
        "[bold]Sections:[/bold]\n\n"
        "  Binary layout (format/sections) · toolchain detection\n"
        "  Strings + references · imports + IAT stubs · reference profile\n"
        "  Reversed-function coverage · dispatch tables · FLIRT (when sigs exist)\n\n"
        "[dim]Best-effort: a missing PDB, diec, or flirt_sigs/ only skips that section.[/dim]"
    ),
)


def _section_dicts(info: Any) -> dict[str, dict[str, int]]:
    """Convert BinaryInfo sections into the {name: {va, size, ...}} dict shape."""
    return {
        s.name: {
            "va": s.va,
            "size": s.size,
            "file_offset": s.file_offset,
            "raw_size": s.raw_size,
        }
        for s in info.sections.values()
    }


def _collect_binary_meta(info: Any) -> dict[str, Any]:
    """Format-agnostic binary metadata: format, base, sections."""
    return {
        "format": info.format,
        "image_base": info.image_base,
        "text_va": info.text_va,
        "text_size": info.text_size,
        "sections": [
            {
                "name": s.name,
                "va": f"0x{s.va:08x}",
                "size": s.size,
                "file_offset": s.file_offset,
                "raw_size": s.raw_size,
            }
            for s in info.sections.values()
        ],
    }


def _collect_toolchain(binary: Path) -> dict[str, Any] | None:
    """Run the layered toolchain detector; None when it fails entirely."""
    from rebrew.toolchain_detect import detect_toolchain

    try:
        info = detect_toolchain(binary)
    except Exception:  # noqa: BLE001 — best-effort dossier section
        return None
    return {
        "family": info.family,
        "version_hint": info.version_hint,
        "confidence": info.confidence,
        "detected_by": info.detected_by,
        "flags": info.flags,
        "evidence": info.evidence,
    }


def _collect_strings(info: Any, min_len: int, top_n: int) -> dict[str, Any]:
    """String census: count + the most-referenced strings."""
    from rebrew.analysis import iter_strings, string_refs

    strings = iter_strings(info, min_len=min_len)
    if not strings:
        return {"count": 0, "top": []}
    refs = string_refs(info, strings)
    ref_counts = {s.va: len(refs.get(s.va, [])) for s in strings}
    top = sorted(strings, key=lambda s: (ref_counts.get(s.va, 0), s.size), reverse=True)[:top_n]
    return {
        "count": len(strings),
        "top": [
            {
                "va": f"0x{s.va:08x}",
                "size": s.size,
                "kind": s.kind,
                "section": s.section,
                "refs": ref_counts.get(s.va, 0),
                "text": s.text[:120],
            }
            for s in top
        ],
    }


def _collect_imports(binary: Path) -> dict[str, Any]:
    """Import table + IAT stub summary (PE only; empty otherwise)."""
    from rebrew.binary_loader import is_ne, load_binary
    from rebrew.imports import find_import_stubs, parse_imports

    # 16-bit NE: the loader parses the module reference + imported names
    # tables directly (Borland Delphi/Turbo Pascal Windows targets).  The
    # per-import table layout varies between Borland linkers and is not yet
    # decoded, so the dossier reports the imported module blocks (each is a
    # separate ordinal-import group) rather than unreliable per-import rows.
    if is_ne(binary):
        info = load_binary(binary)
        dlls = Counter[str]()
        for mod in info.ne_imports:  # type: ignore[attr-defined]
            dlls[mod.module] += 1
        return {
            "count": sum(dlls.values()),
            "dlls": [{"dll": d, "count": c} for d, c in dlls.most_common()],
            "iat_stubs": 0,
            "entries": [],
        }

    imports = parse_imports(binary)
    dlls = Counter[str]()
    for rec in imports:
        dlls[str(rec.get("dll", ""))] += 1
    try:
        stubs = find_import_stubs(binary)
    except Exception:  # noqa: BLE001 — stub scan is best-effort
        stubs = {}
    return {
        "count": len(imports),
        "dlls": [{"dll": d, "count": c} for d, c in dlls.most_common()],
        "iat_stubs": len(stubs),
        "entries": [
            {
                "dll": rec.get("dll", ""),
                "name": rec.get("name", ""),
                "iat_va": f"0x{int(rec['iat_va']):08x}",
            }
            for rec in imports
        ],
    }


def _collect_references(info: Any) -> dict[str, Any]:
    """Code-reference profile: total references broken down by kind."""
    from rebrew.analysis import scan_references

    try:
        refs = scan_references(info)
    except Exception:  # noqa: BLE001 — disassembly is best-effort
        return {"total": 0, "by_kind": {}}
    kinds = Counter(r.kind for r in refs)
    return {"total": len(refs), "by_kind": dict(kinds.most_common())}


def _collect_far_calls(binary: Path) -> list[dict[str, Any]] | None:
    """Catalog distinct 16-bit far-call targets (16-bit NE only).

    Delphi 1.0 code calls the RTL and other segments with ``lcall seg:off``.
    Selectors ≤ the segment count map to segment indices (Borland's index
    marker convention); higher selectors are loader-assigned (system/RTL)
    and reported unmapped.  Returns ``[{selector, offset, count, segment}]``
    sorted by count, or None for non-NE binaries.
    """
    from collections import Counter

    from rebrew.analysis import _ne_code_segments, extract_bytes, section_range
    from rebrew.binary_loader import is_ne, load_binary

    if not is_ne(binary):
        return None
    try:
        info = load_binary(binary)
    except Exception:  # noqa: BLE001 — best-effort dossier section
        return None

    seg_count = info.ne_header.segment_count  # type: ignore[attr-defined]
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    md.detail = True
    targets: Counter[tuple[int, int]] = Counter()
    for name in _ne_code_segments(info):
        rng = section_range(info, name)
        if rng is None:
            continue
        va, size = rng
        raw = extract_bytes(info, va, size)
        for insn in md.disasm(raw[2:], va + 2):  # skip Borland marker
            if insn.mnemonic == "lcall" and len(insn.operands) >= 2:
                seg = int(insn.operands[0].imm)
                off = int(insn.operands[1].imm)
                targets[(seg, off)] += 1
    out = []
    for (seg, off), count in targets.most_common(60):
        out.append(
            {
                "selector": f"0x{seg:04x}",
                "offset": f"0x{off:04x}",
                "count": count,
                # Selectors at or below the segment count follow Borland's
                # index convention (the segment's own \\xNN\\x00 marker).
                "segment": seg if 1 <= seg <= seg_count else None,
            }
        )
    return out


def _collect_functions(cfg: Any) -> dict[str, Any] | None:
    """Reversed-function coverage from the project's function data."""
    from rebrew.naming import load_data

    try:
        ghidra_funcs, existing, _covered = load_data(cfg)
    except Exception:  # noqa: BLE001 — coverage needs the function list
        return None
    total_bytes = sum(getattr(f, "size", 0) or 0 for f in ghidra_funcs)
    return {
        "total": len(ghidra_funcs),
        "covered": len(existing),
        "total_bytes": total_bytes,
    }


def _collect_near_match(cfg: Any) -> list[dict[str, Any]] | None:
    """NEAR_MATCHING functions with their blocker guidance.

    The blocker text (written by ``near-diag --fix-blocker`` / ``diff
    --fix-blocker``) carries the dominant verdict + the GA mutation
    operators to try — the actionable next step per function.
    """
    metadata_dir = getattr(cfg, "metadata_dir", None)
    if metadata_dir is None:
        return None
    from rebrew.metadata import load_metadata

    items: list[dict[str, Any]] = []
    try:
        for (_module, va), entry in load_metadata(metadata_dir).items():
            if entry.get("status") == "NEAR_MATCHING":
                items.append(
                    {
                        "va": f"0x{va:08x}",
                        "blocker": entry.get("blocker", ""),
                    }
                )
    except Exception:  # noqa: BLE001 — best-effort dossier section
        return None
    items.sort(key=lambda i: i["va"])
    return items


def _collect_dispatch(info: Any) -> list[dict[str, Any]]:
    """Dispatch-table / vtable detection in the data sections."""
    from rebrew.data import find_dispatch_tables

    try:
        tables = find_dispatch_tables(
            info.data, _section_dicts(info), {}, ptr_size=4, min_entries=3
        )
    except Exception:  # noqa: BLE001 — best-effort
        return []
    return [
        {
            "va": f"0x{t.va:08x}",
            "section": t.section,
            "entries": t.num_entries,
            "resolved": t.resolved,
        }
        for t in tables
    ]


def _collect_flirt(cfg: Any, info: Any) -> dict[str, Any] | None:
    """FLIRT library identification — only when the project has signatures.

    Returns None (section skipped) when no .sig/.pat files exist, the scan
    finds no .text, or anything in the pipeline fails — a dossier never
    aborts over missing optional data.
    """
    sig_dir = cfg.root / "flirt_sigs" if getattr(cfg, "root", None) else None
    if sig_dir is None or not sig_dir.is_dir():
        return None
    sig_files = list(sig_dir.glob("*.sig")) + list(sig_dir.glob("*.pat"))
    if not sig_files:
        return None

    import warnings

    import flirt

    from rebrew.binary_loader import load_binary
    from rebrew.flirt import load_signatures, match_text

    try:
        sigs = load_signatures(str(sig_dir))
        if not sigs:
            return None
        matcher = flirt.compile(sigs)
        info = load_binary(cfg.target_binary)
        text_sec = info.sections.get(".text") or info.sections.get("__text")
        if text_sec is None:
            return None
        code_data = info.data[text_sec.file_offset : text_sec.file_offset + text_sec.raw_size]
        matches: list[dict[str, Any]] = []
        names_seen: set[str] = set()
        for m in match_text(matcher, code_data, text_sec.va):
            if m["name"] not in names_seen:
                names_seen.add(m["name"])
                matches.append({"va": f"0x{m['va']:08x}", "size": m["size"], "name": m["name"]})
        return {"signature_count": len(sigs), "matches": matches}
    except Exception as exc:  # noqa: BLE001
        warnings.warn(f"FLIRT section skipped: {exc}", stacklevel=2)
        return None


def _collect_library(cfg: Any) -> list[dict[str, Any]]:
    """Library-glue view: which VAs are library functions (identify-library)."""
    from rebrew.identify_library import collect_candidates

    try:
        candidates = collect_candidates(cfg)
    except Exception:  # noqa: BLE001 — best-effort section
        return []
    return [
        {
            "va": f"0x{c.va:08x}",
            "name": c.name,
            "module": c.module,
            "kind": c.kind,
            "confidence": round(c.confidence, 2),
        }
        for c in candidates
    ]


def build_dossier(
    cfg: Any,
    binary: Path,
    *,
    min_len: int = 4,
    top_n: int = 10,
) -> dict[str, Any]:
    """Assemble the full intelligence dossier for *binary*.

    Every section is independently collected; failures degrade to a
    documented null/empty value instead of raising.  This is the single
    testable entry point (mirrors ``collect_status``).
    """
    from rebrew.binary_loader import load_binary

    info = load_binary(binary)
    dossier: dict[str, Any] = {
        "binary": str(binary),
        "meta": _collect_binary_meta(info),
        "toolchain": _collect_toolchain(binary),
        "strings": _collect_strings(info, min_len, top_n),
        "imports": _collect_imports(binary),
        "references": _collect_references(info),
        "far_calls": _collect_far_calls(binary),
        "functions": _collect_functions(cfg),
        "near_match": _collect_near_match(cfg),
        "dispatch_tables": _collect_dispatch(info),
        "flirt": _collect_flirt(cfg, info),
        "library": _collect_library(cfg),
    }
    return dossier


# ---------------------------------------------------------------------------
# Per-function drill (--function) and Markdown report (--output)
# ---------------------------------------------------------------------------


def _function_dossier(cfg: Any, info: Any, va: int) -> dict[str, Any]:
    """Per-function recon dossier via rebrew describe's builder."""
    from rebrew.describe import build_dossier

    return build_dossier(cfg, info, va)


def _render_function_terminal(fn: dict[str, Any]) -> None:
    """Render the --function drill as rich terminal output."""
    console.print(
        f"\n[bold]Function:[/bold] {fn['name']} ([cyan]0x{fn['va']:08x}[/cyan], "
        f"{fn['size'] or '?'} bytes, {fn['status'] or 'no status'})"
    )
    if fn.get("cflags"):
        console.print(f"  [dim]cflags: {fn['cflags']}[/dim]")
    if fn.get("blocker"):
        console.print(f"  [yellow]blocker: {fn['blocker']}[/yellow]")
    if fn.get("note"):
        console.print(f"  [dim]note: {fn['note']}[/dim]")

    for label, key in (
        ("Callers", "callers"),
        ("Callees", "callees"),
        ("Strings", "strings"),
        ("Globals", "globals"),
        ("Imports", "imports"),
    ):
        rows = fn.get(key) or []
        console.print(f"[bold]{label}:[/bold]")
        if not rows:
            console.print("  [dim]none[/dim]")
        for r in rows[:12]:
            console.print(f"  {r}")
        if len(rows) > 12:
            console.print(f"  [dim]... and {len(rows) - 12} more[/dim]")


def _render_markdown(dossier: dict[str, Any], fn: dict[str, Any] | None) -> str:
    """Render the full dossier as a Markdown report (for --output)."""
    meta = dossier["meta"]
    out: list[str] = [
        f"# Rebrew Analysis — `{dossier['binary']}`",
        "",
        f"- Format: `{meta['format']}`, image base `0x{meta['image_base']:x}`",
        f"- .text: `0x{meta['text_va']:x}` ({meta['text_size']} bytes)",
        "",
        "## Sections",
        "",
        "| Name | VA | Size | Raw size | File offset |",
        "|---|---|---|---|---|",
    ]
    for sec in meta["sections"]:
        out.append(
            f"| {sec['name']} | {sec['va']} | {sec['size']} | "
            f"{sec['raw_size']} | {sec['file_offset']} |"
        )

    tc = dossier["toolchain"]
    out += ["", "## Toolchain"]
    if tc and tc["family"] != "unknown":
        out.append(
            f"- Family: `{tc['family']}` ({tc['version_hint'] or 'unknown version'}, {tc['confidence']} confidence)"
        )
        if tc["flags"]:
            out.append(f"- Flags: `{' '.join(tc['flags'])}`")
        out.append(f"- Detected by: `{tc['detected_by'] or 'heuristics'}`")
        for e in tc["evidence"]:
            out.append(f"  - {e}")
    else:
        out.append("- Not identified")

    strings = dossier["strings"]
    out += ["", "## Strings", "", f"{strings['count']} found.", ""]
    if strings["top"]:
        out += ["| VA | Size | Kind | Refs | Text |", "|---|---|---|---|---|"]
        for s in strings["top"]:
            out.append(f"| {s['va']} | {s['size']} | {s['kind']} | {s['refs']} | `{s['text']}` |")

    imports = dossier["imports"]
    out += ["", "## Imports", "", f"{imports['count']} APIs."]
    if imports["dlls"]:
        out += ["", "| DLL | Count |", "|---|---|"]
        for d in imports["dlls"]:
            out.append(f"| {d['dll']} | {d['count']} |")

    refs = dossier["references"]
    out += ["", "## References", "", f"{refs['total']} total."]
    if refs["by_kind"]:
        out.append("")
        for kind, count in refs["by_kind"].items():
            out.append(f"- {kind}: {count}")

    funcs = dossier["functions"]
    if funcs:
        out += [
            "",
            "## Reversed functions",
            "",
            f"{funcs['covered']}/{funcs['total']} covered ({funcs['total_bytes']} bytes).",
        ]

    near_match = dossier.get("near_match") or []
    if near_match:
        out += ["", "## NEAR_MATCHING (blocked)", ""]
        for nm in near_match:
            blocker = nm["blocker"] or "(no blocker documented)"
            out.append(f"- `{nm['va']}` — {blocker[:100]}")

    dispatch = dossier["dispatch_tables"]
    if dispatch:
        out += ["", "## Dispatch tables", ""]
        for t in dispatch:
            out.append(
                f"- `{t['va']}` ({t['section']}) — {t['entries']} entries, {t['resolved']} resolved"
            )

    library = dossier.get("library") or []
    if library:
        out += ["", "## Library functions", ""]
        for lib in library:
            out.append(
                f"- `{lib['va']}` — {lib['name']} ({lib['module']}, {lib['kind']}, "
                f"conf {lib['confidence']:.2f})"
            )

    flirt_result = dossier["flirt"]
    out += ["", "## FLIRT"]
    if flirt_result is not None:
        out.append(
            f"{len(flirt_result['matches'])} library function(s) from {flirt_result['signature_count']} signatures."
        )
        for m in flirt_result["matches"][:50]:
            out.append(f"- `{m['va']}` — {m['name']} ({m['size']}B)")
    else:
        out.append("Skipped (no `flirt_sigs/` in project).")

    if fn is not None:
        out += [
            "",
            "## Function drill",
            "",
            f"### `{fn['name']}` — `0x{fn['va']:08x}` ({fn['size'] or '?'}B, {fn['status'] or 'no status'})",
        ]
        if fn.get("cflags"):
            out.append(f"- cflags: `{fn['cflags']}`")
        if fn.get("blocker"):
            out.append(f"- blocker: {fn['blocker']}")
        if fn.get("note"):
            out.append(f"- note: {fn['note']}")
        for label, key in (
            ("Callers", "callers"),
            ("Callees", "callees"),
            ("Strings", "strings"),
            ("Globals", "globals"),
            ("Imports", "imports"),
        ):
            rows = fn.get(key) or []
            out += ["", f"### {label}", ""]
            if not rows:
                out.append("_none_")
            for r in rows[:30]:
                out.append(f"- {r}")

    out.append("")
    return "\n".join(out)


@app.callback(invoke_without_command=True)
def main(
    binary: Path | None = typer.Argument(
        None,
        help="Binary path (required when no project is present; default: project target binary)",
    ),
    min_len: int = typer.Option(4, "--min-len", help="Minimum string length to report"),
    top_strings: int = typer.Option(
        10, "--top-strings", help="How many most-referenced strings to list"
    ),
    function_va: str | None = typer.Option(
        None,
        "--function",
        help="Drill into one function (hex VA): callers, callees, strings, imports.",
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write a Markdown report to this path instead of the terminal."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """One-shot intelligence dossier for a target binary."""
    from rebrew.cli import error_exit

    cfg: Any
    try:
        cfg = load_config(target=target)
    except FileNotFoundError:
        # Standalone mode: no project — the binary argument is required and
        # project-scoped dossier sections (FLIRT sigs, library headers,
        # near-match metadata) are skipped automatically (build_dossier
        # guards every cfg access).
        if binary is None:
            error_exit(
                "No rebrew-project.toml found and no binary given. "
                "Run inside a project or pass a binary path.",
                json_mode=json_output,
            )
        from types import SimpleNamespace

        cfg = SimpleNamespace(
            root=None,
            target_binary=binary,
            metadata_dir=None,
            marker="",
            target_name=binary.stem,
            crt_sources={},
            reversed_dir=Path("/nonexistent"),  # no sources -> no CRT/library annotations
            source_ext=".c",
        )
    else:
        if binary is None:
            binary = cfg.target_binary

    if json_output and output is not None:
        error_exit("--output cannot be combined with --json", json_mode=True)

    fn_dossier: dict[str, Any] | None = None
    try:
        dossier = build_dossier(cfg, binary, min_len=min_len, top_n=top_strings)
        if function_va is not None:
            from rebrew.binary_loader import load_binary
            from rebrew.cli import parse_va

            va = parse_va(function_va, json_mode=json_output)
            info = load_binary(binary)
            fn_dossier = _function_dossier(cfg, info, va)
    except (OSError, KeyError, ValueError) as e:
        from rebrew.cli import error_exit

        error_exit(f"Analyze failed: {e}", json_mode=json_output)

    if json_output:
        json_print(dossier)
        return

    if output is not None:
        from rebrew.utils import atomic_write_text

        atomic_write_text(output, _render_markdown(dossier, fn_dossier))
        console.print(f"[green]Wrote {output}[/green]")
        if fn_dossier is not None:
            console.print(f"[green]Included function drill for 0x{fn_dossier['va']:08x}[/green]")
        return

    # --- Rich terminal rendering ---
    meta = dossier["meta"]
    console.print(
        f"[bold]{dossier['binary']}[/bold] ([cyan]{meta['format']}[/cyan], "
        f"image base [cyan]0x{meta['image_base']:x}[/cyan])"
    )

    table = Table(title="Sections", box=None)
    table.add_column("Name")
    table.add_column("VA", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Raw size", justify="right")
    table.add_column("File offset", justify="right")
    for sec in meta["sections"]:
        table.add_row(
            sec["name"],
            sec["va"],
            f"{sec['size']:,}",
            f"{sec['raw_size']:,}",
            str(sec["file_offset"]),
        )
    console.print(table)

    tc = dossier["toolchain"]
    if tc and tc["family"] != "unknown":
        console.print(
            f"[bold]Toolchain:[/bold] {tc['family']} ({tc['version_hint'] or 'unknown version'}, "
            f"{tc['confidence']} confidence)"
            + (f", flags: {' '.join(tc['flags'])}" if tc["flags"] else "")
        )
    else:
        console.print("[dim]Toolchain: not identified[/dim]")

    strings = dossier["strings"]
    console.print(f"[bold]Strings:[/bold] {strings['count']} found")
    for s in strings["top"]:
        console.print(f"  [dim]0x{s['va']}[/dim] ({s['refs']} refs): {s['text']!r}")

    imports = dossier["imports"]
    console.print(
        f"[bold]Imports:[/bold] {imports['count']} APIs from {len(imports['dlls'])} DLLs"
        + (f", {imports['iat_stubs']} IAT stubs" if imports["iat_stubs"] else "")
    )
    for d in imports["dlls"]:
        console.print(f"  {d['dll']} ({d['count']})")

    refs = dossier["references"]
    if refs["total"]:
        kinds = ", ".join(f"{k}={c}" for k, c in refs["by_kind"].items())
        console.print(f"[bold]References:[/bold] {refs['total']} ({kinds})")

    funcs = dossier["functions"]
    if funcs:
        console.print(
            f"[bold]Reversed:[/bold] {funcs['covered']}/{funcs['total']} functions "
            f"({funcs['total_bytes']:,} bytes in function list)"
        )

    near_match = dossier.get("near_match") or []
    if near_match:
        console.print(f"[bold]NEAR_MATCHING:[/bold] {len(near_match)} blocked function(s)")
        for nm in near_match[:10]:
            console.print(f"  [dim]0x{nm['va']}[/dim] {nm['blocker'][:70]}")
        if len(near_match) > 10:
            console.print(f"  [dim]... and {len(near_match) - 10} more[/dim]")

    dispatch = dossier["dispatch_tables"]
    if dispatch:
        console.print(f"[bold]Dispatch tables:[/bold] {len(dispatch)} detected")
        for t in dispatch[:10]:
            console.print(
                f"  [dim]0x{t['va']}[/dim] ({t['section']}, {t['entries']} entries, {t['resolved']} resolved)"
            )

    library = dossier.get("library") or []
    if library:
        console.print(f"[bold]Library functions:[/bold] {len(library)} identified")
        for lib in library[:10]:
            console.print(
                f"  [dim]0x{lib['va']}[/dim] {lib['name']} ({lib['module']}, "
                f"{lib['kind']}, conf {lib['confidence']:.2f})"
            )

    flirt_result = dossier["flirt"]
    if flirt_result is not None:
        console.print(
            f"[bold]FLIRT:[/bold] {len(flirt_result['matches'])} library function(s) "
            f"identified from {flirt_result['signature_count']} signatures"
        )
    else:
        console.print("[dim]FLIRT: skipped (no flirt_sigs/ in project)[/dim]")

    if fn_dossier is not None:
        _render_function_terminal(fn_dossier)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
