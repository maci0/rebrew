"""residue.py — how far is the build from byte identity, after postlink?

Applies the postlink fixers to the linked image, diffs the result against
the reference section by section, and attributes the remaining ``.text``
bytes to the functions ``rebrew verify`` reports as not byte-matched.
Read the result as the *remaining work*: everything outside ``.text`` is
either produced by the link already or copied from the layout package, so
a difference there means a pipeline bug, while the ``.text`` residue is
the code that still has to be made to match.

This is the linked truth that object scores (``rebrew test``'s
``match_count``, ``rebrew diagnose probe``'s ``aligned``) only proxy — a size change
anywhere moves every byte after it, so only this number decides whether a
candidate lands.

Generalized from guild-rebrew's ``scripts/postlink_residual.py`` +
``scripts/residue_diff.py`` + ``scripts/linktest.sh`` (MSVC6/x86-32
campaign).  Layout package, binary paths, and image base resolve from the
project config — no hardcoded ``build/split_poc.dll`` or ``0x10000000``.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

import typer
from rich.cells import cell_len

from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)
from rebrew.errors import RebrewError
from rebrew.pe_headers import pe_layout
from rebrew.utils import atomic_write_text, read_json_text, untrusted_ident

#: Width of the function-name column in the residue table.
_NAME_COLUMN = 40


class ResidueError(RebrewError, ValueError):
    """Raised when an input image is not a PE that residue can measure."""


def _name_column(name: str, width: int = _NAME_COLUMN) -> str:
    """*name* truncated and padded to *width* terminal columns.

    ``f"{name:40s}"`` counts code points, but a terminal lays out CJK,
    emoji, and combining marks in two or zero columns, so a Japanese symbol
    name pushed every figure to its right out of alignment.  Truncation uses
    the same unit as the padding: cutting by code points would let a long CJK
    name overflow the column instead of fitting it.
    """
    out = name
    while cell_len(out) > width:
        out = out[:-1]
    return out + " " * (width - cell_len(out))


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew build residue build/game.exe · · · Measure residue against the baseline\n\n"
    "  rebrew build residue build/game.exe --new-baseline · · Record today's bytes as baseline\n\n"
    "  rebrew build residue build/game.exe --baseline old.json --json · Compare against a file\n"
)


app = typer.Typer(
    help="Measure linked byte-identity residue after postlink fixers.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _sections(raw: bytes) -> dict[str, tuple[int, int, int, int]]:
    """name -> (va, vsize, raw_ptr, raw_size), extents clipped to *raw*.

    Geometry comes from :func:`rebrew.pe_headers.pe_layout`, which bounds every
    read against the buffer; a section whose raw extent runs past the end of
    the image keeps the part that is present, so the caller's byte comparison
    stays in bounds.  A section with no bytes in the file (BSS) is dropped.
    """
    layout = pe_layout(raw)
    if layout is None:
        raise ResidueError(f"not a PE image: no MZ/PE header in {len(raw)} bytes")
    out: dict[str, tuple[int, int, int, int]] = {}
    for section in layout.sections:
        end = min(section.pointer_to_raw_data + section.size_of_raw_data, len(raw))
        if end <= section.pointer_to_raw_data:
            continue
        out[section.name] = (
            section.virtual_address,
            section.virtual_size,
            section.pointer_to_raw_data,
            end - section.pointer_to_raw_data,
        )
    return out


def residue_report(
    built: bytes, reference: bytes, bad: list[tuple[int, int, str]], image_base: int
) -> dict[str, Any]:
    """Section diffs plus per-function attribution of remaining .text bytes.

    Both images must carry a ``.text`` section; a missing one means there is
    nothing to attribute, so this raises :class:`ResidueError` rather than
    reporting a zero residue for an image that was never compared.
    """
    sr, sp = _sections(reference), _sections(built)
    for label, table in (("reference", sr), ("built", sp)):
        if ".text" not in table:
            raise ResidueError(f"{label} image has no .text section")
    sections: dict[str, dict[str, Any]] = {}
    for name in sorted(set(sr) | set(sp)):
        if name not in sr or name not in sp:
            sections[name] = {"status": "missing-on-one-side"}
            continue
        _, _, pr_r, rs_r = sr[name]
        _, _, pr_p, rs_p = sp[name]
        span = min(rs_r, rs_p)
        diff = sum(1 for i in range(span) if reference[pr_r + i] != built[pr_p + i])
        sections[name] = {"ref_raw": rs_r, "built_raw": rs_p, "differing": diff, "span": span}

    # The bound is the section's *raw* size, not its virtual size: the indices
    # below read from ``pointer_to_raw_data``, and a virtual tail larger than
    # ``SizeOfRawData`` (a BSS-style .text) would otherwise compare the next
    # section's file bytes and inflate text_differing and text_percent.
    t_rva, t_vs, t_ptr, t_rs = sr[".text"]
    _p_rva, p_vs, p_ptr, p_rs = sp[".text"]
    n = max(
        0,
        min(t_vs, p_vs, t_rs, p_rs, len(reference) - t_ptr, len(built) - p_ptr),
    )
    diffs = [i for i in range(n) if reference[t_ptr + i] != built[p_ptr + i]]

    # Attribute trailing tables to their owner: extend each extent to the
    # next function start (a body's jump table lives past its size).
    starts = sorted(lo for lo, _size, _name in bad)
    extents = []
    for lo, size, name in bad:
        nxt = next((s for s in starts if s > lo), None)
        end = lo + size if nxt is None else nxt
        extents.append((lo, end, name))

    def owner(off: int) -> str | None:
        for lo, end, name in extents:
            if lo <= off < end:
                return name
        return None

    counts: dict[str, int] = {}
    first: dict[str, int] = {}
    for i in diffs:
        key = owner(i) or "<outside the non-matching functions>"
        counts[key] = counts.get(key, 0) + 1
        first.setdefault(key, i)
    outside = counts.get("<outside the non-matching functions>", 0)
    funcs = [
        {"name": name, "bytes": count, "first_diff_va": hex(first[name] + t_rva + image_base)}
        for name, count in sorted(counts.items(), key=lambda kv: -kv[1])
    ]
    return {
        "text_differing": len(diffs),
        "text_size": n,
        "text_percent": round(100.0 * len(diffs) / max(1, n), 2),
        "inside_nonmatching": len(diffs) - outside,
        "outside": outside,
        "nonmatching_count": len(bad),
        "sections": sections,
        "functions": funcs,
    }


def _nonmatching_from_cache(cfg: Any, image_base: int, text_rva: int) -> list[tuple[int, int, str]]:
    """(text-relative offset, size, name) for every non-byte-matched function."""
    from rebrew.verify_cache import cache_identity_matches, load_verify_cache_raw

    raw = load_verify_cache_raw(cfg)
    if not isinstance(raw, dict) or not cache_identity_matches(raw, cfg):
        return []

    entries = raw.get("entries") or raw.get("functions")
    if not isinstance(entries, dict):
        return []

    out = []
    for entry in entries.values():
        if not isinstance(entry, dict):
            continue
        status = entry.get("status")
        delta = entry.get("delta") or 0
        passed = entry.get("passed", False)
        if not passed or delta > 0 or status in ("STUB", "SIZE_MISMATCH"):
            va_raw = entry.get("va", "0")
            try:
                va = int(str(va_raw), 0)
            except (ValueError, TypeError):
                continue
            out.append((va - image_base - text_rva, entry.get("size") or 0, entry.get("name", "?")))
    return out


def layout_map_gate_note(cover: tuple[int, int, int, int]) -> str | None:
    """Warning text for a ``map_coverage`` result, or None when it passes.

    *cover* is ``(operands_ok, operands_total, calls_ok, calls_total)``.  A
    total of zero means the layout package carries no ``.text`` map entries,
    so alignment was never measured: that is reported as unmeasured, not as
    the 0.00% coverage a ratio over an empty denominator used to produce.
    """
    from rebrew.postlink import MIN_LAYOUT_MAP_COVERAGE

    op_ok, op_tot, call_ok, call_tot = cover
    map_total = op_tot + call_tot
    if map_total == 0:
        return (
            "WARNING: layout package has no .text layout-map entries; "
            "position alignment was not measured"
        )
    frac = (op_ok + call_ok) / map_total
    if frac >= MIN_LAYOUT_MAP_COVERAGE:
        return None
    return (
        f"WARNING: layout-map coverage {100 * frac:.2f}% below gate; "
        "fixers rewrite by fixed offset — output is intermediate, not runnable."
    )


@app.callback(invoke_without_command=True)
def main(
    built: str = typer.Argument(None, help="Built image to measure (default: build/<target>)"),
    baseline: str | None = typer.Option(
        None,
        "--baseline",
        help="Baseline JSON file: also print per-function deltas vs it",
    ),
    new_baseline: str | None = typer.Option(
        None, "--new-baseline", help="Write this run's report as JSON to PATH (adopt as baseline)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Apply postlink fixers to BUILT and report the remaining byte residue."""
    import json

    cfg = require_config(target=target, json_mode=json_output)
    built_path = Path(built) if built else Path(cfg.root) / "build" / cfg.target_name
    if not built_path.is_file():
        error_exit(f"Built image not found: {built_path}", json_mode=json_output)

    from rebrew.binary_loader import load_binary
    from rebrew.layout_meta import load_package
    from rebrew.postlink import (
        FIXER_ORDER,
        FIXERS,
        binary_info_from_bytes,
        map_coverage,
    )

    layout_dir = Path(cfg.root) / "layout" / cfg.target_name
    meta = None
    if layout_dir.is_dir():
        try:
            meta = load_package(layout_dir)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # Without the package every fixer is skipped, so the residue would
            # be measured on the unpatched image.
            error_exit(f"cannot load layout package {layout_dir}: {exc}", json_mode=json_output)
    else:
        console.print(
            f"WARNING: no layout package at {untrusted_ident(layout_dir)}; postlink fixers skipped "
            "(run 'rebrew build layout')"
        )
    info_b = load_binary(built_path)
    try:
        cover = map_coverage(bytes(info_b.data), meta, info_b) if meta else (1, 1, 1, 1)
    except KeyError as exc:
        console.print(
            f"WARNING: layout-map coverage unavailable (missing section {untrusted_ident(exc)})"
        )
    else:
        note = layout_map_gate_note(cover)
        if note:
            console.print(note)
    patched = bytearray(info_b.data)
    if meta is not None:
        for name in FIXER_ORDER:
            before = bytes(patched)
            with contextlib.suppress(ValueError):
                info_b = binary_info_from_bytes(bytes(patched), built_path)
            report = FIXERS[name](patched, meta, info_b)
            console.print(f"{name:11s} changed={before != bytes(patched)} {report.stats}")

    reference = Path(cfg.target_binary).read_bytes()
    image_base = getattr(cfg, "image_base", 0)
    try:
        sr = _sections(reference)
        if ".text" not in sr:
            raise ResidueError("reference image has no .text section")
        bad = _nonmatching_from_cache(cfg, image_base, sr[".text"][0])
        summary = residue_report(bytes(patched), reference, bad, image_base)
    except ResidueError as exc:
        error_exit(str(exc), json_mode=json_output)

    if new_baseline:
        atomic_write_text(Path(new_baseline), json.dumps(summary, indent=2), encoding="utf-8")
        console.print(f"baseline written ({untrusted_ident(new_baseline)})")
    if baseline:
        old = json.loads(read_json_text(Path(baseline)))
        old_map = {f["name"]: f["bytes"] for f in old.get("functions", [])}
        new_map = {f["name"]: f["bytes"] for f in summary["functions"]}
        delta_rows = [
            {
                "name": name,
                "before": old_map.get(name, 0),
                "after": new_map.get(name, 0),
                "delta": new_map.get(name, 0) - old_map.get(name, 0),
            }
            for name in sorted(set(old_map) | set(new_map))
            if old_map.get(name, 0) != new_map.get(name, 0)
        ]
        summary["delta_vs_baseline"] = {
            "text_before": old.get("text_differing"),
            "text_after": summary["text_differing"],
            "text_delta": summary["text_differing"] - (old.get("text_differing") or 0),
            "functions": delta_rows,
        }

    if json_output:
        json_print(summary)
        return
    console.print(
        f".text differing {summary['text_differing']:#x} of {summary['text_size']:#x} "
        f"({summary['text_percent']:.2f}%)"
    )
    for sec, s in summary["sections"].items():
        if s.get("status") == "missing-on-one-side":
            console.print(f"{untrusted_ident(sec):9s} MISSING on one side")
        else:
            console.print(
                f"{untrusted_ident(sec):9s} raw {s['ref_raw']:#7x}/{s['built_raw']:#7x}  "
                f"differing {s['differing']:#7x}"
            )
    console.print(f"\n{'function':40s} {'bytes':>6s} {'1st diff':>10s}")
    for f in summary["functions"]:
        if f["bytes"] > 8 or f["name"].startswith("<"):
            console.print(
                f"{_name_column(untrusted_ident(f['name']))} {f['bytes']:6d} {f['first_diff_va']:>10s}"
            )
    if "delta_vs_baseline" in summary:
        d = summary["delta_vs_baseline"]
        console.print(f"\n.text {d['text_before']} -> {d['text_after']} ({d['text_delta']:+d})")
        for row in d["functions"]:
            console.print(
                f"  {_name_column(untrusted_ident(row['name']))} {row['before']:6d} -> "
                f"{row['after']:6d} ({row['delta']:+d})"
            )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
