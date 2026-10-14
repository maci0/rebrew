"""reloc_diff.py: compare PE base relocation sites between the reference and a build.

A site is the absolute VA a base relocation patches.  The reference sites the
build lacks (``missing``) and the build sites the reference lacks (``extra``)
are counted per section and listed with the symbol containing the site, the
VA its pointer operand targets, that target's section, the nearest link-map
symbol at the target, and the ``rebrew-data.toml`` row covering it.

Symbol names come from the MSVC link map of the built image, so they are
exact for ``extra`` sites and for a ``missing`` site only where the build's
layout agrees with the reference.  Data rows carry reference VAs.

``--pairs START:END`` pairs the reference and built operand values at every
site both images relocate whose reference target lies in ``[START, END)``:
a displaced global shows up as one reference target mapped to another built
target.

Usage:
    rebrew binary relocs [--built build/<target>] [--link-map PATH]
                         [--pairs START:END] [--limit 50] [--json] [--target NAME]
"""

from __future__ import annotations

import bisect
import collections
from pathlib import Path
from typing import Any

import typer
from rich.markup import escape

from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    console,
    error_exit,
    json_print,
    option_default,
    parse_va,
    require_config,
    require_non_negative,
)
from rebrew.data_scan import classify_section
from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary, section_dict
from rebrew.formats.binary_model import BinaryInfo

_DEFAULT_LIMIT = 50

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew binary relocs  # Missing/extra sites vs build/<target>\n\n"
    "  # Machine-readable site lists\n"
    "  rebrew binary relocs --built build/game.dll --json\n\n"
    "  # Reference vs built targets in a range\n"
    "  rebrew binary relocs --pairs 0x10035498:0x10035878\n"
)

app = typer.Typer(
    help="Compare PE base relocation sites of the reference and a built image.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


# ---------------------------------------------------------------------------
# Name lookups
# ---------------------------------------------------------------------------


class NameIndex:
    """Sorted ``(va, size, name)`` rows answering "which name covers this VA"."""

    def __init__(self, rows: list[tuple[int, int, str]]) -> None:
        self.rows = sorted(rows)
        self._starts = [va for va, _, _ in self.rows]

    def nearest(self, va: int) -> str | None:
        """``name`` or ``name+0xN`` for the last row at or below *va*, sizes ignored."""
        i = bisect.bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        start, _, name = self.rows[i]
        return name if va == start else f"{name}+{va - start:#x}"

    def covering(self, va: int) -> str | None:
        """Like :meth:`nearest`, but only when *va* is inside that row's size (at least 1)."""
        i = bisect.bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        start, size, _ = self.rows[i]
        return self.nearest(va) if va < start + max(size, 1) else None


def link_map_index(text: str) -> NameIndex:
    """Every public and static symbol of an MSVC link map, code and data."""
    from rebrew.data_ownership import parse_link_map

    return NameIndex([(s.va, 0, s.name) for s in parse_link_map(text)])


def data_row_index(cfg: Any) -> NameIndex:
    """The active target's ``rebrew-data.toml`` rows that carry a name."""
    from rebrew.metadata.data import load_data_metadata, module_visible_to_target

    rows = [
        (va, int(fields.get("size") or 0), str(fields["name"]))
        for (module, va), fields in load_data_metadata(cfg.metadata_dir).items()
        if fields.get("name") and module_visible_to_target(module, cfg)
    ]
    return NameIndex(rows)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def operand(info: BinaryInfo, site: int, kind: str) -> int | None:
    """The pointer a HIGHLOW/DIR64 site holds; None for other types or unread bytes."""
    from rebrew.formats.relocations import (
        PE_RELOCATION_WIDTHS,  # lazy: rebrew.formats.relocations imports lief
    )

    width = PE_RELOCATION_WIDTHS.get(kind)
    if width is None:
        return None
    raw = extract_bytes_at_va(info, site, width, trim_padding=False)
    if raw is None or len(raw) != width:
        return None
    return int.from_bytes(raw, "little")


def _hex(va: int | None) -> str | None:
    return None if va is None else f"0x{va:08x}"


def describe_sites(
    info: BinaryInfo,
    sites: dict[int, str],
    selected: list[int],
    symbols: NameIndex,
    data_rows: NameIndex,
) -> list[dict[str, Any]]:
    """One row per selected site of *info*: where it is and what its operand targets."""
    sections = section_dict(info)
    rows: list[dict[str, Any]] = []
    for site in selected:
        target = operand(info, site, sites[site])
        rows.append(
            {
                "site": _hex(site),
                "type": sites[site],
                "section": classify_section(site, sections) or None,
                "symbol": symbols.nearest(site),
                "target": _hex(target),
                "target_section": (
                    None if target is None else classify_section(target, sections) or None
                ),
                "target_symbol": None if target is None else symbols.nearest(target),
                "target_data": None if target is None else data_rows.covering(target),
            }
        )
    return rows


def by_section(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Site count per containing section, ``?`` for a site in no section."""
    counts = collections.Counter(r["section"] or "?" for r in rows)
    return dict(sorted(counts.items()))


def pair_operands(
    reference: BinaryInfo,
    built: BinaryInfo,
    ref_sites: dict[int, str],
    built_sites: dict[int, str],
    start: int,
    end: int,
    symbols: NameIndex,
    data_rows: NameIndex,
) -> list[dict[str, Any]]:
    """Reference vs built operands at shared sites whose reference target is in [start, end)."""
    pairs: collections.Counter[tuple[int, int | None]] = collections.Counter()
    for site in sorted(ref_sites.keys() & built_sites.keys()):
        ref_target = operand(reference, site, ref_sites[site])
        if ref_target is None or not start <= ref_target < end:
            continue
        pairs[(ref_target, operand(built, site, built_sites[site]))] += 1
    return [
        {
            "reference": _hex(ref_target),
            "built": _hex(built_target),
            "delta": None if built_target is None else built_target - ref_target,
            "sites": count,
            "reference_data": data_rows.covering(ref_target),
            "built_symbol": None if built_target is None else symbols.nearest(built_target),
        }
        for (ref_target, built_target), count in sorted(
            pairs.items(), key=lambda kv: (kv[0][0], -1 if kv[0][1] is None else kv[0][1])
        )
    ]


def _parse_range(text: str, *, json_mode: bool) -> tuple[int, int]:
    lo, sep, hi = text.partition(":")
    if not sep:
        error_exit(f"--pairs takes START:END, got {text!r}", json_mode=json_mode)
    start, end = parse_va(lo, json_mode=json_mode), parse_va(hi, json_mode=json_mode)
    if end <= start:
        error_exit(f"--pairs END must be above START, got {text!r}", json_mode=json_mode)
    return start, end


def _load_pe(path: Path, *, json_mode: bool) -> tuple[BinaryInfo, dict[int, str]]:
    from rebrew.formats.relocations import (
        pe_relocation_sites,  # lazy: rebrew.formats.relocations imports lief
    )

    try:
        info = load_binary(path)
    except (OSError, ValueError) as exc:
        error_exit(f"cannot load {path}: {exc}", json_mode=json_mode)
    if info.format != "pe":
        error_exit(
            f"{path} is {info.format}, base relocations need a PE image", json_mode=json_mode
        )
    try:
        return info, pe_relocation_sites(info)
    except ValueError as exc:
        error_exit(f"cannot read the base relocations of {path}: {exc}", json_mode=json_mode)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_sites(title: str, rows: list[dict[str, Any]], limit: int) -> None:
    if not rows:
        return
    counts = ", ".join(f"{name} {n}" for name, n in by_section(rows).items())
    console.print(f"[bold]{title}[/bold] {len(rows)} ({counts})")
    for r in rows[:limit]:
        target = r["target"] or "-"
        console.print(
            f"  {r['site']} {escape(r['symbol'] or '?'):40} {r['type']:8} -> {target} "
            f"{r['target_section'] or '?':7} {escape(r['target_symbol'] or '?')}"
            + (f"  [{escape(r['target_data'])}]" if r["target_data"] else ""),
            highlight=False,
        )
    if len(rows) > limit:
        console.print(f"  ... {len(rows) - limit} more (increase --limit or use --json for all)")


@app.callback(invoke_without_command=True)
def main(
    built: Path | None = typer.Option(
        None, "--built", help="Built image to compare (default: build/<target>)"
    ),
    link_map: Path | None = typer.Option(
        None,
        "--link-map",
        help="MSVC link map of --built for symbol names (default: the built image's .map beside it)",
    ),
    pairs: str | None = typer.Option(
        None,
        "--pairs",
        help="START:END hex VA range: pair reference and built operands at shared sites "
        "whose reference target is inside it",
    ),
    limit: int = typer.Option(
        _DEFAULT_LIMIT, "--limit", help="Max sites printed per list (0 = none; JSON lists all)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Missing and extra base relocation sites of a build, with their symbols and targets."""
    limit = require_non_negative(
        option_default(limit, _DEFAULT_LIMIT), "--limit", json_mode=json_output
    )
    link_map = option_default(link_map, None)
    pairs = option_default(pairs, None)
    cfg = require_config(target=target, json_mode=json_output)
    root = Path(cfg.root)
    built = option_default(built, None) or Path("build") / cfg.target_name
    built_path = built if built.is_absolute() else root / built
    if not built_path.exists():
        error_exit(
            f"{built_path} not found: build the project first (or pass --built <path>)",
            json_mode=json_output,
        )
    pair_range = None if pairs is None else _parse_range(pairs, json_mode=json_output)

    reference, ref_sites = _load_pe(cfg.target_binary, json_mode=json_output)
    image, built_sites = _load_pe(built_path, json_mode=json_output)
    if reference.image_base != image.image_base:
        error_exit(
            f"image bases differ (reference {reference.image_base:#x}, "
            f"built {image.image_base:#x}): site VAs are not comparable",
            json_mode=json_output,
        )

    map_path = link_map or built_path.with_suffix(".map")
    if map_path.is_file():
        symbols = link_map_index(map_path.read_text(encoding="utf-8", errors="replace"))
    elif link_map is not None:
        error_exit(f"link map not found: {link_map}", json_mode=json_output)
    else:
        symbols = NameIndex([])
    data_rows = data_row_index(cfg)

    missing = describe_sites(
        reference, ref_sites, sorted(ref_sites.keys() - built_sites.keys()), symbols, data_rows
    )
    extra = describe_sites(
        image, built_sites, sorted(built_sites.keys() - ref_sites.keys()), symbols, data_rows
    )
    payload: dict[str, Any] = {
        "reference": str(cfg.target_binary),
        "built": str(built_path),
        "link_map": str(map_path) if symbols.rows else None,
        "reference_sites": len(ref_sites),
        "built_sites": len(built_sites),
        "common_sites": len(ref_sites.keys() & built_sites.keys()),
        "missing": len(missing),
        "extra": len(extra),
        "missing_by_section": by_section(missing),
        "extra_by_section": by_section(extra),
        "missing_sites": missing,
        "extra_sites": extra,
    }
    if pair_range is not None:
        payload["pairs"] = pair_operands(
            reference, image, ref_sites, built_sites, *pair_range, symbols, data_rows
        )

    if json_output:
        json_print(payload)
    else:
        console.print(
            f"reference {len(ref_sites)} sites, built {len(built_sites)}, "
            f"common {payload['common_sites']}, missing {len(missing)}, extra {len(extra)}"
        )
        if payload["link_map"] is None:
            console.print("[yellow]no link map beside the build: symbol columns are '?'[/yellow]")
        _print_sites("missing", missing, limit)
        _print_sites("extra", extra, limit)
        if pair_range is not None:
            console.print(f"[bold]pairs[/bold] {len(payload['pairs'])} reference/built targets")
        for p in payload.get("pairs", []):
            delta = "-" if p["delta"] is None else f"{p['delta']:+#x}"
            console.print(
                f"  ref {p['reference']} built {p['built'] or '-'} delta {delta} x{p['sites']}  "
                f"{escape(p['reference_data'] or '?')} -> {escape(p['built_symbol'] or '?')}",
                highlight=False,
            )
    if missing or extra:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
