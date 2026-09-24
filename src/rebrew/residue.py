"""residue.py — how far is the build from byte identity, after postlink?

Applies the postlink fixers to the linked image, diffs the result against
the reference section by section, and attributes the remaining ``.text``
bytes to the functions ``rebrew verify`` reports as not byte-matched.
Read the result as the *remaining work*: everything outside ``.text`` is
either produced by the link already or copied from the layout package, so
a difference there means a pipeline bug, while the ``.text`` residue is
the code that still has to be made to match.

This is the linked truth that object scores (``rebrew test``'s
``match_count``, ``rebrew probe``'s ``aligned``) only proxy — a size change
anywhere moves every byte after it, so only this number decides whether a
candidate lands.

Generalized from guild-rebrew's ``scripts/postlink_residual.py`` +
``scripts/residue_diff.py`` + ``scripts/linktest.sh`` (MSVC6/x86-32
campaign).  Layout package, binary paths, and image base resolve from the
project config — no hardcoded ``build/split_poc.dll`` or ``0x10000000``.
"""

from __future__ import annotations

import contextlib
import struct
from pathlib import Path
from typing import Any

import typer

from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)

app = typer.Typer(
    help="Measure linked byte-identity residue after postlink fixers.",
    rich_markup_mode="rich",
)


def _sections(raw: bytes) -> dict[str, tuple[int, int, int, int]]:
    """name -> (va, vsize, raw_ptr, raw_size)."""
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    opt = struct.unpack_from("<H", raw, pe + 20)[0]
    out = {}
    for i in range(nsec):
        off = pe + 24 + opt + i * 40
        # latin1 matches pe_headers.parse_pe: PE section names are 8 raw bytes
        # (often padded, rarely UTF-8). Bare .decode() is UTF-8-strict and
        # raises UnicodeDecodeError on any high byte (e.g. b".xyz\xff").
        name = raw[off : off + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, rp = struct.unpack_from("<IIII", raw, off + 8)
        out[name] = (va, vs, rp, rs)
    return out


def residue_report(
    built: bytes, reference: bytes, bad: list[tuple[int, int, str]], image_base: int
) -> dict[str, Any]:
    """Section diffs plus per-function attribution of remaining .text bytes."""
    sr, sp = _sections(reference), _sections(built)
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

    t_rva, t_vs, t_ptr, _ = sr[".text"]
    p_rva, p_vs, p_ptr, _ = sp[".text"]
    n = min(t_vs, p_vs)
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
    from rebrew.verify_cache import CACHE_VERSION, load_verify_cache_raw

    raw = load_verify_cache_raw(cfg)
    if not isinstance(raw, dict) or raw.get("version") != CACHE_VERSION:
        return []
    if raw.get("target") != getattr(cfg, "target_name", ""):
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


@app.callback(invoke_without_command=True)
def main(
    built: str = typer.Argument(None, help="Built image to measure (default: build/<target>)"),
    baseline: str | None = typer.Option(
        None,
        "--baseline",
        help="Baseline JSON file: print per-function delta vs it instead of absolutes",
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
        MIN_LAYOUT_MAP_COVERAGE,
        _binary_info_from_bytes,
        _map_coverage,
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
            f"WARNING: no layout package at {layout_dir}; postlink fixers skipped "
            "(run 'rebrew gen-layout')"
        )
    info_b = load_binary(built_path)
    try:
        cover = _map_coverage(bytes(info_b.data), meta, info_b) if meta else (1, 1, 1, 1)
    except KeyError as exc:
        console.print(f"WARNING: layout-map coverage unavailable (missing section {exc})")
    else:
        op_ok, op_tot, call_ok, call_tot = cover
        frac = (op_ok + call_ok) / max(1, op_tot + call_tot)
        if frac < MIN_LAYOUT_MAP_COVERAGE:
            console.print(
                f"WARNING: layout-map coverage {100 * frac:.2f}% below gate; "
                "fixers rewrite by fixed offset — output is intermediate, not runnable."
            )
    patched = bytearray(info_b.data)
    if meta is not None:
        for name in FIXER_ORDER:
            before = bytes(patched)
            with contextlib.suppress(ValueError):
                info_b = _binary_info_from_bytes(bytes(patched), built_path)
            report = FIXERS[name](patched, meta, info_b)
            console.print(f"{name:11s} changed={before != bytes(patched)} {report.stats}")

    reference = Path(cfg.target_binary).read_bytes()
    image_base = getattr(cfg, "image_base", 0)
    sr = _sections(reference)
    bad = _nonmatching_from_cache(cfg, image_base, sr[".text"][0])
    summary = residue_report(bytes(patched), reference, bad, image_base)

    if new_baseline:
        Path(new_baseline).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        console.print(f"baseline written ({new_baseline})")
    if baseline:
        old = json.loads(Path(baseline).read_text(encoding="utf-8"))
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
            console.print(f"{sec:9s} MISSING on one side")
        else:
            console.print(
                f"{sec:9s} raw {s['ref_raw']:#7x}/{s['built_raw']:#7x}  differing {s['differing']:#7x}"
            )
    console.print(f"\n{'function':40s} {'bytes':>6s} {'1st diff':>10s}")
    for f in summary["functions"]:
        if f["bytes"] > 8 or f["name"].startswith("<"):
            console.print(f"{f['name'][:40]:40s} {f['bytes']:6d} {f['first_diff_va']:>10s}")
    if "delta_vs_baseline" in summary:
        d = summary["delta_vs_baseline"]
        console.print(f"\n.text {d['text_before']} -> {d['text_after']} ({d['text_delta']:+d})")
        for row in d["functions"]:
            console.print(
                f"  {row['name'][:40]:40s} {row['before']:6d} -> {row['after']:6d} ({row['delta']:+d})"
            )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
