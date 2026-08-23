"""cross_import.py — import matched functions from another target.

Finds functions shared between two targets in one project (the same code at
different VAs — binary versions, or a DLL+EXE pair sharing code) and imports
the already-matched source from one target into the other.

Direction: the target the command runs against is the DESTINATION; ``--from``
names the SOURCE target.  Matching is structural: the source target's matched
functions (EXACT/RELOC/PROVEN) and the destination's unmatched functions are
signature-compared from their **target bytes** via the ``rebrew.similar``
machinery (mnemonic histogram + call/branch agreement — no compilation
needed, so matching works even where the toolchain image is absent).  The
best source match above ``--min-score``, clearly ahead of the runner-up
(``--min-gap``), is imported: the .c marker is rewritten to the destination
VA/SIZE, the file is written into the destination's ``reversed_dir``, then
the function is compiled + verified against the destination binary and
STATUS is promoted through the standard verify flow — so a wrong match
simply fails verification and stays untouched (reported as skipped).

Functions that differ between the targets, or that have no counterpart,
are left untouched and reported.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.catalog import RegistryEntry
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.config import ProjectConfig
from rebrew.metadata import MATCHED_STATUSES
from rebrew.similar import _DEFAULT_CS_ARCH, _DEFAULT_CS_MODE, _disasm_signature, similarity_score

console = Console(stderr=True)

#: STATUS values that count as "already matched" on the source side (and
#: exclude a destination function from consideration).


# ---------------------------------------------------------------------------
# Pure matching core (testable with hand-crafted signatures)
# ---------------------------------------------------------------------------


def cross_match(
    dest_sigs: dict[int, dict[str, Any]],
    src_sigs: dict[int, dict[str, Any]],
    min_score: float = 95.0,
    min_gap: float = 5.0,
) -> dict[int, tuple[int, float]]:
    """Map each destination function to its best source-target counterpart.

    *dest_sigs* / *src_sigs* map VA -> structural signature (see
    :func:`rebrew.similar._disasm_signature`).  For every destination
    signature the best-scoring source signature is kept when it is at least
    *min_score* (0-100) AND beats the runner-up by at least *min_gap* (an
    "unambiguous" match — two near-duplicate source functions are not
    enough to pick between, so the destination is left untouched).

    *min_score* defaults high (95.0) because structural signatures are
    prologue-heavy: a genuinely different function with a shared
    prologue/epilogue routinely scores in the high 80s-low 90s against a
    sibling (measured 92.9 on the two-PE fixture), while identical code
    scores 100 (or ~99.x for reloc-only differences).  The default separates
    the two cleanly; lower it only when you know the sibling noise floor.

    Returns ``{dest_va: (src_va, score)}``.
    """
    out: dict[int, tuple[int, float]] = {}
    for d_va, d_sig in dest_sigs.items():
        ranked = sorted(
            ((similarity_score(d_sig, s_sig), s_va) for s_va, s_sig in src_sigs.items()),
            reverse=True,
        )
        if not ranked:
            continue
        best_score, best_src = ranked[0]
        second_score = ranked[1][0] if len(ranked) > 1 else -1.0
        if best_score >= min_score and (best_score - second_score) >= min_gap:
            out[d_va] = (best_src, best_score)
    return out


def _signature_for(cfg: ProjectConfig, code: bytes, va: int) -> dict[str, Any] | None:
    """Structural signature for *code*, honouring the config's arch/mode."""
    return _disasm_signature(
        code,
        va,
        getattr(cfg, "capstone_arch", _DEFAULT_CS_ARCH),
        getattr(cfg, "capstone_mode", _DEFAULT_CS_MODE),
    )


# ---------------------------------------------------------------------------
# Target-facing data (statuses, target bytes)
# ---------------------------------------------------------------------------


def _annotations_by_va(cfg: ProjectConfig) -> dict[int, tuple[str, str]]:
    """``va -> (status, filepath)`` from the target's sources + metadata.

    Status comes from the metadata overlay (``rebrew-function.toml`` via
    ``cfg.metadata_dir``); filepath is relative to ``cfg.reversed_dir``.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import iter_sources

    out: dict[int, tuple[str, str]] = {}
    for path in iter_sources(cfg.reversed_dir, cfg):
        for ann in parse_c_file_multi(
            path,
            target_name=cfg.target_name,
            base_dir=cfg.reversed_dir,
            metadata_dir=cfg.metadata_dir,
        ):
            out[ann.va] = (getattr(ann, "status", "") or "", getattr(ann, "filepath", "") or "")
    return out


def _registry(cfg: ProjectConfig) -> dict[int, RegistryEntry]:
    """The target's function catalog (VA -> entry with ``canonical_size``)."""
    from rebrew.catalog import build_function_registry, parse_function_list
    from rebrew.config import FUNCTION_STRUCTURE_JSON

    funcs = parse_function_list(cfg.function_list)
    return build_function_registry(
        funcs, cfg, cfg.reversed_dir / FUNCTION_STRUCTURE_JSON, cfg.target_binary
    )


def _target_bytes_by_va(cfg: ProjectConfig, vas: dict[int, int]) -> dict[int, bytes]:
    """``va -> target-binary bytes`` for the given ``va -> size`` map."""
    from rebrew.binary_loader import extract_raw_bytes

    out: dict[int, bytes] = {}
    for va, size in vas.items():
        try:
            out[va] = extract_raw_bytes(cfg.target_binary, va, size)
        except (OSError, ValueError):
            continue
    return out


def matched_source_bytes(cfg_src: ProjectConfig) -> dict[int, bytes]:
    """Source side: target bytes of the source target's matched functions.

    Only functions whose metadata STATUS is EXACT/RELOC/PROVEN participate —
    they are the ones whose source can be trusted to reproduce.
    """
    statuses = _annotations_by_va(cfg_src)
    registry = _registry(cfg_src)
    vas = {
        va: int(reg["canonical_size"])
        for va, reg in registry.items()
        if reg.get("canonical_size") and statuses.get(va, ("", ""))[0] in MATCHED_STATUSES
    }
    return _target_bytes_by_va(cfg_src, vas)


def unmatched_dest_bytes(cfg_dst: ProjectConfig, only_va: int | None = None) -> dict[int, bytes]:
    """Destination side: target bytes of the destination's NOT-yet-matched
    functions (anything whose STATUS is not EXACT/RELOC/PROVEN)."""
    statuses = _annotations_by_va(cfg_dst)
    registry = _registry(cfg_dst)
    vas = {
        va: int(reg["canonical_size"])
        for va, reg in registry.items()
        if reg.get("canonical_size") and statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES
    }
    if only_va is not None:
        vas = {only_va: vas[only_va]} if only_va in vas else {}
    return _target_bytes_by_va(cfg_dst, vas)


# ---------------------------------------------------------------------------
# Import mechanics
# ---------------------------------------------------------------------------

#: A ``// FUNCTION: MOD 0xVA`` or ``/* FUNCTION: MOD 0xVA */`` marker line.
_MARKER_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<open>//|/\*)\s*(?P<type>FUNCTION|LIBRARY|STUB)\s*:\s+"
    r"(?P<module>[^\s]+)\s+(?P<va>0x[0-9a-fA-F]+)(?P<close>\s*\*/)?[ \t]*$"
)

#: A ``// KEY: value`` (or ``/* KEY: value */``) line inside a marker block.
_KV_RE = re.compile(r"^[ \t]*(?://|/\*)[ \t]*[A-Za-z_][A-Za-z0-9_]*:[ \t]*")

#: A ``// SIZE: N`` key-value line inside the marker block.
_SIZE_KV_RE = re.compile(r"^[ \t]*//[ \t]*SIZE:[ \t]*\S+")


def _rewrite_marker(text: str, module: str, va: int, size: int) -> str:
    """Remap the first FUNCTION/LIBRARY/STUB marker to *module*/*va* and set SIZE.

    The imported source belongs to the DESTINATION target, so its marker must
    name the destination module + VA and carry the destination's canonical
    size — otherwise the destination's scanner would attribute the function
    to the wrong target/VA and verification would slice the wrong bytes.

    A shared multi-version source stacks one marker per target above a single
    implementation; the imported copy belongs to the destination only, so the
    other targets' stacked marker blocks (marker + their key-value lines,
    before any code) are dropped — they would otherwise carry stale VAs into
    the destination's reversed_dir.
    """
    lines = text.splitlines(keepends=True)

    # 1) Rewrite the FIRST marker to the destination.
    marker_idx = None
    for idx, line in enumerate(lines):
        m = _MARKER_RE.match(line)
        if m:
            marker_idx = idx
            close = " */" if m.group("open") == "/*" else ""
            lines[idx] = (
                f"{m.group('indent')}{m.group('open')} {m.group('type')}: "
                f"{module} 0x{va:x}{close}\n"
            )
            break
    if marker_idx is None:
        raise ValueError("no FUNCTION/LIBRARY/STUB marker found in source")

    # 2) Drop stacked leading marker blocks from other targets — only the
    #    consecutive markers + key-value lines BEFORE any code (the shared
    #    multi-version pattern).  A marker after code (a genuinely
    #    multi-function file) is kept.
    collapsed: list[str] = lines[: marker_idx + 1]
    i = marker_idx + 1
    seen_code = False
    while i < len(lines):
        m = _MARKER_RE.match(lines[i])
        is_marker = m is not None
        if not seen_code and m is not None and m.group("type") in ("FUNCTION", "LIBRARY", "STUB"):
            i += 1
            while i < len(lines) and _KV_RE.match(lines[i]):
                i += 1
            continue
        if is_marker or not _KV_RE.match(lines[i]):
            seen_code = True  # code or a non-stacked marker ends the region
        collapsed.append(lines[i])
        i += 1

    # 3) SIZE on the (now single) destination block: replace an existing
    #    SIZE line, else insert right after the marker.
    for j in range(marker_idx + 1, len(collapsed)):
        if _SIZE_KV_RE.match(collapsed[j]):
            collapsed[j] = re.sub(_SIZE_KV_RE, f"// SIZE: {size}", collapsed[j])
            break
    else:
        collapsed.insert(marker_idx + 1, f"// SIZE: {size}\n")
    return "".join(collapsed)


def import_function(
    cfg_dst: ProjectConfig,
    cfg_src: ProjectConfig,
    dst_va: int,
    src_va: int,
    src_file: str,
    dst_size: int,
    *,
    dst_file: str | None = None,
    dry_run: bool = False,
    cache: Any = None,
) -> dict[str, Any]:
    """Import the matched source function *src_file* into the destination.

    Writes the .c (marker remapped to the destination VA/SIZE) to the
    destination's reversed_dir — *dst_file* if given (the destination VA's
    existing file), else a new file next to the source name — then compiles +
    verifies it against the destination binary and promotes STATUS via the
    standard verify flow (``verify_entry`` + ``apply_status_updates``).

    With *dry_run* nothing is written or verified; the result carries the
    planned action.

    Returns a per-function result dict for the CLI/JSON report.
    """
    src_path = Path(cfg_src.reversed_dir) / src_file
    try:
        text = src_path.read_text(encoding="utf-8")
    except OSError as exc:
        return {
            "dst_va": f"0x{dst_va:08x}",
            "src_va": f"0x{src_va:08x}",
            "score": None,
            "action": "error",
            "status": "READ_ERROR",
            "filepath": src_file,
            "message": str(exc),
        }

    module = cfg_dst.target_name
    rewritten = _rewrite_marker(text, module, dst_va, dst_size)
    if dst_file is None:
        dst_file = src_path.name
    dst_path = Path(cfg_dst.reversed_dir) / dst_file
    rel_dst = str(Path(dst_file))

    # Refuse to clobber: the target file may already belong to a DIFFERENT
    # destination VA (a same-named source for another function).  The
    # destination's OWN annotation file (dst_file from the VA's filepath)
    # always matches dst_va and is overwritten as intended; a name collision
    # on a file with no annotation for this VA is reported, never silently
    # deleted.  Checked before the dry-run return so the preview lists it.
    if dst_path.exists():
        from rebrew.annotation import parse_c_file_multi

        existing = parse_c_file_multi(dst_path, target_name=module)
        if existing and existing[0].va != dst_va:
            return {
                "dst_va": f"0x{dst_va:08x}",
                "src_va": f"0x{src_va:08x}",
                "score": None,
                "action": "error",
                "status": "TARGET_CONFLICT",
                "filepath": rel_dst,
                "message": (
                    f"destination {rel_dst} already annotates VA "
                    f"0x{existing[0].va:x} — remove/rename it or import "
                    "to a different file"
                ),
            }

    if dry_run:
        return {
            "dst_va": f"0x{dst_va:08x}",
            "src_va": f"0x{src_va:08x}",
            "score": None,
            "action": "would-import",
            "status": "",
            "filepath": rel_dst,
            "message": "",
        }

    try:
        dst_path.write_text(rewritten, encoding="utf-8")
    except OSError as exc:
        return {
            "dst_va": f"0x{dst_va:08x}",
            "src_va": f"0x{src_va:08x}",
            "score": None,
            "action": "error",
            "status": "WRITE_ERROR",
            "filepath": rel_dst,
            "message": str(exc),
        }

    # Verify against the destination binary through the shared flow, then
    # promote STATUS exactly like `rebrew verify` would.  A wrong match
    # compiles to bytes that don't compare → NEAR_MATCHING/STUB — the source
    # stays but is not promoted as matched.
    from rebrew.annotation import Annotation
    from rebrew.verify import apply_status_updates, verify_entry

    entry = Annotation(
        va=dst_va,
        name=_source_name(src_path),
        symbol=_source_symbol(src_path),
        size=dst_size,
        filepath=rel_dst,
        marker_type="FUNCTION",
        status="STUB",
        module=module,
    )
    result = verify_entry(entry, cfg_dst, cache=cache)
    apply_status_updates([(entry, result.status, result.delta)], cfg_dst)

    action = "imported" if result.matched else "imported-unverified"
    return {
        "dst_va": f"0x{dst_va:08x}",
        "src_va": f"0x{src_va:08x}",
        "score": None,
        "action": action,
        "status": result.status,
        "filepath": rel_dst,
        "message": result.message,
    }


def _source_name(src_path: Path) -> str:
    """Best-effort C function name from the source file's text."""
    try:
        text = src_path.read_text(encoding="utf-8")
    except OSError:
        return src_path.stem
    from rebrew.c_parser import extract_function_name_from_line

    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("//", "/*", "*", "#")):
            got = extract_function_name_from_line(stripped)
            if got:
                return got[0]
    return src_path.stem


def _source_symbol(src_path: Path) -> str:
    name = _source_name(src_path)
    return "_" + name if not name.startswith("_") else name


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Import matched functions from another target (same code, different VAs).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew cross-import --from v1.1 · · · · · · · Import v1.1's matched functions\n"
        "  rebrew cross-import --from game.exe --min-score 90\n"
        "  rebrew cross-import --from v1.1 --dry-run --json · Preview\n\n"
        "[dim]Matches the source target's EXACT/RELOC/PROVEN functions against this\n"
        "target's unmatched functions structurally (no compile needed to match);\n"
        "imported sources are verified against this target before STATUS promotion.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    from_target: str = typer.Option(
        ..., "--from", help="Source target to import matched functions from"
    ),
    min_score: float = typer.Option(
        95.0,
        "--min-score",
        help="Minimum similarity score (0-100) to import (default 95: identical "
        "code scores 100, structural siblings with a shared prologue score "
        "high 80s-low 90s)",
    ),
    min_gap: float = typer.Option(
        5.0, "--min-gap", help="Best match must beat the runner-up by at least this"
    ),
    va: str | None = typer.Option(
        None, "--va", help="Restrict to one destination VA (hex, e.g. 0x401000)"
    ),
    limit: int | None = typer.Option(None, "--limit", help="Import at most N functions"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Cross-target function import."""
    cfg = require_config(target=target, json_mode=json_output)
    cfg_src = require_config(target=from_target, json_mode=json_output)
    if cfg_src.target_name == cfg.target_name:
        error_exit("--from must name a different target", json_mode=json_output)

    only_va = parse_va(va, json_mode=json_output) if va else None

    dest_bytes = unmatched_dest_bytes(cfg, only_va)
    src_bytes = matched_source_bytes(cfg_src)
    if not dest_bytes:
        error_exit(
            f"no unmatched functions in target {cfg.target_name!r} "
            f"(or the function catalog is empty)",
            json_mode=json_output,
        )
    if not src_bytes:
        error_exit(
            f"no matched functions in source target {from_target!r} to import from",
            json_mode=json_output,
        )

    dest_sigs = {
        va: sig
        for va, code in dest_bytes.items()
        if (sig := _signature_for(cfg, code, va)) is not None
    }
    src_sigs = {
        va: sig
        for va, code in src_bytes.items()
        if (sig := _signature_for(cfg_src, code, va)) is not None
    }
    matches = cross_match(dest_sigs, src_sigs, min_score=min_score, min_gap=min_gap)

    # Destination VA -> (status, filepath) for choosing the write target and
    # the destination canonical sizes for the rewritten marker.
    statuses = _annotations_by_va(cfg)
    registry = _registry(cfg)

    from rebrew.compile_cache import get_compile_cache

    cache = None
    if not dry_run:
        try:
            cache = get_compile_cache(cfg.root)
        except OSError:
            cache = None

    results: list[dict[str, Any]] = []
    matched_vas = set(matches)
    statuses_src = _annotations_by_va(cfg_src)
    for dst_va in sorted(dest_bytes):
        if dst_va not in matched_vas:
            results.append(
                {
                    "dst_va": f"0x{dst_va:08x}",
                    "src_va": None,
                    "score": None,
                    "action": "skipped",
                    "status": "",
                    "filepath": "",
                    "message": "no unambiguous match above threshold",
                }
            )
            continue
        src_va, score = matches[dst_va]
        src_status, src_file = statuses_src.get(src_va, ("", ""))
        dst_status, dst_file = statuses.get(dst_va, ("", ""))
        dst_size = int(registry[dst_va].get("canonical_size") or 0) if dst_va in registry else 0
        if not src_file:
            results.append(
                {
                    "dst_va": f"0x{dst_va:08x}",
                    "src_va": f"0x{src_va:08x}",
                    "score": score,
                    "action": "skipped",
                    "status": "",
                    "filepath": "",
                    "message": "source function has no source file",
                }
            )
            continue
        res = import_function(
            cfg,
            cfg_src,
            dst_va,
            src_va,
            src_file,
            dst_size,
            dst_file=dst_file or None,
            dry_run=dry_run,
            cache=cache,
        )
        res["score"] = score
        results.append(res)
        if limit is not None and len([r for r in results if r["action"] != "skipped"]) >= limit:
            break

    if json_output:
        json_print({"target": cfg.target_name, "from": from_target, "results": results})
        return

    table = Table(title=f"cross-import {from_target} → {cfg.target_name}", header_style="bold")
    for col in ("Dest VA", "Src VA", "Score", "Action", "Status", "File"):
        table.add_column(col)
    for r in results:
        table.add_row(
            r["dst_va"],
            r["src_va"] or "-",
            f"{r['score']:.1f}" if r["score"] is not None else "-",
            r["action"],
            r["status"] or "-",
            r["filepath"] or "-",
        )
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
