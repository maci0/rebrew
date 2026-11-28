"""cross_import — import matched functions from another target.

Finds functions shared between two targets in one project (the same code at
different VAs — binary versions, or a DLL+EXE pair sharing code) and imports
the already-matched source from one target into the other.

Direction: the target the command runs against is the DESTINATION; ``--from``
names the SOURCE target.  Matching is structural: the source target's matched
functions (EXACT/RELOC) and the destination's unmatched functions are
signature-compared from their **target bytes** via the ``rebrew.compare.similar``
machinery (mnemonic histogram + call/branch agreement — no compilation
needed, so matching works even where the toolchain image is absent).  The
best source match above ``--min-score``, clearly ahead of the runner-up
(``--min-gap``), is imported: the .c binding is rewritten to the destination
VA/SIZE in metadata, the source is written into the destination's ``reversed_dir``, then
the function is compiled + verified against the destination binary and
STATUS is promoted through the standard verify flow — so a wrong match
simply fails verification and stays untouched (reported as skipped).

Functions that differ between the targets, or that have no counterpart,
are left untouched and reported.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import typer

from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
    require_non_negative,
)
from rebrew.cross_import import importer as _importer
from rebrew.cross_import import matching as _matching
from rebrew.cross_import.importer import (
    promote_to_shared,
    retarget_moved_identity,
    rewrite_address,
    source_flags,
    symbol_for_va,
)
from rebrew.cross_import.matching import (
    annotations_by_va,
    disasm_sizes,
    import_size,
    interior_preview_rows,
    library_vas,
    matched_source_bytes,
    merge_sizeless_warning,
    registry,
    same_va_preview_rows,
    sizeless_dest_vas,
    sizeless_warning,
    target_bytes_by_va,
    unmatched_dest_bytes,
)
lazy from rebrew.cli import console
lazy from rebrew.compare.similar import disasm_signature, similarity_score
lazy from rebrew.config import ProjectConfig
lazy from rebrew.utils import TerminalTable
lazy from rebrew.workspace.status import MATCHED_STATUSES

if TYPE_CHECKING:
    from rebrew.compiler.cache import CacheBackend
    from rebrew.compiler.compile import CompareResult
    from rebrew.metadata.bindings import SourceBinding

__all__ = [
    "annotations_by_va",
    "app",
    "cross_match",
    "disasm_signature",
    "disasm_sizes",
    "extract_function_text",
    "import_function",
    "import_shared_function",
    "import_size",
    "interior_preview_rows",
    "library_vas",
    "main",
    "main_entry",
    "matched_source_bytes",
    "merge_sizeless_warning",
    "promote_to_shared",
    "registry",
    "retarget_moved_identity",
    "rewrite_address",
    "same_va_preview_rows",
    "signature_for",
    "sizeless_dest_vas",
    "sizeless_warning",
    "source_flags",
    "symbol_for_va",
    "target_bytes_by_va",
    "unmatched_dest_bytes",
    "verify_import",
]


# ---------------------------------------------------------------------------
# Wrappers injecting command-layer dependencies into the library submodules
# ---------------------------------------------------------------------------


def cross_match(
    dest_sigs: dict[int, dict[str, Any]],
    src_sigs: dict[int, dict[str, Any]],
    min_score: float = 95.0,
    min_gap: float = 5.0,
) -> dict[int, tuple[int, float]]:
    """Map each destination function to its best source-target counterpart."""
    return _matching.cross_match(
        dest_sigs,
        src_sigs,
        min_score=min_score,
        min_gap=min_gap,
        similarity_score_fn=similarity_score,
    )


def signature_for(cfg: ProjectConfig, code: bytes, va: int) -> dict[str, Any] | None:
    """Structural signature excluding proven x86 alignment padding."""
    return _matching.signature_for(cfg, code, va, disasm_signature_fn=disasm_signature)


def verify_import(
    entry: SourceBinding,
    cfg_dst: ProjectConfig,
    *,
    cache: CacheBackend | None,
    name_to_va: dict[str, int] | None,
) -> tuple[CompareResult, int | None]:
    """Verify *entry*, re-verifying at the body size on a merged inventory entry."""
    from rebrew.verify.cli import verify_entry

    return _importer.verify_import(
        entry, cfg_dst, cache=cache, name_to_va=name_to_va, verify_entry_fn=verify_entry
    )


def extract_function_text(text: str, name: str) -> str | None:
    """Copy one C definition, its shared declarations and static dependencies."""
    from rebrew.source.split import shared_preamble

    return _importer.extract_function_text(text, name, shared_preamble_fn=shared_preamble)


def import_shared_function(
    cfg_dst: ProjectConfig,
    cfg_src: ProjectConfig,
    dst_va: int,
    src_va: int,
    src_file: str,
    dst_size: int,
    *,
    dst_file: str | None = None,
    dry_run: bool = False,
    cache: CacheBackend | None = None,
    name_to_va: dict[str, int] | None = None,
    require_resolved: bool = False,
) -> dict[str, Any]:
    """Import by recording a destination row for the SHARED source file."""
    from rebrew.verify.cli import apply_status_updates, verify_entry

    return _importer.import_shared_function(
        cfg_dst,
        cfg_src,
        dst_va,
        src_va,
        src_file,
        dst_size,
        dst_file=dst_file,
        dry_run=dry_run,
        cache=cache,
        name_to_va=name_to_va,
        require_resolved=require_resolved,
        verify_entry_fn=verify_entry,
        apply_status_updates_fn=apply_status_updates,
    )


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
    cache: CacheBackend | None = None,
    name_to_va: dict[str, int] | None = None,
    require_resolved: bool = False,
) -> dict[str, Any]:
    """Import the matched source function *src_file* into the destination."""
    from rebrew.source.split import shared_preamble
    from rebrew.verify.cli import apply_status_updates, verify_entry

    return _importer.import_function(
        cfg_dst,
        cfg_src,
        dst_va,
        src_va,
        src_file,
        dst_size,
        dst_file=dst_file,
        dry_run=dry_run,
        cache=cache,
        name_to_va=name_to_va,
        require_resolved=require_resolved,
        shared_preamble_fn=shared_preamble,
        verify_entry_fn=verify_entry,
        apply_status_updates_fn=apply_status_updates,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Import matched functions from another target (same code, different VAs).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  # Import v1.1's matched functions\n"
        "  rebrew source import-related --from v1.1\n"
        "  rebrew source import-related --from game.exe --min-score 90\n"
        "  rebrew source import-related --from v1.1 --dry-run --json  # Preview\n"
        "  rebrew source import-related --from GOLD --same-va-preview --va 0x401000\n"
        "  rebrew source import-related --from GOLD --interior-preview --va 0x401000\n\n"
        "[dim]Matches the source target's EXACT/RELOC functions against this target's unmatched functions structurally (no compile needed to match); imported sources are verified against this target before STATUS promotion.[/dim]\n\n"
        "[dim]--same-va-preview is read-only: it compares the destination binary bytes at each --va against the source target's matched function reference bytes at the same VA (or --source-va), relocation-masked from the linked image's own base-relocation table, and reports exact/reloc-equal/differ per VA with an inputs digest. It writes nothing and never registers or imports; a same-VA row that does not exist in the destination inventory is still compared directly (unavailable when the source has no matched donor). Structural search for a destination VA is out of scope.[/dim]\n\n"
        "[dim]--interior-preview is read-only: for each --va it reports the containing inventory head (greatest function start at or below the VA), the offset and head end, external call/jmp callers outside the head, and whether the VA bytes open with a function prologue, with an inputs digest. It writes nothing and records no alias.[/dim]"
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
        help="Minimum similarity score (0-100) to import (identical "
        "code scores 100, structural siblings with a shared prologue score "
        "high 80s-low 90s)",
    ),
    min_gap: float = typer.Option(
        5.0, "--min-gap", help="Best match must beat the runner-up by at least this"
    ),
    va: list[str] | None = typer.Option(
        None,
        "--va",
        help="Destination VA(s) to check: with --same-va-preview or "
        "--interior-preview, every "
        "hex VA may be repeated (e.g. 0x401000); otherwise one VA "
        "restricts the import to a single destination",
    ),
    source_va: str | None = typer.Option(
        None,
        "--source-va",
        help="Restrict to one matched source VA (hex); score, gap and verification still apply",
    ),
    limit: int | None = typer.Option(
        None, "--limit", help="Import at most N functions (0 = none; omitted = unlimited)"
    ),
    shared: bool = typer.Option(
        False,
        "--shared",
        help="Record the destination MODULE.0xVA row on the shared source "
        "file instead of copying into the destination tree (one file, one "
        "row per target). Promotes the source into src/shared first when needed",
    ),
    promote: bool = typer.Option(
        False,
        "--promote",
        help="Move the source file into src/shared (preserving relative path) "
        "without importing, the manual step before --shared",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    same_va_preview: bool = typer.Option(
        False,
        "--same-va-preview",
        help="Read-only byte check only: report exact/reloc-equal/differ per --va "
        "against the --from target's matched function at the same VA (or "
        "--source-va), with an inputs digest. Writes nothing.",
    ),
    interior_preview: bool = typer.Option(
        False,
        "--interior-preview",
        help="Read-only interior-entry evidence only: report the containing "
        "inventory head, offset, head end, external call/jmp callers and "
        "prologue per --va, with an inputs digest. Writes nothing.",
    ),
    require_resolved: bool = typer.Option(
        False,
        "--require-resolved",
        help="Record an import only when every relocation operand binds in the "
        "destination; otherwise report it as skipped-unresolved and write nothing",
    ),
    candidates_only: bool = typer.Option(
        False,
        "--candidates-only",
        help="Report only destination functions with a match: the per-function "
        "'no match' rows for the whole inventory are hidden (use with "
        "--dry-run to answer 'is this code already reversed in another target, "
        "and where?')",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Cross-target function import."""
    if limit is not None:
        require_non_negative(limit, "--limit", json_mode=json_output)
    cfg = require_config(target=target, json_mode=json_output)
    cfg_src = require_config(target=from_target, json_mode=json_output)
    if cfg_src.target_name == cfg.target_name:
        error_exit("--from must name a different target", json_mode=json_output)

    if va and len(va) > 1 and not same_va_preview and not interior_preview:
        error_exit(
            "--va may be repeated only with --same-va-preview or --interior-preview "
            "(the import flow takes one destination VA)",
            json_mode=json_output,
        )
    if same_va_preview and interior_preview:
        error_exit(
            "--same-va-preview and --interior-preview are mutually exclusive",
            json_mode=json_output,
        )
    only_vas = [parse_va(v, json_mode=json_output) for v in (va or [])]
    only_va = only_vas[0] if only_vas else None
    only_source_va = parse_va(source_va, json_mode=json_output) if source_va else None

    if same_va_preview:
        if not only_vas:
            error_exit(
                "--same-va-preview requires --va (repeatable; one or more hex VAs)",
                json_mode=json_output,
            )
        if only_source_va is not None and len(only_vas) != 1:
            error_exit(
                "--source-va with --same-va-preview requires exactly one --va",
                json_mode=json_output,
            )
        source_vas = {only_vas[0]: only_source_va} if only_source_va is not None else None
        rows, inputs_digest = same_va_preview_rows(cfg_src, cfg, only_vas, source_vas=source_vas)
        payload: dict[str, Any] = {
            "target": cfg.target_name,
            "from": from_target,
            "mode": "same-va-preview",
            "dry_run": True,
            "results": rows,
            "inputs_digest": inputs_digest,
        }
        if json_output:
            json_print(payload)
            return
        table = TerminalTable(
            title=f"source import-related --same-va-preview {from_target} → {cfg.target_name}",
            header_style="bold",
        )
        for col in ("Dest VA", "Src VA", "Size", "Verdict", "Message"):
            table.add_column(col)
        for row in rows:
            table.add_row(
                row["dst_va"],
                row.get("src_va") or "-",
                str(row["size"]) if row.get("size") is not None else "-",
                row["verdict"],
                row["message"],
            )
        console.print(table)
        console.print(f"[dim]inputs_digest {inputs_digest}[/dim]")
        return

    if interior_preview:
        if not only_vas:
            error_exit(
                "--interior-preview requires --va (repeatable; one or more hex VAs)",
                json_mode=json_output,
            )
        rows, inputs_digest = interior_preview_rows(cfg, only_vas)
        payload = {
            "target": cfg.target_name,
            "from": from_target,
            "mode": "interior-preview",
            "dry_run": True,
            "results": rows,
            "inputs_digest": inputs_digest,
        }
        if json_output:
            json_print(payload)
            return
        table = TerminalTable(
            title=f"source import-related --interior-preview {from_target} \u2192 {cfg.target_name}",
            header_style="bold",
        )
        for col in ("VA", "Head VA", "Offset", "Head End", "External Callers", "Prologue"):
            table.add_column(col)
        for row in rows:
            table.add_row(
                row["va"],
                row.get("head_va") or "-",
                str(row["head_offset"]) if row.get("head_offset") is not None else "-",
                row.get("head_end") or "-",
                str(row["external_callers"]),
                str(row["prologue"]),
            )
        console.print(table)
        console.print(f"[dim]inputs_digest {inputs_digest}[/dim]")
        return

    try:
        dest_bytes = unmatched_dest_bytes(cfg, only_va)
        src_bytes = matched_source_bytes(cfg_src)
    except (OSError, ValueError) as exc:
        error_exit(f"cannot read target binary: {exc}", json_mode=json_output)
    if only_source_va is not None:
        if only_source_va not in src_bytes:
            error_exit(
                f"source VA 0x{only_source_va:x} is not an available EXACT/RELOC donor "
                f"in target {from_target!r}",
                json_mode=json_output,
            )
        src_bytes = {only_source_va: src_bytes[only_source_va]}
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
        if (sig := signature_for(cfg, code, va)) is not None
    }
    src_sigs = {
        va: sig
        for va, code in src_bytes.items()
        if (sig := signature_for(cfg_src, code, va)) is not None
    }
    matches = cross_match(dest_sigs, src_sigs, min_score=min_score, min_gap=min_gap)

    # Destination VA -> (status, filepath) for choosing the write target and
    # the destination canonical sizes for the rewritten binding.
    statuses = annotations_by_va(cfg)
    entries = registry(cfg)

    from rebrew.compiler.cache import get_project_cache

    cache = None
    if not dry_run:
        try:
            cache = get_project_cache(cfg)
        except OSError:
            cache = None
    # Verification masks a typed relocation only when it can resolve the symbol,
    # as `rebrew test` and `verify` do; build the destination's map once.
    name_to_va: dict[str, int] | None = None
    if not dry_run:
        from rebrew.compare.coff_reloc import CatalogScanError, build_name_to_va

        try:
            name_to_va = build_name_to_va(cfg)
        except CatalogScanError as exc:
            error_exit(str(exc), json_mode=json_output)

    results: list[dict[str, Any]] = []
    matched_vas = set(matches)
    statuses_src = annotations_by_va(cfg_src)
    # Sizeless refusals: the registry has no size and the disassembler
    # cannot derive one — surface the guidance instead of silently
    # dropping the function from every match.
    _disasm_sized, refused = sizeless_dest_vas(cfg)
    disasm_sized = {
        va
        for va in _disasm_sized
        if statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES
        and (only_va is None or va == only_va)
    }
    refused = [
        va
        for va in refused
        if statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES
        and (only_va is None or va == only_va)
        and va not in dest_bytes
    ]
    # A source file is ONE function body: importing it at several destination
    # VAs records several rows on that one body, which only works when the
    # destinations really are byte-identical copies.  When they are not, the
    # extra rows are guaranteed mismatches on a shared body (guild-rebrew:
    # one GOLD function was recorded at GOLDTL 0x659fbf and
    # 0x6508a3 with 9- and 11-byte spans).  Import the best-scoring match per
    # source file; further destination VAs need a deliberate twin.
    imported_src_files: dict[str, str] = {}
    non_skipped = sum(1 for r in results if not r["action"].startswith("skipped"))
    for dst_va in sorted(dest_bytes):
        # Budget BEFORE importing: the old post-import guard ran with the
        # first import already appended, so ``--limit 0`` still imported one.
        if limit is not None and non_skipped >= limit:
            break
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
        dst_size = int(entries[dst_va].get("canonical_size") or 0) if dst_va in entries else 0
        disasm_size: int | None = None
        if dst_va in disasm_sized:
            dst_size = len(dest_bytes[dst_va])
            disasm_size = dst_size
        else:
            # A stale registry size would verify only a prefix of a body the
            # matcher already matched in full (see import_size).
            dst_size = import_size(dst_size, src_bytes.get(src_va))
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
        prev_dst = imported_src_files.get(src_file)
        if prev_dst is not None:
            results.append(
                {
                    "dst_va": f"0x{dst_va:08x}",
                    "src_va": f"0x{src_va:08x}",
                    "score": score,
                    "action": "skipped",
                    "status": "",
                    "filepath": src_file,
                    "src_file": src_file,
                    "src_status": src_status,
                    "message": (
                        f"source already imported for {prev_dst}; a second "
                        "destination VA needs a deliberate twin"
                    ),
                }
            )
            continue
        if promote:
            res = promote_to_shared(cfg_src, src_file, dry_run=dry_run)
            res.update({"dst_va": f"0x{dst_va:08x}", "src_va": f"0x{src_va:08x}", "score": score})
            results.append(res)
            continue
        if shared and getattr(cfg_src, "shared_dir", None) is not None:
            # The shared tree only works when the file lives under the shared
            # root. Auto-promote a per-target source there first so the
            # recorded row names the one file every target scans. An existing
            # shared copy still goes through this call: it may be a move whose
            # metadata publication was interrupted.
            promo = promote_to_shared(cfg_src, src_file, dry_run=dry_run)
            if promo["action"] == "error":
                promo.update(
                    {"dst_va": f"0x{dst_va:08x}", "src_va": f"0x{src_va:08x}", "score": score}
                )
                results.append(promo)
                continue
        try:
            res = (
                import_shared_function(
                    cfg,
                    cfg_src,
                    dst_va,
                    src_va,
                    src_file,
                    dst_size,
                    dst_file=dst_file or None,
                    dry_run=dry_run,
                    cache=cache,
                    name_to_va=name_to_va,
                    require_resolved=require_resolved,
                )
                if shared
                else import_function(
                    cfg,
                    cfg_src,
                    dst_va,
                    src_va,
                    src_file,
                    dst_size,
                    dst_file=dst_file or None,
                    dry_run=dry_run,
                    cache=cache,
                    name_to_va=name_to_va,
                    require_resolved=require_resolved,
                )
            )
        except ValueError as exc:
            # One unsuitable donor (for example a definition inside a target
            # #if block) must not abort the batch: report it as a row and keep
            # matching the remaining candidates.
            results.append(
                {
                    "dst_va": f"0x{dst_va:08x}",
                    "src_va": f"0x{src_va:08x}",
                    "score": score,
                    "action": "error",
                    "status": "",
                    "filepath": src_file,
                    "src_file": src_file,
                    "src_status": src_status,
                    "dst_status": dst_status,
                    "message": str(exc),
                }
            )
            continue
        res["score"] = score
        # The question this command answers is "is this code already reversed
        # somewhere, and where?".  The destination path alone cannot answer it
        # in a unified tree (both are often the same file), so every row names
        # the SOURCE function, its file and its earned STATUS.
        res["src_file"] = src_file
        res["src_status"] = src_status
        res["dst_status"] = dst_status
        merge_sizeless_warning(res, disasm_size)
        if not res["action"].startswith("skipped") and res["action"] != "error":
            imported_src_files[src_file] = res["dst_va"]
        if not res["action"].startswith("skipped"):
            non_skipped += 1
        results.append(res)

    for refused_va in refused:
        results.append(
            {
                "dst_va": f"0x{refused_va:08x}",
                "src_va": None,
                "score": None,
                "action": "skipped",
                "status": "",
                "filepath": "",
                "message": "sizeless function: no registry size and no clean "
                "disassembly extent — pass --va to match this VA explicitly",
            }
        )

    skipped = sum(1 for r in results if r["action"].startswith("skipped"))
    if candidates_only:
        # A "find what is already reversed elsewhere" run has four thousand
        # destination functions and a handful of findings: the per-function
        # "no match" rows are noise in both the table and the JSON.
        results = [r for r in results if not r["action"].startswith("skipped")]

    if json_output:
        payload = {
            "target": cfg.target_name,
            "from": from_target,
            "results": results,
        }
        if candidates_only:
            payload["skipped_count"] = skipped
        json_print(payload)
        return

    table = TerminalTable(
        title=f"source import-related {from_target} → {cfg.target_name}", header_style="bold"
    )
    for col in (
        "Dest VA",
        "Src VA",
        "Score",
        "Action",
        "Status",
        "Src File",
        "Dest File",
    ):
        table.add_column(col)
    for r in results:
        table.add_row(
            r["dst_va"],
            r["src_va"] or "-",
            f"{r['score']:.1f}" if r["score"] is not None else "-",
            r["action"],
            r["status"] or "-",
            r.get("src_file") or "-",
            r["filepath"] or "-",
        )
    console.print(table)
    unresolved_rows = [r["dst_va"] for r in results if r.get("unresolved_relocations")]
    if unresolved_rows:
        console.print(
            f"[yellow]{len(unresolved_rows)} row(s) carry relocation operands unresolved in "
            f"{cfg.target_name}[/yellow] ({', '.join(unresolved_rows[:5])}"
            f"{', ...' if len(unresolved_rows) > 5 else ''}): the compare masked them without "
            f"proof, and the body names callees or globals by {from_target} spelling. They will "
            "not link until those names exist here; see unresolved_relocations in --json, or "
            "use --require-resolved to record only fully bound imports."
        )
    if candidates_only:
        console.print(
            f"[dim]{skipped} destination function(s) had no match above the "
            "threshold (hidden by --candidates-only)[/dim]"
        )
    if not shared and not dry_run and getattr(cfg, "shared_dir", None) is not None:
        imported = sum(1 for r in results if r["action"] in ("imported", "imported-unverified"))
        if imported:
            console.print(
                "[dim]Copies drift. Re-run with --shared to record these on "
                "one src/shared file instead.[/dim]"
            )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
