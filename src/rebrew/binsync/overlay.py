"""overlay.py: overlay a related target's BinSync data onto matched functions.

Two targets in one project (a DLL/EXE pair, or two versions) can share code at
different VAs.  This command structurally matches the related target's BinSync
functions against this target's unmatched functions (reusing the
:mod:`rebrew.cross_import` matcher, so no compilation is needed) and overlays
the BinSync names, prototypes, and notes field by field.

Direction: the target the command runs against is the DESTINATION; the state
directory names the SOURCE, from ``--from`` or the state ``manifest.toml``
``target`` key.  A conflict (both sides carry a meaningful, differing value)
follows the ``binsync-import`` policy: ``--accept-binsync`` takes the remote
value, ``--accept-local`` keeps the local one and records the remote value as
``GHIDRA`` provenance, and with neither the conflict is reported and nothing
is written (exit 1).

Globals are address-keyed to the source binary, so they are matched by exact
content instead: the source global's bytes are searched in the destination
binary's same-named section and mapped only when they occur exactly once.
Globals are opt-in via ``--fields global`` (or ``--fields name,prototype,note,global``).

After the per-function fields, unknown struct, enum, and typedef definitions in
the state import into the destination's ``binsync_types.h`` (known names are
never overwritten).

Typical flow::

    rebrew binsync-overlay ../v1/state --dry-run     # preview
    rebrew binsync-overlay ../v1/state --accept-binsync
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.binsync.importer import (
    _apply_binsync_func_name,
    _import_structs,
    _import_type_definitions,
    _is_meaningful,
    _normalize_prototype,
    _strip_cdecl_prefix,
)
from rebrew.binsync.state import (
    load_binsync_comments,
    load_binsync_enums,
    load_binsync_state,
    load_binsync_structs,
    load_binsync_typedefs,
    load_manifest,
)
from rebrew.cli import EXIT_MISMATCH, TargetOption, error_exit, json_print, require_config
from rebrew.config import ProjectConfig
from rebrew.cross_import import (
    _annotations_by_va,
    _disasm_sizes,
    _registry,
    _signature_for,
    _target_bytes_by_va,
    cross_match,
    unmatched_dest_bytes,
)
from rebrew.utils import strip_body

log = logging.getLogger(__name__)

console = Console(stderr=True)

#: Overlayable fields, in report order.  ``global`` is opt-in (not in the
#: default ``--fields`` set) because it needs the source and destination
#: binaries, not just their function catalogs.
_VALID_FIELDS: tuple[str, ...] = ("name", "prototype", "note", "global")

#: Keys the ``--json`` payload carries (in emission order).
_JSON_KEYS: tuple[str, ...] = (
    "state_dir",
    "from_target",
    "target",
    "dry_run",
    "matches",
    "applied_names",
    "applied_prototypes",
    "applied_notes",
    "applied_globals",
    "applied_structs",
    "applied_enums",
    "applied_typedefs",
    "applied_locals",
    "applied_comments",
    "skipped",
    "touched_vas",
    "conflicts",
    "proposed",
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _hex(va: int) -> str:
    """Format *va* as the canonical ``0x%08x`` report string."""
    return f"0x{va:08x}"


def _parse_fields(raw: str, *, json_mode: bool) -> set[str]:
    """Parse and validate the ``--fields`` comma list."""
    requested = {part.strip().lower() for part in raw.split(",") if part.strip()}
    unknown = requested - set(_VALID_FIELDS)
    if unknown:
        error_exit(
            f"unknown --fields value(s): {', '.join(sorted(unknown))} "
            f"(valid: {', '.join(_VALID_FIELDS)})",
            json_mode=json_mode,
        )
    return requested


def _conflict(dst_va: int, src_va: int, field: str, local: str, remote: str) -> dict[str, str]:
    return {
        "va": _hex(dst_va),
        "src_va": _hex(src_va),
        "field": field,
        "local": local,
        "remote": remote,
    }


def _proposal(
    dst_va: int, src_va: int, field: str, local: str, remote: str, action: str
) -> dict[str, str]:
    return {
        "va": _hex(dst_va),
        "src_va": _hex(src_va),
        "field": field,
        "local": local,
        "remote": remote,
        "action": action,
    }


def match_globals_by_content(
    src_bytes: dict[int, bytes], spans: list[tuple[int, bytes]]
) -> dict[int, int]:
    """Map source global VAs to destination VAs by unique exact content.

    *spans* is ``(span_va, span_bytes)`` pairs (one per destination section).
    For each source VA the number of exact occurrences of its bytes across
    every span is counted; the VA maps to ``span_va + offset`` only when the
    content occurs exactly once in total.  A duplicate (two occurrences) or an
    absent blob leaves the source VA unmapped, never guessed.
    """
    out: dict[int, int] = {}
    for src_va, needle in src_bytes.items():
        if not needle:
            continue
        total = 0
        hit = -1
        for span_va, span in spans:
            count = span.count(needle)
            if not count:
                continue
            total += count
            if total > 1:
                break
            hit = span_va + span.find(needle)
        if total == 1:
            out[src_va] = hit
    return out


def _source_signatures(cfg_src: ProjectConfig, vas: list[int]) -> dict[int, dict[str, Any]]:
    """Structural signatures for the source target's BinSync function VAs.

    Each VA takes its catalog ``canonical_size``; sizeless VAs fall back to
    the disassembly-derived extent.  VAs with no size or no readable bytes are
    skipped (they simply cannot participate in the match).
    """
    registry = _registry(cfg_src)
    sizes: dict[int, int] = {}
    for va in vas:
        entry = registry.get(va)
        size = int(entry.get("canonical_size") or 0) if entry is not None else 0
        if size > 0:
            sizes[va] = size
    sizeless = [va for va in vas if va not in sizes]
    if sizeless:
        disasm_sizes, _refused = _disasm_sizes(cfg_src, sizeless)
        sizes.update(disasm_sizes)
    codes = _target_bytes_by_va(cfg_src, sizes)
    out: dict[int, dict[str, Any]] = {}
    for va, code in codes.items():
        sig = _signature_for(cfg_src, code, va)
        if sig is not None:
            out[va] = sig
    return out


def _dest_signatures(cfg: ProjectConfig) -> dict[int, dict[str, Any]]:
    """Structural signatures for this target's not-yet-matched functions."""
    codes = unmatched_dest_bytes(cfg)
    out: dict[int, dict[str, Any]] = {}
    for va, code in codes.items():
        sig = _signature_for(cfg, code, va)
        if sig is not None:
            out[va] = sig
    return out


def _dest_annotation(cfg: ProjectConfig, va: int, filepath: str) -> Any:
    """The local :class:`~rebrew.annotation.Annotation` for *(va, filepath)*."""
    if not filepath:
        return None
    from rebrew.annotation import parse_c_file_multi

    try:
        annotations = parse_c_file_multi(
            Path(cfg.reversed_dir) / filepath,
            target_name=cfg.target_name,
            base_dir=cfg.reversed_dir,
            metadata_dir=cfg.metadata_dir,
        )
    except OSError:
        log.debug("cannot parse local annotation file %s", filepath, exc_info=True)
        return None
    for ann in annotations:
        if ann.va == va:
            return ann
    return None


def _section_for_va(info: Any, va: int) -> str:
    """Name of the binary section containing *va* (empty when none)."""
    for name, section in info.sections.items():
        extent = max(section.size or 0, section.raw_size or 0)
        if section.va <= va < section.va + extent:
            return str(name)
    return ""


def _apply_global_entry(
    cfg: ProjectConfig,
    dst_va: int,
    bs_name: str,
    entry: dict[str, Any],
    section: str,
    module: str,
) -> None:
    """Write a matched BinSync global's fields to the destination metadata.

    The name is always written; ``type``/``size``/``section`` follow when the
    source record carries them.  ``section`` uses the destination's own
    section name (the span the content was matched in).
    """
    from rebrew.data_metadata import set_data_field

    set_data_field(cfg.metadata_dir, dst_va, "name", bs_name, module)
    type_value = str(entry.get("type") or "").strip()
    if type_value:
        set_data_field(cfg.metadata_dir, dst_va, "type", type_value, module)
    size_value = str(entry.get("size") or "").strip()
    if size_value:
        set_data_field(cfg.metadata_dir, dst_va, "size", int(size_value, 0), module)
    set_data_field(cfg.metadata_dir, dst_va, "section", section, module)


# ---------------------------------------------------------------------------
# Overlay core
# ---------------------------------------------------------------------------


def overlay_state(
    cfg: ProjectConfig,
    cfg_src: ProjectConfig,
    state_dir: Path,
    funcs_by_va: dict[int, dict[str, Any]],
    globals_by_va: dict[int, dict[str, Any]],
    *,
    fields: set[str],
    module: str | None,
    min_score: float,
    min_gap: float,
    accept_binsync: bool,
    accept_local: bool,
    dry_run: bool,
) -> dict[str, Any]:
    """Match and overlay the source target's BinSync data onto *cfg*.

    *globals_by_va* carries the source state's ``global_vars.toml`` records,
    used only when ``"global"`` is in *fields*.  Returns the report dict
    (documented ``--json`` keys plus a ``rows`` list for the non-JSON table).
    Writes happen only when *dry_run* is False.
    """
    from rebrew.annotation import update_annotation_key
    from rebrew.metadata import get_entry, update_field

    src_sigs = _source_signatures(cfg_src, sorted(funcs_by_va))
    dest_sigs = _dest_signatures(cfg)
    matches = cross_match(dest_sigs, src_sigs, min_score=min_score, min_gap=min_gap)

    statuses = _annotations_by_va(cfg)
    applied_names = 0
    applied_prototypes = 0
    applied_notes = 0
    applied_locals = 0
    applied_comments = 0
    skipped = 0
    touched: set[int] = set()
    conflicts: list[dict[str, str]] = []
    proposed: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []

    # Per-instruction comments (provenance comments are skipped here: note and
    # ghidra travel through the function entry instead).
    src_comments_by_func: dict[int, dict[int, dict[str, Any]]] = {}
    for addr, comment in load_binsync_comments(state_dir).items():
        text = str(comment.get("comment") or "")
        if text.startswith("[rebrew:"):
            continue
        owner = comment.get("func_addr")
        if isinstance(owner, int):
            src_comments_by_func.setdefault(owner, {})[addr] = {
                "comment": text,
                "func_addr": owner,
            }

    for dst_va in sorted(matches):
        src_va, score = matches[dst_va]
        remote = funcs_by_va.get(src_va, {})
        _status, filepath = statuses.get(dst_va, ("", ""))
        local = _dest_annotation(cfg, dst_va, filepath)
        if local is None:
            skipped += 1
            rows.append(
                {"dst_va": _hex(dst_va), "src_va": _hex(src_va), "score": score, "fields": ""}
            )
            continue
        local_module = getattr(local, "module", "") or ""
        if module is not None and local_module != module:
            skipped += 1
            continue
        file_path = Path(cfg.reversed_dir) / filepath
        applied: list[str] = []

        if "name" in fields:
            bs_name = remote.get("name", "")
            local_name = getattr(local, "symbol", "") or getattr(local, "name", "") or ""
            bs_stripped = _strip_cdecl_prefix(bs_name) if bs_name.startswith("_") else bs_name
            local_stripped = (
                _strip_cdecl_prefix(local_name) if local_name.startswith("_") else local_name
            )
            if bs_name and _is_meaningful(bs_name) and bs_stripped != local_stripped:
                if not _is_meaningful(local_name):
                    if dry_run:
                        proposed.append(
                            _proposal(dst_va, src_va, "name", local_name, bs_name, "would rename")
                        )
                        applied_names += 1
                        applied.append("name")
                    else:
                        try:
                            if _apply_binsync_func_name(cfg, local, bs_stripped, filepath):
                                applied_names += 1
                                touched.add(dst_va)
                                applied.append("name")
                            else:
                                skipped += 1
                        except Exception:
                            log.debug("name overlay failed for VA %s", _hex(dst_va), exc_info=True)
                            skipped += 1
                else:
                    conflicts.append(_conflict(dst_va, src_va, "name", local_name, bs_name))
                    if accept_binsync:
                        if dry_run:
                            proposed.append(
                                _proposal(
                                    dst_va,
                                    src_va,
                                    "name",
                                    local_name,
                                    bs_name,
                                    "would rename (accept-binsync)",
                                )
                            )
                            applied.append("name")
                        else:
                            try:
                                if _apply_binsync_func_name(cfg, local, bs_stripped, filepath):
                                    applied_names += 1
                                    touched.add(dst_va)
                                    applied.append("name")
                                else:
                                    skipped += 1
                            except Exception:
                                log.debug(
                                    "name overlay failed for VA %s", _hex(dst_va), exc_info=True
                                )
                                skipped += 1
                    elif accept_local:
                        if not dry_run:
                            try:
                                update_field(
                                    cfg.metadata_dir, dst_va, "ghidra", bs_name, local_module
                                )
                                touched.add(dst_va)
                                applied.append("ghidra")
                            except Exception:
                                log.debug(
                                    "GHIDRA provenance write failed for VA %s",
                                    _hex(dst_va),
                                    exc_info=True,
                                )
                                skipped += 1
                        proposed.append(
                            _proposal(
                                dst_va,
                                src_va,
                                "name",
                                local_name,
                                bs_name,
                                "keep local (accept-local)",
                            )
                        )

        if "prototype" in fields:
            bs_proto = (remote.get("prototype") or "").strip()
            raw_local = getattr(local, "prototype", "") or ""
            local_proto = strip_body(raw_local) if raw_local else ""
            if bs_proto and _normalize_prototype(bs_proto) != _normalize_prototype(local_proto):
                if local_proto:
                    conflicts.append(_conflict(dst_va, src_va, "prototype", local_proto, bs_proto))
                if not local_proto or accept_binsync:
                    if dry_run:
                        proposed.append(
                            _proposal(
                                dst_va, src_va, "prototype", local_proto, bs_proto, "would update"
                            )
                        )
                        applied_prototypes += 1
                        applied.append("prototype")
                    else:
                        try:
                            update_annotation_key(
                                file_path,
                                dst_va,
                                "PROTOTYPE",
                                bs_proto,
                                metadata_dir=cfg.metadata_dir,
                            )
                            applied_prototypes += 1
                            touched.add(dst_va)
                            applied.append("prototype")
                        except Exception:
                            log.debug(
                                "prototype overlay failed for VA %s", _hex(dst_va), exc_info=True
                            )
                            skipped += 1
                elif accept_local:
                    proposed.append(
                        _proposal(
                            dst_va,
                            src_va,
                            "prototype",
                            local_proto,
                            bs_proto,
                            "keep local (accept-local)",
                        )
                    )

        if "note" in fields:
            bs_note = (remote.get("note") or "").strip()
            if bs_note:
                local_note = str(
                    get_entry(cfg.metadata_dir, dst_va, local_module).get("note") or ""
                )
                if local_note.strip() != bs_note:
                    if dry_run:
                        proposed.append(
                            _proposal(dst_va, src_va, "note", local_note, bs_note, "would update")
                        )
                        applied_notes += 1
                        applied.append("note")
                    else:
                        try:
                            update_field(cfg.metadata_dir, dst_va, "note", bs_note, local_module)
                            applied_notes += 1
                            touched.add(dst_va)
                            applied.append("note")
                        except Exception:
                            log.debug("note overlay failed for VA %s", _hex(dst_va), exc_info=True)
                            skipped += 1

        # LOCALS: frame offsets are address-independent, so a matched pair
        # keeps the source's stack variables unchanged.
        stack_vars = remote.get("stack_vars")
        if isinstance(stack_vars, dict) and stack_vars:
            normalized = {
                str(offset): {
                    "name": str(value.get("name") or ""),
                    "type": str(value.get("type") or ""),
                    "size": int(value.get("size") or 0),
                }
                for offset, value in stack_vars.items()
                if isinstance(value, dict)
            }
            if normalized:
                if dry_run:
                    applied_locals += 1
                    applied.append("locals")
                else:
                    try:
                        update_field(cfg.metadata_dir, dst_va, "locals", normalized, local_module)
                        applied_locals += 1
                        touched.add(dst_va)
                        applied.append("locals")
                    except Exception:
                        log.debug("locals overlay failed for VA %s", _hex(dst_va), exc_info=True)
                        skipped += 1

        # COMMENTS: shift each comment addr by (dst_va - src_va), only for
        # addrs inside the source function's range.
        source_comments = src_comments_by_func.get(src_va)
        if source_comments:
            src_size = int(str(remote.get("size") or 0) or 0)
            shifted: dict[str, dict[str, Any]] = {}
            markers: dict[int, str] = {}
            for addr, info in source_comments.items():
                if src_size <= 0 or not (src_va <= addr < src_va + src_size):
                    continue
                new_addr = addr + (dst_va - src_va)
                shifted[f"0x{new_addr:08x}"] = {
                    "comment": info["comment"],
                    "func_addr": dst_va,
                }
                markers[new_addr] = str(info["comment"])
            if shifted:
                if dry_run:
                    applied_comments += len(shifted)
                    applied.append("comments")
                else:
                    try:
                        update_field(cfg.metadata_dir, dst_va, "comments", shifted, local_module)
                        applied_comments += len(shifted)
                        touched.add(dst_va)
                        applied.append("comments")
                    except Exception:
                        log.debug("comments overlay failed for VA %s", _hex(dst_va), exc_info=True)
                        skipped += 1
                    filepath = getattr(local, "filepath", "") or ""
                    if markers and filepath:
                        from rebrew.binsync.state import write_analysis_markers

                        try:
                            write_analysis_markers(Path(cfg.reversed_dir) / filepath, markers)
                        except OSError:
                            log.debug(
                                "ANALYSIS marker write failed for %s", filepath, exc_info=True
                            )

        rows.append(
            {
                "dst_va": _hex(dst_va),
                "src_va": _hex(src_va),
                "score": score,
                "fields": ",".join(applied),
            }
        )

    applied_globals = 0
    if "global" in fields and globals_by_va:
        from rebrew.binary_loader import extract_bytes_at_va, load_binary
        from rebrew.data_metadata import get_data_entry

        try:
            src_info = load_binary(cfg_src.target_binary)
            dst_info = load_binary(cfg.target_binary)
        except (OSError, ValueError):
            log.debug("global overlay: cannot load binaries", exc_info=True)
        else:
            # Group source blobs by section so each is searched only in the
            # destination's same-named section (never guessed across sections).
            by_section: dict[str, dict[int, bytes]] = {}
            for src_va, entry in sorted(globals_by_va.items()):
                size = int(entry.get("size") or 0)
                if size <= 0:
                    skipped += 1
                    continue
                section = _section_for_va(src_info, src_va)
                if not section or section not in dst_info.sections:
                    skipped += 1
                    continue
                raw = extract_bytes_at_va(src_info, src_va, size, trim_padding=False)
                if not raw:
                    skipped += 1
                    continue
                by_section.setdefault(section, {})[src_va] = raw

            mapping: dict[int, tuple[int, str]] = {}
            for section, group in by_section.items():
                dest_section = dst_info.sections[section]
                span = dst_info.data[
                    dest_section.file_offset : dest_section.file_offset + dest_section.raw_size
                ]
                matched = match_globals_by_content(group, [(dest_section.va, span)])
                for src_va, dst_va in matched.items():
                    mapping[src_va] = (dst_va, section)
            skipped += sum(len(group) for group in by_section.values()) - len(mapping)

            mod = module or getattr(cfg, "marker", "") or "SERVER"
            for src_va, (dst_va, section) in sorted(mapping.items()):
                entry = globals_by_va.get(src_va, {})
                bs_name = (entry.get("name") or "").strip()
                if not bs_name or not _is_meaningful(bs_name):
                    skipped += 1
                    continue
                local_name = str(
                    get_data_entry(cfg.metadata_dir, dst_va, mod).get("name") or ""
                ).strip()
                if local_name == bs_name:
                    continue
                if _is_meaningful(local_name):
                    conflicts.append(_conflict(dst_va, src_va, "name", local_name, bs_name))
                    if accept_binsync:
                        if dry_run:
                            proposed.append(
                                _proposal(
                                    dst_va,
                                    src_va,
                                    "global",
                                    local_name,
                                    bs_name,
                                    "would rename (accept-binsync)",
                                )
                            )
                            applied_globals += 1
                        else:
                            try:
                                _apply_global_entry(cfg, dst_va, bs_name, entry, section, mod)
                                applied_globals += 1
                                touched.add(dst_va)
                            except Exception:
                                log.debug(
                                    "global overlay failed for VA %s",
                                    _hex(dst_va),
                                    exc_info=True,
                                )
                                skipped += 1
                    elif accept_local:
                        proposed.append(
                            _proposal(
                                dst_va,
                                src_va,
                                "global",
                                local_name,
                                bs_name,
                                "keep local (accept-local)",
                            )
                        )
                    continue
                if dry_run:
                    proposed.append(
                        _proposal(dst_va, src_va, "global", local_name, bs_name, "would update")
                    )
                    applied_globals += 1
                else:
                    try:
                        _apply_global_entry(cfg, dst_va, bs_name, entry, section, mod)
                        applied_globals += 1
                        touched.add(dst_va)
                    except Exception:
                        log.debug("global overlay failed for VA %s", _hex(dst_va), exc_info=True)
                        skipped += 1

    applied_structs = 0
    structs = load_binsync_structs(state_dir)
    if structs:
        applied_structs = _import_structs(cfg, structs, dry_run=dry_run, proposed=proposed)

    applied_enums = 0
    enums = load_binsync_enums(state_dir)
    if enums:
        applied_enums = _import_type_definitions(cfg, enums, dry_run=dry_run, proposed=proposed)

    applied_typedefs = 0
    typedefs = load_binsync_typedefs(state_dir)
    if typedefs:
        applied_typedefs = _import_type_definitions(
            cfg, typedefs, dry_run=dry_run, proposed=proposed
        )

    return {
        "state_dir": str(state_dir),
        "from_target": cfg_src.target_name,
        "target": cfg.target_name,
        "dry_run": dry_run,
        "matches": len(matches),
        "applied_names": applied_names,
        "applied_prototypes": applied_prototypes,
        "applied_notes": applied_notes,
        "applied_globals": applied_globals,
        "applied_structs": applied_structs,
        "applied_enums": applied_enums,
        "applied_typedefs": applied_typedefs,
        "applied_locals": applied_locals,
        "applied_comments": applied_comments,
        "skipped": skipped,
        "touched_vas": [_hex(va) for va in sorted(touched)],
        "conflicts": conflicts,
        "proposed": proposed,
        "rows": rows,
    }


def _print_result(result: dict[str, Any], *, resolved: bool) -> None:
    """Render the Rich table plus the one-line summary."""
    table = Table(
        title=f"binsync-overlay {result['from_target']} -> {result['target']}",
        header_style="bold",
    )
    for col in ("Dest VA", "Src VA", "Score", "Fields"):
        table.add_column(col)
    for row in result.get("rows") or []:
        table.add_row(
            row["dst_va"],
            row["src_va"],
            f"{row['score']:.1f}",
            row.get("fields") or "-",
        )
    console.print(table)

    for conflict in result["conflicts"]:
        console.print(
            f"[yellow]CONFLICT[/yellow] {conflict['va']} {conflict['field']}: "
            f"local={conflict['local']!r} vs remote={conflict['remote']!r}"
        )
    verb = "Would apply" if result["dry_run"] else "Applied"
    console.print(
        f"[green]{verb}[/green] {result['applied_names']} name(s), "
        f"{result['applied_prototypes']} prototype(s), {result['applied_notes']} note(s), "
        f"{result['applied_globals']} global(s), {result['applied_structs']} struct(s), "
        f"{result['applied_enums']} enum(s), {result['applied_typedefs']} typedef(s), "
        f"{result['applied_locals']} locals, {result['applied_comments']} comment(s) "
        f"from [cyan]{result['from_target']}[/cyan]"
    )
    if result["conflicts"] and not resolved:
        console.print(
            f"[yellow]{len(result['conflicts'])} conflict(s)[/yellow], re-run with "
            "[cyan]--accept-binsync[/cyan] or [cyan]--accept-local[/cyan] to resolve"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Overlay a related target's BinSync names onto this target.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync-overlay ../v1/state --dry-run · · Preview\n\n"
        "  rebrew binsync-overlay ../v1/state --accept-binsync\n\n"
        "  rebrew binsync-overlay ./state --fields name,prototype\n\n"
        "  rebrew binsync-overlay ./state --fields global\n\n"
        "[dim]Structurally matches the source target's BinSync functions against this\n"
        "target's unmatched functions (same code, different VAs) and overlays names,\n"
        "prototypes, and notes.  --fields global adds content-matched globals.\n"
        "Source defaults to the manifest's target.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    state_dir: Path = typer.Argument(..., help="BinSync state directory of the related target"),
    from_target: str | None = typer.Option(
        None, "--from", help="Source target name (defaults to the state manifest's target)"
    ),
    accept_binsync: bool = typer.Option(
        False, "--accept-binsync", help="Accept BinSync values for all conflicts"
    ),
    accept_local: bool = typer.Option(
        False, "--accept-local", help="Keep local values for all conflicts (records provenance)"
    ),
    min_score: float = typer.Option(
        95.0, "--min-score", help="Minimum structural similarity (0-100) to overlay"
    ),
    min_gap: float = typer.Option(
        5.0, "--min-gap", help="Best match must beat the runner-up by at least this"
    ),
    fields: str = typer.Option(
        "name,prototype,note",
        "--fields",
        help="Comma-separated fields to overlay (name, prototype, note, global)",
    ),
    module: str | None = typer.Option(
        None, "--module", help="Only overlay annotations in this module (e.g. SERVER)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Overlay a related target's BinSync data onto structurally-matched functions."""
    if accept_binsync and accept_local:
        error_exit(
            "--accept-binsync and --accept-local are mutually exclusive", json_mode=json_output
        )

    try:
        resolved = state_dir.resolve()
    except OSError as exc:
        error_exit(f"Cannot resolve state directory {state_dir}: {exc}", json_mode=json_output)
    if not resolved.exists():
        error_exit(f"State directory not found: {state_dir}", json_mode=json_output)
    if not resolved.is_dir():
        error_exit(f"Not a directory: {state_dir}", json_mode=json_output)
    state_dir = resolved

    cfg = require_config(target=target, json_mode=json_output)

    src_name = from_target or (load_manifest(state_dir).get("target") or "")
    if not src_name:
        error_exit(
            "cannot determine the source target: pass --from or record 'target' in "
            f"{state_dir / 'manifest.toml'}",
            json_mode=json_output,
        )
    if src_name == cfg.target_name:
        error_exit("--from must name a different target", json_mode=json_output)
    cfg_src = require_config(target=src_name, json_mode=json_output)

    selected_fields = _parse_fields(fields, json_mode=json_output)

    funcs_by_va, globals_by_va = load_binsync_state(state_dir)
    if not funcs_by_va and not globals_by_va:
        error_exit(f"No BinSync data found in {state_dir}", json_mode=json_output)

    result = overlay_state(
        cfg,
        cfg_src,
        state_dir,
        funcs_by_va,
        globals_by_va,
        fields=selected_fields,
        module=module,
        min_score=min_score,
        min_gap=min_gap,
        accept_binsync=accept_binsync,
        accept_local=accept_local,
        dry_run=dry_run,
    )

    resolved_conflicts = accept_binsync or accept_local
    unresolved = bool(result["conflicts"]) and not resolved_conflicts
    if json_output:
        json_print({key: result[key] for key in _JSON_KEYS})
        if unresolved:
            raise typer.Exit(code=EXIT_MISMATCH)
        return

    _print_result(result, resolved=resolved_conflicts)
    if unresolved:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt``, click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
