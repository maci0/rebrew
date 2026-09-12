"""data_annotate.py — GLOBAL annotation and header generation.

Inserts ``// GLOBAL:`` markers into reversed sources, applies declared global
types, and generates ``rebrew_globals.h`` from the data metadata and source
declarations.
"""

from __future__ import annotations

import logging
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.config import ProjectConfig
from rebrew.data_metadata import iter_data_symbols
from rebrew.utils import atomic_write_text, read_source_text

console = Console(stderr=True)


def annotate_globals(
    src_dir: Path,
    metadata: Path,
    marker: str,
    dry_run: bool = False,
    cfg: ProjectConfig | None = None,
) -> tuple[dict[str, int], int]:
    """Insert ``// GLOBAL: <marker> 0x<VA>`` markers from the data metadata.

    For every symbol in ``rebrew-data.toml``, insert the marker immediately
    above the first declaration/definition of that name in each source file
    that mentions it (extern or definition).  Declarations already carrying a
    ``GLOBAL:`` or ``DATA:`` marker are skipped.

    Sources are discovered with :func:`iter_sources` (``cfg.source_ext``,
    exclude dirs, and the project shared-sources root), matching
    ``scan_globals`` — a raw ``rglob("*.c")`` missed ``.cpp`` sources and the
    shared tree, and descended into build directories.

    Returns ``(per_file, skipped_unnamed)`` — *skipped_unnamed* is the count
    of metadata entries dropped because they carry no ``name`` field (the
    marker anchors on the source declaration, so an unnamed entry cannot be
    placed); a project whose data metadata is entirely unnamed (e.g. notepad)
    previously produced a silent 0-marker no-op.
    """
    from rebrew.sources import iter_sources
    from rebrew.utils import rel_display_path

    with open(metadata, "rb") as fh:
        db = tomllib.load(fh)
    skipped_unnamed = 0
    symbols: dict[str, tuple[str, int]] = {}
    for module, addr, val in iter_data_symbols(db, section=None):
        # Count by the entry itself, not by ``total - len(symbols)``: two
        # metadata entries sharing a name collapse in ``symbols`` and would be
        # misreported as missing a ``name`` field.
        if not val.get("name"):
            skipped_unnamed += 1
            continue
        symbols[str(val["name"])] = (module, addr)

    marker_re = re.compile(r"^\s*//\s*GLOBAL:\s*\S+\s+0x([0-9a-fA-F]+)")
    decl_cache: dict[str, re.Pattern[str]] = {}
    total = 0
    per_file: dict[str, int] = {}
    for f in iter_sources(src_dir, cfg):
        text, encoding = read_source_text(f)
        lines = text.splitlines()
        existing = {int(m.group(1), 16) for m in (marker_re.match(ln) for ln in lines) if m}
        insertions: list[tuple[int, str]] = []
        used: set[int] = set()
        for name, (_mod, sym_addr) in sorted(symbols.items(), key=lambda kv: kv[1][1]):
            if sym_addr in existing:
                continue
            pat = decl_cache.get(name)
            if pat is None:
                pat = re.compile(
                    r"^\s*(?:extern\s+)?[\w\s\*]+\s+"
                    + re.escape(name)
                    + r"(\[\d*\])?\s*(?:=\s*[^;]*|\s*;)"
                )
                decl_cache[name] = pat
            hit = next(
                (i for i, ln in enumerate(lines) if i not in used and pat.match(ln)),
                None,
            )
            if hit is None:
                continue
            if hit > 0 and re.match(r"^\s*//\s*DATA:", lines[hit - 1]):
                continue
            used.add(hit)
            insertions.append((hit, f"// GLOBAL: {marker} 0x{sym_addr:08x}"))
        if not insertions:
            continue
        insertions.sort(key=lambda x: x[0])
        for shift, (hit, marker_line) in enumerate(insertions):
            lines.insert(hit + shift, marker_line)
        total += len(insertions)
        per_file[rel_display_path(f, src_dir)] = len(insertions)
        if not dry_run:
            atomic_write_text(f, "\n".join(lines) + "\n", encoding=encoding)
    return per_file, skipped_unnamed


def _emit_extern_decl(row: dict[str, Any]) -> str | None:
    """Format an `extern` declaration honoring an explicit `type` when given.

    Uses `unsigned char <name>[]` as the fallback when no type is specified.
    A metadata type carries its pointer/array-ness in the string, but the
    declarator still has to be assembled around the *name*: `struct T[18] x`
    and `void (*)(int) x` are not C, while `struct T x[18]` and
    `void (*x)(int)` are.  Measured on a project whose header was generated
    this way and never compiled, because nothing included it.
    """
    type_str = (row.get("type") or "").strip()
    name = row["name"]
    if not type_str:
        # No declared type: the global stays with the TU that declares it.
        # `char` would be a guess, and a wrong guess is a compile error the
        # moment the header is included next to the real declaration.
        return None
    array = re.search(r"\s*(\[[^\]]*\])$", type_str)
    if array:
        base = type_str[: array.start()].strip()
        return f"extern {base} {name}{array.group(1)};"
    if "(*)" in type_str:
        return f"extern {type_str.replace('(*)', f'(*{name})', 1)};"
    fp = re.match(r"^(.*?)\(\s*([^()]*?)\s*\*\s*\)(.*)$", type_str)
    if fp:
        prefix, quals, suffix = fp.group(1), fp.group(2), fp.group(3)
        inner = f"{quals} *{name}" if quals else f"*{name}"
        return f"extern {prefix}({inner}){suffix};"
    return f"extern {type_str} {name};"


def _set_data_types(
    cfg: ProjectConfig, specs: list[str], *, dry_run: bool = False
) -> list[dict[str, str]]:
    """Set declared global types in rebrew-data.toml from ``0xVA=TYPE`` specs.

    The declared type decides which of two conflicting declarations the
    compiler sees, and `--gen-header` reads it from the metadata, so a wrong
    one has to be correctable through the tool rather than by editing the TOML.
    """
    from rebrew.data_metadata import set_data_field
    from rebrew.sources import target_marker

    module = target_marker(cfg) or ""
    if not module:
        raise ValueError("no target marker configured to address the data metadata")
    rows: list[dict[str, str]] = []
    for spec in specs:
        va_s, sep, type_s = spec.partition("=")
        type_s = type_s.strip()
        if not sep:
            raise ValueError(f"--set-type wants 0xVA=TYPE, got {spec!r}")
        va = int(va_s, 16)
        if not dry_run:
            set_data_field(cfg.metadata_dir, va, "type", type_s, module)
        rows.append({"va": f"0x{va:x}", "type": type_s, "module": module})
    return rows


_VA_COMMENT_RE = re.compile(r"/\*\s*(0x[0-9a-fA-F]+)")


def _source_decl_types_by_va(src_dir: Path, cfg: ProjectConfig | None = None) -> dict[int, str]:
    """Index VA → declared C type from ``extern <type> <name>; /* 0xVA */`` lines.

    Kept as the public name; delegates to :func:`_source_decls_by_va`.
    """
    return {va: typ for va, (_name, typ) in _source_decls_by_va(src_dir, cfg).items()}


def _source_decls_by_va(
    src_dir: Path,
    cfg: ProjectConfig | None = None,
    *,
    extra_files: list[Path | None] | None = None,
) -> dict[int, tuple[str, str]]:
    """Index VA → ``(name, type)`` from VA-anchored source declarations.

    Sources are authoritative for the header: their spelling is the one that
    compiles to matching bytes, while the metadata type is a guess that can
    be wrong (e.g. ``float`` for a ``double`` constant).  Only lines carrying
    an explicit VA comment participate, so unanchored decls never leak across
    globals.  Tree-sitter parses each declaration line; the regex fallback
    covers spellings the grammar rejects.

    *extra_files* are scanned in addition to *src_dir* (e.g. the stub TU,
    which lives outside the reversed tree but holds real markers).
    """
    from rebrew.c_parser import find_extern_variables
    from rebrew.sources import iter_sources
    from rebrew.utils import read_source_text

    try:
        from rebrew.binsync.export import _type_from_declaration
    except ImportError:  # binsync.export pulls catalog; keep header gen usable without it
        _type_from_declaration = None  # type: ignore[assignment]

    found: dict[int, tuple[str, str]] = {}
    files = sorted(iter_sources(src_dir, cfg)) if src_dir.exists() else []
    for extra in extra_files or []:
        if extra is not None and extra.is_file() and extra not in files:
            files.append(extra)
    for cfile in files:
        try:
            text, _ = read_source_text(cfile)
        except OSError:
            continue
        for line in text.splitlines():
            m = _VA_COMMENT_RE.search(line)
            if not m:
                continue
            va = int(m.group(1), 16)
            if va in found:
                continue
            decl = line[: m.start()].strip().rstrip(";").strip()
            if not decl:
                continue
            name, type_str = "", ""
            try:
                ext_vars = find_extern_variables(decl + ";")
            except Exception:
                ext_vars = []
            if ext_vars:
                name, type_str = ext_vars[0].name, ext_vars[0].type_str
            elif _type_from_declaration is not None:
                var_m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\])?\s*$", decl)
                if var_m:
                    name = var_m.group(1)
                    type_str = _type_from_declaration(decl + ";", name) or ""
            if name and type_str:
                found[va] = (name, type_str)
    return found


def _gen_globals_header(
    cfg: ProjectConfig,
    src_dir: Path,
    out_path: Path | None = None,
    force: bool = False,
    *,
    dry_run: bool = False,
    json_output: bool = False,
) -> None:
    """Generate rebrew_globals.h from GLOBAL:/DATA: annotations + data metadata.

    Writes ``{out_path}`` (default: ``{src_dir}/rebrew_globals.h``) with
    ``extern`` declarations for every known global, grouped by section
    (``.data``, ``.rdata``, ``.bss``).  Does not require Ghidra — uses local
    annotation data only.

    Args:
        cfg: Project configuration.
        src_dir: Reversed sources directory (used for annotation scanning).
        out_path: Output file path.  Defaults to ``src_dir/rebrew_globals.h``.
        force: When False (default), refuses to overwrite an existing file and
            exits with an error message.  Pass True to allow overwriting.
        dry_run: When True, report what would be written without touching disk.
        json_output: When True, errors are emitted as JSON.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.data_metadata import load_data_metadata
    from rebrew.sources import iter_sources

    marker = getattr(cfg, "marker", getattr(cfg, "target_name", "GAME").upper())
    metadata = load_data_metadata(cfg.metadata_dir)

    # Sources are authoritative for the emitted name and type: a
    # VA-anchored declaration in the tree beats the metadata guess.
    # The stub TU (src/link_stubs.c) is compiled into the link but lives
    # outside reversed_dir, so scan it too: stub-held globals (e.g. .rdata
    # constants owned by the rdata_restore blob) have their markers and
    # VA-anchored declarations only there.
    stub_path = cfg.root / "src" / "link_stubs.c" if cfg else None
    source_decls = _source_decls_by_va(src_dir, cfg, extra_files=[stub_path] if stub_path else [])
    source_types = {va: typ for va, (_name, typ) in source_decls.items()}
    source_names = {va: name for va, (name, _typ) in source_decls.items()}

    rows: list[dict[str, Any]] = []
    seen_va: set[int] = set()

    header_sources = sorted(iter_sources(src_dir, cfg))
    if stub_path is not None and stub_path.is_file() and stub_path not in header_sources:
        header_sources.append(stub_path)

    for src in header_sources:
        try:
            annotations = parse_c_file_multi(src, target_name=marker, metadata_dir=cfg.metadata_dir)
        except Exception:  # non-fatal; skip unparseable files
            logging.debug("Skipping %s: annotation parse failed", src, exc_info=True)
            continue
        for ann in annotations:
            if ann.marker_type not in ("GLOBAL", "DATA"):
                continue
            va = ann.va
            if not va or va in seen_va:
                continue
            seen_va.add(va)

            # Merge from metadata: section, size, note, name, type
            sk = (ann.module, va)
            se = metadata.get(sk, {})

            # Prefer the VA-anchored source declaration (authoritative: the
            # spelling that compiles to matching bytes); then the annotation
            # name; then the metadata name; then address-based.
            src_name = source_names.get(va, "")
            if src_name:
                raw_name = src_name
            elif ann.name:
                raw_name = ann.name
            elif str(se.get("name", "")):
                # A metadata name is already the C name: `_FPinit`, `_osver` and
                # the `__sbh_*` family are the real identifiers, not decorated.
                raw_name = str(se["name"])
            else:
                # Only a bare object-file symbol carries the compiler's leading
                # underscore; strip that one.
                raw_name = ann.symbol or ""
                if raw_name.startswith("_"):
                    raw_name = raw_name[1:]
            name = raw_name or f"g_{va:08x}"

            section = ann.section or str(se.get("section", ""))
            size = ann.size or int(se.get("size", 0) or 0)
            note = str(se.get("note", ""))
            type_str = source_types.get(va) or str(se.get("type", ""))

            rows.append(
                {
                    "va": va,
                    "name": name,
                    "section": section,
                    "size": size,
                    "note": note,
                    "type": type_str,
                }
            )

    rows.sort(key=lambda x: int(x["va"]))

    # Group by section
    by_section: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_section.setdefault(row["section"] or "", []).append(row)

    generated = datetime.now(UTC).isoformat(timespec="seconds")
    header_lines = [
        "/* Auto-generated by rebrew data --gen-header. DO NOT EDIT.",
        " * Source: GLOBAL:/DATA: annotations + rebrew-data.toml",
        f" * Generated: {generated}",
        " */",
        "",
        "#ifndef REBREW_GLOBALS_H",
        "#define REBREW_GLOBALS_H",
        "",
    ]

    def _emit_section(label: str, items: list[dict[str, Any]]) -> None:
        header_lines.append(f"/* {label} */")
        for row in items:
            note_parts = [f"0x{row['va']:08X}"]
            if row["size"]:
                note_parts.append(f"{row['size']} bytes")
            if row["note"]:
                note_parts.append(row["note"])
            decl = _emit_extern_decl(row)
            if decl is not None:
                header_lines.append(f"{decl} /* {', '.join(note_parts)} */")
        header_lines.append("")

    section_order = [".data", ".rdata", ".bss", ""]
    emitted: set[str] = set()
    for sec in section_order:
        if sec not in by_section:
            continue
        _emit_section(sec or "(unknown section)", by_section[sec])
        emitted.add(sec)

    for sec in sorted(by_section):
        if sec not in emitted:
            _emit_section(sec or "(unknown)", by_section[sec])

    header_lines += ["#endif /* REBREW_GLOBALS_H */", ""]

    out = out_path if out_path is not None else src_dir / "rebrew_globals.h"
    if out.exists() and not force:
        error_exit(
            f"{out} already exists. Use --force to overwrite.",
            json_mode=json_output,
        )

    def _header_payload(written: bool) -> dict[str, Any]:
        """--json output for every success path (docs/CLI.md: JSON for all modes)."""
        return {
            "path": str(out),
            "written": written,
            "dry_run": dry_run,
            "globals": len(rows),
            "sections": {
                (sec or "(unknown)"): len(items) for sec, items in by_section.items() if items
            },
        }

    if dry_run:
        if json_output:
            json_print(_header_payload(written=False))
        else:
            console.print(f"[cyan]dry-run:[/cyan] would write {out} with {len(rows)} globals")
        return

    content = "\n".join(header_lines)
    if out.exists():
        existing = out.read_text(encoding="utf-8")

        # Idempotency: regeneration only bumps the "Generated:" timestamp —
        # skip the write when the body is otherwise identical to avoid
        # needless git churn on every run.
        def _strip_timestamp(text: str) -> str:
            return "\n".join(line for line in text.splitlines() if "Generated:" not in line)

        if _strip_timestamp(existing) == _strip_timestamp(content):
            if json_output:
                json_print(_header_payload(written=False))
            else:
                console.print(f"[dim]{out.name} unchanged[/dim] ({len(rows)} globals)")
            return

    atomic_write_text(out, content, encoding="utf-8")

    if json_output:
        json_print(_header_payload(written=True))
        return
    console.print(f"[green]Wrote {out.name}[/green] with {len(rows)} globals")
    for sec in section_order:
        items = by_section.get(sec or "")
        if items:
            console.print(f"  {sec or '(unknown)'}: {len(items)}")
