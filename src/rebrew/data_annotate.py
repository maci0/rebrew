"""data_annotate.py — GLOBAL annotation and header generation.

Inserts ``// GLOBAL:`` markers into reversed sources, applies declared global
types, and generates ``rebrew_globals.h`` from the data metadata and source
declarations.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rebrew.config import ProjectConfig, module_marker
from rebrew.data_metadata import iter_data_symbols
from rebrew.utils import (
    atomic_write_text,
    c_comment_safe,
    is_safe_c_ident,
    join_source_lines,
    load_tomllib,
    read_source_text,
    split_source_lines,
    strip_generated_timestamp,
)

log = logging.getLogger(__name__)

_GLOBAL_MARKER_RE = re.compile(r"^\s*(?://|/\*)\s*GLOBAL:\s*\S+\s+0x([0-9a-fA-F]+)")
_DECL_LINE_RE = re.compile(
    r"^\s*(?:extern\s+)?[\w\s\*]+\s+([A-Za-z_]\w*)(?:\[\d*\])?\s*(?:=\s*[^;]*|\s*;)"
)
_EXISTING_MARKER_RE = re.compile(r"^\s*(?://|/\*)\s*(?:DATA|GLOBAL):")
_ARRAY_TYPE_RE = re.compile(r"\s*(\[[^\]]*\])$")
#: Label for a global whose section name is empty, in both the emitted header
#: and the returned report, so a caller can match one against the other.
_UNKNOWN_SECTION_LABEL = "(unknown section)"
_FUNCPTR_TYPE_RE = re.compile(r"^(.*?)\(\s*([^()]*?)\s*\*\s*\)(.*)$")
#: A C type spelled out in metadata: word chars, whitespace, and the
#: declarator punctuation only.
_SAFE_TYPE_RE = re.compile(r"\A[A-Za-z0-9_ \t*(),[\]]+\Z")
_VAR_DECL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\])?\s*$")


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

    db = load_tomllib(metadata)
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

    per_file: dict[str, int] = {}
    for f in iter_sources(src_dir, cfg):
        text, encoding = read_source_text(f)
        lines = split_source_lines(text)
        existing = {int(m.group(1), 16) for m in (_GLOBAL_MARKER_RE.match(ln) for ln in lines) if m}
        pending = {
            name: (mod, addr) for name, (mod, addr) in symbols.items() if addr not in existing
        }
        insertions: list[tuple[int, str]] = []
        for i, ln in enumerate(lines):
            if not pending:
                break
            m = _DECL_LINE_RE.match(ln)
            if not m:
                continue
            name = m.group(1)
            if name not in pending:
                continue
            if i > 0 and _EXISTING_MARKER_RE.match(lines[i - 1]):
                continue
            _mod, sym_addr = pending.pop(name)
            insertions.append((i, f"// GLOBAL: {marker} 0x{sym_addr:08x}"))
        if not insertions:
            continue
        insertions.sort(key=lambda x: x[0])
        for shift, (hit, marker_line) in enumerate(insertions):
            lines.insert(hit + shift, marker_line)
        per_file[rel_display_path(f, src_dir)] = len(insertions)
        if not dry_run:
            atomic_write_text(f, join_source_lines(text, lines), encoding=encoding)
    return per_file, skipped_unnamed


def _emit_extern_decl(row: dict[str, Any]) -> str | None:
    """Format an `extern` declaration honoring an explicit `type` when given.

    Returns `None` when no type is specified: an untyped global is left out
    of the header rather than guessed at.
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
    # The type arrives from metadata, which can be synced from a BinSync
    # state written elsewhere.  Only declarator characters may reach a
    # compiled header: a `;`, `{`, `}` or `#` would end the declaration and
    # start top-level code.
    if not _SAFE_TYPE_RE.match(type_str):
        return None
    array = _ARRAY_TYPE_RE.search(type_str)
    if array:
        base = type_str[: array.start()].strip()
        return f"extern {base} {name}{array.group(1)};"
    if "(*)" in type_str:
        return f"extern {type_str.replace('(*)', f'(*{name})', 1)};"
    fp = _FUNCPTR_TYPE_RE.match(type_str)
    if fp:
        prefix, quals, suffix = fp.group(1), fp.group(2), fp.group(3)
        inner = f"{quals} *{name}" if quals else f"*{name}"
        return f"extern {prefix}({inner}){suffix};"
    return f"extern {type_str} {name};"


def _set_global_field(
    cfg: ProjectConfig,
    specs: list[str],
    *,
    option: str,
    placeholder: str,
    field: str,
    allowed: tuple[str, ...] | None = None,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Write one metadata field per ``0xVA=VALUE`` spec and return the rows.

    *option* and *placeholder* only shape the two ValueError messages, so
    ``--type`` still reports ``0xVA=TYPE`` and ``--section`` reports
    ``0xVA=SECTION``; *allowed*, when given, rejects a value outside it.
    """
    from rebrew.data_metadata import set_data_fields_batch
    from rebrew.sources import target_marker

    module = target_marker(cfg) or ""
    if not module:
        raise ValueError("no target marker configured to address the data metadata")
    rows: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    for spec in specs:
        va_s, sep, value = spec.partition("=")
        value = value.strip()
        if not sep:
            raise ValueError(f"{option} wants 0xVA={placeholder}, got {spec!r}")
        if field == "name" and not is_safe_c_ident(value):
            raise ValueError(f"{option} wants a C identifier, got {value!r}")
        if allowed is not None and value not in allowed:
            raise ValueError(f"{option} wants one of {', '.join(allowed)}, got {value!r}")
        va = int(va_s, 16)
        fields: dict[str, Any] = {field: value}
        if field == "size":
            size = int(value, 0)
            if size <= 0:
                raise ValueError(f"{option} wants a positive byte count, got {value!r}")
            fields = {"size": size, "status": "UNCHECKED"}
        rows.append({"va": f"0x{va:x}", field: fields[field], "module": module})
        updates.append({"module": module, "va": va, "fields": fields, "updated_by": "data"})
    if not dry_run:
        set_data_fields_batch(cfg.metadata_dir, updates)
    return rows


def set_data_relation(
    cfg: ProjectConfig, specs: list[str], field: str, *, dry_run: bool = False
) -> list[dict[str, Any]]:
    """Record explicit storage relationships; attribution still needs link evidence."""
    if field not in {"storage_kind", "backing", "link_symbol"}:
        raise ValueError(f"unsupported data relationship {field!r}")
    return _set_global_field(
        cfg,
        specs,
        option="--set-" + field.replace("_", "-"),
        placeholder="VALUE",
        field=field,
        allowed=("object", "alias", "literal", "span", "import")
        if field == "storage_kind"
        else None,
        dry_run=dry_run,
    )


def set_data_types(
    cfg: ProjectConfig, specs: list[str], *, dry_run: bool = False
) -> list[dict[str, str]]:
    """Set declared global types in rebrew-data.toml from ``0xVA=TYPE`` specs.

    The declared type decides which of two conflicting declarations the
    compiler sees, and `--gen-header` reads it from the metadata, so a wrong
    one has to be correctable through the tool rather than by editing the TOML.
    """
    return _set_global_field(
        cfg, specs, option="--type", placeholder="TYPE", field="type", dry_run=dry_run
    )


def set_data_names(
    cfg: ProjectConfig, specs: list[str], *, dry_run: bool = False
) -> list[dict[str, Any]]:
    """Name annotated globals so data verification can attribute their spans."""
    return _set_global_field(
        cfg, specs, option="--name", placeholder="NAME", field="name", dry_run=dry_run
    )


def set_data_sizes(
    cfg: ProjectConfig, specs: list[str], *, dry_run: bool = False
) -> list[dict[str, Any]]:
    """Correct positive byte sizes and invalidate verdicts for the old spans."""
    return _set_global_field(
        cfg, specs, option="--size", placeholder="BYTES", field="size", dry_run=dry_run
    )


_DATA_SECTIONS = (".data", ".rdata", ".bss")


def set_data_sections(
    cfg: ProjectConfig, specs: list[str], *, dry_run: bool = False
) -> list[dict[str, str]]:
    """Set a global's PE section in rebrew-data.toml from ``0xVA=SECTION`` specs.

    ``rebrew lint`` W016 wants a SECTION for every ``// GLOBAL:`` marker, but
    the type setter never wrote one, so a global that exists only through an
    annotation could not carry the marker without a warning.
    """
    return _set_global_field(
        cfg,
        specs,
        option="--section",
        placeholder="SECTION",
        field="section",
        allowed=_DATA_SECTIONS,
        dry_run=dry_run,
    )


_VA_COMMENT_RE = re.compile(r"/\*\s*(0x[0-9a-fA-F]+)")


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
    from rebrew.c_parser import find_extern_variables, type_from_declaration
    from rebrew.sources import iter_sources
    from rebrew.utils import read_source_text

    found: dict[int, tuple[str, str]] = {}
    files = sorted(iter_sources(src_dir, cfg)) if src_dir.exists() else []
    for extra in extra_files or []:
        if extra is not None and extra.is_file() and extra not in files:
            files.append(extra)
    for cfile in files:
        try:
            text, _ = read_source_text(cfile)
        except OSError as exc:
            # The generated header is derived from these decls, so a skipped
            # file silently drops its globals from it; name the file instead.
            log.warning("skipping unreadable source %s: %s", cfile, exc)
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
                # Falling back to the regex spelling below keeps the decl, but
                # a parser that fails here usually fails on that too — say which
                # declaration lost its type instead of dropping it in silence.
                log.debug("extern-variable parse failed for %r in %s", decl, cfile, exc_info=True)
                ext_vars = []
            if ext_vars:
                name, type_str = ext_vars[0].name, ext_vars[0].type_str
            else:
                var_m = _VAR_DECL_RE.search(decl)
                if var_m:
                    name = var_m.group(1)
                    type_str = type_from_declaration(decl + ";", name) or ""
            if name and type_str:
                found[va] = (name, type_str)
    return found


def gen_globals_header(
    cfg: ProjectConfig,
    src_dir: Path,
    out_path: Path | None = None,
    force: bool = False,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Generate rebrew_globals.h from GLOBAL:/DATA: annotations + data metadata.

    Writes ``{out_path}`` (default: ``{src_dir}/rebrew_globals.h``) with
    ``extern`` declarations for every known global, grouped by section
    (``.data``, ``.rdata``, ``.bss``).  Does not require Ghidra — uses local
    annotation data only.

    Args:
        cfg: Project configuration.
        src_dir: Reversed sources directory (used for annotation scanning).
        out_path: Output file path.  Defaults to ``src_dir/rebrew_globals.h``.
        force: When False (default), refuses to overwrite an existing file with
            differing content. Pass True to allow overwriting.
        dry_run: When True, report what would be written without touching disk.

    Returns:
        ``path``, ``written``, ``dry_run``, ``globals`` (count) and
        ``sections`` (count per section, in emission order).

    Raises:
        FileExistsError: ``out_path`` exists with differing content and ``force`` is False.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.data_metadata import load_data_metadata
    from rebrew.sources import iter_sources

    marker = module_marker(cfg)
    metadata = load_data_metadata(cfg.metadata_dir)

    # Sources are authoritative for the emitted name and type: a
    # VA-anchored declaration in the tree beats the metadata guess.
    # The stub TU (src/link_stubs.c) is compiled into the link but lives
    # outside reversed_dir, so scan it too: stub-held globals (e.g. .rdata
    # constants owned by the rdata_restore blob) have their markers and
    # VA-anchored declarations only there.
    stub_path = cfg.root / "src" / "link_stubs.c"
    source_decls = _source_decls_by_va(src_dir, cfg, extra_files=[stub_path])
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
        except Exception:  # one bad file must not abort the scan
            logging.warning("Skipping %s: annotation parse failed", src, exc_info=True)
            continue
        for ann in annotations:
            if ann.is_function:
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

            # The header is compiled, so a name that is not a C identifier
            # cannot go in it.  Decorated import symbols are the real case:
            # `__imp__GetLocalTime@4` is a perfectly good metadata name for an
            # IAT slot and an instant syntax error in C.  Those slots are
            # supplied by the import library anyway, so skip rather than emit
            # something that will not compile.
            if not is_safe_c_ident(name):
                continue

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
        "/* Auto-generated by rebrew data list --gen-header. DO NOT EDIT.",
        " * Source: GLOBAL:/DATA: annotations + rebrew-data.toml",
        f" * Generated: {generated}",
        " */",
        "",
        "#ifndef REBREW_GLOBALS_H",
        "#define REBREW_GLOBALS_H",
        "",
    ]

    def _emit_section(label: str, items: list[dict[str, Any]]) -> None:
        # A section name and a note are both free text, and ``*/`` in either
        # closes the enclosing comment early and puts the rest of the line
        # into the header body as C the next compile builds.
        header_lines.append(f"/* {c_comment_safe(label)} */")
        for row in items:
            note_parts = [f"0x{row['va']:08X}"]
            if row["size"]:
                note_parts.append(f"{row['size']} bytes")
            if row["note"]:
                note_parts.append(c_comment_safe(row["note"]))
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
            _emit_section(sec or _UNKNOWN_SECTION_LABEL, by_section[sec])

    header_lines += ["#endif /* REBREW_GLOBALS_H */", ""]

    out = out_path if out_path is not None else src_dir / "rebrew_globals.h"
    content = "\n".join(header_lines)

    # Idempotency: regeneration only bumps the "Generated:" timestamp —
    # skip the write when the body is otherwise identical to avoid
    # needless git churn on every run.
    is_identical = False
    if out.exists():
        try:
            existing = out.read_text(encoding="utf-8")
            is_identical = strip_generated_timestamp(existing) == strip_generated_timestamp(content)
        except OSError:
            existing = ""
        if not is_identical and not force:
            raise FileExistsError(f"{out} already exists. Use --force to overwrite.")

    def _header_payload(written: bool) -> dict[str, Any]:
        ordered = [sec for sec in section_order if sec in by_section]
        ordered += sorted(sec for sec in by_section if sec not in emitted)
        return {
            "path": str(out),
            "written": written,
            "dry_run": dry_run,
            "globals": len(rows),
            "sections": {(sec or _UNKNOWN_SECTION_LABEL): len(by_section[sec]) for sec in ordered},
        }

    if dry_run or is_identical:
        return _header_payload(written=False)

    atomic_write_text(out, content, encoding="utf-8")
    return _header_payload(written=True)
