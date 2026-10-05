"""data_annotate.py — data-row binding and header generation.

Binds a data row's ``file`` to the declaration that owns it, applies declared
global types, and generates ``rebrew_globals.h`` from the data metadata and
source declarations. It does not write marker lines.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rebrew.c_parser import CALLING_CONVENTION, is_pointer_to_array
from rebrew.config import ProjectConfig, module_marker
from rebrew.data_metadata import iter_data_symbols
from rebrew.utils import (
    atomic_write_text,
    c_comment_safe,
    is_safe_c_ident,
    load_tomllib,
    read_source_text,
    split_source_lines,
    strip_generated_timestamp,
)

log = logging.getLogger(__name__)

# Brackets may be hex, an expression, several dimensions, or one nested
# pair. A decimal-only bound skipped ``g[0x10]``. Stopping at the first
# ``]`` skipped ``g[sizeof(wchar_t[3])]``, so that row was never bound.
# ``(*g)[4]`` puts the name inside parentheses; a bare word never saw it.
# ``*table[4]`` glues the star to the name. ``(*rows[4])`` and
# ``(counts[4])`` put the brackets inside the parentheses.
# ``(__cdecl *name)`` and ``(* const name)`` keep the convention and the
# qualifier off the name. ``(*name[N])(int)`` keeps the parameter list
# off the name.
_POINTER_NAME_QUALIFIER = r"(?:(?:const|volatile)\b\s*)*"
_FN_PARAMS = r"(?:\((?:[^()]|\([^()]*\))*\))?"
_DECL_LINE_RE = re.compile(
    r"^\s*(?:extern\s+)?[\w\s]+"
    r"(?:"
    r"\s+\*+\s*" + _POINTER_NAME_QUALIFIER + r"([A-Za-z_]\w*)"
    r"|\(\s*"
    + CALLING_CONVENTION
    + r"\*+\s*"
    + _POINTER_NAME_QUALIFIER
    + r"([A-Za-z_]\w*)\s*\)"
    + _FN_PARAMS
    + r"|\(\s*"
    + CALLING_CONVENTION
    + r"\**\s*"
    + _POINTER_NAME_QUALIFIER
    + r"([A-Za-z_]\w*)\s*(?:\[(?:[^\[\]]|\[[^\]]*\])*\])+\s*\)"
    + _FN_PARAMS
    + r"|\(\s*"
    + CALLING_CONVENTION
    + r"([A-Za-z_]\w*)\s*(?:\[(?:[^\[\]]|\[[^\]]*\])*\])+\s*\)"
    r"|\s+([A-Za-z_]\w*)"
    r")"
    r"(?:\[(?:[^\[\]]|\[[^\]]*\])*\])*\s*(?:=\s*[^;]*|\s*;)"
)
# The whole trailing bracket run moves onto the name. A group that stops
# at the first ``]`` left ``char[sizeof(wchar_t[3])]`` as the type, and
# matching only the last group turned ``char[2][4]`` into ``extern char[2] g[4]``.
_ARRAY_TYPE_RE = re.compile(r"\s*((?:\[(?:[^\[\]]|\[[^\]]*\])*\])+)$")
#: Label for a global whose section name is empty, in both the emitted header
#: and the returned report, so a caller can match one against the other.
_UNKNOWN_SECTION_LABEL = "(unknown section)"
_FUNCPTR_TYPE_RE = re.compile(r"^(.*?)\(\s*([^()]*?)\s*\*\s*\)(.*)$")
#: A C type spelled out in metadata: word chars, whitespace, and the
#: declarator punctuation only. A quote is a ``sizeof`` literal
#: (``sizeof(L"hi")``, ``sizeof(L'A')``). ``;``, braces, ``#``, and
#: ``\`` stay out: those end the declaration or escape into one.
_SAFE_TYPE_RE = re.compile(r"""\A[A-Za-z0-9_ \t*(),[\]'"]+\Z""")
_VAR_DECL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\])?\s*$")


def annotate_globals(
    src_dir: Path,
    metadata: Path,
    marker: str,
    dry_run: bool = False,
    cfg: ProjectConfig | None = None,
) -> tuple[dict[str, int], int]:
    """Bind ``file`` on named data rows that do not have one yet.

    The first declaration of the name owns the row. A row that already has
    ``file`` is left alone. A file that still has a data-marker line is
    migrated first (every marker, not only this target's) so a new ``file``
    is visible; a VA that marker already names is not bound again.

    *marker* is unused. The row's own module is the key, and the kind
    written for a new bind is ``GLOBAL``.

    Returns ``(per_file, skipped_unnamed)``. *skipped_unnamed* counts rows
    with no ``name``: the declaration is what locates them.
    """
    from types import SimpleNamespace

    from rebrew.annotation import DATA_MARKERS, NEW_FUNC_CAPTURE_RE
    from rebrew.data_metadata import record_migrated_data_markers
    from rebrew.marker_migration import migrate_source_file
    from rebrew.metadata import identity_file
    from rebrew.sources import iter_sources
    from rebrew.utils import rel_display_path

    del marker
    db = load_tomllib(metadata)
    skipped_unnamed = 0
    symbols: dict[str, tuple[str, int, bool]] = {}
    for module, addr, val in iter_data_symbols(db, section=None):
        # Count by the entry itself, not by ``total - len(symbols)``: two
        # metadata entries sharing a name collapse in ``symbols`` and would be
        # misreported as missing a ``name`` field.
        if not val.get("name"):
            skipped_unnamed += 1
            continue
        symbols[str(val["name"])] = (module, addr, bool(str(val.get("file") or "").strip()))

    meta_dir = metadata.parent
    migrate_cfg: Any = (
        cfg if cfg is not None else SimpleNamespace(metadata_dir=meta_dir, root=meta_dir)
    )
    claimed: set[str] = set()
    rows: list[dict[str, Any]] = []
    per_file: dict[str, int] = {}
    for f in iter_sources(src_dir, cfg):
        text, _encoding = read_source_text(f)
        lines = split_source_lines(text)
        marked = {
            int(match.group("va"), 16)
            for line in lines
            if (match := NEW_FUNC_CAPTURE_RE.match(line.strip()))
            and match.group("type") in DATA_MARKERS
            and match.group("va")
        }
        if marked and not dry_run:
            migrated = migrate_source_file(migrate_cfg, f, None, dry_run=False)
            if migrated and migrated.get("skipped") == "unrecorded-markers":
                log.warning(
                    "%s has marker lines that were not recorded; its data rows were not bound",
                    f,
                )
                continue
            text, _encoding = read_source_text(f)
            lines = split_source_lines(text)
        bound_here = 0
        seen_in_file: set[str] = set()
        for line in lines:
            decl = _DECL_LINE_RE.match(line)
            if not decl:
                continue
            name = next(group for group in decl.groups() if group)
            if name not in symbols or name in claimed or name in seen_in_file:
                continue
            seen_in_file.add(name)
            module, addr, has_file = symbols[name]
            if has_file or addr in marked:
                if addr in marked:
                    claimed.add(name)
                continue
            claimed.add(name)
            bound_here += 1
            if not dry_run:
                rows.append(
                    {
                        "module": module,
                        "va": addr,
                        "identity": {
                            "file": identity_file(f, meta_dir),
                            "marker_type": "GLOBAL",
                            "name": name,
                        },
                    }
                )
        if bound_here:
            per_file[rel_display_path(f, src_dir)] = bound_here
    if rows:
        record_migrated_data_markers(meta_dir, rows)
    return per_file, skipped_unnamed


def _name_in_pointer_to_array(type_str: str, name: str) -> str | None:
    """Insert *name* into the ``(*)`` or ``(**)`` that declares *type_str*."""
    depth = 0
    index = 0
    while index < len(type_str):
        char = type_str[index]
        if char == "[":
            depth += 1
        elif char == "]" and depth:
            depth -= 1
        elif char == "(" and depth == 0:
            close = type_str.find(")", index + 1)
            if close == -1:
                return None
            raw = type_str[index + 1 : close]
            after = type_str[close + 1 :].lstrip()
            # Stars only, or a calling convention and a pointer qualifier.
            # ``(*)`` and ``(__cdecl *)`` and ``(* const)`` are this pointer.
            # An identifier is already a name, so it is not inserted again.
            if _POINTER_DECL_INNER_RE.match(raw) and after.startswith("["):
                joiner = "" if type_str[close - 1] == "*" else " "
                return type_str[:close] + joiner + name + type_str[close:]
        index += 1
    return None


# A calling convention and a pointer qualifier stay on the declarator.
# ``(__cdecl *[N])`` and ``(* const [N])`` are still N pointers.
_POINTER_DECL_INNER_RE = re.compile(
    r"\A\s*" + CALLING_CONVENTION + r"\*+(?:\s*(?:const|volatile)\b)*\s*\Z"
)
_ABSTRACT_POINTER_ARRAY_RE = re.compile(
    r"\A\s*"
    + CALLING_CONVENTION
    + r"(\*+)"
    + r"((?:\s*(?:const|volatile)\b)*)"
    + r"\s*"
    + r"((?:\[(?:[^\[\]]|\[[^\]]*\])*\])+)\s*\Z"
)


def _name_in_abstract_pointer_array(type_str: str, name: str) -> str | None:
    """Insert *name* into ``(*[N])`` or ``(**[N])``.

    ``int (*[4])`` is four pointers. The name used to follow the whole
    type (``extern int (*[4]) g``), which is not C. Brackets outside the
    parentheses are a pointer to an array and are not this form.
    """
    depth = 0
    start = -1
    for index, char in enumerate(type_str):
        if char == "(":
            if depth == 0:
                start = index
            depth += 1
        elif char == ")" and depth:
            depth -= 1
            if depth == 0 and start >= 0:
                inside = type_str[start + 1 : index]
                matched = _ABSTRACT_POINTER_ARRAY_RE.match(inside)
                if matched:
                    at = matched.start(3)
                    head, tail = inside[:at], inside[at:]
                    joiner = "" if head[-1:] in {"*", " ", "\t"} else " "
                    return type_str[: start + 1] + head + joiner + name + tail + type_str[index:]
                start = -1
    return None


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
    # ``char (*)[4]`` is a pointer to an array. The brackets stay on the
    # array; peeling them first emitted ``extern char (*) g[4]``.
    # A ``(*)`` inside the bound is not the declarator:
    # ``char[sizeof(char (*)[4])]`` became ``extern char[sizeof(char (*g)[4])];``.
    # ``(**)`` has no ``(*)`` substring, so ``char (**)[4]`` became
    # ``extern char (**) g[4]``.
    if is_pointer_to_array(type_str):
        declarator = _name_in_pointer_to_array(type_str, name)
        if declarator is not None:
            return f"extern {declarator};"
    # ``int (*[4])`` is an array of pointers. The brackets are inside the
    # parentheses, so the name cannot follow the type.
    abstract = _name_in_abstract_pointer_array(type_str, name)
    if abstract is not None:
        return f"extern {abstract};"
    array = _ARRAY_TYPE_RE.search(type_str)
    if array:
        base = type_str[: array.start()].strip()
        return f"extern {base} {name}{array.group(1)};"
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
                else:
                    # ``char (*g_row)[4];`` is a file-scope definition, not an
                    # extern, and the name is inside parentheses, so the
                    # regex above never sees it. The definition is the type
                    # that compiles.
                    ext_vars = find_extern_variables(decl + ";", include_definitions=True)
                    if ext_vars:
                        name, type_str = ext_vars[0].name, ext_vars[0].type_str
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
