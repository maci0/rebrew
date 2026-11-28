"""data_annotate.py — data-row binding and header generation.

Binds a data row's ``file`` to the declaration that owns it, applies declared
global types, and generates ``rebrew_globals.h`` from the data metadata and
source declarations. It does not write binding lines.
"""

from __future__ import annotations

import logging
import re
lazy from datetime import UTC, datetime
lazy from pathlib import Path
lazy from typing import Any

from rebrew.c_syntax.parser import CALLING_CONVENTION, is_pointer_to_array  # noqa: F401
lazy from rebrew.config import ProjectConfig, target_module
lazy from rebrew.metadata.data import iter_data_symbols, load_data_document
lazy from rebrew.utils import (
    atomic_write_text,
    c_comment_safe,
    is_safe_c_ident,
    read_source_text,
    split_source_lines,
    strip_generated_timestamp,
)

log = logging.getLogger(__name__)

#: Label for a global whose section name is empty, in both the emitted header
#: and the returned report, so a caller can match one against the other.
_UNKNOWN_SECTION_LABEL = "(unknown section)"
#: A C type spelled out in metadata: word chars, whitespace, and the
#: declarator punctuation only. A quote is a ``sizeof`` literal
#: (``sizeof(L"hi")``, ``sizeof(L'A')``). ``;``, braces, ``#``, and
#: ``\`` stay out: those end the declaration or escape into one.
_SAFE_TYPE_RE = re.compile(r"""\A[A-Za-z0-9_ \t*(),[\]'"]+\Z""")


def annotate_globals(
    src_dir: Path,
    metadata: Path,
    dry_run: bool = False,
    cfg: ProjectConfig | None = None,
) -> tuple[dict[str, int], int]:
    """Bind ``file`` on named data rows that do not have one yet.

    Existing file bindings are preserved. New GLOBAL rows use their stored
    module and the first matching declaration's source path.

    Returns ``(per_file, skipped_unnamed)``. *skipped_unnamed* counts rows
    with no ``name``: the declaration is what locates them.
    """

    from rebrew.c_syntax.parser import find_extern_variables
    from rebrew.metadata.data import module_visible_to_target, record_data_rows
    from rebrew.metadata.functions import identity_file
    from rebrew.source.discovery import iter_sources
    from rebrew.utils import rel_display_path

    db = load_data_document(metadata)
    skipped_unnamed = 0
    candidates: dict[str, list[tuple[str, int, bool]]] = {}
    for module, addr, val in iter_data_symbols(db, section=None):
        if not module_visible_to_target(module, cfg):
            continue
        if not val.get("name"):
            skipped_unnamed += 1
            continue
        candidates.setdefault(str(val["name"]), []).append(
            (module, addr, bool(str(val.get("file") or "").strip()))
        )
    symbols = {name: matches[0] for name, matches in candidates.items() if len(matches) == 1}

    meta_dir = metadata.parent
    claimed: set[str] = set()
    rows: list[dict[str, Any]] = []
    per_file: dict[str, int] = {}
    for f in iter_sources(src_dir, cfg):
        text, _encoding = read_source_text(f)
        bound_here = 0
        for declaration in find_extern_variables(
            text, include_definitions=True, function_filter=lambda _line: False
        ):
            name = declaration.name
            if name not in symbols or name in claimed:
                continue
            module, addr, has_file = symbols[name]
            if has_file:
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
                            "kind": "GLOBAL",
                            "name": name,
                        },
                    }
                )
        if bound_here:
            per_file[rel_display_path(f, src_dir)] = bound_here
    if rows:
        record_data_rows(meta_dir, rows)
    return per_file, skipped_unnamed


def _abstract_declarator_insert_pos(
    type_str: str,
) -> tuple[int, bool] | None:
    """Return ``(offset, in_paren)`` where an identifier belongs inside *type_str*.

    Parses ``void _f(<masked_type>);`` with ``tree-sitter-c`` and walks down
    the abstract declarator chain to the innermost placeholder position.
    Returns ``None`` when the type cannot be parsed cleanly.
    """
    from rebrew.c_syntax.parser import mask_msvc_syntax, parse_c_source

    masked = mask_msvc_syntax(type_str)
    prefix = "void _f("
    probe = f"{prefix}{masked});"
    tree, _data = parse_c_source(probe)
    root = tree.root_node
    if root.has_error:
        return None
    decl_nodes = [c for c in root.named_children if c.type == "declaration"]
    if len(decl_nodes) != 1:
        return None
    fn_decl = decl_nodes[0].child_by_field_name("declarator")
    if fn_decl is None or fn_decl.type != "function_declarator":
        return None
    params = fn_decl.child_by_field_name("parameters")
    if params is None:
        return None
    param_decls = [c for c in params.named_children if c.type == "parameter_declaration"]
    if len(param_decls) != 1:
        return None
    param = param_decls[0]
    declarator = param.child_by_field_name("declarator")
    if declarator is None:
        return len(type_str), False

    prefix_len = len(prefix.encode("utf-8", errors="surrogateescape"))
    in_paren = False
    cur = declarator
    while True:
        kind = cur.type
        if kind == "abstract_parenthesized_declarator":
            in_paren = True
            inner_children = [c for c in cur.named_children if c.type != "comment"]
            if not inner_children:
                return int(cur.end_byte) - prefix_len - 1, True
            cur = inner_children[0]
            continue
        if kind == "abstract_pointer_declarator":
            child = cur.child_by_field_name("declarator")
            if child is None:
                return int(cur.end_byte) - prefix_len, in_paren
            cur = child
            continue
        if kind == "abstract_array_declarator":
            child = cur.child_by_field_name("declarator")
            if child is None:
                return int(cur.start_byte) - prefix_len, in_paren
            cur = child
            continue
        if kind == "abstract_function_declarator":
            child = cur.child_by_field_name("declarator")
            if child is None:
                return int(cur.start_byte) - prefix_len, in_paren
            cur = child
            continue
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
    inserted = _abstract_declarator_insert_pos(type_str)
    if inserted is not None:
        pos, in_paren = inserted
        head = type_str[:pos]
        tail = type_str[pos:]
        if in_paren:
            joiner = "" if head[-1:] in {"*", " ", "\t"} else " "
            return f"extern {head}{joiner}{name}{tail};"
        return f"extern {head.rstrip()} {name}{tail};"
    return f"extern {type_str} {name};"


def patch_data_fields(
    cfg: ProjectConfig,
    specifications: dict[str, list[str]],
    *,
    dry_run: bool = False,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    """Normalize CLI fields, then preview/apply one locked non-verdict patch."""
    from rebrew.metadata.data import patch_data_fields_batch

    updates, rows = data_field_updates(cfg, specifications)
    report = patch_data_fields_batch(
        cfg.metadata_dir, updates, dry_run=dry_run, expected_digest=expected_digest
    )
    return {**report, "set": rows}


def data_field_updates(
    cfg: ProjectConfig, specifications: dict[str, list[str]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The data patch updates and per-row summaries ``rebrew data set`` options name.

    Raises ValueError naming the first specification it rejects, before any
    metadata is read: a malformed ``0xVA=VALUE``, a value outside its field's
    vocabulary (``validate_data_field``), or a ``--file`` that names no source.
    """
    from rebrew.config import target_module
    from rebrew.metadata.bindings import DATA_KINDS
    from rebrew.metadata.data import validate_data_field
    from rebrew.metadata.functions import identity_file, validate_identity_file

    module = target_module(cfg) or ""
    if not module:
        raise ValueError("no target module configured to address the data metadata")
    updates: list[dict[str, Any]] = []
    rows: dict[int, dict[str, Any]] = {}
    for field, specs in specifications.items():
        for spec in specs:
            va_s, sep, text = spec.partition("=")
            value: Any = text.strip()
            option = "--" + field.replace("_", "-")
            placeholder = {"file": "PATH", "size": "BYTES"}.get(field, field.upper())
            if not sep or (not value and field in {"note", "kind", "file"}):
                raise ValueError(f"{option} wants 0xVA={placeholder}, got {spec!r}")
            va = int(va_s, 16)
            if field == "size":
                from rebrew.utils import parse_int_literal

                value = parse_int_literal(value)
                if value <= 0:
                    raise ValueError(f"{option} wants a positive byte count, got {text!r}")
            elif field == "name" and not is_safe_c_ident(value):
                raise ValueError(f"{option} wants a C identifier, got {value!r}")
            elif field == "kind" and value not in DATA_KINDS:
                raise ValueError(
                    f"{option} wants one of {', '.join(sorted(DATA_KINDS))}, got {value!r}"
                )
            elif field == "section" and value not in _DATA_SECTIONS:
                raise ValueError(
                    f"{option} wants one of {', '.join(_DATA_SECTIONS)}, got {value!r}"
                )
            elif field == "file":
                source = Path(value)
                if not source.is_absolute():
                    source = cfg.root / source
                if not source.is_file():
                    raise ValueError(f"--file names a missing source: {value}")
                value = validate_identity_file(identity_file(source, cfg.metadata_dir))
            value = validate_data_field(field, value)
            updates.append({"module": module, "va": va, "fields": {field: value}})
            row = rows.setdefault(va, {"va": f"0x{va:x}", "module": module})
            row[field] = value
    return updates, list(rows.values())


#: Recorded storage kinds a compiler literal at the same VA may replace. A
#: named object is refined to the literal the build emits there; an alias,
#: span, or import slot describes a different relationship and is reported.
_LITERAL_REPLACEABLE_KINDS = ("", "object", "literal")


def mark_literal_rows(
    cfg: ProjectConfig, symbols: list[Any], *, dry_run: bool = False
) -> dict[str, Any]:
    """Mark data rows at a compiler literal's linked VA as ``storage_kind = "literal"``.

    *symbols* are :class:`rebrew.data.ownership.LinkSymbol` rows of a link
    whose layout matches the reference, so a map VA names a reference row.
    Each marked row also records the literal's ``link_symbol``. A VA holding
    two different literal symbols, or a row whose storage kind is not
    replaceable, is returned under ``conflicts`` and left unchanged.
    """
    from rebrew.config import target_module
    from rebrew.data.ownership import is_compiler_literal
    from rebrew.metadata.data import load_data_metadata, set_data_fields_batch

    module = target_module(cfg) or ""
    if not module:
        raise ValueError("no target module configured to address the data metadata")
    literals: dict[int, set[str]] = {}
    for sym in symbols:
        if not sym.is_function and is_compiler_literal(sym.name):
            literals.setdefault(sym.va, set()).add(sym.name)
    marked: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    unchanged = 0
    updates: list[dict[str, Any]] = []
    for (row_module, va), row in sorted(
        load_data_metadata(cfg.metadata_dir, deepcopy=False).items()
    ):
        names = literals.get(va)
        if row_module != module or not names:
            continue
        if len(names) > 1:
            conflicts.append(
                {"va": f"0x{va:x}", "symbols": sorted(names), "reason": "several literal symbols"}
            )
            continue
        symbol = next(iter(names))
        kind = str(row.get("storage_kind") or "")
        link = str(row.get("link_symbol") or "")
        if kind not in _LITERAL_REPLACEABLE_KINDS:
            conflicts.append(
                {"va": f"0x{va:x}", "symbol": symbol, "reason": f"storage_kind is {kind}"}
            )
            continue
        if kind == "literal" and link == symbol:
            unchanged += 1
            continue
        marked.append(
            {
                "va": f"0x{va:x}",
                "symbol": symbol,
                "storage_kind_was": kind or None,
                "link_symbol_was": link or None,
            }
        )
        updates.append(
            {
                "module": module,
                "va": va,
                "fields": {"storage_kind": "literal", "link_symbol": symbol},
                "updated_by": "data",
            }
        )
    if not dry_run:
        set_data_fields_batch(cfg.metadata_dir, updates)
    return {"module": module, "marked": marked, "unchanged": unchanged, "conflicts": conflicts}


_DATA_SECTIONS = (".data", ".rdata", ".bss", ".text")


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
    which lives outside the reversed tree but holds real bindings).
    """
    from rebrew.c_syntax.parser import find_extern_variables
    from rebrew.source.discovery import iter_sources
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
        for line in split_source_lines(text):
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
                ext_vars = find_extern_variables(decl + ";", include_definitions=True)
            except Exception:
                log.debug("extern-variable parse failed for %r in %s", decl, cfile, exc_info=True)
                ext_vars = []
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
    """Generate rebrew_globals.h from ADDRESS-bound declarations and data metadata.

    Writes ``{out_path}`` (default: ``{src_dir}/rebrew_globals.h``) with
    ``extern`` declarations for every known global, grouped by section
    (``.data``, ``.rdata``, ``.bss``).  Does not require Ghidra: it uses local
    source declarations and metadata only.

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
    from rebrew.metadata.bindings import read_source_bindings
    from rebrew.metadata.data import load_data_metadata
    from rebrew.metadata.functions import load_metadata
    from rebrew.source.discovery import iter_sources

    target_module_name = target_module(cfg)
    metadata_dir = cfg.metadata_dir
    metadata = load_data_metadata(metadata_dir, deepcopy=False)
    # One store read for the whole walk: read_source_bindings otherwise
    # re-resolves and re-fingerprints it once per source.
    function_entries = load_metadata(metadata_dir, deepcopy=False)

    # Sources are authoritative for the emitted name and type: a
    # VA-anchored declaration in the tree beats the metadata guess.
    # The stub TU (src/link_stubs.c) is compiled into the link but lives
    # outside reversed_dir, so scan it too: stub-held globals (e.g. .rdata
    # constants owned by the rdata_restore blob) have their bindings and
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
            annotations = read_source_bindings(
                src,
                target_name=target_module_name,
                metadata_dir=metadata_dir,
                project_root=getattr(cfg, "root", None),
                function_entries=function_entries,
            )
        except Exception:  # one bad file must not abort the scan
            logging.warning("Skipping %s: annotation parse failed", src, exc_info=True)
            continue
        for ann in annotations:
            if ann.is_function:
                continue
            va = ann.va
            if va in seen_va:
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
        "/* Auto-generated by rebrew data header. DO NOT EDIT.",
        " * Source: ADDRESS-bound declarations + rebrew-data.toml",
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
