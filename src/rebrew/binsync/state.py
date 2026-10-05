"""state.py — Shared BinSync-state readers for the binsync CLIs.

``importer`` and ``diff`` both need the same indexes over a
BinSync state directory: the raw function/global maps and the local
annotation + catalog overlay.  This module is that single source; it imports
no CLI machinery so both tools stay independently importable.

State is read through :mod:`rebrew.binsync.serial` (declib), so a directory
written by rebrew, BinSync, IDA, Ghidra, or Binary Ninja parses the same way.
"""

from __future__ import annotations

import logging
import re
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import tomlkit

from rebrew.c_parser import type_from_declaration
from rebrew.catalog import build_function_registry, cached_function_list, scan_reversed_dir
from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.utils import is_safe_c_ident, preset_module_key

log = logging.getLogger(__name__)

_NOTE_PREFIX = "[rebrew:note]"
_GHIDRA_PREFIX = "[rebrew:ghidra]"

#: Per-address source comment marker (line comment only).  This is the single
#: prefix import writes and export scans; format::
#:
#:     // ANALYSIS @ 0x401010: some note
ANALYSIS_MARKER_PREFIX = "// ANALYSIS @ "

_ANALYSIS_MARKER_RE = re.compile(r"^//\s*ANALYSIS\s*@\s*(0x[0-9a-fA-F]+)\s*:\s?(.*)$")

#: A comment lands inside a ``//`` line in a real source file, so it must
#: stay on that one line.  BinSync state is written by collaborators, and a
#: comment carrying a newline would add live source lines to the file.
_MARKER_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def marker_comment_text(comment: str) -> str:
    """One-line form of a BinSync comment, safe to splice into a ``.c`` file.

    Line breaks and control characters become spaces, so the text cannot end
    the ``//`` marker line and start new source of its own.
    """
    return _MARKER_CONTROL_RE.sub(" ", str(comment)).rstrip()


def parse_analysis_markers(text: str) -> dict[int, str]:
    """Return ``{addr: comment}`` for every per-address ANALYSIS marker line."""
    out: dict[int, str] = {}
    for line in text.splitlines():
        match = _ANALYSIS_MARKER_RE.match(line.strip())
        if match:
            out[int(match.group(1), 16)] = match.group(2).rstrip()
    return out


def containing_va(candidates: list[tuple[int, int]], addr: int) -> int | None:
    """VA of the first ``(va, size)`` candidate whose range contains *addr*."""
    for va, size in candidates:
        if size and va <= addr < va + size:
            return va
    return None


def write_analysis_markers(path: Path, comments: dict[int, str]) -> bool:
    """Merge per-address *comments* into *path*'s trailing ANALYSIS block.

    Existing lines for the same address are updated in place and new addresses
    are appended, so a re-import is idempotent.  The block is sorted by address
    and separated from the code by one blank line.  Returns True when the file
    changed (a no-op rewrite returns False without touching the file).

    Comment text is flattened to one line by :func:`marker_comment_text`; a
    comment arriving from a collaborator's state directory never contributes
    source lines of its own.

    Raises:
        OSError: *path* cannot be read or written.  A failed read is not a
            no-op — callers must not treat it as "nothing to merge".
    """
    from rebrew.utils import atomic_write_text, read_source_text, split_source_lines

    if not comments:
        return False
    text, encoding = read_source_text(path)

    merged = parse_analysis_markers(text)
    merged.update({addr: marker_comment_text(text) for addr, text in comments.items()})

    kept = [
        line for line in split_source_lines(text) if not _ANALYSIS_MARKER_RE.match(line.strip())
    ]
    while kept and not kept[-1].strip():
        kept.pop()
    block = "\n".join(
        f"{ANALYSIS_MARKER_PREFIX}0x{addr:08x}: {merged[addr]}" for addr in sorted(merged)
    )
    body = "\n".join(kept)
    new_text = f"{body}\n\n{block}\n" if body else f"{block}\n"
    if new_text == text:
        return False
    atomic_write_text(path, new_text, encoding=encoding)
    return True


def load_binsync_state(
    state_dir: Path,
) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    """Load a declib-backed BinSync state directory.

    Returns ``(funcs_by_va, globals_by_va)``.  Function entries carry
    ``name``/``prototype``/``size``/``stack_vars``; rebrew's note/ghidra
    provenance comments (kept at ``va+1``/``va+2`` in ``comments.toml``) are
    folded back in as ``note``/``ghidra``.  Foreign declib state dirs load the
    same way.
    """
    from rebrew.binsync import serial

    funcs: dict[int, dict[str, Any]] = {}
    funcs_dir = state_dir / serial.FUNCTIONS_DIR
    if not funcs_dir.is_dir():
        # An empty map is also the "nothing to import" signal.  A partial or
        # unreadable state dir must not look like that: globals.toml and
        # comments.toml beside it carry entries that would never be applied.
        log.warning(
            "no %s directory under %s — BinSync import sees no functions",
            serial.FUNCTIONS_DIR,
            state_dir,
        )
    else:
        for toml_path in sorted(funcs_dir.glob("*.toml")):
            func = serial.load_artifact(toml_path, "function")
            if func is None:
                continue
            addr = func.addr
            if addr is None:
                try:
                    addr = int(toml_path.stem, 16)
                except ValueError:
                    continue
            entry: dict[str, Any] = {}
            if func.name:
                entry["name"] = func.name
            prototype = func.type
            if isinstance(prototype, str) and prototype.strip():
                entry["prototype"] = prototype.strip()
            if func.size:
                entry["size"] = str(func.size)
            stack_vars: dict[str, dict[str, Any]] = {}
            for offset, var in (func.stack_vars or {}).items():
                stack_vars[str(offset)] = {
                    "name": var.name or "",
                    "type": var.type or "",
                    "size": int(var.size or 0),
                }
            if stack_vars:
                entry["stack_vars"] = stack_vars
            funcs[int(addr)] = entry

    globals_map: dict[int, dict[str, Any]] = {}
    for gvar in serial.load_many(state_dir / serial.GLOBAL_VARS_FILE, "global_variable"):
        addr = gvar.addr
        if addr is None:
            continue
        record: dict[str, Any] = {}
        if gvar.name:
            record["name"] = gvar.name
        if isinstance(gvar.type, str) and gvar.type.strip():
            record["type"] = gvar.type.strip()
        if gvar.size is not None:
            record["size"] = str(gvar.size)
        globals_map[int(addr)] = record

    # rebrew provenance travels as prefixed comments at va+1 (note) / va+2
    # (ghidra), tagged with the owning function's addr.
    for comment in serial.load_many(state_dir / serial.COMMENTS_FILE, "comment"):
        text = comment.comment or ""
        func_addr = comment.func_addr
        if func_addr is None:
            func_addr = (comment.addr or 0) - 1
        func_entry = funcs.get(int(func_addr))
        if func_entry is None:
            continue
        if text.startswith(_NOTE_PREFIX):
            func_entry["note"] = text[len(_NOTE_PREFIX) :].strip()
        elif text.startswith(_GHIDRA_PREFIX):
            func_entry["ghidra"] = text[len(_GHIDRA_PREFIX) :].strip()

    return funcs, globals_map


def load_binsync_comments(state_dir: Path) -> dict[int, dict[str, Any]]:
    """Load ``comments.toml`` as ``{addr: {"comment", "func_addr"}}``."""
    from rebrew.binsync import serial

    out: dict[int, dict[str, Any]] = {}
    for comment in serial.load_many(state_dir / serial.COMMENTS_FILE, "comment"):
        if comment.addr is None:
            continue
        out[int(comment.addr)] = {
            "comment": comment.comment or "",
            "func_addr": int(comment.func_addr) if comment.func_addr is not None else None,
        }
    return out


def load_manifest(state_dir: Path) -> dict[str, str]:
    """Read ``manifest.toml`` freshness facts; empty dict when absent."""
    manifest = state_dir / "manifest.toml"
    if not manifest.exists():
        return {}
    try:
        doc = tomlkit.parse(manifest.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, tomlkit.exceptions.TOMLKitError) as exc:
        raise ValueError(f"unparseable BinSync manifest {manifest}: {exc}") from exc
    out: dict[str, str] = {}
    for key in (
        "exported_at",
        "content_hash",
        "commit",
        "target",
        "binary_hash",
        "input_hash",
        "metadata_schema",
    ):
        val = doc.get(key)
        if key == "metadata_schema" and isinstance(val, int) and not isinstance(val, bool):
            val = str(val)
        if key in doc and not isinstance(val, str):
            raise ValueError(f"invalid BinSync manifest field {key!r} in {manifest}")
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


def load_binsync_structs(state_dir: Path) -> dict[str, dict[str, object]]:
    """Load ``structs/*.toml`` declib Structs.

    Returns ``{name: {"definition": synthesized_typedef, "fields": {name:
    {"type", "offset", "size"}}}}``.  The synthesized definition lets the
    import path reuse the same shared type-model validation as before.
    """
    from rebrew.binsync import serial

    structs: dict[str, dict[str, object]] = {}
    structs_dir = state_dir / serial.STRUCTS_DIR
    if not structs_dir.is_dir():
        return structs
    for toml_path in sorted(structs_dir.glob("*.toml")):
        struct = serial.load_artifact(toml_path, "struct")
        if struct is None:
            continue
        name = struct.name
        if not isinstance(name, str) or not name.strip():
            name = toml_path.stem
        members: dict[int, Any] = dict(struct.members or {})
        fields: dict[str, dict[str, object]] = {}
        lines: list[str] = []
        for offset in sorted(members):
            member = members[offset]
            # A member name is spliced into the synthesized declaration, so a
            # collaborator's struct cannot close the body and add its own code.
            if not is_safe_c_ident(member.name):
                log.warning("skipping struct %s member at offset %s: bad name", name, offset)
                continue
            member_type = member.type or "int"
            fields[member.name] = {
                "type": member_type,
                "offset": offset,
                "size": int(member.size or 0),
            }
            lines.append(f"\t{member_type} {member.name};")
        definition = f"typedef struct {name} {{\n" + "\n".join(lines) + f"\n}} {name};"
        structs[name.strip()] = {"definition": definition, "fields": fields}
    return structs


def load_binsync_enums(state_dir: Path) -> dict[str, dict[str, object]]:
    """Load ``enums.toml`` declib Enums.

    Returns ``{name: {"definition": synthesized_typedef, "members":
    {MEMBER: int}}}``.  declib carries no enum body text, so the definition is
    synthesized from the members for the import path."""
    from rebrew.binsync import serial

    enums: dict[str, dict[str, object]] = {}
    for enum in serial.load_many(state_dir / serial.ENUMS_FILE, "enum"):
        name = enum.name
        if not isinstance(name, str) or not name.strip():
            continue
        raw_members = {str(k): int(v) for k, v in (enum.members or {}).items()}
        # As with struct members, a name that is not an identifier would carry
        # more than a member into the synthesized enumerator list.
        members = {k: v for k, v in raw_members.items() if is_safe_c_ident(k)}
        # Sorted: the difference is a set, so its order follows str hashing and
        # the same state dir would warn in a different order on every process.
        for skipped in sorted(raw_members.keys() - members.keys()):
            log.warning("skipping enum %s member %r: not an identifier", name, skipped)
        if not members:
            continue
        body = ", ".join(f"{member} = {value}" for member, value in members.items())
        definition = f"typedef enum {{ {body} }} {name};"
        enums[name.strip()] = {"definition": definition, "members": members}
    return enums


def load_binsync_typedefs(state_dir: Path) -> dict[str, dict[str, object]]:
    """Load ``typedefs.toml`` declib Typedefs.

    Returns ``{name: {"definition": synthesized_typedef, "type": underlying}}``.
    """
    from rebrew.binsync import serial

    typedefs: dict[str, dict[str, object]] = {}
    for typedef in serial.load_many(state_dir / serial.TYPEDEFS_FILE, "typedef"):
        name = typedef.name
        if not isinstance(name, str) or not name.strip():
            continue
        underlying = typedef.type if isinstance(typedef.type, str) else ""
        definition = " ".join(f"typedef {underlying} {name};".split())
        typedefs[name.strip()] = {"definition": definition, "type": underlying}
    return typedefs


def index_local_and_catalog(
    cfg: ProjectConfig,
) -> tuple[dict[int, object], dict[int, int]]:
    """Index local annotations by VA, and catalog-only VAs by their size.

    The catalog (discovery inventory) is the project file:
    its VAs represent the ground truth binary layout even when no .c file
    exists yet.  Catalog-only VAs land in the second map so callers can
    surface them (stub-able / new-in-BinSync) without overwriting real
    annotations.  Membership is the catalog signal and the size is the only
    property a caller reads, so the map carries the size and nothing else.
    """
    local_entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    local_by_va: dict[int, object] = {}
    for e in local_entries:
        va = getattr(e, "va", 0)
        if va and (va not in local_by_va or getattr(e, "marker_type", "") == "FUNCTION"):
            # Keep FUNCTION entries preferentially; DATA/GLOBAL overwrite only if no function
            local_by_va[va] = e

    catalog_sizes: dict[int, int] = {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            funcs = cached_function_list(cfg)
        ghidra_path = inventory_path_for(cfg.reversed_dir, cfg)
        registry = build_function_registry(funcs, cfg, ghidra_path, cfg.target_binary)
        for va, reg_entry in registry.items():
            if va in local_by_va:
                continue
            if reg_entry.get("is_thunk"):
                continue
            size = int(reg_entry.get("canonical_size", 0) or 0)
            if size <= 0:
                continue
            catalog_sizes[va] = size
    except Exception:
        # An empty catalog is also the "nothing to import" signal.  A scan
        # failure must not look like that: create-missing would skip every
        # catalog-only function and a re-run would not retry them.
        log.warning(
            "catalog scan failed — BinSync import will not see catalog-only functions",
            exc_info=True,
        )

    return local_by_va, catalog_sizes


# ---------------------------------------------------------------------------
# Result-dict readers
# ---------------------------------------------------------------------------


def result_count(result: dict[str, object], key: str, default: int = 0) -> int:
    """Read a counter out of an export/import result, narrowing the ``object`` value.

    A result that reaches a CLI printer may have been through a JSON round-trip,
    so the value is checked rather than asserted.
    """
    value = result.get(key, default)
    if value is None:
        return default
    if not isinstance(value, int):
        raise TypeError(f"result field {key!r} is not an int: {value!r}")
    return value


def result_rows(result: dict[str, object], key: str) -> list[dict[str, Any]]:
    """Read a list-of-mappings field out of an export/import result."""
    value = _result_list(result, key)
    rows: list[dict[str, Any]] = []
    for row in value:
        if not isinstance(row, dict):
            raise TypeError(f"result field {key!r} holds a non-mapping row: {row!r}")
        rows.append(row)
    return rows


def result_paths(result: dict[str, object], key: str) -> list[str]:
    """Read a list-of-path-strings field out of an export/import result."""
    return [str(item) for item in _result_list(result, key)]


def module_predicate(wanted: str | None) -> Callable[[str], bool]:
    """Build the ``--module`` row filter for an already-canonical *wanted* name.

    The filter and the stored row meet in
    :func:`~rebrew.utils.preset_module_key` (NFC, then upper), the spelling every
    metadata writer emits, so ``--module server`` selects the same rows as
    ``--module SERVER`` instead of skipping all of them.  ``None`` (no
    ``--module``) passes every row.
    """
    return lambda local_module: wanted is None or preset_module_key(local_module) == wanted


def _result_list(result: dict[str, object], key: str) -> list[Any]:
    """Read the list behind *key*, treating an absent or null field as empty."""
    value = result.get(key) or []
    if not isinstance(value, list):
        raise TypeError(f"result field {key!r} is not a list: {value!r}")
    return value


def global_name_and_type(
    cfg: Any,
    va: int,
    filepath: str,
) -> tuple[str | None, str | None]:
    """Return ``(name, type_str)`` for the ``// GLOBAL:`` / ``// DATA:`` marker at *va*.

    Parses the declaration line that follows the marker (the next non-comment
    line).  Uses tree-sitter's ``find_extern_variables`` for accurate parsing
    and falls back to a regex extraction.  ``DATA`` declarations may be bare
    (no ``extern``), e.g. ``char g_buf[64];``, so the plain-declaration helper
    is also tried.  Returns ``(None, None)`` if the marker/decl cannot be found.
    """
    try:
        from rebrew.c_parser import (
            find_extern_variables as _find_extern,
        )
        from rebrew.utils import read_source_text as _rts

        cfg_reversed = getattr(cfg, "reversed_dir", None)
        if cfg_reversed is None:
            return None, None
        full = Path(cfg_reversed) / filepath if filepath else None
        if full is None or not full.exists():
            from rebrew.sources import iter_sources as _iter_sources

            found = None
            for cand in _iter_sources(Path(cfg_reversed), cfg):
                try:
                    txt, _ = _rts(cand)
                except OSError:
                    continue
                if f"0x{va:08x}" in txt.lower() or f"0x{va:x}" in txt.lower():
                    found = cand
                    break
            full = found
        if full is None or not full.exists():
            return None, None
        text, _ = _rts(full)
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if (f"0x{va:08x}" in line.lower() or f"0x{va:x}" in line.lower()) and (
                "GLOBAL:" in line or "DATA:" in line
            ):
                for j in range(idx + 1, min(idx + 4, len(lines))):
                    cand_decl = lines[j].strip()
                    if not cand_decl or cand_decl.startswith("//"):
                        continue
                    if cand_decl.startswith("#"):
                        # Preprocessor directive (#include/#define/#pragma) is
                        # not a declaration.  A DATA marker placed above one
                        # (synthetic link-stub VAs like notepad's 0xDEADBEEF)
                        # must fall through to the g_<hex> fallback instead of
                        # fabricating a name/type from the directive.
                        continue
                    ext_vars = _find_extern(cand_decl)
                    if not ext_vars:
                        # ``char (*g_row)[4];`` is a file-scope definition.
                        # The name is inside parentheses, so the regex below
                        # skips the line and the next declaration is reported
                        # for this marker.
                        ext_vars = _find_extern(cand_decl, include_definitions=True)
                    if ext_vars:
                        return ext_vars[0].name, ext_vars[0].type_str
                    # Bare declaration (no extern) — try regex extraction.
                    # The extracted name must be a plain C identifier: a
                    # function-definition line ('void f(void) {}') or other
                    # non-declaration yields '{}'/'{' and must be skipped,
                    # not fabricated into a name/type.
                    decl_name = (
                        cand_decl.split(";")[0].split()[-1].split("[")[0].split("*")[-1].strip()
                    )
                    if (
                        decl_name
                        and decl_name != cand_decl
                        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", decl_name)
                    ):
                        t = type_from_declaration(cand_decl, decl_name)
                        if t:
                            return decl_name, t
                break
    except Exception:
        log.debug("name/type resolve failed for VA 0x%x", va, exc_info=True)
    return None, None


def resolve_global_types(
    cfg: ProjectConfig,
    global_entries: Sequence[object],
) -> dict[int, str]:
    """Map VA → C type string for each global entry.

    Uses :func:`rebrew.c_parser.find_extern_variables` on the declaration
    line that follows each ``// GLOBAL:`` / ``// DATA:`` marker, which is
    the authoritative source (also handles non-extern DATA declarations).
    Falls back to :func:`rebrew.data_scan.scan_globals` name→type index when
    the direct parse finds no extern.
    """
    va_to_type: dict[int, str] = {}
    if not global_entries:
        return va_to_type

    # Build a name→type index from scan_globals as a supplementary source
    name_to_type: dict[str, str] = {}
    try:
        from rebrew.data_scan import scan_globals as _scan_globals

        scan = _scan_globals(cfg.reversed_dir, cfg=cfg)
        for ge in scan.globals.values():
            if ge.type_str and not ge.conflict and ge.name and ge.name != "unknown":
                name_to_type[ge.name] = ge.type_str
    except Exception:
        log.debug("scan_globals unavailable for type resolution", exc_info=True)

    for e in global_entries:
        va = getattr(e, "va", 0)
        if va in va_to_type:
            continue
        filepath = getattr(e, "filepath", "")
        _decl_name, found_type = global_name_and_type(cfg, va, filepath)
        if found_type:
            va_to_type[va] = found_type
            continue
        # Supplementary: if marker-based parse failed, try name-indexed map
        gname = getattr(e, "symbol", "") or getattr(e, "name", "")
        if gname and gname in name_to_type:
            va_to_type[va] = name_to_type[gname]

    return va_to_type


def resolve_global_names(
    cfg: ProjectConfig,
    global_entries: Sequence[object],
) -> dict[int, str]:
    """Map VA → variable name for each DATA/GLOBAL entry.

    For ``// GLOBAL:`` / ``// DATA:`` blocks the annotation parser does not
    populate ``ann.name``/``ann.symbol`` (it only does for FUNCTION blocks).
    This helper extracts the real variable name from the declaration line that
    follows the marker, so that ``global_vars.toml`` contains ``g_szBuffer``
    rather than ``g_01008000``.  Falls back to ``g_<hex>`` when the decl
    cannot be resolved.
    """
    va_to_name: dict[int, str] = {}
    for e in global_entries:
        va = getattr(e, "va", 0)
        existing = getattr(e, "symbol", "") or getattr(e, "name", "")
        if existing:
            va_to_name[va] = existing
            continue
        filepath = getattr(e, "filepath", "")
        decl_name, _ = global_name_and_type(cfg, va, filepath)
        if decl_name:
            va_to_name[va] = decl_name
        else:
            va_to_name[va] = f"g_{va:08x}"
    return va_to_name


def locals_map(entry: object) -> dict[int, dict[str, object]]:
    """``{offset: {"name", "type", "size"}}`` from an annotation's LOCALS metadata."""
    raw = getattr(entry, "locals", None)
    if not isinstance(raw, dict):
        return {}
    out: dict[int, dict[str, object]] = {}
    for key, value in raw.items():
        if not isinstance(value, dict):
            continue
        try:
            offset = int(str(key), 0)
        except (TypeError, ValueError):
            continue
        out[offset] = value
    return out


def iter_comment_metadata(entry: object) -> list[tuple[int, int, str]]:
    """``(addr, func_addr, comment)`` triples from an annotation's COMMENTS metadata."""
    raw = getattr(entry, "comments", None)
    if not isinstance(raw, dict):
        return []
    func_addr = int(getattr(entry, "va", 0) or 0)
    out: list[tuple[int, int, str]] = []
    for key, value in raw.items():
        if not isinstance(value, dict):
            continue
        try:
            addr = int(str(key), 0)
        except (TypeError, ValueError):
            continue
        comment = str(value.get("comment") or "")
        if not comment:
            continue
        try:
            owner = int(value.get("func_addr", func_addr))
        except (TypeError, ValueError):
            owner = func_addr
        out.append((addr, owner, comment))
    return out


def scan_analysis_comments(
    cfg: ProjectConfig, func_entries: list[object]
) -> dict[int, tuple[int, str]]:
    """``{addr: (func_va, comment)}`` from source ``// ANALYSIS @ 0xADDR: text``.

    Scans the target's sources and the project-shared tree; the owning function
    VA is resolved by address containment (falling back to the address itself).
    These markers win over the metadata COMMENTS store for the same address.
    """
    from rebrew.binsync.state import containing_va, parse_analysis_markers
    from rebrew.sources import iter_sources
    from rebrew.utils import read_source_text

    ranges = [
        (int(getattr(e, "va", 0) or 0), int(getattr(e, "size", 0) or 0))
        for e in func_entries
        if getattr(e, "va", 0)
    ]
    paths: list[Path] = []
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is not None:
        try:
            paths.extend(iter_sources(Path(reversed_dir), cfg))
        except OSError:
            log.debug("ANALYSIS scan: cannot list %s", reversed_dir, exc_info=True)
    shared_dir = getattr(cfg, "shared_dir", None)
    if shared_dir is not None:
        try:
            paths.extend(iter_sources(Path(shared_dir), cfg))
        except OSError:
            log.debug("ANALYSIS scan: cannot list %s", shared_dir, exc_info=True)

    out: dict[int, tuple[int, str]] = {}
    for path in paths:
        try:
            # Detected encoding (not UTF-8-replace): a CP1252/Shift-JIS
            # ANALYSIS comment (e.g. "Café") must survive into the export.
            text, _ = read_source_text(path)
        except OSError:
            continue
        for addr, comment in parse_analysis_markers(text).items():
            owner = containing_va(ranges, addr)
            out[addr] = (owner if owner is not None else addr, comment)
    return out


# ---------------------------------------------------------------------------
# Canonical projections and the last successfully shared field values
# ---------------------------------------------------------------------------


def normalize_prototype(proto: str) -> str:
    """Canonical signature for sync comparisons, without body or cosmetic spacing."""
    from rebrew.c_parser import prototype_name_span
    from rebrew.utils import strip_body

    text = strip_body(proto).strip().rstrip(";").strip()
    span = prototype_name_span(text)
    if span:
        _name, start, end = span
        encoded = text.encode("utf-8", errors="surrogateescape")
        text = (encoded[:start] + b"__rebrew_function" + encoded[end:]).decode(
            "utf-8", errors="surrogateescape"
        )
    text = " ".join(text.split())
    return re.sub(r"\s*([(),;*])\s*", r"\1", text)


def normalize_sync_value(field: str, value: Any, *, kind: str = "function") -> Any:
    """Normalize native fields identically for baseline, push, pull and diff."""
    from rebrew.metadata import as_metadata_int
    from rebrew.utils import fold_ident

    if field == "name":
        text = str(value or "").strip()
        if kind == "function":
            # The sync name is the linker symbol. ``hook@@12`` and ``_hook``
            # are one C function; stripping one ``_`` left the decoration.
            from rebrew.rename_ops import c_name_from_symbol

            text = c_name_from_symbol(text)
        return fold_ident(text)
    if field == "prototype":
        return normalize_prototype(str(value or ""))
    if field == "size":
        return as_metadata_int(value) if value not in (None, "") else 0
    if field == "stack_vars":
        return {
            str(int(str(k), 0)): {
                "name": v.get("name") or "",
                "type": v.get("type") or "",
                "size": v.get("size") or 0,
            }
            for k, v in (value or {}).items()
            if isinstance(v, dict)
        }
    if field == "comments":
        return {f"0x{int(str(k), 0):08x}": v for k, v in (value or {}).items()}
    if field in {"note", "ghidra", "type"}:
        return str(value or "").strip()
    if isinstance(value, str):
        return value.strip()
    return value


def sync_key(kind: str, module: str, va: int) -> str:
    """Qualified identity inside a binary-scoped integration baseline."""
    return f"{kind}.{preset_module_key(module)}.0x{va:x}"


def local_sync_records(
    cfg: ProjectConfig, entries: Sequence[Any] | None = None
) -> dict[str, dict[str, Any]]:
    """Project native field values from the same annotations all sync paths use."""
    from rebrew.config import module_marker
    from rebrew.data_metadata import get_data_entry
    from rebrew.metadata import SYNC_FIELD_RULES, get_entry

    if entries is None:
        indexed, _ = index_local_and_catalog(cfg)
        entries = list(indexed.values())
    globals_ = [e for e in entries if getattr(e, "is_data", False)]
    names = resolve_global_names(cfg, globals_)
    types = resolve_global_types(cfg, globals_)
    records: dict[str, dict[str, Any]] = {}
    for entry in entries:
        va = int(getattr(entry, "va", 0) or 0)
        if not va:
            continue
        kind = "global" if getattr(entry, "is_data", False) else "function"
        module = getattr(entry, "module", "") or module_marker(cfg)
        fields = {
            field: getattr(entry, attr, "")
            for field, (attr, _direction) in SYNC_FIELD_RULES[kind].items()
        }
        if kind == "global":
            metadata = get_data_entry(cfg.metadata_dir, va, module)
            fields.update({k: metadata[k] for k in fields if k in metadata})
            fields["name"] = fields.get("name") or names.get(va) or f"g_{va:08x}"
            fields["type"] = fields.get("type") or types.get(va) or "char"
        else:
            fields["name"] = fields.get("name") or getattr(entry, "name", "") or f"func_{va:08x}"
            if fields.get("ghidra") == fields["name"]:
                fields["ghidra"] = ""
            metadata = get_entry(cfg.metadata_dir, va, module)
            fields["stack_vars"] = metadata.get("locals") or fields.get("stack_vars") or {}
            fields["comments"] = metadata.get("comments") or fields.get("comments") or {}
        records[sync_key(kind, module, va)] = fields
    # Source ANALYSIS markers are authoritative over their metadata projection.
    for addr, (owner, comment) in scan_analysis_comments(cfg, list(entries)).items():
        for key, fields in records.items():
            if key.startswith("function.") and key.endswith(f".0x{owner:x}"):
                fields["comments"] = dict(fields.get("comments") or {})
                fields["comments"][f"0x{addr:08x}"] = {"comment": comment, "func_addr": owner}
    records.update(type_sync_records(cfg))
    return records


def remote_sync_records(
    cfg: ProjectConfig,
    state_dir: Path,
    funcs: dict[int, dict[str, Any]] | None = None,
    globals_: dict[int, dict[str, Any]] | None = None,
    local: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Read native records under their local module identity; ignore private fields."""
    from rebrew.config import module_marker
    from rebrew.metadata import SYNC_FIELD_RULES

    if funcs is None or globals_ is None:
        funcs, globals_ = load_binsync_state(state_dir)
    local = local or {}
    records: dict[str, dict[str, Any]] = {}
    for kind, source in (("function", funcs), ("global", globals_)):
        for va, entry in source.items():
            key = next(
                (k for k in local if k.startswith(f"{kind}.") and k.endswith(f".0x{va:x}")),
                sync_key(kind, module_marker(cfg), va),
            )
            records[key] = {k: v for k, v in entry.items() if k in SYNC_FIELD_RULES[kind]}
    for addr, comment in load_binsync_comments(state_dir).items():
        text = str(comment.get("comment") or "")
        if text.startswith((_NOTE_PREFIX, _GHIDRA_PREFIX)):
            continue
        owner = comment.get("func_addr")
        if not isinstance(owner, int):
            continue
        for key, fields in records.items():
            if key.startswith("function.") and key.endswith(f".0x{owner:x}"):
                fields.setdefault("comments", {})[f"0x{addr:08x}"] = {
                    "comment": text,
                    "func_addr": owner,
                }
    records.update(incoming_type_records(state_dir))
    return records


def records_hash(records: dict[str, dict[str, Any]]) -> str:
    """Stable SHA256 of the canonical integration projection; excludes edit stamps."""
    import hashlib
    import json

    normalized = {
        key: {
            field: normalize_sync_value(field, value, kind=key.split(".", 1)[0])
            for field, value in fields.items()
        }
        for key, fields in records.items()
    }
    return hashlib.sha256(
        json.dumps(normalized, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def artifact_hash(state_dir: Path) -> str:
    """Hash artifact paths and content, including removals, excluding sync bookkeeping."""
    import hashlib

    digest = hashlib.sha256()
    for path in sorted(state_dir.rglob("*.toml")):
        relative = path.relative_to(state_dir)
        if path.name == "manifest.toml" or ".git" in relative.parts:
            continue
        name = relative.as_posix().encode()
        try:
            body = path.read_bytes()
        except OSError as exc:
            raise OSError(f"cannot hash BinSync artifact {path}: {exc}") from exc
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(body).to_bytes(8, "big") + body)
    return digest.hexdigest()


def sync_baseline_path(cfg: ProjectConfig, state_dir: Path) -> Path:
    """A project-local sidecar for this integration directory and target module."""
    import hashlib

    from rebrew.config import module_marker

    identity = f"{state_dir.resolve()}\0{module_marker(cfg)}"
    key = hashlib.sha256(identity.encode()).hexdigest()[:24]
    root = Path(getattr(cfg, "root", None) or Path(cfg.reversed_dir).parent)
    return root / ".rebrew" / "sync" / f"{key}.toml"


def binary_identity(cfg: ProjectConfig) -> str:
    """BinSync's native binary fingerprint, empty only when no binary is available."""
    from rebrew.utils import md5_file

    binary = getattr(cfg, "target_binary", None)
    return md5_file(Path(binary)) if binary and Path(binary).is_file() else ""


def load_sync_baseline(cfg: ProjectConfig, state_dir: Path) -> dict[str, dict[str, Any]]:
    """Load acknowledged values; reject damaged sidecars and discard a foreign binary."""
    import tomllib

    path = sync_baseline_path(cfg, state_dir)
    if not path.exists():
        return {}
    with path.open("rb") as stream:
        doc = tomllib.load(stream)
    if doc.get("format") != 1 or not isinstance(doc.get("records"), dict):
        raise ValueError(f"invalid sync baseline {path}")
    if doc.get("binary_hash", "") != binary_identity(cfg):
        return {}
    records = doc["records"]
    if any(not isinstance(v, dict) for v in records.values()):
        raise ValueError(f"invalid sync baseline records in {path}")
    return {str(k): dict(v) for k, v in records.items()}


def sync_action(
    field: str, local: Any, remote: Any, base: dict[str, Any], *, kind: str = "function"
) -> str:
    """Three-way decision; an omitted remote field never authorizes a deletion."""
    left = normalize_sync_value(field, local, kind=kind)
    right = normalize_sync_value(field, remote, kind=kind)
    if left == right:
        return "same"
    if field not in base:
        return "unbased"
    previous = base[field]
    if left == previous:
        return "deletion_required" if remote is None else "pull"
    if right == previous:
        return "push"
    return "conflict"


def acknowledge_sync(
    cfg: ProjectConfig,
    state_dir: Path,
    local: dict[str, dict[str, Any]],
    remote: dict[str, dict[str, Any]],
) -> None:
    """Advance only fields equal after successful application; preserve unresolved bases."""
    from rebrew.utils import atomic_write_locked, file_lock

    path = sync_baseline_path(cfg, state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(path.with_suffix(".lock")):
        baseline = load_sync_baseline(cfg, state_dir)
        before = {k: dict(v) for k, v in baseline.items()}
        for key in local.keys() & remote.keys():
            for field in local[key]:
                left = normalize_sync_value(field, local[key][field], kind=key.split(".", 1)[0])
                if left == normalize_sync_value(
                    field, remote[key].get(field), kind=key.split(".", 1)[0]
                ):
                    baseline.setdefault(key, {})[field] = left
        if baseline != before:
            doc = {"format": 1, "binary_hash": binary_identity(cfg), "records": baseline}
            atomic_write_locked(path, tomlkit.dumps(doc))


def sync_origin(state_dir: Path) -> dict[str, str]:
    """External source facts, distinct from the rebrew command applying them."""
    import tomllib

    origin = {"tool": "binsync"}
    metadata = state_dir / "metadata.toml"
    if metadata.exists():
        with metadata.open("rb") as stream:
            user = tomllib.load(stream).get("user")
        if isinstance(user, str) and user:
            origin["user"] = user
    origin.update(
        {k: v for k, v in load_manifest(state_dir).items() if k in {"commit", "binary_hash"}}
    )
    origin["content_hash"] = artifact_hash(state_dir)
    return origin


def sync_health(
    cfg: ProjectConfig,
    state_dir: Path,
    local: dict[str, dict[str, Any]],
    remote: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Actionable freshness and field decisions shared by previews and sync commands."""
    import json

    from rebrew.metadata import FORMAT_VERSION, SYNC_FIELD_RULES

    manifest = load_manifest(state_dir)
    binary = binary_identity(cfg)
    stored_binaries = {manifest.get("binary_hash", "")}
    if (state_dir / "binary_hash").exists():
        stored_binaries.add((state_dir / "binary_hash").read_text().strip())
    issues: list[str] = []
    if binary and any(stored and stored != binary for stored in stored_binaries):
        issues.append("binary_mismatch")
    if manifest.get("metadata_schema") and manifest["metadata_schema"] != str(FORMAT_VERSION):
        issues.append("schema_mismatch")
    if manifest.get("content_hash") and manifest["content_hash"] != artifact_hash(state_dir):
        issues.append("remote_changed_since_export")
    if manifest.get("input_hash") and manifest["input_hash"] != records_hash(local):
        issues.append("local_changed_since_export")
    baseline = load_sync_baseline(cfg, state_dir)
    items: list[dict[str, Any]] = []
    for key in sorted(local.keys() | remote.keys()):
        kind = key.split(".", 1)[0]
        left, right = local.get(key, {}), remote.get(key, {})
        for field, (_attr, direction) in SYNC_FIELD_RULES[kind].items():
            action = sync_action(
                field, left.get(field), right.get(field), baseline.get(key, {}), kind=kind
            )
            if action == "same":
                continue
            if direction == "push":
                action = "push"
            items.append(
                {
                    "identity": key,
                    "field": field,
                    "action": action,
                    "direction": direction,
                    "local": left.get(field),
                    "remote": right.get(field),
                }
            )
    counts = {
        action: sum(i["action"] == action for i in items)
        for action in (
            "push",
            "pull",
            "conflict",
            "unbased",
            "deletion_required",
        )
    }
    stale_verification: list[str] = []
    stale_origins: list[dict[str, str]] = []
    from rebrew.data_metadata import data_definition_hash, get_data_entry
    from rebrew.metadata import get_entry
    from rebrew.sources import contained_path, source_roots
    from rebrew.verify_hash import compiler_config_hash, entry_fingerprint, source_hash

    indexed: dict[int, object] | None = None
    for key, values in local.items():
        kind, identity = key.split(".", 1)
        if kind not in {"function", "global"}:
            continue
        module, address = identity.rsplit(".", 1)
        va = int(address, 16)
        entry = (get_entry if kind == "function" else get_data_entry)(cfg.metadata_dir, va, module)
        for field, origin in (entry.get("origins") or {}).items():
            if (
                isinstance(origin, dict)
                and origin.get("value_hash")
                and origin["value_hash"] != sync_value_hash(field, values.get(field), kind=kind)
            ):
                stale_origins.append({"identity": key, "field": field})
        evidence = entry.get("verification")
        if not isinstance(evidence, dict) or not evidence:
            continue
        stale = evidence.get("status") != entry.get("status")
        if kind == "global" and evidence.get("definition_hash"):
            stale |= evidence["definition_hash"] != data_definition_hash(
                module, va, entry, arch=getattr(cfg, "arch", "x86_32")
            )
        elif evidence.get("source_hash"):
            if indexed is None:
                indexed, _ = index_local_and_catalog(cfg)
            annotation = indexed.get(va)
            fingerprint = entry_fingerprint(cfg, annotation) if annotation is not None else None
            if fingerprint is None:
                stale = True
            else:
                current = {
                    "source_hash": fingerprint.source_hash,
                    "headers_hash": fingerprint.headers_fp,
                    "toolchain": fingerprint.toolchain,
                    "cflags": fingerprint.cflags,
                    "reference_size": str(fingerprint.size),
                    "compiler_hash": compiler_config_hash(cfg),
                    "defines": json.dumps(
                        sorted(getattr(cfg, "defines", None) or []), separators=(",", ":")
                    ),
                }
                stale |= any(
                    evidence[field] != value
                    for field, value in current.items()
                    if field in evidence
                )
            path = contained_path(source_roots(cfg), getattr(annotation, "filepath", ""))
            try:
                stale |= path is None or source_hash(path) != evidence["source_hash"]
            except OSError:
                stale = True
        if stale:
            stale_verification.append(key)
    return {
        "issues": issues,
        "stale_verification": stale_verification,
        "stale_origins": stale_origins,
        "pending": counts,
        "items": items,
        "baseline": str(sync_baseline_path(cfg, state_dir)),
        "input_hash": records_hash(local),
        "metadata_schema": FORMAT_VERSION,
        "binary_hash": binary,
        "blocked": bool({"binary_mismatch", "schema_mismatch"} & set(issues)),
    }


def sync_health_messages(health: dict[str, Any]) -> list[str]:
    """Plain summaries shared by the human push, pull and diff output paths."""
    messages = [f"Sync freshness: {issue.replace('_', ' ')}" for issue in health.get("issues", [])]
    pending = ", ".join(
        f"{count} {action.replace('_', ' ')}"
        for action, count in health.get("pending", {}).items()
        if count
    )
    if pending:
        messages.append(f"Sync pending: {pending}; inspect with rebrew binsync diff")
    unresolved = [
        item
        for item in health.get("items", [])
        if item["action"] in {"conflict", "deletion_required"}
    ]
    for item in unresolved[:10]:
        messages.append(f"  {item['identity']} {item['field']}: {item['action'].replace('_', ' ')}")
    if len(unresolved) > 10:
        messages.append(f"  ... and {len(unresolved) - 10} more; see --json health.items")
    for key, label in (
        ("stale_verification", "verification records"),
        ("stale_origins", "field origins"),
    ):
        count = len(health.get(key, []))
        if count:
            messages.append(f"Sync freshness: {count} stale {label}")
    return messages


def prepare_sync_import(
    cfg: ProjectConfig,
    state_dir: Path,
    local: dict[str, dict[str, Any]],
    remote: dict[str, dict[str, Any]],
    funcs: dict[int, dict[str, Any]],
    globals_: dict[int, dict[str, Any]],
    *,
    accept_binsync: bool,
    accept_local: bool,
) -> tuple[
    dict[int, dict[str, Any]], dict[int, dict[str, Any]], set[tuple[int, str]], list[dict[str, str]]
]:
    """Filter incoming native fields with the same three-way decisions used by diff."""
    if accept_binsync and accept_local:
        raise ValueError("accept-binsync and accept-local are mutually exclusive")
    health = sync_health(cfg, state_dir, local, remote)
    if health["blocked"]:
        raise ValueError(f"sync refused: {', '.join(health['issues'])}")
    from rebrew.metadata import SYNC_FIELD_RULES

    baseline = load_sync_baseline(cfg, state_dir)
    prepared = (
        {va: dict(row) for va, row in funcs.items()},
        {va: dict(row) for va, row in globals_.items()},
    )
    safe: set[tuple[int, str]] = set()
    conflicts: list[dict[str, str]] = []
    for key, fields in remote.items():
        kind, _module_va = key.split(".", 1)
        if kind not in {"function", "global"}:
            continue
        va = int(key.rsplit(".", 1)[1], 16)
        target = prepared[0 if kind == "function" else 1][va]
        if "comments" in fields:
            target["comments"] = fields["comments"]
        for field, value in fields.items():
            if SYNC_FIELD_RULES[kind][field][1] == "push":
                target.pop(field, None)
                continue
            action = sync_action(
                field, local.get(key, {}).get(field), value, baseline.get(key, {}), kind=kind
            )
            if action == "pull":
                safe.add((va, field))
            elif action == "push" or (action == "conflict" and not accept_binsync):
                if action == "conflict" and not accept_local:
                    conflicts.append(
                        {
                            "va": f"0x{va:08x}",
                            "field": field,
                            "local": str(local.get(key, {}).get(field, "")),
                            "binsync": str(value),
                            "action": "conflict",
                        }
                    )
                target.pop(field, None)
        # Keep the local label when its incoming name was filtered, so unrelated
        # global type/size changes still reach the existing writer.
        if "name" not in target and local.get(key, {}).get("name"):
            target["name"] = local[key]["name"]
    return *prepared, safe, conflicts


def record_sync_origins(
    cfg: ProjectConfig,
    state_dir: Path,
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    remote: dict[str, dict[str, Any]],
) -> None:
    """Stamp only externally changed fields that actually landed in canonical metadata."""
    from rebrew.data_metadata import get_data_entry, set_data_fields_batch
    from rebrew.metadata import get_entry, set_fields_batch

    origin = sync_origin(state_dir)
    function_updates: list[dict[str, Any]] = []
    data_updates: list[dict[str, Any]] = []
    for key in after.keys() & remote.keys():
        kind, identity = key.split(".", 1)
        if kind not in {"function", "global"}:
            continue
        module, address = identity.rsplit(".", 1)
        va = int(address, 16)
        accepted = {}
        for field, value in remote[key].items():
            normalized = normalize_sync_value(field, value, kind=kind)
            if normalized == normalize_sync_value(
                field, after[key].get(field), kind=kind
            ) and normalized != normalize_sync_value(
                field, before.get(key, {}).get(field), kind=kind
            ):
                accepted[field] = {**origin, "value_hash": sync_value_hash(field, value, kind=kind)}
        if not accepted:
            continue
        entry = (get_entry if kind == "function" else get_data_entry)(cfg.metadata_dir, va, module)
        origins = dict(entry.get("origins") or {})
        if all(origins.get(field) == value for field, value in accepted.items()):
            continue
        origins.update(accepted)
        update = {
            "module": module,
            "va": va,
            "fields": {"origins": origins},
            "updated_by": "binsync-import",
        }
        (function_updates if kind == "function" else data_updates).append(update)
    set_fields_batch(cfg.metadata_dir, function_updates)
    set_data_fields_batch(cfg.metadata_dir, data_updates)


def merge_sync_record(
    key: str,
    local: dict[str, Any],
    remote: dict[str, Any],
    baseline: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Push local changes while retaining incoming/conflicting native field values."""
    from rebrew.metadata import SYNC_FIELD_RULES

    kind = key.split(".", 1)[0]
    result = dict(local)
    for field in local.keys() | remote.keys():
        if SYNC_FIELD_RULES[kind][field][1] == "push":
            continue
        action = sync_action(
            field,
            local.get(field),
            remote.get(field),
            baseline.get(key, {}),
            kind=key.split(".", 1)[0],
        )
        if action in {"pull", "conflict", "unbased", "deletion_required"}:
            if field in remote:
                result[field] = remote[field]
            elif action == "deletion_required":
                result.pop(field, None)
    return result


def parse_struct_fields(typedef_text: str) -> list[dict[str, Any]]:
    """Extract ``{name, type, offset, size}`` field dicts from a typedef-struct string.

    Parses via the shared :mod:`rebrew.types` model (tree-sitter), which
    supplies real member offsets and scalar sizes for the declib Struct.
    Falls back to the legacy brace/body splitter for definitions the shared
    model cannot size, so unrecognized declarator forms still export.
    """
    try:
        from rebrew.types import parse_structs, type_size

        parsed = parse_structs(typedef_text)
        if parsed:
            struct = next(iter(parsed.values()))
            if struct.fields:
                return [
                    {
                        "name": name,
                        "type": spelling,
                        "offset": offset,
                        "size": type_size(spelling) or 0,
                    }
                    for name, spelling, offset in struct.fields
                ]
    except Exception:
        log.debug("shared struct parse failed, falling back to regex", exc_info=True)

    # Regex fallback: extract body between { and } then split on ;
    m = re.search(r"\{(.*)\}", typedef_text, flags=re.DOTALL)
    if not m:
        return []
    body = m.group(1)
    out: list[dict[str, Any]] = []
    for raw_field in body.split(";"):
        raw_field = raw_field.strip()
        if not raw_field:
            continue
        raw_field = raw_field.split("//")[0].strip()
        if not raw_field:
            continue
        # Expect "<type> <name>[array]"
        parts = raw_field.rsplit(None, 1)
        if len(parts) != 2:
            continue
        type_part, name_part = parts
        name_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[.*\])?", name_part)
        if not name_match:
            continue
        fname = name_match.group(1)
        arr = name_match.group(2) or ""
        ftype = type_part.strip() + arr
        out.append({"name": fname, "type": ftype})
    return out


def _struct_name(typedef_text: str) -> str:
    """Struct name: the typedef alias before ``;``, else the ``struct Name {`` tag."""
    name_match = re.search(r"\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", typedef_text)
    if name_match:
        return name_match.group(1)
    sm = re.search(r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", typedef_text)
    return sm.group(1) if sm else ""


def collect_struct_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, list[dict[str, Any]]]]:
    """Collect struct definitions from ``reversed_dir`` headers and sources.

    Returns ``{struct_name: (raw_typedef_text, fields)}``.  Prefers the
    header definition when a name appears in both.
    """
    from rebrew.struct_parser import extract_structs_from_file

    result: dict[str, tuple[str, list[dict[str, Any]]]] = {}
    for path in _iter_definition_files(cfg):
        try:
            for typedef_text in extract_structs_from_file(path):
                name = _struct_name(typedef_text)
                if not name or name in result:
                    continue
                result[name] = (typedef_text.strip(), parse_struct_fields(typedef_text))
        except Exception:
            # One malformed file must not drop every later definition from the export.
            log.warning("struct collection failed for %s; skipped", path, exc_info=True)
    return result


def _iter_definition_files(cfg: ProjectConfig) -> list[Path]:
    """Files scanned for type definitions, in preference order.

    Target-local headers first, then the project-shared header tree, then the
    target's sources; the first definition of a name wins.
    """
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return []
    rd = Path(reversed_dir)
    header_files = sorted(rd.rglob("*.h"))
    shared_dir = getattr(cfg, "shared_dir", None)
    if shared_dir is not None:
        header_files += sorted(Path(shared_dir).rglob("*.h"))
    try:
        from rebrew.sources import iter_sources

        return header_files + list(iter_sources(rd, cfg))
    except OSError:
        log.warning("cannot list sources under %s; exporting header types only", rd, exc_info=True)
        return header_files


def _split_top_level(text: str) -> list[str]:
    """Split *text* on commas at bracket/paren/brace depth zero."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _enum_name(definition: str) -> str:
    """Enum name: the trailing typedef identifier, else the ``enum Tag`` name."""
    match = re.search(r"\}\s*([A-Za-z_]\w*)\s*;", definition)
    if match:
        return match.group(1)
    match = re.search(r"enum\s+([A-Za-z_]\w*)\s*\{", definition)
    return match.group(1) if match else ""


def _enum_members(definition: str) -> dict[str, int]:
    """``{member: value}`` for an enum body.

    A bare ``IDENT`` (or one whose literal cannot be parsed) takes the
    previous value + 1, starting at 0.
    """
    match = re.search(r"\{(.*)\}", definition, flags=re.DOTALL)
    if not match:
        return {}
    members: dict[str, int] = {}
    next_value = 0
    for entry in _split_top_level(match.group(1)):
        entry = entry.split("//")[0].strip()
        if not entry:
            continue
        if "=" in entry:
            ident, _, literal = entry.partition("=")
            ident = ident.strip()
            try:
                value = int(literal.strip(), 0)
            except ValueError:
                value = next_value
        else:
            ident = entry
            value = next_value
        if not re.fullmatch(r"[A-Za-z_]\w*", ident):
            continue
        members[ident] = value
        next_value = value + 1
    return members


def collect_enum_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, dict[str, int]]]:
    """Collect ``{enum_name: (raw_definition, {member: value})}``."""
    from rebrew.struct_parser import extract_enums_from_file

    result: dict[str, tuple[str, dict[str, int]]] = {}
    for path in _iter_definition_files(cfg):
        try:
            for text in extract_enums_from_file(path):
                name = _enum_name(text)
                if not name or name in result:
                    continue
                members = _enum_members(text)
                if not members:
                    continue
                result[name] = (text.strip(), members)
        except Exception:
            log.warning("enum collection failed for %s; skipped", path, exc_info=True)
    return result


def _typedef_name_and_type(definition: str) -> tuple[str, str] | None:
    """``(name, underlying_type)`` for a standalone typedef, else None."""
    text = definition.strip()
    if not text.startswith("typedef"):
        return None
    body = text[len("typedef") :].rstrip().rstrip(";").rstrip()
    identifiers = re.findall(r"[A-Za-z_]\w*", body)
    if not identifiers:
        return None
    name = identifiers[-1]
    idx = body.rfind(name)
    return name, " ".join(body[:idx].split())


def collect_typedef_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, str]]:
    """Collect ``{name: (raw_definition, underlying_type)}`` for plain typedefs.

    Struct and enum typedefs are excluded (the struct/enum collectors own them).
    """
    from rebrew.struct_parser import extract_type_definitions

    result: dict[str, tuple[str, str]] = {}
    for path in _iter_definition_files(cfg):
        try:
            for text in extract_type_definitions(path):
                if re.search(r"\b(?:struct|enum)\b", text) or "{" in text:
                    continue
                parsed = _typedef_name_and_type(text)
                if parsed is None:
                    continue
                name, underlying = parsed
                if name and name not in result:
                    result[name] = (text.strip(), underlying)
        except Exception:
            log.warning("typedef collection failed for %s; skipped", path, exc_info=True)
    return result


def type_sync_records(cfg: ProjectConfig) -> dict[str, dict[str, Any]]:
    """Native type projections shared by hashing, reconciliation and export."""
    from rebrew.types import type_size

    records: dict[str, dict[str, Any]] = {}
    for name, (_text, fields) in collect_struct_definitions(cfg).items():
        members = {}
        next_offset = 0
        for field in fields:
            size = int(field.get("size") or type_size(str(field["type"])) or 0)
            offset = int(field.get("offset", next_offset))
            members[field["name"]] = {"type": field["type"], "offset": offset, "size": size}
            next_offset = offset + size
        records[f"struct.{name}"] = {"definition": members}
    for name, (_text, members_) in collect_enum_definitions(cfg).items():
        records[f"enum.{name}"] = {"definition": members_}
    for name, (_text, underlying) in collect_typedef_definitions(cfg).items():
        records[f"typedef.{name}"] = {"definition": underlying}
    return records


def incoming_type_records(state_dir: Path) -> dict[str, dict[str, Any]]:
    """Read external type projections through the shared artifact readers."""
    records: dict[str, dict[str, Any]] = {}
    for name, entry in load_binsync_structs(state_dir).items():
        records[f"struct.{name}"] = {"definition": entry["fields"]}
    for name, entry in load_binsync_enums(state_dir).items():
        records[f"enum.{name}"] = {"definition": entry["members"]}
    for name, entry in load_binsync_typedefs(state_dir).items():
        records[f"typedef.{name}"] = {"definition": entry["type"]}
    return records


def sync_watch_paths(cfg: ProjectConfig, state_dir: Path) -> list[Path]:
    """All inputs that can change the integration projection, including new sources."""
    from rebrew.sources import iter_sources

    paths = set(iter_sources(cfg.reversed_dir, cfg))
    paths.update(_iter_definition_files(cfg))
    paths.update(
        Path(root) for root in (cfg.reversed_dir, getattr(cfg, "shared_dir", None)) if root
    )
    paths.update(
        cfg.metadata_dir / name
        for name in (
            "rebrew-functions.toml",
            "rebrew-data.toml",
            "rebrew-libraries.toml",
        )
    )
    root = getattr(cfg, "root", None)
    if root:
        paths.add(Path(root) / "rebrew-project.toml")
    binary = getattr(cfg, "target_binary", None)
    if binary:
        paths.add(Path(binary))
    # Remote edits also require reconciliation, even when local sources stand still.
    paths.add(state_dir)
    paths.update(state_dir.rglob("*.toml"))
    return sorted(paths)


def sync_value_hash(field: str, value: Any, *, kind: str = "function") -> str:
    """Digest of the accepted field value, so a later local edit cannot inherit its origin."""
    import hashlib
    import json

    normalized = normalize_sync_value(field, value, kind=kind)
    return hashlib.sha256(
        json.dumps(normalized, sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()
