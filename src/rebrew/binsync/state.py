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
lazy import warnings
lazy from collections.abc import Callable, Sequence
lazy from pathlib import Path
lazy from typing import Any

lazy import tomlkit

lazy from rebrew.catalog import build_function_registry, cached_function_list, scan_reversed_dir
lazy from rebrew.config import ProjectConfig, inventory_path_for
lazy from rebrew.types import StructDef
lazy from rebrew.utils import is_safe_c_ident, preset_module_key

log = logging.getLogger(__name__)

_NOTE_PREFIX = "[rebrew:note]"
_GHIDRA_PREFIX = "[rebrew:ghidra]"


def containing_va(candidates: list[tuple[int, int]], addr: int) -> int | None:
    """VA of the first ``(va, size)`` candidate whose range contains *addr*."""
    for va, size in candidates:
        if size and va <= addr < va + size:
            return va
    return None


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

    Returns ``{name: {"definition": synthesized_typedef, "size": total_size, "fields": {name:
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
        structs[name.strip()] = {
            "definition": definition,
            "fields": fields,
            "size": int(struct.size or 0),
        }
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
        if va and (va not in local_by_va or getattr(e, "kind", "") == "FUNCTION"):
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
    """Resolve a canonical data identity to its actual C declaration."""
    from rebrew.c_parser import find_extern_variables
    from rebrew.metadata.bindings import DATA_KINDS, read_source_bindings
    from rebrew.sources import iter_sources
    from rebrew.utils import read_source_text

    directory = getattr(cfg, "reversed_dir", None)
    if directory is None:
        return None, None
    candidate = Path(directory) / filepath if filepath else None
    paths = (
        [candidate]
        if candidate is not None and candidate.is_file()
        else iter_sources(Path(directory), cfg)
    )
    for path in paths:
        bindings = read_source_bindings(
            path,
            metadata_dir=getattr(cfg, "metadata_dir", None),
            project_root=getattr(cfg, "root", None),
        )
        matching = [
            b
            for b in bindings
            if b.va == va
            and b.kind in DATA_KINDS
            and (not getattr(cfg, "module", "") or b.module == cfg.module)
        ]
        if not matching:
            continue
        text, _ = read_source_text(path)
        variables = {v.name: v for v in find_extern_variables(text, include_definitions=True)}
        for binding in matching:
            variable = variables.get(binding.name)
            if variable is not None:
                return variable.name, variable.type_str
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
        except TypeError, ValueError:
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
        except TypeError, ValueError:
            continue
        comment = str(value.get("comment") or "")
        if not comment:
            continue
        try:
            owner = int(value.get("func_addr", func_addr))
        except TypeError, ValueError:
            owner = func_addr
        out.append((addr, owner, comment))
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


def normalize_comment_text(text: Any) -> str:
    """Comment text with every whitespace run folded to one space.

    declib's ``Comment`` re-wraps text at 100 columns when it loads or builds
    an artifact, so a note that went out as one line comes back with line
    breaks, including one after the hyphen of a hyphenated word
    (``double-\nfree``).  Comparing the folded text lets that round trip
    settle instead of reading as a remote edit on every pull.
    """
    return " ".join(_WRAPPED_HYPHEN_RE.sub("-", str(text or "")).split())


#: A line break textwrap inserted after a hyphen (it breaks on hyphens).
_WRAPPED_HYPHEN_RE = re.compile(r"(?<=\w)-\n[ \t]*")


def normalize_sync_value(field: str, value: Any, *, kind: str = "function") -> Any:
    """Normalize native fields identically for baseline, push, pull and diff."""
    from rebrew.metadata.functions import as_metadata_int
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
        return {
            f"0x{int(str(k), 0):08x}": (
                {**v, "comment": normalize_comment_text(v.get("comment"))}
                if isinstance(v, dict)
                else v
            )
            for k, v in (value or {}).items()
        }
    if field == "note":
        return normalize_comment_text(value)
    if field in {"ghidra", "type"}:
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
    from rebrew.config import target_module
    from rebrew.metadata.data import get_data_entry
    from rebrew.metadata.functions import SYNC_FIELD_RULES, get_entry

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
        module = getattr(entry, "module", "") or target_module(cfg)
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
            from rebrew.rename_ops import c_name_from_symbol

            # The linker symbol's C name: undecorated for Ghidra (``_x@4`` is
            # ``x``), the decorated spelling stays local.
            fields["name"] = (
                c_name_from_symbol(str(fields.get("name") or ""))
                or str(getattr(entry, "name", "") or "")
                or f"func_{va:08x}"
            )
            if not is_safe_c_ident(fields["name"]):
                # A catalog label (``fcn.<va>``) or a prose row name cannot be
                # a symbol in Ghidra; export reports the prose case.
                fields["name"] = f"func_{va:08x}"
            # A Ghidra name that is the function's own name, decorated or not,
            # is not an alternate name.
            if normalize_sync_value("name", fields.get("ghidra")) == normalize_sync_value(
                "name", fields["name"]
            ):
                fields["ghidra"] = ""
            metadata = get_entry(cfg.metadata_dir, va, module)
            fields["stack_vars"] = metadata.get("locals") or fields.get("stack_vars") or {}
            fields["comments"] = metadata.get("comments") or fields.get("comments") or {}
        records[sync_key(kind, module, va)] = fields
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
    from rebrew.config import target_module
    from rebrew.metadata.functions import SYNC_FIELD_RULES

    if funcs is None or globals_ is None:
        funcs, globals_ = load_binsync_state(state_dir)
    local = local or {}
    records: dict[str, dict[str, Any]] = {}
    for kind, source in (("function", funcs), ("global", globals_)):
        for va, entry in source.items():
            key = next(
                (k for k in local if k.startswith(f"{kind}.") and k.endswith(f".0x{va:x}")),
                sync_key(kind, target_module(cfg), va),
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

    from rebrew.config import target_module

    identity = f"{state_dir.resolve()}\0{target_module(cfg)}"
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
    result = {str(k): dict(v) for k, v in records.items()}
    for key, fields in result.items():
        definition = fields.get("definition")
        if (
            key.startswith("struct.")
            and isinstance(definition, dict)
            and not isinstance(definition.get("size"), int)
        ):
            # Old baselines shared only the member extent, without tail padding.
            extent = max(
                (int(member["offset"]) + int(member["size"]) for member in definition.values()),
                default=0,
            )
            fields["definition"] = {"size": extent, "members": definition}
    return result


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


def seed_peer_baseline(cfg: ProjectConfig, state_dir: Path, peer_dir: Path) -> None:
    """Fill a peer's baseline from what rebrew last shared through *state_dir*.

    A peer branch is reconciled against its own baseline (keyed by the
    peer's snapshot directory), so a field rebrew changed after the peer last
    synced reads as a local edit, not as the peer reverting it.  Fields the
    peer baseline has never recorded start from rebrew's own baseline: the
    value rebrew published, which a peer's differing value then edited.
    Only identities present in the peer's state are seeded.
    """
    from rebrew.utils import atomic_write_locked, file_lock

    own = load_sync_baseline(cfg, state_dir)
    if not own:
        return
    present = remote_sync_records(cfg, peer_dir).keys()
    path = sync_baseline_path(cfg, peer_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(path.with_suffix(".lock")):
        baseline = load_sync_baseline(cfg, peer_dir)
        before = {k: dict(v) for k, v in baseline.items()}
        for key in present & own.keys():
            baseline[key] = {**own[key], **baseline.get(key, {})}
        if baseline != before:
            doc = {"format": 1, "binary_hash": binary_identity(cfg), "records": baseline}
            atomic_write_locked(path, tomlkit.dumps(doc))


def has_state_data(state_dir: Path) -> bool:
    """True when *state_dir* carries any artifact beyond ``metadata.toml``."""
    from rebrew.binsync import serial

    funcs = state_dir / serial.FUNCTIONS_DIR
    structs = state_dir / serial.STRUCTS_DIR
    return (
        (funcs.is_dir() and any(funcs.glob("*.toml")))
        or (structs.is_dir() and any(structs.glob("*.toml")))
        or any(
            (state_dir / name).is_file()
            for name in (
                serial.GLOBAL_VARS_FILE,
                serial.COMMENTS_FILE,
                serial.ENUMS_FILE,
                serial.TYPEDEFS_FILE,
            )
        )
    )


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
    *,
    peer: bool = False,
) -> dict[str, Any]:
    """Actionable freshness and field decisions shared by previews and sync commands.

    *peer* marks *state_dir* as another BinSync user's branch: that user holds
    only what they synced or edited, so an identity absent from it is not a
    removal and is left out of the field decisions.
    """
    import json

    from rebrew.metadata.document import FORMAT_VERSION
    from rebrew.metadata.functions import SYNC_FIELD_RULES

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
        if peer and key not in remote:
            continue
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
    from rebrew.metadata.data import data_definition_hash, get_data_entry
    from rebrew.metadata.functions import get_entry
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
    peer: bool = False,
) -> tuple[
    dict[int, dict[str, Any]], dict[int, dict[str, Any]], set[tuple[int, str]], list[dict[str, str]]
]:
    """Filter incoming native fields with the same three-way decisions used by diff."""
    if accept_binsync and accept_local:
        raise ValueError("accept-binsync and accept-local are mutually exclusive")
    health = sync_health(cfg, state_dir, local, remote, peer=peer)
    if health["blocked"]:
        raise ValueError(f"sync refused: {', '.join(health['issues'])}")
    from rebrew.metadata.functions import SYNC_FIELD_RULES

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
    from rebrew.metadata.data import get_data_entry, set_data_fields_batch
    from rebrew.metadata.functions import get_entry, set_fields_batch

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
    from rebrew.metadata.functions import SYNC_FIELD_RULES

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


#: Spellings of C types that Win32 headers and Ghidra use for the same type.
#: Project typedefs (:func:`type_aliases`) extend and override these.
_BUILTIN_TYPE_ALIASES: dict[str, str] = {
    "BOOL": "int",
    "BYTE": "unsigned char",
    "CHAR": "char",
    "DWORD": "unsigned long",
    "HANDLE": "void *",
    "INT": "int",
    "LONG": "long",
    "LPCSTR": "const char *",
    "LPDWORD": "unsigned long *",
    "LPSTR": "char *",
    "LPVOID": "void *",
    "PVOID": "void *",
    "SHORT": "short",
    "UCHAR": "unsigned char",
    "UINT": "unsigned int",
    "ULONG": "unsigned long",
    "USHORT": "unsigned short",
    "WORD": "unsigned short",
    "byte": "unsigned char",
    "uchar": "unsigned char",
    "uint": "unsigned int",
    "ulong": "unsigned long",
    "ushort": "unsigned short",
}

#: An alias's underlying type must be this simple to substitute textually:
#: words and trailing pointers, nothing a function-pointer typedef carries.
_SIMPLE_TYPE_RE = re.compile(r"[A-Za-z_][\w ]*[\s*]*\Z")

#: Rounds of alias substitution (an alias may name another alias).
_ALIAS_DEPTH = 4

_WORD_RE = re.compile(r"\b[A-Za-z_]\w*\b")


def type_aliases(cfg: ProjectConfig) -> dict[str, str]:
    """``{alias: underlying}`` for simple typedefs, Win32 spellings included."""
    aliases = dict(_BUILTIN_TYPE_ALIASES)
    for name, (_raw, underlying) in collect_typedef_definitions(cfg).items():
        if underlying and _SIMPLE_TYPE_RE.match(underlying):
            aliases[name] = underlying
    return aliases


def expand_type_aliases(text: str, aliases: dict[str, str]) -> str:
    """*text* with every alias word replaced by its underlying type, to a fixed point."""
    for _round in range(_ALIAS_DEPTH):
        expanded = _WORD_RE.sub(lambda m: aliases.get(m.group(), m.group()), text)
        if expanded == text:
            break
        text = expanded
    return text


def _expand_member_types(source_text: str, aliases: dict[str, str]) -> str:
    """Expand member type identifiers without changing names, bounds or pragmas."""
    from rebrew.c_parser import node_text, parse_c_source

    tree, source = parse_c_source(source_text)
    declared: set[str] = set()
    member_types: list[Any] = []
    edits: list[tuple[int, int, str]] = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "struct_specifier" and node.child_by_field_name("body") is not None:
            parent = node.parent
            if parent is not None and parent.type == "type_definition":
                declared.update(
                    node_text(child, source)
                    for child in parent.children
                    if child.type == "type_identifier"
                )
        if node.type == "field_declaration":
            base = node.child_by_field_name("type")
            if base is not None and base.type == "type_identifier":
                member_types.append(base)
        pending.extend(node.children)
    aliases = {name: spelling for name, spelling in aliases.items() if name not in declared}
    for base in member_types:
        spelling = node_text(base, source)
        expanded = expand_type_aliases(spelling, aliases)
        if expanded != spelling:
            edits.append((base.start_byte, base.end_byte, expanded))
    for start, end, spelling in sorted(edits, reverse=True):
        source = source[:start] + spelling.encode("utf-8", errors="surrogateescape") + source[end:]
    return source.decode("utf-8", errors="surrogateescape")


def parse_struct_fields(
    typedef_text: str, aliases: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """``{name, type, offset, size}`` field dicts of one struct definition.

    Laid out by the shared :mod:`rebrew.types` model (tree-sitter, 32-bit
    MSVC alignment) after simple typedef *aliases* are expanded, so a
    ``DWORD`` member is sized as ``unsigned long`` and exported under that
    spelling.  A member whose size the model cannot know (a nested or
    unknown aggregate, a bitfield, a function pointer) ends the layout: it
    and every later member are left out with a warning naming the struct,
    because their offsets are unknown and declib keys members by offset.
    Members are never guessed.
    """
    from rebrew.types import parse_structs

    text = _expand_member_types(typedef_text, aliases) if aliases else typedef_text
    parsed = parse_structs(text)
    if not parsed:
        return []
    name = _struct_name(text)
    struct = parsed.get(name) or next(iter(parsed.values()))
    return _parsed_struct_fields(name, struct, parsed)


def _parsed_struct_fields(
    name: str, struct: StructDef, known: dict[str, StructDef]
) -> list[dict[str, Any]]:
    """Convert the shared layout without losing its file's packing context."""
    from rebrew.types import type_size

    fields = [
        {"name": field, "type": spelling, "offset": offset, "size": type_size(spelling, known) or 0}
        for field, spelling, offset in struct.fields
    ]
    if not struct.complete:
        after = f"after member {fields[-1]['name']}" if fields else "at its first member"
        log.warning(
            "struct %s: layout stops %s (a member of unknown size: nested or unknown "
            "aggregate, bitfield, or function pointer); %d member offset(s) known",
            name or "?",
            after,
            len(fields),
        )
    return fields


def _struct_name(typedef_text: str) -> str:
    """Struct name: the typedef alias after the closing brace, else the ``struct Name {`` tag.

    The alias follows the outermost ``}``; a nested member aggregate
    (``struct { ... } check;``) closes earlier and is not the type's name.
    """
    name_match = re.search(r"\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;\s*\Z", typedef_text.strip())
    if name_match:
        return name_match.group(1)
    sm = re.search(r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", typedef_text)
    return sm.group(1) if sm else ""


def _unsafe_type_names(source: str) -> set[str]:
    """Names whose scope, conditional selection or repeated definition is unknown."""
    from rebrew.c_parser import node_text, parse_c_source

    tree, raw = parse_c_source(source)
    root = tree.root_node
    allowed = {root}
    children = [child for child in root.named_children if child.type != "comment"]
    if len(children) == 1 and children[0].type == "preproc_ifdef":
        guard = children[0]
        name = guard.child_by_field_name("name")
        if (
            guard.children[0].type == "#ifndef"
            and name is not None
            and not any(c.type in {"preproc_else", "preproc_elif"} for c in guard.children)
            and any(
                c.type == "preproc_def"
                and (defined := c.child_by_field_name("name")) is not None
                and node_text(defined, raw) == node_text(name, raw)
                for c in guard.named_children
            )
        ):
            allowed.add(guard)
    counts: dict[str, int] = {}
    unsafe: set[str] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        pending.extend(node.named_children)
        if node.type == "type_definition":
            text = node_text(node, raw)
            alias = _typedef_name_and_type(text) if "{" not in text else None
            name = alias[0] if alias else (_struct_name(text) or _enum_name(text))
        elif (
            node.type in {"struct_specifier", "enum_specifier"}
            and node.child_by_field_name("body") is not None
            and node.parent.type != "type_definition"
        ):
            text = node_text(node, raw)
            name = _struct_name(text) or _enum_name(text)
        else:
            continue
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
        parent = node.parent
        if parent.type == "declaration":
            parent = parent.parent
        if parent not in allowed or node.has_error:
            unsafe.add(name)
    return unsafe | {name for name, count in counts.items() if count > 1}


def collect_struct_definitions(
    cfg: ProjectConfig,
) -> dict[str, tuple[str, list[dict[str, Any]], int | None]]:
    """Collect struct definitions from ``reversed_dir`` headers and sources.

    Returns ``{struct_name: (raw_typedef_text, fields, complete_size)}``.
    Differing definitions or layouts are omitted: BinSync cannot represent
    translation-unit-private types under the same name.
    """
    from rebrew.struct_parser import extract_structs_from_file, extract_type_definitions
    from rebrew.types import parse_structs
    from rebrew.utils import read_source_text

    result: dict[str, tuple[str, list[dict[str, Any]], int | None]] = {}
    duplicates: set[str] = set()
    unresolved: set[str] = set()
    for path in _iter_definition_files(cfg):
        try:
            definitions = list(extract_structs_from_file(path))
            if not definitions:
                continue
            source, _ = read_source_text(path)
            unsafe = _unsafe_type_names(source)
            file_aliases = dict(_BUILTIN_TYPE_ALIASES)
            for text in extract_type_definitions(path):
                if (
                    "{" not in text
                    and (alias := _typedef_name_and_type(text)) is not None
                    and alias[0] not in unsafe
                ):
                    file_aliases[alias[0]] = alias[1]
            for name in unsafe:
                file_aliases.pop(name, None)
            # shortcut: include packing is unknown, use preprocessed input to resolve it.
            parsed = parse_structs(_expand_member_types(source, file_aliases))
            for typedef_text in definitions:
                name = _struct_name(typedef_text)
                if not name:
                    continue
                if name in unsafe:
                    unresolved.add(name)
                    log.warning(
                        "struct %s in %s: unresolved scope or conditional context; omitted",
                        name,
                        path,
                    )
                    continue
                struct = parsed.get(name)
                if struct is None:
                    continue
                candidate = (
                    typedef_text.strip(),
                    _parsed_struct_fields(name, struct, parsed),
                    struct.size if struct.complete else None,
                )
                if name in result:
                    previous = result[name]
                    if (
                        " ".join(previous[0].split()) != " ".join(typedef_text.split())
                        or previous[1:] != candidate[1:]
                    ):
                        duplicates.add(name)
                else:
                    result[name] = candidate
        except Exception:
            # One malformed file must not drop every later definition from the export.
            log.warning("struct collection failed for %s; skipped", path, exc_info=True)
    if duplicates:
        listed = ", ".join(sorted(duplicates)[:_DUPLICATE_LIST_LIMIT])
        more = len(duplicates) - _DUPLICATE_LIST_LIMIT
        log.warning(
            "%d struct name(s) have more than one differing definition or layout; "
            "omitted from sync: %s%s",
            len(duplicates),
            listed,
            f" and {more} more" if more > 0 else "",
        )
    return {
        name: definition
        for name, definition in result.items()
        if name not in duplicates | unresolved
    }


#: Duplicate struct names listed by name in the collection warning.
_DUPLICATE_LIST_LIMIT = 10


def _iter_definition_files(cfg: ProjectConfig) -> list[Path]:
    """Files scanned for type definitions, in preference order.

    Target-local headers, then the project-shared header tree, then the
    target's sources. Collectors must check name collisions across these files.
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

    A bare ``IDENT`` takes the previous value + 1, starting at 0.
    An unknown explicit value invalidates the complete projection.
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
                return {}
        else:
            ident = entry
            value = next_value
        if not re.fullmatch(r"[A-Za-z_]\w*", ident):
            return {}
        members[ident] = value
        next_value = value + 1
    return members


def collect_enum_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, dict[str, int]]]:
    """Collect ``{enum_name: (raw_definition, {member: value})}``."""
    from rebrew.struct_parser import extract_enums_from_file
    from rebrew.utils import read_source_text

    result: dict[str, tuple[str, dict[str, int]]] = {}
    ambiguous: set[str] = set()
    for path in _iter_definition_files(cfg):
        try:
            source, _ = read_source_text(path)
            unsafe = _unsafe_type_names(source)
            for text in extract_enums_from_file(path):
                name = _enum_name(text)
                if not name:
                    continue
                members = _enum_members(text)
                if name in unsafe or not members or name in result and result[name][1] != members:
                    ambiguous.add(name)
                else:
                    result[name] = (text.strip(), members)
        except Exception:
            log.warning("enum collection failed for %s; skipped", path, exc_info=True)
    if ambiguous:
        log.warning(
            "ambiguous or unresolved enum names omitted from sync: %s", ", ".join(sorted(ambiguous))
        )
    return {name: definition for name, definition in result.items() if name not in ambiguous}


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
    from rebrew.utils import read_source_text

    result: dict[str, tuple[str, str]] = {}
    ambiguous: set[str] = set()
    for path in _iter_definition_files(cfg):
        try:
            source, _ = read_source_text(path)
            unsafe = _unsafe_type_names(source)
            for text in extract_type_definitions(path):
                if re.search(r"\b(?:struct|enum)\b", text) or "{" in text:
                    continue
                parsed = _typedef_name_and_type(text)
                if parsed is None:
                    continue
                name, underlying = parsed
                if name in unsafe:
                    ambiguous.add(name)
                if name in result and result[name][1] != underlying:
                    ambiguous.add(name)
                elif name:
                    result[name] = (text.strip(), underlying)
        except Exception:
            log.warning("typedef collection failed for %s; skipped", path, exc_info=True)
    if ambiguous:
        log.warning("ambiguous typedef names omitted from sync: %s", ", ".join(sorted(ambiguous)))
    return {name: definition for name, definition in result.items() if name not in ambiguous}


def type_sync_records(cfg: ProjectConfig) -> dict[str, dict[str, Any]]:
    """Native type projections shared by hashing, reconciliation and export."""
    from rebrew.types import type_size

    records: dict[str, dict[str, Any]] = {}
    definitions = collect_struct_definitions(cfg)
    known = {
        name: StructDef(name, size=size)
        for name, (_text, _fields, size) in definitions.items()
        if size is not None and size > 0
    }
    while True:
        missing = {
            name
            for name in known
            if any(type_size(str(field["type"]), known) is None for field in definitions[name][1])
        }
        if not missing:
            break
        for name in missing:
            log.warning(
                "struct %s: embedded type has no unambiguous exported layout; omitted", name
            )
            del known[name]
    for name, (_text, fields, total_size) in definitions.items():
        if total_size is None or total_size <= 0:
            log.warning("struct %s: incomplete or zero-size layout omitted from sync", name)
            continue
        if name not in known:
            continue
        members = {}
        next_offset = 0
        for field in fields:
            size = int(field.get("size") or type_size(str(field["type"])) or 0)
            offset = int(field.get("offset", next_offset))
            members[field["name"]] = {"type": field["type"], "offset": offset, "size": size}
            next_offset = offset + size
        records[f"struct.{name}"] = {
            "definition": {
                "size": total_size,
                "members": members,
            }
        }
    for name, (_text, members_) in collect_enum_definitions(cfg).items():
        records[f"enum.{name}"] = {"definition": members_}
    for name, (_text, underlying) in collect_typedef_definitions(cfg).items():
        records[f"typedef.{name}"] = {"definition": underlying}
    return records


def incoming_type_records(state_dir: Path) -> dict[str, dict[str, Any]]:
    """Read external type projections through the shared artifact readers."""
    records: dict[str, dict[str, Any]] = {}
    for name, entry in load_binsync_structs(state_dir).items():
        records[f"struct.{name}"] = {
            "definition": {"size": entry["size"], "members": entry["fields"]}
        }
    for name, entry in load_binsync_enums(state_dir).items():
        records[f"enum.{name}"] = {"definition": entry["members"]}
    for name, entry in load_binsync_typedefs(state_dir).items():
        records[f"typedef.{name}"] = {"definition": entry["type"]}
    return records


def sync_watch_paths(cfg: ProjectConfig, state_dir: Path) -> list[Path]:
    """All inputs that can change the integration projection, including new sources."""
    from rebrew.metadata.storage import metadata_store
    from rebrew.sources import iter_sources

    paths = set(iter_sources(cfg.reversed_dir, cfg))
    paths.update(_iter_definition_files(cfg))
    paths.update(
        Path(root) for root in (cfg.reversed_dir, getattr(cfg, "shared_dir", None)) if root
    )
    for name in ("rebrew-functions.toml", "rebrew-data.toml", "rebrew-libraries.toml"):
        store = cfg.metadata_dir / name
        paths.update(metadata_store(store).inputs())
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
