"""Source promotion, copying, shared-file binding, and verification helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
lazy import shutil
lazy from collections.abc import Callable
lazy from dataclasses import replace
lazy from pathlib import Path

lazy from rebrew.config import ProjectConfig, target_module
lazy from rebrew.source.discovery import contained_path, source_roots
lazy from rebrew.utils import (
    atomic_write_text,
    preset_module_key,
    read_source_text,
    rel_display_path,
    sha256_file,
    split_source_lines,
)

if TYPE_CHECKING:
    from rebrew.compiler.cache import CacheBackend
    from rebrew.compiler.compile import CompareResult
    from rebrew.metadata.bindings import SourceBinding

__all__ = [
    "extract_function_text",
    "import_function",
    "import_shared_function",
    "promote_to_shared",
    "retarget_moved_identity",
    "rewrite_address",
    "source_flags",
    "symbol_for_va",
    "verify_import",
]

#: Function starts in the destination are aligned to this many bytes; the gap
#: before the next start is linker padding.
_FUNCTION_ALIGNMENT = 16


# ---------------------------------------------------------------------------
# Verification sizing and merged inventory recovery
# ---------------------------------------------------------------------------


def _merged_entry_body_size(
    cfg_dst: ProjectConfig, va: int, entry_size: int, result: CompareResult
) -> int | None:
    """Compiled size when the destination inventory entry merges functions.

    Discovery joins adjacent functions when the boundary is only ``ret`` plus
    alignment padding, so the entry's size covers the next function too and a
    true twin verifies as ``SIZE_MISMATCH`` (guild-rebrew GOLD 0x5510f0: entry
    1056 bytes, function 62).  The compiled body is the whole function when it
    is shorter than the entry, every byte of it matches (relocations masked),
    and the destination bytes from its end to the next
    :data:`_FUNCTION_ALIGNMENT` boundary are all padding (none when the end is
    already aligned).  Returns that size, or ``None`` for any other result.
    """
    from rebrew.formats.binary_loader import PADDING_BYTES, extract_bytes_at_va, load_binary

    body = result.full_obj_size
    if (
        result.status != "SIZE_MISMATCH"
        or body is None
        or not 0 < body < entry_size
        or result.match_count != body
    ):
        return None
    end = va + body
    gap = -end % _FUNCTION_ALIGNMENT
    if gap == 0:
        return body
    tail = extract_bytes_at_va(load_binary(cfg_dst.target_binary), end, gap, trim_padding=False)
    if tail is not None and len(tail) == gap and all(b in PADDING_BYTES for b in tail):
        return body
    return None


def verify_import(
    entry: SourceBinding,
    cfg_dst: ProjectConfig,
    *,
    cache: CacheBackend | None,
    name_to_va: dict[str, int] | None,
    verify_entry_fn: Callable[..., CompareResult] | None = None,
) -> tuple[CompareResult, int | None]:
    """Verify *entry*, re-verifying at the body size on a merged inventory entry.

    Returns the result and the body size when the entry's own size was
    replaced by :func:`_merged_entry_body_size` (``None`` otherwise).  A
    re-verify that does not match keeps the original result.
    """
    if verify_entry_fn is None:
        raise ValueError("verify_entry_fn is required")
    result = verify_entry_fn(entry, cfg_dst, cache=cache, name_to_va=name_to_va)
    body = _merged_entry_body_size(cfg_dst, entry.va, entry.size, result)
    if body is None:
        return result, None
    body_entry = replace(entry, size=body)
    retry = verify_entry_fn(body_entry, cfg_dst, cache=cache, name_to_va=name_to_va)
    if not retry.matched:
        return result, None
    entry.size = body
    entry.comparison_inputs = body_entry.comparison_inputs
    return retry, body


def _merged_entry_note(body: int) -> str:
    """Result message suffix for an import sized by :func:`_merged_entry_body_size`."""
    return f"(destination inventory entry merges functions: sized to the {body}-byte body)"


# ---------------------------------------------------------------------------
# Source extraction, anchor rewriting, and stub retirement
# ---------------------------------------------------------------------------


def extract_function_text(
    text: str,
    name: str,
    *,
    shared_preamble_fn: Callable[..., str] | None = None,
) -> str | None:
    """Copy one C definition, its shared declarations and static dependencies."""
    from rebrew.source.layout import source_layout, span_extent

    if shared_preamble_fn is None:
        raise ValueError("shared_preamble_fn is required")
    raw, spans = source_layout(text)
    functions = [span for span in spans if span.kind == "function"]
    selected = [span for span in functions if span.name == name]
    if not selected:
        return None
    if len(functions) == 1:
        return text
    if any(span.inside_pp for span in selected):
        raise ValueError("cannot extract a conditional definition from a multi-function file")
    copied = [
        span
        for span in spans
        if span in selected or span.kind == "storage" or (span.kind == "function" and span.static)
    ]
    extents = [span_extent(raw, span, spans) for span in copied]
    preamble = shared_preamble_fn(raw, spans, extents)
    return preamble + "\n".join(
        raw[start:end].decode("utf-8", errors="surrogateescape") for start, end in extents
    )


def rewrite_address(
    text: str, module: str, va: int, *, name: str, syntax: Any = None, source_syntax: Any = None
) -> str:
    """A copied definition receives only the destination address."""
    from rebrew.metadata.anchors import add_address_anchor, parse_address_anchors

    anchors = parse_address_anchors(text, syntax=source_syntax)
    removed = {a.line for a in anchors if a.kind == "FUNCTION" and a.name == name}
    body = "".join(
        line
        for i, line in enumerate(split_source_lines(text, keepends=True), 1)
        if i not in removed
    )
    return add_address_anchor(body, module, va, name, syntax=syntax)


def _strip_claim(block: str, claim: tuple[str, int], *, syntax: Any = None) -> str:
    """Remove one superseded address while preserving the declaration and other targets."""
    from rebrew.metadata.anchors import parse_address_anchors

    removed = {
        a.line
        for a in parse_address_anchors(block, syntax=syntax)
        if preset_module_key(a.module) == preset_module_key(claim[0]) and a.va == claim[1]
    }
    return "".join(
        ("\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else "")
        if i in removed
        else line
        for i, line in enumerate(split_source_lines(block, keepends=True), 1)
    )


def _retire_shared_stub(cfg: ProjectConfig, path: Path, claim: tuple[str, int]) -> bool:
    """Delete only an unowned single-body stub; return whether it was retired."""
    from rebrew.c_syntax.parser import find_c_function_definitions, find_variable_roles
    from rebrew.metadata.anchors import parse_address_anchors
    from rebrew.metadata.data import load_data_metadata
    from rebrew.metadata.functions import identity_file, load_metadata, stored_file_matches
    from rebrew.utils import SOURCE_BACKUP_DIRNAME, source_backup

    text, encoding = read_source_text(path)
    rel = identity_file(path, cfg.metadata_dir)
    owners = [
        *load_metadata(cfg.metadata_dir, deepcopy=False).values(),
        *load_data_metadata(cfg.metadata_dir, deepcopy=False).values(),
    ]
    syntax = getattr(cfg, "address_comments", None)
    kept = _strip_claim(text, claim, syntax=syntax)
    indexes = parse_address_anchors(kept, syntax=syntax)
    definitions, _declarations, _uses = find_variable_roles(text)
    remaining = any(stored_file_matches(str(row.get("file") or ""), rel) for row in owners)
    if remaining or indexes or definitions or len(find_c_function_definitions(text)) != 1:
        if kept != text:
            with source_backup(
                path,
                text,
                encoding,
                Path(cfg.root) / ".rebrew" / SOURCE_BACKUP_DIRNAME,
                label="shared-import",
                keep=True,
            ):
                atomic_write_text(path, kept, encoding=encoding)
        return False
    path.unlink()
    return True


# ---------------------------------------------------------------------------
# Shared promotion and import operations
# ---------------------------------------------------------------------------


def promote_to_shared(
    cfg_src: ProjectConfig,
    src_file: str,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Move a per-target source into ``src/shared`` preserving relative path.

    The shared tree only works when the file actually lives under the shared
    root. A file left in the source target's own tree is invisible to other
    targets' scans. This moves ``<reversed_dir>/<src_file>`` to
    ``<shared_dir>/<src_file>`` (creating parent dirs), refusing when the
    shared dir is disabled, the source is missing, or the destination already
    exists with different bytes. ``(module, va)`` keys stay put. Rows whose
    ``file`` named the old path are retargeted at the shared path, in both
    metadata stores.

    Returns a result dict with ``action`` ``promoted`` / ``would-promote`` /
    ``already-shared`` / ``error`` and the shared-relative ``filepath``. A source
    already under the shared root is a successful no-op, so replaying the
    promotion cannot move it into a nested shared tree or overwrite itself. If
    the move landed but its metadata update did not, the replay finishes that
    update instead of leaving rows pointed at the vanished per-target path.
    """
    shared_root = getattr(cfg_src, "shared_dir", None)
    if shared_root is None:
        return {
            "action": "error",
            "status": "NO_SHARED_DIR",
            "filepath": src_file,
            "message": "shared_dir is disabled — set project.shared_dir first",
        }
    shared_path = Path(shared_root).resolve()
    src_path = contained_path(source_roots(cfg_src), src_file)
    shared_candidate = contained_path(shared_path, src_file)
    if (
        (src_path is None or not src_path.is_file())
        and shared_candidate is not None
        and shared_candidate.is_file()
    ):
        # The original relative name still resolves after a completed move.
        # Accept the shared copy so a retry can finish an interrupted retarget.
        src_path = shared_candidate
    if src_path is None:
        return {
            "action": "error",
            "status": "READ_ERROR",
            "filepath": src_file,
            "message": f"file escapes its tree: {src_file!r}",
        }
    if not src_path.is_file():
        return {
            "action": "error",
            "status": "READ_ERROR",
            "filepath": src_file,
            "message": f"source not found: {src_path}",
        }
    if src_path.is_relative_to(shared_path):
        if not dry_run and getattr(cfg_src, "metadata_dir", None) is not None:
            previous = Path(cfg_src.reversed_dir).resolve() / src_path.relative_to(shared_path)
            if not previous.exists():
                retarget_moved_identity(cfg_src, previous, src_path)
        return {
            "action": "already-shared",
            "status": "",
            "filepath": src_file,
            "message": f"source is already in the shared tree: {src_path}",
        }
    dst_path = contained_path(shared_root, src_file)
    if dst_path is None:
        return {
            "action": "error",
            "status": "READ_ERROR",
            "filepath": src_file,
            "message": f"file escapes its tree: {src_file!r}",
        }
    if dst_path.exists():
        if not dry_run:
            try:
                interrupted_copy = (
                    src_path.is_file()
                    and dst_path.is_file()
                    and sha256_file(src_path) == sha256_file(dst_path)
                )
            except OSError:
                interrupted_copy = False
            if interrupted_copy:
                # A cross-filesystem move copies before unlinking its source.
                # If it stopped between those steps, equal bytes prove the
                # destination is that copy, so finish the move instead of
                # refusing every later retry as a conflict.
                try:
                    src_path.unlink()
                except OSError as exc:
                    return {
                        "action": "error",
                        "status": "WRITE_ERROR",
                        "filepath": src_file,
                        "message": str(exc),
                    }
                retarget_moved_identity(cfg_src, src_path, dst_path)
                return {
                    "action": "promoted",
                    "status": "",
                    "filepath": src_file,
                    "message": f"completed interrupted move from {src_path} to {dst_path}",
                }
        return {
            "action": "error",
            "status": "TARGET_CONFLICT",
            "filepath": src_file,
            "message": f"shared destination already exists: {dst_path}",
        }
    if dry_run:
        return {
            "action": "would-promote",
            "status": "",
            "filepath": src_file,
            "message": f"would move {src_path} to {dst_path}",
        }
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        # shared_dir is config-set and may sit on another mount; rename raises EXDEV there.
        shutil.move(src_path, dst_path)
    except OSError as exc:
        return {
            "action": "error",
            "status": "WRITE_ERROR",
            "filepath": src_file,
            "message": str(exc),
        }
    retarget_moved_identity(cfg_src, src_path, dst_path)
    return {
        "action": "promoted",
        "status": "",
        "filepath": src_file,
        "message": f"moved {src_path} to {dst_path}",
    }


def retarget_moved_identity(cfg: Any, old_path: Path, new_path: Path) -> None:
    """Point function and data rows from *old_path* at *new_path*.

    Identity is the row's ``file``, not a binding that travels with the bytes.
    A path the store refuses (absolute, or a ``..`` segment) is left as it
    was. Publication errors propagate so a replay can retry the unfinished
    retarget after the move.
    """
    meta = getattr(cfg, "metadata_dir", None)
    if meta is None:
        return
    from rebrew.metadata.data import load_data_metadata, record_data_rows
    from rebrew.metadata.functions import (
        identity_file,
        load_metadata,
        record_function_rows,
        validate_identity_file,
    )

    try:
        old_rel = validate_identity_file(identity_file(old_path, meta))
        new_rel = validate_identity_file(identity_file(new_path, meta))
    except ValueError:
        return
    if old_rel == new_rel:
        return
    old_key = old_rel.replace("\\", "/")

    def _matches(entry: dict[str, Any]) -> bool:
        return str(entry.get("file") or "").replace("\\", "/") == old_key

    rows = [
        {"module": module, "va": va, "identity": {"file": new_rel}}
        for (module, va), entry in load_metadata(meta, deepcopy=False).items()
        if _matches(entry)
    ]
    if rows:
        record_function_rows(meta, rows)
    data_rows = [
        {"module": module, "va": va, "identity": {"file": new_rel}}
        for (module, va), entry in load_data_metadata(meta, deepcopy=False).items()
        if _matches(entry)
    ]
    if data_rows:
        record_data_rows(meta, data_rows)


def _import_result(
    dst_va: int,
    src_va: int,
    *,
    action: str,
    status: str,
    filepath: str,
    message: str,
    relocation_bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Per-function import result row for the CLI/JSON report.

    Unresolved relocation operands are listed under ``unresolved_relocations``:
    the compare masks them without proof, and for an import they usually name a
    callee or global by the source target's spelling, which the destination does
    not define.
    """
    unresolved = _unresolved_operands(relocation_bindings)
    return {
        "dst_va": f"0x{dst_va:08x}",
        "src_va": f"0x{src_va:08x}",
        "score": None,
        "action": action,
        "status": status,
        "filepath": filepath,
        "message": message,
        **({"relocation_bindings": relocation_bindings} if relocation_bindings is not None else {}),
        **({"unresolved_relocations": unresolved} if unresolved else {}),
    }


def _unresolved_operands(bindings: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Offset, symbol and kind of each operand the destination could not bind."""
    return [
        {"offset": row["offset"], "symbol": row["symbol"], "kind": row["kind"]}
        for row in bindings or []
        if row.get("status") == "UNRESOLVED"
    ]


def _unresolved_message(result_message: str, unresolved: list[dict[str, Any]]) -> str:
    """Skip reason for an import refused because operands stay unresolved."""
    shown = ", ".join(row["symbol"] for row in unresolved[:5])
    more = f" and {len(unresolved) - 5} more" if len(unresolved) > 5 else ""
    return (
        f"{result_message} ({len(unresolved)} unresolved relocation operand(s): {shown}{more}; "
        "claim not recorded)"
    )


class _UnresolvedImport(Exception):
    """A verified import was refused for unresolved operands; the transaction rolls back."""

    def __init__(self, message: str, status: str, bindings: list[dict[str, Any]]) -> None:
        super().__init__(message)
        self.status = status
        self.bindings = bindings


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
    verify_entry_fn: Callable[..., CompareResult] | None = None,
    apply_status_updates_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Import by recording a destination row for the SHARED source file.

    Unlike :func:`import_function` (which copies the source into the
    destination's ``reversed_dir``), this keeps one file (in the shared dir
    when the source already lives there, else in the source target's own
    tree). The function is compiled and verified against the destination
    binary through the standard verify flow. A match records
    ``MODULE.0xVA`` in the destination store, preserving existing bindings and
    their state. The destination metadata records the source's flags. The source directory
    is not added as an include path: the file stays in its own tree.

    The import is verified before STATUS promotion exactly like the copy
    path: a mismatch reports ``imported-unverified``, never a false match.

    When *dst_file* names the destination's existing stub for *dst_va* (a
    different file than the shared target), a matched import retires it only
    when no other target, function or data owner remains. Otherwise only the
    superseded inline claim is blanked, preserving line numbers and the other
    owners. An unverified import leaves the stub in place.
    """
    shared_root = getattr(cfg_src, "shared_dir", None)
    shared_path = contained_path(shared_root, src_file) if shared_root is not None else None
    reversed_path = contained_path(source_roots(cfg_src), src_file)
    if reversed_path is None:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="READ_ERROR",
            filepath=src_file,
            message=f"file escapes reversed_dir: {src_file!r}",
        )
    target_path = (
        shared_path if shared_path is not None and shared_path.is_file() else reversed_path
    )
    try:
        text, _encoding = read_source_text(target_path)
    except OSError as exc:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="READ_ERROR",
            filepath=src_file,
            message=str(exc),
        )
    module = target_module(cfg_dst) or cfg_dst.target_name

    from rebrew.metadata.bindings import (
        FUNCTION_KINDS,
        read_source_bindings,
        split_address_sections,
    )

    existing = read_source_bindings(
        target_path,
        target_name=module,
        metadata_dir=cfg_dst.metadata_dir,
        project_root=cfg_dst.root,
    )
    src_module = target_module(cfg_src) or cfg_src.target_name
    superseded = any(e.va == dst_va for e in existing)
    syntax = getattr(cfg_src, "address_comments", None)
    if syntax != getattr(cfg_dst, "address_comments", None):
        raise ValueError("shared imports require compatible address_comments settings")
    _preamble, blocks = split_address_sections(text, syntax=syntax)
    already_on_source = False
    dst_elsewhere = False
    has_src = False
    for block in blocks:
        from rebrew.metadata.anchors import parse_address_anchors

        claims = [(a.module, a.va) for a in parse_address_anchors(block, syntax=syntax)]
        if (src_module, src_va) in claims:
            has_src = True
            if (module, dst_va) in claims:
                already_on_source = True
        elif (module, dst_va) in claims:
            dst_elsewhere = True
    needs_move = dst_elsewhere and has_src
    # A VA that is not already in this file, and whose binding is not already
    # on the source body, is a new claim. A failed new claim must not write
    # STATUS: the file text no longer changes, so that is not the signal.
    new_claim = not superseded and not already_on_source

    from rebrew.metadata.functions import get_entry

    # Managed identities can bind another definition in this same file.
    name, symbol = symbol_for_va(text, src_module, src_va, target_path.stem, syntax=syntax)
    if name == target_path.stem:
        for ann in read_source_bindings(
            target_path, target_name=src_module, metadata_dir=getattr(cfg_src, "metadata_dir", None)
        ):
            if ann.va == src_va and ann.name and ann.kind in FUNCTION_KINDS:
                name, symbol = ann.name, ann.symbol or ("_" + ann.name)
                break
    prior = get_entry(cfg_dst.metadata_dir, dst_va, module)
    from rebrew.metadata.binding_history import retired_binding

    if retired_binding(prior):
        # Refuse before verifying or writing anything: the identity write
        # would refuse it later, after the size write had already landed.
        raise ValueError("retired source bindings require an explicit reviewed rebind")
    if prior.get("symbol") and prior["symbol"] != symbol:
        needs_move = True

    if dry_run:
        if needs_move:
            note = f"would retarget {module} 0x{dst_va:x} onto the 0x{src_va:x} body"
        elif dst_file:
            note = f"would supersede {dst_file}"
        else:
            note = f"would record {module} 0x{dst_va:x}"
        return _import_result(
            dst_va,
            src_va,
            action="would-import-shared",
            status="",
            filepath=rel_display_path(target_path, cfg_dst.reversed_dir),
            message=note,
        )

    if verify_entry_fn is None:
        raise ValueError("verify_entry_fn is required")
    if apply_status_updates_fn is None:
        raise ValueError("apply_status_updates_fn is required")

    from rebrew.metadata.bindings import SourceBinding
    from rebrew.metadata.functions import remove_field, update_field

    src_flags = source_flags(cfg_src, target_path, src_va)
    # No source-dir /I here (unlike the copy path): the shared file moves
    # WITH its tree under src/shared, so relative #include chains resolve
    # against its own directory already (compiler/compile.py always adds src_parent).
    # Recording an absolute ``/I<parent>`` would bake one machine's checkout
    # path into the metadata and break the file on promote or clone —
    # exactly the guild-rebrew GOLDTL.0x004c75e0 case.
    cflags = src_flags.strip()
    # Record flags only when they differ from what the destination would use
    # anyway: an inherited value written per function is lint W029 noise and
    # one more thing to keep in sync (guild-rebrew imported 25
    # functions and 25 W029 rows appeared).
    inherited = str(getattr(cfg_dst, "cflags", "") or "").strip()
    # The verify filepath resolves against the destination's reversed_dir —
    # a shared file becomes ``../shared/f.c`` via the standard helper.
    rel_dst = rel_display_path(target_path, cfg_dst.reversed_dir)
    entry = SourceBinding(
        va=dst_va,
        name=name,
        symbol=symbol,
        size=dst_size,
        filepath=rel_dst,
        kind="FUNCTION",
        status="STUB",
        module=module,
        cflags=cflags,
    )
    # Removing a superseded address preserves physical lines and C semantics.
    # Compare the exact candidate bytes so the stored input hash names that source.
    candidate = _strip_claim(text, (module, dst_va), syntax=syntax) if needs_move else text
    from rebrew.utils import SOURCE_BACKUP_DIRNAME, source_backup

    with source_backup(
        target_path,
        text,
        _encoding,
        Path(cfg_dst.root) / ".rebrew" / SOURCE_BACKUP_DIRNAME,
        label="shared-import",
        keep=candidate != text,
    ):
        try:
            if candidate != text:
                atomic_write_text(target_path, candidate, encoding=_encoding)
            result, body = verify_import(
                entry,
                cfg_dst,
                cache=cache,
                name_to_va=name_to_va,
                verify_entry_fn=verify_entry_fn,
            )
        except BaseException:
            if candidate != text:
                atomic_write_text(target_path, text, encoding=_encoding)
            raise
        unresolved = _unresolved_operands(result.relocation_bindings)
        unresolved_refused = require_resolved and result.matched and bool(unresolved)
        if (not result.matched or unresolved_refused) and candidate != text:
            atomic_write_text(target_path, text, encoding=_encoding)
    if unresolved_refused:
        return _import_result(
            dst_va,
            src_va,
            action="skipped-unresolved",
            status=result.status,
            filepath=rel_dst,
            message=_unresolved_message(result.message, unresolved),
            relocation_bindings=result.relocation_bindings,
        )
    # A failed new claim, and a failed move of an existing claim onto a
    # different body, must not promote STATUS. An existing claim that is
    # already on the source body still records the verify result.
    reject = (not result.matched) and (new_claim or needs_move)
    action = "imported-shared" if result.matched else "imported-unverified"
    message = result.message
    if body is not None and not reject:
        message = f"{message} {_merged_entry_note(body)}".strip()
    if reject:
        action = "skipped-unverified"
        message = (
            f"{message} (destination already annotates this VA; claim not recorded)"
            if dst_file
            else f"{message} (claim not recorded)"
        )
    else:
        if result.matched:
            from rebrew.metadata.functions import identity_file, record_function_identity

            record_function_identity(
                cfg_dst.metadata_dir,
                module=module,
                va=dst_va,
                file=identity_file(target_path, cfg_dst.metadata_dir),
                kind="FUNCTION",
                name=name,
                symbol=symbol,
                size=body if body is not None else dst_size,
                overwrite_name=True,
            )
            if needs_move:
                message = (
                    f"{message} (retargeted {module} 0x{dst_va:x} onto the 0x{src_va:x} body)"
                ).strip()
        if body is not None:
            update_field(
                cfg_dst.metadata_dir, dst_va, "size", body, module, updated_by="cross-import"
            )
        if cflags and cflags != inherited:
            update_field(
                cfg_dst.metadata_dir, dst_va, "cflags", cflags, module, updated_by="cross-import"
            )
        else:
            remove_field(cfg_dst.metadata_dir, dst_va, "cflags", module)
        apply_status_updates_fn([(entry, result.status, result.delta)], cfg_dst)
    if result.matched and dst_file:
        stub_path = contained_path(source_roots(cfg_dst), dst_file)
        if stub_path is not None and stub_path != target_path and stub_path.is_file():
            try:
                retired = _retire_shared_stub(cfg_dst, stub_path, (module, dst_va))
                note = (
                    f"superseded {dst_file}"
                    if retired
                    else f"kept {dst_file}: other source owners remain"
                )
                message = f"{message} ({note})".strip()
            except OSError as exc:
                return _import_result(
                    dst_va,
                    src_va,
                    action="error",
                    status=result.status,
                    filepath=rel_dst,
                    message=f"shared import verified but stub removal failed: {exc}",
                )
    return _import_result(
        dst_va,
        src_va,
        action=action,
        status=result.status,
        filepath=rel_dst,
        message=message,
        relocation_bindings=result.relocation_bindings,
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
    shared_preamble_fn: Callable[..., str] | None = None,
    verify_entry_fn: Callable[..., CompareResult] | None = None,
    apply_status_updates_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Import the matched source function *src_file* into the destination.

    Writes pure C to the destination's reversed_dir (*dst_file* if given,
    else the source's own relative path) and records the destination
    ``MODULE.0xVA`` row, then compiles and
    verifies it against the destination binary and promotes STATUS via the
    standard verify flow (``verify_entry`` + ``apply_status_updates``).  The
    destination metadata records the flags the copy needs, which include the
    source's directory so its relative ``#include``s still resolve.

    With *dry_run* nothing is written or verified; the result carries the
    planned action.

    Returns a per-function result dict for the CLI/JSON report.
    """
    src_path = contained_path(source_roots(cfg_src), src_file)
    if src_path is None:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="READ_ERROR",
            filepath=src_file,
            message=f"file escapes reversed_dir: {src_file!r}",
        )
    try:
        text, src_encoding = read_source_text(src_path)
    except OSError as exc:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="READ_ERROR",
            filepath=src_file,
            message=str(exc),
        )

    module = target_module(cfg_dst) or cfg_dst.target_name
    src_module = target_module(cfg_src) or cfg_src.target_name
    from rebrew.metadata.bindings import FUNCTION_KINDS, read_source_bindings

    donor = next(
        (
            ann
            for ann in read_source_bindings(
                src_path,
                target_name=src_module,
                metadata_dir=cfg_src.metadata_dir,
                project_root=cfg_src.root,
            )
            if ann.va == src_va and ann.kind in FUNCTION_KINDS
        ),
        None,
    )
    extracted = (
        extract_function_text(text, donor.name, shared_preamble_fn=shared_preamble_fn)
        if donor is not None
        else None
    )
    if donor is None or extracted is None:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="NO_DEFINITION",
            filepath=src_file,
            message=f"source {src_file} has no definition for 0x{src_va:x}",
        )
    copied_name = donor.name
    copied_symbol = donor.symbol or ("_" + donor.name)
    rewritten = rewrite_address(
        extracted,
        module,
        dst_va,
        name=copied_name,
        syntax=getattr(cfg_dst, "address_comments", None),
        source_syntax=getattr(cfg_src, "address_comments", None),
    )
    if dst_file is None:
        # Keep the source's path relative to its own reversed_dir: it gives
        # one destination file per source file (two imports out of one
        # multi-function source no longer collide on the bare name) and keeps
        # the directory depth the copy's relative #includes assume.
        dst_file = src_file if not Path(src_file).is_absolute() else src_path.name
    dst_path = contained_path(source_roots(cfg_dst), dst_file)
    rel_dst = str(Path(dst_file))
    if dst_path is None:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="READ_ERROR",
            filepath=rel_dst,
            message=f"destination file escapes reversed_dir: {dst_file!r}",
        )

    from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction

    expected = coordinated_inputs(cfg_dst.metadata_dir, [dst_path]) if not dry_run else {}

    # Refuse to clobber.  The copy path writes ONE extracted function over
    # whatever the destination path holds, so it is only safe when that file
    # holds exactly the destination's own single block and nothing else.  In
    # the unified tree (``shared_dir``) the destination path is usually the
    # SOURCE file itself, holding this function's SERVER block plus every
    # co-resident function: a whole-file write there deletes them all and
    # duplicates the body (C2084).  Those cases need ``--shared``, which moves
    # the binding onto the body already in the file.  Checked before the
    # dry-run return so the preview lists it.
    dst_encoding = src_encoding
    if dst_path.exists():
        from rebrew.metadata.bindings import source_bindings
        from rebrew.source.layout import source_layout

        try:
            dst_text, dst_encoding = read_source_text(dst_path)
        except OSError as exc:
            return _import_result(
                dst_va,
                src_va,
                action="error",
                status="READ_ERROR",
                filepath=rel_dst,
                message=str(exc),
            )
        existing = source_bindings(
            dst_text,
            dst_path,
            None,
            None,
            cfg_dst.metadata_dir,
            project_root=cfg_dst.root,
        )
        own = [
            entry
            for entry in existing
            if entry.va == dst_va
            and preset_module_key(entry.module) == preset_module_key(module)
            and entry.kind in FUNCTION_KINDS
        ]
        other = [entry for entry in existing if entry not in own]
        src_module = target_module(cfg_src) or cfg_src.target_name
        src_in_file = any(
            e.va == src_va
            for e in read_source_bindings(
                dst_path,
                target_name=src_module,
                metadata_dir=cfg_src.metadata_dir,
                project_root=cfg_src.root,
            )
        )
        raw, spans = source_layout(dst_text)
        definitions = [span for span in spans if span.kind in {"function", "storage"}]
        preamble = [raw[span.start : span.end] for span in spans if span.kind == "preamble"]
        preamble_changed = False
        if preamble:
            replacement, replacement_spans = source_layout(rewritten)
            preamble_changed = preamble != [
                replacement[span.start : span.end]
                for span in replacement_spans
                if span.kind == "preamble"
            ]
        if (
            src_in_file
            or other
            or len(own) != 1
            or len(definitions) != 1
            or definitions[0].kind != "function"
            or definitions[0].name != own[0].name
            or definitions[0].inside_pp
            or preamble_changed
        ):
            if src_in_file:
                why = (
                    f"the source body already lives in {rel_dst}. Recording the "
                    "destination row on it (--shared) is the shared import, not "
                    "a copy. Copying would delete the file's other functions and "
                    "duplicate this body"
                )
            elif other:
                why = (
                    f"destination {rel_dst} already annotates VA "
                    f"0x{other[0].va:x} — remove/rename it or import to a "
                    "different file"
                )
            elif not own:
                why = (
                    f"destination {rel_dst} exists without a binding for this VA "
                    "— copying would overwrite a file this VA does not own"
                )
            else:
                why = (
                    f"destination {rel_dst} does not contain only the selected function definition"
                )
            return _import_result(
                dst_va,
                src_va,
                action="error",
                status="TARGET_CONFLICT",
                filepath=rel_dst,
                message=why,
            )

    if dry_run:
        return _import_result(
            dst_va,
            src_va,
            action="would-import",
            status="",
            filepath=rel_dst,
            message="",
        )

    if verify_entry_fn is None:
        raise ValueError("verify_entry_fn is required")
    if apply_status_updates_fn is None:
        raise ValueError("apply_status_updates_fn is required")

    # Verify against the destination binary through the shared flow, then
    # promote STATUS exactly like `rebrew verify` would.  A wrong match
    # compiles to bytes that don't compare → NEAR_MATCHING/STUB — the source
    # stays but is not promoted as matched.
    from rebrew.metadata.bindings import SourceBinding
    from rebrew.metadata.functions import update_field

    # The copy compiles where the source did, so it needs the source's flags
    # and, because the destination tree does not carry the source's headers,
    # the source's own directory on the include path: MSVC resolves
    # `#include "../../Units/Error/error.h"` against it.  Without this the copy
    # fails with C1083 and is recorded without the source's effective CFLAGS.
    # The absolute path is a known portability wart (breaks on clone/move) —
    # the shared path avoids it because the file itself moves with its headers.
    src_flags = source_flags(cfg_src, src_path, src_va)
    include = "-I" if cfg_dst.posix_style else "/I"
    cflags = f"{src_flags} {include}{src_path.parent}".strip()
    from rebrew.metadata.functions import identity_file, record_function_identity

    entry = SourceBinding(
        va=dst_va,
        name=copied_name,
        symbol=copied_symbol,
        size=dst_size,
        filepath=rel_dst,
        kind="FUNCTION",
        status="STUB",
        module=module,
        cflags=cflags,
    )
    encoded = rewritten.encode(dst_encoding)
    published = False
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        with coordinated_transaction(
            cfg_dst.metadata_dir, [dst_path], expected_inputs=expected, allow_unconfigured=True
        ) as staged:
            staged.publish(dst_path, encoded)
            published = True
            # Verify reads the new owner row and source together.
            record_function_identity(
                cfg_dst.metadata_dir,
                module=module,
                va=dst_va,
                file=identity_file(dst_path, cfg_dst.metadata_dir),
                kind="FUNCTION",
                name=copied_name,
                symbol=copied_symbol,
                size=dst_size,
            )
            update_field(
                cfg_dst.metadata_dir, dst_va, "cflags", cflags, module, updated_by="cross-import"
            )
            result, body = verify_import(
                entry,
                cfg_dst,
                cache=cache,
                name_to_va=name_to_va,
                verify_entry_fn=verify_entry_fn,
            )
            message = result.message
            if (
                require_resolved
                and result.matched
                and _unresolved_operands(result.relocation_bindings)
            ):
                raise _UnresolvedImport(
                    result.message, result.status, result.relocation_bindings or []
                )
            if result.matched:
                record_function_identity(
                    cfg_dst.metadata_dir,
                    module=module,
                    va=dst_va,
                    file=identity_file(dst_path, cfg_dst.metadata_dir),
                    kind="FUNCTION",
                    name=copied_name,
                    symbol=copied_symbol,
                    overwrite_name=True,
                )
            if body is not None:
                update_field(
                    cfg_dst.metadata_dir, dst_va, "size", body, module, updated_by="cross-import"
                )
                message = f"{message} {_merged_entry_note(body)}".strip()
            apply_status_updates_fn([(entry, result.status, result.delta)], cfg_dst)
    except _UnresolvedImport as refused:
        return _import_result(
            dst_va,
            src_va,
            action="skipped-unresolved",
            status=refused.status,
            filepath=rel_dst,
            message=_unresolved_message(str(refused), _unresolved_operands(refused.bindings)),
            relocation_bindings=refused.bindings,
        )
    except OSError as exc:
        if published:
            raise
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="WRITE_ERROR",
            filepath=rel_dst,
            message=str(exc),
        )

    action = "imported" if result.matched else "imported-unverified"
    return _import_result(
        dst_va,
        src_va,
        action=action,
        status=result.status,
        filepath=rel_dst,
        message=message,
        relocation_bindings=result.relocation_bindings,
    )


def symbol_for_va(
    text: str, module: str, va: int, fallback: str, *, syntax: Any = None
) -> tuple[str, str]:
    """The C definition attached to a target address, with native symbol decoration."""
    from rebrew.metadata.anchors import parse_address_anchors
    from rebrew.metadata.bindings import derive_c_symbol

    for anchor in parse_address_anchors(text, syntax=syntax):
        if preset_module_key(anchor.module) == preset_module_key(module) and anchor.va == va:
            return anchor.name, derive_c_symbol(anchor.name, anchor.prototype)
    return fallback, "_" + fallback


def source_flags(cfg_src: ProjectConfig, src_path: Path, src_va: int) -> str:
    """The source entry's effective flags: stored CFLAGS, else preset, else default.

    The copy must compile with the flags its source build used — a MSVCRT
    source built at ``/O1`` would not compare under the destination's ``/O2``.
    """
    from rebrew.compiler.overrides import resolve_cflags
    from rebrew.metadata.bindings import read_source_bindings

    try:
        anns = read_source_bindings(
            src_path,
            target_name=target_module(cfg_src),
            metadata_dir=cfg_src.metadata_dir,
            project_root=cfg_src.root,
        )
    except OSError:
        anns = []
    for ann in anns:
        if ann.va == src_va and preset_module_key(ann.module) == preset_module_key(
            target_module(cfg_src) or ""
        ):
            return resolve_cflags(cfg_src, ann.cflags, ann.module)
    return resolve_cflags(cfg_src, "", "")
