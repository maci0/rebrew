"""cross_import.py — import matched functions from another target.

Finds functions shared between two targets in one project (the same code at
different VAs — binary versions, or a DLL+EXE pair sharing code) and imports
the already-matched source from one target into the other.

Direction: the target the command runs against is the DESTINATION; ``--from``
names the SOURCE target.  Matching is structural: the source target's matched
functions (EXACT/RELOC) and the destination's unmatched functions are
signature-compared from their **target bytes** via the ``rebrew.similar``
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

import heapq
import shutil
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.table import Table

from rebrew.analysis import DEFAULT_CS_ARCH, DEFAULT_CS_MODE
from rebrew.catalog import RegistryEntry
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
    require_non_negative,
)
from rebrew.config import ProjectConfig, inventory_path_for, target_module
from rebrew.similar import disasm_signature, similarity_score
from rebrew.sources import contained_path, iter_sources, source_roots
from rebrew.utils import (
    atomic_write_text,
    preset_module_key,
    read_source_text,
    rel_display_path,
)
from rebrew.workspace.status import MATCHED_STATUSES

if TYPE_CHECKING:
    from rebrew.compiler.cache import CacheBackend
    from rebrew.compiler.compile import CompareResult
    from rebrew.metadata.bindings import SourceBinding


from rebrew.cli import console

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
    :func:`rebrew.similar.disasm_signature`).  For every destination
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
        # Only the top two scores are read, so select them instead of sorting
        # every source signature: same tie-break (descending ``(score, va)``),
        # O(S) instead of O(S log S) per destination.
        ranked = heapq.nlargest(
            2,
            ((similarity_score(d_sig, s_sig), s_va) for s_va, s_sig in src_sigs.items()),
        )
        if not ranked:
            continue
        best_score, best_src = ranked[0]
        second_score = ranked[1][0] if len(ranked) > 1 else -1.0
        if best_score >= min_score and (best_score - second_score) >= min_gap:
            out[d_va] = (best_src, best_score)
    return out


def signature_for(cfg: ProjectConfig, code: bytes, va: int) -> dict[str, Any] | None:
    """Structural signature excluding proven x86 alignment padding."""
    from rebrew.formats.binary_loader import PADDING_BYTES, function_extent_from_bytes, load_binary

    if code and code[-1] in PADDING_BYTES:
        try:
            info = load_binary(cfg.target_binary)
            if info.arch in ("x86_16", "x86_32", "x86_64"):
                got = function_extent_from_bytes(info, code, va, with_kind=True)
                if isinstance(got, tuple):
                    extent, kind = got
                    if (
                        kind == "ret"
                        and 0 < extent < len(code)
                        and all(b in PADDING_BYTES for b in code[extent:])
                    ):
                        code = code[:extent]
        except (OSError, ValueError):
            pass
    return disasm_signature(
        code,
        va,
        getattr(cfg, "capstone_arch", DEFAULT_CS_ARCH),
        getattr(cfg, "capstone_mode", DEFAULT_CS_MODE),
    )


# ---------------------------------------------------------------------------
# Target-facing data (statuses, target bytes)
# ---------------------------------------------------------------------------


def annotations_by_va(cfg: ProjectConfig) -> dict[int, tuple[str, str]]:
    """``va -> (status, filepath)`` from the target's sources + metadata.

    Status comes from the metadata overlay (``rebrew-functions.toml`` via
    ``cfg.metadata_dir``); filepath is relative to ``cfg.reversed_dir``.
    """
    from rebrew.metadata.bindings import read_source_bindings

    out: dict[int, tuple[str, str]] = {}
    for path in iter_sources(cfg.reversed_dir, cfg):
        for ann in read_source_bindings(
            path,
            target_name=target_module(cfg),
            base_dir=cfg.reversed_dir,
            metadata_dir=cfg.metadata_dir,
            project_root=getattr(cfg, "root", None),
        ):
            out[ann.va] = (getattr(ann, "status", "") or "", getattr(ann, "filepath", "") or "")
    return out


def registry(cfg: ProjectConfig) -> dict[int, RegistryEntry]:
    """The target's function catalog (VA -> entry with ``canonical_size``)."""
    from rebrew.catalog import build_function_registry, cached_function_list

    funcs = cached_function_list(cfg)
    return build_function_registry(
        funcs, cfg, inventory_path_for(cfg.reversed_dir, cfg), cfg.target_binary
    )


def target_bytes_by_va(cfg: ProjectConfig, vas: dict[int, int]) -> dict[int, bytes]:
    """``va -> target-binary bytes`` for the given ``va -> size`` map.

    Raises ``OSError`` / ``ValueError`` when the binary itself is missing or
    unparseable; only a VA whose own extraction fails is skipped.
    """
    from rebrew.formats.binary_loader import extract_raw_bytes, load_binary

    out: dict[int, bytes] = {}
    if vas:
        load_binary(cfg.target_binary)
    for va, size in vas.items():
        try:
            out[va] = extract_raw_bytes(cfg.target_binary, va, size)
        except ValueError:
            continue
    return out


def disasm_sizes(cfg: ProjectConfig, vas: list[int]) -> tuple[dict[int, int], list[int]]:
    """Disassembly-derived sizes for sizeless registry entries.

    Returns ``(sizes, refused)``: VAs whose extent the disassembler derives
    cleanly (terminated by a real ``ret``, never by a branch-merge ``jmp``)
    and VAs it cannot size.  Sizes feed the structural match bytes; refusals
    surface the ``sizeless, use --va`` guidance instead of silently dropping
    the function from every match.
    """
    from rebrew.formats.binary_loader import function_extent_from_disasm

    sizes: dict[int, int] = {}
    refused: list[int] = []
    for va in vas:
        try:
            got = function_extent_from_disasm(cfg.target_binary, va, with_kind=True)
        except (OSError, ValueError):
            got = None
        if got is None:
            refused.append(va)
            continue
        extent, kind = got
        if kind != "ret" or extent <= 0:
            refused.append(va)
            continue
        sizes[va] = extent
    return sizes, refused


def sizeless_dest_vas(cfg: ProjectConfig) -> tuple[dict[int, int], list[int]]:
    """Sizeless registry entries (``canonical_size`` 0/missing), split into
    disassembly-sized matches and refusals (see :func:`disasm_sizes`).

    Public so the CLI can attach the ``sizeless, use --va`` guidance rows
    for the refusals.
    """
    entries = registry(cfg)
    sizeless = [va for va, reg in entries.items() if not int(reg.get("canonical_size") or 0)]
    return disasm_sizes(cfg, sizeless)


def matched_source_bytes(cfg_src: ProjectConfig) -> dict[int, bytes]:
    """Source side: target bytes of the source target's matched functions.

    Only functions whose metadata STATUS is EXACT/RELOC participate (PROVEN
    bytes differ, so a PROVEN body is not a byte-exact donor) —
    they are the ones whose source can be trusted to reproduce. Managed
    source extents override discovery spans that may include trailing padding.
    Entries with no source or registry size fall back to the disassembly-derived extent (ret-ended
    only); ones the disassembler cannot size are skipped with the
    ``sizeless, use --va`` guidance on the result rows.
    """
    from rebrew.metadata.functions import load_metadata

    statuses = annotations_by_va(cfg_src)
    entries = registry(cfg_src)
    metadata_dir = getattr(cfg_src, "metadata_dir", None)
    metadata = load_metadata(metadata_dir) if metadata_dir is not None else {}
    module = (target_module(cfg_src) or "") if metadata else ""
    sizes = {
        va: int(metadata.get((module, va), {}).get("size") or reg.get("canonical_size") or 0)
        for va, reg in entries.items()
    }
    vas = {
        va: sizes[va]
        for va, reg in entries.items()
        if sizes[va] > 0 and statuses.get(va, ("", ""))[0] in MATCHED_STATUSES
    }
    sizeless = [
        va for va in entries if sizes[va] <= 0 and statuses.get(va, ("", ""))[0] in MATCHED_STATUSES
    ]
    if sizeless:
        sizes, _refused = disasm_sizes(cfg_src, sizeless)
        vas.update(sizes)
    return target_bytes_by_va(cfg_src, vas)


def import_size(dst_size: int, src_code: bytes | None) -> int:
    """The size an imported binding claims.

    The destination's registry size is whatever the tree last recorded, and a
    skeleton from an earlier round can leave it stale.  Verifying only that
    prefix reports a false ``EXACT MATCH``: the import succeeds, and the next
    ``rebrew verify --no-cache`` flags ``SIZE_MISMATCH`` (guild-rebrew round 1412 —
    GOLD 0x00449d80 claimed 23 bytes while the body is 25, carried over from
    the superseded stub).  Never claim less than the body the matcher matched;
    a destination that really is shorter then fails verification and the stack
    is rolled back, which is the honest outcome.
    """
    if src_code and len(src_code) > dst_size:
        return len(src_code)
    return dst_size


#: Function starts in the destination are aligned to this many bytes; the gap
#: before the next start is linker padding.
_FUNCTION_ALIGNMENT = 16


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


def _verify_import(
    entry: SourceBinding,
    cfg_dst: ProjectConfig,
    *,
    cache: CacheBackend | None,
    name_to_va: dict[str, int] | None,
) -> tuple[CompareResult, int | None]:
    """Verify *entry*, re-verifying at the body size on a merged inventory entry.

    Returns the result and the body size when the entry's own size was
    replaced by :func:`_merged_entry_body_size` (``None`` otherwise).  A
    re-verify that does not match keeps the original result.
    """
    from rebrew.verify import verify_entry

    result = verify_entry(entry, cfg_dst, cache=cache, name_to_va=name_to_va)
    body = _merged_entry_body_size(cfg_dst, entry.va, entry.size, result)
    if body is None:
        return result, None
    body_entry = replace(entry, size=body)
    retry = verify_entry(body_entry, cfg_dst, cache=cache, name_to_va=name_to_va)
    if not retry.matched:
        return result, None
    entry.size = body
    entry.comparison_inputs = body_entry.comparison_inputs
    return retry, body


def _merged_entry_note(body: int) -> str:
    """Result message suffix for an import sized by :func:`_merged_entry_body_size`."""
    return f"(destination inventory entry merges functions: sized to the {body}-byte body)"


def sizeless_warning(size: int) -> str:
    """Warning attached to a match sized by disassembly, not the registry."""
    return (
        "warning: no registry size — matched on the disassembly-derived "
        f"extent ({size}B); pass --va to confirm"
    )


def merge_sizeless_warning(res: dict[str, Any], size: int | None) -> dict[str, Any]:
    """Attach :func:`sizeless_warning` to *res* when it reports no message.

    A verification message of its own (a real mismatch explanation) wins;
    the sizing caveat only fills the gap.
    """
    if size is not None and not res.get("message"):
        res["message"] = sizeless_warning(size)
    return res


def _library_vas(cfg: ProjectConfig) -> set[int]:
    """VAs the destination binary gets from a linked library, not game source.

    ``// LIBRARY:`` rows in the target's ``library_*.h`` headers, plus rows
    whose module is named in ``targets.<name>.external_libs`` (D3DX8, LIBCMT,
    MSS32, …).  Cross-import must never create a game-source annotation for one:
    the code is linker-supplied, byte-identical across the clients by
    construction, and importing it turns a library band into dozens of
    unmatchable "game" functions — guild-rebrew round 1293 matched ~50 D3DX8
    bodies in GOLDTL's ``0x5e0000-0x64ffff`` band against GOLD's copies before
    this filter existed.
    """
    from rebrew.metadata.bindings import library_inventory_bindings, read_source_bindings
    from rebrew.sources import iter_library_headers

    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return set()
    modules = {preset_module_key(str(m)) for m in (getattr(cfg, "external_libs", None) or ())}
    out: set[int] = set()
    for path in iter_library_headers(reversed_dir, cfg):
        for ann in read_source_bindings(
            path, metadata_dir=cfg.metadata_dir, project_root=getattr(cfg, "root", None)
        ):
            kind = str(getattr(ann, "kind", "") or "").upper()
            module = preset_module_key(str(getattr(ann, "module", "") or ""))
            if ann.va and (kind == "LIBRARY" or (module and module in modules)):
                out.add(int(ann.va))
    for ann in library_inventory_bindings(cfg.metadata_dir, reversed_dir):
        if ann.va:
            out.add(int(ann.va))
    return out


def _in_external_range(va: int, ranges: list[tuple[int, int]]) -> bool:
    """True when *va* falls in a band the binary fills from a linked library."""
    return any(lo <= va <= hi for lo, hi in ranges)


def unmatched_dest_bytes(cfg_dst: ProjectConfig, only_va: int | None = None) -> dict[int, bytes]:
    """Destination side: target bytes of the destination's NOT-yet-matched
    functions (anything whose STATUS is not EXACT/RELOC, PROVEN included).

    Library VAs (see :func:`_library_vas`) and VAs inside the target's
    ``external_ranges`` bands are excluded: they are linked, not reversed, and
    importing them would pollute the progress accounting.

    Entries with no registry size fall back to the disassembly-derived
    extent (ret-ended only); ones the disassembler cannot size stay out of
    the match and surface as ``sizeless, use --va`` rows from
    :func:`sizeless_dest_vas`."""
    statuses = annotations_by_va(cfg_dst)
    entries = registry(cfg_dst)
    library_vas = _library_vas(cfg_dst)
    bands = list(getattr(cfg_dst, "external_ranges", None) or [])
    vas = {
        va: int(reg["canonical_size"])
        for va, reg in entries.items()
        if reg.get("canonical_size")
        and statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES
        and va not in library_vas
        and not _in_external_range(va, bands)
    }
    if only_va is not None:
        if only_va in vas:
            vas = {only_va: vas[only_va]}
        elif statuses.get(only_va, ("", ""))[0] in MATCHED_STATUSES:
            # ``--va`` must not bypass the matched-STATUS filter: an already
            # EXACT/RELOC function whose registry entry was filtered out above
            # would otherwise be re-imported and possibly demoted.
            vas = {}
        elif only_va in library_vas or _in_external_range(only_va, bands):
            vas = {}
        else:
            sizes, _refused = disasm_sizes(cfg_dst, [only_va])
            vas = sizes
    else:
        _disasm_sizes_out, _ = sizeless_dest_vas(cfg_dst)
        for va, size in _disasm_sizes_out.items():
            if statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES:
                vas[va] = size
    return target_bytes_by_va(cfg_dst, vas)


# ---------------------------------------------------------------------------
# Import mechanics
# ---------------------------------------------------------------------------


def _extract_function_text(text: str, name: str) -> str | None:
    """Copy one C definition, its shared declarations and static dependencies."""
    from rebrew.split import shared_preamble, source_layout, span_extent

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
    preamble = shared_preamble(raw, spans, extents)
    return preamble + "\n".join(
        raw[start:end].decode("utf-8", errors="surrogateescape") for start, end in extents
    )


def _rewrite_address(text: str, module: str, va: int, *, name: str) -> str:
    """A copied definition receives only the destination address."""
    from rebrew.metadata.anchors import add_address_anchor, parse_address_anchors

    anchors = parse_address_anchors(text)
    removed = {a.line for a in anchors if a.kind == "FUNCTION" and a.name == name}
    body = "".join(
        line for i, line in enumerate(text.splitlines(keepends=True), 1) if i not in removed
    )
    return add_address_anchor(body, module, va, name)


def _strip_claim(block: str, claim: tuple[str, int]) -> str:
    """Remove one superseded address while preserving the declaration and other targets."""
    from rebrew.metadata.anchors import parse_address_anchors

    removed = {
        a.line
        for a in parse_address_anchors(block)
        if preset_module_key(a.module) == preset_module_key(claim[0]) and a.va == claim[1]
    }
    return "".join(
        ("\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else "")
        if i in removed
        else line
        for i, line in enumerate(block.splitlines(keepends=True), 1)
    )


def _retire_shared_stub(cfg: ProjectConfig, path: Path, claim: tuple[str, int]) -> bool:
    """Delete only an unowned single-body stub; return whether it was retired."""
    from rebrew.c_parser import find_c_function_definitions, find_variable_roles
    from rebrew.metadata.anchors import parse_address_anchors
    from rebrew.metadata.data import load_data_metadata
    from rebrew.metadata.functions import identity_file, load_metadata, stored_file_matches
    from rebrew.utils import SOURCE_BACKUP_DIRNAME, source_backup

    text, encoding = read_source_text(path)
    rel = identity_file(path, cfg.metadata_dir)
    owners = [
        *load_metadata(cfg.metadata_dir).values(),
        *load_data_metadata(cfg.metadata_dir).values(),
    ]
    kept = _strip_claim(text, claim)
    indexes = parse_address_anchors(kept)
    definitions, _declarations, _uses = find_variable_roles(text)
    remaining = any(stored_file_matches(str(row.get("file") or ""), rel) for row in owners)
    if remaining or indexes or definitions or len(find_c_function_definitions(text)) != 1:
        if kept != text:
            with source_backup(
                path,
                text,
                encoding,
                Path(cfg.root) / SOURCE_BACKUP_DIRNAME,
                label="shared-import",
                keep=True,
            ):
                atomic_write_text(path, kept, encoding=encoding)
        return False
    path.unlink()
    return True


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
    exists. ``(module, va)`` keys stay put. Rows whose ``file`` named the old
    path are retargeted at the shared path, in both metadata stores.

    Returns a result dict with ``action`` ``promoted`` / ``would-promote`` /
    ``error`` and the shared-relative ``filepath``.
    """
    shared_root = getattr(cfg_src, "shared_dir", None)
    if shared_root is None:
        return {
            "action": "error",
            "status": "NO_SHARED_DIR",
            "filepath": src_file,
            "message": "shared_dir is disabled — set project.shared_dir first",
        }
    src_path = contained_path(source_roots(cfg_src), src_file)
    dst_path = contained_path(shared_root, src_file)
    if src_path is None or dst_path is None:
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
    if dst_path.exists():
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
    _retarget_moved_identity(cfg_src, src_path, dst_path)
    return {
        "action": "promoted",
        "status": "",
        "filepath": src_file,
        "message": f"moved {src_path} to {dst_path}",
    }


def _retarget_moved_identity(cfg: Any, old_path: Path, new_path: Path) -> None:
    """Point function and data rows from *old_path* at *new_path*.

    Identity is the row's ``file``, not a binding that travels with the bytes.
    A path the store refuses (absolute, or a ``..`` segment) is left as it
    was: the move already landed, and a failed rewrite must not report the
    promote as a write error.
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
        for (module, va), entry in load_metadata(meta).items()
        if _matches(entry)
    ]
    if rows:
        record_function_rows(meta, rows)
    data_rows = [
        {"module": module, "va": va, "identity": {"file": new_rel}}
        for (module, va), entry in load_data_metadata(meta).items()
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
    """Per-function import result row for the CLI/JSON report."""
    return {
        "dst_va": f"0x{dst_va:08x}",
        "src_va": f"0x{src_va:08x}",
        "score": None,
        "action": action,
        "status": status,
        "filepath": filepath,
        "message": message,
        **({"relocation_bindings": relocation_bindings} if relocation_bindings is not None else {}),
    }


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
    _preamble, blocks = split_address_sections(text)
    already_on_source = False
    dst_elsewhere = False
    has_src = False
    for block in blocks:
        from rebrew.metadata.anchors import parse_address_anchors

        claims = [(a.module, a.va) for a in parse_address_anchors(block)]
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
    name, symbol = _symbol_for_va(text, src_module, src_va, target_path.stem)
    if name == target_path.stem:
        for ann in read_source_bindings(
            target_path, target_name=src_module, metadata_dir=getattr(cfg_src, "metadata_dir", None)
        ):
            if ann.va == src_va and ann.name and ann.kind in FUNCTION_KINDS:
                name, symbol = ann.name, ann.symbol or ("_" + ann.name)
                break
    prior = get_entry(cfg_dst.metadata_dir, dst_va, module)
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

    from rebrew.metadata.bindings import SourceBinding
    from rebrew.metadata.functions import remove_field, update_field
    from rebrew.verify import apply_status_updates

    src_flags = _source_flags(cfg_src, target_path, src_va)
    # No source-dir /I here (unlike the copy path): the shared file moves
    # WITH its tree under src/shared, so relative #include chains resolve
    # against its own directory already (compiler/compile.py always adds src_parent).
    # Recording an absolute ``/I<parent>`` would bake one machine's checkout
    # path into the metadata and break the file on promote or clone —
    # exactly the guild-rebrew GOLDTL.0x004c75e0 case.
    cflags = src_flags.strip()
    # Record flags only when they differ from what the destination would use
    # anyway: an inherited value written per function is lint W029 noise and
    # one more thing to keep in sync (guild-rebrew round 1293 imported 25
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
    candidate = _strip_claim(text, (module, dst_va)) if needs_move else text
    from rebrew.utils import SOURCE_BACKUP_DIRNAME, source_backup

    with source_backup(
        target_path,
        text,
        _encoding,
        Path(cfg_dst.root) / SOURCE_BACKUP_DIRNAME,
        label="shared-import",
        keep=candidate != text,
    ):
        try:
            if candidate != text:
                atomic_write_text(target_path, candidate, encoding=_encoding)
            result, body = _verify_import(entry, cfg_dst, cache=cache, name_to_va=name_to_va)
        except BaseException:
            if candidate != text:
                atomic_write_text(target_path, text, encoding=_encoding)
            raise
        if not result.matched and candidate != text:
            atomic_write_text(target_path, text, encoding=_encoding)
    # A failed new claim, and a failed move of an existing claim onto a
    # different body, must not promote STATUS. An existing claim that is
    # already on the source body still records the verify result.
    reject = (not result.matched) and (new_claim or needs_move)
    action = "imported-shared" if result.matched else "imported-unverified"
    message = result.message
    if body is not None and not reject:
        update_field(cfg_dst.metadata_dir, dst_va, "size", body, module, updated_by="cross-import")
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
        if cflags and cflags != inherited:
            update_field(
                cfg_dst.metadata_dir, dst_va, "cflags", cflags, module, updated_by="cross-import"
            )
        else:
            remove_field(cfg_dst.metadata_dir, dst_va, "cflags", module)
        apply_status_updates([(entry, result.status, result.delta)], cfg_dst)
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
    extracted = _extract_function_text(text, donor.name) if donor is not None else None
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
    rewritten = _rewrite_address(extracted, module, dst_va, name=copied_name)
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

    # Refuse to clobber.  The copy path writes ONE extracted function over
    # whatever the destination path holds, so it is only safe when that file
    # holds exactly the destination's own single block and nothing else.  In
    # the unified tree (``shared_dir``) the destination path is usually the
    # SOURCE file itself, holding this function's SERVER block plus every
    # co-resident function: a whole-file write there deletes them all and
    # duplicates the body (C2084).  Those cases need ``--shared``, which moves
    # the binding onto the body already in the file.  Checked before the
    # dry-run return so the preview lists it.
    if dst_path.exists():
        from rebrew.metadata.bindings import read_source_bindings

        existing = read_source_bindings(
            dst_path,
            target_name=module,
            metadata_dir=cfg_dst.metadata_dir,
            project_root=cfg_dst.root,
        )
        own = [e for e in existing if e.va == dst_va]
        other = [e for e in existing if e.va != dst_va]
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
        if not own or other or src_in_file:
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
            else:
                why = (
                    f"destination {rel_dst} exists without a binding for this VA "
                    "— copying would overwrite a file this VA does not own"
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

    # Write with the destination file's own encoding when it exists, else the
    # source's detected encoding.  The old hardcoded-UTF-8, non-atomic write
    # could not round-trip a legacy-encoded source and a crash mid-write left a
    # truncated .c.
    if dst_path.exists():
        try:
            _, dst_encoding = read_source_text(dst_path)
        except OSError:
            dst_encoding = src_encoding
    else:
        dst_encoding = src_encoding
    try:
        atomic_write_text(dst_path, rewritten, encoding=dst_encoding)
    except OSError as exc:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="WRITE_ERROR",
            filepath=rel_dst,
            message=str(exc),
        )

    # Verify against the destination binary through the shared flow, then
    # promote STATUS exactly like `rebrew verify` would.  A wrong match
    # compiles to bytes that don't compare → NEAR_MATCHING/STUB — the source
    # stays but is not promoted as matched.
    from rebrew.metadata.bindings import SourceBinding
    from rebrew.metadata.functions import update_field
    from rebrew.verify import apply_status_updates

    # The copy compiles where the source did, so it needs the source's flags
    # and, because the destination tree does not carry the source's headers,
    # the source's own directory on the include path: MSVC resolves
    # `#include "../../Units/Error/error.h"` against it.  Without this the copy
    # fails with C1083 and keeps the source's inline `// CFLAGS:` line without
    # its metadata counterpart (lint W019).  The absolute path is a known
    # portability wart (breaks on clone/move) — the shared path avoids it
    # because the file itself moves with its headers.
    src_flags = _source_flags(cfg_src, src_path, src_va)
    include = "-I" if cfg_dst.posix_style else "/I"
    cflags = f"{src_flags} {include}{src_path.parent}".strip()
    from rebrew.metadata.functions import identity_file, record_function_identity

    # The row has to exist before verify: a binding-less file is invisible
    # until rebrew-functions.toml names it.
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
    update_field(cfg_dst.metadata_dir, dst_va, "cflags", cflags, module, updated_by="cross-import")

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
    result, body = _verify_import(entry, cfg_dst, cache=cache, name_to_va=name_to_va)
    message = result.message
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
        update_field(cfg_dst.metadata_dir, dst_va, "size", body, module, updated_by="cross-import")
        message = f"{message} {_merged_entry_note(body)}".strip()
    apply_status_updates([(entry, result.status, result.delta)], cfg_dst)

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


def _symbol_for_va(text: str, module: str, va: int, fallback: str) -> tuple[str, str]:
    """The C definition attached to a target address, with native symbol decoration."""
    from rebrew.metadata.anchors import parse_address_anchors
    from rebrew.metadata.bindings import derive_c_symbol

    for anchor in parse_address_anchors(text):
        if preset_module_key(anchor.module) == preset_module_key(module) and anchor.va == va:
            return anchor.name, derive_c_symbol(anchor.name, anchor.prototype)
    return fallback, "_" + fallback


def _source_flags(cfg_src: ProjectConfig, src_path: Path, src_va: int) -> str:
    """The source entry's effective flags: inline CFLAGS, else preset, else default.

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
        "  rebrew source import-related --from v1.1 --dry-run --json  # Preview\n\n"
        "[dim]Matches the source target's EXACT/RELOC functions against this target's unmatched functions structurally (no compile needed to match); imported sources are verified against this target before STATUS promotion.[/dim]"
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
    va: str | None = typer.Option(
        None, "--va", help="Restrict to one destination VA (hex, e.g. 0x401000)"
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

    only_va = parse_va(va, json_mode=json_output) if va else None
    only_source_va = parse_va(source_va, json_mode=json_output) if source_va else None

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
        from rebrew.coff_reloc import CatalogScanError, build_name_to_va

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
    # extra rows are guaranteed mismatches on a shared body (guild-rebrew
    # round 1293: one GOLD function was recorded at GOLDTL 0x659fbf and
    # 0x6508a3 with 9- and 11-byte spans).  Import the best-scoring match per
    # source file; further destination VAs need a deliberate twin.
    imported_src_files: dict[str, str] = {}
    for dst_va in sorted(dest_bytes):
        # Check the budget BEFORE importing: the old post-import guard ran with
        # the first import already appended, so ``--limit 0`` still imported one.
        if (
            limit is not None
            and len([r for r in results if not r["action"].startswith("skipped")]) >= limit
        ):
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
        if shared:
            # The shared tree only works when the file lives under the shared
            # root. Auto-promote a per-target source there first so the
            # recorded row names the one file every target scans.
            shared_root = getattr(cfg_src, "shared_dir", None)
            shared_candidate = (
                contained_path(shared_root, src_file) if shared_root is not None else None
            )
            if shared_root is not None and not (
                shared_candidate is not None and shared_candidate.is_file()
            ):
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
        payload: dict[str, Any] = {
            "target": cfg.target_name,
            "from": from_target,
            "results": results,
        }
        if candidates_only:
            payload["skipped_count"] = skipped
        json_print(payload)
        return

    table = Table(
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
