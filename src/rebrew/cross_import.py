"""cross_import.py — import matched functions from another target.

Finds functions shared between two targets in one project (the same code at
different VAs — binary versions, or a DLL+EXE pair sharing code) and imports
the already-matched source from one target into the other.

Direction: the target the command runs against is the DESTINATION; ``--from``
names the SOURCE target.  Matching is structural: the source target's matched
functions (EXACT/RELOC/PROVEN) and the destination's unmatched functions are
signature-compared from their **target bytes** via the ``rebrew.similar``
machinery (mnemonic histogram + call/branch agreement — no compilation
needed, so matching works even where the toolchain image is absent).  The
best source match above ``--min-score``, clearly ahead of the runner-up
(``--min-gap``), is imported: the .c marker is rewritten to the destination
VA/SIZE, the file is written into the destination's ``reversed_dir``, then
the function is compiled + verified against the destination binary and
STATUS is promoted through the standard verify flow — so a wrong match
simply fails verification and stays untouched (reported as skipped).

Functions that differ between the targets, or that have no counterpart,
are left untouched and reported.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.catalog import RegistryEntry
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.similar import DEFAULT_CS_ARCH, DEFAULT_CS_MODE, disasm_signature, similarity_score
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import atomic_write_text, read_source_text, rel_display_path
from rebrew.workspace.status import MATCHED_STATUSES

if TYPE_CHECKING:
    from rebrew.compile_cache import CacheBackend

console = Console(stderr=True)

#: STATUS values that count as "already matched" on the source side (and
#: exclude a destination function from consideration).


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
        ranked = sorted(
            ((similarity_score(d_sig, s_sig), s_va) for s_va, s_sig in src_sigs.items()),
            reverse=True,
        )
        if not ranked:
            continue
        best_score, best_src = ranked[0]
        second_score = ranked[1][0] if len(ranked) > 1 else -1.0
        if best_score >= min_score and (best_score - second_score) >= min_gap:
            out[d_va] = (best_src, best_score)
    return out


def _signature_for(cfg: ProjectConfig, code: bytes, va: int) -> dict[str, Any] | None:
    """Structural signature for *code*, honouring the config's arch/mode."""
    return disasm_signature(
        code,
        va,
        getattr(cfg, "capstone_arch", DEFAULT_CS_ARCH),
        getattr(cfg, "capstone_mode", DEFAULT_CS_MODE),
    )


# ---------------------------------------------------------------------------
# Target-facing data (statuses, target bytes)
# ---------------------------------------------------------------------------


def _annotations_by_va(cfg: ProjectConfig) -> dict[int, tuple[str, str]]:
    """``va -> (status, filepath)`` from the target's sources + metadata.

    Status comes from the metadata overlay (``rebrew-functions.toml`` via
    ``cfg.metadata_dir``); filepath is relative to ``cfg.reversed_dir``.
    """
    from rebrew.annotation import parse_c_file_multi

    out: dict[int, tuple[str, str]] = {}
    for path in iter_sources(cfg.reversed_dir, cfg):
        for ann in parse_c_file_multi(
            path,
            target_name=target_marker(cfg),
            base_dir=cfg.reversed_dir,
            metadata_dir=cfg.metadata_dir,
        ):
            out[ann.va] = (getattr(ann, "status", "") or "", getattr(ann, "filepath", "") or "")
    return out


def _registry(cfg: ProjectConfig) -> dict[int, RegistryEntry]:
    """The target's function catalog (VA -> entry with ``canonical_size``)."""
    from rebrew.catalog import build_function_registry, cached_function_list

    funcs = cached_function_list(cfg)
    return build_function_registry(
        funcs, cfg, inventory_path_for(cfg.reversed_dir, cfg), cfg.target_binary
    )


def _target_bytes_by_va(cfg: ProjectConfig, vas: dict[int, int]) -> dict[int, bytes]:
    """``va -> target-binary bytes`` for the given ``va -> size`` map.

    Raises ``OSError`` / ``ValueError`` when the binary itself is missing or
    unparseable; only a VA whose own extraction fails is skipped.
    """
    from rebrew.binary_loader import extract_raw_bytes, load_binary

    out: dict[int, bytes] = {}
    if vas:
        load_binary(cfg.target_binary)
    for va, size in vas.items():
        try:
            out[va] = extract_raw_bytes(cfg.target_binary, va, size)
        except ValueError:
            continue
    return out


def _disasm_sizes(cfg: ProjectConfig, vas: list[int]) -> tuple[dict[int, int], list[int]]:
    """Disassembly-derived sizes for sizeless registry entries.

    Returns ``(sizes, refused)``: VAs whose extent the disassembler derives
    cleanly (terminated by a real ``ret``, never by a branch-merge ``jmp``)
    and VAs it cannot size.  Sizes feed the structural match bytes; refusals
    surface the ``sizeless, use --va`` guidance instead of silently dropping
    the function from every match.
    """
    from rebrew.binary_loader import function_extent_from_disasm

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
    disassembly-sized matches and refusals (see :func:`_disasm_sizes`).

    Public so the CLI can attach the ``sizeless, use --va`` guidance rows
    for the refusals.
    """
    registry = _registry(cfg)
    sizeless = [va for va, reg in registry.items() if not int(reg.get("canonical_size") or 0)]
    return _disasm_sizes(cfg, sizeless)


def matched_source_bytes(cfg_src: ProjectConfig) -> dict[int, bytes]:
    """Source side: target bytes of the source target's matched functions.

    Only functions whose metadata STATUS is EXACT/RELOC/PROVEN participate —
    they are the ones whose source can be trusted to reproduce.  Entries with
    no registry size fall back to the disassembly-derived extent (ret-ended
    only); ones the disassembler cannot size are skipped with the
    ``sizeless, use --va`` guidance on the result rows.
    """
    statuses = _annotations_by_va(cfg_src)
    registry = _registry(cfg_src)
    vas = {
        va: int(reg["canonical_size"])
        for va, reg in registry.items()
        if reg.get("canonical_size") and statuses.get(va, ("", ""))[0] in MATCHED_STATUSES
    }
    sizeless = [
        va
        for va, reg in registry.items()
        if not int(reg.get("canonical_size") or 0)
        and statuses.get(va, ("", ""))[0] in MATCHED_STATUSES
    ]
    if sizeless:
        disasm_sizes, _refused = _disasm_sizes(cfg_src, sizeless)
        vas.update(disasm_sizes)
    return _target_bytes_by_va(cfg_src, vas)


def import_size(dst_size: int, src_code: bytes | None) -> int:
    """The size an imported marker claims.

    The destination's registry size is whatever the tree last recorded, and a
    skeleton from an earlier round can leave it stale.  Verifying only that
    prefix reports a false ``EXACT MATCH``: the import succeeds, and the next
    ``rebrew verify --full`` flags ``SIZE_MISMATCH`` (guild-rebrew round 1412 —
    GOLD 0x00449d80 claimed 23 bytes while the body is 25, carried over from
    the superseded stub).  Never claim less than the body the matcher matched;
    a destination that really is shorter then fails verification and the stack
    is rolled back, which is the honest outcome.
    """
    if src_code and len(src_code) > dst_size:
        return len(src_code)
    return dst_size


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
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import iter_library_headers

    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return set()
    modules = {str(m).upper() for m in (getattr(cfg, "external_libs", None) or ())}
    out: set[int] = set()
    for path in iter_library_headers(reversed_dir, cfg):
        for ann in parse_c_file_multi(path, metadata_dir=cfg.metadata_dir):
            kind = str(getattr(ann, "marker_type", "") or "").upper()
            module = str(getattr(ann, "module", "") or "").upper()
            if ann.va and (kind == "LIBRARY" or (module and module in modules)):
                out.add(int(ann.va))
    return out


def _in_external_range(va: int, ranges: list[tuple[int, int]]) -> bool:
    """True when *va* falls in a band the binary fills from a linked library."""
    return any(lo <= va <= hi for lo, hi in ranges)


def unmatched_dest_bytes(cfg_dst: ProjectConfig, only_va: int | None = None) -> dict[int, bytes]:
    """Destination side: target bytes of the destination's NOT-yet-matched
    functions (anything whose STATUS is not EXACT/RELOC/PROVEN).

    Library VAs (see :func:`_library_vas`) and VAs inside the target's
    ``external_ranges`` bands are excluded: they are linked, not reversed, and
    importing them would pollute the progress accounting.

    Entries with no registry size fall back to the disassembly-derived
    extent (ret-ended only); ones the disassembler cannot size stay out of
    the match and surface as ``sizeless, use --va`` rows from
    :func:`sizeless_dest_vas`."""
    statuses = _annotations_by_va(cfg_dst)
    registry = _registry(cfg_dst)
    library_vas = _library_vas(cfg_dst)
    bands = list(getattr(cfg_dst, "external_ranges", None) or [])
    vas = {
        va: int(reg["canonical_size"])
        for va, reg in registry.items()
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
        else:
            disasm_sizes, _refused = _disasm_sizes(cfg_dst, [only_va])
            vas = disasm_sizes
    else:
        _disasm_sizes_out, _ = sizeless_dest_vas(cfg_dst)
        for va, size in _disasm_sizes_out.items():
            if statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES:
                vas[va] = size
    return _target_bytes_by_va(cfg_dst, vas)


# ---------------------------------------------------------------------------
# Import mechanics
# ---------------------------------------------------------------------------

#: A ``// FUNCTION: MOD 0xVA`` or ``/* FUNCTION: MOD 0xVA */`` marker line.
#: ``\r?`` before the anchor: ``$`` matches at the end of a ``\r\n`` line only
#: after the ``\r``, which ``[ \t]*`` cannot consume, so a CRLF source matched
#: no marker at all ("no FUNCTION/LIBRARY/STUB marker found").
_MARKER_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<open>//|/\*)\s*(?P<type>FUNCTION|LIBRARY|STUB)\s*:\s+"
    r"(?P<module>[^\s]+)\s+(?P<va>0x[0-9a-fA-F]+)(?P<close>\s*\*/)?[ \t]*\r?$"
)

#: Any marker, including the data types ``_MARKER_RE`` does not rewrite.  The
#: module filter below must see them too: a `// DATA: SERVER 0x...` line left in
#: a copy is the same lint error (E012) as a foreign FUNCTION marker.
_ANY_MARKER_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<open>//|/\*)\s*"
    r"(?P<type>FUNCTION|LIBRARY|STUB|GLOBAL|DATA|VTABLE|STRING)\s*:\s+"
    r"(?P<module>[^\s]+)\s+(?P<va>0x[0-9a-fA-F]+)(?P<close>\s*\*/)?[ \t]*\r?$"
)

#: A ``// KEY: value`` (or ``/* KEY: value */``) line inside a marker block.
_KV_RE = re.compile(r"^[ \t]*(?://|/\*)[ \t]*[A-Za-z_][A-Za-z0-9_]*:[ \t]*")

#: A ``// SIZE: N`` or ``/* SIZE: N */`` key-value line inside the marker block.
#: The block form must be matched too: the annotation parser accepts it and is
#: last-wins, so inserting a second `// SIZE` before an existing `/* SIZE: */`
#: left the SOURCE's size in force for the destination.
_SIZE_KV_RE = re.compile(r"^[ \t]*(?://|/\*)[ \t]*SIZE:[ \t]*\S+(?:[ \t]*\*/)?")


def _extract_function_text(text: str, src_va: int) -> str | None:
    """Reduce a (possibly multi-function) source to preamble + the one block.

    Cross-import previously copied the WHOLE source file into the destination
    tree.  A multi-function SERVER file landed with every SERVER marker intact,
    so the GOLDTL tree inherited E012 lint (foreign module marker) and
    duplicated every co-resident function.  The imported copy must carry only
    the matched function and the shared preamble/headers it needs to compile,
    re-tagged for the destination.

    Returns the block text (marker + body, still in the SOURCE module) or
    ``None`` when *src_va* matches no marker block.
    """
    from rebrew.annotation import NEW_FUNC_CAPTURE_RE, split_annotation_sections

    preamble, blocks = split_annotation_sections(text)
    if not blocks:
        return None
    for block in blocks:
        for line in block.splitlines():
            m = NEW_FUNC_CAPTURE_RE.match(line.strip())
            if m and int(m.group("va"), 16) == src_va:
                return preamble + block
    return None


def _rewrite_marker(text: str, module: str, va: int, size: int) -> str:
    """Remap the first FUNCTION/LIBRARY/STUB marker to *module*/*va* and set SIZE.

    The imported source belongs to the DESTINATION target, so its marker must
    name the destination module + VA and carry the destination's canonical
    size — otherwise the destination's scanner would attribute the function
    to the wrong target/VA and verification would slice the wrong bytes.

    A shared multi-version source stacks one marker per target above a single
    implementation; the imported copy belongs to the destination only, so the
    other targets' stacked marker blocks (marker + their key-value lines,
    before any code) are dropped — they would otherwise carry stale VAs into
    the destination's reversed_dir.
    """
    lines = text.splitlines(keepends=True)

    # 1) Rewrite the FIRST marker to the destination.
    marker_idx = None
    eol = "\n"
    for idx, line in enumerate(lines):
        m = _MARKER_RE.match(line)
        if m:
            marker_idx = idx
            # Preserve the source's line ending: hardcoding "\n" left a CRLF
            # file with one LF-terminated marker line (mixed endings).
            eol = "\r\n" if line.endswith("\r\n") else "\n"
            close = " */" if m.group("open") == "/*" else ""
            lines[idx] = (
                f"{m.group('indent')}{m.group('open')} {m.group('type')}: "
                f"{module} 0x{va:x}{close}{eol}"
            )
            break
    if marker_idx is None:
        raise ValueError("no FUNCTION/LIBRARY/STUB marker found in source")

    # 2) Drop stacked leading marker blocks from other targets — only the
    #    consecutive markers + key-value lines BEFORE any code (the shared
    #    multi-version pattern).  A marker after code (a genuinely
    #    multi-function file) is kept only when it belongs to this target:
    #    another target's marker in the destination tree is a lint error
    #    (E012), and this import has no destination VA for that function.
    collapsed: list[str] = lines[: marker_idx + 1]
    i = marker_idx + 1
    seen_code = False
    while i < len(lines):
        m = _ANY_MARKER_RE.match(lines[i])
        is_marker = m is not None
        drop = False
        if m is not None:
            if not seen_code:
                drop = True  # stacked leading block for another version
            elif m.group("module") != module:
                drop = True  # a later item that belongs to another target
        if drop:
            i += 1
            while i < len(lines) and _KV_RE.match(lines[i]):
                i += 1
            continue
        if is_marker or not _KV_RE.match(lines[i]):
            seen_code = True  # code or a non-stacked marker ends the region
        collapsed.append(lines[i])
        i += 1

    # 3) SIZE on the (now single) destination block: scan only the marker's own
    #    key-value run (it ends at the first non-KV line), replace a SIZE line,
    #    else insert right after the marker.  A scan to EOF would clobber a
    #    LATER function's SIZE in a genuinely multi-function file.
    block_end = marker_idx + 1
    while block_end < len(collapsed) and _KV_RE.match(collapsed[block_end]):
        block_end += 1
    for j in range(marker_idx + 1, block_end):
        if _SIZE_KV_RE.match(collapsed[j]):
            # keepends left the old ending on the line; strip before appending
            # *eol* or the rewritten SIZE gets a blank line after it.
            collapsed[j] = _SIZE_KV_RE.sub(f"// SIZE: {size}", collapsed[j].rstrip("\r\n")) + eol
            break
    else:
        collapsed.insert(marker_idx + 1, f"// SIZE: {size}{eol}")
    return "".join(collapsed)


def _stack_marker(text: str, module: str, va: int, size: int) -> str:
    """Prepend a destination marker block above the existing marker.

    Shared-source import (``--shared``): the source file stays the single
    home for the function and gains one stacked ``// FUNCTION: <dst> <va>``
    block per target (ADR-010).  The existing blocks keep their own VAs;
    only the new block carries the destination VA/SIZE.  Returns the text
    unchanged when a block for *module*/*va* already exists (idempotent).
    """
    from rebrew.annotation import NEW_FUNC_CAPTURE_RE

    for line in text.splitlines():
        m = NEW_FUNC_CAPTURE_RE.match(line.strip())
        if m and m.group("module") == module and int(m.group("va"), 16) == va:
            return text
    eol = "\r\n" if "\r\n" in text else "\n"
    marker_idx = next(
        (i for i, line in enumerate(text.splitlines(keepends=True)) if _MARKER_RE.match(line)),
        None,
    )
    block = f"// FUNCTION: {module} 0x{va:x}{eol}// SIZE: {size}{eol}"
    if marker_idx is None:
        return block + text
    lines = text.splitlines(keepends=True)
    return "".join(lines[:marker_idx] + [block] + lines[marker_idx:])


def _block_marker(block: str) -> tuple[str, int] | None:
    """``(module, va)`` of a block's first marker line, or ``None``."""
    from rebrew.annotation import NEW_FUNC_CAPTURE_RE

    for line in block.splitlines():
        m = NEW_FUNC_CAPTURE_RE.match(line.strip())
        if m:
            return str(m.group("module")), int(m.group("va"), 16)
    return None


def stack_marker_on_block(
    text: str,
    module: str,
    va: int,
    size: int,
    src_module: str,
    src_va: int,
    drop: tuple[str, int] | None = None,
) -> str | None:
    """Stack the destination marker directly above the source function's block.

    The unified (``shared_dir``) layout puts every target's sources in ONE tree
    and often in ONE file: ``src/Develop/Units/vfs/vfs.c`` holds the GOLDTL
    block *and* the SERVER block for the same function.  Importing there is not
    a copy — the body is already in the file, so the destination marker must
    move onto it (ADR-010 one body, one marker per target).  ``_stack_marker``
    cannot do that: it prepends above the file's FIRST marker, so a source
    block in the middle of a multi-function file would leave the destination
    marker on an empty block, and a destination block that already claims *va*
    elsewhere must be dropped or the file has two claims (lint E013).

    Returns the new text, or ``None`` when no block for *src_module*/*src_va*
    exists (the caller falls back to the plain stack / reports the conflict).
    *drop* names an existing block to remove (the superseded destination
    claim).
    """
    from rebrew.annotation import split_annotation_sections

    preamble, blocks = split_annotation_sections(text)
    eol = "\r\n" if "\r\n" in text else "\n"
    marker = f"// FUNCTION: {module} 0x{va:x}{eol}// SIZE: {size}{eol}"
    out: list[str] = []
    inserted = False
    for block in blocks:
        owner = _block_marker(block)
        if drop is not None and owner == drop:
            continue  # superseded claim: the marker moves onto the source body
        if owner == (src_module, src_va) and not inserted:
            # Insert directly above the source MARKER line: a split block
            # carries the blank lines that preceded its marker (annotation
            # runs keep their leading blanks), and a marker separated from the
            # one below by a blank line leaves the destination claim an empty
            # block — the pattern every shared file in the tree avoids.
            lines = block.splitlines(keepends=True)
            cut = next(i for i, line in enumerate(lines) if _block_marker(line) is not None)
            out.append("".join(lines[:cut]))
            out.append(marker)
            out.append("".join(lines[cut:]))
            inserted = True
            continue
        out.append(block)
    if not inserted:
        return None
    return preamble + "".join(out)


def promote_to_shared(
    cfg_src: ProjectConfig,
    src_file: str,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Move a per-target source into ``src/shared`` preserving relative path.

    The shared tree only works when the file actually lives under the shared
    root — stacking a marker onto a file in the SOURCE target's own tree
    leaves it invisible to other targets' scans.  This moves
    ``<reversed_dir>/<src_file>`` to ``<shared_dir>/<src_file>`` (creating
    parent dirs), refusing when the shared dir is disabled, the source is
    missing, or the destination already exists.  Markers and metadata are
    untouched: the stacked blocks travel with the file, and the
    ``(module, va)`` metadata keys are path-independent.

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
    src_path = Path(cfg_src.reversed_dir) / src_file
    dst_path = Path(shared_root) / src_file
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
    return {
        "action": "promoted",
        "status": "",
        "filepath": src_file,
        "message": f"moved {src_path} to {dst_path}",
    }


def _import_result(
    dst_va: int, src_va: int, *, action: str, status: str, filepath: str, message: str
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
) -> dict[str, Any]:
    """Import by stacking a destination marker onto the SHARED source file.

    Unlike :func:`import_function` (which copies the source into the
    destination's ``reversed_dir``), this keeps one file: the stacked marker
    is prepended in place (in the shared dir when the source already lives
    there, else in the source target's own tree), then the function is
    compiled + verified against the destination binary through the standard
    verify flow.  The destination metadata records the source's flags plus
    the source directory for relative ``#include``s — the same rule the copy
    path uses.

    The import is verified before STATUS promotion exactly like the copy
    path: a mismatch reports ``imported-unverified``, never a false match.

    When *dst_file* names the destination's existing stub for *dst_va* (a
    different file than the shared target), a matched import deletes it —
    otherwise the old stub and the new stacked block claim the same VA and
    lint E013 fires.  Deletion happens only on a matched verify; an
    unverified import leaves the stub in place.
    """
    shared_root = getattr(cfg_src, "shared_dir", None)
    shared_path = Path(shared_root) / src_file if shared_root is not None else None
    if shared_path is not None and shared_path.is_file():
        target_path = shared_path
    else:
        target_path = Path(cfg_src.reversed_dir) / src_file
    try:
        text, encoding = read_source_text(target_path)
    except OSError as exc:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="READ_ERROR",
            filepath=src_file,
            message=str(exc),
        )
    module = target_marker(cfg_dst) or cfg_dst.target_name

    from rebrew.annotation import parse_c_file_multi

    existing = parse_c_file_multi(target_path, target_name=module)
    src_module = target_marker(cfg_src) or cfg_src.target_name
    superseded = any(e.va == dst_va for e in existing)
    # The destination's own claim can live in THIS file — the unified tree's
    # normal case, where the source body and the destination marker share one
    # file.  Move the marker onto the source body (dropping the old claim)
    # instead of the no-op idempotent stack, which would verify the stale body.
    moved: str | None = None
    if superseded:
        moved = stack_marker_on_block(
            text,
            module,
            dst_va,
            dst_size,
            src_module,
            src_va,
            drop=(module, dst_va),
        )
    if moved is not None:
        stacked = moved
    elif superseded:
        stacked = text  # idempotent: marker already on the source block
    else:
        stacked = _stack_marker(text, module, dst_va, dst_size)

    if dry_run:
        if moved is not None:
            note = f"would move the {module} marker onto the 0x{src_va:x} body (same file)"
        elif dst_file:
            note = f"would supersede {dst_file}"
        else:
            note = ""
        return _import_result(
            dst_va,
            src_va,
            action="would-import-shared",
            status="",
            filepath=rel_display_path(target_path, cfg_dst.reversed_dir),
            message=note,
        )

    try:
        atomic_write_text(target_path, stacked, encoding=encoding)
    except OSError as exc:
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="WRITE_ERROR",
            filepath=str(target_path),
            message=str(exc),
        )

    from rebrew.annotation import Annotation
    from rebrew.metadata import get_entry, remove_field, update_field
    from rebrew.verify import apply_status_updates, verify_entry

    src_flags = _source_flags(cfg_src, target_path)
    # No source-dir /I here (unlike the copy path): the shared file moves
    # WITH its tree under src/shared, so relative #include chains resolve
    # against its own directory already (compile.py always adds src_parent).
    # Recording an absolute ``/I<parent>`` would bake one machine's checkout
    # path into the metadata and break the file on promote or clone —
    # exactly the guild-rebrew GOLDTL.0x004c75e0 case.
    cflags = src_flags.strip()
    # Record flags only when they differ from what the destination would use
    # anyway: an inherited value written per function is lint W029 noise and
    # one more thing to keep in sync (guild-rebrew round 1293 imported 25
    # functions and 25 W029 rows appeared).
    inherited = str(getattr(cfg_dst, "cflags", "") or "").strip()
    prior_cflags = ""
    wrote_cflags = False
    if cflags and cflags != inherited:
        prior_cflags = str(get_entry(cfg_dst.metadata_dir, dst_va, module).get("cflags") or "")
        update_field(cfg_dst.metadata_dir, dst_va, "cflags", cflags, module)
        wrote_cflags = True

    # The verify filepath resolves against the destination's reversed_dir —
    # a shared file becomes ``../shared/f.c`` via the standard helper.
    rel_dst = rel_display_path(target_path, cfg_dst.reversed_dir)
    # The symbol verified is the one the SOURCE VA's block defines — not the
    # file's first definition, which is a different function in a
    # multi-function file whose marker moved onto a later block.
    name = _name_for_va(text, src_va) or _source_name(target_path)
    entry = Annotation(
        va=dst_va,
        name=name,
        symbol=name if name.startswith("_") else "_" + name,
        size=dst_size,
        filepath=rel_dst,
        marker_type="FUNCTION",
        status="STUB",
        module=module,
        cflags=cflags,
    )
    result = verify_entry(entry, cfg_dst, cache=cache)
    # The stack is withdrawn when it did not verify AND the destination
    # already claims this VA from its own file: a rolled-back claim must not
    # promote/demote STATUS either — the stub's earned status stands.
    # A marker whose body does not match the destination VA is a false claim:
    # withdraw every failed stack, not only the ones that collide with an
    # existing stub (guild-rebrew round 1294 — 12 unverified imports had left
    # markers asserting that a GOLD body is the GOLDTL function at that VA).
    revert = not result.matched and stacked != text
    if not revert:
        apply_status_updates([(entry, result.status, result.delta)], cfg_dst)

    action = "imported-shared" if result.matched else "imported-unverified"
    message = result.message
    if moved is not None and result.matched:
        message = (f"{message} (moved the {module} marker onto the 0x{src_va:x} body)").strip()
    if revert:
        # The stacked marker did not verify, and the destination already had
        # its own file for this VA.  Leaving both claims in place is a
        # duplicate VA (lint E013) for a function nobody has matched yet, so
        # roll the stack back — the stub stays the sole owner.  The rollback
        # covers the pre-verify metadata writes too: without restoring the
        # flags the destination had before this attempt, a withdrawn import
        # would keep compiling the stub under the SOURCE's cflags (a co-read
        # contract field) with the original value lost.
        atomic_write_text(target_path, text, encoding=encoding)
        if wrote_cflags:
            if prior_cflags:
                update_field(cfg_dst.metadata_dir, dst_va, "cflags", prior_cflags, module)
            else:
                remove_field(cfg_dst.metadata_dir, dst_va, "cflags", module)
        action = "skipped-unverified"
        message = (
            f"{message} (destination already annotates this VA; stack reverted)"
            if dst_file
            else f"{message} (stack reverted)"
        )
    if result.matched and dst_file:
        stub_path = Path(cfg_dst.reversed_dir) / dst_file
        if stub_path.resolve() != target_path.resolve() and stub_path.is_file():
            try:
                stub_path.unlink()
                message = f"{message} (superseded {dst_file})".strip()
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
) -> dict[str, Any]:
    """Import the matched source function *src_file* into the destination.

    Writes the .c (marker remapped to the destination VA/SIZE) to the
    destination's reversed_dir — *dst_file* if given (the destination VA's
    existing file), else at the source's own relative path — then compiles +
    verifies it against the destination binary and promotes STATUS via the
    standard verify flow (``verify_entry`` + ``apply_status_updates``).  The
    destination metadata records the flags the copy needs, which include the
    source's directory so its relative ``#include``s still resolve.

    With *dry_run* nothing is written or verified; the result carries the
    planned action.

    Returns a per-function result dict for the CLI/JSON report.
    """
    src_path = Path(cfg_src.reversed_dir) / src_file
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

    module = target_marker(cfg_dst) or cfg_dst.target_name
    # Emit only the matched function (preamble + its block), re-tagged to the
    # destination.  Copying the whole multi-function source would carry every
    # co-resident marker into the destination tree (lint E012) and duplicate
    # the other functions.
    extracted = _extract_function_text(text, src_va)
    if extracted is None:
        # The source annotation and the file disagree (the VA has no marker
        # block).  A whole-inventory run must not abort on one bad row.
        return _import_result(
            dst_va,
            src_va,
            action="error",
            status="NO_MARKER",
            filepath=src_file,
            message=f"source {src_file} has no FUNCTION marker for 0x{src_va:x}",
        )
    rewritten = _rewrite_marker(extracted, module, dst_va, dst_size)
    if dst_file is None:
        # Keep the source's path relative to its own reversed_dir: it gives
        # one destination file per source file (two imports out of one
        # multi-function source no longer collide on the bare name) and keeps
        # the directory depth the copy's relative #includes assume.
        dst_file = src_file if not Path(src_file).is_absolute() else src_path.name
    dst_path = Path(cfg_dst.reversed_dir) / dst_file
    rel_dst = str(Path(dst_file))

    # Refuse to clobber.  The copy path writes ONE extracted function over
    # whatever the destination path holds, so it is only safe when that file
    # holds exactly the destination's own single block and nothing else.  In
    # the unified tree (``shared_dir``) the destination path is usually the
    # SOURCE file itself, holding this function's SERVER block plus every
    # co-resident function: a whole-file write there deletes them all and
    # duplicates the body (C2084).  Those cases need ``--shared``, which moves
    # the marker onto the body already in the file.  Checked before the
    # dry-run return so the preview lists it.
    if dst_path.exists():
        from rebrew.annotation import parse_c_file_multi

        existing = parse_c_file_multi(dst_path, target_name=module)
        own = [e for e in existing if e.va == dst_va]
        other = [e for e in existing if e.va != dst_va]
        src_module = target_marker(cfg_src) or cfg_src.target_name
        src_in_file = any(
            e.va == src_va for e in parse_c_file_multi(dst_path, target_name=src_module)
        )
        if not own or other or src_in_file:
            if src_in_file:
                why = (
                    f"the source body already lives in {rel_dst} — stacking the "
                    "destination marker onto it (--shared) is a marker move, not "
                    "a copy; copying would delete the file's other functions and "
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
                    f"destination {rel_dst} exists without a marker for this VA "
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
    from rebrew.annotation import Annotation
    from rebrew.metadata import update_field
    from rebrew.verify import apply_status_updates, verify_entry

    # The copy compiles where the source did, so it needs the source's flags
    # and, because the destination tree does not carry the source's headers,
    # the source's own directory on the include path: MSVC resolves
    # `#include "../../Units/Error/error.h"` against it.  Without this the copy
    # fails with C1083 and keeps the source's inline `// CFLAGS:` line without
    # its metadata counterpart (lint W019).  The absolute path is a known
    # portability wart (breaks on clone/move) — the shared path avoids it
    # because the file itself moves with its headers.
    src_flags = _source_flags(cfg_src, src_path)
    include = "-I" if cfg_dst.posix_style else "/I"
    cflags = f"{src_flags} {include}{src_path.parent}".strip()
    update_field(cfg_dst.metadata_dir, dst_va, "cflags", cflags, module)

    entry = Annotation(
        va=dst_va,
        name=_source_name(src_path),
        symbol=_source_symbol(src_path),
        size=dst_size,
        filepath=rel_dst,
        marker_type="FUNCTION",
        status="STUB",
        module=module,
        cflags=cflags,
    )
    result = verify_entry(entry, cfg_dst, cache=cache)
    apply_status_updates([(entry, result.status, result.delta)], cfg_dst)

    action = "imported" if result.matched else "imported-unverified"
    return _import_result(
        dst_va,
        src_va,
        action=action,
        status=result.status,
        filepath=rel_dst,
        message=result.message,
    )


def _name_for_va(text: str, va: int) -> str | None:
    """C function name owned by the marker block for *va*.

    :func:`_source_name` reads the file's FIRST definition — correct for the
    copy path (the copy holds one function) and for a marker prepended above
    the first block, but wrong for a marker moved onto a LATER block of a
    multi-function file: verification then compiles the file, finds the first
    function and compares ITS bytes against this VA.  That is the "Size 33B vs
    235B" failure on ``ErrorModule.c``.  A marker-only block (the stacked
    pattern) borrows the name from the block below it.
    """
    from rebrew.annotation import split_annotation_sections
    from rebrew.c_parser import find_c_function_definitions

    _preamble, blocks = split_annotation_sections(text)
    for i, block in enumerate(blocks):
        owner = _block_marker(block)
        if owner is None or owner[1] != va:
            continue
        for candidate in blocks[i:]:
            definitions = find_c_function_definitions(candidate)
            if definitions:
                return definitions[0][0]
        return None
    return None


def _source_name(src_path: Path) -> str:
    """Best-effort C function name from the source file's text.

    The definition wins over the first parseable line: that line is usually a
    prototype or an ``extern`` declaration, and naming the import after one of
    those leaves verification looking for a symbol the object never defines
    (``EXTRACT_ERROR: Symbol '_rand' not found in .obj``).
    """
    try:
        text, _ = read_source_text(src_path)
    except OSError:
        return src_path.stem
    from rebrew.c_parser import extract_function_name_from_line, find_c_function_definitions

    definitions = find_c_function_definitions(text)
    if definitions:
        return definitions[0][0]
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("//", "/*", "*", "#")):
            got = extract_function_name_from_line(stripped)
            if got:
                return got[0]
    return src_path.stem


def _source_symbol(src_path: Path) -> str:
    name = _source_name(src_path)
    return "_" + name if not name.startswith("_") else name


def _source_flags(cfg_src: ProjectConfig, src_path: Path) -> str:
    """The source entry's effective flags: inline CFLAGS, else preset, else default.

    The copy must compile with the flags its source build used — a MSVCRT
    source built at ``/O1`` would not compare under the destination's ``/O2``.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.compile_overrides import resolve_cflags

    try:
        anns = parse_c_file_multi(
            src_path,
            target_name=target_marker(cfg_src),
            metadata_dir=cfg_src.metadata_dir,
        )
    except OSError:
        anns = []
    if anns:
        return resolve_cflags(cfg_src, anns[0].cflags, anns[0].module)
    return resolve_cflags(cfg_src, "", "")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Import matched functions from another target (same code, different VAs).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew cross-import --from v1.1 · · · · · · · Import v1.1's matched functions\n"
        "  rebrew cross-import --from game.exe --min-score 90\n"
        "  rebrew cross-import --from v1.1 --dry-run --json · Preview\n\n"
        "[dim]Matches the source target's EXACT/RELOC/PROVEN functions against this\n"
        "target's unmatched functions structurally (no compile needed to match);\n"
        "imported sources are verified against this target before STATUS promotion.[/dim]"
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
        help="Minimum similarity score (0-100) to import (default 95: identical "
        "code scores 100, structural siblings with a shared prologue score "
        "high 80s-low 90s)",
    ),
    min_gap: float = typer.Option(
        5.0, "--min-gap", help="Best match must beat the runner-up by at least this"
    ),
    va: str | None = typer.Option(
        None, "--va", help="Restrict to one destination VA (hex, e.g. 0x401000)"
    ),
    limit: int | None = typer.Option(None, "--limit", help="Import at most N functions"),
    shared: bool = typer.Option(
        False,
        "--shared",
        help="Stack the destination marker onto the shared source file "
        "instead of copying into the destination tree (one file, one marker "
        "per target). Promotes the source into src/shared first when needed",
    ),
    promote: bool = typer.Option(
        False,
        "--promote",
        help="Move the source file into src/shared (preserving relative path) "
        "without importing — the manual step before --shared",
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
    cfg = require_config(target=target, json_mode=json_output)
    cfg_src = require_config(target=from_target, json_mode=json_output)
    if cfg_src.target_name == cfg.target_name:
        error_exit("--from must name a different target", json_mode=json_output)

    only_va = parse_va(va, json_mode=json_output) if va else None

    try:
        dest_bytes = unmatched_dest_bytes(cfg, only_va)
        src_bytes = matched_source_bytes(cfg_src)
    except (OSError, ValueError) as exc:
        error_exit(f"cannot read target binary: {exc}", json_mode=json_output)
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
        if (sig := _signature_for(cfg, code, va)) is not None
    }
    src_sigs = {
        va: sig
        for va, code in src_bytes.items()
        if (sig := _signature_for(cfg_src, code, va)) is not None
    }
    matches = cross_match(dest_sigs, src_sigs, min_score=min_score, min_gap=min_gap)

    # Destination VA -> (status, filepath) for choosing the write target and
    # the destination canonical sizes for the rewritten marker.
    statuses = _annotations_by_va(cfg)
    registry = _registry(cfg)

    from rebrew.compile_cache import DEFAULT_CACHE_BACKEND, get_compile_cache

    cache = None
    if not dry_run:
        try:
            cache = get_compile_cache(
                cfg.root, getattr(cfg, "cache_backend", DEFAULT_CACHE_BACKEND)
            )
        except OSError:
            cache = None

    results: list[dict[str, Any]] = []
    matched_vas = set(matches)
    statuses_src = _annotations_by_va(cfg_src)
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
    # VAs stacks several markers onto that one body, which only works when the
    # destinations really are byte-identical copies.  When they are not, the
    # extra markers are guaranteed mismatches on a shared body (guild-rebrew
    # round 1293: one GOLD function was stacked at GOLDTL 0x659fbf and
    # 0x6508a3 with 9- and 11-byte spans).  Import the best-scoring match per
    # source file; further destination VAs need a deliberate twin.
    imported_src_files: dict[str, str] = {}
    for dst_va in sorted(dest_bytes):
        # Check the budget BEFORE importing: the old post-import guard ran with
        # the first import already appended, so ``--limit 0`` still imported one.
        if limit is not None and len([r for r in results if r["action"] != "skipped"]) >= limit:
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
        dst_size = int(registry[dst_va].get("canonical_size") or 0) if dst_va in registry else 0
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
            # root — auto-promote a per-target source there first so the
            # stacked marker lands on the one file every target scans.
            shared_root = getattr(cfg_src, "shared_dir", None)
            if shared_root is not None and not (Path(shared_root) / src_file).is_file():
                promo = promote_to_shared(cfg_src, src_file, dry_run=dry_run)
                if promo["action"] == "error":
                    promo.update(
                        {"dst_va": f"0x{dst_va:08x}", "src_va": f"0x{src_va:08x}", "score": score}
                    )
                    results.append(promo)
                    continue
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
            )
        )
        res["score"] = score
        # The question this command answers is "is this code already reversed
        # somewhere, and where?".  The destination path alone cannot answer it
        # in a unified tree (both are often the same file), so every row names
        # the SOURCE function, its file and its earned STATUS.
        res["src_file"] = src_file
        res["src_status"] = src_status
        res["dst_status"] = dst_status
        merge_sizeless_warning(res, disasm_size)
        if res["action"] not in ("skipped", "error"):
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

    skipped = sum(1 for r in results if r["action"] == "skipped")
    if candidates_only:
        # A "find what is already reversed elsewhere" run has four thousand
        # destination functions and a handful of findings: the per-function
        # "no match" rows are noise in both the table and the JSON.
        results = [r for r in results if r["action"] != "skipped"]

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

    table = Table(title=f"cross-import {from_target} → {cfg.target_name}", header_style="bold")
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
                "[dim]Copies drift — re-run with --shared to stack these onto "
                "one src/shared file instead.[/dim]"
            )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
