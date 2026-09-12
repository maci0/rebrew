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
from pathlib import Path
from typing import Any

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
from rebrew.config import ProjectConfig
from rebrew.metadata import MATCHED_STATUSES
from rebrew.similar import DEFAULT_CS_ARCH, DEFAULT_CS_MODE, disasm_signature, similarity_score
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import atomic_write_text, read_source_text

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
    from rebrew.catalog import build_function_registry, parse_function_list
    from rebrew.config import FUNCTION_STRUCTURE_JSON

    funcs = parse_function_list(cfg.function_list)
    return build_function_registry(
        funcs, cfg, cfg.reversed_dir / FUNCTION_STRUCTURE_JSON, cfg.target_binary
    )


def _target_bytes_by_va(cfg: ProjectConfig, vas: dict[int, int]) -> dict[int, bytes]:
    """``va -> target-binary bytes`` for the given ``va -> size`` map."""
    from rebrew.binary_loader import extract_raw_bytes

    out: dict[int, bytes] = {}
    for va, size in vas.items():
        try:
            out[va] = extract_raw_bytes(cfg.target_binary, va, size)
        except (OSError, ValueError):
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


def _sizeless_vas(cfg: ProjectConfig) -> tuple[dict[int, int], list[int]]:
    """Sizeless registry entries (``canonical_size`` 0/missing), split into
    disassembly-sized matches and refusals (see :func:`_disasm_sizes`)."""
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


def sizeless_dest_vas(cfg_dst: ProjectConfig) -> tuple[dict[int, int], list[int]]:
    """Destination-side sizeless entries: ``(disasm_sizes, refused)``.

    Public (no leading underscore) so the CLI can attach the ``sizeless,
    use --va`` guidance rows for the refusals.
    """
    return _sizeless_vas(cfg_dst)


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


def unmatched_dest_bytes(cfg_dst: ProjectConfig, only_va: int | None = None) -> dict[int, bytes]:
    """Destination side: target bytes of the destination's NOT-yet-matched
    functions (anything whose STATUS is not EXACT/RELOC/PROVEN).

    Entries with no registry size fall back to the disassembly-derived
    extent (ret-ended only); ones the disassembler cannot size stay out of
    the match and surface as ``sizeless, use --va`` rows from
    :func:`sizeless_dest_vas`."""
    statuses = _annotations_by_va(cfg_dst)
    registry = _registry(cfg_dst)
    vas = {
        va: int(reg["canonical_size"])
        for va, reg in registry.items()
        if reg.get("canonical_size") and statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES
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
        _disasm_sizes_out, _ = _sizeless_vas(cfg_dst)
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
            collapsed[j] = _SIZE_KV_RE.sub(f"// SIZE: {size}", collapsed[j]) + eol
            break
    else:
        collapsed.insert(marker_idx + 1, f"// SIZE: {size}{eol}")
    return "".join(collapsed)


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
    cache: Any = None,
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
        return {
            "dst_va": f"0x{dst_va:08x}",
            "src_va": f"0x{src_va:08x}",
            "score": None,
            "action": "error",
            "status": "READ_ERROR",
            "filepath": src_file,
            "message": str(exc),
        }

    module = target_marker(cfg_dst) or cfg_dst.target_name
    rewritten = _rewrite_marker(text, module, dst_va, dst_size)
    if dst_file is None:
        # Keep the source's path relative to its own reversed_dir: it gives
        # one destination file per source file (two imports out of one
        # multi-function source no longer collide on the bare name) and keeps
        # the directory depth the copy's relative #includes assume.
        dst_file = src_file if not Path(src_file).is_absolute() else src_path.name
    dst_path = Path(cfg_dst.reversed_dir) / dst_file
    rel_dst = str(Path(dst_file))

    # Refuse to clobber: the target file may already belong to a DIFFERENT
    # destination VA (a same-named source for another function).  The
    # destination's OWN annotation file (dst_file from the VA's filepath)
    # always matches dst_va and is overwritten as intended; a name collision
    # on a file with no annotation for this VA is reported, never silently
    # deleted.  Checked before the dry-run return so the preview lists it.
    if dst_path.exists():
        from rebrew.annotation import parse_c_file_multi

        existing = parse_c_file_multi(dst_path, target_name=module)
        # Any annotation on a DIFFERENT VA — not just the first one — makes
        # the destination file off-limits (sync-review F13).
        conflicting = next((e for e in existing if e.va != dst_va), None)
        if conflicting is not None:
            return {
                "dst_va": f"0x{dst_va:08x}",
                "src_va": f"0x{src_va:08x}",
                "score": None,
                "action": "error",
                "status": "TARGET_CONFLICT",
                "filepath": rel_dst,
                "message": (
                    f"destination {rel_dst} already annotates VA "
                    f"0x{conflicting.va:x} — remove/rename it or import "
                    "to a different file"
                ),
            }

    if dry_run:
        return {
            "dst_va": f"0x{dst_va:08x}",
            "src_va": f"0x{src_va:08x}",
            "score": None,
            "action": "would-import",
            "status": "",
            "filepath": rel_dst,
            "message": "",
        }

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
        return {
            "dst_va": f"0x{dst_va:08x}",
            "src_va": f"0x{src_va:08x}",
            "score": None,
            "action": "error",
            "status": "WRITE_ERROR",
            "filepath": rel_dst,
            "message": str(exc),
        }

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
    # its metadata counterpart (lint W019).
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
    return {
        "dst_va": f"0x{dst_va:08x}",
        "src_va": f"0x{src_va:08x}",
        "score": None,
        "action": action,
        "status": result.status,
        "filepath": rel_dst,
        "message": result.message,
    }


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
    from rebrew.cli import resolve_cflags

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
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Cross-target function import."""
    cfg = require_config(target=target, json_mode=json_output)
    cfg_src = require_config(target=from_target, json_mode=json_output)
    if cfg_src.target_name == cfg.target_name:
        error_exit("--from must name a different target", json_mode=json_output)

    only_va = parse_va(va, json_mode=json_output) if va else None

    dest_bytes = unmatched_dest_bytes(cfg, only_va)
    src_bytes = matched_source_bytes(cfg_src)
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

    from rebrew.compile_cache import get_compile_cache

    cache = None
    if not dry_run:
        try:
            cache = get_compile_cache(cfg.root, getattr(cfg, "cache_backend", "diskcache"))
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
        res = import_function(
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
        res["score"] = score
        merge_sizeless_warning(res, disasm_size)
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

    if json_output:
        json_print({"target": cfg.target_name, "from": from_target, "results": results})
        return

    table = Table(title=f"cross-import {from_target} → {cfg.target_name}", header_style="bold")
    for col in ("Dest VA", "Src VA", "Score", "Action", "Status", "File"):
        table.add_column(col)
    for r in results:
        table.add_row(
            r["dst_va"],
            r["src_va"] or "-",
            f"{r['score']:.1f}" if r["score"] is not None else "-",
            r["action"],
            r["status"] or "-",
            r["filepath"] or "-",
        )
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
