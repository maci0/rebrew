"""Structural matching, signature extraction, and byte-level preview helpers."""

from __future__ import annotations

from typing import Any
lazy import hashlib
lazy import heapq
lazy import logging
lazy from collections.abc import Callable

lazy from rebrew.binary.analysis import DEFAULT_CS_ARCH, DEFAULT_CS_MODE
lazy from rebrew.catalog import RegistryEntry
lazy from rebrew.config import ProjectConfig, inventory_path_for, target_module
lazy from rebrew.source.discovery import iter_sources
lazy from rebrew.utils import preset_module_key
lazy from rebrew.workspace.status import MATCHED_STATUSES

_log = logging.getLogger(__name__)

__all__ = [
    "annotations_by_va",
    "cross_match",
    "disasm_sizes",
    "import_size",
    "interior_preview_rows",
    "library_vas",
    "matched_source_bytes",
    "merge_sizeless_warning",
    "registry",
    "same_va_preview_rows",
    "signature_for",
    "sizeless_dest_vas",
    "sizeless_warning",
    "target_bytes_by_va",
    "unmatched_dest_bytes",
]

# ---------------------------------------------------------------------------
# Pure matching core (testable with hand-crafted signatures)
# ---------------------------------------------------------------------------


def cross_match(
    dest_sigs: dict[int, dict[str, Any]],
    src_sigs: dict[int, dict[str, Any]],
    min_score: float = 95.0,
    min_gap: float = 5.0,
    *,
    similarity_score_fn: Callable[[dict[str, Any], dict[str, Any]], float] | None = None,
) -> dict[int, tuple[int, float]]:
    """Map each destination function to its best source-target counterpart.

    *dest_sigs* / *src_sigs* map VA -> structural signature (see
    :func:`rebrew.compare.similar.disasm_signature`).  For every destination
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
    if similarity_score_fn is None:
        raise ValueError("similarity_score_fn is required")
    out: dict[int, tuple[int, float]] = {}
    for d_va, d_sig in dest_sigs.items():
        # Only the top two scores are read, so select them instead of sorting
        # every source signature: same tie-break (descending ``(score, va)``),
        # O(S) instead of O(S log S) per destination.
        ranked = heapq.nlargest(
            2,
            ((similarity_score_fn(d_sig, s_sig), s_va) for s_va, s_sig in src_sigs.items()),
        )
        if not ranked:
            continue
        best_score, best_src = ranked[0]
        second_score = ranked[1][0] if len(ranked) > 1 else -1.0
        if best_score >= min_score and (best_score - second_score) >= min_gap:
            out[d_va] = (best_src, best_score)
    return out


def signature_for(
    cfg: ProjectConfig,
    code: bytes,
    va: int,
    *,
    disasm_signature_fn: Callable[[bytes, int, int | str, int | str], dict[str, Any] | None]
    | None = None,
) -> dict[str, Any] | None:
    """Structural signature excluding proven x86 alignment padding."""
    from rebrew.formats.binary_loader import PADDING_BYTES, function_extent_from_bytes, load_binary

    if disasm_signature_fn is None:
        raise ValueError("disasm_signature_fn is required")
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
        except (OSError, ValueError) as exc:
            _log.warning(
                "signature_for: cannot load %s to strip padding at 0x%x (%s); "
                "signature includes the padding bytes",
                cfg.target_binary,
                va,
                exc,
            )
    return disasm_signature_fn(
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
    from rebrew.metadata.functions import load_metadata

    out: dict[int, tuple[str, str]] = {}
    metadata_dir = cfg.metadata_dir
    module_name = target_module(cfg)
    project_root = getattr(cfg, "root", None)
    function_entries = load_metadata(metadata_dir, deepcopy=False)
    for path in iter_sources(cfg.reversed_dir, cfg):
        for ann in read_source_bindings(
            path,
            target_name=module_name,
            base_dir=cfg.reversed_dir,
            metadata_dir=metadata_dir,
            project_root=project_root,
            function_entries=function_entries,
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
        except OSError, ValueError:
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
    eligible = _destination_eligibility(cfg)
    sizeless = [
        va
        for va, reg in entries.items()
        if not int(reg.get("canonical_size") or 0) and eligible(va)
    ]
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
    metadata = load_metadata(metadata_dir, deepcopy=False) if metadata_dir is not None else {}
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
    skeleton from an earlier run can leave it stale.  Verifying only that
    prefix reports a false ``EXACT MATCH``: the import succeeds, and the next
    ``rebrew verify --no-cache`` flags ``SIZE_MISMATCH`` (guild-rebrew: GOLD
    0x00449d80 claimed 23 bytes while the body is 25, carried over from
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


def library_vas(cfg: ProjectConfig) -> set[int]:
    """VAs the destination binary gets from a linked library, not game source.

    ``LIBRARY`` rows whose ``file`` is one of the target's ``library_*.h``
    headers, plus rows whose module is named in
    ``targets.<name>.external_libs`` (D3DX8, LIBCMT, MSS32, …).  Cross-import
    must never create a game-source annotation for one:
    the code is linker-supplied, byte-identical across the clients by
    construction, and importing it turns a library band into dozens of
    unmatchable "game" functions; guild-rebrew matched ~50 D3DX8
    bodies in GOLDTL's ``0x5e0000-0x64ffff`` band against GOLD's copies before
    this filter existed.
    """
    from rebrew.metadata.bindings import library_inventory_bindings, read_source_bindings
    from rebrew.metadata.functions import load_metadata
    from rebrew.source.discovery import iter_library_headers

    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return set()
    modules = {preset_module_key(str(m)) for m in (getattr(cfg, "external_libs", None) or ())}
    # One store read for the whole header walk: read_source_bindings otherwise
    # re-resolves and re-fingerprints it once per header.
    function_entries = load_metadata(cfg.metadata_dir, deepcopy=False)
    project_root = getattr(cfg, "root", None)
    out: set[int] = set()
    for path in iter_library_headers(reversed_dir, cfg):
        for ann in read_source_bindings(
            path,
            metadata_dir=cfg.metadata_dir,
            project_root=project_root,
            function_entries=function_entries,
        ):
            kind = str(getattr(ann, "kind", "") or "").upper()
            module = preset_module_key(str(getattr(ann, "module", "") or ""))
            if kind == "LIBRARY" or module in modules:
                out.add(ann.va)
    for ann in library_inventory_bindings(cfg.metadata_dir, reversed_dir):
        out.add(ann.va)
    # ``library bind-source`` rows can name a vendored file outside reversed_dir
    # (references/zlib/deflate.c), which neither scan above reaches.
    module = target_module(cfg)
    for (row_module, va), entry in function_entries.items():
        if row_module == module and str(entry.get("kind") or "").upper() == "LIBRARY":
            out.add(int(va))
    return out


def _in_external_range(va: int, ranges: list[tuple[int, int]]) -> bool:
    """True when *va* falls in a band the binary fills from a linked library."""
    return any(lo <= va <= hi for lo, hi in ranges)


def _destination_eligibility(cfg: ProjectConfig) -> Callable[[int], bool]:
    statuses = annotations_by_va(cfg)
    library = library_vas(cfg)
    bands = list(getattr(cfg, "external_ranges", None) or [])

    def eligible(va: int) -> bool:
        return (
            statuses.get(va, ("", ""))[0] not in MATCHED_STATUSES
            and va not in library
            and not _in_external_range(va, bands)
        )

    return eligible


def unmatched_dest_bytes(
    cfg_dst: ProjectConfig,
    only_va: int | None = None,
) -> dict[int, bytes]:
    """Destination side: target bytes of the destination's NOT-yet-matched
    functions (anything whose STATUS is not EXACT/RELOC, PROVEN included).

    Library VAs (see :func:`library_vas`) and VAs inside the target's
    ``external_ranges`` bands are excluded: they are linked, not reversed, and
    importing them would pollute the progress accounting.

    Entries with no registry size fall back to the disassembly-derived
    extent (ret-ended only); ones the disassembler cannot size stay out of
    the match and surface as ``sizeless, use --va`` rows from
    :func:`sizeless_dest_vas`."""
    eligible = _destination_eligibility(cfg_dst)
    if only_va is not None and not eligible(only_va):
        return {}
    entries = registry(cfg_dst)
    if only_va is not None:
        entries = {only_va: entries.get(only_va, {})}
    candidates = {va: entry for va, entry in entries.items() if eligible(va)}
    vas = {
        va: int(reg["canonical_size"])
        for va, reg in candidates.items()
        if reg.get("canonical_size")
    }
    missing = list(candidates.keys() - vas.keys())
    if missing:
        sizes, _refused = disasm_sizes(cfg_dst, sorted(missing))
        vas.update(sizes)
    return target_bytes_by_va(cfg_dst, vas)


# ---------------------------------------------------------------------------
# Same-VA byte preview (read-only; no register/import apply)
# ---------------------------------------------------------------------------


def _masked_digest(code: bytes, reloc_offsets: list[int]) -> str:
    """SHA-256 of *code* with the relocation slots zeroed.

    Uses ``normalize_with_reloc_offsets`` (the same normaliser
    ``ops.binary_function_digests`` digests with), so the same function
    linked at another base digests alike."""
    from rebrew.matcher.scoring import normalize_with_reloc_offsets

    normalized = normalize_with_reloc_offsets(code, reloc_offsets, pointer_size=1)
    return hashlib.sha256(normalized).hexdigest()


def same_va_preview_rows(
    cfg_src: ProjectConfig,
    cfg_dst: ProjectConfig,
    vas: list[int],
    *,
    source_vas: dict[int, int] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Per-VA verdict: destination binary bytes at the same VA vs the source
    function reference bytes.

    *vas* are the destination VAs to check; the source function is the one at
    the same VA in *cfg_src* unless *source_vas* maps ``dst_va -> src_va``.
    The source extent is the matched-source size (``matched_source_bytes``);
    a VA with no matched source donor is ``unavailable`` — never inferred.

    Returns ``(rows, inputs_digest)`` where *inputs_digest* is the SHA-256
    over the sorted ``dst_va|src_va|src_digest|dst_digest`` lines, the
    digest-guarded "inputs" of this preview.  The relocation mask comes from
    the linked image's own base-relocation table via
    :func:`rebrew.formats.relocations.relocation_spans` — the same loaders
    ``ops.binary_function_digests`` uses; no new PE parser, no invented
    fixups.  Read-only: touches no store, writes no file, and never proves
    an adopt — a ``reloc-equal``/``exact`` row is byte evidence only;
    re-verification after any apply is still required."""
    from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary

    source_vas = dict(source_vas or {})
    src_bytes = matched_source_bytes(cfg_src)
    rows: list[dict[str, Any]] = []
    digest_lines: list[str] = []
    try:
        dst_info = load_binary(cfg_dst.target_binary)
    except (OSError, ValueError) as exc:
        for va in sorted(vas):
            rows.append(
                {
                    "dst_va": f"0x{va:08x}",
                    "src_va": None,
                    "size": None,
                    "verdict": "unreadable",
                    "message": f"destination binary unreadable: {exc}",
                }
            )
        return rows, hashlib.sha256(b"").hexdigest()
    from rebrew.formats.relocations import relocation_spans

    try:
        spans = relocation_spans(dst_info)
    except NotImplementedError, ValueError:
        spans = []
    for va in sorted(set(vas)):
        src_va = source_vas.get(va, va)
        src_code = src_bytes.get(src_va)
        if src_code is None:
            rows.append(
                {
                    "dst_va": f"0x{va:08x}",
                    "src_va": f"0x{src_va:08x}",
                    "size": None,
                    "verdict": "unavailable",
                    "message": (
                        "no matched EXACT/RELOC source function at this VA "
                        "in the source target; extent not inferred"
                    ),
                }
            )
            continue
        size = len(src_code)
        dst_code = extract_bytes_at_va(dst_info, va, size, trim_padding=False)
        offsets: list[int] = []
        if dst_code is None:
            rows.append(
                {
                    "dst_va": f"0x{va:08x}",
                    "src_va": f"0x{src_va:08x}",
                    "size": size,
                    "verdict": "unreadable",
                    "message": "destination VA is outside file-backed image bytes",
                }
            )
            continue
        if len(dst_code) != size:
            verdict = "differ"
            message = f"destination extent is {len(dst_code)}B, source is {size}B"
        elif dst_code == src_code:
            verdict = "exact"
            message = "byte-identical at the same VA"
        else:
            offsets = sorted(
                {
                    off - va
                    for address, width in spans
                    for off in range(max(va, address), min(va + size, address + width))
                }
            )
            if (
                spans
                and offsets
                and _masked_digest(dst_code, offsets) == _masked_digest(src_code, offsets)
            ):
                verdict = "reloc-equal"
                message = (
                    "equal after masking linked-image relocation spans "
                    f"({len(offsets)} offset(s)); base-relocation evidence only, "
                    "not a compile proof"
                )
            else:
                mismatches = sum(1 for a, b in zip(src_code, dst_code, strict=True) if a != b)
                verdict = "differ"
                message = f"{mismatches}/{size} byte(s) differ at the same VA"
        if verdict == "reloc-equal":
            src_masked = _masked_digest(src_code, offsets)
            dst_masked = _masked_digest(dst_code, offsets)
        else:
            src_masked = hashlib.sha256(src_code).hexdigest()
            dst_masked = hashlib.sha256(dst_code).hexdigest()
        row: dict[str, Any] = {
            "dst_va": f"0x{va:08x}",
            "src_va": f"0x{src_va:08x}",
            "size": size,
            "verdict": verdict,
            "message": message,
            "src_sha256": hashlib.sha256(src_code).hexdigest(),
            "dst_sha256": hashlib.sha256(dst_code).hexdigest(),
            "src_masked_sha256": src_masked,
            "dst_masked_sha256": dst_masked,
        }
        if verdict == "reloc-equal":
            row["reloc_offsets"] = offsets
        rows.append(row)
        digest_lines.append(
            f"{row['dst_va']}|{row['src_va']}|{row['src_masked_sha256']}|{row['dst_masked_sha256']}"
        )
    inputs_digest = hashlib.sha256("\n".join(digest_lines).encode()).hexdigest()
    return rows, inputs_digest


def _looks_like_prologue(code: bytes | None) -> bool:
    """Whether *code* opens with a function prologue the discoverer accepts.

    Mirrors the opener shapes in :func:`rebrew.binary.discover._function_start`
    (and its ``verify._looks_like_inventory_merge`` copy) on raw bytes
    after optional nop/int3 padding, without a loader handle.  Deliberately
    narrow: this is evidence for a secondary entry point, not a boundary
    proof, so a false positive would invent a head alias.
    """
    if not code:
        return False
    i = 0
    while i < len(code) and code[i] in (0x90, 0xCC):
        i += 1
    body = code[i:]
    if body.startswith(
        (
            b"\x55\x8b\xec",
            b"\x81\xec",
            b"\x83\xec",
            b"\x6a\xff\x68",
            b"\x64\xa1\x00\x00\x00\x00",
            b"\xa1",
            b"\x8b\x44\x24\x04",
            b"\x8b\x4c\x24\x04",
        )
    ):
        return True
    if len(body) >= 6 and body[0] == 0xB8 and body[5] == 0xC3:
        return True
    return (
        len(body) >= 4
        and 0x50 <= body[0] <= 0x57
        and body[1] == 0x8B
        and body[3] == 0x24
        and (body[2] & 0xC0) == 0x40
        and (body[2] & 0x07) == 0x04
        and ((body[2] >> 3) & 7) == (body[0] - 0x50)
    )


def interior_preview_rows(
    cfg_dst: ProjectConfig,
    vas: list[int],
) -> tuple[list[dict[str, Any]], str]:
    """Per-VA interior-entry evidence against the destination inventory head.

    For each VA, the containing function start is the greatest inventory
    start at or below the VA.  ``head_end`` is that head plus its inventory
    size (falling back to the next inventory start, then the VA itself, when
    the head size is zero or missing).  ``external_callers`` counts
    ``call``/``jmp`` sites the existing disassembly/xref helper
    (:func:`rebrew.binary.analysis.scan_references`) finds outside
    ``[head_va, head_end)`` whose target is the VA exactly.  ``prologue``
    reports whether the bytes at the VA open with a function prologue.

    Returns ``(rows, inputs_digest)`` with a SHA-256 over the sorted
    ``va|head_va|head_offset|head_end|external_callers|prologue`` lines,
    mirroring :func:`same_va_preview_rows`.  Read-only: touches no store,
    writes no file, records no alias; a VA with no inventory head below it
    reports null head fields and zero external callers.
    """
    from rebrew.binary.analysis import scan_references
    from rebrew.catalog.loaders import load_function_structure
    from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary

    rows: list[dict[str, Any]] = []
    digest_lines: list[str] = []
    inventory: list[tuple[int, int]] = sorted(
        {
            (int(e.va), int(e.size))
            for e in load_function_structure(inventory_path_for(cfg_dst.reversed_dir, cfg_dst))
        }
    )
    starts = [va for va, _size in inventory]
    sizes = dict(inventory)
    try:
        info = load_binary(cfg_dst.target_binary)
    except (OSError, ValueError) as exc:
        for va in sorted(set(vas)):
            rows.append(
                {
                    "va": f"0x{va:08x}",
                    "head_va": None,
                    "head_offset": None,
                    "head_end": None,
                    "external_callers": 0,
                    "prologue": False,
                    "message": f"destination binary unreadable: {exc}",
                }
            )
        return rows, hashlib.sha256(b"").hexdigest()
    for va in sorted(set(vas)):
        head_va: int | None = None
        for start in starts:
            if start > va:
                break
            head_va = start
        if head_va is None:
            rows.append(
                {
                    "va": f"0x{va:08x}",
                    "head_va": None,
                    "head_offset": None,
                    "head_end": None,
                    "external_callers": 0,
                    "prologue": _looks_like_prologue(
                        extract_bytes_at_va(info, va, 16, trim_padding=False)
                    ),
                    "message": "no inventory function start at or below this VA",
                }
            )
            continue
        head_size = sizes.get(head_va, 0)
        if head_size > 0:
            head_end = head_va + head_size
        else:
            following = [s for s in starts if s > head_va]
            head_end = following[0] if following else va
        head_offset = va - head_va
        refs = scan_references(info, target_va=va)
        external_callers = sum(
            1
            for ref in refs
            if ref.kind in ("call", "jmp") and not (head_va <= ref.from_va < head_end)
        )
        prologue = _looks_like_prologue(extract_bytes_at_va(info, va, 16, trim_padding=False))
        row: dict[str, Any] = {
            "va": f"0x{va:08x}",
            "head_va": f"0x{head_va:08x}",
            "head_offset": head_offset,
            "head_end": f"0x{head_end:08x}",
            "external_callers": external_callers,
            "prologue": prologue,
        }
        rows.append(row)
        digest_lines.append(
            f"{row['va']}|{row['head_va']}|{row['head_offset']}|{row['head_end']}"
            f"|{row['external_callers']}|{row['prologue']}"
        )
    inputs_digest = hashlib.sha256("\n".join(digest_lines).encode()).hexdigest()
    return rows, inputs_digest
