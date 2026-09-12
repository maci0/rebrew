"""match_batch.py — batch stub/near-miss discovery and source updates.

Parses source annotations into the STUB / NEAR_MATCHING / SIZE_MISMATCH work
lists and writes the resulting STATUS and CFLAGS back to the metadata.
"""

from __future__ import annotations

import logging
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console

from rebrew.annotation import (
    has_skip_annotation,
    min_valid_va_for,
    parse_c_file_multi,
    resolve_symbol,
)
from rebrew.config import ProjectConfig
from rebrew.metadata import update_source_status
from rebrew.sources import iter_sources
from rebrew.utils import atomic_write_text, read_source_text

log = logging.getLogger(__name__)
console = Console(stderr=True)


#: A smaller annotation is usually a size-0/unknown marker whose "function"
#: would be a handful of placeholder bytes.  ``--min-size`` overrides it in
#: either direction, so a genuine 5-9 byte function is reachable.
_MIN_STUB_SIZE_FLOOR = 10


@dataclass
class StubInfo:
    """Parsed annotation fields for a STUB or near-miss NEAR_MATCHING function."""

    filepath: Path
    va: str
    size: int
    symbol: str
    cflags: str
    status: str
    module: str
    delta: int = 9999
    #: Per-function TOOLCHAIN metadata (rebrew-functions.toml).  Batch paths
    #: must resolve it like the single-function path, or a library compiled
    #: with a different compiler is recompiled with the project default.
    toolchain: str = ""


_FUNC_START_RE = re.compile(
    r"^(?:BOOL|int|void|char|short|long|unsigned|signed|float|double|"
    r"DWORD|HANDLE|LPVOID|LPCSTR|LPSTR|HRESULT|UINT|ULONG|BYTE|WORD|"
    r"SIZE_T|WPARAM|LPARAM|LRESULT|"
    r"static|__declspec|extern|struct|enum|union)\s",
    re.MULTILINE,
)


def _parse_annotations(
    filepath: Path,
    *,
    status_filter: set[str],
    max_delta: int | None = None,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
    min_size: int = 0,
) -> list[StubInfo]:
    """Parse annotations with configurable status and delta filters.

    *metadata_dir* defaults to ``filepath.parent`` (the legacy inline-layout
    assumption); batch callers pass ``cfg.metadata_dir`` so functions whose
    SIZE/STATUS live in ``rebrew-functions.toml`` at the reversed_dir parent
    are found.

    *min_size* is the caller's explicit size floor (``--min-size``); when it
    is 0 the default :data:`_MIN_STUB_SIZE_FLOOR` applies.  The floor used to
    be a hardcoded 10, so ``--min-size 5`` could never reach a genuine 5-9
    byte function.
    """
    from rebrew.metadata import GA_CEILING_PREFIX

    if ignored is None:
        ignored = set()
    meta_dir = metadata_dir if metadata_dir is not None else filepath.parent

    entries = parse_c_file_multi(filepath, metadata_dir=meta_dir)
    if not entries:
        return []

    if has_skip_annotation(filepath, metadata_dir=meta_dir):
        return []

    stubs: list[StubInfo] = []
    for ann in entries:
        parsed_status = ann.status
        if parsed_status not in status_filter:
            continue

        # A GA_CEILING blocker means the GA exhausted its budget on a
        # register-only (effective-match) delta that portable C cannot
        # reproduce — further GA runs on it are wasted work.  Only `rebrew
        # prove` can move it to PROVEN (prove's own selectors do not use
        # this parse path, so ceiling entries stay prove-eligible).
        if ann.blocker.startswith(GA_CEILING_PREFIX):
            continue

        if ann.va < min_va:
            continue

        symbol = resolve_symbol(ann, filepath)
        if symbol in ignored or symbol.lstrip("_") in ignored:
            continue

        if ann.size < (min_size if min_size > 0 else _MIN_STUB_SIZE_FLOOR):
            continue

        # Pass STUB and PROVEN directly.
        # NEAR_MATCHING functions need delta checks:
        if parsed_status in ("NEAR_MATCHING",):
            d = ann.blocker_delta or 9999
            if max_delta is not None and d > max_delta:
                continue
            delta = d
        else:
            delta = 9999

        stubs.append(
            StubInfo(
                filepath=filepath,
                va=f"0x{ann.va:x}",
                size=ann.size,
                symbol=symbol,
                cflags=ann.cflags,
                status=parsed_status,
                module=ann.module,
                delta=delta,
                toolchain=getattr(ann, "toolchain", "") or "",
            )
        )
    return stubs


def parse_stub_info(
    filepath: Path,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
    min_size: int = 0,
) -> list[StubInfo]:
    """Extract STUB annotation fields from a reversed .c file."""
    return _parse_annotations(
        filepath,
        status_filter={"STUB"},
        ignored=ignored,
        metadata_dir=metadata_dir,
        min_va=min_va,
        min_size=min_size,
    )


def parse_matching_info(
    filepath: Path,
    ignored: set[str] | None = None,
    max_delta: int = 10,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
    min_size: int = 0,
) -> list[StubInfo]:
    """Extract NEAR_MATCHING annotation fields with byte delta <= max_delta."""
    return _parse_annotations(
        filepath,
        status_filter={"NEAR_MATCHING"},
        max_delta=max_delta,
        ignored=ignored,
        metadata_dir=metadata_dir,
        min_va=min_va,
        min_size=min_size,
    )


def parse_matching_all(
    filepath: Path,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
    min_size: int = 0,
) -> list[StubInfo]:
    """Extract all NEAR_MATCHING annotations (no delta filter)."""
    return _parse_annotations(
        filepath,
        status_filter={"NEAR_MATCHING"},
        ignored=ignored,
        metadata_dir=metadata_dir,
        min_va=min_va,
        min_size=min_size,
    )


def parse_size_mismatch_all(
    filepath: Path,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
    min_size: int = 0,
) -> list[StubInfo]:
    """Extract all SIZE_MISMATCH annotations (no delta filter)."""
    return _parse_annotations(
        filepath,
        status_filter={"SIZE_MISMATCH"},
        ignored=ignored,
        metadata_dir=metadata_dir,
        min_va=min_va,
        min_size=min_size,
    )


def _collect_with_dedup(
    reversed_dir: Path,
    cfg: ProjectConfig | None,
    parser_fn: Callable[[Path], list[StubInfo]],
    sort_key: Callable[[StubInfo], Any],
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Collect StubInfo entries from source files, deduplicating by VA."""
    from rebrew.utils import rel_display_path

    results: list[StubInfo] = []
    seen_vas: dict[str, str] = {}
    dup_warnings: list[str] = []

    if not reversed_dir.exists():
        return results

    for cfile in iter_sources(reversed_dir, cfg):
        infos = parser_fn(cfile)
        rel_name = rel_display_path(cfile, reversed_dir)
        for info in infos:
            va_str = info.va
            if va_str in seen_vas:
                if warn_duplicates:
                    dup_warnings.append(
                        f"  [yellow]warning:[/yellow] Duplicate VA {va_str} found in {rel_name} "
                        f"(already in {seen_vas[va_str]}), skipping"
                    )
                continue
            seen_vas[va_str] = rel_name
            results.append(info)

    for w in dup_warnings:
        console.print(w)

    results.sort(key=sort_key)
    return results


def find_all_stubs(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
    min_size: int = 0,
) -> list[StubInfo]:
    """Find all STUB files in reversed/ and return sorted by size."""
    md = cfg.metadata_dir if cfg is not None else None
    min_va = min_valid_va_for(cfg)
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_stub_info(
            cfile, ignored=ignored, metadata_dir=md, min_va=min_va, min_size=min_size
        ),
        sort_key=lambda x: x.size,
        warn_duplicates=warn_duplicates,
    )


def find_near_miss(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    max_delta: int = 10,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
    min_size: int = 0,
) -> list[StubInfo]:
    """Find NEAR_MATCHING functions with small byte deltas, sorted by delta ascending."""
    md = cfg.metadata_dir if cfg is not None else None
    min_va = min_valid_va_for(cfg)
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_info(
            cfile,
            ignored=ignored,
            max_delta=max_delta,
            metadata_dir=md,
            min_va=min_va,
            min_size=min_size,
        ),
        sort_key=lambda x: (x.delta, x.size),
        warn_duplicates=warn_duplicates,
    )


def find_all_matching(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
    min_size: int = 0,
) -> list[StubInfo]:
    """Find all NEAR_MATCHING functions, sorted by byte delta then size."""
    md = cfg.metadata_dir if cfg is not None else None
    min_va = min_valid_va_for(cfg)
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_all(
            cfile, ignored=ignored, metadata_dir=md, min_va=min_va, min_size=min_size
        ),
        sort_key=lambda x: (x.delta, x.size),
        warn_duplicates=warn_duplicates,
    )


def find_size_mismatch(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
    min_size: int = 0,
) -> list[StubInfo]:
    """Find all SIZE_MISMATCH functions (bytes differ in length, not just
    content), sorted by size.  Batch GA previously could not target these —
    ``--all`` matches STUBs, ``--improve``/``--near-miss`` NEAR_MATCHING —
    leaving SIZE_MISMATCH functions unreachable by any batch mode."""
    md = cfg.metadata_dir if cfg is not None else None
    min_va = min_valid_va_for(cfg)
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_size_mismatch_all(
            cfile, ignored=ignored, metadata_dir=md, min_va=min_va, min_size=min_size
        ),
        sort_key=lambda x: x.size,
        warn_duplicates=warn_duplicates,
    )


# ---------------------------------------------------------------------------
# Source update helpers
# ---------------------------------------------------------------------------


def update_cflags_annotation(
    filepath: Path, new_cflags: str, metadata_dir: Path | None = None
) -> bool:
    """Update the ``cflags`` for a function — writes to the metadata.

    Returns True if the metadata was updated, False on failure.
    """
    from rebrew.metadata import get_entry, update_field

    try:
        text, _ = read_source_text(filepath)
    except OSError:
        return False

    m = re.search(
        r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*(\S+)\s+(0x[0-9a-fA-F]+)",
        text,
    )
    if m is None:
        return False

    module = m.group(1)
    va_int = int(m.group(2), 16)

    meta_root = metadata_dir or filepath.parent
    entry = get_entry(meta_root, va_int, module=module)
    if entry.get("cflags", "") == new_cflags:
        return False

    update_field(meta_root, va_int, "cflags", new_cflags, module=module)
    return True


def update_stub_to_matched(
    filepath: Path, best_src: str, stub: StubInfo, metadata_dir: Path | None = None
) -> bool:
    """Replace STUB source with matched source and update STATUS.

    Validates the transformed content before writing, then uses
    ``atomic_write_text`` with a .bak backup to prevent data loss.

    STATUS promotion happens only after the body splice succeeded AND the
    post-write parse validation passed — a failed splice or a validation
    error must not claim RELOC on a file whose body is still a stub.

    Returns True when the splice landed, the file was rewritten, and STATUS
    was promoted; False when the stub's own block could not be located (the
    file is left untouched).
    """
    bak_path = filepath.with_suffix(".c.bak")

    original, encoding = read_source_text(filepath)

    m = re.search(
        # Trailing lookahead: without it, stub.va="0x401000" would also match
        # a marker "0x4010000" (hex-prefix collision), splicing the wrong
        # function and writing STATUS/CFLAGS to the wrong module.
        r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*(\S+)\s+"
        + re.escape(stub.va)
        + r"(?![0-9a-fA-F])",
        original,
        re.IGNORECASE,
    )
    module = m.group(1) if m else None
    va_int = int(stub.va, 16) if m else None

    # NOTE: STATUS is metadata-owned (update_source_status above); the old
    # whole-file inline `// STATUS: RELOC` rewrite is gone — it hit the file's
    # FIRST block regardless of stub.va (clobbering sibling functions in
    # multi-function files and tripping lint W019).
    updated = original

    # Splice the matched body into the STUB's OWN block — search for the
    # function definition AFTER the stub's marker, not the file's first one.
    body_start = _FUNC_START_RE.search(updated, m.end() if m else 0)
    best_body = _FUNC_START_RE.search(best_src)
    spliced = bool(body_start and best_body)

    if body_start and best_body:
        # The stub's span ends at the NEXT function marker comment (or EOF) —
        # the splice must not drop sibling functions that follow this stub's
        # block in a multi-function file.
        next_fn = re.compile(
            r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*\S+\s+0x[0-9a-fA-F]+"
        ).search(updated, body_start.end())
        body_end = next_fn.start() if next_fn else len(updated)
        header = updated[: body_start.start()]
        tail = updated[body_end:]
        new_body = best_src[best_body.start() :]
        updated = header + new_body + tail

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".c",
        dir=filepath.parent,
        delete=False,
        encoding=encoding,
    ) as tmp:
        tmp.write(updated)
        tmp_path = Path(tmp.name)

    try:
        annos = parse_c_file_multi(tmp_path)
        if not annos:
            raise RuntimeError(
                f"Post-write validation failed: {filepath} would not re-parse after stub update"
            )
    finally:
        tmp_path.unlink(missing_ok=True)

    # Fail closed: if the stub's own block could not be located (no marker, or
    # a return type _FUNC_START_RE does not recognise), do NOT write, backup,
    # promote, or claim a match — the .c still holds a stub.
    if not (spliced and module is not None and va_int is not None):
        return False

    # Promote only when the splice actually landed, the file re-parses, AND
    # the write succeeded — otherwise the metadata would claim RELOC on an
    # unchanged stub body (a failed atomic_write_text — disk full, read-only
    # dir — must not leave rebrew-functions.toml saying RELOC while the .c
    # still holds the stub).  The promotion therefore runs AFTER the write.

    shutil.copy2(filepath, bak_path)
    atomic_write_text(filepath, updated, encoding=encoding)

    meta_root = metadata_dir or filepath.parent
    update_source_status(meta_root, "RELOC", module, va_int, updated_by="match")

    from rebrew.utils import rel_display_path

    display = rel_display_path(filepath, filepath.parent.parent)
    console.print(f"  [bold green]Updated[/] {display}: STUB → RELOC (backup: {bak_path.name})")
    return True


# ---------------------------------------------------------------------------
