"""``rebrew round-trip`` — splice matched function bytes back into the target PE.

Pipeline: enumerate every EXACT/RELOC function from rebrew-functions.toml,
compile each via the existing compile_and_compare path, apply COFF relocations
against the active target's function + data catalogs, splice the patched
bytes into a byte copy of the original PE at each function's file offset,
SHA-256 the result, write ``<binary>.reasm`` next to the original, exit
non-zero on any unexpected byte mismatch.

Relocation targets that the catalog cannot resolve by name are tried against
three round-trip-specific fallbacks before being reported as catalog gaps:
Ghidra auto-names that encode their VA in trailing hex (``_g_1003546c``),
MSVC ``$L<N>``/``$cleanup_loop$<N>`` jump/dispatch tables mapped from the
compiled .obj's own layout, and string literals whose compiled copy is a
strict prefix of the target's (bound to the target string's start).  The
post-splice byte compare turns any wrong fallback hit into a visible
``catalog_resolution_drift`` mismatch rather than silent corruption.

PROVEN functions are deliberately skipped — their bytes differ from the
original by design (semantic equivalence, not byte equivalence) — and are
reported as ``skipped_proven`` without altering the spliced PE.
"""

from __future__ import annotations

import hashlib
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rebrew.binary_loader import BinaryInfo, SectionInfo, load_binary, va_to_file_offset
from rebrew.catalog import trim_trailing_padding
from rebrew.cli import (
    EXIT_MISMATCH,
    EXIT_OK,
    STATUS_COLORS,
    TargetOption,
    error_exit,
    iter_annotations,
    json_print,
    require_config,
)
from rebrew.compile import compile_to_obj
from rebrew.config import ProjectConfig
from rebrew.core.matching import (
    CoffRelocRecord,
    UnresolvedSymbolError,
    apply_coff_relocations,
    build_symbol_resolver,
)
from rebrew.matcher import parse_obj_relocs_full, parse_obj_symbol_bytes
from rebrew.metadata import get_entry
from rebrew.sources import (
    iter_sources,
    target_marker,
)
from rebrew.utils import atomic_write_bytes, safe_shlex_split

console = Console(stderr=True)

app = typer.Typer(
    help="Splice every matched function back into the target PE and verify byte equality.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    out: Path | None = typer.Option(
        None, "--out", help="Override output PE path (default: <binary>.reasm next to target)"
    ),
    no_write: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview changes without writing",
    ),
    symbol_filter: str | None = typer.Option(
        None, "--filter", help="Only round-trip functions whose symbol contains this substring"
    ),
    strict_catalog: bool = typer.Option(
        False,
        "--strict-catalog",
        help="Exit non-zero when any EXACT/RELOC function hits an unresolved catalog symbol",
    ),
    fix_headers: bool = typer.Option(
        False,
        "--fix-headers",
        help="Patch the reasm copy's PE header (linker/OS/subsystem versions, "
        "TSAWARE, stack, timestamp, checksum) to match the original — values "
        "from [link] in rebrew-project.toml, falling back to the original's "
        "own fields",
    ),
    allow_naked: bool = typer.Option(
        False,
        "--allow-naked",
        help="Define REBREW_ALLOW_NAKED so fenced naked functions use their "
        "__declspec(naked) + __asm exact-byte branch (round-trip only; the "
        "comparison build keeps the idiomatic C fallback)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    cfg = require_config(target=target, json_mode=json_output)
    raise typer.Exit(
        _run_round_trip(
            cfg,
            out=out,
            no_write=no_write,
            symbol_filter=symbol_filter,
            json_output=json_output,
            strict_catalog=strict_catalog,
            fix_headers=fix_headers,
            allow_naked=allow_naked,
        )
    )


@dataclass
class _SpliceFn:
    symbol: str
    va: int
    size: int
    status: str
    path: Path
    module: str
    cflags: list[str]


def _collect_splice_set(
    cfg: ProjectConfig, symbol_filter: str | None
) -> tuple[list[_SpliceFn], list[_SpliceFn], int]:
    """Walk every annotated function, partition into splice set, PROVEN-skip set, and other count.

    Returns (splice_list, proven_list, other_count) where other_count includes functions
    with metadata but status not in {EXACT, RELOC, PROVEN} (e.g. NEAR_MATCHING, STUB, missing).
    """
    splice: list[_SpliceFn] = []
    proven: list[_SpliceFn] = []
    other_count = 0
    for path, anns in iter_annotations(
        iter_sources(cfg.reversed_dir, cfg),
        target=target_marker(cfg),
        metadata_dir=cfg.metadata_dir,
    ):
        for ann in anns:
            if symbol_filter and symbol_filter not in ann.symbol:
                continue
            md = get_entry(cfg.metadata_dir, ann.va, ann.module)  # canonical: (dir, va, module)
            status = md.get("status", "STUB")
            # iter_annotations(..., metadata_dir=...) already merges cflags into the
            # annotation, so prefer ann.cflags as the single source of truth.
            # Fall back to the project-default cflags (e.g. ``/O2 /Gd``) — without
            # this fallback, functions whose metadata has no explicit ``cflags`` key
            # would compile with only ``base_cflags`` (missing ``/O2``), producing
            # frame-pointer prologues that don't match the original optimized code.
            cflags_str = (
                getattr(ann, "cflags", "")
                or md.get("cflags", "")
                or getattr(cfg, "cflags", "")
                or ""
            )
            fn = _SpliceFn(
                symbol=ann.symbol,
                va=ann.va,
                size=int(md.get("size", 0) or 0),
                status=status,
                path=path,
                module=ann.module,
                cflags=safe_shlex_split(cflags_str),
            )
            if status in ("EXACT", "RELOC"):
                splice.append(fn)
            elif status == "PROVEN":
                proven.append(fn)
            else:
                other_count += 1
    return splice, proven, other_count


def _compile_and_extract(
    cfg: ProjectConfig, fn: _SpliceFn, work_dir: Path
) -> tuple[bytes, list[CoffRelocRecord], dict[str, bytes], dict[str, int], bool, str]:
    """Compile fn.path inside ``work_dir`` and pull out the splice inputs.

    Returns ``(text_bytes, reloc_records, str_symbols, local_labels, ok, detail)``
    where ``str_symbols`` maps MSVC string-constant names (``$SG<N>`` /
    ``??_C@...``) to their content bytes and ``local_labels`` maps ``$L<N>``
    compiler labels (jump/dispatch tables) to target VAs via
    :func:`_extract_local_labels`.  On compile failure ``ok`` is False and
    ``detail`` carries the compiler error; the other fields are empty.
    """
    obj_path, err = compile_to_obj(cfg, fn.path, fn.cflags, work_dir)
    if obj_path is None:
        return b"", [], {}, {}, False, err or "compile failed"

    text, _reloc_offsets = parse_obj_symbol_bytes(obj_path, fn.symbol)
    if text is None:
        return b"", [], {}, {}, False, f"symbol {fn.symbol} not found in .obj"
    relocs = parse_obj_relocs_full(obj_path, fn.symbol)
    str_syms = _extract_string_symbols(obj_path, {r.symbol for r in relocs})
    # Only the function's own referenced labels may be mapped — sibling
    # functions' $L labels share the section but not this function's layout.
    local_labels = _extract_local_labels(
        obj_path, fn.symbol, fn.va, referenced={r.symbol for r in relocs}
    )
    return bytes(text), relocs, str_syms, local_labels, True, ""


def _sg_key(name: str) -> str:
    """Normalize MSVC ``$SG`` / ``_$SG`` symbol names for membership tests."""
    return name.lstrip("_")


def _extract_string_symbols(obj_path: str | Path, symbol_names: set[str]) -> dict[str, bytes]:
    """Extract bytes for MSVC string constants referenced by relocations.

    Handles both compiler-generated name forms: ``$SG<N>`` (inline string
    literals in ``.rdata$<N>``/``.data``) and ``??_C@...`` (the mangled name
    for a static string constant).  Returns ``{sym_name: bytes}`` keyed by
    the **reloc-side** symbol name (so later resolve/apply steps see the same
    spelling the reloc table used).  Content includes the trailing NUL so
    target scans match whole strings, not prefixes of longer ones.
    """
    sg_by_key: dict[str, str] = {}
    for s in symbol_names:
        if "$SG" in s:
            sg_by_key[_sg_key(s)] = s
        elif s.startswith("??_C@"):
            sg_by_key[s] = s
    if not sg_by_key:
        return {}
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return {}
    out: dict[str, bytes] = {}
    for sym in coff.symbols:
        name = str(sym.name or "")
        reloc_name = sg_by_key.get(_sg_key(name))
        if reloc_name is None or sym.section is None:
            continue
        sec_data = bytes(sym.section.content)
        start = sym.value
        if start < 0 or start >= len(sec_data):
            continue
        # Include the NUL terminator so target search cannot match a prefix.
        end = sec_data.find(b"\x00", start)
        content = sec_data[start:] if end < 0 else sec_data[start : end + 1]
        if content:
            out[reloc_name] = content
    return out


def _resolve_string_symbols_in_target(
    target_bytes: bytes,
    str_syms: dict[str, bytes],
    sections: dict[str, SectionInfo],  # SectionInfo dict from BinaryInfo
) -> dict[str, int]:
    """Find each string literal in the target's .rdata/.data and return VAs.

    *str_syms* values should be NUL-terminated (see :func:`_extract_string_symbols`).
    A literal is first matched whole (with its NUL terminator); if that misses,
    the match is retried without the terminator so a compiled literal that is a
    strict prefix of the target's copy (e.g. the source is missing a trailing
    ``\\n``) still binds to the **start** of the target string — the address the
    reloc actually needs.  Prefix binding is safe because the post-splice byte
    compare catches any wrong-address patch as a catalog_resolution_drift
    mismatch rather than silently corrupting the output.
    """
    found: dict[str, int] = {}
    # Scan .rdata and .data sections only.  The search is bounded by the
    # section's raw file extent (not its virtual size): virtual > raw happens
    # whenever a section has a BSS tail (PE .data routinely does), and a
    # probe must never match bytes belonging to the *next* section on disk.
    candidate_secs = []
    for name in (".rdata", ".data"):
        sec = sections.get(name)
        if sec is not None:
            raw_end = sec.file_offset + getattr(sec, "raw_size", sec.size)
            candidate_secs.append((sec.va, raw_end, sec.file_offset))
    for sym_name, content in str_syms.items():
        if not content:
            continue
        # Fallback probe: the compiled literal without its NUL terminator,
        # used only when the whole (terminated) match misses.  An empty
        # probe must never be searched (find(b"") always matches).
        probes = [content]
        stripped = content.rstrip(b"\x00")
        if stripped and stripped != content:
            probes.append(stripped)
        for sec_va, scan_end, file_off in candidate_secs:
            for probe in probes:
                pos = file_off
                while True:
                    pos = target_bytes.find(probe, pos, scan_end)
                    if pos < 0:
                        break
                    # Only accept a match at a string boundary: the section
                    # start, a NUL (the previous string's terminator), a control
                    # byte, or a 0xff sentinel (MSVC string pools are often
                    # delimited by 0xffffffff).  Printable ASCII (0x20-0x7e) and
                    # high-ASCII (0x80-0xfe) are string content, so a probe
                    # matching there is a substring of a longer string — e.g.
                    # "at\x00" inside "Sat\x00" (the day-name table).
                    if pos == file_off:
                        found[sym_name] = sec_va + (pos - file_off)
                        break
                    prev = target_bytes[pos - 1]
                    if prev < 0x20 or prev == 0xFF:
                        found[sym_name] = sec_va + (pos - file_off)
                        break
                    pos += 1
                if sym_name in found:
                    break
            if sym_name in found:
                break
    return found


def _extract_local_labels(
    obj_path: str | Path,
    fn_symbol: str,
    fn_va: int,
    referenced: set[str] | None = None,
) -> dict[str, int]:
    """Map MSVC ``$``-prefixed compiler labels to their target VAs.

    MSVC emits jump tables, dispatch tables, switch labels, and cleanup loops
    as ``$L<N>`` / ``$cleanup_loop$<N>`` symbols **in the same .text section**
    as the function (immediately after the code, e.g. the
    ``jmp dword ptr [edx*4 + <table>]`` operand).  Because round-trip only
    splices functions whose compiled layout is byte-identical to the target
    (verified by the post-splice compare), a label's offset relative to the
    function symbol in the .obj equals its offset relative to ``fn_va`` in the
    target, so ``target_va = fn_va + (sym.value - fn.value)``.

    ``$``-prefixed symbols in *other* sections (e.g. ``.rdata`` string
    constants under this name form) are left unresolved — those keep going
    through string content matching / the catalog.  When *referenced* is
    given (the function's own reloc symbol set), only labels it names are
    mapped — ``$``-labels of *sibling* functions in the same .c file share
    the section but not the function's layout, and must never enter the map.
    """
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return {}
    fn_sym = next((s for s in coff.symbols if str(s.name or "") == fn_symbol), None)
    if fn_sym is None or fn_sym.section is None:
        return {}
    fn_sec = fn_sym.section.name
    fn_off = fn_sym.value
    out: dict[str, int] = {}
    for sym in coff.symbols:
        name = str(sym.name or "")
        if not name.startswith("$") or sym.section is None:
            continue
        if sym.section.name != fn_sec:
            continue
        if referenced is not None and name not in referenced:
            continue
        out[name] = fn_va + (sym.value - fn_off)
    return out


def _name_encoded_va(symbol: str) -> int | None:
    """Decode the VA Ghidra auto-names embed in their trailing hex digits.

    Ghidra's ``_g_1003546c`` / ``_s_<preview>_1002d9ec`` conventions append the
    symbol's VA to the auto-generated name, which lets us resolve symbols the
    catalog cannot find by name alone.  The trailing run must be 6-8 hex
    digits (a 32-bit VA) — 4-digit suffixes and ordinary names are ignored,
    and a longer run (9+ digits) is *not* truncated to 8, so
    ``_g_123456789``-style names never decode to a plausible-but-wrong VA.
    The ``0x100000`` floor keeps false hits rare (a genuine
    ``_g_myvar_12345678``-looking name would be misread, which we accept as a
    documented edge case).
    """
    m = re.search(r"([0-9a-fA-F]+)$", symbol)
    if not m:
        return None
    suffix = m.group(1)
    if not 6 <= len(suffix) <= 8:
        return None
    va = int(suffix, 16)
    return va if va >= 0x100000 else None


def _make_resolver(
    funcs_by_va: dict[int, str],
    data_by_name: dict[str, int],
    local_labels: dict[str, int] | None = None,
) -> Callable[[str], int | None]:
    """Build a symbol resolver with local-label + Ghidra name-encoded-VA fallbacks.

    Composes the shared catalog resolver (rebrew.core.matching) with two
    round-trip-only fallbacks, fired only when the catalog itself cannot
    resolve a symbol:

    * ``local_labels`` — ``$L<N>`` jump/dispatch tables from the compiled .obj
      (see :func:`_extract_local_labels`).
    * Ghidra auto-name VA encoding (``_g_1003546c``) via :func:`_name_encoded_va`.

    Kept local to round-trip because both conventions are codegen/Ghidra
    artifacts — the shared resolver (used by test/verify) must not interpret
    arbitrary symbol names as VAs.
    """

    _resolve = build_symbol_resolver(funcs_by_va, data_by_name)
    _local = local_labels or {}

    def resolve_va(symbol: str) -> int | None:
        va = _resolve(symbol)
        if va is not None:
            return va
        if symbol in _local:
            return _local[symbol]
        stripped = symbol.lstrip("_")
        if stripped in _local:
            return _local[stripped]
        return _name_encoded_va(symbol)

    return resolve_va


def _source_is_naked_fenced(path: str | Path) -> bool:
    """True when *path* guards its body behind ``#ifdef REBREW_ALLOW_NAKED``.

    The fenced sources are exactly the functions that need the define for
    byte-identity; round-trip reports them so the reccmp recomp build can be
    checked against the same list (those sources must also be compiled with
    ``-DREBREW_ALLOW_NAKED=1``).
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "#ifdef REBREW_ALLOW_NAKED" in text


def _run_round_trip(
    cfg: ProjectConfig,
    *,
    out: Path | None,
    no_write: bool,
    symbol_filter: str | None,
    json_output: bool,
    strict_catalog: bool = False,
    fix_headers: bool = False,
    allow_naked: bool = False,
) -> int:
    """Top-level orchestration. Returns the process exit code."""
    if cfg.image_base == 0:
        error_exit(
            "round-trip requires a non-zero image_base — it is auto-detected from "
            f"the target binary ({cfg.target_binary}); check that the binary "
            "exists and 'format' is set correctly in rebrew-project.toml",
            json_mode=json_output,
        )
    try:
        original = cfg.target_binary.read_bytes()
    except FileNotFoundError:
        error_exit(f"target binary missing: {cfg.target_binary}", json_mode=json_output)

    reasm = bytearray(original)
    # info is loaded lazily — only parsed when at least one function reaches
    # the file-offset lookup.  This avoids touching LIEF when the splice set
    # is empty or every entry fails compilation.
    info: BinaryInfo | None = None

    splice_set, proven_set, other_count = _collect_splice_set(cfg, symbol_filter)

    # Naked reconstruction is a round-trip-only capability: the
    # REBREW_ALLOW_NAKED define selects the `__declspec(naked)` + __asm
    # branch of fenced sources (exact bytes) instead of the idiomatic C
    # fallback.  It is NEVER added by test/verify/match — only here.
    fenced_naked_vas: list[str] = []
    if allow_naked:
        define = "-DREBREW_ALLOW_NAKED" if cfg.posix_style else "/DREBREW_ALLOW_NAKED"
        for fn in splice_set:
            fn.cflags.append(define)
            # The fenced functions are exactly the ones that require the
            # define for byte-identity — report them so the reccmp recomp
            # build matrix can be checked against this list (those sources
            # must be compiled with -DREBREW_ALLOW_NAKED=1 too).
            if _source_is_naked_fenced(fn.path):
                fenced_naked_vas.append(f"0x{fn.va:08x}")

    funcs_by_va, data_by_name = _load_catalogs(cfg)

    mismatches: list[dict[str, str | None]] = []
    skipped_catalog: list[dict[str, str | None]] = []  # entries we can't splice due to catalog gaps
    spliced_vas: set[str] = set()
    spliced_actual_bytes = 0
    extra_string_syms: dict[str, int] = {}
    from rebrew.utils import remove_temp_dir, writable_temp_dir

    work_dir = writable_temp_dir("rebrew-rt-")
    try:
        for fn in splice_set:
            text, relocs, str_syms, local_labels, ok, detail = _compile_and_extract(
                cfg, fn, work_dir
            )
            if not ok:
                mismatches.append(_mismatch(fn, "compile_drift", detail))
                continue
            # Per-function resolver: local_labels are specific to this
            # function's compiled .obj; string symbols accumulate across
            # functions.  Rebuild every iteration so both are always live.
            if str_syms:
                if info is None:
                    info = load_binary(cfg.target_binary)
                resolved = _resolve_string_symbols_in_target(info.data, str_syms, info.sections)
                extra_string_syms.update(resolved)
            merged_data = dict(data_by_name)
            merged_data.update(extra_string_syms)
            resolve_va = _make_resolver(funcs_by_va, merged_data, local_labels)
            try:
                patched = apply_coff_relocations(
                    text,
                    relocs,
                    resolve_va,
                    section_va=fn.va,
                )
            except UnresolvedSymbolError as exc:
                # Catalog gap — we can't splice but the original bytes are still
                # in the reasm buffer, so SHA equality is preserved.  Don't count
                # this as a mismatch by default; --strict-catalog fails the run.
                skipped_catalog.append(_mismatch(fn, "unresolved_symbol", exc.symbol))
                continue
            except NotImplementedError as exc:
                mismatches.append(_mismatch(fn, "reloc_application_failed", str(exc)))
                continue
            if fn.size <= 0:
                mismatches.append(_mismatch(fn, "oversize", "size <= 0 in metadata"))
                continue
            # va_to_file_offset does not raise; it falls back to (va - text_va + text_raw_offset).
            # The downstream oversize check catches any VA that would write outside the buffer.
            if info is None:
                info = load_binary(cfg.target_binary)
            offset = va_to_file_offset(info, fn.va)
            if offset < 0 or offset >= len(reasm):
                mismatches.append(_mismatch(fn, "oversize", f"VA 0x{fn.va:08x} outside image"))
                continue
            end = offset + fn.size
            if end > len(reasm):
                mismatches.append(_mismatch(fn, "oversize", None))
                continue
            # SIZE metadata may include trailing NOP/INT3 padding that the
            # compiler never emits (Ghidra sizes often do).  `rebrew test`
            # tolerates that (padding-tolerant byte compare), so round-trip
            # must too — compare against the trimmed span, otherwise a
            # genuinely matched function reports a false "oversize" because
            # len(compiled) < SIZE (e.g. cm_ExAllocThemaPredigt: SIZE 176,
            # compiles to 172, 4 trailing padding bytes).
            original_slice = bytes(original[offset:end])
            trimmed_size = trim_trailing_padding(original_slice)
            # The compiled text (padding already stripped by
            # parse_obj_symbol_bytes) must match the target's real-code span
            # EXACTLY.  Shorter is a genuine oversize; longer means the
            # source emits code the target doesn't have — the compiled tail
            # would be silently dropped by the splice below, so it must fail
            # the verification too.
            if trimmed_size <= 0 or len(patched) != trimmed_size:
                mismatches.append(_mismatch(fn, "oversize", None))
                continue
            # Sanity: patched bytes must match the original at this offset.
            # Split reasons so diagnosis is accurate:
            #   - no relocs applied → compile_drift (wrong code / cflags / size)
            #   - relocs applied → catalog_resolution_drift (wrong symbol VA)
            if bytes(patched[:trimmed_size]) != original_slice[:trimmed_size]:
                first_diff = next(
                    (i for i in range(trimmed_size) if patched[i] != original_slice[i]), 0
                )
                reason = "catalog_resolution_drift" if relocs else "compile_drift"
                detail = f"first byte diff at offset 0x{first_diff:x}"
                # When the diff sits inside a REL32 relocation, decode the two
                # call/jmp targets so the user can fix the source call
                # directly (this is exactly what `rebrew test` masks).
                if relocs:
                    for r in relocs:
                        if r.offset <= first_diff < r.offset + 4 and r.type == 0x14:
                            target_src = resolve_va(r.symbol)
                            target_orig = _rel32_target(original_slice, r.offset, fn.va)
                            if target_orig is not None:
                                target_src_str = (
                                    f"{target_src:#x}" if target_src is not None else "?"
                                )
                                name_src = _target_name(funcs_by_va, target_src) or _list_name(
                                    cfg, target_src
                                )
                                name_orig = _target_name(funcs_by_va, target_orig) or _list_name(
                                    cfg, target_orig
                                )
                                detail += (
                                    f"; reloc@{r.offset:#x}: source → {target_src_str}"
                                    f" ({name_src}), target → {target_orig:#x} ({name_orig})"
                                )
                            break
                mismatches.append(
                    _mismatch(
                        fn,
                        reason,
                        detail,
                    )
                )
                continue
            # Splice only the verified real-code span; any trailing padding
            # stays untouched in the buffer (already byte-identical to the
            # original), so SHA equality is preserved by construction.
            reasm[offset : offset + trimmed_size] = patched[:trimmed_size]
            spliced_vas.add(f"0x{fn.va:08x}")
            spliced_actual_bytes += trimmed_size
    finally:
        remove_temp_dir(work_dir)

    # --fix-headers: patch the reasm PE header (linker/OS/subsystem versions,
    # TSAWARE, stack/heap, timestamp, checksum) so the byte-identical goal is
    # not blocked by header cosmetics.  Values come from [link] config where
    # set; unconfigured fields are copied from the ORIGINAL so the patched
    # header matches it.  file_align is reported but not patched (needs a
    # relink — /ALIGN).  Runs before the SHA comparison so a truly identical
    # reasm reports match=True.
    header_parity: list[dict[str, object]] = []
    if fix_headers:
        from rebrew.pe_headers import (
            PATCHABLE,
            patch_pe_headers,
            read_pe_header_fields,
        )
        from rebrew.pe_headers import (
            header_parity as _header_parity,
        )

        original_fields = read_pe_header_fields(original)
        if original_fields is not None:
            configured = getattr(cfg, "link", None)
            configured_fields = configured.to_patch_fields() if configured else {}
            patch: dict[str, int] = {}
            for label in PATCHABLE:
                if label in configured_fields:
                    patch[label] = configured_fields[label]
                elif label in original_fields.values:
                    patch[label] = original_fields.values[label]
            reasm = bytearray(patch_pe_headers(bytes(reasm), patch))
            header_parity = _header_parity(
                original, bytes(reasm), configured_fields if configured_fields else None
            )

    sha_original = hashlib.sha256(bytes(original)).hexdigest()
    sha_reasm = hashlib.sha256(bytes(reasm)).hexdigest()
    # Match = byte-exactness of the rebuilt PE AND no verification failures.
    # Passthrough fallbacks keep the SHA equal even when a splice fails, but a
    # mismatch (compile drift, oversize, reloc failure, drift) means a function
    # in the splice set was not verified — the round trip is incomplete, so the
    # CLI exits non-zero (docs: "exit 1 on mismatch").  Catalog gaps are
    # informational unless --strict-catalog is set.
    # Catalog gaps are informational unless --strict-catalog is set.  Under
    # --strict-catalog, an entry that neither spliced nor mismatched went to
    # skipped_catalog, so `catalog_ok` alone already fails the run — a
    # separate "nothing verified" term is redundant (every splice-set entry
    # terminates in exactly one of spliced / mismatch / skipped_catalog).
    catalog_ok = not strict_catalog or not skipped_catalog
    match = not mismatches and sha_original == sha_reasm and catalog_ok

    out_path = out or cfg.target_binary.with_suffix(cfg.target_binary.suffix + ".reasm")
    if not no_write:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(out_path, bytes(reasm))

    # Byte-coverage accounting: how much of .text came from our compilation
    # versus passthrough from the input PE.  Uses the actual spliced span
    # (trimmed of padding), not the metadata SIZE which can include trailing
    # NOP/INT3 bytes the compiler never emits.
    spliced_bytes = spliced_actual_bytes
    proven_bytes = sum(fn.size for fn in proven_set if fn.size > 0)
    # Keep the lazy-LIEF contract (see the `info` comment above): when nothing
    # reached the file-offset lookup, don't parse the binary — coverage is 0.
    text_size = info.text_size if info is not None else 0
    passthrough_bytes = max(text_size - spliced_bytes - proven_bytes, 0)

    # Aggregate reason breakdown for at-a-glance triage (e.g. "92 skipped:
    # 85 unresolved_symbol, 5 size_mismatch, 2 ...").
    reason_counts: dict[str, int] = {}
    for _skip_entry in [*skipped_catalog, *mismatches]:
        reason_label = str(_skip_entry.get("reason") or "unknown")
        reason_counts[reason_label] = reason_counts.get(reason_label, 0) + 1

    report = {
        "schema_version": 1,
        "target": cfg.target_name,
        "binary": str(cfg.target_binary),
        "arch": getattr(cfg, "arch", ""),
        "out": str(out_path) if not no_write else None,
        "sha256_original": sha_original,
        "sha256_reasm": sha_reasm,
        "match": match,
        "strict_catalog": strict_catalog,
        "spliced": len(spliced_vas),
        "skipped_proven": len(proven_set),
        "skipped_other": other_count,
        "fenced_naked": {
            "count": len(fenced_naked_vas),
            "vas": fenced_naked_vas,
        },
        "skipped_catalog": skipped_catalog,
        "mismatches": mismatches,
        "reason_counts": reason_counts,
        "header_parity": header_parity,
        "byte_coverage": {
            "text_size": text_size,
            "spliced_bytes": spliced_bytes,
            "proven_bytes": proven_bytes,
            "passthrough_bytes": passthrough_bytes,
            "spliced_pct": round(100.0 * spliced_bytes / text_size, 2) if text_size else 0.0,
            "passthrough_pct": (
                round(100.0 * passthrough_bytes / text_size, 2) if text_size else 0.0
            ),
        },
    }
    if json_output:
        json_print(report)
    else:
        _render_rich(report)

    return EXIT_OK if match else EXIT_MISMATCH


def _mismatch(fn: _SpliceFn, reason: str, detail: str | None) -> dict[str, str | None]:
    return {
        "symbol": fn.symbol,
        "va": f"0x{fn.va:08x}",
        "status": fn.status,
        "reason": reason,
        "detail": detail,
    }


def _rel32_target(blob: bytes, offset: int, fn_va: int) -> int | None:
    """Decode a REL32 displacement at fn-relative *offset* to an absolute VA.

    The displacement is relative to the byte after the 4-byte field, so the
    next-IP is ``fn_va + offset + 4``.  Returns ``None`` when the field lies
    past the end of *blob*.
    """
    if offset + 4 > len(blob):
        return None
    disp: int = struct.unpack("<i", blob[offset : offset + 4])[0]
    return fn_va + offset + 4 + disp


def _target_name(funcs_by_va: dict[int, str], va: int | None) -> str:
    """Best-effort human name for a call target VA (empty when unknown)."""
    if va is None:
        return "?"
    return funcs_by_va.get(va, "")


def _list_name(cfg: ProjectConfig, va: int | None) -> str:
    """Function-list name for an un-annotated target VA (e.g. fcn.1001a286).

    The annotated-function map only knows reversed functions; the function
    list (r2) names everything the disassembler found.  Falls back to the
    ``fcn.<va>``-style name so drift details are actionable even for
    un-reversed targets.  Returns "" when unavailable.  The underlying
    parse is cached by ``cached_function_list`` (path-keyed); this helper
    is only reached on mismatch error paths, so the projection is rebuilt
    per call rather than kept in a second cache.
    """
    if va is None:
        return ""
    from rebrew.catalog import cached_function_list

    try:
        names = {f["va"]: str(f["name"]) for f in cached_function_list(cfg)}
    except (OSError, ValueError, KeyError, TypeError):
        names = {}
    return names.get(va, "")


def _load_catalogs(cfg: ProjectConfig) -> tuple[dict[int, str], dict[str, int]]:
    """Build the function ``{va: name}`` map + the data ``{name: va}`` map.

    Sources, in priority order:
      * Function VAs: union of ``cfg.dll_exports`` and every annotated function in
        ``cfg.reversed_dir`` (annotations are the canonical inter-function name source
        for the active target).
      * Data names: the single ``rebrew-data.toml`` at ``cfg.metadata_dir``
        (filtered to the active target's marker) plus DATA/GLOBAL annotations.
    """
    from rebrew.data_metadata import load_data_metadata

    marker = target_marker(cfg)  # honors cfg.marker overrides
    funcs: dict[int, str] = dict(cfg.dll_exports)  # base layer: PE exports
    # Data names live in cfg.metadata_dir/rebrew-data.toml — not under each
    # annotated source's parent directory.  DATA/GLOBAL annotations are also
    # folded in below.
    data: dict[str, int] = {}
    # Scan source files plus any sibling headers (e.g. library_msvc.h) for
    # LIBRARY/FUNCTION annotations.  Headers carry CRT and Win32 symbol VAs.
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    for h in cfg.reversed_dir.rglob("*.h"):
        sources.append(h)
    for _path, anns in iter_annotations(
        sources,
        target=marker,
        metadata_dir=cfg.metadata_dir,
    ):
        for ann in anns:
            if ann.module != marker or not ann.name:
                continue
            # DATA/GLOBAL annotations (e.g. an IAT import slot annotated as a
            # global named like its function) belong in the data map, never in
            # the function VA map — otherwise a same-named function is shadowed
            # and REL32 calls resolve to the data slot (CreateListenSocket:
            # function@0x10009e60 vs data@0x101deb14).
            if ann.marker_type in ("DATA", "GLOBAL"):
                data[ann.name] = ann.va
            else:
                funcs[ann.va] = ann.name

    for (mod, va), meta in load_data_metadata(cfg.metadata_dir).items():
        if mod == marker and meta.get("name"):
            data[meta["name"]] = va
    return funcs, data


def _render_rich(report: dict[str, Any]) -> None:
    """Rich panel + table summary, aligned with ``rebrew status`` and ``rebrew verify --summary``."""
    binary_path = report.get("binary", "")
    binary_name = Path(binary_path).name if binary_path else ""
    arch = report.get("arch", "")
    match = report.get("match", False)
    mismatches = report.get("mismatches", [])
    spliced = report.get("spliced", 0)
    skipped_proven = report.get("skipped_proven", 0)
    skipped_other = report.get("skipped_other", 0)
    sha_orig = report.get("sha256_original", "")
    sha_reasm = report.get("sha256_reasm", "")
    out_path = report.get("out")
    byte_coverage = report.get("byte_coverage", {}) or {}

    # --- Panel header ---
    header_parts: list[str] = []
    if binary_name:
        header_parts.append(f"[bold]{binary_name}[/bold]")
    if binary_path:
        header_parts.append(f"[dim]{binary_path}[/dim]")
    if arch:
        header_parts.append(f"[dim]({arch})[/dim]")
    title = "[bold]Rebrew Round-Trip[/bold]"
    if header_parts:
        title += "  " + "  ".join(header_parts)

    # --- Stats line ---
    skipped_catalog = report.get("skipped_catalog", []) or []
    n_catalog = len(skipped_catalog)
    n_mismatch = len(mismatches)

    # --- Coverage bar (include catalog gaps so incompleteness is visible) ---
    total = spliced + skipped_proven + skipped_other + n_catalog + n_mismatch
    bar_items: list[Text] = []
    if total > 0:
        bar_width = 40
        filled = int(bar_width * spliced / total)
        bar_text = Text()
        bar_text.append("  Spliced  ", style="bold")
        bar_text.append("█" * filled, style="green")
        bar_text.append("░" * (bar_width - filled), style="dim")
        bar_text.append(f"  {spliced}/{total}", style="bold")
        bar_items.append(bar_text)

    stats_parts: list[str] = [
        f"[green]spliced: {spliced}[/green]",
        f"[cyan]proven skipped: {skipped_proven}[/cyan]",
        f"[dim]other skipped: {skipped_other}[/dim]",
    ]
    if n_catalog:
        stats_parts.append(f"[yellow]catalog gaps: {n_catalog}[/yellow]")
    if n_mismatch:
        stats_parts.append(f"[red]mismatches: {n_mismatch}[/red]")
    fenced = (report.get("fenced_naked") or {}).get("count", 0)
    if fenced:
        stats_parts.append(f"[magenta]naked fenced: {fenced}[/magenta]")
    reason_counts = report.get("reason_counts", {}) or {}
    if reason_counts:
        reason_breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(reason_counts.items()))
        stats_parts.append(f"[dim]({reason_breakdown})[/dim]")
    stats_text = Text.from_markup("  " + "  ·  ".join(stats_parts))

    # --- SHA lines ---
    sha_orig_disp = sha_orig[:16] if sha_orig else "-"
    sha_reasm_disp = sha_reasm[:16] if sha_reasm else "-"
    sha_orig_text = Text.from_markup(f"  [dim]Original:[/dim] [cyan]{sha_orig_disp}[/cyan]")
    sha_reasm_text = Text.from_markup(f"  [dim]Reasm:   [/dim] [cyan]{sha_reasm_disp}[/cyan]")

    summary_items: list[Text] = [
        *bar_items,
        Text(""),  # spacer
        stats_text,
    ]

    # --- Byte coverage breakdown ---
    if byte_coverage.get("text_size", 0) > 0:
        text_size = byte_coverage["text_size"]
        spliced_b = byte_coverage.get("spliced_bytes", 0)
        proven_b = byte_coverage.get("proven_bytes", 0)
        passthru_b = byte_coverage.get("passthrough_bytes", 0)
        spliced_pct = byte_coverage.get("spliced_pct", 0.0)
        passthru_pct = byte_coverage.get("passthrough_pct", 0.0)
        bar_width = 40
        sp_filled = int(bar_width * spliced_b / text_size) if text_size else 0
        pr_filled = int(bar_width * proven_b / text_size) if text_size else 0
        pass_filled = max(bar_width - sp_filled - pr_filled, 0)
        byte_bar = Text()
        byte_bar.append("  .text    ", style="bold")
        byte_bar.append("█" * sp_filled, style="green")
        if pr_filled:
            byte_bar.append("█" * pr_filled, style="cyan")
        byte_bar.append("░" * pass_filled, style="dim")
        byte_bar.append(
            f"  {spliced_b:,}/{text_size:,}B compiled ({spliced_pct:.1f}%)",
            style="bold",
        )
        summary_items.append(byte_bar)
        breakdown = Text.from_markup(
            f"  [green]compiled: {spliced_b:,}B ({spliced_pct:.1f}%)[/green]  ·  "
            f"[cyan]proven: {proven_b:,}B[/cyan]  ·  "
            f"[dim]passthrough: {passthru_b:,}B ({passthru_pct:.1f}%)[/dim]"
        )
        summary_items.append(breakdown)
        summary_items.append(Text(""))

    summary_items.append(sha_orig_text)
    summary_items.append(sha_reasm_text)

    if out_path:
        summary_items.append(Text.from_markup(f"  [dim]Output:[/dim] {out_path}"))

    # --- Mismatch table ---
    table_items: list[Table] = []
    if mismatches:
        summary_items.append(Text(""))  # spacer before table
        table = Table(title="Mismatches", show_header=True, header_style="bold")
        table.add_column("VA", style="cyan", no_wrap=True)
        table.add_column("Symbol", style="magenta")
        table.add_column("Status", style="bold")
        table.add_column("Reason")
        table.add_column("Detail")
        for m in mismatches:
            st = m.get("status", "")
            color = STATUS_COLORS.get(st, "red")
            st_str = f"[{color}]{st}[/{color}]" if st else "-"
            reason = m.get("reason", "")
            detail = m.get("detail") or "-"
            table.add_row(m.get("va", "-"), m.get("symbol", "-"), st_str, reason, detail)
        table_items.append(table)

    # --- Subtitle (verdict) ---
    if match:
        subtitle = "[bold green]✔ match[/bold green]"
    else:
        n = len(mismatches)
        subtitle = f"[bold red]✗ {n} mismatch{'es' if n != 1 else ''}[/bold red]"

    # --- Assemble panel ---
    all_content: list[Text | Table] = [*summary_items, *table_items]
    panel = Panel(
        Group(*all_content),
        title=title,
        subtitle=subtitle,
        border_style="blue",
    )
    console.print(panel)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
