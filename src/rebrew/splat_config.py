"""import-splat, seed a rebrew project from a splat config.

`splat <https://github.com/ethteck/splat>`_ is the standard splitter for
GNU-toolchain decompilation projects: its YAML config describes a target
binary as a list of rom segments with file offsets, vrams, and per-subsegment
types, and its ``symbol_addrs`` file names addresses (``name = 0x00401000;
// type:func size:0x2A``).  This module reads that surface and writes the
equivalent rebrew project state, so names, addresses, and section geometry
are not re-derived by hand.

Rebrew is not a splat re-implementation: its loop is compiler-in-the-loop C,
while splat's reassembly path needs GNU ``as``/``ld``/``objcopy``.  What this
module provides is interop in one direction, the one that helps: splat ->
rebrew.  Nothing here writes a splat file back out (``rebrew symbol-addrs``
already exports the symbol side).

What it delegates to (no second mechanism):

- YAML: :func:`parse_splat_config`, a strict reader for the config subset
  splat's own ``create_config`` emits (see "Config subset" below).  rebrew
  does not depend on PyYAML, so the subset is parsed here and anything
  outside it is a hard error, never a silent misread.
- Symbols: :func:`rebrew.symbol_addrs.parse_symbol_addrs` reads every
  ``symbol_addrs_path`` file, including the rich ``// type:``/``// size:``
  trailing comments the ``rebrew symbol-addrs`` writer emits.
- Binary identity and layout: :func:`rebrew.binary_loader.load_binary`
  supplies format, arch, and image base; the configured binary is copied by
  the same convention ``rebrew intake`` uses (``original/<target>``).
- Function annotations: :func:`rebrew.skeleton.generate_skeleton` renders the
  ``// FUNCTION: <MODULE> 0x<va>`` marker and its stub body;
  ``SIZE``/``STATUS`` land in ``rebrew-functions.toml`` through
  :func:`rebrew.metadata.set_fields_batch` and
  :func:`rebrew.metadata.update_statuses_batch` (status is metadata-owned,
  never inline).
- Library annotations: :func:`rebrew.identify_library.write_candidates` appends
  the ``// LIBRARY: <MODULE> 0x<va>`` entries to ``library_<module>.h``.
- Data annotations: the ``// DATA: <MODULE> 0x<va>`` marker plus
  :func:`rebrew.data_metadata.set_data_field` for ``size``/``section``.
- Layout entries: :class:`rebrew.layout_meta.SectionMeta` records, written
  into ``[targets.<target>.layout]`` in the same shape
  ``rebrew gen-layout`` writes, so ``rebrew data``/``calibrate-bss`` read them
  unchanged.

What a splat config cannot give rebrew (skipped on purpose, reported by
:func:`parse_splat_config` as ignored keys):

- GNU-linker directives: ``subalign``, ``emit_subalign``, ``ld_script_path``,
  ``ld_symbol_header_path``, ``auto_link_sections``, ``ld_fill_value``,
  ``ld_partial_linking``, the ``vram_class``/``follows_vram`` machinery.  Those
  drive splat's own linker script, not a rebrew build (rebrew compiles C and
  links with the target's toolchain).
- PSX/MIPS/N64 segment vocabulary: ``platform`` values other than ``win32``
  and the subsegment types behind them (``Vtx``/``Gfx``/``Yay0``/``Ci4``/
  ``Rdata``-style assets, ``c``/``hasm`` split ranges).  rebrew has no
  compiler profile for those targets and no asset pipeline, so a non-win32
  platform is refused outright rather than half-imported.
- splat's reassembly-only fields: ``asm_path``/``src_path``/``asset_path``/
  ``o_as_suffix``/``cache_path``/``section_order``/``string_encoding`` and the
  rest of the ``options`` keys this module reports as ignored (each with its
  reason).  rebrew's sources are hand-written and its layout comes from the
  binary, so none of them has an effect here.

Usage::

    rebrew import-splat splat.yaml            # dry run: what it would write
    rebrew import-splat splat.yaml --write    # apply
    rebrew import-splat splat.yaml --write --force --target win32_app.exe

Config subset
-------------

Read: block mappings and sequences, inline ``{...}``/``[...]`` flows, quoted
and plain scalars (``0x…``/decimal ints, ``true``/``false``), ``#`` comments,
and a leading ``---``.  Refused with a line number: tabs in indentation,
block scalars (``|``/``>``), anchors/aliases/tags (``&``/``*``/``!``),
multiple documents, and duplicate mapping keys.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import (
    EXIT_MISMATCH,
    error_exit,
    iter_annotations,
    json_print,
    require_config,
)
from rebrew.layout_meta import SectionMeta
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import atomic_write_text, parse_int_literal

if TYPE_CHECKING:
    from rebrew.symbol_addrs import SymbolRow

console = Console(stderr=True)

#: The splat ``platform`` values this importer understands.  A config for any
#: other platform names a target rebrew cannot compile (MIPS/PSX/N64 assets and
#: segment vocabularies), so the import refuses instead of writing annotations
#: against the wrong architecture.
SUPPORTED_PLATFORM = "win32"

#: splat ``compiler`` tags -> rebrew compiler profile.  Tags splat can emit but
#: rebrew has no matching profile for (``CLANG_LLD``, ``MSVC12``, ``MSVC14``,
#: the N64/PS2/PSX tags) are absent: the project keeps its configured profile
#: and the plan carries a note.
SPLAT_COMPILER_PROFILES: dict[str, str] = {
    "MSVC2": "msvc-2.0",
    "MSVC4": "msvc-4.0",
    "MSVC5": "msvc-5.0",
    "MSVC6": "msvc-6.0",
    "MSVC7": "msvc-7.0",
    "MSVC8": "msvc-8.0",
    "MSVC9": "msvc-9.0",
    "MSVC10": "msvc-10.0",
    "MSVC11": "msvc-11.0",
    "MINGW": "mingw-16.2.0",
}

#: ``options`` keys whose value the importer uses.
_CONSUMED_OPTIONS: frozenset[str] = frozenset(
    {
        "base_path",
        "basename",
        "compiler",
        "platform",
        "symbol_addrs_path",
        "symbol_addrs_paths",
        "target_path",
        "undefined_funcs_auto_path",
        "undefined_syms_auto_path",
    }
)

#: Known splat ``options`` keys rebrew ignores, with the reason.  A key that is
#: in neither this table nor :data:`_CONSUMED_OPTIONS` is reported with
#: :data:`UNKNOWN_OPTION_REASON`, never dropped silently.
_IGNORED_OPTION_REASONS: dict[str, str] = {
    "asm_path": "splat writes per-segment .s files; rebrew's sources are hand-written",
    "asset_path": "splat's asset extraction path (no rebrew equivalent)",
    "build_path": "splat's own build directory",
    "cache_path": "splat's split cache (rebrew caches compiles, not splits)",
    "create_c_files": "splat generates .c files from ranges; rebrew has no generator",
    "data_string_encoding": "splat's assembly emitter option",
    "disassemble_all": "splat's split path",
    "dump_symbols": "splat's own symbols dump; use `rebrew symbol-addrs --references`",
    "dump_symbols_references": "splat's own symbols dump",
    "emit_subalign": "GNU ld directive (splat's linker script)",
    "elf_path": "splat's reassembly output (rebrew compiles sources directly; parsed, not read)",
    "endianness": "splat's assembly emitter option (rebrew reads it from the binary)",
    "extensions_path": "splat extension scripts (no rebrew equivalent)",
    "find_file_boundaries": "splat split heuristic",
    "generate_asm_macros_files": "splat's asm macro include files",
    "generated_asm_macros_directory": "splat's asm macro include files",
    "generated_c_preamble": "splat's generated C preamble",
    "generated_s_preamble": "splat's generated asm preamble",
    "hasm_in_src_path": "splat's handwritten-asm location option",
    "ld_align_section_vram_end": "GNU ld directive",
    "ld_align_segment_start": "GNU ld directive",
    "ld_align_segment_vram_end": "GNU ld directive",
    "ld_bss_contains_common": "GNU ld directive",
    "ld_bss_is_noload": "GNU ld directive",
    "ld_dependencies": "GNU ld dependency file generation",
    "ld_dependencies_include": "GNU ld dependency file generation",
    "ld_discard_section": "GNU ld directive",
    "ld_fill_value": "GNU ld directive",
    "ld_generate_symbol_per_data_segment": "GNU ld directive",
    "ld_gp_expression": "GNU ld directive (MIPS $gp)",
    "ld_legacy_generation": "GNU ld directive",
    "ld_partial_building": "GNU ld partial linking",
    "ld_partial_linking": "GNU ld partial linking",
    "ld_partial_scripts_path": "GNU ld partial linking",
    "ld_rom_start": "GNU ld directive",
    "ld_script_path": "GNU ld linker script (rebrew links with the target toolchain)",
    "ld_sections_allowlist": "GNU ld directive",
    "ld_sections_denylist": "GNU ld directive",
    "ld_sort_segments_by_vram_class_dependency": "GNU ld directive",
    "ld_symbol_header_path": "GNU ld directive",
    "ld_use_symbolic_vram_addresses": "GNU ld directive",
    "ld_wildcard_sections": "GNU ld directive",
    "migrate_rodata_to_functions": "splat split heuristic",
    "modes": "splat CLI modes",
    "nonmatchings_path": "splat's own asm tree layout",
    "o_as_suffix": "splat's object-file naming",
    "pair_rodata_to_text": "splat split heuristic",
    "section_order": "splat's linker script section order",
    "segment_end_before_align": "GNU ld directive",
    "segment_symbols_style": "GNU ld symbol naming",
    "src_path": "splat's generated C output path",
    "string_encoding": "splat's assembly emitter option",
    "subalign": "GNU ld directive (`subalign` in the generated linker script)",
    "symbol_name_format": "splat's generated label naming",
    "symbol_name_format_no_rom": "splat's generated label naming",
    "vram_classes": "splat's linker script vram classes (GNU ld only)",
}

UNKNOWN_OPTION_REASON = (
    "not a splat option this importer consumes; rebrew has no equivalent "
    "(see docs/CLI.md `rebrew import-splat`)"
)

#: Top-level keys (outside ``options``) splat writes or accepts.
_IGNORED_TOP_LEVEL_REASONS: dict[str, str] = {
    "name": "splat's document title comment; the rebrew target name is separate",
    "sha1": "provenance for splat's own config generator",
    "options": "",  # consumed as the options table
    "segments": "",  # consumed as the segment list
    "vram_classes": "splat's linker script vram classes (GNU ld only)",
}

UNKNOWN_TOP_LEVEL_REASON = "not a splat top-level key; ignored"

#: top-level ``segments`` entries: ``type`` values rebrew can place.
_SEGMENT_KINDS: frozenset[str] = frozenset({"header", "code", "bss", "bin"})

#: Segment keys the importer reads.
_CONSUMED_SEGMENT_KEYS: frozenset[str] = frozenset(
    {"name", "type", "start", "vram", "subsegments", "bss_size"}
)

_IGNORED_SEGMENT_KEY_REASONS: dict[str, str] = {
    "align": "splat's linker script alignment directive",
    "bss_contains_common": "GNU ld directive",
    "follows_classes": "GNU ld vram-class ordering",
    "follows_vram": "GNU ld vram-class ordering",
    "is_overlay": "splat overlay segments (no rebrew equivalent)",
    "ld_align_segment_vram_end": "GNU ld directive",
    "linker_entry": "splat's linker-script entry symbol",
    "subalign": "GNU ld directive",
    "vram_class": "GNU ld vram class",
}

UNKNOWN_SEGMENT_KEY_REASON = "not a segment key this importer consumes"

#: Subsegment kinds the importer maps onto rebrew sections.  ``text``/``asm``
#: are code; ``data``/``rodata``/``bss`` are data (kept distinct so the derived
#: PE characteristics in :data:`_PE_SECTION_CHARS` stay correct); ``bin``/
#: ``pdata`` carry no C-level annotation of their own and only contribute their
#: span.
_SUBSEGMENT_SECTION_KINDS: dict[str, str] = {
    "text": "text",
    "asm": "text",
    "data": "data",
    "rodata": "rodata",
    "bss": "bss",
    "bin": "bin",
    "pdata": "bin",
}

#: Subsegment kinds rebrew cannot consume, keyed by the reason.  The N64/PSX
#: asset vocabulary and splat's own C/asm file split live here.
_IGNORED_SUBSEGMENT_REASONS: dict[str, str] = {
    "c": "splat's C-file split range (rebrew's sources are hand-written, not "
    "generated from ranges)",
    "hasm": "splat's handwritten-asm split range",
    "jtbl": "splat's jump-table split (rebrew decodes switches with `rebrew switch`)",
    "jtbl_label": "splat's jump-table labels",
    "label": "splat's bare label marker (no bytes, no rebrew annotation)",
    "alabel": "splat's asm label marker",
    "yay0": "Nintendo decompression asset (N64)",
    "rnc": "RNC-compressed asset (PSX)",
    "ipl3": "N64 IPL3 boot block asset",
    "gfx": "N64/PSX display-list asset",
    "vtx": "N64/PSX vertex array asset",
    "light": "N64 light asset",
    "rgba16": "N64/PSX texture asset",
    "ci4": "N64/PSX texture asset",
    "ci8": "N64/PSX texture asset",
    "i4": "N64/PSX texture asset",
    "i8": "N64/PSX texture asset",
    "ia4": "N64/PSX texture asset",
    "ia8": "N64/PSX texture asset",
    "palette": "N64/PSX texture asset",
    "vtx_list": "N64/PSX asset",
    "str": "splat's string split",
    "n64": "N64-specific subsegment type",
    "psx": "PSX-specific subsegment type",
    "psp": "PSP-specific subsegment type",
    "ps2": "PS2-specific subsegment type",
}

UNKNOWN_SUBSEGMENT_REASON = "subsegment type rebrew has no equivalent for"

#: splat symbol ``type:`` (as written in the ``// type:`` comment) -> C type for
#: a ``// DATA:`` declaration.  ``func`` is handled as a function annotation and
#: is deliberately absent here.
_DATA_C_TYPES: dict[str, str] = {
    "u8": "unsigned char",
    "s8": "char",
    "u16": "unsigned short",
    "s16": "short",
    "u32": "unsigned int",
    "s32": "int",
    "u64": "unsigned long long",
    "s64": "long long",
    "f32": "float",
    "f64": "double",
    "ptr": "void *",
}

#: splat symbol type recorded in the ``// type:`` comment for a function.
FUNC_TYPE = "func"

#: The provenance splat's ``create_config`` writes for an IAT-slot symbol
#: (``// type:u32 -- import from KERNEL32.dll``).  A row carrying it names an
#: imported library API, so a code-section row becomes a ``LIBRARY`` entry (the
#: same classification ``rebrew identify-library``'s import backend makes).
_IMPORT_DETAIL_RE = re.compile(r"import from\s+(?P<dll>[^\s,;]+)")

#: Bytes per :data:`_DATA_C_TYPES` element, for sizing an array declaration.
_DATA_TYPE_SIZES: dict[str, int] = {
    "u8": 1,
    "s8": 1,
    "u16": 2,
    "s16": 2,
    "u32": 4,
    "s32": 4,
    "u64": 8,
    "s64": 8,
    "f32": 4,
    "f64": 8,
    "ptr": 4,
}

#: PE section characteristics per rebrew section kind (IMAGE_SCN_*).  The splat
#: segment table carries no characteristics, so these are the standard flag sets
#: for the section each subsegment kind describes.
_PE_SECTION_CHARS: dict[str, int] = {
    "text": 0x60000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ
    "data": 0xC0000040,  # CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
    "rodata": 0x40000040,  # CNT_INITIALIZED_DATA | MEM_READ
    "bss": 0xC0000080,  # CNT_UNINITIALIZED_DATA | MEM_READ | MEM_WRITE
}

#: splat segment/subsegment name -> PE section name.  ``create_config`` strips
#: the leading dot from a section name (``.text`` -> ``text``), and rebrew's
#: readers (``layout_geometry``, ``data_layout``) look sections up by their PE
#: name, so the dot goes back on for the known stems.
_PE_SECTION_STEMS: frozenset[str] = frozenset(
    {
        "text",
        "data",
        "rdata",
        "bss",
        "reloc",
        "rsrc",
        "pdata",
        "idata",
        "tls",
        "CRT",
        "edata",
        "debug",
    }
)

#: Status a seeded skeleton gets in ``rebrew-functions.toml``.
SEED_STATUS = "STUB"

#: Blocker written for a seeded skeleton (lint W005 expects a reason on a STUB).
SEED_BLOCKER = "seeded from a splat config, implementation pending"

#: Characters the rebrew marker is built from (same rule as ``rebrew intake``).
_MARKER_STRIP_RE = re.compile(r"[^A-Za-z0-9_]")

app = typer.Typer(
    help="Seed a rebrew project from a splat config (YAML): names, layout, annotations.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew import-splat splat.yaml · · · · · · Dry run: what would be written\n\n"
        "  rebrew import-splat splat.yaml --write · · · Apply\n\n"
        "  rebrew import-splat splat.yaml --json · · · · Machine-readable plan\n\n"
        "[dim]Reads the config surface rebrew consumes (target_path, platform, "
        "compiler, segments/subsegments, symbol_addrs, undefined_* lists).\n"
        "Ignored keys are reported by name with the reason, never dropped "
        "silently.\n"
        "A splat config cannot give rebrew GNU ld directives, the PSX/MIPS/N64 "
        "segment vocabulary, or splat's own reassembly paths.[/dim]"
    ),
)


# ---------------------------------------------------------------------------
# Typed config model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Ignored:
    """One YAML key (or key value) the importer did not use, and why."""

    key: str
    reason: str


@dataclass(frozen=True)
class Subsegment:
    """One ``[start, type, name]`` entry inside a segment."""

    rom_start: int
    kind: str
    name: str


@dataclass(frozen=True)
class Segment:
    """One entry of the top-level ``segments`` list.

    ``rom_end`` is derived from the next segment's start (or the trailing
    ``[<rom_end>]`` sentinel), since splat stores only the start.
    """

    name: str
    kind: str
    rom_start: int | None
    rom_end: int | None
    vram: int | None
    bss_size: int | None
    subsegments: tuple[Subsegment, ...]

    @property
    def rom_size(self) -> int | None:
        """Bytes this segment covers in the file, when both ends are known."""
        if self.rom_start is None or self.rom_end is None or self.rom_end < self.rom_start:
            return None
        return self.rom_end - self.rom_start

    def subsegment_at(self, va: int) -> Subsegment | None:
        """The subsegment whose vram span contains *va*, or ``None``.

        A subsegment spans from its own start to the next subsegment's start
        (or the segment's end), which is how splat delimits them.
        """
        if self.vram is None or self.rom_start is None:
            return None
        for index, sub in enumerate(self.subsegments):
            sub_end = (
                self.subsegments[index + 1].rom_start
                if index + 1 < len(self.subsegments)
                else self.rom_end
            )
            if sub_end is None:
                continue
            lo = self.vram + (sub.rom_start - self.rom_start)
            hi = self.vram + (sub_end - self.rom_start)
            if lo <= va < hi:
                return sub
        return None


@dataclass(frozen=True)
class SplatConfig:
    """The typed splat surface rebrew consumes, plus what it ignored."""

    path: Path
    base_path: Path
    platform: str
    compiler: str
    basename: str
    target_path: Path | None
    elf_path: Path | None
    segments: tuple[Segment, ...]
    rom_end: int | None
    symbol_addrs_paths: tuple[Path, ...]
    undefined_funcs_auto_path: Path | None
    undefined_syms_auto_path: Path | None
    ignored: tuple[Ignored, ...]


def pe_section_name(segment_name: str) -> str:
    """Map a splat segment name onto its PE section name (``text`` -> ``.text``)."""
    if segment_name.startswith("."):
        return segment_name
    if segment_name in _PE_SECTION_STEMS:
        return f".{segment_name}"
    return segment_name


def section_kind_of(segment: Segment) -> str:
    """The rebrew section kind a segment describes (from its first subsegment).

    ``create_config`` emits one segment per PE section, so the first
    subsegment's kind describes the whole segment.  A segment mixing kinds
    (hand-written configs only) reports the first and is noted by
    :func:`build_plan`.
    """
    for sub in segment.subsegments:
        kind = _SUBSEGMENT_SECTION_KINDS.get(sub.kind)
        if kind is not None:
            return kind
    return "bin"


def segment_mixes_kinds(segment: Segment) -> bool:
    """True when a segment's subsegments disagree on their rebrew section kind."""
    kinds = {_SUBSEGMENT_SECTION_KINDS.get(sub.kind) for sub in segment.subsegments}
    kinds.discard(None)
    return len(kinds) > 1


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _rel(base: Path, raw: Any) -> Path | None:
    """Resolve a YAML path value against *base* (splat's ``base_path``)."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    path = Path(raw)
    return path if path.is_absolute() else (base / path)


def _as_int(value: Any, key: str, path: Path) -> int | None:
    """Read an integer (``0x…`` or decimal) from a YAML value, or ``None``."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{path}: {key} must be an integer, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return parse_int_literal(value)
        except ValueError as exc:
            raise ValueError(f"{path}: {key} = {value!r} is not an integer") from exc
    raise ValueError(f"{path}: {key} must be an integer, got {type(value).__name__}")


def _string_list(value: Any) -> list[str]:
    """A YAML scalar or sequence of scalars as a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v.strip()]
    return []


def _parse_subsegment(entry: Any, path: Path) -> Subsegment:
    """Read one ``[start, type, name]`` (or ``{start:, type:, name:}``) entry."""
    if isinstance(entry, list):
        if not entry:
            raise ValueError(f"{path}: empty subsegment entry")
        start = _as_int(entry[0], "subsegment start", path)
        if start is None:
            raise ValueError(f"{path}: subsegment entry has no start address")
        kind = str(entry[1]) if len(entry) > 1 and entry[1] is not None else ""
        name = str(entry[2]) if len(entry) > 2 and entry[2] is not None else ""
        return Subsegment(rom_start=start, kind=kind.lstrip("."), name=name)
    if isinstance(entry, dict):
        start = _as_int(entry.get("start"), "subsegment.start", path)
        if start is None:
            raise ValueError(f"{path}: subsegment mapping has no start address")
        return Subsegment(
            rom_start=start,
            kind=str(entry.get("type") or "").lstrip("."),
            name=str(entry.get("name") or ""),
        )
    raise ValueError(f"{path}: subsegment entry must be a list or a mapping")


def _parse_segment(entry: Any, path: Path, ignored: list[Ignored]) -> Segment | None:
    """Read one top-level ``segments`` entry (``None`` for the rom-end sentinel)."""
    if isinstance(entry, list):
        # ``- [0x800]`` is splat's rom-end sentinel, not a segment.
        return None
    if not isinstance(entry, dict):
        raise ValueError(f"{path}: segment entry must be a mapping or a rom-end list")

    kind = str(entry.get("type") or "")
    for key in entry:
        if key in _CONSUMED_SEGMENT_KEYS:
            continue
        reason = _IGNORED_SEGMENT_KEY_REASONS.get(key, UNKNOWN_SEGMENT_KEY_REASON)
        ignored.append(Ignored(key=f"segments[].{key}", reason=reason))

    raw_subs = entry.get("subsegments")
    subs: list[Subsegment] = []
    if raw_subs is not None:
        if not isinstance(raw_subs, list):
            raise ValueError(f"{path}: segment {entry.get('name')!r} subsegments must be a list")
        subs = [_parse_subsegment(sub, path) for sub in raw_subs]

    return Segment(
        name=str(entry.get("name") or ""),
        kind=kind,
        rom_start=_as_int(entry.get("start"), "segment.start", path),
        rom_end=None,
        vram=_as_int(entry.get("vram"), "segment.vram", path),
        bss_size=_as_int(entry.get("bss_size"), "segment.bss_size", path),
        subsegments=tuple(subs),
    )


def parse_splat_config(path: Path) -> SplatConfig:
    """Parse *path* as a splat config.

    Returns the typed model plus every key the importer ignored (with the
    reason).  Raises :class:`ValueError` for a malformed config, an
    unsupported platform, and any construct outside the supported subset: a
    config this module cannot read fails loudly rather than half-importing.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"splat config not found: {path}")
    # Absolute from here on: every path in the model (target_path, symbol
    # files) is derived from the config's own directory, and callers compare
    # them against the project root.
    path = path.resolve()
    try:
        raw = parse_yaml_subset(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: not readable as UTF-8: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level value must be a mapping")

    ignored: list[Ignored] = []
    for key in raw:
        if key in _IGNORED_TOP_LEVEL_REASONS and not _IGNORED_TOP_LEVEL_REASONS[key]:
            continue
        ignored.append(
            Ignored(
                key=key,
                reason=_IGNORED_TOP_LEVEL_REASONS.get(key, UNKNOWN_TOP_LEVEL_REASON),
            )
        )

    options = raw.get("options")
    if options is None:
        raise ValueError(f"{path}: missing 'options' table")
    if not isinstance(options, dict):
        raise ValueError(f"{path}: 'options' must be a mapping")
    for key in options:
        if key in _CONSUMED_OPTIONS:
            continue
        ignored.append(
            Ignored(
                key=f"options.{key}",
                reason=_IGNORED_OPTION_REASONS.get(key, UNKNOWN_OPTION_REASON),
            )
        )

    target_raw = options.get("target_path")
    if not isinstance(target_raw, str) or not target_raw.strip():
        raise ValueError(f"{path}: options.target_path is required")

    platform = str(options.get("platform") or "")
    if not platform:
        raise ValueError(f"{path}: options.platform is required")
    platform = platform.lower()
    if platform != SUPPORTED_PLATFORM:
        raise ValueError(
            f"{path}: platform {platform!r} is not supported: rebrew seeds only "
            f"from a {SUPPORTED_PLATFORM!r} (PE) config: other platforms carry "
            "segment vocabularies and assets rebrew cannot compile "
            "(see `rebrew import-splat --help`)"
        )

    compiler = str(options.get("compiler") or "")
    if not compiler:
        raise ValueError(f"{path}: options.compiler is required")

    segments_raw = raw.get("segments")
    if not isinstance(segments_raw, list) or not segments_raw:
        raise ValueError(f"{path}: 'segments' must be a non-empty list")

    # The caller's base_path is relative to the config's own directory.
    config_dir = path.parent
    base_rel = options.get("base_path")
    base_path = config_dir
    if isinstance(base_rel, str) and base_rel.strip() and base_rel.strip() not in (".", "./"):
        candidate = Path(base_rel)
        base_path = candidate if candidate.is_absolute() else (config_dir / candidate)

    segments: list[Segment] = []
    rom_end: int | None = None
    for entry in segments_raw:
        if isinstance(entry, list) and len(entry) == 1:
            end = _as_int(entry[0], "rom end", path)
            if end is not None:
                rom_end = end
            continue
        segment = _parse_segment(entry, path, ignored)
        if segment is not None:
            segments.append(segment)
    if not segments:
        raise ValueError(f"{path}: 'segments' lists no segment")

    # Fill rom_end: the next segment's start, else the config's rom-end sentinel.
    ordered = sorted(
        (s for s in segments if s.rom_start is not None), key=lambda s: s.rom_start or 0
    )
    ends: dict[int, int] = {}
    for index, segment in enumerate(ordered):
        if index + 1 < len(ordered):
            next_start = ordered[index + 1].rom_start
            if next_start is not None:
                ends[id(segment)] = next_start
        elif rom_end is not None:
            ends[id(segment)] = rom_end
    segments = [
        Segment(
            name=s.name,
            kind=s.kind,
            rom_start=s.rom_start,
            rom_end=ends.get(id(s)),
            vram=s.vram,
            bss_size=s.bss_size,
            subsegments=s.subsegments,
        )
        for s in segments
    ]

    for segment in segments:
        if segment.kind not in _SEGMENT_KINDS:
            ignored.append(
                Ignored(
                    key=f"segments[type={segment.kind!r}]",
                    reason="segment type with no rebrew equivalent",
                )
            )
        for sub in segment.subsegments:
            if sub.kind in _SUBSEGMENT_SECTION_KINDS:
                continue
            reason = _IGNORED_SUBSEGMENT_REASONS.get(sub.kind, UNKNOWN_SUBSEGMENT_REASON)
            ignored.append(Ignored(key=f"subsegment type {sub.kind!r}", reason=reason))

    def resolve_list(value: Any) -> tuple[Path, ...]:
        return tuple(p for raw_path in _string_list(value) if (p := _rel(base_path, raw_path)))

    symbols = options.get("symbol_addrs_path", options.get("symbol_addrs_paths"))
    undefined_funcs = options.get("undefined_funcs_auto_path")
    undefined_syms = options.get("undefined_syms_auto_path")

    return SplatConfig(
        path=path,
        base_path=base_path,
        platform=platform,
        compiler=compiler,
        basename=str(options.get("basename") or ""),
        target_path=_rel(base_path, target_raw),
        elf_path=_rel(base_path, options.get("elf_path")),
        segments=tuple(segments),
        rom_end=rom_end,
        symbol_addrs_paths=resolve_list(symbols),
        undefined_funcs_auto_path=_rel(base_path, undefined_funcs),
        undefined_syms_auto_path=_rel(base_path, undefined_syms),
        ignored=tuple(_dedupe_ignored(ignored)),
    )


def _dedupe_ignored(items: list[Ignored]) -> list[Ignored]:
    """One entry per ``(key, reason)`` pair, in first-seen order."""
    seen: set[tuple[str, str]] = set()
    out: list[Ignored] = []
    for item in items:
        pair = (item.key, item.reason)
        if pair in seen:
            continue
        seen.add(pair)
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Symbols
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SymbolSet:
    """Symbol rows read from a splat config's symbol files."""

    defined: tuple[SymbolRow, ...]
    undefined: tuple[SymbolRow, ...]
    files: tuple[Path, ...]
    missing: tuple[Path, ...]
    note_lines: int


def load_symbols(cfg_splat: SplatConfig) -> SymbolSet:
    """Read the config's symbol files.

    Every row goes through :func:`rebrew.symbol_addrs.parse_symbol_addrs`, the
    reader for the rich ``name = 0xVA; // type:… size:…`` form that
    ``rebrew symbol-addrs`` writes.  ``undefined_funcs_auto``/``undefined_syms_auto``
    use the plain ``name = 0xVA;`` form splat writes (splat's
    ``write_undefined_auto``); the same reader covers both.

    Comment-only lines are counted, not parsed: the reader drops them, and
    splat's forwarded-export notes (a name with no address in this image) live
    there, so the count is reported rather than silently ignored.
    """
    from rebrew.symbol_addrs import parse_symbol_addrs

    defined: list[SymbolRow] = []
    undefined: list[SymbolRow] = []
    files: list[Path] = []
    missing: list[Path] = []
    note_lines = 0

    for paths, target in (
        (cfg_splat.symbol_addrs_paths, defined),
        ((cfg_splat.undefined_funcs_auto_path, cfg_splat.undefined_syms_auto_path), undefined),
    ):
        for path in paths:
            if path is None:
                continue
            if not path.is_file():
                missing.append(path)
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            note_lines += sum(1 for line in text.splitlines() if line.strip().startswith("//"))
            files.append(path)
            target.extend(parse_symbol_addrs(text))
    return SymbolSet(
        defined=tuple(defined),
        undefined=tuple(undefined),
        files=tuple(files),
        missing=tuple(missing),
        note_lines=note_lines,
    )


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Annotation:
    """One annotation the import would add, in rebrew's syntax.

    ``kind`` is the rebrew marker (``FUNCTION``/``LIBRARY``/``DATA``); *path*
    is relative to the target's ``reversed_dir``; ``marker`` is the annotation
    text itself (the ``// DATA:`` form also carries its declaration).
    """

    kind: str
    module: str
    va: int
    name: str
    size: int | None
    section: str
    detail: str
    path: str
    marker: str
    state: str  # "create" | "unchanged" | "conflict"
    overridable: bool = False  # a conflict --force may replace

    def display_path(self, reversed_dir: str) -> str:
        """The project-relative path this annotation lands in."""
        return f"{reversed_dir}/{self.path}" if reversed_dir else self.path


@dataclass
class ImportPlan:
    """What :func:`apply_plan` would write, and what it would not."""

    splat: SplatConfig
    target: str
    marker: str
    reversed_display: str
    binary: Path
    binary_dest: str
    copy_binary: bool
    profile: str
    format: str
    arch: str
    image_base: int
    sections: list[SectionMeta]
    annotations: list[Annotation]
    conflicts: list[str]
    unresolvable: list[str]
    skipped: list[tuple[str, str]]
    notes: list[str]
    symbols: SymbolSet
    #: ``va -> (annotation description, file)`` already in the project, as read
    #: by :func:`_existing_annotations`; only the keys matter to the writers.
    existing_vas: dict[int, tuple[str, str]] = field(default_factory=dict)


def _data_declaration(name: str, kind: str, size: int | None) -> str:
    """A C declaration for a splat data symbol (``extern unsigned int x;``).

    The element type comes from the splat ``type:`` comment; when a ``size:``
    is present and an exact multiple, the declaration is an array of that many
    elements, so the declared extent matches the symbol's.
    """
    c_type = _DATA_C_TYPES[kind]
    element = _DATA_TYPE_SIZES.get(kind)
    if size and element and size % element == 0 and size // element > 1:
        return f"extern {c_type} {name}[{size // element}];"
    return f"extern {c_type} {name};"


def build_plan(cfg_splat: SplatConfig, target: str | None = None) -> ImportPlan:
    """Build the import plan for *cfg_splat* against the current project.

    Pure reads: the project config, the splat config, and its symbol files.
    Nothing is written, so the dry run and the tests share this path exactly.
    """
    from rebrew.binary_loader import load_binary

    cfg = require_config(target=target)
    target_name = cfg.target_name
    marker = cfg.marker or _MARKER_STRIP_RE.sub("", target_name).upper()

    binary = cfg_splat.target_path
    if binary is None or not binary.is_file():
        raise ValueError(
            f"splat config target_path {binary} does not exist; the config's "
            "paths are relative to its base_path"
        )

    info = load_binary(binary)
    notes: list[str] = []
    if info.image_base == 0:
        raise ValueError(f"{binary}: no image base (not a PE?); cannot map splat vrams")
    if cfg_splat.elf_path is not None and not cfg_splat.elf_path.is_file():
        notes.append(
            f"elf_path {cfg_splat.elf_path} does not exist and is not used "
            "(splat's reassembly output)"
        )
    if info.format != "pe":
        notes.append(
            f"the target binary is {info.format!r}, but platform {SUPPORTED_PLATFORM!r} "
            "describes a PE; rebrew will write format='pe'"
        )

    profile = SPLAT_COMPILER_PROFILES.get(cfg_splat.compiler.upper(), "")
    if not profile:
        profile = cfg.compiler_profile
        notes.append(
            f"splat compiler {cfg_splat.compiler!r} has no rebrew profile; "
            f"keeping the project's {cfg.compiler_profile!r}"
        )
    elif profile != cfg.compiler_profile:
        notes.append(f"compiler profile {profile!r} from splat compiler {cfg_splat.compiler!r}")

    raw_sections, layout_notes, layout_skipped = _layout_sections(cfg_splat, info)
    notes.extend(layout_notes)

    symbols = load_symbols(cfg_splat)
    for path in symbols.missing:
        notes.append(f"symbol file {path} does not exist (splat had not generated it yet)")

    existing = _existing_annotations(cfg)
    annotations, conflicts, unresolvable, skipped, notes_ann = _plan_annotations(
        cfg_splat, cfg, marker, info.image_base, symbols, existing
    )
    notes.extend(notes_ann)
    skipped.extend(layout_skipped)

    binary_dest = f"original/{binary.name}"
    in_project = _inside_project(binary, cfg.root)
    plan = ImportPlan(
        splat=cfg_splat,
        target=target_name,
        marker=marker,
        reversed_display=_display_dir(cfg),
        binary=binary,
        binary_dest=str(binary.relative_to(cfg.root)) if in_project else binary_dest,
        copy_binary=not in_project,
        profile=profile,
        format="pe",
        arch=info.arch or "x86_32",
        image_base=info.image_base,
        sections=raw_sections,
        annotations=annotations,
        conflicts=conflicts,
        unresolvable=unresolvable,
        skipped=skipped,
        notes=notes,
        symbols=symbols,
        existing_vas=existing,
    )
    return plan


def _display_dir(cfg: Any) -> str:
    """The target's reversed_dir as a project-relative display prefix."""
    try:
        return str(cfg.reversed_dir.relative_to(cfg.root))
    except ValueError:
        return str(cfg.reversed_dir.name)


def _inside_project(path: Path, root: Path) -> bool:
    """True when *path* already lives inside the project tree."""
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _layout_sections(
    cfg_splat: SplatConfig, info: Any
) -> tuple[list[SectionMeta], list[str], list[tuple[str, str]]]:
    """Section records for ``[targets.<t>.layout]`` from the splat segments.

    Each ``type: code`` segment becomes one :class:`SectionMeta` with the PE
    section name and the section's RVA (``vram - image_base``).  When the
    binary really has that section its measured geometry wins (the splat
    numbers are reported when they disagree); a segment with no PE counterpart
    falls back to the splat span and the characteristics implied by its
    subsegment kind.  Either way the record is the same shape
    ``rebrew gen-layout`` writes, so ``rebrew data`` and
    ``rebrew calibrate-bss`` read it unchanged.
    """
    from rebrew.pe_headers import pe_layout

    sections: list[SectionMeta] = []
    notes: list[str] = []
    skipped: list[tuple[str, str]] = []
    real: dict[str, Any] = {}
    layout = pe_layout(info.data)
    if layout is not None:
        real = {s.name: s for s in layout.sections}

    for segment in cfg_splat.segments:
        if segment.kind != "code" or not segment.subsegments:
            continue
        name = pe_section_name(segment.name)
        if segment.vram is None or segment.rom_start is None or segment.rom_size is None:
            skipped.append(
                (f"segment {segment.name!r}", "no vram/start/end to derive a section from")
            )
            continue
        kind = section_kind_of(segment)
        if segment_mixes_kinds(segment):
            notes.append(
                f"segment {segment.name!r} mixes subsegment kinds; its layout "
                f"section takes the first ({kind!r})"
            )
        rva = segment.vram - info.image_base
        raw = segment.rom_size
        section = real.get(name)
        if section is not None:
            # Compare like with like: vram against the section RVA, the segment's
            # rom span against the section's raw size (a PE VirtualSize is the
            # content length, not the file span the segment describes).
            if section.virtual_address != rva or section.size_of_raw_data != raw:
                notes.append(
                    f"segment {segment.name!r} says va=0x{rva:X} raw=0x{raw:X}, the "
                    f"binary says va=0x{section.virtual_address:X} "
                    f"raw=0x{section.size_of_raw_data:X}; using the binary's"
                )
            sections.append(
                SectionMeta(
                    name,
                    section.virtual_address,
                    section.virtual_size,
                    section.size_of_raw_data,
                    section.pointer_to_raw_data,
                    section.characteristics,
                )
            )
            continue
        sections.append(
            SectionMeta(
                name=name,
                va=rva,
                vs=raw,
                raw=raw,
                raw_ptr=segment.rom_start,
                chars=_PE_SECTION_CHARS.get(kind, _PE_SECTION_CHARS["data"]),
            )
        )
        notes.append(
            f"segment {segment.name!r} does not correspond to a PE section; its "
            "layout entry carries the splat geometry and derived characteristics"
        )
    return sections, notes, skipped


def _existing_annotations(cfg: Any) -> dict[int, tuple[str, str]]:
    """``va -> ("MARKER name", path)`` for every annotation already in the project.

    Sources come through :func:`rebrew.cli.iter_annotations` (the shared batch
    reader) and ``library_*.h`` headers through
    :func:`rebrew.annotation.parse_library_header`, so the import sees every
    way an address can already be claimed.  Paths are relative to
    ``reversed_dir`` so they compare against a planned file directly.
    """
    from rebrew.annotation import parse_library_header

    existing: dict[int, tuple[str, str]] = {}
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    marker = target_marker(cfg)
    for path, annos in iter_annotations(sources, target=marker, metadata_dir=cfg.metadata_dir):
        for ann in annos:
            name = ann.symbol or ann.name or ""
            existing.setdefault(ann.va, (f"{ann.marker_type} {name}".strip(), path.name))
    for header in sorted(cfg.reversed_dir.glob("library_*.h")):
        for ann in parse_library_header(header):
            name = ann.symbol or ann.name or ""
            existing.setdefault(ann.va, (f"LIBRARY {name}".strip(), header.name))
    return existing


def _plan_annotations(
    cfg_splat: SplatConfig,
    cfg: Any,
    marker: str,
    image_base: int,
    symbols: SymbolSet,
    existing: dict[int, tuple[str, str]],
) -> tuple[list[Annotation], list[str], list[str], list[tuple[str, str]], list[str]]:
    """Classify every symbol row into a planned annotation, a skip, or a conflict.

    The symbol's splat ``type:`` picks the marker (``func`` -> FUNCTION, a
    sized type -> DATA); the segment map decides whether the address exists in
    the image as code or as data.  A row whose two signals disagree is skipped
    with the reason rather than annotated on a guess.  A row the project
    already annotates is ``unchanged`` (so a re-run is an idempotent no-op) or,
    when the annotations disagree, a conflict: *conflicts* are the ones
    ``--force`` may overwrite, *unresolvable* the ones it cannot.

    Returns ``(annotations, conflicts, unresolvable, skipped, notes)``.
    """
    from rebrew.naming import make_filename, sanitize_name

    planned: list[Annotation] = []
    conflicts: list[str] = []
    unresolvable: list[str] = []
    notes: list[str] = []
    skipped: list[tuple[str, str]] = []
    source = str(cfg_splat.path.name)
    seen_names: dict[str, int] = {}

    for row in symbols.defined:
        if row.va is None:
            skipped.append(
                (row.name, "splat symbol has no address in this image (forwarded export)")
            )
            continue
        if row.va < image_base:
            skipped.append(
                (row.name, f"address 0x{row.va:08X} is below the image base 0x{image_base:08X}")
            )
            continue
        where = _locate(cfg_splat, row.va)
        if where is None:
            skipped.append(
                (row.name, f"address 0x{row.va:08X} falls outside every code segment of the config")
            )
            continue
        section, section_kind = where
        is_func = row.kind == FUNC_TYPE
        library_module = _import_module(row.detail)
        if section_kind != "text" and is_func:
            skipped.append(
                (row.name, f"splat types it {FUNC_TYPE} but 0x{row.va:08X} lies in {section}")
            )
            continue
        if section_kind != "text" and row.kind not in _DATA_C_TYPES:
            skipped.append((row.name, f"splat type {row.kind!r} has no rebrew annotation"))
            continue
        name = sanitize_name(row.name)
        if not name or name == "unnamed":
            skipped.append((row.name, "splat symbol name sanitizes to nothing"))
            continue
        if name in seen_names and seen_names[name] != row.va:
            skipped.append(
                (
                    row.name,
                    f"another symbol of this name is already planned at 0x{seen_names[name]:08X}",
                )
            )
            continue
        seen_names[name] = row.va

        # The section decides the marker (code vs data); the splat type and the
        # provenance detail only refine it.  Code the config attributes to a DLL
        # import is LIBRARY, the same classification identify_library's import
        # backend makes for `jmp [IAT]` thunks.
        declaration = ""
        if section_kind == "text":
            if library_module:
                kind = "LIBRARY"
                module = library_module
                rel = f"library_{module.lower()}.h"
                path = None  # a library header is appended to, not owned
            else:
                kind = "FUNCTION"
                module = marker
                rel = make_filename(name, custom_name=name, cfg=cfg)
                path = cfg.reversed_dir / rel
        else:
            kind = "DATA"
            module = marker
            declaration = _data_declaration(name, row.kind, row.size)
            rel = f"data_{name}{_first_ext(cfg)}"
            path = cfg.reversed_dir / rel

        state, message, overridable = _annotation_state(existing, path, rel, row.va, name)
        if state == "conflict":
            conflicts.append(
                f"{message}, splat says {name}" if overridable else f"{message} (splat: {name})"
            )
            if not overridable:
                unresolvable.append(conflicts[-1])
        elif message:
            notes.append(message)
        planned.append(
            Annotation(
                kind=kind,
                module=module,
                va=row.va,
                name=name,
                size=row.size,
                section=section,
                detail=row.detail or (f"from {source}" if source else ""),
                path=rel,
                marker=_marker_line(kind, module, row.va, declaration),
                state=state,
                overridable=overridable,
            )
        )

    planned.extend(
        _plan_library_annotations(
            cfg_splat,
            marker,
            symbols,
            existing,
            {ann.va for ann in planned},
            conflicts,
            unresolvable,
            notes,
            skipped,
        )
    )
    planned.sort(key=lambda a: (a.va, a.kind, a.name))
    return planned, conflicts, unresolvable, skipped, notes


def _annotation_state(
    existing: dict[int, tuple[str, str]], path: Path | None, rel: str, va: int, name: str
) -> tuple[str, str, bool]:
    """``(state, message, overridable)`` for one planned annotation.

    Identity is the VA plus the file that annotates it, which is what rebrew
    tracks (a symbol spelling can change when the C definition is written).
    So a VA already annotated in the planned file is ``unchanged``; the message
    carries a name disagreement as a note.  A VA claimed by *another* file is a
    conflict ``--force`` cannot fix (a second marker for one VA is lint error
    E013), and a planned ``.c`` that exists without annotating this VA is a
    conflict ``--force`` may overwrite.
    """
    claimed = existing.get(va)
    if claimed is not None:
        description, claimed_rel = claimed
        if claimed_rel == rel:
            note = (
                ""
                if _same_name(description, name)
                else f"{rel} already annotates 0x{va:08X} as {description}, left as is"
            )
            return "unchanged", note, False
        return (
            "conflict",
            f"0x{va:08X}: the project already annotates it as {description} in "
            f"{claimed_rel}; remove or rename that annotation first",
            False,
        )
    if path is not None and path.exists() and not _file_annotates(path, va):
        return ("conflict", f"{rel} already exists and does not annotate 0x{va:08X}", True)
    return "create", "", False


def _file_annotates(path: Path, va: int) -> bool:
    """True when *path* holds an annotation block for *va*."""
    from rebrew.annotation import parse_c_file_multi

    try:
        return any(a.va == va for a in parse_c_file_multi(path))
    except (OSError, ValueError):
        return False


def _plan_library_annotations(
    cfg_splat: SplatConfig,
    marker: str,
    symbols: SymbolSet,
    existing: dict[int, tuple[str, str]],
    planned_vas: set[int],
    conflicts: list[str],
    unresolvable: list[str],
    notes: list[str],
    skipped: list[tuple[str, str]],
) -> list[Annotation]:
    """Plan ``// LIBRARY:`` entries from the two ``undefined_*`` lists.

    Splat writes those files for symbols referenced but *not defined* in the
    image: code that lives in a library, which is what rebrew's ``LIBRARY``
    marker records.  The module is inferred with
    :func:`rebrew.identify_library._infer_module` (the CRT/zlib name tables,
    the same inference ``identify_library``'s import backend uses) and falls
    back to the target's own marker.  The VA has to land inside the image,
    else there is no address to anchor an annotation to and the row is
    reported as skipped.
    """
    from rebrew.identify_library import _infer_module
    from rebrew.naming import sanitize_name

    planned: list[Annotation] = []
    for row in symbols.undefined:
        if row.va is None:
            skipped.append((row.name, "undefined symbol has no address"))
            continue
        if row.va in planned_vas:
            skipped.append((row.name, f"0x{row.va:08X} is already planned from the symbol table"))
            continue
        if _locate(cfg_splat, row.va) is None:
            skipped.append(
                (
                    row.name,
                    f"undefined symbol at 0x{row.va:08X} lies outside the image; splat "
                    "records no bytes for it, so there is no address to annotate "
                    "(link it with `rebrew gen-stubs` instead)",
                )
            )
            continue
        name = sanitize_name(row.name)
        module = _infer_module(row.name, marker or "LIBRARY")
        rel = f"library_{module.lower()}.h"
        # No file check for a library entry: the header is appended to, so it
        # existing is the normal case.
        state, message, overridable = _annotation_state(existing, None, rel, row.va, name)
        planned_vas.add(row.va)
        if state == "conflict":
            conflicts.append(f"{message}, the undefined_* list says {name}")
            if not overridable:
                unresolvable.append(conflicts[-1])
        elif message:
            notes.append(message)
        planned.append(
            Annotation(
                kind="LIBRARY",
                module=module,
                va=row.va,
                name=name,
                size=row.size,
                section="",
                detail=f"undefined in {cfg_splat.path.name}",
                path=rel,
                marker=_marker_line("LIBRARY", module, row.va, ""),
                state=state,
                overridable=overridable,
            )
        )
    return planned


def _import_module(detail: str) -> str:
    """The library module a splat provenance comment names, or ``""``.

    A generated win32 symbol file writes ``// type:u32 -- import from
    KERNEL32.dll`` for an IAT slot; the module is that DLL's stem uppercased,
    the spelling ``rebrew identify-library`` gives import candidates.
    """
    match = _IMPORT_DETAIL_RE.search(detail or "")
    if match is None:
        return ""
    return Path(match.group("dll")).stem.upper()


def _locate(cfg_splat: SplatConfig, va: int) -> tuple[str, str] | None:
    """``(section name, rebrew section kind)`` for *va*, or ``None``.

    ``None`` means the config's segments do not place the address: the symbol
    is not part of the image the config describes.
    """
    for segment in cfg_splat.segments:
        if segment.kind != "code":
            continue
        sub = segment.subsegment_at(va)
        if sub is None:
            continue
        section = pe_section_name(segment.name)
        return section, _SUBSEGMENT_SECTION_KINDS.get(sub.kind, "bin")
    return None


def _marker_line(kind: str, module: str, va: int, declaration: str) -> str:
    """The annotation text a plan entry would write, in rebrew's syntax."""
    marker = f"// {kind}: {module} 0x{va:08x}"
    return f"{marker}\n{declaration}" if declaration else marker


def _same_name(existing: str, name: str) -> bool:
    """True when an existing annotation already names *name*."""
    return f" {name} " in f" {existing} "


def _first_ext(cfg: Any) -> str:
    """The project's first configured source extension."""
    from rebrew.sources import source_exts

    exts = source_exts(cfg)
    return exts[0] if exts else ".c"


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def apply_plan(plan: ImportPlan, force: bool = False, dry_run: bool = False) -> dict[str, Any]:
    """Write *plan* into the project.

    Raises :class:`ValueError` when an annotation conflicts with an existing
    one: an ``unresolvable`` conflict (the VA is already annotated in another
    file, and a second marker for one VA would fail lint E013) always refuses,
    and an overridable one refuses unless *force* is set.  *dry_run* returns
    the same report without touching the project and never refuses, so the
    preview can show the conflict.
    """
    written: list[str] = []
    if dry_run:
        return _report(written, 0)
    if plan.unresolvable:
        raise ValueError(
            "refusing to import: these annotations cannot be written without "
            "duplicating an address (fix the project first, --force cannot "
            "resolve them):\n  " + "\n  ".join(plan.unresolvable)
        )
    if plan.conflicts and not force:
        raise ValueError(
            "refusing to overwrite conflicting annotations (pass --force to "
            "replace them):\n  " + "\n  ".join(plan.conflicts)
        )

    from rebrew.config import find_root, load_config

    root = find_root()
    if plan.copy_binary:
        dest = root / plan.binary_dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or dest.read_bytes() != plan.binary.read_bytes():
            shutil.copy2(plan.binary, dest)
            written.append(plan.binary_dest)

    if _write_target_metadata(plan, root):
        written.append("rebrew-project.toml")
    # Reload after the patch: the skeletons probe the binary through the config
    # (arch, marker, reversed_dir), all of which this import just set.
    cfg = load_config(root=root, target=plan.target)

    by_kind: dict[str, list[Annotation]] = {}
    unchanged = 0
    for ann in plan.annotations:
        if ann.state == "unchanged":
            unchanged += 1
            continue
        by_kind.setdefault(ann.kind, []).append(ann)

    written.extend(_write_functions(cfg, plan, by_kind.get("FUNCTION", [])))
    written.extend(_write_data(cfg, plan, by_kind.get("DATA", [])))
    written.extend(_write_libraries(cfg, plan, by_kind.get("LIBRARY", [])))
    return _report(written, unchanged)


def _report(written: list[str], unchanged: int) -> dict[str, Any]:
    """The writers' own result: what landed on disk, and what was already there."""
    return {"written": written, "unchanged": unchanged}


def _write_target_metadata(plan: ImportPlan, root: Path) -> bool:
    """Patch the target's binary/format/arch/profile and its layout sections.

    Uses a tomlkit round trip (the same ``load_toml_for_write`` +
    ``atomic_write_text`` pair ``rebrew gen-layout`` uses) so comments and
    unrelated keys survive.  Returns whether the file changed, so a re-run
    does not bump the mtime of an unchanged config (caches key on it).
    """
    import tomlkit

    from rebrew.utils import load_toml_for_write

    toml_path = root / "rebrew-project.toml"
    doc = load_toml_for_write(toml_path, "rebrew-project.toml")
    targets = doc.setdefault("targets", tomlkit.table())
    entry = targets.setdefault(plan.target, tomlkit.table())
    entry["binary"] = plan.binary_dest
    entry["format"] = plan.format
    entry["arch"] = plan.arch
    compiler = entry.setdefault("compiler", tomlkit.table())
    compiler["profile"] = plan.profile
    layout = entry.setdefault("layout", tomlkit.table())
    layout["image_base"] = plan.image_base
    sections = tomlkit.array().multiline(True)
    for section in plan.sections:
        if not isinstance(section, SectionMeta):
            continue
        inline = tomlkit.inline_table()
        for key, value in section.as_dict().items():
            inline[key] = value
        sections.append(inline)
    layout["sections"] = sections
    layout["source"] = f"splat:{plan.splat.path.name}"
    rendered = tomlkit.dumps(doc)
    if toml_path.is_file() and toml_path.read_text(encoding="utf-8") == rendered:
        return False
    atomic_write_text(toml_path, rendered, encoding="utf-8")
    return True


def _write_functions(cfg: Any, plan: ImportPlan, planned: list[Annotation]) -> list[str]:
    """Write one ``// FUNCTION:`` skeleton per planned function annotation.

    The marker and stub body come from
    :func:`rebrew.skeleton.generate_skeleton` (the project's FUNCTION-marker
    writer); ``SIZE``/``BLOCKER`` and ``STATUS`` go to
    ``rebrew-functions.toml`` through the batched metadata writers, because
    those keys are metadata-owned, never inline.
    """
    from rebrew.metadata import set_fields_batch, update_statuses_batch
    from rebrew.skeleton import generate_skeleton

    written: list[str] = []
    field_updates: list[dict[str, Any]] = []
    status_updates: list[dict[str, Any]] = []
    for ann in planned:
        target_path = cfg.reversed_dir / ann.path
        body = generate_skeleton(
            cfg,
            ann.va,
            ghidra_name=ann.name,
            module=plan.marker,
            custom_name=ann.name,
        )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(target_path, body)
        written.append(str(target_path.relative_to(cfg.root)))
        fields: dict[str, Any] = {"blocker": SEED_BLOCKER}
        if ann.size:
            fields["size"] = ann.size
        field_updates.append({"module": plan.marker, "va": ann.va, "fields": fields})
        status_updates.append(
            {
                "module": plan.marker,
                "va": ann.va,
                "new_status": SEED_STATUS,
                "clear_blockers": False,
                "updated_by": "import-splat",
            }
        )
    set_fields_batch(cfg.metadata_dir, field_updates)
    update_statuses_batch(cfg.metadata_dir, status_updates)
    return written


def _write_data(cfg: Any, plan: ImportPlan, planned: list[Annotation]) -> list[str]:
    """Write ``// DATA:`` markers and their ``rebrew-data.toml`` size/section."""
    from rebrew.data_metadata import set_data_field

    written: list[str] = []
    for ann in planned:
        target_path = cfg.reversed_dir / ann.path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(target_path, f"{ann.marker}\n")
        written.append(str(target_path.relative_to(cfg.root)))
        set_data_field(cfg.metadata_dir, ann.va, "section", ann.section, plan.marker)
        set_data_field(cfg.metadata_dir, ann.va, "name", ann.name, plan.marker)
        if ann.size:
            set_data_field(cfg.metadata_dir, ann.va, "size", ann.size, plan.marker)
    return written


def _write_libraries(cfg: Any, plan: ImportPlan, planned: list[Annotation]) -> list[str]:
    """Append ``// LIBRARY:`` entries through ``identify_library.write_candidates``."""
    from rebrew.identify_library import LibCandidate, write_candidates
    from rebrew.naming import sanitize_name

    candidates = [
        LibCandidate(
            va=ann.va,
            name=sanitize_name(ann.name),
            module=ann.module,
            kind="import",
            # An import backend candidate carries no CRT reference match, the
            # same confidence `identify_library` uses for its own import stubs.
            confidence=0.3,
        )
        for ann in planned
    ]
    if not candidates:
        return []
    written = write_candidates(cfg, candidates, set(plan.existing_vas))
    if not written:
        return []
    headers = sorted({ann.path for ann in planned})
    return [str((cfg.reversed_dir / h).relative_to(cfg.root)) for h in headers]


# ---------------------------------------------------------------------------
# YAML subset reader
# ---------------------------------------------------------------------------


def parse_yaml_subset(text: str) -> Any:
    """Parse the YAML subset splat configs use.

    Block mappings/sequences, inline ``{...}``/``[...]`` flows, quoted and
    plain scalars, ``#`` comments, and a leading ``---``.  Anything else
    (tabs for indentation, block scalars, anchors/aliases/tags, multiple
    documents, duplicate keys) raises :class:`ValueError` naming the line; a
    construct this reader does not model must not be guessed at.
    """
    lines = _logical_lines(text)
    if not lines:
        return {}
    value, index = _parse_block(lines, 0, lines[0].indent)
    if index != len(lines):
        raise ValueError(f"line {lines[index].number}: unexpected content")
    return value


@dataclass(frozen=True)
class _Line:
    """One significant YAML line: its number, indent, and content."""

    number: int
    indent: int
    text: str


#: YAML constructs this reader refuses to guess at.
_UNSUPPORTED_LEADING: dict[str, str] = {
    "|": "block scalars (| and >) are not part of the supported subset",
    ">": "block scalars (| and >) are not part of the supported subset",
    "&": "anchors are not part of the supported subset",
    "*": "aliases are not part of the supported subset",
    "!": "tags are not part of the supported subset",
    "%": "YAML directives are not part of the supported subset",
}


def _logical_lines(text: str) -> list[_Line]:
    """Strip comments and blanks, and reject constructs outside the subset."""
    out: list[_Line] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ValueError(f"line {number}: tab indentation is not supported")
        content = _strip_comment(raw).rstrip()
        if not content.strip():
            continue
        stripped = content.strip()
        if stripped == "---":
            continue
        if stripped.startswith("..."):
            raise ValueError(f"line {number}: multiple documents are not supported")
        first = stripped[0]
        if first in _UNSUPPORTED_LEADING:
            raise ValueError(f"line {number}: {_UNSUPPORTED_LEADING[first]}")
        out.append(_Line(number, len(content) - len(content.lstrip()), stripped))
    return out


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment (not inside quotes)."""
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            continue
        if char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _parse_block(lines: list[_Line], index: int, indent: int) -> tuple[Any, int]:
    """Parse the block at *indent* starting at *index*."""
    if lines[index].text.startswith("- "):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_mapping(lines: list[_Line], index: int, indent: int) -> tuple[dict[str, Any], int]:
    out: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise ValueError(f"line {line.number}: unexpected indentation")
        if line.text.startswith("- "):
            raise ValueError(f"line {line.number}: sequence item inside a mapping")
        key, sep, rest = _split_key(line)
        if not sep:
            raise ValueError(f"line {line.number}: expected 'key: value'")
        if key in out:
            raise ValueError(f"line {line.number}: duplicate key {key!r}")
        value_text = rest.strip()
        index += 1
        if value_text:
            out[key] = _parse_scalar(value_text, line.number)
            continue
        if index < len(lines) and lines[index].indent > indent:
            out[key], index = _parse_block(lines, index, lines[index].indent)
        elif (
            index < len(lines)
            and lines[index].indent == indent
            and lines[index].text.startswith("- ")
        ):
            out[key], index = _parse_sequence(lines, index, indent)
        else:
            out[key] = None
    return out, index


def _parse_sequence(lines: list[_Line], index: int, indent: int) -> tuple[list[Any], int]:
    """Parse a ``- item`` block.

    An item's own content is every following line indented past the dash
    column, so ``- key: value`` with more keys underneath parses as one
    mapping and ``- [0x200, text, name]`` as one flow list.
    """
    out: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if line.indent != indent or not line.text.startswith("- "):
            if line.indent > indent:
                raise ValueError(f"line {line.number}: unexpected indentation")
            break
        item_indent = line.indent + 2
        block: list[_Line] = []
        rest = line.text[2:].strip()
        if rest:
            block.append(_Line(line.number, item_indent, rest))
        index += 1
        while index < len(lines) and lines[index].indent >= item_indent:
            nested = lines[index]
            block.append(_Line(nested.number, nested.indent, nested.text))
            index += 1
        if not block:
            out.append(None)
            continue
        if _looks_like_mapping(block[0].text) or block[0].text.startswith("- "):
            value, consumed = _parse_block(block, 0, block[0].indent)
            if consumed != len(block):
                raise ValueError(f"line {block[consumed].number}: unexpected content")
            out.append(value)
            continue
        if len(block) > 1:
            raise ValueError(
                f"line {block[0].number}: a sequence item with nested lines must be a mapping"
            )
        out.append(_parse_scalar(block[0].text, block[0].number))
    return out, index


def _split_key(line: _Line) -> tuple[str, str, str]:
    """Split ``key: value`` outside quotes; returns ``(key, sep, rest)``."""
    quote = ""
    depth = 0
    text = line.text
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            continue
        if char in "[{":
            depth += 1
            continue
        if char in "]}":
            depth -= 1
            continue
        if char == ":" and depth == 0:
            if index + 1 < len(text) and text[index + 1] not in " \t":
                continue
            return text[:index].strip(), ":", text[index + 1 :]
    return text, "", ""


def _looks_like_mapping(text: str) -> bool:
    """True when a sequence item's content starts a mapping (``key: value``)."""
    if text.startswith(("[", "{")):
        return False
    key, sep, _rest = _split_key(_Line(0, 0, text))
    return bool(sep) and bool(key)


def _parse_scalar(text: str, number: int) -> Any:
    """A plain, quoted, flow, or scalar value."""
    text = text.strip()
    if text.startswith(("[", "{")):
        value, position = _flow_value(text, 0, number)
        if text[position:].strip():
            raise ValueError(f"line {number}: unexpected content after a flow value")
        return value
    if text[0] in _UNSUPPORTED_LEADING:
        # ``key: |`` (block scalar), ``key: &a`` (anchor), ``key: !tag``, ...
        # The same indicators the line-start check refuses, in value position.
        raise ValueError(f"line {number}: {_UNSUPPORTED_LEADING[text[0]]}")
    if text.startswith(('"', "'")):
        return _parse_quoted(text, number)
    if text in ("true", "True"):
        return True
    if text in ("false", "False"):
        return False
    if text in ("null", "~", "Null", "NULL"):
        return None
    return _parse_plain(text)


def _parse_plain(text: str) -> Any:
    """A plain scalar: an int when it parses as one, else the text."""
    try:
        return parse_int_literal(text)
    except ValueError:
        return text


def _parse_quoted(text: str, number: int) -> str:
    """A single- or double-quoted scalar, with the closing quote required.

    Delegates to the flow reader's quoted-scalar parser (one implementation for
    both positions) and rejects trailing content.
    """
    value, position = _flow_quoted(text, 0, number)
    rest = text[position:].strip()
    if rest and not rest.startswith("#"):
        raise ValueError(f"line {number}: unexpected content after a quoted scalar")
    return value


def _flow_value(text: str, position: int, number: int) -> tuple[Any, int]:
    """Parse one flow entry (sequence, mapping, quoted or plain scalar)."""
    position = _skip_spaces(text, position)
    if position >= len(text):
        raise ValueError(f"line {number}: flow value ends unexpectedly")
    char = text[position]
    if char == "[":
        return _flow_sequence(text, position, number)
    if char == "{":
        return _flow_mapping(text, position, number)
    if char in "\"'":
        return _flow_quoted(text, position, number)
    start = position
    while position < len(text) and text[position] not in ",]}":
        position += 1
    return _parse_plain(text[start:position].strip()), position


def _flow_sequence(text: str, position: int, number: int) -> tuple[list[Any], int]:
    """Parse ``[a, b, ...]`` starting at *position* (the opening bracket)."""
    items: list[Any] = []
    position = _skip_spaces(text, position + 1)
    while True:
        if position >= len(text):
            raise ValueError(f"line {number}: unterminated flow sequence")
        if text[position] == "]":
            return items, position + 1
        value, position = _flow_value(text, position, number)
        items.append(value)
        position = _skip_spaces(text, position)
        if position >= len(text):
            raise ValueError(f"line {number}: unterminated flow sequence")
        if text[position] == ",":
            position = _skip_spaces(text, position + 1)
            continue
        if text[position] == "]":
            return items, position + 1
        raise ValueError(f"line {number}: expected ',' or ']' in a flow sequence")


def _flow_mapping(text: str, position: int, number: int) -> tuple[dict[str, Any], int]:
    """Parse ``{k: v, ...}`` starting at *position* (the opening brace)."""
    out: dict[str, Any] = {}
    position = _skip_spaces(text, position + 1)
    while True:
        if position >= len(text):
            raise ValueError(f"line {number}: unterminated flow mapping")
        if text[position] == "}":
            return out, position + 1
        if text[position] in "\"'":
            key, position = _flow_quoted(text, position, number)
            key = str(key)
        else:
            start = position
            while position < len(text) and text[position] not in ":{,}":
                position += 1
            key = text[start:position].strip()
        if position >= len(text) or text[position] != ":":
            raise ValueError(f"line {number}: flow mapping entry {key!r} has no value")
        if key in out:
            raise ValueError(f"line {number}: duplicate key {key!r}")
        value, position = _flow_value(text, position + 1, number)
        out[key] = value
        position = _skip_spaces(text, position)
        if position >= len(text):
            raise ValueError(f"line {number}: unterminated flow mapping")
        if text[position] == ",":
            position = _skip_spaces(text, position + 1)
            continue
        if text[position] == "}":
            return out, position + 1
        raise ValueError(f"line {number}: expected ',' or '}}' in a flow mapping")


def _flow_quoted(text: str, position: int, number: int) -> tuple[str, int]:
    """Parse a quoted flow scalar; returns ``(value, position after quote)``."""
    quote = text[position]
    out: list[str] = []
    index = position + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and quote == '"':
            if index + 1 >= len(text):
                raise ValueError(f"line {number}: unterminated escape in a quoted scalar")
            out.append(
                {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(text[index + 1], text[index + 1])
            )
            index += 2
            continue
        if char == quote:
            return "".join(out), index + 1
        out.append(char)
        index += 1
    raise ValueError(f"line {number}: unterminated quoted scalar")


def _skip_spaces(text: str, position: int) -> int:
    """Advance past spaces and tabs."""
    while position < len(text) and text[position] in " \t":
        position += 1
    return position


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    config: Path = typer.Argument(..., help="Path to the splat YAML config."),
    write: bool = typer.Option(
        False, "--write", help="Apply the plan (default: dry run, nothing is written)"
    ),
    force: bool = typer.Option(
        False, "--force", help="Replace annotations that conflict with the splat config"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Target name from rebrew-project.toml"
    ),
) -> None:
    """Seed a rebrew project from a splat config (dry run by default)."""
    try:
        cfg_splat = parse_splat_config(Path(config))
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)

    try:
        plan = build_plan(cfg_splat, target)
    except (ValueError, FileNotFoundError, KeyError) as exc:
        error_exit(str(exc), json_mode=json_output)

    if write:
        try:
            result = apply_plan(plan, force=force)
        except ValueError as exc:
            error_exit(str(exc), json_mode=json_output, code=EXIT_MISMATCH)
    else:
        result = apply_plan(plan, force=force, dry_run=True)

    if json_output:
        json_print(_plan_payload(plan, result, written=write))
        return
    _render(plan, result, written=write)


def _plan_payload(plan: ImportPlan, result: dict[str, Any], *, written: bool) -> dict[str, Any]:
    """The full plan as JSON (identical for the dry run and the applied run)."""
    return {
        "splat_config": str(plan.splat.path),
        "target": plan.target,
        "dry_run": not written,
        "binary": {
            "source": str(plan.binary),
            "dest": plan.binary_dest,
            "copied": plan.copy_binary,
        },
        "project": {
            "format": plan.format,
            "arch": plan.arch,
            "profile": plan.profile,
            "image_base": f"0x{plan.image_base:08X}",
        },
        "layout": {
            "image_base": plan.image_base,
            "sections": [s.as_dict() for s in plan.sections if isinstance(s, SectionMeta)],
        },
        "annotations": [
            {
                "kind": a.kind,
                "marker": a.marker,
                "module": a.module,
                "va": f"0x{a.va:08X}",
                "name": a.name,
                "size": a.size,
                "section": a.section,
                "detail": a.detail,
                "path": a.display_path(plan.reversed_display),
                "state": a.state,
            }
            for a in plan.annotations
        ],
        "conflicts": plan.conflicts,
        "unresolvable_conflicts": plan.unresolvable,
        "skipped": [{"symbol": name, "reason": reason} for name, reason in plan.skipped],
        "notes": plan.notes,
        "ignored_keys": [{"key": i.key, "reason": i.reason} for i in plan.splat.ignored],
        "written": result["written"],
        "unchanged": result["unchanged"],
        "next": f"rebrew lint -t {plan.target} && rebrew status -t {plan.target}",
    }


def _render(plan: ImportPlan, result: dict[str, Any], *, written: bool) -> None:
    """Human-readable plan (and, with ``--write``, what was written)."""
    header = "import-splat" if written else "dry run"
    console.print(f"[bold]{header}:[/bold] {plan.splat.path} -> target {plan.target!r}")
    console.print(
        f"  binary  {plan.binary}"
        + (" (copied to the project)" if plan.copy_binary else " (already in the project)")
    )
    console.print(
        f"  project format={plan.format} arch={plan.arch} profile={plan.profile} "
        f"image_base=0x{plan.image_base:08X}"
    )
    for note in plan.notes:
        console.print(f"  [yellow]note:[/yellow] {note}")

    if plan.sections:
        table = Table(title="layout sections", header_style="bold")
        for col in ("section", "rva", "virtual", "raw", "raw ptr"):
            table.add_column(col)
        for section in plan.sections:
            if not isinstance(section, SectionMeta):
                continue
            table.add_row(
                section.name,
                f"0x{section.va:X}",
                f"0x{section.vs:X}",
                f"0x{section.raw:X}",
                f"0x{section.raw_ptr:X}",
            )
        console.print(table)

    if plan.annotations:
        table = Table(title="annotations", header_style="bold")
        for col in ("kind", "va", "name", "size", "file", "state"):
            table.add_column(col)
        for ann in plan.annotations:
            table.add_row(
                ann.kind,
                f"0x{ann.va:08X}",
                ann.name,
                f"0x{ann.size:X}" if ann.size else "-",
                ann.display_path(plan.reversed_display),
                ann.state,
            )
        console.print(table)
        if not written:
            console.print("[dim]annotation syntax:[/dim]")
            for ann in plan.annotations:
                for line in ann.marker.splitlines():
                    console.print(f"  [dim]{line}[/dim]")

    for conflict in plan.conflicts:
        console.print(f"[red]conflict:[/red] {conflict}")
    if plan.unresolvable:
        console.print(
            "[red]these conflicts need the project fixed first; --force cannot resolve them[/red]"
        )
    for name, reason in plan.skipped:
        console.print(f"[dim]skipped {name}: {reason}[/dim]")

    if plan.splat.ignored:
        ignored = Table(title="ignored config keys", header_style="bold dim", title_style="dim")
        ignored.add_column("key", style="dim")
        ignored.add_column("why rebrew does not read it", style="dim")
        for item in plan.splat.ignored:
            ignored.add_row(item.key, item.reason)
        console.print(ignored)

    if written:
        console.print(f"[green]wrote {len(result['written'])} file(s)[/green]")
        for path in result["written"]:
            console.print(f"  {path}")
        if result["unchanged"]:
            console.print(f"  ({result['unchanged']} annotation(s) already present)")
    else:
        console.print(
            f"[cyan]dry run:[/cyan] {len(plan.annotations)} annotation(s), "
            f"{len(plan.sections)} layout section(s); re-run with --write to apply"
        )
    if plan.conflicts and not written:
        console.print(
            "[yellow]conflicts are reported above; re-run with --force to replace "
            "the ones that are overwritable[/yellow]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
