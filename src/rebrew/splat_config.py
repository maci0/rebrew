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
rebrew.  Nothing here writes a splat file back out (``rebrew export symbols``
already exports the symbol side).

What it delegates to (no second mechanism):

- YAML: :func:`parse_splat_config`, a strict reader for the config subset
  splat's own ``create_config`` emits (see "Config subset" below).  rebrew
  does not depend on PyYAML, so the subset is parsed here and anything
  outside it is a hard error, never a silent misread.
- Symbols: :func:`rebrew.symbol_addrs.parse_symbol_addrs` reads every
  ``symbol_addrs_path`` file, including the rich ``// type:``/``// size:``
  trailing comments the ``rebrew export symbols`` writer emits.
- Binary identity and layout: :func:`rebrew.formats.binary_loader.load_binary`
  supplies format, arch, and image base; the configured binary is copied by
  the same convention ``rebrew intake`` uses (``original/<target>``).
- Function annotations: :func:`rebrew.skeleton.generate_skeleton` renders a
  pure-C stub. Identity, ``SIZE``, and ``STATUS`` land in
  ``rebrew-functions.toml`` (status is metadata-owned, never inline).
- Library annotations: :func:`rebrew.identify_library.write_candidates` records
  ``LIBRARY`` rows. The header is a banner, not inline state.
- Data annotations: the C declaration plus a ``rebrew-data.toml`` row for
  ``size`` and ``section``.
- Layout entries: :class:`rebrew.layout_meta.SectionMeta` records, written
  into ``layout/<target>/rebrew-layout.toml`` in the same shape
  ``rebrew build layout`` writes, so ``rebrew data list``/``calibrate-bss`` read them
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

    rebrew source import-splat splat.yaml            # dry run: what it would write
    rebrew source import-splat splat.yaml --apply    # apply
    rebrew source import-splat splat.yaml --apply --force --target win32_app.exe

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
lazy import shutil

import typer
import yaml

from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
)
from rebrew.layout_meta import SectionMeta
lazy from rebrew.config import target_module
lazy from rebrew.metadata.bindings import iter_source_bindings
lazy from rebrew.sources import iter_sources
lazy from rebrew.utils import (
    TerminalTable,
    atomic_write_text,
    library_header_name,
    parse_int_literal,
    untrusted_ident,
)
lazy from rebrew.workspace.config import config_path

if TYPE_CHECKING:
    from rebrew.symbol_addrs import SymbolRow


lazy from rebrew.cli import console

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
    "dump_symbols": "splat's own symbols dump; use `rebrew export symbols --references`",
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
    "(see the rebrew repo's docs/CLI.md `rebrew source import-splat`)"
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
    "jtbl": "splat's jump-table split (rebrew decodes switches with `rebrew binary switches`)",
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
#: a data declaration.  ``func`` is handled as a function annotation and
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
#: same classification ``rebrew library identify``'s import backend makes).
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

app = typer.Typer(
    help="Seed a Rebrew project from splat YAML: names, layout, and metadata.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source import-splat splat.yaml  # Dry run: what would be written\n\n"
        "  rebrew source import-splat splat.yaml --apply  # Apply\n\n"
        "  rebrew source import-splat splat.yaml --json  # Machine-readable plan\n\n"
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
    """Resolve a YAML path value against *base* (splat's ``base_path``).

    Paths must stay inside *base*: absolute paths and ``..`` escapes are
    refused so a hostile splat config cannot make the importer read or copy
    arbitrary files outside the directory it was invoked from.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    path = config_path(raw)
    base_resolved = base.resolve()
    candidate = (base_resolved / path) if not path.is_absolute() else path
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base_resolved):
        raise ValueError(f"splat path {raw!r} escapes the config directory")
    return resolved


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
        if len(entry) == 1:
            # ``- [0x800]`` is splat's rom-end sentinel, not a segment.
            return None
        # splat also spells a segment as a list; this importer supports only the
        # mapping form.  Dropping it silently would leave its symbols stranded
        # outside every segment with no diagnostic, so it fails loudly.
        raise ValueError(f"{path}: segment entry must be a mapping or the rom-end sentinel list")
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
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: not readable as UTF-8: {exc}") from exc
    return parse_splat_text(text, path)


def parse_splat_text(text: str, path: Path) -> SplatConfig:
    """Parse already-read splat config *text* as if it lived at *path*.

    *path* must be absolute: the model's relative paths (target_path, symbol
    files) hang from its directory and error messages name it.  Nothing at
    *path* is opened, so a caller holding the text in memory (an anonymous
    buffer, an upload) needs no file for the parser to resolve.  The result and
    the errors are those :func:`parse_splat_config` gives for a file with this
    text and location.
    """
    path = Path(path)
    if not path.is_absolute():
        raise ValueError(f"splat config location must be absolute: {path}")
    try:
        raw = parse_yaml_subset(text)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
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
            "(see `rebrew source import-splat --help`)"
        )

    compiler = str(options.get("compiler") or "")
    if not compiler:
        raise ValueError(f"{path}: options.compiler is required")

    segments_raw = raw.get("segments")
    if not isinstance(segments_raw, list) or not segments_raw:
        raise ValueError(f"{path}: 'segments' must be a non-empty list")

    # The caller's base_path is relative to the config's own directory and
    # must stay inside it (see _rel).
    config_dir = path.parent
    base_rel = options.get("base_path")
    base_path = config_dir
    if isinstance(base_rel, str) and base_rel.strip() and base_rel.strip() not in (".", "./"):
        candidate = Path(base_rel)
        base_path = candidate if candidate.is_absolute() else (config_dir / candidate)
        base_resolved = config_dir.resolve()
        resolved_base = base_path.resolve()
        if not resolved_base.is_relative_to(base_resolved):
            raise ValueError(f"{path}: options.base_path {base_rel!r} escapes the config directory")
        base_path = resolved_base

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
        ignored=tuple(dict.fromkeys(ignored)),
    )


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
    ``rebrew export symbols`` writes.  ``undefined_funcs_auto``/``undefined_syms_auto``
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
class SourceBinding:
    """One annotation the import would add.

    ``kind`` is ``FUNCTION``, ``LIBRARY``, or ``DATA``. *path* is relative to
    the target's ``reversed_dir``. ``declaration`` is the text written into the
    source: the C declaration, or a comment that is not the legacy marker
    grammar. Identity is recorded in the metadata stores.
    """

    kind: str
    module: str
    va: int
    name: str
    size: int | None
    section: str
    detail: str
    path: str
    declaration: str
    state: str  # "create" | "unchanged" | "conflict"

    def display_path(self, reversed_dir: str) -> str:
        """The project-relative path this annotation lands in."""
        return f"{reversed_dir}/{self.path}" if reversed_dir else self.path


@dataclass
class ImportPlan:
    """What :func:`apply_plan` would write, and what it would not."""

    splat: SplatConfig
    target: str
    module: str
    reversed_display: str
    binary: Path
    binary_dest: str
    copy_binary: bool
    profile: str
    format: str
    arch: str
    image_base: int
    sections: list[SectionMeta]
    annotations: list[SourceBinding]
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
    from rebrew.formats.binary_loader import load_binary

    cfg = require_config(target=target)
    target_name = cfg.target_name
    target_module_name = target_module(cfg)

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
        cfg_splat, cfg, target_module_name, info.image_base, symbols, existing
    )
    notes.extend(notes_ann)
    skipped.extend(layout_skipped)

    binary_dest = f"original/{binary.name}"
    in_project = _inside_project(binary, cfg.root)
    return ImportPlan(
        splat=cfg_splat,
        target=target_name,
        module=target_module_name,
        reversed_display=_display_dir(cfg),
        binary=binary,
        binary_dest=binary.relative_to(cfg.root).as_posix() if in_project else binary_dest,
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


def _display_dir(cfg: Any) -> str:
    """The target's reversed_dir as a project-relative display prefix."""
    try:
        return str(cfg.reversed_dir.relative_to(cfg.root).as_posix())
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
    """Section records for ``layout/<target>/rebrew-layout.toml`` from the splat segments.

    Each ``type: code`` segment becomes one :class:`SectionMeta` with the PE
    section name and the section's RVA (``vram - image_base``).  When the
    binary really has that section its measured geometry wins (the splat
    numbers are reported when they disagree); a segment with no PE counterpart
    falls back to the splat span and the characteristics implied by its
    subsegment kind.  Either way the record is the same shape
    ``rebrew build layout`` writes, so ``rebrew data list`` and
    ``rebrew build calibrate-bss`` read it unchanged.
    """
    from rebrew.formats.pe_headers import pe_layout

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
    """``va -> ("KIND name", path)`` for every annotation already in the project.

    Sources come through :func:`rebrew.metadata.bindings.iter_source_bindings` (the shared batch
    reader) and ``library_*.h`` headers through
    :func:`rebrew.metadata.bindings.library_bindings_for_file`, so the import sees every
    way an address can already be claimed.  Paths are relative to
    ``reversed_dir`` so they compare against a planned file directly.
    """
    from rebrew.metadata.bindings import library_bindings_for_file

    existing: dict[int, tuple[str, str]] = {}
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    target_module_name = target_module(cfg)
    metadata_dir = cfg.metadata_dir
    for path, annos in iter_source_bindings(
        sources,
        target=target_module_name,
        metadata_dir=metadata_dir,
        project_root=getattr(cfg, "root", None),
    ):
        for ann in annos:
            name = ann.symbol or ann.name or ""
            existing.setdefault(ann.va, (f"{ann.kind} {name}".strip(), path.name))
    for header in sorted(cfg.reversed_dir.glob("library_*.h")):
        for ann in library_bindings_for_file(header, metadata_dir=metadata_dir):
            name = ann.symbol or ann.name or ""
            existing.setdefault(ann.va, (f"LIBRARY {name}".strip(), header.name))
    return existing


def _plan_annotations(
    cfg_splat: SplatConfig,
    cfg: Any,
    target_module_name: str,
    image_base: int,
    symbols: SymbolSet,
    existing: dict[int, tuple[str, str]],
) -> tuple[list[SourceBinding], list[str], list[str], list[tuple[str, str]], list[str]]:
    """Classify every symbol row into a planned annotation, a skip, or a conflict.

    The symbol's splat ``type:`` picks the metadata kind (``func`` -> FUNCTION, a
    sized type -> DATA); the segment map decides whether the address exists in
    the image as code or as data.  A row whose two signals disagree is skipped
    with the reason rather than annotated on a guess.  A row the project
    already annotates is ``unchanged`` (so a re-run is an idempotent no-op) or,
    when the annotations disagree, a conflict: *conflicts* are the ones
    ``--force`` may overwrite, *unresolvable* the ones it cannot.

    Returns ``(annotations, conflicts, unresolvable, skipped, notes)``.
    """
    from rebrew.naming import make_filename, sanitize_name

    planned: list[SourceBinding] = []
    conflicts: list[str] = []
    unresolvable: list[str] = []
    notes: list[str] = []
    skipped: list[tuple[str, str]] = []
    source = str(cfg_splat.path.name)
    seen_names: dict[str, int] = {}
    # Several symbols usually land in one planned file; parse each existing
    # file once instead of once per symbol.
    annotated_vas: dict[Path, set[int]] = {}

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

        # The section decides the metadata kind (code vs data); the splat type and the
        # provenance detail only refine it.  Code the config attributes to a DLL
        # import is LIBRARY, the same classification identify_library's import
        # backend makes for `jmp [IAT]` thunks.
        declaration = ""
        if section_kind == "text":
            if library_module:
                kind = "LIBRARY"
                module = library_module
                rel = library_header_name(module)
                path = None  # a library header is appended to, not owned
            else:
                kind = "FUNCTION"
                module = target_module_name
                rel = make_filename(name, custom_name=name, cfg=cfg)
                path = cfg.reversed_dir / rel
        else:
            kind = "DATA"
            module = target_module_name
            declaration = _data_declaration(name, row.kind, row.size)
            rel = f"data_{name}{_first_ext(cfg)}"
            path = cfg.reversed_dir / rel

        state, message, overridable = _annotation_state(
            existing, path, rel, row.va, name, annotated_vas
        )
        if state == "conflict":
            conflicts.append(
                f"{message}, splat says {name}" if overridable else f"{message} (splat: {name})"
            )
            if not overridable:
                unresolvable.append(conflicts[-1])
        elif message:
            notes.append(message)
        planned.append(
            SourceBinding(
                kind=kind,
                module=module,
                va=row.va,
                name=name,
                size=row.size,
                section=section,
                detail=row.detail or (f"from {source}" if source else ""),
                path=rel,
                declaration=_source_declaration(
                    module, row.va, declaration, syntax=getattr(cfg, "address_comments", None)
                ),
                state=state,
            )
        )

    planned.extend(
        _plan_library_annotations(
            cfg_splat,
            target_module_name,
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
    existing: dict[int, tuple[str, str]],
    path: Path | None,
    rel: str,
    va: int,
    name: str,
    annotated_vas: dict[Path, set[int]] | None = None,
) -> tuple[str, str, bool]:
    """``(state, message, overridable)`` for one planned annotation.

    Identity is the VA plus the file that annotates it, which is what rebrew
    tracks (a symbol spelling can change when the C definition is written).
    So a VA already annotated in the planned file is ``unchanged``; the message
    carries a name disagreement as a note.  A VA claimed by *another* file is a
    conflict ``--force`` cannot fix (a second binding for one VA is lint error
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
    if path is not None and path.exists() and va not in _file_annotated_vas(path, annotated_vas):
        return ("conflict", f"{rel} already exists and does not annotate 0x{va:08X}", True)
    return "create", "", False


def _file_annotated_vas(path: Path, cache: dict[Path, set[int]] | None = None) -> set[int]:
    """VAs *path* carries, parsed once per planning run."""
    if cache is not None:
        cached = cache.get(path)
        if cached is not None:
            return cached
    from rebrew.metadata.bindings import read_source_bindings

    try:
        found = {a.va for a in read_source_bindings(path)}
    except OSError, ValueError:
        found = set()
    if cache is not None:
        cache[path] = found
    return found


def _plan_library_annotations(
    cfg_splat: SplatConfig,
    target_module_name: str,
    symbols: SymbolSet,
    existing: dict[int, tuple[str, str]],
    planned_vas: set[int],
    conflicts: list[str],
    unresolvable: list[str],
    notes: list[str],
    skipped: list[tuple[str, str]],
) -> list[SourceBinding]:
    """Plan ``LIBRARY`` rows from the two ``undefined_*`` lists.

    Splat writes those files for symbols referenced but *not defined* in the
    image: code that lives in a library, which is what a ``LIBRARY``
    row records.  The module is inferred with
    :func:`rebrew.identify_library.infer_module` (the CRT/zlib name tables,
    the same inference ``identify_library``'s import backend uses) and falls
    back to the target's own marker.  The VA has to land inside the image,
    else there is no address to anchor an annotation to and the row is
    reported as skipped.
    """
    from rebrew.identify_library import infer_module
    from rebrew.naming import sanitize_name

    planned: list[SourceBinding] = []
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
                    "(link it with `rebrew build symbol-stubs` instead)",
                )
            )
            continue
        name = sanitize_name(row.name)
        module = infer_module(row.name, target_module_name or "LIBRARY")
        rel = library_header_name(module)
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
            SourceBinding(
                kind="LIBRARY",
                module=module,
                va=row.va,
                name=name,
                size=row.size,
                section="",
                detail=f"undefined in {cfg_splat.path.name}",
                path=rel,
                declaration=_source_declaration(module, row.va, ""),
                state=state,
            )
        )
    return planned


def _import_module(detail: str) -> str:
    """The library module a splat provenance comment names, or ``""``.

    A generated win32 symbol file writes ``// type:u32 -- import from
    KERNEL32.dll`` for an IAT slot; the module is that DLL's stem uppercased,
    the spelling ``rebrew library identify`` gives import candidates.
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


def _source_declaration(module: str, va: int, declaration: str, *, syntax: Any = None) -> str:
    """Emit a declaration-bound address, or no text for an inventory-only identity."""
    from rebrew.c_parser import find_c_function_definitions, find_extern_variables
    from rebrew.metadata.anchors import add_address_anchor

    if not declaration:
        return ""
    functions = find_c_function_definitions(declaration)
    names = (
        [name for name, _line in functions]
        if functions
        else [v.name for v in find_extern_variables(declaration, include_definitions=True)]
    )
    if len(names) != 1:
        raise ValueError("one source declaration is required for an address anchor")
    return add_address_anchor(declaration.rstrip() + "\n", module, va, names[0], syntax=syntax)


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
    file, and a second binding for one VA would fail lint E013) always refuses,
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
    # (arch, module, reversed_dir), all of which this import just set.
    cfg = load_config(root=root, target=plan.target)

    by_kind: dict[str, list[SourceBinding]] = {}
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
    """Patch the target's binary/format/arch/profile and write its layout package.

    Layout sections + image base go to ``layout/<target>/rebrew-layout.toml`` (the
    same package ``rebrew build layout`` writes, minus the hex blobs a splat
    import has no binary to derive) so ``data``/``calibrate-bss`` read one
    source.  Uses a tomlkit round trip for the project config so comments
    and unrelated keys survive.  Returns whether anything changed, so a
    re-run does not bump mtimes of unchanged files (caches key on it).
    """
    import tomlkit

    from rebrew.config import project_toml_lock
    from rebrew.utils import load_toml_for_write

    changed = False
    # One locked read-modify-write: the document is parsed inside the lock so
    # a concurrent writer of another key in the same file cannot have its edit
    # dropped by the replace below.
    with project_toml_lock(root) as toml_path:
        doc = load_toml_for_write(toml_path, "rebrew-project.toml")
        targets = doc.setdefault("targets", tomlkit.table())
        entry = targets.setdefault(plan.target, tomlkit.table())
        entry["binary"] = plan.binary_dest
        entry["format"] = plan.format
        entry["arch"] = plan.arch
        compiler = entry.setdefault("compiler", tomlkit.table())
        compiler["profile"] = plan.profile
        rendered = tomlkit.dumps(doc)
        if not toml_path.is_file() or toml_path.read_text(encoding="utf-8-sig") != rendered:
            atomic_write_text(toml_path, rendered, encoding="utf-8")
            changed = True

    # Layout package (rebrew-layout.toml only — a splat import has no reference
    # binary to derive hex blobs from; postlink fixers need a real package).
    pkg_dir = root / "layout" / plan.target
    pkg_dir.mkdir(parents=True, exist_ok=True)
    lay = tomlkit.document()
    lay["layout"] = {
        "target": plan.target,
        "image_base": plan.image_base,
        "link_options": [],
        "sections": [
            section.as_dict() for section in plan.sections if isinstance(section, SectionMeta)
        ],
        "exports": [],
        "imports": [],
        "export_stamp": [0, 0],
        "exp_rva": 0,
        "source": f"splat:{plan.splat.path.name}",
    }
    lay_text = tomlkit.dumps(lay)
    lay_path = pkg_dir / "rebrew-layout.toml"
    if not lay_path.is_file() or lay_path.read_text(encoding="utf-8") != lay_text:
        atomic_write_text(lay_path, lay_text, encoding="utf-8")
        changed = True
    return changed


def _write_functions(cfg: Any, plan: ImportPlan, planned: list[SourceBinding]) -> list[str]:
    """Write one pure-C skeleton per planned function.

    The body comes from :func:`rebrew.skeleton.generate_skeleton`. Identity,
    ``SIZE``/``BLOCKER``, and ``STATUS`` go to ``rebrew-functions.toml``.
    """
    from rebrew.metadata.bindings import derive_c_symbol
    from rebrew.metadata.functions import (
        identity_file,
        record_function_rows,
        set_fields_batch,
        update_statuses_batch,
    )
    from rebrew.skeleton import generate_skeleton

    written: list[str] = []
    identity_rows: list[dict[str, Any]] = []
    field_updates: list[dict[str, Any]] = []
    status_updates: list[dict[str, Any]] = []
    metadata_dir = cfg.metadata_dir
    for ann in planned:
        target_path = cfg.reversed_dir / ann.path
        body = generate_skeleton(
            cfg,
            ann.va,
            ghidra_name=ann.name,
            module=plan.module,
            custom_name=ann.name,
        )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(target_path, body)
        written.append(target_path.relative_to(cfg.root).as_posix())
        identity_rows.append(
            {
                "module": plan.module,
                "va": ann.va,
                "identity": {
                    "file": identity_file(target_path, metadata_dir),
                    "symbol": derive_c_symbol(ann.name, ""),
                    "name": ann.name,
                    "kind": "FUNCTION",
                },
                "fields": {},
            }
        )
        fields: dict[str, Any] = {"blocker": SEED_BLOCKER}
        if ann.size:
            fields["size"] = ann.size
        field_updates.append({"module": plan.module, "va": ann.va, "fields": fields})
        status_updates.append(
            {
                "module": plan.module,
                "va": ann.va,
                "new_status": SEED_STATUS,
                "clear_blockers": False,
                "updated_by": "import-splat",
            }
        )
    record_function_rows(metadata_dir, identity_rows)
    set_fields_batch(metadata_dir, field_updates)
    update_statuses_batch(metadata_dir, status_updates)
    return written


def _write_data(cfg: Any, plan: ImportPlan, planned: list[SourceBinding]) -> list[str]:
    """Write data declarations and their ``rebrew-data.toml`` identity."""
    from rebrew.metadata.data import record_data_rows, set_data_fields_batch
    from rebrew.metadata.functions import identity_file

    written: list[str] = []
    updates: list[dict[str, Any]] = []
    identity_rows: list[dict[str, Any]] = []
    metadata_dir = cfg.metadata_dir
    for ann in planned:
        target_path = cfg.reversed_dir / ann.path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            target_path,
            ann.declaration if ann.declaration.endswith("\n") else f"{ann.declaration}\n",
        )
        written.append(target_path.relative_to(cfg.root).as_posix())
        identity_rows.append(
            {
                "module": plan.module,
                "va": ann.va,
                "identity": {
                    "file": identity_file(target_path, metadata_dir),
                    "kind": "DATA",
                    "name": ann.name,
                },
                "fill": {"size": ann.size, "section": ann.section},
            }
        )
        fields: dict[str, Any] = {"section": ann.section, "name": ann.name}
        if ann.size:
            fields["size"] = ann.size
        updates.append(
            {"module": plan.module, "va": ann.va, "fields": fields, "updated_by": "intake"}
        )
    record_data_rows(metadata_dir, identity_rows)
    # One rebrew-data.toml rewrite for the whole import, not three per symbol.
    set_data_fields_batch(metadata_dir, updates)
    return written


def _write_libraries(cfg: Any, plan: ImportPlan, planned: list[SourceBinding]) -> list[str]:
    """Record LIBRARY rows through ``identify_library.write_candidates``."""
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
    return [(cfg.reversed_dir / h).relative_to(cfg.root).as_posix() for h in headers]


# ---------------------------------------------------------------------------
# YAML reader (PyYAML, strict)
# ---------------------------------------------------------------------------


_MAX_YAML_DEPTH = 64


class _StrictLoader(yaml.SafeLoader):  # type: ignore[misc]
    """SafeLoader with the subset's scalar rules and duplicate-key refusal.

    Keys are always strings (splat keys never coerce). Values keep the old
    subset's coercion: only true/false (any case), null/~, ints and hex ints
    coerce; the YAML 1.1 ``yes``/``no``/``on``/``off`` booleans, floats and
    dates would turn a config's string into a type the importer must reject.
    """

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_yaml_str(key_node)
            if key in mapping:
                mark = key_node.start_mark
                raise ValueError(f"line {mark.line + 1}: duplicate key {key!r}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


# Subset implicit resolvers: drop the 1.1 ``yes``/``no``/``on``/``off`` bools,
# timestamps and floats; keep null/int/bool only in the old subset's spellings.
def _subset_implicit_resolvers() -> dict[str, list[tuple[str, Any]]]:
    bool_re = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$", re.VERBOSE)
    null_re = re.compile(r"^(?: ~|null|Null|NULL| )$", re.VERBOSE)
    int_re = re.compile(
        r"^(?:[-+]?0b[0-1_]+|[-+]?0x[0-9a-fA-F_]+|[-+]?(?:0|[1-9][0-9_]*))$",
        re.VERBOSE,
    )
    base = yaml.resolver.Resolver.yaml_implicit_resolvers
    out: dict[str, list[tuple[str, Any]]] = {}
    for first in base:
        keep = []
        for tag, regex in base[first]:
            if tag == "tag:yaml.org,2002:bool":
                keep.append((tag, bool_re))
            elif tag == "tag:yaml.org,2002:null":
                keep.append((tag, null_re))
            elif tag == "tag:yaml.org,2002:int":
                # Old subset: leading-zero octal stays decimal (010 is ten);
                # drop the sexagesimal form the stock int regex carries.
                keep.append((tag, int_re))
            elif tag in ("tag:yaml.org,2002:float", "tag:yaml.org,2002:timestamp"):
                continue
            else:
                keep.append((tag, regex))
        if keep:
            out[first] = keep
    return out


_StrictLoader.yaml_implicit_resolvers = _subset_implicit_resolvers()


def parse_yaml_subset(text: str) -> Any:
    """Parse a splat config as YAML.

    PyYAML parses; this wrapper keeps the strictness the importer relies on
    (duplicate keys, anchors, block scalars, deep nesting, tabs, multiple
    documents are refused with a line reason), because a config this module
    cannot read must fail loudly rather than half-importing.
    """
    try:
        document = yaml.compose(text, Loader=_StrictLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 1
        problem = getattr(exc, "problem", None) or str(exc)
        detail = str(exc)
        if "\\t" in detail or "tab" in detail.lower():
            problem = "tab indentation is not supported"
        elif "expected a single document" in problem:
            problem = "multiple documents are not supported"
        elif "expected" in problem and "']'" in detail:
            problem = f"unterminated flow sequence: {problem}"
        raise ValueError(f"line {line}: {problem}") from exc
    except RecursionError:
        raise ValueError(f"line 1: YAML nesting exceeds {_MAX_YAML_DEPTH} levels") from None
    if document is None:
        return {}
    _check_yaml_text_before_doc(text)
    if not isinstance(document, (yaml.MappingNode, yaml.SequenceNode)):
        mark = getattr(document, "start_mark", None)
        line = mark.line + 1 if mark is not None else 1
        raise ValueError(f"line {line}: expected a mapping or sequence at the document root")
    _check_yaml_text_doc(text)
    _check_yaml_nodes(document, text)
    loader = _StrictLoader(text)
    try:
        return loader.construct_document(document)
    except ValueError:
        raise
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 1
        problem = getattr(exc, "problem", None) or str(exc)
        raise ValueError(f"line {line}: {problem}") from exc
    except RecursionError:
        raise ValueError(f"line 1: YAML nesting exceeds {_MAX_YAML_DEPTH} levels") from None
    finally:
        loader.dispose()


def _check_yaml_text_before_doc(text: str) -> None:
    """Refuse ``...``/trailing-marker misuse before the root check.

    ``---`` opens one document; ``...`` anywhere in a file the importer reads
    means the file holds more than one document, which it refuses.
    """
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped == "...":
            raise ValueError(f"line {number}: multiple documents are not supported")


def _check_yaml_text_doc(text: str) -> None:
    """Refuse a second ``---`` and tab indentation the node walk cannot see."""
    seen_document = False
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ValueError(f"line {number}: tab indentation is not supported")
        stripped = raw.strip()
        if stripped == "---":
            if seen_document:
                raise ValueError(f"line {number}: multiple documents are not supported")
            seen_document = True


def _check_yaml_nodes(node: Any, text: str) -> None:
    """Refuse anchors, block scalars, and nesting deeper than the limit."""
    stack = [(node, 0)]
    seen = set()
    while stack:
        current, depth = stack.pop()
        if depth >= _MAX_YAML_DEPTH:
            mark = getattr(current, "start_mark", None)
            line = mark.line + 1 if mark is not None else 1
            raise ValueError(f"line {line}: YAML nesting exceeds {_MAX_YAML_DEPTH} levels")
        if id(current) in seen:
            continue
        seen.add(id(current))
        mark = getattr(current, "start_mark", None)
        line = mark.line + 1 if mark is not None else 1
        if isinstance(current, yaml.ScalarNode) and current.style in ("|", ">"):
            raise ValueError(f"line {line}: block scalar is not supported")
        if isinstance(current, yaml.MappingNode):
            for k, v in current.value:
                stack.append((k, depth + 1))
                stack.append((v, depth + 1))
        elif isinstance(current, yaml.SequenceNode):
            for v in current.value:
                stack.append((v, depth + 1))
    for event in yaml.parse(text):
        anchor = getattr(event, "anchor", None)
        if anchor is not None:
            line = event.start_mark.line + 1
            raise ValueError(f"line {line}: anchors are not supported")
        if isinstance(event, yaml.AliasEvent):
            line = event.start_mark.line + 1
            raise ValueError(f"line {line}: anchors are not supported")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    config: Path = typer.Argument(..., help="Path to the splat YAML config"),
    apply: bool = typer.Option(
        False, "--apply", help="Apply the plan (default: dry run, nothing is written)"
    ),
    force: bool = typer.Option(
        False, "--force", help="Replace metadata entries that conflict with the splat config"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
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

    if apply:
        try:
            result = apply_plan(plan, force=force)
        except ValueError as exc:
            error_exit(str(exc), json_mode=json_output)
    else:
        result = apply_plan(plan, force=force, dry_run=True)

    if json_output:
        json_print(_plan_payload(plan, result, written=apply))
        return
    _render(plan, result, written=apply)


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
                "declaration": a.declaration,
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
        "next": f"rebrew lint --target {plan.target} && rebrew status --target {plan.target}",
    }


def _render(plan: ImportPlan, result: dict[str, Any], *, written: bool) -> None:
    """Human-readable plan (and, with ``--apply``, what was written)."""
    header = "import-splat" if written else "dry run"
    console.print(
        f"[bold]{header}:[/bold] {untrusted_ident(plan.splat.path)} -> target {plan.target!r}"
    )
    console.print(
        f"  binary  {untrusted_ident(plan.binary)}"
        + (" (copied to the project)" if plan.copy_binary else " (already in the project)")
    )
    console.print(
        f"  project format={plan.format} arch={plan.arch} "
        f"profile={untrusted_ident(plan.profile)} image_base=0x{plan.image_base:08X}"
    )
    for note in plan.notes:
        console.print(f"  [yellow]note:[/yellow] {untrusted_ident(note)}")

    if plan.sections:
        table = TerminalTable(title="layout sections", header_style="bold")
        for col in ("section", "rva", "virtual", "raw", "raw ptr"):
            table.add_column(col)
        for section in plan.sections:
            if not isinstance(section, SectionMeta):
                continue
            table.add_row(
                untrusted_ident(section.name),
                f"0x{section.va:X}",
                f"0x{section.vs:X}",
                f"0x{section.raw:X}",
                f"0x{section.raw_ptr:X}",
            )
        console.print(table)

    if plan.annotations:
        table = TerminalTable(title="annotations", header_style="bold")
        for col in ("kind", "va", "name", "size", "file", "state"):
            table.add_column(col)
        for ann in plan.annotations:
            table.add_row(
                ann.kind,
                f"0x{ann.va:08X}",
                untrusted_ident(ann.name),
                f"0x{ann.size:X}" if ann.size else "-",
                untrusted_ident(ann.display_path(plan.reversed_display)),
                untrusted_ident(ann.state),
            )
        console.print(table)
        if not written:
            console.print("[dim]annotation syntax:[/dim]")
            for ann in plan.annotations:
                for line in ann.declaration.splitlines():
                    console.print(f"  [dim]{untrusted_ident(line)}[/dim]")

    for conflict in plan.conflicts:
        console.print(f"[red]conflict:[/red] {untrusted_ident(conflict)}")
    if plan.unresolvable:
        console.print(
            "[red]these conflicts need the project fixed first; --force cannot resolve them[/red]"
        )
    for name, reason in plan.skipped:
        console.print(f"[dim]skipped {untrusted_ident(name)}: {untrusted_ident(reason)}[/dim]")

    if plan.splat.ignored:
        ignored = TerminalTable(
            title="ignored config keys", header_style="bold dim", title_style="dim"
        )
        ignored.add_column("key", style="dim")
        ignored.add_column("why rebrew does not read it", style="dim")
        for item in plan.splat.ignored:
            ignored.add_row(untrusted_ident(item.key), untrusted_ident(item.reason))
        console.print(ignored)

    if written:
        console.print(f"[green]wrote {len(result['written'])} file(s)[/green]")
        for path in result["written"]:
            console.print(f"  {untrusted_ident(path)}")
        if result["unchanged"]:
            console.print(f"  ({result['unchanged']} annotation(s) already present)")
    else:
        console.print(
            f"[cyan]dry run:[/cyan] {len(plan.annotations)} annotation(s), "
            f"{len(plan.sections)} layout section(s); re-run with --apply to apply"
        )
    if plan.conflicts and not written:
        console.print(
            "[yellow]conflicts are reported above; re-run with --force to replace "
            "the ones that are overwritable[/yellow]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
